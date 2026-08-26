# WcnMachine.ps1 — "which physical PC am I standing at?", answered so it can be re-answered.
#
# WHY THIS EXISTS AT ALL. The capture spans a reboot. The state file lives on C:, the kit lives
# on a USB stick, and both are portable. The failure this guards is mundane and entirely
# plausible: an engineer pulls the USB out of the server PC, walks to counter 3, and runs the
# resume there. Everything would work. The strip would run, the capture would run, and the
# artefact would be filed against the slot the SERVER was registered under. Nothing downstream
# could detect it — a P2V image is a P2V image, and by the time anybody notices, the site has
# been imported.
#
# ⭐ AND THIS IS WHY THE PC NAME IS PROVENANCE AND NEVER A KEY. A hostname survives P2V: the
# captured image boots as a VM still calling itself the same thing the physical PC did, so two
# machines in this estate legitimately share one name, and a pharmacy that had its PCs imaged
# from one another's clones may have several. Recorded, reported, never compared.

Set-StrictMode -Version 2.0

# Values SMBIOS reports when the board vendor never programmed the field. Matched
# case-insensitively against the WHOLE trimmed value: these are placeholders, not prefixes, and
# a real serial that happens to start with "None" must not be discarded.
$script:WcnSmbiosPlaceholders = @(
    'to be filled by o.e.m.', 'to be filled by oem', 'default string', 'system serial number',
    'not specified', 'not applicable', 'none', 'n/a', 'na', 'unknown', 'null', '0',
    '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    'x.x.x', 'oem', 'chassis serial number', 'base board serial number'
)

function Test-WcnSmbiosUsable {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v.Length -lt 3) { return $false }
    if ($script:WcnSmbiosPlaceholders -contains $v.ToLowerInvariant()) { return $false }
    # A field of one repeated character (000000, ......) is a placeholder however long it is.
    if ($v -match '^(.)\1+$') { return $false }
    return $true
}

function Get-WcnMachineIdentity {
    <#
      Returns an object describing this machine, with a stable `Fingerprint` and an honest
      `Quality`. Never throws: a machine we cannot describe still has to reach the refusal
      table, where "we cannot identify this PC" is a decision rather than a stack trace.

      THE FOUR COMPONENTS, and why the fourth is not optional:
        smbios_uuid    Win32_ComputerSystemProduct.UUID — the strongest, and the one whitebox
                       and refurbished machines most often leave unprogrammed.
        bios_serial    the asset tag an engineer can read off the case.
        board_serial   survives a disk swap; differs from bios_serial on most OEM builds.
        volume_serial  the NTFS serial of C:. Weakest as an *asset* identifier — it changes if
                       the volume is ever reformatted — but it is the one component that is
                       ALWAYS present and always unique, and this fingerprint's real job is
                       "is this the same machine I was on forty minutes ago", which it answers
                       perfectly. Without it a whitebox PC would have no fingerprint at all and
                       the resume check would have to be abandoned on exactly the hardware
                       where it is most needed.

      Quality is 'strong' when at least one SMBIOS component is real, 'weak' when the volume
      serial is carrying it alone. Weak is reported to Watchman, not hidden: a weak fingerprint
      still detects the walked-to-another-counter mistake, but it cannot be trusted as a
      pre-issued pin, and the refusal table treats those two cases differently.
    #>
    $ident = [ordered]@{
        Hostname     = $env:COMPUTERNAME          # PROVENANCE ONLY — see the header.
        Manufacturer = $null
        Model        = $null
        SmbiosUuid   = $null
        BiosSerial   = $null
        BoardSerial  = $null
        VolumeSerial = $null
        Components   = @()
        Quality      = 'none'
        Fingerprint  = $null
    }

    try {
        $csp = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
        if ($csp) {
            if (Test-WcnSmbiosUsable $csp.UUID) { $ident.SmbiosUuid = $csp.UUID.Trim().ToUpperInvariant() }
            $ident.Manufacturer = $csp.Vendor
            $ident.Model        = $csp.Name
        }
    } catch { }

    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        if ($bios -and (Test-WcnSmbiosUsable $bios.SerialNumber)) { $ident.BiosSerial = $bios.SerialNumber.Trim().ToUpperInvariant() }
    } catch { }

    try {
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        if ($board -and (Test-WcnSmbiosUsable $board.SerialNumber)) { $ident.BoardSerial = $board.SerialNumber.Trim().ToUpperInvariant() }
    } catch { }

    try {
        $vol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($vol -and $vol.VolumeSerialNumber) { $ident.VolumeSerial = $vol.VolumeSerialNumber.Trim().ToUpperInvariant() }
    } catch { }

    $parts = @()
    foreach ($pair in @(@('smbios_uuid', $ident.SmbiosUuid), @('bios_serial', $ident.BiosSerial),
                        @('board_serial', $ident.BoardSerial), @('volume_serial', $ident.VolumeSerial))) {
        if ($pair[1]) { $parts += ("{0}={1}" -f $pair[0], $pair[1]); $ident.Components += $pair[0] }
    }

    if ($parts.Count -gt 0) {
        # Sorted, so the fingerprint does not depend on the order the CIM classes answered in,
        # and hashed, so the log and the Watchman record carry an identifier rather than the
        # site's hardware serials.
        $material = (($parts | Sort-Object) -join '|')
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material))
            $ident.Fingerprint = (($hash | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 32)
        } finally { $sha.Dispose() }
    }

    $strong = @('smbios_uuid', 'bios_serial', 'board_serial') | Where-Object { $ident.Components -contains $_ }
    if     ($strong.Count -gt 0)   { $ident.Quality = 'strong' }
    elseif ($ident.Fingerprint)    { $ident.Quality = 'weak' }
    else                           { $ident.Quality = 'none' }

    return [pscustomobject]$ident
}

function Format-WcnMachine {
    param([Parameter(Mandatory)]$Identity)
    $bits = @()
    if ($Identity.Manufacturer -or $Identity.Model) { $bits += (('{0} {1}' -f $Identity.Manufacturer, $Identity.Model).Trim()) }
    $bits += ("name={0}" -f $Identity.Hostname)
    $bits += ("fp={0} ({1}: {2})" -f $Identity.Fingerprint, $Identity.Quality, ($Identity.Components -join ','))
    return ($bits -join '  |  ')
}
