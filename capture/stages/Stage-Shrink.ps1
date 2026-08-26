# Stage-Shrink.ps1 — shrink the PARTITION, so the virtual disk is genuinely smaller.
#
# ⛔ THE PROBLEM. "We cannot keep hosting 250 GB drives." A pharmacy PC with a 250 GB disk and
# 70 GB of real data captures as a 250 GB virtual disk. Compression hides that on the wire — the
# measured run went 159 GB to 72 GB — but it is hidden only in transit: the moment it is
# imported, the pool allocates for the DECLARED size, and a node that could hold four sites holds
# one. The compression ratio was never the number that mattered.
#
# ⭐ AND THIS IS WHY THE PARTITION IS SHRUNK BEFORE THE CAPTURE, NOT AFTER. disk2vhd sizes the
# VHDX from the VOLUME. Shrinking C: from 250 GB to 90 GB here means the captured virtual disk
# IS 90 GB — geometry, not compression. Doing it after capture would mean resizing a VHDX
# host-side, which nothing in this pipeline does and which would have to happen on the cluster.
#
# ⚠️ A SHRINK CAN FAIL, AND THAT IS A NORMAL TUESDAY, NOT A CRASH. Windows can only move
# clusters it is allowed to move. Anything unmovable near the end of the volume pins the
# shrink point there, and the classic four culprits are the pagefile, hibernation, the shadow
# storage and the WinRE image. Strip-PmrImage.ps1 already removes ALL FOUR before the reboot —
# which is why this stage runs after it and after the reboot, and why it usually works. When it
# does not, this reports how far it got and NAMES the blocker, and the run continues. A capture
# that is bigger than we wanted is worth infinitely more than no capture.

Set-StrictMode -Version 2.0

# Left free INSIDE Windows after the shrink. Not slack for the sake of it: Windows re-creates a
# pagefile on first boot in the VM, Windows Update needs working room, and a C: at 100% is a
# desktop that stops working a fortnight after go-live. 12 GB covers a pagefile sized for the
# 6 GB the estate standard gives a desktop VM, plus room to patch.
$script:WcnShrinkHeadroomBytes = 12GB

function Get-WcnVolumeFacts {
    param([string]$DriveLetter = 'C')
    try {
        $part = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop
        $vol  = Get-Volume  -DriveLetter $DriveLetter -ErrorAction Stop
        return [pscustomobject]@{
            Ok = $true
            PartitionSize = [int64]$part.Size
            VolumeSize    = [int64]$vol.Size
            FreeBytes     = [int64]$vol.SizeRemaining
            UsedBytes     = [int64]($vol.Size - $vol.SizeRemaining)
            DiskNumber    = $part.DiskNumber
            PartitionNumber = $part.PartitionNumber
            Error = $null
        }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message
                                  PartitionSize = $null; VolumeSize = $null; FreeBytes = $null; UsedBytes = $null
                                  DiskNumber = $null; PartitionNumber = $null }
    }
}

function Get-WcnShrinkBlocker {
    <#
      Best-effort: name what is pinning the shrink point.

      Windows records the last unmovable file it hit in the Application log as event 259 from
      "Microsoft-Windows-Defrag" — that is the message the Disk Management UI shows as "there
      is not enough space... a page file or shadow copy". Best-effort by design: this is a
      diagnostic to save an engineer twenty minutes, and its absence must never turn a
      partially-successful shrink into a failure.
    #>
    $notes = @()
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Microsoft-Windows-Defrag'; Id = 259 } `
                -MaxEvents 3 -ErrorAction SilentlyContinue
        foreach ($e in $ev) { if ($e.Message) { $notes += ($e.Message -replace '\s+', ' ').Trim() } }
    } catch { }

    # The usual four, checked directly — far more actionable than the event text when present.
    try {
        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
        if ($pf.Count -gt 0) { $notes += ("a pagefile is still active: {0} — it should have been removed before the reboot" -f (($pf | ForEach-Object { $_.Name }) -join ', ')) }
    } catch { }
    if (Test-Path 'C:\hiberfil.sys') { $notes += 'hiberfil.sys is still present — hibernation was not disabled' }
    try {
        $sc = & vssadmin.exe list shadows 2>&1 | Out-String
        if ($sc -notmatch 'No items found') { $notes += 'VSS shadow copies still exist on this volume' }
    } catch { }
    if (Test-Path 'C:\Windows\System32\Recovery\Winre.wim') { $notes += 'the WinRE image is still present' }

    if ($notes.Count -eq 0) { $notes += 'no specific blocker identified — most likely ordinary file fragmentation with unmovable clusters near the end of the volume' }
    return $notes
}

function Invoke-WcnPartitionShrink {
    <#
      Returns @{ Outcome; BeforeBytes; AfterBytes; TargetBytes; MinBytes; Reclaimed; Blockers; Note }

      Outcome is one of:
        'shrunk'      the partition is smaller than it was
        'at-minimum'  Windows says it cannot go below its current size — nothing to do, not an error
        'partial'     it moved, but not as far as asked. Reported honestly, run continues.
        'failed'      the resize was refused outright. Reported honestly, run continues.
        'unreadable'  the volume could not be measured
        'dry-run'     nothing was attempted

      ⛔ THIS FUNCTION NEVER THROWS ON A SHRINK FAILURE. It is called after the strip, the
      debloat and the reboot have already changed this PC. Throwing here would abandon that work
      over an optimisation, and would leave the pharmacy's PC modified with nothing to show for
      it.
    #>
    param([string]$DriveLetter = 'C', [switch]$DryRun, [int64]$HeadroomBytes = 0)

    if ($HeadroomBytes -le 0) { $HeadroomBytes = $script:WcnShrinkHeadroomBytes }

    $before = Get-WcnVolumeFacts -DriveLetter $DriveLetter
    if (-not $before.Ok) {
        Write-WcnWarn ("could not read the volume: {0}" -f $before.Error)
        return [pscustomobject]@{ Outcome = 'unreadable'; BeforeBytes = $null; AfterBytes = $null; TargetBytes = $null
                                  MinBytes = $null; Reclaimed = 0; Blockers = @(); Note = $before.Error }
    }

    Write-WcnInfo ("{0}: partition {1}, {2} used, {3} free" -f $DriveLetter, (Format-WcnGB $before.PartitionSize), (Format-WcnGB $before.UsedBytes), (Format-WcnGB $before.FreeBytes))

    $sup = $null
    try { $sup = Get-PartitionSupportedSize -DriveLetter $DriveLetter -ErrorAction Stop }
    catch {
        Write-WcnWarn ("Windows would not report a supported size range: {0}" -f $_.Exception.Message)
        return [pscustomobject]@{ Outcome = 'failed'; BeforeBytes = $before.PartitionSize; AfterBytes = $before.PartitionSize
                                  TargetBytes = $null; MinBytes = $null; Reclaimed = 0
                                  Blockers = (Get-WcnShrinkBlocker); Note = $_.Exception.Message }
    }

    # SizeMin is where Windows says the last unmovable cluster sits. Adding headroom ABOVE it is
    # the whole trick: aiming at SizeMin exactly produces a volume with zero free space.
    $target = [int64]$sup.SizeMin + $HeadroomBytes
    if ($target -gt $before.PartitionSize) { $target = [int64]$before.PartitionSize }

    Write-WcnInfo ("Windows says the smallest possible is {0}; targeting {1} (leaving {2} headroom inside Windows)" -f `
        (Format-WcnGB $sup.SizeMin), (Format-WcnGB $target), (Format-WcnGB $HeadroomBytes))

    # Less than 5 GB to gain is not worth a partition operation on a pharmacy's only copy of its
    # dispensing system. The risk is small but it is not zero, and neither is the reward.
    if (($before.PartitionSize - $target) -lt 5GB) {
        Write-WcnOk 'the partition is already about as small as it can usefully be — leaving it alone'
        return [pscustomobject]@{ Outcome = 'at-minimum'; BeforeBytes = $before.PartitionSize; AfterBytes = $before.PartitionSize
                                  TargetBytes = $target; MinBytes = [int64]$sup.SizeMin; Reclaimed = 0
                                  Blockers = @(); Note = 'less than 5 GB available to reclaim' }
    }

    if ($DryRun) {
        Write-WcnWarn ("DRY RUN: would shrink {0}: from {1} to {2}" -f $DriveLetter, (Format-WcnGB $before.PartitionSize), (Format-WcnGB $target))
        return [pscustomobject]@{ Outcome = 'dry-run'; BeforeBytes = $before.PartitionSize; AfterBytes = $before.PartitionSize
                                  TargetBytes = $target; MinBytes = [int64]$sup.SizeMin; Reclaimed = 0
                                  Blockers = @(); Note = 'dry run' }
    }

    Write-WcnInfo 'shrinking the partition — this can take several minutes and must not be interrupted'
    $err = $null
    try { Resize-Partition -DriveLetter $DriveLetter -Size $target -ErrorAction Stop }
    catch { $err = $_.Exception.Message }

    $after = Get-WcnVolumeFacts -DriveLetter $DriveLetter
    $afterSize = $(if ($after.Ok) { $after.PartitionSize } else { $before.PartitionSize })
    $reclaimed = [int64]($before.PartitionSize - $afterSize)

    if ($err) {
        # ⭐ A REPORTED OUTCOME. Named blockers, honest numbers, and the run carries on.
        $blockers = Get-WcnShrinkBlocker
        Write-WcnWarn ("the partition shrink was refused: {0}" -f $err)
        foreach ($b in $blockers) { Write-WcnLine ("        blocker: {0}" -f $b) 'Yellow' }
        Write-WcnWarn ("continuing — the capture will be {0} instead of the {1} we hoped for" -f (Format-WcnGB $afterSize), (Format-WcnGB $target))
        return [pscustomobject]@{
            Outcome = $(if ($reclaimed -gt 0) { 'partial' } else { 'failed' })
            BeforeBytes = $before.PartitionSize; AfterBytes = $afterSize; TargetBytes = $target
            MinBytes = [int64]$sup.SizeMin; Reclaimed = $reclaimed; Blockers = $blockers; Note = $err
        }
    }

    if ($reclaimed -le 0) {
        Write-WcnWarn 'the resize reported success but the partition is not smaller'
        return [pscustomobject]@{ Outcome = 'failed'; BeforeBytes = $before.PartitionSize; AfterBytes = $afterSize
                                  TargetBytes = $target; MinBytes = [int64]$sup.SizeMin; Reclaimed = 0
                                  Blockers = (Get-WcnShrinkBlocker); Note = 'no change in partition size' }
    }

    Write-WcnOk ("partition shrunk: {0} -> {1}  (reclaimed {2})" -f (Format-WcnGB $before.PartitionSize), (Format-WcnGB $afterSize), (Format-WcnGB $reclaimed))
    $outcome = $(if ($afterSize -le ($target + 1GB)) { 'shrunk' } else { 'partial' })
    if ($outcome -eq 'partial') {
        Write-WcnWarn ("it did not reach the target of {0} — reporting partial" -f (Format-WcnGB $target))
    }
    return [pscustomobject]@{
        Outcome = $outcome
        BeforeBytes = $before.PartitionSize; AfterBytes = $afterSize; TargetBytes = $target
        MinBytes = [int64]$sup.SizeMin; Reclaimed = $reclaimed; Blockers = @(); Note = $null
    }
}

function Invoke-WcnZeroFreeSpace {
    <#
      Zero the free space so it compresses to nothing.

      RUNS AFTER THE SHRINK, and that ordering is deliberate: after the shrink there is less free
      space to zero, so the pass is shorter, and zeroing first would only have the shrink discard
      the zeroes anyway.

      sdelete is Sysinternals and has to be staged on the kit. Its absence is a WARNING and not a
      refusal: an unzeroed image still captures correctly, it just compresses worse, and that is
      not worth abandoning a run over.
    #>
    param([string]$SdeletePath, [string]$DriveLetter = 'C', [switch]$DryRun)

    $exe = $null
    if ($SdeletePath -and (Test-Path -LiteralPath $SdeletePath)) { $exe = (Resolve-Path -LiteralPath $SdeletePath).Path }
    else {
        $cmd = Get-Command 'sdelete.exe' -ErrorAction SilentlyContinue
        if ($cmd) { $exe = $cmd.Source }
    }
    if (-not $exe) {
        Write-WcnWarn 'sdelete.exe was not found — skipping the zero pass. The image will still be correct, just larger.'
        return [pscustomobject]@{ Ok = $false; Skipped = $true; Note = 'sdelete not staged' }
    }
    if ($DryRun) {
        Write-WcnWarn ("DRY RUN: would zero free space on {0}: with {1}" -f $DriveLetter, $exe)
        return [pscustomobject]@{ Ok = $true; Skipped = $true; Note = 'dry run' }
    }
    Write-WcnInfo 'zeroing free space — several minutes, and the disk will sound busy'
    try {
        & $exe -accepteula -nobanner -z ("{0}:" -f $DriveLetter) | Out-Null
        Write-WcnOk 'free space zeroed'
        return [pscustomobject]@{ Ok = $true; Skipped = $false; Note = $null }
    } catch {
        Write-WcnWarn ("the zero pass failed: {0} — continuing, the image will just compress less" -f $_.Exception.Message)
        return [pscustomobject]@{ Ok = $false; Skipped = $false; Note = $_.Exception.Message }
    }
}
