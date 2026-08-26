# Stage-Capture.ps1 — disk2vhd, then convert. The proven pipeline, pointed at the server's format.
#
# ⚠️ THE ONE PLACE THE OLD KIT'S PIPELINE HAD TO CHANGE. Capture-Compress-Upload.ps1 produced
# `.vhdx.zst` — disk2vhd then `zstd --ultra -22 --long=31 -T0`, measured at 159 GB -> 72 GB. That
# compresses beautifully and it is NOT what the platform accepts: captureToken.IMAGE_FORMATS is
# a closed list of qcow2 | raw | vmdk, POST /capture/register 400s anything else, and the server
# composes the filename with the matching extension. A `.vhdx.zst` is a file nothing on the far
# end can import without a human decompressing it first.
#
# ⭐ SO THE DEFAULT IS QCOW2 WITH INTERNAL ZSTD, which is better than it sounds:
#
#     disk2vhd C: -> .vhdx
#     qemu-img convert -O qcow2 -c -o compression_type=zstd  ->  .qcow2
#
#   * it lands in the server's list, so the register call can record what it is;
#   * it is compressed AT REST and stays compressed — Proxmox boots a compressed qcow2 directly,
#     so there is no decompress step, no second copy of 200 GB on the node, and no window where
#     an import needs twice the disk it will finally use;
#   * `qemu-img convert` from an already-shrunk volume is the same content the .zst held.
#
#   The cost is honest: qcow2's internal zstd works per-cluster, so it does not reach what
#   `-22 --long=31` reached with a 2 GB window over the whole image. A somewhat larger file that
#   imports by itself beats a smaller one that needs an engineer.
#
# THE FALLBACK IS THE OLD PIPELINE, kept because it is proven and because a USB stick without
# qemu-img.exe on it should still produce a usable artefact — but it is loud, because the server
# cannot record a format it does not recognise. See Invoke-WcnCapture.
#
# ⚠️ disk2vhd IS A GUI-SUBSYSTEM TOOL AND HANGS IF RUN HEADLESS. That note was in the old kit and
# it is the technical reason -Unattended could never have worked for the part of the run that
# matters. Repeated here because it is easy to "improve" this stage into a scheduled task and
# then spend an evening watching a process that will never exit.

Set-StrictMode -Version 2.0

function Get-WcnTool {
    # Find a staged tool. Beside the kit FIRST, PATH second — the USB copy is the one that has
    # been tested, and a stray zstd on a pharmacy PC's PATH could be any version at all.
    param([Parameter(Mandatory)][string]$Name, [string]$KitRoot)
    if ($KitRoot) {
        $local = Get-ChildItem -Path $KitRoot -Filter $Name -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($local) { return $local.FullName }
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-WcnFileSha256 {
    <#
      The hash the server stores as image_sha256. Worth the few minutes it costs on a 40 GB file:
      it is the only end-to-end integrity check across a transfer that will be interrupted and
      resumed, and a resumed upload is exactly where a silent truncation hides.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        Write-WcnInfo 'hashing the image (sha256) — this is the end-to-end integrity check'
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        Write-WcnWarn ("could not hash the image: {0} — it will be registered without a checksum" -f $_.Exception.Message)
        return $null
    }
}

function Invoke-WcnCapture {
    <#
      Returns @{ Ok; Path; Format; Bytes; VhdxBytes; Ratio; Sha256; Error }

      Format is 'qcow2' (the server's list) or $null for the vhdx+zstd fallback, which is
      deliberately reported as "no recognised format" rather than mislabelled as something the
      far end would then try to import.

      The intermediate VHDX is deleted once the final artefact exists AND VERIFIES. It is the
      single largest thing on the scratch drive and it is fully reconstructible from the
      converted copy; leaving it there is what fills the USB on the second site of the evening.
    #>
    param(
        [Parameter(Mandatory)][string]$Scratch,
        [Parameter(Mandatory)][string]$BaseName,
        [string]$KitRoot,
        [int]$Level = 22,
        [switch]$DryRun,
        [switch]$KeepVhdx,
        [switch]$SkipHash
    )

    $fail = { param($msg) [pscustomobject]@{ Ok = $false; Error = $msg; Path = $null; Format = $null
                                             Bytes = $null; VhdxBytes = $null; Ratio = $null; Sha256 = $null } }

    $disk2vhd = Get-WcnTool -Name 'disk2vhd.exe' -KitRoot $KitRoot
    if (-not $disk2vhd) { return (& $fail 'disk2vhd.exe is not staged on the kit or on PATH') }
    $qemuImg = Get-WcnTool -Name 'qemu-img.exe' -KitRoot $KitRoot
    $zstd    = Get-WcnTool -Name 'zstd.exe'     -KitRoot $KitRoot
    if (-not $qemuImg -and -not $zstd) {
        return (& $fail 'neither qemu-img.exe nor zstd.exe is staged — stage qemu-img.exe on the kit for the qcow2 pipeline')
    }

    if (-not (Test-Path $Scratch)) { New-Item -ItemType Directory -Force -Path $Scratch | Out-Null }
    $vhdx = Join-Path $Scratch ("{0}.vhdx" -f $BaseName)

    if ($DryRun) {
        $what = $(if ($qemuImg) { 'convert to .qcow2 (zstd, compressed at rest)' } else { 'compress to .vhdx.zst (FALLBACK — the server cannot record this format)' })
        Write-WcnWarn ("DRY RUN: would capture C: -> {0}, then {1}" -f $vhdx, $what)
        return [pscustomobject]@{ Ok = $true; Error = $null; Path = $null; Format = $(if ($qemuImg) { 'qcow2' } else { $null })
                                  Bytes = $null; VhdxBytes = $null; Ratio = $null; Sha256 = $null }
    }

    # ── 1. capture ──────────────────────────────────────────────────────────────
    Write-WcnInfo ("disk2vhd: capturing C: -> {0}" -f $vhdx)
    Write-WcnLine '        This is the long one. Do not lock the screen and do not close this window —' 'DarkGray'
    Write-WcnLine '        disk2vhd needs an interactive desktop and will hang without one.' 'DarkGray'
    try { & $disk2vhd 'c:' $vhdx -accepteula }
    catch { return (& $fail ("disk2vhd failed: {0}" -f $_.Exception.Message)) }
    if (-not (Test-Path -LiteralPath $vhdx)) {
        return (& $fail 'disk2vhd produced no file — if it appeared to hang, it was run without an interactive desktop')
    }
    $vhdxBytes = (Get-Item -LiteralPath $vhdx).Length
    Write-WcnOk ("captured: {0}" -f (Format-WcnGB $vhdxBytes))

    # ── 2. convert ──────────────────────────────────────────────────────────────
    $out = $null
    $format = $null

    if ($qemuImg) {
        $out = Join-Path $Scratch ("{0}.qcow2" -f $BaseName)
        $format = 'qcow2'
        Write-WcnInfo 'qemu-img convert -> qcow2, compressed at rest (imports without a decompress step)'
        $converted = $false
        # compression_type=zstd needs qemu 5.1+. An older qemu-img on somebody's USB stick fails
        # ONLY on that option, so the retry drops it and takes zlib rather than failing the run
        # — a slightly larger qcow2 is still a qcow2 the platform can import.
        foreach ($opts in @('compression_type=zstd', $null)) {
            $args = @('convert', '-p', '-O', 'qcow2', '-c')
            if ($opts) { $args += @('-o', $opts) }
            $args += @($vhdx, $out)
            try {
                & $qemuImg @args
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $out)) { $converted = $true; break }
            } catch { }
            if ($opts) { Write-WcnWarn 'this qemu-img does not support compression_type=zstd — falling back to its default compression' }
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
        if (-not $converted) {
            Write-WcnWarn 'the qcow2 conversion failed'
            $out = $null; $format = $null
        }
    }

    if (-not $out -and $zstd) {
        # ── THE FALLBACK: the old kit's proven pipeline, and it is announced as a fallback ────
        $out = "$vhdx.zst"
        $format = $null    # NOT in captureToken.IMAGE_FORMATS — reported as unknown, never mislabelled
        Write-WcnWarn 'FALLBACK PIPELINE: producing .vhdx.zst instead of .qcow2'
        Write-WcnWarn 'The platform''s format list is qcow2|raw|vmdk, so this artefact will be registered'
        Write-WcnWarn 'WITHOUT a format and somebody will have to decompress and convert it by hand.'
        Write-WcnWarn 'Stage qemu-img.exe on the kit to avoid this.'
        Write-WcnInfo ("zstd --ultra -{0} --long=31 -T0 -> {1}" -f $Level, $out)
        # --long=31 is a 2 GB window, which is what finds redundancy across a whole Windows image
        # rather than within a few megabytes of it; -T0 uses every core; -22 needs --ultra.
        $zargs = @()
        if ($Level -gt 19) { $zargs += '--ultra' }
        $zargs += @("-$Level", '--long=31', '-T0', '-f', $vhdx, '-o', $out)
        try { & $zstd @zargs } catch { return (& $fail ("zstd failed: {0}" -f $_.Exception.Message)) }
        if (-not (Test-Path -LiteralPath $out)) { return (& $fail 'zstd produced no output file') }
    }

    if (-not $out) { return (& $fail 'no converter succeeded — the VHDX is kept on the scratch drive for a manual retry') }

    # ── 3. ⭐ VERIFY BEFORE DELETING THE ONLY OTHER COPY ────────────────────────
    # Skipping this and deleting the VHDX on the strength of "the output file exists" is how a
    # truncated archive becomes the only artefact from a ninety-minute run.
    Write-WcnInfo 'verifying the converted image'
    $verified = $false
    try {
        if ($format -eq 'qcow2') {
            & $qemuImg 'check' $out
            # 0 = no errors; 3 = leaked clusters only, which is not corruption and imports fine.
            $verified = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3)
        } else {
            & $zstd '-t' '--long=31' $out
            $verified = ($LASTEXITCODE -eq 0)
        }
    } catch { $verified = $false }

    $bytes = (Get-Item -LiteralPath $out).Length
    $ratio = $(if ($bytes -gt 0) { [math]::Round($vhdxBytes / $bytes, 2) } else { $null })

    if (-not $verified) {
        Write-WcnFail 'the converted image FAILED verification — the VHDX is being kept so it can be retried'
        return [pscustomobject]@{ Ok = $false; Error = 'the converted image did not verify'; Path = $out
                                  Format = $format; Bytes = $bytes; VhdxBytes = $vhdxBytes; Ratio = $ratio; Sha256 = $null }
    }
    Write-WcnOk ("converted and verified: {0}  ({1}, ratio {2}x)" -f (Format-WcnGB $bytes), $(if ($format) { $format } else { 'vhdx.zst' }), $ratio)

    $sha = $null
    if (-not $SkipHash) { $sha = Get-WcnFileSha256 -Path $out }

    if (-not $KeepVhdx) {
        Remove-Item -LiteralPath $vhdx -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $vhdx)) { Write-WcnInfo ("removed the intermediate VHDX, freeing {0} of scratch" -f (Format-WcnGB $vhdxBytes)) }
    }

    return [pscustomobject]@{
        Ok = $true; Error = $null; Path = $out; Format = $format
        Bytes = $bytes; VhdxBytes = $vhdxBytes; Ratio = $ratio; Sha256 = $sha
    }
}
