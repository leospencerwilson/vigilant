# Stage-Upload.ps1 — resumable, to a destination the SERVER names.
#
# ⛔ THERE IS NO DEFAULT DESTINATION IN THIS FILE AND THERE MUST NEVER BE ONE. The old kit had
#
#     [string]$UploadTarget = "wcn-dreadnaught:/mnt/pve/wcn-shared/p2v-import/"
#     [string]$ProxyJump    = "teleport,wcn-dreadnaught"
#     [string]$IdentityFile = "$PSScriptRoot\wcn_upload"
#
# — three facts about WCN's internal estate compiled into a script that ships to pharmacy PCs on
# a USB stick, next to the private key they refer to. That is a long-lived credential in a
# building we do not control and a map of where to use it, both readable by whoever picks the
# stick up. And the share it names is DEAD: the working target is a directory on a Proxmox
# node's LOCAL storage, which is why the server refuses an nfs/cifs target by name.
#
# ⭐ WHERE THE PATH COMES FROM, AND WHY IT CANNOT COME FROM HERE. Vigilant has no route to the
# Proxmox API — it sits on the DMZ VLAN with no path to the management VLAN, which is why the
# whole Proxmox integration is a collector pushing outward. So the drop directory is reported by
# the NODE ITSELF on the outward call it already makes, stored, and handed back on the register
# response as `upload.path`, already including the filename the SERVER chose. The kit never
# joins a path. When the server names none it says WHY by name — 'no-target-reported',
# 'target-is-network-storage', 'target-short-on-space' — and the kit falls back to the USB it
# runs from, which the baseline explicitly sanctions.
#
# ⭐ RESUMABLE IS NOT OPTIONAL. A 70 GB transfer over a pharmacy line WILL be interrupted — the
# router's overnight reboot, a DSL retrain, somebody unplugging something. The server's contract
# says how: resume.probe = 'stat', resume.append = true. Stat the destination, send from its
# length. Re-registering the same role on the same ticket hands back the SAME path, which is what
# makes a second run continue rather than start again.

Set-StrictMode -Version 2.0

function Write-WcnProgress {
    param([string]$Activity, [int64]$Done, [int64]$Total, [datetime]$Started)
    if ($Total -le 0) { return }
    $pct = [int](100 * $Done / $Total)
    if ($pct -gt 100) { $pct = 100 }
    $el = ((Get-Date) - $Started).TotalSeconds
    $rate = $(if ($el -gt 0) { $Done / $el } else { 0 })
    $eta = $(if ($rate -gt 0) { [TimeSpan]::FromSeconds(($Total - $Done) / $rate).ToString('hh\:mm\:ss') } else { '--:--:--' })
    Write-Progress -Activity $Activity -PercentComplete $pct `
        -Status ("{0} of {1}  ({2:N1} MB/s, ETA {3})" -f (Format-WcnGB $Done), (Format-WcnGB $Total), ($rate / 1MB), $eta)
}

function Invoke-WcnUploadSftp {
    <#
      OpenSSH sftp with `reput` — the resume primitive. It stats the remote file and continues
      from its length, which is exactly the contract the server describes (probe 'stat',
      append true). Chosen over scp (no resume at all) and over rsync (absent on a Windows
      build, and shipping one is another binary to trust on a pharmacy PC). The OpenSSH client
      has been in Windows since 1803, so nothing needs staging.

      ⚠️ THE TRANSPORT CREDENTIAL IS NOT IN THE SERVER'S CONTRACT TODAY. shapeUploadTarget()
      returns node / storage / dir / filename / path and no host, user or key. So this function
      is written against the fields that WOULD carry one and refuses cleanly when they are
      absent — it does not guess a username, invent a hostname from the node name, or fall back
      to an agent key that happens to be loaded. The USB fallback covers the gap, loudly. See
      the note in the kit README.
    #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$Path)

    $sftp = Get-Command 'sftp.exe' -ErrorAction SilentlyContinue
    if (-not $sftp) { return [pscustomobject]@{ Ok = $false; Error = 'the Windows OpenSSH client (sftp.exe) is not installed on this PC' } }

    $host_ = [string](Get-WcnProp $Target 'host')
    $user  = [string](Get-WcnProp $Target 'user')
    $keyText = [string](Get-WcnProp $Target 'credential')
    $hostKey = [string](Get-WcnProp $Target 'host_key')
    $proxyJump = [string](Get-WcnProp $Target 'proxy_jump')
    $remotePath = [string](Get-WcnProp $Target 'path')

    if (-not $host_ -or -not $remotePath) {
        return [pscustomobject]@{ Ok = $false
            Error = 'the server named a drop directory but no transport to reach it (no host/user/credential on the upload target), so this kit will not guess one' }
    }
    # ⛔ StrictHostKeyChecking stays ON. Accepting any key would make the TLS-protected exchange
    # that delivered this destination pointless at the last hop.
    if (-not $hostKey) {
        return [pscustomobject]@{ Ok = $false; Error = 'the upload target pins no ssh host key — refusing to connect blind' }
    }

    $tmpDir = Join-Path $env:LOCALAPPDATA 'wcn-capture'
    if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null }
    $keyPath = Join-Path $tmpDir ('k-{0}' -f ([guid]::NewGuid().ToString('N')))
    $khPath  = Join-Path $tmpDir ('kh-{0}' -f ([guid]::NewGuid().ToString('N')))
    $batch   = Join-Path $tmpDir ('b-{0}.sftp' -f ([guid]::NewGuid().ToString('N')))

    try {
        if ($keyText) {
            # LOCAL profile, never the USB, which travels.
            Set-Content -LiteralPath $keyPath -Value $keyText -Encoding ASCII -NoNewline
            # OpenSSH refuses a key readable by anyone else: strip inheritance, grant only this
            # account. The Windows equivalent of chmod 600.
            & icacls.exe $keyPath /inheritance:r /grant:r ("{0}:R" -f $env:USERNAME) 2>&1 | Out-Null
        }
        Set-Content -LiteralPath $khPath -Value $hostKey -Encoding ASCII

        # `reput` is the resume; `progress` gives sftp's own live bar.
        @('progress', ("reput `"{0}`" `"{1}`"" -f $Path, $remotePath), 'bye') |
            Set-Content -LiteralPath $batch -Encoding ASCII

        $args = @('-b', $batch, '-o', 'StrictHostKeyChecking=yes', '-o', ("UserKnownHostsFile={0}" -f $khPath),
                  '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=6')
        if ($keyText)   { $args += @('-o', 'IdentitiesOnly=yes', '-i', $keyPath) }
        if ($proxyJump) { $args += @('-J', $proxyJump) }
        $args += $(if ($user) { "$user@$host_" } else { $host_ })

        Write-WcnInfo 'uploading over sftp (resumable — a dropped line continues from where it stopped)'
        & $sftp.Source @args
        if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Ok = $false; Error = ("sftp exited {0}" -f $LASTEXITCODE) } }
        return [pscustomobject]@{ Ok = $true; Error = $null }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
    } finally {
        # Shredded whatever happened. A transfer key outliving the transfer is the problem this
        # whole file exists to avoid.
        foreach ($f in @($keyPath, $khPath, $batch)) {
            try {
                if (Test-Path -LiteralPath $f) {
                    $len = (Get-Item -LiteralPath $f).Length
                    if ($len -gt 0) { $j = New-Object byte[] $len; (New-Object System.Random).NextBytes($j); [System.IO.File]::WriteAllBytes($f, $j) }
                    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
    }
}

function Invoke-WcnUploadUsb {
    <#
      Copy to the USB the kit runs from — the baseline's second sanctioned destination, and the
      honest answer for a site whose line will not carry 70 GB in a night.

      robocopy /Z is restartable mode: it records progress inside the destination file and picks
      up mid-file. A genuine resume, not a retry.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$KitRoot, [string]$DestDir)

    $dest = $DestDir
    if (-not $dest -and $KitRoot) { $dest = Join-Path $KitRoot 'captures' }
    if (-not $dest) { return [pscustomobject]@{ Ok = $false; Error = 'no destination directory for a USB copy'; Destination = $null } }
    if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Force -Path $dest | Out-Null }

    $srcDir  = Split-Path -Parent $Path
    $srcName = Split-Path -Leaf   $Path
    if ((Resolve-Path $srcDir).Path -eq (Resolve-Path $dest).Path) {
        Write-WcnOk 'the artefact is already on the destination drive — nothing to copy'
        return [pscustomobject]@{ Ok = $true; Error = $null; Destination = $Path }
    }

    Write-WcnInfo ("copying to {0} (robocopy /Z, restartable)" -f $dest)
    & robocopy.exe $srcDir $dest $srcName /Z /J /NP /R:3 /W:10 | Out-Null
    # robocopy's exit code is a bitmask: < 8 is success, >= 8 is a real failure.
    if ($LASTEXITCODE -ge 8) { return [pscustomobject]@{ Ok = $false; Error = ("robocopy failed with code {0}" -f $LASTEXITCODE); Destination = $null } }
    return [pscustomobject]@{ Ok = $true; Error = $null; Destination = (Join-Path $dest $srcName) }
}

function Invoke-WcnUpload {
    <#
      Returns @{ Ok; Uploaded; BytesSent; Error; Note; Destination }

      Ok = $true with Uploaded = $false is the LEGITIMATE "left on the USB" outcome: the capture
      succeeded, nothing crossed the wire, and the register call is told exactly that — uploaded_at
      stays null, which is the only thing separating "in progress" from "held" on the far end. A
      build checklist must never think an image is held that nobody has.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        $Upload,                 # upload.target from POST /capture/register, or $null
        $UploadRefused,          # { reason, message } when the server named none
        [string]$KitRoot,
        [switch]$DryRun,
        [switch]$ForceUsb
    )

    $size = $(if (Test-Path -LiteralPath $Path) { (Get-Item -LiteralPath $Path).Length } else { 0 })

    if ($DryRun) {
        Write-WcnWarn 'DRY RUN: nothing would be transferred'
        return [pscustomobject]@{ Ok = $true; Uploaded = $false; BytesSent = $null; Error = $null; Note = 'dry run'; Destination = $null }
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Ok = $false; Uploaded = $false; BytesSent = $null
                                  Error = ("there is nothing to upload at {0}" -f $Path); Note = $null; Destination = $null }
    }

    # ── the server named no destination ─────────────────────────────────────────
    if ($null -eq $Upload -or $ForceUsb) {
        if ($UploadRefused) {
            # ⭐ THE SERVER'S OWN SENTENCE, VERBATIM. These are specific and actionable —
            # 'target-is-network-storage' means the documented NFS share is dead and the
            # collector is pointed at the wrong place; 'no-target-reported' means the node's
            # collector has not pushed its drop directory yet. Replacing them with "upload
            # failed" would throw away the only useful part.
            Write-WcnWarn ("Watchman named no upload destination ({0}):" -f (Get-WcnProp $UploadRefused 'reason' 'unknown'))
            Write-WcnLine ("        {0}" -f (Get-WcnProp $UploadRefused 'message' '')) 'Yellow'
        } elseif (-not $ForceUsb) {
            Write-WcnWarn 'Watchman named no upload destination for this capture'
        }
        Write-WcnInfo 'taking the USB road instead — which the baseline explicitly allows'
        $usb = Invoke-WcnUploadUsb -Path $Path -KitRoot $KitRoot
        if (-not $usb.Ok) {
            return [pscustomobject]@{ Ok = $false; Uploaded = $false; BytesSent = $null; Error = $usb.Error
                                      Note = 'the image is still on the scratch drive'; Destination = $null }
        }
        Write-WcnOk ("copied to {0}" -f $usb.Destination)
        # ⚠️ Uploaded = $false ON PURPOSE. It is on a USB stick in an engineer's bag, which is
        # not the same fact as "Watchman holds this image", and the far end must not be told it is.
        return [pscustomobject]@{ Ok = $true; Uploaded = $false; BytesSent = $null; Error = $null
                                  Note = 'copied to the USB the kit runs from — carry it in'; Destination = $usb.Destination }
    }

    # ── the server named one ────────────────────────────────────────────────────
    $kind = [string](Get-WcnProp $Upload 'kind' '')
    $remote = [string](Get-WcnProp $Upload 'path' '')
    Write-WcnInfo ("destination: {0} on {1} ({2})" -f $remote, (Get-WcnProp $Upload 'node' '?'), (Get-WcnProp $Upload 'source' '?'))
    Write-WcnInfo ("size to send: {0}" -f (Format-WcnGB $size))

    if ($kind -ne 'proxmox-drop-dir') {
        # ⛔ A CLOSED ONE-VALUE LIST, AND THE KIT FAILS LOUDLY RATHER THAN IMPROVISING. A future
        # destination kind this version does not implement must not be half-handled.
        Write-WcnWarn ("this kit does not implement upload kind '{0}' — it will not improvise" -f $kind)
        return (Invoke-WcnUpload -Path $Path -Upload $null -UploadRefused `
                    ([pscustomobject]@{ reason = 'unknown-kind'; message = ("the server named upload kind '{0}', which this version of the kit does not implement. Update the kit." -f $kind) }) `
                    -KitRoot $KitRoot -ForceUsb)
    }

    $r = Invoke-WcnUploadSftp -Target $Upload -Path $Path
    if (-not $r.Ok) {
        Write-WcnWarn ("the upload did not complete: {0}" -f $r.Error)
        if ([bool](Get-WcnProp $Upload 'usb_fallback_ok' $true)) {
            Write-WcnInfo 'the server allows the USB fallback — taking it so the evening is not wasted'
            return (Invoke-WcnUpload -Path $Path -Upload $null -UploadRefused `
                        ([pscustomobject]@{ reason = 'transfer-failed'; message = $r.Error }) `
                        -KitRoot $KitRoot -ForceUsb)
        }
        Write-WcnWarn ("the image is intact at {0} — re-running with -Resume continues from where it stopped" -f $Path)
        return [pscustomobject]@{ Ok = $false; Uploaded = $false; BytesSent = $null; Error = $r.Error
                                  Note = 'the artefact is kept for a retry'; Destination = $null }
    }

    Write-WcnOk 'upload complete'
    return [pscustomobject]@{ Ok = $true; Uploaded = $true; BytesSent = $size; Error = $null
                              Note = $null; Destination = $remote }
}
