# Stage-GuestAgent.ps1 — the QEMU guest agent and virtio drivers. REQUIRED, and VERIFIED.
#
# ⛔ WHY THIS IS NO LONGER OPTIONAL. Strip-PmrImage.ps1 installs virtio-win-guest-tools in its A0
# stage, which works — it is Red Hat / WHQL-signed so EDR does not flag it. But it sits behind
# -SkipGuestTools, and when it fails it writes a yellow line and carries on:
#
#     } catch { Write-Host "  guest-tools install skipped/failed: ..." -ForegroundColor Yellow }
#
# Three VMs in this estate have no guest agent. That is not a coincidence; it is this catch
# block. And the cost is not theoretical: without the agent, `qm guest exec` cannot reach the VM,
# so every subsequent operation on that site needs an engineer physically at the pharmacy. It
# has already cost three visits.
#
# ⭐ AND THIS IS PRECISELY WHY A HUMAN IS STANDING HERE. The virtio driver package triggers
# Windows' driver-publisher trust prompt. A person can answer it. An unattended run cannot —
# which is the real reason a silent install fails, and the reason the agreed baseline calls the
# guest agent install "the point of a human being there". The tool therefore waits, tells the
# operator exactly what to expect, and then CHECKS.
#
# ⚠️ THE CHECK IS THE SERVICE STATE, NOT THE INSTALLER'S EXIT CODE. virtio-win-guest-tools
# returns 0 for "installed the drivers, and the agent did not start". Only Get-Service answers
# the question that matters.

Set-StrictMode -Version 2.0

# Names the QEMU guest agent service has shipped under. QEMU-GA is current; the other two appear
# on older virtio-win builds that are still in circulation on engineers' USB sticks.
$script:WcnGuestAgentServices = @('QEMU-GA', 'QEMU Guest Agent', 'qemu-ga')

function Get-WcnGuestAgentState {
    <#
      Returns @{ Present; Running; ServiceName; Status; Version }. Never throws.
      Present without Running is the exact state that produced the three engineer visits: the
      package is installed, the service exists, and it is stopped or disabled.
    #>
    foreach ($n in $script:WcnGuestAgentServices) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) { $svc = Get-Service -DisplayName $n -ErrorAction SilentlyContinue }
        if ($svc) {
            $ver = $null
            try {
                $ver = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -match 'virtio-win|QEMU guest agent' } |
                        Select-Object -First 1 -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue)
            } catch { }
            return [pscustomobject]@{
                Present = $true
                Running = ($svc.Status -eq 'Running')
                ServiceName = $svc.Name
                Status = [string]$svc.Status
                Version = $ver
            }
        }
    }
    return [pscustomobject]@{ Present = $false; Running = $false; ServiceName = $null; Status = 'absent'; Version = $null }
}

function Install-WcnGuestAgent {
    <#
      Returns @{ Ok; Installed; State; Note }.

      Ok = $false is a REFUSAL the orchestrator acts on. An image without the agent costs a site
      an engineer visit later, and the whole reason to be standing here at 11pm is to spend the
      five minutes now instead of the two-hour round trip then.

      -InstallerPath points at a virtio-win-guest-tools.exe staged on the USB. Prefer it: a
      pharmacy line downloading a 60 MB installer out of hours is slow, and the kit is on a USB
      stick that can carry it. The download is the fallback, not the plan.
    #>
    param(
        [string]$InstallerPath,
        [string]$Url = 'https://fedorapeople.org/groups/virtio-win/direct-downloads/stable-virtio/virtio-win-guest-tools.exe',
        [switch]$DryRun,
        [int]$ServiceWaitSeconds = 90
    )

    $state = Get-WcnGuestAgentState
    if ($state.Present -and $state.Running) {
        Write-WcnOk ("the QEMU guest agent is already installed and running (service {0}{1})" -f $state.ServiceName, $(if ($state.Version) { ", v$($state.Version)" } else { '' }))
        return [pscustomobject]@{ Ok = $true; Installed = $false; State = $state; Note = 'already present and running' }
    }
    if ($state.Present -and -not $state.Running) {
        Write-WcnWarn ("the guest agent is installed but the service is {0} — trying to start it before reinstalling" -f $state.Status)
        try {
            Set-Service -Name $state.ServiceName -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $state.ServiceName -ErrorAction Stop
            Start-Sleep -Seconds 3
            $state = Get-WcnGuestAgentState
            if ($state.Running) {
                Write-WcnOk 'the guest agent service is now running'
                return [pscustomobject]@{ Ok = $true; Installed = $false; State = $state; Note = 'started an already-installed agent' }
            }
        } catch { Write-WcnWarn ("could not start it: {0}" -f $_.Exception.Message) }
    }

    if ($DryRun) {
        Write-WcnWarn 'DRY RUN: the guest tools would be installed here, and this run would REFUSE to continue if the service were not running afterwards'
        return [pscustomobject]@{ Ok = $true; Installed = $false; State = $state; Note = 'dry run — not installed' }
    }

    # ── locate the installer ────────────────────────────────────────────────────
    $exe = $null
    if ($InstallerPath -and (Test-Path -LiteralPath $InstallerPath)) {
        $exe = (Resolve-Path -LiteralPath $InstallerPath).Path
        Write-WcnInfo ("using the staged installer: {0}" -f $exe)
    } else {
        Write-WcnInfo 'no installer staged on the kit — downloading virtio-win-guest-tools'
        Write-WcnLine '        (Red Hat / WHQL-signed, which is why EDR does not flag it)' 'DarkGray'
        $exe = Join-Path $env:TEMP 'virtio-win-guest-tools.exe'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $Url -OutFile $exe -UseBasicParsing -ErrorAction Stop
        } catch {
            return [pscustomobject]@{
                Ok = $false; Installed = $false; State = (Get-WcnGuestAgentState)
                Note = ("the guest tools could not be downloaded ({0}) and none was staged on the kit. Stage virtio-win-guest-tools.exe next to the kit and run again." -f $_.Exception.Message)
            }
        }
    }

    # ── ⭐ the trust prompt: the reason a person is here ─────────────────────────
    Write-WcnLine ''
    Write-WcnLine '   ┌────────────────────────────────────────────────────────────────────┐' 'Cyan'
    Write-WcnLine '   │  WATCH THE SCREEN. Windows will ask whether to trust drivers from   │' 'Cyan'
    Write-WcnLine '   │  "Red Hat, Inc." — ANSWER INSTALL. Nothing else in this run needs   │' 'Cyan'
    Write-WcnLine '   │  you, and an unanswered prompt is why three sites have no agent.    │' 'Cyan'
    Write-WcnLine '   └────────────────────────────────────────────────────────────────────┘' 'Cyan'
    Write-WcnLine ''

    # /passive, NOT /quiet: passive shows a progress bar and still surfaces the driver-trust
    # dialog for the human to answer. /quiet suppresses it, the drivers stage unsigned-trusted
    # or fail, and this is exactly how the silent install produced agent-less VMs.
    try {
        $p = Start-Process -FilePath $exe -ArgumentList '/install', '/passive', '/norestart' -PassThru -Wait -ErrorAction Stop
        Write-WcnInfo ("installer exit code {0}" -f $p.ExitCode)
    } catch {
        return [pscustomobject]@{ Ok = $false; Installed = $false; State = (Get-WcnGuestAgentState)
                                  Note = ("the installer would not run: {0}" -f $_.Exception.Message) }
    }

    # ── ⭐ VERIFY. The exit code is not the answer. ──────────────────────────────
    Write-WcnInfo ("waiting up to {0}s for the guest agent service to come up" -f $ServiceWaitSeconds)
    $deadline = (Get-Date).AddSeconds($ServiceWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = Get-WcnGuestAgentState
        if ($state.Running) { break }
        if ($state.Present -and -not $state.Running) {
            try { Set-Service -Name $state.ServiceName -StartupType Automatic -ErrorAction SilentlyContinue
                  Start-Service -Name $state.ServiceName -ErrorAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 5
    }
    $state = Get-WcnGuestAgentState

    if ($state.Running) {
        Write-WcnOk ("guest agent installed and RUNNING (service {0})" -f $state.ServiceName)
        return [pscustomobject]@{ Ok = $true; Installed = $true; State = $state; Note = 'installed and verified running' }
    }

    $why = if ($state.Present) {
        ("the agent is installed but its service is {0}, not Running" -f $state.Status)
    } else {
        'the guest agent service does not exist after the install — the driver trust prompt was most likely dismissed'
    }
    return [pscustomobject]@{ Ok = $false; Installed = $false; State = $state; Note = $why }
}
