#Requires -Version 5.1
<#
  Invoke-PmrCapture.ps1 — THE capture tool. There is one, and this is it.
  ═══════════════════════════════════════════════════════════════════════════════════════════
  WCN engineer, out of hours, at a pharmacy PC, with a capture ticket issued from Watchman.

      .\Invoke-PmrCapture.ps1 -Ticket D:\ticket.json            start a capture
      .\Invoke-PmrCapture.ps1 -Resume                           continue after the reboot
      .\Invoke-PmrCapture.ps1 -Ticket D:\ticket.json -DryRun    run every check, change nothing

  ⛔ WHAT WAS DELETED, AND WHY IT IS NOT COMING BACK
  ───────────────────────────────────────────────────────────────────────────────────────────
  -Unattended is gone. A capture is a 30-90 minute destructive operation on the only copy of a
    pharmacy's dispensing system, with the physical PC as the sole rollback. It also cannot
    work: disk2vhd is a GUI-subsystem tool that hangs without an interactive desktop, and the
    VirtIO driver-trust prompt needs a human to answer it. An unattended mode was a switch that
    turned off the last safeguard which is not code.
  -Site is gone, and there is nothing to replace it with. The pharmacy is a property of the
    TICKET; no capture route accepts a site, and POST /capture/register rejects a body that
    names one. A typo cannot file a real pharmacy's image against a site that does not exist,
    because there is no field in which to type it.
  Invoke-PmrImagePrep.ps1 is gone: it was the second orchestrator, and two of them means two
    places for a safety rule to be almost right.
  -Force is gone from every gate. See lib/WcnRefuse.ps1.

  THE PIPELINE
  ───────────────────────────────────────────────────────────────────────────────────────────
    1  identify this PC, redeem the ticket, REFUSE (pre)
    2  confirm the SITE the ticket admits, pick the ROLE from what is free
    3  SQL integrity — clean, or refuse. Unreadable is not clean.
    4  REGISTER: the site is visibly mid-build, and this PC is bound to the run
    5  guest agent — REQUIRED, installed, and verified running
    6  printers — recorded, then all deleted
    7  strip + debloat  (vendor/Strip-PmrImage.ps1, vendor/Remove-Bloat.ps1, unchanged)
    8  REBOOT, so the removed pagefile/hibernation space is genuinely free
    9  REFUSE (resume), SQL after-check, shrink the partition, zero free space
   10  REFUSE (destructive), capture, convert, verify, hash
   11  upload — resumable, to a destination the server named, or the USB
   12  report the outcome, shred the ticket
  ═══════════════════════════════════════════════════════════════════════════════════════════
#>
[CmdletBinding()]
param(
    # The capture ticket from Watchman. The ONLY way a credential enters this kit.
    [string]$Ticket,

    # Where the VHDX and the converted image are written. Must not be C:.
    [string]$Scratch = 'E:\pmrcap',

    # Continue after the reboot. Set automatically by the RunOnce entry.
    [switch]$Resume,

    # Run every refusal and every read-only measurement, change nothing — on this PC or in
    # Watchman. This is the mode to prove the tool in a VM before it is pointed at a pharmacy.
    [switch]$DryRun,

    # virtio-win-guest-tools.exe staged on the USB, so a pharmacy line is not downloading
    # 60 MB at midnight.
    [string]$GuestToolsInstaller,

    # sdelete.exe (Sysinternals) for the zero pass.
    [string]$SdeletePath,

    [int]$CompressionLevel = 22
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ── self-elevate ────────────────────────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host 'Elevating to Administrator...' -ForegroundColor Yellow
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ("`"$PSCommandPath`"")) + $MyInvocation.UnboundArguments
    Start-Process powershell.exe -ArgumentList $relaunch -Verb RunAs
    exit
}

$KitRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
foreach ($f in @('lib\WcnUi.ps1', 'lib\WcnMachine.ps1', 'lib\WcnTicket.ps1', 'lib\WcnWatchman.ps1',
                 'lib\WcnSql.ps1', 'lib\WcnRefuse.ps1',
                 'stages\Stage-Printers.ps1', 'stages\Stage-GuestAgent.ps1', 'stages\Stage-Shrink.ps1',
                 'stages\Stage-Capture.ps1', 'stages\Stage-Upload.ps1')) {
    $p = Join-Path $KitRoot $f
    if (-not (Test-Path $p)) { Write-Host "kit file missing: $f — copy the WHOLE capture folder to the USB" -ForegroundColor Red; exit 1 }
    . $p
}

$WorkDir   = 'C:\wcn-imageprep'
$StatePath = Join-Path $WorkDir 'capture-state.json'
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null }
Start-WcnLog -Path (Join-Path $WorkDir ('capture-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))

# ── state across the reboot ─────────────────────────────────────────────────────────────────
# ⛔ NEITHER SECRET IS WRITTEN HERE. Not the ticket, not the minted token. The state file records
# the ticket's PATH, and the resume re-reads it from the USB and redeems again — which is what
# the ticket's redemption budget exists for. A secret in a file on C: outlives the run, the
# engineer and the visit; a secret on the USB leaves with the engineer and is shredded at the end.
function Save-WcnState { param($State) ($State | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $StatePath -Encoding UTF8 }
function Load-WcnState {
    if (-not (Test-Path $StatePath)) { return $null }
    try { return (Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json) } catch { return $null }
}

$state = Load-WcnState
$machine = Get-WcnMachineIdentity

try { Clear-Host } catch { }
Write-WcnBanner 'WCN  ·  PMR SITE CAPTURE'
Write-WcnLine ("   machine : {0}" -f (Format-WcnMachine $machine)) 'DarkGray'
Write-WcnLine ("   time    : {0}  (local)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm')) 'DarkGray'
if ($DryRun) {
    Write-WcnLine ''
    Write-WcnLine '   +----------------------------------------------------------------+' 'Magenta'
    Write-WcnLine '   |  DRY RUN — every check runs. Nothing is changed on this PC or   |' 'Magenta'
    Write-WcnLine '   |  in Watchman.                                                  |' 'Magenta'
    Write-WcnLine '   +----------------------------------------------------------------+' 'Magenta'
}

# ── resolve the ticket ──────────────────────────────────────────────────────────────────────
$ticketPath = $Ticket
if (-not $ticketPath -and $state -and $state.PSObject.Properties['ticketPath']) { $ticketPath = [string]$state.ticketPath }
if (-not $ticketPath) {
    # Convenience only, and it looks beside the KIT — never anywhere on C:.
    $guess = Get-ChildItem -Path $KitRoot -Filter '*ticket*.json' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($guess) { $ticketPath = $guess.FullName; Write-WcnInfo ("using the ticket found beside the kit: {0}" -f $ticketPath) }
}
$tk = if ($ticketPath) { Read-WcnTicket -Path $ticketPath }
      else { [pscustomobject]@{ Ok = $false; Error = 'no ticket supplied — pass -Ticket <the file Watchman issued>'; Path = $null } }
if ($tk.Ok -and $tk.IssuedTo) { Write-WcnLine ("   ticket  : issued to {0}" -f $tk.IssuedTo) 'DarkGray' }

$session = New-WcnSession -Ticket $tk

function Show-WcnTicketBudget {
    if (-not $session.Token) { return }
    Write-WcnLine ("   token   : valid to {0}   |   ticket redemptions {1}/{2}, ticket dies {3}" -f `
        $session.TokenExpiresAt, $session.RedeemCount, $session.RedeemMax, $session.TicketExpiresAt) 'DarkGray'
    Write-WcnLine  '             (the ticket dies when this pharmacy reopens — that IS the out-of-hours rule)' 'DarkGray'
}

# ═════════════════════════════════════════════════════════════════════════════════════════════
# THE RESUME PATH
# ═════════════════════════════════════════════════════════════════════════════════════════════
$isResume = ($Resume -or ($state -and $state.PSObject.Properties['phase'] -and [string]$state.phase -eq 'rebooted'))

if ($isResume) {
    if (-not $state) { Write-WcnFail 'there is no capture in progress on this PC — nothing to resume'; exit 1 }

    # ⛔ ONLY A REBOOTED RUN MAY RESUME. A run that died at phase 'registered' never got through
    # the strip, the debloat or the reboot. Resuming would jump straight to shrink and capture
    # and quietly produce a full-fat image that LOOKS finished — the strip silently skipped, and
    # nothing in the artefact to say so. There is no safe automatic repair, so it goes to a person.
    $phase = [string](Get-WcnProp $state 'phase' '')
    if ($phase -ne 'rebooted') {
        Write-WcnFail ("this capture stopped at '{0}', before the reboot — it cannot be resumed from here." -f $phase)
        Write-WcnLine  '        The strip and debloat did not complete, so resuming would capture an unstripped' 'Yellow'
        Write-WcnLine  '        PC and file it as a finished image. Printers may already have been deleted.' 'Yellow'
        Write-WcnLine  ''
        Write-WcnLine  '        Withdraw this attempt in Watchman, delete the state file, and start again:' 'Gray'
        Write-WcnLine ("          Remove-Item '{0}'" -f $StatePath) 'Cyan'
        exit 1
    }

    Write-WcnBanner ("RESUMING  ·  {0}  ·  {1}" -f $state.pharmacyCode, $state.role)
    $Scratch = [string]$state.scratch
    $role    = [string]$state.role
    $roleKind = $(if ($role -eq 'server') { 'server' } else { 'client' })

    # ⭐ THE FULL TABLE AGAIN, INCLUDING THE MACHINE BINDING. The whole point of re-running it is
    # that the world moved while the machine rebooted: the pharmacy may have opened (which kills
    # the ticket by arithmetic), and the USB may be in a different PC.
    $refusals = @(Test-WcnCaptureRefusals -Gate 'resume' -Session $session -Machine $machine `
                    -Scratch $Scratch -Role $role -BoundFingerprint ([string]$state.fingerprint))
    if ($refusals.Count -gt 0) { Write-WcnRefusals -Refusals $refusals -Gate 'resume'; exit 2 }
    Show-WcnTicketBudget
    Write-WcnOk 'all resume checks passed'

    # Everything the report will carry, read back from the state the pre-reboot half wrote.
    # ⚠️ TRI-STATES COME BACK AS $true / $false / $null AND ARE NOT COERCED ANYWHERE BELOW.
    $agentTri   = $null; if ($state.PSObject.Properties['guestAgentInstalled']) { $agentTri   = $state.guestAgentInstalled }
    $printerTri = $null; if ($state.PSObject.Properties['printersCleared'])     { $printerTri = $state.printersCleared }

    # A helper so every failure exit reports rather than going quiet. An abandoned capture that
    # told nobody leaves the site reading "mid-build" forever, and the next engineer cannot tell
    # that from one genuinely in progress.
    function Report-WcnFailure {
        param([string]$Why)
        try {
            Register-WcnCapture -Session $session -Role $role -Machine $machine `
                -StartedAt ([string]$state.startedAt) -GuestAgentInstalled $agentTri `
                -PrintersCleared $printerTri -Slimmed $null -FailedReason $Why | Out-Null
        } catch { }
    }

    # ── SQL after-check ─────────────────────────────────────────────────────────────────────
    Write-WcnBanner 'STEP 9a  ·  DATABASE INTEGRITY AFTER THE STRIP'
    $sqlAfter = Test-WcnSqlIntegrity
    Write-WcnSqlReport -Label 'after' -Result $sqlAfter
    $accept = Test-WcnSqlAcceptable -Result $sqlAfter -Role $roleKind
    if (-not $accept.Pass) {
        Write-WcnFail ("REFUSED: {0}" -f $accept.Reason)
        Write-WcnFail 'do NOT capture this image. Restore from a known-good copy and investigate.'
        Report-WcnFailure ("SQL after strip: {0}" -f $accept.Reason)
        exit 3
    }
    if ($state.PSObject.Properties['sqlBefore'] -and $state.sqlBefore) {
        $cmp = Compare-WcnSqlAfter -Before $state.sqlBefore -After $sqlAfter
        if (-not $cmp.Pass) {
            foreach ($pr in $cmp.Problems) { Write-WcnFail $pr }
            Report-WcnFailure 'SQL integrity regressed across the strip'
            exit 3
        }
    }
    Write-WcnOk 'database integrity is unchanged across the strip'

    # ── shrink, then zero ───────────────────────────────────────────────────────────────────
    # ⭐ SHRINK BEFORE ZERO, and shrink at all: disk2vhd sizes the VHDX from the VOLUME, so
    # shrinking C: from 250 GB to 90 GB means the captured virtual disk IS 90 GB. Compression
    # only hides a big disk in transit; the pool allocates for the declared size on import.
    Write-WcnBanner 'STEP 9b  ·  SHRINK THE PARTITION'
    $shrink = Invoke-WcnPartitionShrink
    Write-WcnBanner 'STEP 9c  ·  ZERO FREE SPACE'
    $zero = Invoke-WcnZeroFreeSpace -SdeletePath $SdeletePath

    # ── the last refusal before the point of no return ──────────────────────────────────────
    Write-WcnBanner 'STEP 10  ·  FINAL CHECK, THEN CAPTURE'
    $refusals = @(Test-WcnCaptureRefusals -Gate 'destructive' -Session $session -Machine $machine `
                    -Scratch $Scratch -Role $role -BoundFingerprint ([string]$state.fingerprint))
    if ($refusals.Count -gt 0) {
        Write-WcnRefusals -Refusals $refusals -Gate 'destructive'
        Report-WcnFailure ("refused at the final gate: {0}" -f $refusals[0].Id)
        exit 2
    }

    $baseName = ('{0}-{1}' -f ([string]$state.pharmacyCode), $role)
    $cap = Invoke-WcnCapture -Scratch $Scratch -BaseName $baseName -KitRoot $KitRoot -Level $CompressionLevel
    if (-not $cap.Ok) {
        Write-WcnFail ("capture failed: {0}" -f $cap.Error)
        Report-WcnFailure $cap.Error
        exit 4
    }

    # ── re-register: records the image, and is handed the upload path ───────────────────────
    # ⭐ REGISTER IS AN UPSERT, WHICH IS WHAT MAKES A RESUME WORK. The same ticket registering the
    # same role updates its own row and is handed the SAME path back, so a broken 70 GB transfer
    # continues instead of starting again. It is also where the short-lived destination is
    # refreshed: 30-90 minutes have passed since the first registration.
    Write-WcnBanner 'STEP 11  ·  UPLOAD'
    $diskGb = $null
    if ($shrink.AfterBytes) { $diskGb = [math]::Round($shrink.AfterBytes / 1GB, 2) }

    $reReg = Register-WcnCapture -Session $session -Role $role -Machine $machine `
                -StartedAt ([string]$state.startedAt) -DiskGB $diskGb `
                -ImageFormat $cap.Format -ImageSha256 $cap.Sha256 -BytesTotal $cap.Bytes `
                -GuestAgentInstalled $agentTri -PrintersCleared $printerTri `
                -Slimmed ($shrink.Outcome -in @('shrunk', 'at-minimum'))
    if (-not $reReg.Ok) {
        Write-WcnWarn ("could not refresh the registration: {0}" -f $reReg.Error)
        Write-WcnWarn ("the image is intact at {0} — fix the connection and re-run with -Resume" -f $cap.Path)
        exit 5
    }

    $up = Invoke-WcnUpload -Path $cap.Path -Upload $reReg.Upload -UploadRefused $reReg.UploadRefused -KitRoot $KitRoot

    # Carry the printer provenance next to the artefact so the two travel together.
    if ($state.PSObject.Properties['printersProvenance'] -and $state.printersProvenance -and (Test-Path -LiteralPath ([string]$state.printersProvenance))) {
        try { Copy-Item -LiteralPath ([string]$state.printersProvenance) -Destination (Join-Path $Scratch ("{0}.printers.json" -f $baseName)) -Force } catch { }
    }

    # ── the final report ────────────────────────────────────────────────────────────────────
    Write-WcnBanner 'STEP 12  ·  REPORT TO WATCHMAN'
    # ⚠️ uploaded_at IS SET ONLY IF IT ACTUALLY CROSSED THE WIRE. (started_at, uploaded_at) is
    # the only thing separating "in progress" from "held" on the far end, and a build checklist
    # must never think an image is held that is in fact on a USB stick in somebody's bag.
    $final = Register-WcnCapture -Session $session -Role $role -Machine $machine `
                -StartedAt ([string]$state.startedAt) `
                -UploadedAt $(if ($up.Uploaded) { (Get-Date).ToUniversalTime().ToString('o') } else { $null }) `
                -DiskGB $diskGb -ImageFormat $cap.Format -ImageSha256 $cap.Sha256 `
                -BytesTotal $cap.Bytes -BytesSent $up.BytesSent `
                -GuestAgentInstalled $agentTri -PrintersCleared $printerTri `
                -Slimmed ($shrink.Outcome -in @('shrunk', 'at-minimum')) `
                -FailedReason $up.Error
    if ($final.Ok) { Write-WcnOk 'Watchman has the outcome' }
    else { Write-WcnWarn ("could not report to Watchman: {0} — the artefact is safe on the scratch drive" -f $final.Error) }

    # ── summary ─────────────────────────────────────────────────────────────────────────────
    Write-WcnBanner 'DONE'
    Write-WcnRule
    Write-WcnLine ("   Site        : {0}  ({1})" -f $state.pharmacyCode, $state.pharmacyName) 'White'
    Write-WcnLine ("   Role        : {0}" -f $role) 'White'
    Write-WcnLine ("   Source PC   : {0}   [provenance only — never a key]" -f $machine.Hostname) 'DarkGray'
    Write-WcnLine ("   Partition   : {0} -> {1}   ({2})" -f (Format-WcnGB $shrink.BeforeBytes), (Format-WcnGB $shrink.AfterBytes), $shrink.Outcome) `
        $(if ($shrink.Outcome -in @('shrunk', 'at-minimum')) { 'Green' } else { 'Yellow' })
    foreach ($b in @($shrink.Blockers)) { Write-WcnLine ("                 blocker: {0}" -f $b) 'Yellow' }
    Write-WcnLine ("   Image       : {0} -> {1}  (x{2}, {3})" -f (Format-WcnGB $cap.VhdxBytes), (Format-WcnGB $cap.Bytes), $cap.Ratio, $(if ($cap.Format) { $cap.Format } else { 'vhdx.zst — NOT a platform format' })) `
        $(if ($cap.Format) { 'Green' } else { 'Yellow' })
    Write-WcnLine ("   Artefact    : {0}" -f $cap.Path) 'Green'
    Write-WcnLine ("   Guest agent : {0}" -f $(if ($agentTri -eq $true) { 'installed and running' } elseif ($agentTri -eq $false) { 'NOT INSTALLED' } else { 'not established' })) `
        $(if ($agentTri -eq $true) { 'Green' } else { 'Yellow' })
    Write-WcnLine ("   Printers    : {0}" -f $(if ($printerTri -eq $true) { 'all deleted' } elseif ($printerTri -eq $false) { 'SOME REMAIN' } else { 'not established' })) `
        $(if ($printerTri -eq $true) { 'Green' } else { 'Yellow' })
    Write-WcnLine ("   Uploaded    : {0}" -f $(if ($up.Uploaded) { $up.Destination } else { ("NO — {0}" -f $up.Note) })) $(if ($up.Uploaded) { 'Green' } else { 'Yellow' })
    Write-WcnRule

    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    if ($ticketPath -and (Remove-WcnTicket -Path $ticketPath)) { Write-WcnInfo 'the capture ticket has been shredded' }
    else { Write-WcnWarn 'the ticket could not be deleted — remove it from the USB by hand' }
    Write-Progress -Activity 'PMR capture' -Completed
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════════════════════
# THE FIRST-RUN PATH
# ═════════════════════════════════════════════════════════════════════════════════════════════
if ($state) {
    Write-WcnWarn 'a capture is already in progress on this PC:'
    Write-WcnLine ("        {0} / {1}, started {2}" -f $state.pharmacyCode, $state.role, $state.startedAt) 'Yellow'
    Write-WcnWarn 'starting again would strip this machine a second time. Use -Resume to continue it.'
    exit 1
}

# ── STEP 1 · refuse before acting ───────────────────────────────────────────────────────────
Write-WcnBanner 'STEP 1  ·  CHECKS'
$refusals = @(Test-WcnCaptureRefusals -Gate 'pre' -Session $session -Machine $machine -Scratch $Scratch)
if ($refusals.Count -gt 0) { Write-WcnRefusals -Refusals $refusals -Gate 'pre'; exit 2 }
Show-WcnTicketBudget
Write-WcnOk 'ticket redeemed, token scoped correctly, this PC identified, scratch big enough'

# ── STEP 2 · the site (confirmed) and the role (picked) ─────────────────────────────────────
Write-WcnBanner 'STEP 2  ·  SITE AND ROLE'
$sitesR = Get-WcnCaptureSite -Session $session
if (-not $sitesR.Ok) { Write-WcnFail ("could not read the site: {0}" -f $sitesR.Error); exit 2 }
if (@($sitesR.Sites).Count -eq 0) {
    Write-WcnFail 'this ticket admits no site — the pharmacy it was issued for no longer exists in Watchman'
    exit 2
}

# ⭐ CONFIRMED, NOT TYPED. The ticket already decided which pharmacy this is; the picker exists
# so a human looks at the name and the address before a destructive run, not so they can choose.
$site = Read-WcnChoice -Items @($sitesR.Sites) -Prompt 'is this the site you are standing in?' `
    -Label { param($s) ("{0}  —  {1}   [{2}]   {3}" -f (Get-WcnProp $s 'code'), (Get-WcnProp $s 'name'), (Get-WcnProp $s 'status'), (Get-WcnProp $s 'subnet' '')) }
if (-not $site) { Write-WcnWarn 'cancelled — nothing has been changed'; exit 0 }

$slotsR = Get-WcnCaptureSlots -Session $session
if (-not $slotsR.Ok) { Write-WcnFail ("could not read this site's slots: {0}" -f $slotsR.Error); exit 2 }

# ⭐ ONE PICKER, NOT TWO BOOLEANS: 'server', or 'client-01'..'client-10'. The list of roles comes
# from the SERVER (captureToken.ROLE_VALUES), so the kit cannot invent an eleventh client — ten,
# because a /27 site addresses its desktops at .11-.20 and that is exactly the addressable range.
# Each slot carries the address it would land on, so ".13" is visible beside client-03 and a
# mis-pick is not silent.
$chosen = Read-WcnChoice -Items @($slotsR.Slots) -Prompt 'which role is this PC?' `
    -Label { param($s)
        $addr = [string](Get-WcnProp $s 'address' '')
        $lbl  = [string](Get-WcnProp $s 'counter_label' '')
        $by   = @(Get-WcnProp $s 'taken_by' @())
        ("{0,-10} {1,-16} {2}{3}" -f (Get-WcnProp $s 'role'), $addr, $lbl,
            $(if ([bool](Get-WcnProp $s 'taken' $false)) { ("   [TAKEN: {0}]" -f ($by -join ',')) } else { '' }))
    } `
    -Selectable { param($s) (-not [bool](Get-WcnProp $s 'taken' $false)) }
if (-not $chosen) { Write-WcnWarn 'cancelled — nothing has been changed'; exit 0 }

$role = [string](Get-WcnProp $chosen 'role')
$roleKind = [string](Get-WcnProp $chosen 'kind' $(if ($role -eq 'server') { 'server' } else { 'client' }))

# ── STEP 3 · SQL integrity. Unreadable is NOT clean. ────────────────────────────────────────
Write-WcnBanner 'STEP 3  ·  DATABASE INTEGRITY'
Write-WcnInfo 'DBCC CHECKDB (PHYSICAL_ONLY) on every online user database — this can take a few minutes'
$sqlBefore = Test-WcnSqlIntegrity
Write-WcnSqlReport -Label 'before' -Result $sqlBefore

# ── the whole table again, now that the role and the SQL verdict exist ──────────────────────
$refusals = @(Test-WcnCaptureRefusals -Gate 'pre' -Session $session -Machine $machine `
                -Scratch $Scratch -Role $role -SqlResult $sqlBefore -SqlRoleKind $roleKind)
if ($refusals.Count -gt 0) { Write-WcnRefusals -Refusals $refusals -Gate 'pre'; exit 2 }
Write-WcnOk 'every check passed'

# ── the consent ─────────────────────────────────────────────────────────────────────────────
Write-WcnBanner 'WHAT IS ABOUT TO HAPPEN'
Write-WcnLine ("   Site         : {0}  —  {1}" -f (Get-WcnProp $site 'code'), (Get-WcnProp $site 'name')) 'White'
Write-WcnLine ("   Role         : {0}   ->  {1}" -f $role, (Get-WcnProp $chosen 'address' '')) 'White'
Write-WcnLine ("   This PC      : {0}   (recorded as provenance, never as a key)" -f $machine.Hostname) 'DarkGray'
Write-WcnLine ''
Write-WcnLine '   1) install the QEMU guest agent  — you WILL be asked to trust Red Hat drivers' 'Gray'
Write-WcnLine '   2) DELETE EVERY PRINTER on this PC (recorded first, and recoverable)' 'Yellow'
Write-WcnLine '   3) strip Windows and remove non-ProScript software' 'Gray'
Write-WcnLine '   4) REBOOT this PC' 'Yellow'
Write-WcnLine '   5) shrink C:, zero the free space, capture and convert the disk' 'Gray'
Write-WcnLine '   6) upload the image, or leave it on the USB' 'Gray'
Write-WcnLine ''
Write-WcnLine '   ProScript, EMIS, the SQL engine and its data, NHS smartcard middleware and the' 'Green'
Write-WcnLine '   .NET/VC++ runtimes are hard-protected throughout and are never touched.' 'Green'
Write-WcnLine ''
Write-WcnLine '   This takes 30-90 minutes and CANNOT be undone. The only rollback is this PC itself.' 'Red'

if ($DryRun) {
    # ⭐ THE DRY RUN STOPS HERE, BEFORE REGISTERING. A registration is server state — it marks the
    # site mid-build and claims the role slot — so a rehearsal must not create one. It stops
    # having done every READ, which is worth something: below are the two facts an engineer
    # actually wants before committing an evening to this PC.
    Write-WcnBanner 'DRY RUN  ·  WHAT THIS PC WOULD LOOK LIKE'
    $dryPrinters = Get-WcnPrinterInventory
    if ($dryPrinters.readable) {
        Write-WcnLine ("   printers that would be DELETED: {0}" -f @($dryPrinters.printers).Count) 'Yellow'
        foreach ($pr in $dryPrinters.printers) {
            Write-WcnLine ("        {0}  ->  {1}{2}" -f $pr.name, $pr.port_name, $(if ($pr.is_default) { '   (DEFAULT)' } else { '' })) 'DarkGray'
        }
    } else { Write-WcnWarn ("the print spooler could not be read: {0}" -f $dryPrinters.error) }

    Write-WcnLine ''
    Write-WcnLine '   Shrink projection — PESSIMISTIC, deliberately: the pagefile, hibernation file,' 'DarkGray'
    Write-WcnLine '   shadow copies and WinRE image are all still here and all still pinning the shrink' 'DarkGray'
    Write-WcnLine '   point. A real run removes them and reboots first, so it gets further.' 'DarkGray'
    $null = Invoke-WcnPartitionShrink -DryRun
    Write-WcnLine ''
    Write-WcnDiskBar
    Write-WcnBanner 'DRY RUN COMPLETE'
    Write-WcnOk 'every refusal was evaluated and passed. Nothing was changed, here or in Watchman.'
    Write-WcnLine '   Re-run without -DryRun to perform the capture.' 'Cyan'
    exit 0
}

if (-not (Confirm-Wcn -Question ("capture {0} as {1}?" -f (Get-WcnProp $site 'code'), $role) `
                      -RequireTyped -TypedAnswer ([string](Get-WcnProp $site 'code')))) {
    Write-WcnWarn 'cancelled — nothing has been changed'
    exit 0
}

# ── STEP 4 · register, and BIND this machine ────────────────────────────────────────────────
Write-WcnBanner 'STEP 4  ·  REGISTER WITH WATCHMAN'
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
$reg = Register-WcnCapture -Session $session -Role $role -Machine $machine -StartedAt $startedAt `
            -GuestAgentInstalled $null -PrintersCleared $null -Slimmed $null
if (-not $reg.Ok) {
    Write-WcnFail ("Watchman refused the registration: {0}" -f $reg.Error)
    if ($reg.Conflict) { Write-WcnFail 'that slot is held by a different capture ticket — pick another role, or have it withdrawn in Watchman.' }
    Write-WcnFail 'nothing has been changed on this PC.'
    exit 2
}
Write-WcnOk 'registered — this site is now visibly mid-build in Watchman'
if ($reg.Upload) { Write-WcnInfo ("upload destination: {0}" -f (Get-WcnProp $reg.Upload 'path' '?')) }
elseif ($reg.UploadRefused) { Write-WcnWarn ("no upload destination yet ({0}) — the image will go to the USB" -f (Get-WcnProp $reg.UploadRefused 'reason' '?')) }

$state = [ordered]@{
    schema         = 1
    phase          = 'registered'
    ticketPath     = $ticketPath          # the PATH. Never the secret, never the token.
    pharmacyCode   = (Get-WcnProp $site 'code')
    pharmacyName   = (Get-WcnProp $site 'name')
    role           = $role
    roleKind       = $roleKind
    fingerprint    = $machine.Fingerprint # ⭐ the binding the resume gate compares against
    sourceHostname = $machine.Hostname
    scratch        = $Scratch
    startedAt      = $startedAt
    sqlBefore      = $sqlBefore
}
Save-WcnState $state

# From here on a failure has to tell Watchman: an abandoned capture that told nobody leaves the
# site reading "mid-build" forever, and the next engineer cannot tell that from one in progress.
function Stop-WcnRun {
    param([string]$Why, [int]$Code = 5)
    try {
        Register-WcnCapture -Session $session -Role $role -Machine $machine -StartedAt $startedAt `
            -GuestAgentInstalled $null -PrintersCleared $null -Slimmed $null -FailedReason $Why | Out-Null
    } catch { }
    Write-WcnFail $Why
    exit $Code
}

# ── STEP 5 · the guest agent. REQUIRED. ─────────────────────────────────────────────────────
Write-WcnBanner 'STEP 5  ·  QEMU GUEST AGENT  (required)'
$agent = Install-WcnGuestAgent -InstallerPath $GuestToolsInstaller
if (-not $agent.Ok) {
    Write-WcnFail ("the guest agent is not running: {0}" -f $agent.Note)
    Write-WcnFail 'REFUSING to continue. An image without the agent cannot be managed from the cluster,'
    Write-WcnFail 'and fixing it later costs this site an engineer visit — which has happened three times.'
    Write-WcnFail 'Nothing destructive has run yet: this PC is unchanged apart from the install attempt.'
    Stop-WcnRun -Why ("guest agent not running: {0}" -f $agent.Note) -Code 6
}
$state.guestAgentInstalled = $true
Save-WcnState $state

# ── STEP 6 · printers ───────────────────────────────────────────────────────────────────────
Write-WcnBanner 'STEP 6  ·  PRINTERS  (recorded, then all deleted)'
$printers = Invoke-WcnPrinterPurge -ProvenanceDir $WorkDir
$state.printersCleared    = $printers.Cleared        # ⚠️ tri-state, passed straight through
$state.printersProvenance = $printers.ProvenancePath
Save-WcnState $state
if ($printers.Cleared -eq $false) {
    Write-WcnWarn 'some printers could not be removed. Continuing, and Watchman will be told printers_cleared = false —'
    Write-WcnWarn 'which means the post-import checklist still has printer work to do at this site.'
}

# ── STEP 7 · strip + debloat  (vendor scripts, unchanged) ───────────────────────────────────
Write-WcnBanner 'STEP 7  ·  STRIP AND DEBLOAT'
Write-WcnLine '   Remove-Bloat.ps1 and Strip-PmrImage.ps1 run here EXACTLY as they were written.' 'DarkGray'
Write-WcnLine '   Their $NEVER and $PROTECT_PATH lists are what make aggressive slimming safe.' 'DarkGray'
# -SkipGuestTools: step 5 owns it now, and REQUIRES a running service where the vendor script
#   only warned. -SkipSqlCheck: lib/WcnSql.ps1 owns it now, because the vendor gate treats a
#   NO-CONNECT as a pass. Both stages still happen — properly, upstream, where failing is a refusal.
#
# ⚠️ DO NOT TEST $LASTEXITCODE AFTER THESE. A .ps1 invoked with & only sets it if the script calls
# `exit`; otherwise it still holds whatever the last NATIVE command left. Strip-PmrImage.ps1 runs
# dism, wevtutil, powercfg and takeown, and `wevtutil cl` on a log it cannot clear is routine — so
# a completed, successful strip reliably leaves a non-zero $LASTEXITCODE. Gating on it would abort
# a healthy run at step 7, after the printers had already been deleted. Its only `exit` paths are
# the SQL gates and -ZeroFree, none of which we invoke; a genuine failure is a terminating error.
try { & (Join-Path $KitRoot 'vendor\Strip-PmrImage.ps1') -SkipGuestTools -SkipSqlCheck }
catch { Stop-WcnRun -Why ("Strip-PmrImage.ps1 failed: {0}" -f $_.Exception.Message) -Code 7 }

try { & (Join-Path $KitRoot 'vendor\Remove-Bloat.ps1') -Execute }
catch {
    # Remove-Bloat sets $ErrorActionPreference='Continue' internally and is written to survive
    # individual failures, so reaching here means something structural. The strip has already
    # run, so this is reported rather than silently swallowed — and the run continues.
    Write-WcnWarn ("Remove-Bloat.ps1 raised: {0} — continuing; the strip has already run" -f $_.Exception.Message)
}
Write-WcnDiskBar

# ── STEP 8 · reboot ─────────────────────────────────────────────────────────────────────────
Write-WcnBanner 'STEP 8  ·  REBOOT'
Write-WcnLine '   The pagefile, hibernation file, shadow copies and WinRE image have been removed,' 'Gray'
Write-WcnLine '   but that space is not actually free until Windows restarts — and the partition' 'Gray'
Write-WcnLine '   cannot be shrunk past files that are still open.' 'Gray'
$state.phase = 'rebooted'
Save-WcnState $state

if (Confirm-Wcn -Question 'reboot now and continue automatically when you log back in?') {
    $runOnce = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Set-ItemProperty -Path $runOnce -Name 'WcnPmrCaptureResume' -Type String `
        -Value ("powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"{0}`" -Resume" -f $PSCommandPath)
    Write-WcnInfo 'rebooting in 10 seconds — Ctrl+C to cancel'
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-WcnWarn 'reboot when you are ready, then run:'
    Write-WcnLine ("      {0} -Resume" -f $PSCommandPath) 'Cyan'
}
