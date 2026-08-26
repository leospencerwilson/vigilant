# WcnRefuse.ps1 — EVERY refusal, in one place, re-evaluated at every gate.
#
# ⭐ WHY ONE FILE. A refusal that lives in the stage which happens to notice it is a refusal that
# exists at one moment in the run. This kit spans a REBOOT: what was true when the operator
# pressed go is not necessarily true when the machine comes back. The ticket may have died
# because THE PHARMACY OPENED. Somebody may have taken the slot from another PC. The USB may be
# in a different machine. Every one of those is an ordinary Tuesday, and none is detectable by a
# pipeline that checked once at the top.
#
# So the table is a function taking a Gate, and the orchestrator calls it at THREE points:
#
#   'pre'         before anything is touched
#   'resume'      immediately after the reboot, before the machine is touched again
#   'destructive' immediately before the capture — the last moment stopping is free
#
# ── ⭐ WHAT THE SERVER ALREADY ENFORCES, AND WHY THESE STILL EXIST ───────────────────────────
# Several rules in the agreed baseline are enforced by the SHAPE of the credential rather than
# by anything here, and that is strictly better:
#
#   "never a typed site"   — there is no site field on any capture route. POST /capture/register
#                            REFUSES a body carrying pharmacy_id/site/site_code. The kit is
#                            physically unable to name another pharmacy.
#   "out of hours only"    — the ticket's expiry is min(issue + 12 h, the site's next opening
#                            time), so it cannot be alive while the pharmacy is trading. The kit
#                            does not check this; the kit cannot violate it.
#   "no duplicate slot"    — partial unique indexes in the database, and an upsert that only
#                            updates a row owned by the same ticket.
#
# The checks below are therefore NOT re-implementations of those rules. They exist to make the
# refusal land EARLY and in a sentence — before ninety minutes are spent — and to cover the two
# things the server genuinely cannot see: which physical machine this is, and whether there is
# room on the scratch drive.
#
# ⛔ THERE IS NO OVERRIDE SWITCH. Not -Force, not -Yes, not -SkipChecks. Each refusal exists
# because the alternative cost a site something real, and an override gets reached for on
# exactly the night the check was right.

Set-StrictMode -Version 2.0

function New-WcnRefusal {
    param([string]$Id, [string]$Title, [string]$Detail, [string]$Fix)
    return [pscustomobject]@{ Id = $Id; Title = $Title; Detail = $Detail; Fix = $Fix }
}

# How much ticket must remain before a capture may START. A capture takes up to 90 minutes and
# the server refuses to ISSUE a ticket into a window shorter than that (MIN_WINDOW_MIN); this is
# the same number applied at the other end, because a ticket issued at 22:00 for a site opening
# at 08:00 is still a ticket somebody might pick up at 07:00.
$script:WcnMinStartMinutes = 90

function Test-WcnRoleSlotFree {
    <#
      Is this role slot free, according to the slot list the server just sent?

      The server counts three sources of "taken" — an existing capture run, a counter row, and
      (for the server role) the site's own srv_vmid — so this is a read of its answer, never a
      second opinion. Named in the refusal, because "already taken" without saying by what is a
      refusal an engineer will work around.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Slots, [Parameter(Mandatory)][string]$Role)
    $match = @($Slots | Where-Object { [string](Get-WcnProp $_ 'role' '') -eq $Role })
    if ($match.Count -eq 0) {
        return [pscustomobject]@{ Free = $false; Why = ("Watchman does not list a role '{0}' at this site" -f $Role) }
    }
    $s = $match[0]
    if ([bool](Get-WcnProp $s 'taken' $false)) {
        $by = @(Get-WcnProp $s 'taken_by' @())
        $held = Get-WcnProp $s 'capture'
        $who = [string](Get-WcnProp $held 'taken_by' '')
        $said = ("{0} is already taken ({1})" -f $Role, $(if ($by.Count) { $by -join ', ' } else { 'held' }))
        if ($who) { $said += (" — registered by {0}" -f $who) }
        return [pscustomobject]@{ Free = $false; Why = $said }
    }
    return [pscustomobject]@{ Free = $true; Why = ("{0} is free" -f $Role) }
}

function Test-WcnScratchSpace {
    <#
      Scratch space — one of the two things the server cannot see.

      disk2vhd writes a VHDX roughly the size of C:'s USED space, and the converter then writes
      the compressed image beside it, because it must read the whole VHDX before it can produce
      the qcow2. Both live on the scratch drive at once.

      1.3x used is carried forward from the old kit's own arithmetic, where it was a WARNING.
      It is a refusal here: running out of scratch happens 50 minutes in, after the strip, the
      debloat and the reboot have already changed the pharmacy's PC, so a check that only warns
      costs the engineer the whole evening and gives the site nothing.
    #>
    param([Parameter(Mandatory)][string]$Scratch, [double]$Factor = 1.3)
    $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
    if (-not $c) { return [pscustomobject]@{ Ok = $false; Why = 'cannot read the size of C:' } }
    $used = $c.Size - $c.FreeSpace
    $need = [int64]($used * $Factor)

    $root = $null
    try {
        if (-not (Test-Path -LiteralPath $Scratch)) { New-Item -ItemType Directory -Force -Path $Scratch -ErrorAction Stop | Out-Null }
        $root = (Get-Item -LiteralPath $Scratch).PSDrive
    } catch {
        return [pscustomobject]@{ Ok = $false; Why = ("the scratch path {0} does not exist and could not be created: {1}" -f $Scratch, $_.Exception.Message) }
    }
    if (-not $root -or $null -eq $root.Free) {
        return [pscustomobject]@{ Ok = $false; Why = ("cannot read free space on the scratch drive for {0}" -f $Scratch) }
    }
    # Refuse a scratch path on C:. It is self-defeating — the VHDX grows C: as it captures C: —
    # and it is an easy mistake to make when the USB drive letter has moved.
    if ($root.Name -eq 'C') {
        return [pscustomobject]@{ Ok = $false; Why = 'the scratch path is on C: — the capture cannot be written to the disk it is capturing. Use the USB/external drive.' }
    }
    if ($root.Free -lt $need) {
        return [pscustomobject]@{
            Ok = $false
            Why = ("scratch is too small: {0} needs about {1} for the VHDX plus its compressed copy, and {2}: has {3} free" -f `
                    $Scratch, (Format-WcnGB $need), $root.Name, (Format-WcnGB $root.Free))
        }
    }
    return [pscustomobject]@{ Ok = $true; Why = ("{0}: has {1} free; the capture needs about {2}" -f $root.Name, (Format-WcnGB $root.Free), (Format-WcnGB $need)) }
}

function Test-WcnCaptureRefusals {
    <#
      THE TABLE. Returns an array of refusals — empty means proceed.

      Everything that talks to Watchman is re-asked at every gate rather than cached: the whole
      reason to re-run the table is that the world moved while the machine rebooted, and a
      cached "the ticket was alive" is not evidence that it is alive.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('pre', 'resume', 'destructive')][string]$Gate,
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)]$Machine,
        [string]$Scratch,
        [string]$Role = $null,
        $BoundFingerprint = $null,     # from the state file, once the machine has been bound
        $SqlResult = $null,
        [string]$SqlRoleKind = $null   # 'server' | 'client' — decides whether "no SQL" is fatal
    )
    $refusals = @()

    # ── 1. elevation ────────────────────────────────────────────────────────────
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        $refusals += New-WcnRefusal 'NOT_ADMIN' 'not running as Administrator' `
            'every stage of this kit needs Administrator' `
            'right-click PowerShell, Run as administrator, and start the tool again'
    }

    # ── 2. the ticket ───────────────────────────────────────────────────────────
    $tk = $Session.Ticket
    if (-not $tk -or -not $tk.Ok) {
        $refusals += New-WcnRefusal 'TICKET_MISSING' 'no usable capture ticket' `
            $(if ($tk) { $tk.Error } else { 'no ticket was supplied' }) `
            'issue a capture ticket in Watchman (Site -> Capture -> Issue ticket) and pass it with -Ticket <path>'
        # Nothing below can be evaluated. Return now rather than cascading consequential
        # refusals that bury the one real cause.
        return $refusals
    }

    # ── 3. redeem — the single call that proves everything at once ──────────────
    # ⭐ THIS IS THE OUT-OF-HOURS GATE, THE CONNECTIVITY GATE AND THE CREDENTIAL GATE, TOGETHER.
    # The ticket cannot outlive the site's closed window, so a ticket that will not redeem
    # because it has expired is very often telling us THE PHARMACY HAS OPENED — which is why
    # the server's own sentence is surfaced verbatim rather than replaced with "unauthorized".
    # Reuses a token that is still comfortably alive rather than spending a redemption on every
    # gate — see Invoke-WcnEnsureToken for why that does not weaken the out-of-hours rule.
    $mint = Invoke-WcnEnsureToken -Session $Session
    if (-not $mint.Ok) {
        $id = switch ($mint.Reason) {
            'expired'        { 'TICKET_EXPIRED' }
            'spent'          { 'TICKET_SPENT' }
            'revoked'        { 'TICKET_REVOKED' }
            'no-such-ticket' { 'TICKET_UNKNOWN' }
            default          { $(if ($mint.Status -eq 0) { 'NO_CONNECTIVITY' } else { 'TICKET_REFUSED' }) }
        }
        $fix = switch ($id) {
            'TICKET_EXPIRED'  { 'a capture ticket dies when the pharmacy opens — that is the out-of-hours rule, and it is arithmetic rather than a check. Get a fresh one out of hours.' }
            'TICKET_SPENT'    { 'the redemption budget is used up. Ask for a new ticket in Watchman.' }
            'TICKET_REVOKED'  { 'somebody revoked this ticket in Watchman. Ask why before asking for another.' }
            'NO_CONNECTIVITY' { 'there is no offline capture path, on purpose — offline is the run with every check below disabled. Fix the connection or come back.' }
            default           { 'issue a fresh capture ticket in Watchman.' }
        }
        $refusals += New-WcnRefusal $id 'Watchman would not issue a capture token' $mint.Error $fix
        return $refusals   # every check below needs a token
    }

    # ── 4. the credential is not broader than the job ───────────────────────────
    $scope = Test-WcnCapabilities -Capabilities $Session.Capabilities
    if (-not $scope.Ok) {
        $bits = @()
        if ($scope.Extra.Count)   { $bits += ("it also carries: {0}" -f ($scope.Extra -join ', ')) }
        if ($scope.Missing.Count) { $bits += ("it is missing: {0}"  -f ($scope.Missing -join ', ')) }
        $refusals += New-WcnRefusal 'TOKEN_OVERSCOPED' 'the minted token is not scoped for capture work' `
            ("this kit runs on a credential carrying exactly {0} — {1}" -f ($scope.Required -join ', '), ($bits -join '; ')) `
            'this should be impossible against a correct Watchman. Report it rather than working around it: a pharmacy PC is not a place for a broader credential.'
    }

    # ── 5. enough ticket left to be worth starting ──────────────────────────────
    if ($Gate -eq 'pre' -and $Session.TicketExpiresAt) {
        $left = $null
        try { $left = ([datetime]$Session.TicketExpiresAt).ToUniversalTime() - [DateTime]::UtcNow } catch { }
        if ($null -ne $left -and $left.TotalMinutes -lt $script:WcnMinStartMinutes) {
            # Only at 'pre'. Refusing a RESUME for this would strand a half-stripped PC, which is
            # strictly worse than finishing on a ticket with forty minutes left.
            $refusals += New-WcnRefusal 'WINDOW_TOO_SHORT' 'not enough closed window left to start' `
                ("the ticket dies in {0:N0} minutes (it is bounded to when this pharmacy reopens) and a capture takes up to {1}" -f $left.TotalMinutes, $script:WcnMinStartMinutes) `
                'come back earlier in the closed window. Starting now leaves an engineer mid-run at a counter that has opened.'
        }
    }

    # ── 6. the machine — the other thing the server cannot see ──────────────────
    if (-not $Machine.Fingerprint) {
        $refusals += New-WcnRefusal 'FINGERPRINT_UNAVAILABLE' 'this PC cannot be identified' `
            'neither SMBIOS nor the volume serial produced anything usable, so after the reboot the tool cannot tell whether it is still on the same machine' `
            'run the tool from the PC being captured; if this persists, raise it — do not proceed blind'
    }
    if ($BoundFingerprint -and $Machine.Fingerprint -and $BoundFingerprint -ne $Machine.Fingerprint) {
        # ⭐ THE ONE THAT CATCHES THE REALISTIC MISTAKE: the resume run started on the wrong box.
        # Everything would otherwise work, and this image would be filed under the other
        # machine's slot with nothing downstream able to tell.
        $refusals += New-WcnRefusal 'MACHINE_MISMATCH' 'this is not the PC the capture was started on' `
            ("the capture was registered against {0}; this machine is {1} ({2})" -f $BoundFingerprint, $Machine.Fingerprint, $Machine.Hostname) `
            'take the USB back to the PC the run was started on. Resuming here would file THIS machine''s image against the other one''s slot.'
    }

    # ── 7. the role slot, re-asked every time ───────────────────────────────────
    if ($Role) {
        $slots = Get-WcnCaptureSlots -Session $Session
        if (-not $slots.Ok) {
            $refusals += New-WcnRefusal 'SITE_UNREADABLE' 'the site''s slots could not be read' `
                $slots.Error `
                'without the slot list a duplicate capture cannot be ruled out'
        } else {
            $slot = Test-WcnRoleSlotFree -Slots $slots.Slots -Role $Role
            # ⚠️ At 'resume' and 'destructive' the slot is EXPECTED to be taken — by us. The
            # server's upsert only updates a row owned by the same ticket, so a slot held by
            # this run is not a conflict. Only the 'pre' gate treats taken as a refusal.
            if ($Gate -eq 'pre' -and -not $slot.Free) {
                $refusals += New-WcnRefusal 'ROLE_TAKEN' 'that role is already taken at this site' `
                    $slot.Why `
                    'pick the correct role, or have the existing capture withdrawn in Watchman if it is stale'
            }
        }
    }

    # ── 8. SQL: unreadable is NOT a pass ────────────────────────────────────────
    if ($null -ne $SqlResult -and $SqlRoleKind) {
        $verdict = Test-WcnSqlAcceptable -Result $SqlResult -Role $SqlRoleKind
        if (-not $verdict.Pass) {
            $refusals += New-WcnRefusal 'SQL_UNPROVEN' 'the database integrity check did not return a clean result' `
                $verdict.Reason `
                'the physical PC is the only rollback this pharmacy has, so an unprovable database must not be captured. Investigate the instance first — there is deliberately no override.'
        }
    }

    # ── 9. scratch ──────────────────────────────────────────────────────────────
    if ($Scratch) {
        $sp = Test-WcnScratchSpace -Scratch $Scratch
        if (-not $sp.Ok) {
            $refusals += New-WcnRefusal 'SCRATCH_TOO_SMALL' 'not enough scratch space for the capture' `
                $sp.Why `
                'attach a larger USB SSD and point -Scratch at it'
        }
    }

    return $refusals
}

function Write-WcnRefusals {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Refusals, [string]$Gate)
    if ($Refusals.Count -eq 0) { return }
    Write-WcnBanner ("REFUSED  ({0} gate)  —  {1} reason(s)" -f $Gate, $Refusals.Count)
    foreach ($r in $Refusals) {
        Write-WcnLine ''
        Write-WcnFail ("{0}  —  {1}" -f $r.Id, $r.Title)
        if ($r.Detail) { Write-WcnLine ("        why : {0}" -f $r.Detail) 'Yellow' }
        if ($r.Fix)    { Write-WcnLine ("        fix : {0}" -f $r.Fix) 'Gray' }
    }
    Write-WcnLine ''
    Write-WcnRule
    # Honest about state, per gate. "Nothing has been changed" after the reboot would be a lie,
    # and the engineer's next decision depends on knowing which it is.
    switch ($Gate) {
        'pre' { Write-WcnLine '   Nothing on this PC has been changed by this run.' 'Cyan' }
        'resume' {
            Write-WcnLine '   ⚠ The strip and debloat ALREADY RAN before the reboot. This PC has been changed.' 'Yellow'
            Write-WcnLine '     No capture was taken. Fix the reason above and run with -Resume again — the run' 'Yellow'
            Write-WcnLine '     picks up where it stopped. Do not start fresh: it would strip twice.' 'Yellow'
        }
        'destructive' {
            Write-WcnLine '   ⚠ The strip and debloat have already run. No capture was taken and nothing was' 'Yellow'
            Write-WcnLine '     uploaded. Fix the reason above and re-run with -Resume.' 'Yellow'
        }
    }
    Write-WcnRule
}
