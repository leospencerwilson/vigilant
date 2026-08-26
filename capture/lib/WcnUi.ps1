# WcnUi.ps1 — console output, the run log, and the ONE redaction point.
#
# Carried forward from Start-PmrOnboard.ps1's output helpers, which were good and which the
# engineer standing at the counter already recognises. Two things are new:
#
#   1. EVERY line goes through Write-WcnLine, and Write-WcnLine redacts. The capture ticket is
#      short-lived, but a log file is not: it is written to C:\wcn-imageprep on a pharmacy PC we
#      do not own and it outlives the run by months. A token that reaches the log has escaped
#      its TTL in every way that matters, because the log is what gets emailed to whoever is
#      debugging. So redaction is not a courtesy at the call sites — it is enforced HERE, where
#      no call site can forget it.
#
#   2. There is no Ask() that can answer itself. The old one returned $true under -Unattended,
#      which is how a 30-90 minute destructive operation on a pharmacy's only dispensing system
#      acquired a mode with nobody watching it. Confirm-Wcn reads the keyboard or it fails.

Set-StrictMode -Version 2.0

$script:WcnLogPath = $null

# The two shapes a secret takes in this kit, both of which would otherwise be logged verbatim by
# an error message quoting a URL or a header:
#   * the capture token          <base64url>.<base64url>, two long segments and a dot
#   * an Authorization header    "Bearer <anything>"
# Deliberately greedy and deliberately stupid: over-redaction costs a debugging session, and
# under-redaction costs a credential. There is no third pattern to add later without adding it
# here, because nothing else in this kit holds a secret.
$script:WcnRedactions = @(
    @{ Pattern = '(?i)(bearer\s+)\S+';                     Replace = '${1}[REDACTED]' },
    @{ Pattern = '[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}'; Replace = '[REDACTED-TOKEN]'  },
    @{ Pattern = '(?i)("?(?:token|secret|password|credential)"?\s*[:=]\s*"?)[^"\s,}]+'; Replace = '${1}[REDACTED]' }
)

function Protect-WcnSecret {
    # The ONE redactor. Public so a stage that builds a command line can scrub it before it is
    # shown, but nothing has to remember to: Write-WcnLine calls this on every line regardless.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    foreach ($r in $script:WcnRedactions) { $out = [regex]::Replace($out, $r.Pattern, $r.Replace) }
    return $out
}

function Start-WcnLog {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $script:WcnLogPath = $Path
    "== WCN PMR capture == $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') ==" |
        Out-File -FilePath $Path -Append -Encoding ASCII
}

function Write-WcnLine {
    param([string]$Message, [string]$Colour = 'Gray')
    $safe = Protect-WcnSecret $Message
    Write-Host $safe -ForegroundColor $Colour
    if ($script:WcnLogPath) { $safe | Out-File -FilePath $script:WcnLogPath -Append -Encoding ASCII }
}

function Write-WcnRule   { Write-WcnLine ('-' * 74) 'DarkCyan' }
function Write-WcnBanner {
    param([string]$Title)
    Write-WcnLine ''
    Write-WcnLine ('=' * 74) 'Cyan'
    Write-WcnLine ("   $Title") 'Cyan'
    Write-WcnLine ('=' * 74) 'Cyan'
}
function Write-WcnInfo { param([string]$m) Write-WcnLine ("   [..] $m") 'Gray' }
function Write-WcnOk   { param([string]$m) Write-WcnLine ("   [OK] $m") 'Green' }
function Write-WcnWarn { param([string]$m) Write-WcnLine ("   [!!] $m") 'Yellow' }
function Write-WcnFail { param([string]$m) Write-WcnLine ("   [XX] $m") 'Red' }

function Format-WcnGB {
    param($Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    return ('{0:N1} GB' -f ($Bytes / 1GB))
}

function Write-WcnDiskBar {
    param([string]$DriveLetter = 'C')
    $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}:'" -f $DriveLetter) -ErrorAction SilentlyContinue
    if (-not $d -or -not $d.Size) { Write-WcnWarn "cannot read ${DriveLetter}: size"; return }
    $used = $d.Size - $d.FreeSpace
    $width = 46
    $filled = [int](($used / $d.Size) * $width)
    if ($filled -lt 0) { $filled = 0 }; if ($filled -gt $width) { $filled = $width }
    Write-WcnLine ("   {0}: |{1}{2}|  {3} used / {4} free" -f `
        $DriveLetter, ('#' * $filled), ('-' * ($width - $filled)), (Format-WcnGB $used), (Format-WcnGB $d.FreeSpace)) 'White'
}

function Confirm-Wcn {
    # ⛔ THERE IS NO UNATTENDED ANSWER. This blocks on a human or it does not return true.
    # A capture is destructive, it runs 30-90 minutes, and the physical PC is the only rollback
    # the pharmacy has. The person who owns that risk has to be in the room to accept it, and a
    # switch that answers on their behalf is the removal of the only safeguard that is not code.
    param([Parameter(Mandatory)][string]$Question, [switch]$RequireTyped, [string]$TypedAnswer)
    Write-WcnLine ''
    if ($RequireTyped) {
        # Used where Y is too cheap: the site's own code, typed, before anything destructive.
        # Same instrument the platform already uses for apply-now on a live counter.
        $r = Read-Host ("   ?  $Question  (type {0} to confirm)" -f $TypedAnswer)
        $ok = ($r.Trim() -eq $TypedAnswer)
        Write-WcnLine ("   >  answered: {0}" -f $(if ($ok) { 'confirmed' } else { 'NOT confirmed' })) 'DarkGray'
        return $ok
    }
    $r = Read-Host ("   ?  $Question  [y/N]")
    $ok = ($r -match '^\s*(y|yes)\s*$')
    Write-WcnLine ("   >  answered: {0}" -f $(if ($ok) { 'yes' } else { 'no' })) 'DarkGray'
    return $ok
}

function Read-WcnChoice {
    # A numbered picker over a list of objects. Returns the chosen object, or $null if the
    # operator backed out. Used for the site and the role — neither is ever typed as free text,
    # because a typo in a site code produces a valid capture of a real pharmacy filed against a
    # site that does not exist, and that association cannot be corrected afterwards.
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][scriptblock]$Label,
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Selectable = { $true }
    )
    if (-not $Items -or $Items.Count -eq 0) { Write-WcnFail 'nothing to choose from'; return $null }
    Write-WcnLine ''
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $item = $Items[$i]
        $can  = [bool](& $Selectable $item)
        $text = & $Label $item
        $mark = if ($can) { ' ' } else { 'x' }
        Write-WcnLine ("   {0} {1,3}) {2}" -f $mark, ($i + 1), $text) $(if ($can) { 'White' } else { 'DarkGray' })
    }
    Write-WcnLine ('     {0,3}) cancel' -f 0) 'DarkGray'
    while ($true) {
        $r = (Read-Host "   ?  $Prompt").Trim()
        if ($r -eq '0' -or $r -eq '') { return $null }
        $n = 0
        if (-not [int]::TryParse($r, [ref]$n) -or $n -lt 1 -or $n -gt $Items.Count) {
            Write-WcnWarn 'pick one of the numbers listed'; continue
        }
        $chosen = $Items[$n - 1]
        if (-not (& $Selectable $chosen)) {
            # Not a silent re-prompt: the operator picked something for a reason and needs to
            # know it was unavailable rather than mistyped.
            Write-WcnWarn 'that one is not available — the reason is shown against it above'; continue
        }
        Write-WcnLine ("   >  chose: {0}" -f (& $Label $chosen)) 'DarkGray'
        return $chosen
    }
}
