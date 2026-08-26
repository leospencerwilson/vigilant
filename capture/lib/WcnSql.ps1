# WcnSql.ps1 — "is this pharmacy's dispensing database provably intact?"
#
# ⛔ THE DEFECT THIS FILE FIXES. Strip-PmrImage.ps1 runs DBCC CHECKDB before and after the strip
# and calls that a bit-check, which it is. But look at what it does with the answer: it records
# Errors = 'NO-CONNECT' when the instance will not answer and Errors = 'ERR' when the check
# itself throws, and then the abort gate is
#
#     $_.Errors -is [int] -and $_.Errors -gt 0
#
# 'NO-CONNECT' is a string, so it is not [int], so it is not > 0, so it does not abort. The
# regression gate afterwards has the same shape and the same hole. The result is that a database
# nobody could read produced the line "SQL check PASSED - DB integrity unchanged" in green, and
# the capture proceeded.
#
# That is the worst available failure mode, because it is silent and it is confident. The whole
# reason to check integrity before a P2V is that the physical PC is the only rollback the
# pharmacy has: once the strip has run, "was the database already broken?" can no longer be
# answered. An unreadable database is not a clean database. It is an unknown one, and unknown
# must refuse.
#
# ⭐ SO THERE ARE THREE VERDICTS HERE, NOT TWO: clean / dirty / UNPROVEN. Only 'clean' proceeds.
# Same direction as pmr_disruptive_allowed() in the schema — a gate answers FALSE when it does
# not know, and the comment there says exactly why: do not disrupt on the strength of a silence.
#
# ⚠️ AND THERE IS NO -Force. Strip-PmrImage.ps1 had one, for the pre-strip check. It is not
# carried forward. "Capture this pharmacy's dispensing database even though I could not prove it
# is intact" is not an option an operator should be able to exercise at 11pm on their own
# judgement, and every override in this kit's history would have been used for the one reason
# that makes it dangerous: it was late and the check was inconvenient.

Set-StrictMode -Version 2.0

function Invoke-WcnSqlRows {
    # Carried forward from Strip-PmrImage.ps1's Invoke-SqlRows, including its comment about the
    # trailing comma: `return $rows` and not `return ,$rows`, because the caller wraps with @()
    # and a comma here nests the array one level deeper than anything expects.
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Database,
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 3600,
        [string]$SqlUser, [string]$SqlPassword
    )
    $cs = "Server=$Server;Database=$Database;TrustServerCertificate=True;Connect Timeout=10"
    if ($SqlUser) { $cs += ";User ID=$SqlUser;Password=$SqlPassword" } else { $cs += ";Integrated Security=SSPI" }
    $cn = New-Object System.Data.SqlClient.SqlConnection $cs
    $cn.Open()
    try {
        $cmd = $cn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = $TimeoutSec
        $rd = $cmd.ExecuteReader()
        $rows = @()
        while ($rd.Read()) {
            $v = @()
            for ($i = 0; $i -lt $rd.FieldCount; $i++) { $v += [string]$rd.GetValue($i) }
            $rows += ($v -join ' | ')
        }
        $rd.Close()
        return $rows
    } finally { $cn.Close() }
}

function Get-WcnSqlInstances {
    param([string]$Override)
    if ($Override) { return @($Override) }
    $servers = @()
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
    if ($reg) {
        foreach ($p in $reg.PSObject.Properties) {
            if ($p.Name -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') { continue }
            $servers += $(if ($p.Name -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$($p.Name)" })
        }
    }
    return @($servers)
}

function Test-WcnSqlIntegrity {
    <#
      Returns:
        Verdict   'clean' | 'dirty' | 'unproven' | 'none-installed'
        Reason    a sentence for the operator
        Databases per-database detail, for the log and for the after-comparison

      PHYSICAL_ONLY by default. It reads every page and verifies the checksums, which is what
      detects the storage-level damage a P2V would otherwise carry into the VM forever, and it
      finishes in minutes rather than the hour a full logical check takes on a dispensing
      database. -Full gets the exhaustive one where there is time for it.
    #>
    param(
        [string]$SqlInstance,
        [switch]$Full,
        [string]$SqlUser, [string]$SqlPassword,
        [int]$TimeoutSec = 3600
    )
    $servers = Get-WcnSqlInstances -Override $SqlInstance
    if ($servers.Count -eq 0) {
        # NOT a verdict on its own. Whether "no SQL here" is acceptable depends on the ROLE
        # being captured, and the role is not this function's business — see
        # Test-WcnSqlAcceptable, which is where that judgement lives.
        return [pscustomobject]@{
            Verdict = 'none-installed'
            Reason  = 'no SQL Server instance is installed on this PC'
            Databases = @()
        }
    }

    $opt = $(if ($Full) { 'ALL_ERRORMSGS' } else { 'PHYSICAL_ONLY' })
    $detail = @()
    foreach ($srv in $servers) {
        $dbs = $null
        try {
            # database_id>4 skips master/model/msdb/tempdb; state=0 is ONLINE. A database that
            # is OFFLINE or RECOVERING is deliberately not checked here and is caught below.
            $dbs = @(Invoke-WcnSqlRows -Server $srv -Database 'master' -TimeoutSec 30 -SqlUser $SqlUser -SqlPassword $SqlPassword `
                        -Query 'SELECT name FROM sys.databases WHERE database_id>4 AND state=0')
            # A database that exists but is not ONLINE is a fact the operator must see, and it
            # is not covered by DBCC because DBCC cannot open it.
            $notOnline = @(Invoke-WcnSqlRows -Server $srv -Database 'master' -TimeoutSec 30 -SqlUser $SqlUser -SqlPassword $SqlPassword `
                        -Query 'SELECT name + '' ('' + state_desc + '')'' FROM sys.databases WHERE database_id>4 AND state<>0')
            foreach ($n in $notOnline) {
                $detail += [pscustomobject]@{ Server = $srv; Database = $n; Status = 'unproven'; Errors = $null
                                              Note = 'the database is not ONLINE, so its integrity cannot be checked' }
            }
        } catch {
            # ⭐ THE FIX. This used to be recorded as Errors='NO-CONNECT' and then sail through
            # an -is [int] test. It is a REFUSAL.
            $detail += [pscustomobject]@{ Server = $srv; Database = '(instance)'; Status = 'unproven'; Errors = $null
                                          Note = ("the instance would not answer: {0}" -f $_.Exception.Message) }
            continue
        }

        if ($dbs.Count -eq 0) {
            $detail += [pscustomobject]@{ Server = $srv; Database = '(none)'; Status = 'empty'; Errors = 0
                                          Note = 'the instance holds no user databases' }
            continue
        }

        foreach ($db in $dbs) {
            try {
                # TABLERESULTS makes each problem a row, so counting rows counts problems, and
                # NO_INFOMSGS keeps the clean case at exactly zero rows.
                $errs = @(Invoke-WcnSqlRows -Server $srv -Database 'master' -TimeoutSec $TimeoutSec -SqlUser $SqlUser -SqlPassword $SqlPassword `
                            -Query "DBCC CHECKDB([$db]) WITH NO_INFOMSGS, TABLERESULTS, $opt")
                $detail += [pscustomobject]@{
                    Server = $srv; Database = $db
                    Status = $(if ($errs.Count -eq 0) { 'clean' } else { 'dirty' })
                    Errors = $errs.Count
                    Note   = $(if ($errs.Count -eq 0) { 'clean' } else { (($errs | Select-Object -First 3) -join ' ;; ') })
                }
            } catch {
                # ⭐ THE OTHER HALF OF THE FIX. Used to be Errors='ERR'; also sailed through.
                $detail += [pscustomobject]@{ Server = $srv; Database = $db; Status = 'unproven'; Errors = $null
                                              Note = ("the check itself failed: {0}" -f $_.Exception.Message) }
            }
        }
    }

    # Worst wins, and 'unproven' outranks 'clean'. There is no arithmetic here on purpose: the
    # bug being fixed was an integer comparison quietly deciding a safety question.
    $verdict = 'clean'
    if (@($detail | Where-Object { $_.Status -eq 'unproven' }).Count -gt 0) { $verdict = 'unproven' }
    if (@($detail | Where-Object { $_.Status -eq 'dirty'    }).Count -gt 0) { $verdict = 'dirty' }

    $reason = switch ($verdict) {
        'clean'    { ("every database checked returned 0 errors ({0} checked)" -f @($detail | Where-Object { $_.Status -eq 'clean' }).Count) }
        'dirty'    { ("{0} database(s) report integrity errors" -f @($detail | Where-Object { $_.Status -eq 'dirty' }).Count) }
        'unproven' { ("{0} database(s)/instance(s) could NOT be checked — unreadable is not clean" -f @($detail | Where-Object { $_.Status -eq 'unproven' }).Count) }
    }
    return [pscustomobject]@{ Verdict = $verdict; Reason = $reason; Databases = $detail }
}

function Test-WcnSqlAcceptable {
    <#
      Turn a verdict into a pass/refuse, which depends on the ROLE being captured.

        Server role — the ProScript database engine lives on this box by definition. An instance
                      MUST be found and MUST check clean. 'none-installed' is therefore a
                      REFUSAL: either this is not the server, or the engine is broken, and both
                      are reasons to stop rather than to capture.

        Client role — a counter PC has no dispensing database. 'none-installed' is the expected,
                      correct answer and passes. But if an instance IS present (SQL Express
                      arrives with plenty of third-party software) it still has to check clean:
                      an unreadable one is still unproven, because we are about to capture it
                      and we cannot say afterwards what state it was in.
    #>
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][ValidateSet('server', 'client')][string]$Role
    )
    switch ($Result.Verdict) {
        'clean' { return [pscustomobject]@{ Pass = $true;  Reason = $Result.Reason } }
        'dirty' { return [pscustomobject]@{ Pass = $false; Reason = ("the database reports integrity errors — do NOT capture a corrupt dispensing database. {0}" -f $Result.Reason) } }
        'unproven' { return [pscustomobject]@{ Pass = $false; Reason = ("SQL integrity is UNPROVEN, which is not a pass. {0}" -f $Result.Reason) } }
        'none-installed' {
            if ($Role -eq 'server') {
                return [pscustomobject]@{ Pass = $false; Reason = 'no SQL instance found, but this capture is registered as the SERVER — the ProScript database engine should be on this PC. Check the role, or the engine.' }
            }
            return [pscustomobject]@{ Pass = $true; Reason = 'no SQL instance on this PC, which is expected for a counter/client' }
        }
    }
    return [pscustomobject]@{ Pass = $false; Reason = 'the SQL check returned a verdict this kit does not understand' }
}

function Compare-WcnSqlAfter {
    <#
      The after-check. Refuses on ANY regression, and — unlike the original — refuses when a
      database that was checkable before is not checkable now. That transition is the single
      most alarming thing the after-check can find: it means the strip took the instance out,
      and an image whose database will not open is worth nothing to the site it came from.
    #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
    $problems = @()
    $beforeMap = @{}
    foreach ($d in $Before.Databases) { $beforeMap[("{0}|{1}" -f $d.Server, $d.Database)] = $d }
    foreach ($a in $After.Databases) {
        $key = ("{0}|{1}" -f $a.Server, $a.Database)
        $b = $(if ($beforeMap.ContainsKey($key)) { $beforeMap[$key] } else { $null })
        if (-not $b) { continue }
        if ($b.Status -eq 'clean' -and $a.Status -eq 'unproven') {
            $problems += ("{0}: was checkable and clean before the strip, and cannot be checked now — {1}" -f $key, $a.Note)
        } elseif ($b.Status -eq 'clean' -and $a.Status -eq 'dirty') {
            $problems += ("{0}: 0 errors before the strip, {1} after — THE STRIP INTRODUCED CORRUPTION" -f $key, $a.Errors)
        } elseif ($b.Status -eq 'dirty' -and $a.Status -eq 'dirty' -and $a.Errors -gt $b.Errors) {
            $problems += ("{0}: errors {1} -> {2}" -f $key, $b.Errors, $a.Errors)
        }
    }
    return [pscustomobject]@{ Pass = ($problems.Count -eq 0); Problems = $problems }
}

function Write-WcnSqlReport {
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)]$Result)
    Write-WcnLine ("   SQL [{0}] {1}: {2}" -f $Label, $Result.Verdict.ToUpperInvariant(), $Result.Reason) `
        $(switch ($Result.Verdict) { 'clean' { 'Green' } 'dirty' { 'Red' } default { 'Yellow' } })
    foreach ($d in $Result.Databases) {
        $c = switch ($d.Status) { 'clean' { 'DarkGray' } 'dirty' { 'Red' } 'unproven' { 'Yellow' } default { 'DarkGray' } }
        Write-WcnLine ("        {0} | {1} : {2} — {3}" -f $d.Server, $d.Database, $d.Status, $d.Note) $c
    }
}
