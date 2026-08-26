# Stage-Printers.ps1 — RECORD every printer, then DELETE every printer.
#
# ⛔ WHAT THIS REPLACES. The old kit's only mention of printers was a line in a runbook telling
# the operator to "review printers with Cegedim". Nothing deleted anything. So every image
# imported so far arrived carrying the pharmacy's physical printer set — queues pointing at USB
# ports that no longer exist and IP printers on a LAN the VM is not on — and clearing them was
# one of the ten manual post-import repairs somebody did by hand at every site.
#
# The agreed baseline moves that repair TO SOURCE: all printers deleted, clean slate, and the
# platform's own printer model puts them back. That model is not optional decoration — the queue
# name IS the Windows printer name, RDP names a redirected printer after the CUPS queue, and
# ProScript stores that name in its report mapping. A leftover local printer with the same name
# as a queue the Pi is about to redirect is a name collision on the one string that must not
# change, and Windows resolves it by renaming the redirected one. Dispensing then prints to a
# port that does not exist.
#
# ⭐ RECORD FIRST, AND THAT IS NOT A FORMALITY. This deletes the site's printer configuration
# with no undo. The recorded set is the only way to answer "what did this pharmacy actually
# have?" afterwards — which is what the printer queues are rebuilt from, and what tells an
# engineer that counter 3 had a Zebra on ETP tokens. It is written to disk BEFORE the first
# deletion and beside the artefact, so it survives even if this PC is wiped an hour later.
#
# ⚠️ TRI-STATE OUT. printers_cleared is $true / $false / $null and $null means "this run did not
# establish it". A run that could not read the spooler reports $null, never $false and never
# $true — pmr_site_captures' own comment says a false all-clear here is a site imported with the
# pharmacy's old printers still installed.

Set-StrictMode -Version 2.0

# Windows' own pseudo-printers. Not the pharmacy's configuration, present on every Windows
# install, and removing them changes nothing about the image except to make it look unlike
# Windows. Matched on the WHOLE name, so a real printer called "Fax Downstairs" is not caught.
$script:WcnBuiltInPrinters = @(
    'Microsoft Print to PDF',
    'Microsoft XPS Document Writer',
    'Fax',
    'OneNote (Desktop)',
    'OneNote for Windows 10',
    'Send To OneNote 2016',
    'Send to Microsoft OneNote 16'
)

function Get-WcnPrinterInventory {
    <#
      Everything about the site's printers, in the vocabulary the platform's printer contract
      already uses — the physical device is identified by USB serial or network address and NOT
      by its name, because a printer keeps its identity across a rename and across a move to
      another counter. Recording the name alone would produce provenance nobody can act on.
    #>
    $inv = [ordered]@{
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
        hostname     = $env:COMPUTERNAME
        readable     = $false
        error        = $null
        printers     = @()
        ports        = @()
        drivers      = @()
    }
    try {
        $printers = @(Get-Printer -ErrorAction Stop)
        $ports    = @(Get-PrinterPort -ErrorAction SilentlyContinue)
        $drivers  = @(Get-PrinterDriver -ErrorAction SilentlyContinue)
        $portMap  = @{}
        foreach ($p in $ports) { $portMap[$p.Name] = $p }

        foreach ($p in $printers) {
            $port = $(if ($p.PortName -and $portMap.ContainsKey($p.PortName)) { $portMap[$p.PortName] } else { $null })
            $inv.printers += [ordered]@{
                name        = $p.Name
                # The identity that survives a rename: where it actually is.
                port_name   = $p.PortName
                port_type   = $(if ($port) { [string]$port.Description } else { $null })
                host_address = $(if ($port -and $port.PSObject.Properties['PrinterHostAddress']) { [string]$port.PrinterHostAddress } else { $null })
                driver      = $p.DriverName
                share_name  = $p.ShareName
                shared      = [bool]$p.Shared
                published   = [bool]$p.Published
                type        = [string]$p.Type          # Local | Connection
                # Which one ProScript prints to by default is the single most operationally
                # important fact in this whole record.
                is_default  = $false
                location    = $p.Location
                comment     = $p.Comment
            }
        }
        # Get-Printer does not report the default; the legacy CIM class does.
        try {
            $def = @(Get-CimInstance Win32_Printer -ErrorAction Stop | Where-Object { $_.Default })
            foreach ($d in $def) {
                foreach ($rec in $inv.printers) { if ($rec.name -eq $d.Name) { $rec.is_default = $true } }
            }
        } catch { }

        foreach ($p in $ports) {
            $inv.ports += [ordered]@{
                name = $p.Name; description = $p.Description
                host_address = $(if ($p.PSObject.Properties['PrinterHostAddress']) { [string]$p.PrinterHostAddress } else { $null })
                port_number  = $(if ($p.PSObject.Properties['PortNumber']) { [string]$p.PortNumber } else { $null })
            }
        }
        foreach ($d in $drivers) { $inv.drivers += [ordered]@{ name = $d.Name; manufacturer = $d.Manufacturer; environment = $d.PrinterEnvironment } }
        $inv.readable = $true
    } catch {
        # Spooler stopped, WMI broken, PrintManagement module absent on an old build. All of
        # them mean the same thing: we do not know what printers this PC has.
        $inv.error = $_.Exception.Message
        $inv.readable = $false
    }
    return $inv
}

function Invoke-WcnPrinterPurge {
    <#
      Returns @{ Cleared; Inventory; Removed; Remaining; ProvenancePath; Note }

      Cleared is the TRI-STATE:
        $true   every non-built-in printer is gone, confirmed by re-reading the spooler
        $false  we could read the spooler, we tried, and something is still there
        $null   we could not read the spooler at all — established nothing

      -DryRun lists what would go and returns Cleared = $null, because a dry run establishes
      nothing about the finished state and must not be able to report an all-clear.
    #>
    param(
        [Parameter(Mandatory)][string]$ProvenanceDir,
        [switch]$DryRun,
        [switch]$KeepBuiltIn
    )

    Write-WcnInfo 'reading the printer configuration before touching anything'
    $inv = Get-WcnPrinterInventory

    if (-not $ProvenanceDir) { throw 'Invoke-WcnPrinterPurge needs a ProvenanceDir' }
    if (-not (Test-Path $ProvenanceDir)) { New-Item -ItemType Directory -Force -Path $ProvenanceDir | Out-Null }
    $provPath = Join-Path $ProvenanceDir 'printers-removed.json'

    if (-not $inv.readable) {
        Write-WcnWarn ("the print spooler could not be read: {0}" -f $inv.error)
        Write-WcnWarn 'printers_cleared will be reported as NOT ESTABLISHED (null), not as false and certainly not as true'
        ($inv | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $provPath -Encoding UTF8
        return [pscustomobject]@{
            Cleared = $null; Inventory = $inv; Removed = @(); Remaining = @()
            ProvenancePath = $provPath
            Note = ("the spooler was unreadable: {0}" -f $inv.error)
        }
    }

    # ⭐ WRITTEN BEFORE THE FIRST DELETION. If the process dies mid-purge, the record of what
    # was there still exists — which is the entire point of recording it.
    ($inv | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $provPath -Encoding UTF8
    Write-WcnOk ("recorded {0} printer(s) to {1}" -f @($inv.printers).Count, $provPath)

    $targets = @($inv.printers | Where-Object {
        $KeepBuiltIn.IsPresent -eq $false -or ($script:WcnBuiltInPrinters -notcontains $_.name)
    })
    if ($KeepBuiltIn) {
        Write-WcnInfo ("keeping Windows' own pseudo-printers: {0}" -f ($script:WcnBuiltInPrinters -join ', '))
    }

    if ($targets.Count -eq 0) {
        Write-WcnOk 'there are no printers to remove'
        return [pscustomobject]@{
            Cleared = $(if ($DryRun) { $null } else { $true })
            Inventory = $inv; Removed = @(); Remaining = @(); ProvenancePath = $provPath
            Note = 'no printers were installed'
        }
    }

    foreach ($t in $targets) {
        Write-WcnLine ("        {0}  ->  {1}  [{2}]{3}" -f $t.name, $t.port_name, $t.driver, $(if ($t.is_default) { '  (DEFAULT)' } else { '' })) 'DarkGray'
    }

    if ($DryRun) {
        Write-WcnWarn ("DRY RUN: {0} printer(s) would be deleted; nothing was touched" -f $targets.Count)
        return [pscustomobject]@{
            Cleared = $null      # a dry run establishes nothing
            Inventory = $inv; Removed = @(); Remaining = @($targets | ForEach-Object { $_.name })
            ProvenancePath = $provPath
            Note = 'dry run — no printer was deleted'
        }
    }

    $removed = @()
    foreach ($t in $targets) {
        try {
            Remove-Printer -Name $t.name -ErrorAction Stop
            $removed += $t.name
            Write-WcnLine ("        deleted: {0}" -f $t.name) 'DarkGray'
        } catch {
            # Retry through the legacy CIM path: Remove-Printer fails on some connection-type
            # printers and on entries whose driver has already gone, and Win32_Printer.Delete()
            # gets those.
            try {
                $cim = Get-CimInstance Win32_Printer -Filter ("Name='{0}'" -f ($t.name -replace "'", "''")) -ErrorAction Stop
                if ($cim) { $cim | Remove-CimInstance -ErrorAction Stop; $removed += $t.name; Write-WcnLine ("        deleted (cim): {0}" -f $t.name) 'DarkGray' }
            } catch {
                Write-WcnWarn ("could not delete printer '{0}': {1}" -f $t.name, $_.Exception.Message)
            }
        }
    }

    # Ports next. A deleted printer leaves its TCP/IP port behind, and a port pointing at
    # 192.168.x on the pharmacy LAN is meaningless in the VM and looks to an engineer like a
    # printer that is still configured. Built-in ports (LPT/COM/FILE/PORTPROMPT/nul) stay:
    # removing those is a change to Windows itself, not to the site's configuration.
    foreach ($p in $inv.ports) {
        if ($p.name -match '^(LPT\d+:|COM\d+:|FILE:|PORTPROMPT:|nul:|SHRFAX:)$') { continue }
        try { Remove-PrinterPort -Name $p.name -ErrorAction Stop; Write-WcnLine ("        deleted port: {0}" -f $p.name) 'DarkGray' }
        catch { }   # A port still referenced by a printer we failed to delete. The re-read below is the judge, not this.
    }

    # ⭐ THE ALL-CLEAR IS EARNED BY RE-READING, NEVER BY COUNTING SUCCESSES. "I called
    # Remove-Printer N times without throwing" is not the same fact as "there are no printers",
    # and the second one is what the record claims.
    $after = Get-WcnPrinterInventory
    if (-not $after.readable) {
        Write-WcnWarn 'the spooler could not be re-read, so the result cannot be confirmed — reporting NOT ESTABLISHED'
        return [pscustomobject]@{
            Cleared = $null; Inventory = $inv; Removed = $removed; Remaining = @()
            ProvenancePath = $provPath; Note = 'the post-purge re-read failed'
        }
    }
    $remaining = @($after.printers | Where-Object {
        $KeepBuiltIn.IsPresent -eq $false -or ($script:WcnBuiltInPrinters -notcontains $_.name)
    } | ForEach-Object { $_.name })

    if ($remaining.Count -eq 0) {
        Write-WcnOk ("all printers deleted ({0} removed); the spooler is now clear" -f $removed.Count)
        return [pscustomobject]@{
            Cleared = $true; Inventory = $inv; Removed = $removed; Remaining = @()
            ProvenancePath = $provPath; Note = ("{0} removed" -f $removed.Count)
        }
    }
    Write-WcnWarn ("{0} printer(s) are still present: {1}" -f $remaining.Count, ($remaining -join ', '))
    return [pscustomobject]@{
        Cleared = $false; Inventory = $inv; Removed = $removed; Remaining = $remaining
        ProvenancePath = $provPath
        Note = ("still present: {0}" -f ($remaining -join ', '))
    }
}
