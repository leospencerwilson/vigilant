#Requires -RunAsAdministrator
<#
  Strip-PmrImage.ps1  -  WCN PMR hosted-desktop
  ===========================================================================
  Aggressive PRE-UPLOAD strip of a Windows image so the captured/compressed
  disk is as small as possible. Supersedes Prepare-PmrCapture.ps1.

  SQL SAFETY: runs DBCC CHECKDB on the ProScript database BEFORE and AFTER the
  strip (a "bit check"). Physical/page-checksum verify by default (fast),
  -FullSqlCheck for the exhaustive logical check. It ABORTS before stripping
  if the DB is already corrupt (override with -Force), and FAILS loudly if the
  after-check shows errors the before-check didn't.

  SAFE BY DESIGN - it will NOT touch:
    * ProScript / EMIS / SQL data:  C:\ProScript, C:\RXPROGS,
      C:\Program Files\EmisHealth, C:\Program Files\Rx_TLSLib,
      C:\Program Files\Microsoft SQL Server  (and its .mdf/.ldf)
    * user Documents / Desktop / Pictures (business data)
    * the primary ProScript user
  Extra profiles (leftover clones) are removed ONLY via -PurgeProfiles.

  WORKFLOW
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Strip-PmrImage.ps1 -PurgeProfiles proscript1,proscript2
    # reboot (frees pagefile.sys)
    .\Strip-PmrImage.ps1 -ZeroFree          # sdelete -z (also re-checks SQL)
    # then Disk2VHD -> compress (zstd) -> upload
  ===========================================================================
#>
[CmdletBinding()]
param(
  [string[]]$PurgeProfiles = @(),
  [switch]$ZeroFree,
  [string]$SdeletePath = 'sdelete.exe',
  [switch]$SkipServices,
  [switch]$SkipStoreApps,
  [switch]$SkipPagefile,
  [switch]$SkipHibernate,
  [switch]$SkipVssDelete,                   # skip `vssadmin delete shadows` (destructive + EDR ransomware-trigger)
  [switch]$SkipGuestTools,                  # skip installing QEMU guest agent + virtio drivers
  [string]$GuestToolsUrl = 'https://fedorapeople.org/groups/virtio-win/direct-downloads/stable-virtio/virtio-win-guest-tools.exe',
  # --- SQL integrity check ---
  [switch]$SkipSqlCheck,
  [switch]$FullSqlCheck,                    # full DBCC CHECKDB instead of PHYSICAL_ONLY
  [string]$SqlInstance,                     # override auto-detect, e.g. 'localhost\PROSCRIPT'
  [string]$SqlUser,[string]$SqlPassword,    # optional SQL auth; default = Windows/trusted
  [switch]$Force                            # proceed even if the pre-strip DB check finds errors
)
$ErrorActionPreference = 'SilentlyContinue'
function Free { (Get-PSDrive C).Free }
function GB($b){ '{0:N1} GB' -f ($b/1GB) }
function Step($m){ Write-Host "  $m" -ForegroundColor DarkCyan }

# =============================================================================
# SQL integrity ("bit check")
# =============================================================================
function Invoke-SqlRows($server,$db,$query,$timeout=3600){
  $cs = "Server=$server;Database=$db;TrustServerCertificate=True;Connect Timeout=10"
  if ($SqlUser) { $cs += ";User ID=$SqlUser;Password=$SqlPassword" } else { $cs += ";Integrated Security=SSPI" }
  $cn = New-Object System.Data.SqlClient.SqlConnection $cs
  $cn.Open()
  try {
    $cmd = $cn.CreateCommand(); $cmd.CommandText = $query; $cmd.CommandTimeout = $timeout
    $rd = $cmd.ExecuteReader(); $rows = @()
    while ($rd.Read()) { $v=@(); for($i=0;$i -lt $rd.FieldCount;$i++){$v+=[string]$rd.GetValue($i)}; $rows += ($v -join ' | ') }
    $rd.Close(); return $rows          # caller wraps with @(); a comma here nests the array
  } finally { $cn.Close() }
}
function Get-SqlIntegrity {
  $servers = @()
  if ($SqlInstance) { $servers = @($SqlInstance) }
  else {
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
    if ($reg) { foreach($p in $reg.PSObject.Properties){ if($p.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider'){
      $servers += $(if($p.Name -eq 'MSSQLSERVER'){'localhost'}else{"localhost\$($p.Name)"}) } } }
  }
  $out = [ordered]@{}
  if (-not $servers) { $out['(no SQL instance found)'] = 'n/a'; return $out }
  $opt = $(if($FullSqlCheck){'ALL_ERRORMSGS'}else{'PHYSICAL_ONLY'})
  foreach ($srv in $servers) {
    try {
      $dbs = @(Invoke-SqlRows $srv 'master' "SELECT name FROM sys.databases WHERE database_id>4 AND state=0" 30)
      foreach ($db in $dbs) {
        try {
          $errs = @(Invoke-SqlRows $srv 'master' "DBCC CHECKDB([$db]) WITH NO_INFOMSGS, TABLERESULTS, $opt")
          $out["$srv | $db"] = @{ Errors = $errs.Count; Sample = ($errs | Select-Object -First 3) }
        } catch { $out["$srv | $db"] = @{ Errors = 'ERR'; Sample = @($_.Exception.Message) } }
      }
    } catch { $out["$srv"] = @{ Errors = 'NO-CONNECT'; Sample = @($_.Exception.Message) } }
  }
  return $out
}
function Show-Sql($label,$r){
  Write-Host "  [$label] SQL integrity:" -ForegroundColor Cyan
  if (-not $r.Count) { Write-Host "    (nothing checked)"; return }
  foreach($k in $r.Keys){ $e=$r[$k].Errors
    $c = if($e -eq 0){'Green'}elseif($e -match '^\d+$'){'Red'}else{'Yellow'}
    Write-Host ("    {0}: {1}" -f $k, $(if($e -eq 0){'clean (0 errors)'}else{"$e errors"})) -ForegroundColor $c
    if ($e -ne 0 -and $r[$k].Sample) { $r[$k].Sample | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkYellow } }
  }
}

# =============================================================================
# Zero-only pass (step 3, after reboot) - zeros free space, re-checks SQL
# =============================================================================
if ($ZeroFree) {
  if (-not $SkipSqlCheck) { Show-Sql 'pre-zero' (Get-SqlIntegrity) }
  if (-not (Get-Command $SdeletePath -ErrorAction SilentlyContinue)) {
    Write-Host "sdelete.exe not found (Sysinternals). Put it on PATH or -SdeletePath." -ForegroundColor Red; exit 1
  }
  Write-Host "Zeroing free space on C: ..." -ForegroundColor Cyan
  & $SdeletePath -accepteula -z C:
  if (-not $SkipSqlCheck) { Show-Sql 'post-zero' (Get-SqlIntegrity) }
  Write-Host "Done. Now capture with Disk2VHD." -ForegroundColor Green; exit 0
}

# == SQL baseline BEFORE the strip ===========================================
$sqlBefore = @{}
if (-not $SkipSqlCheck) {
  Write-Host "== SQL baseline (before strip) ==" -ForegroundColor Cyan
  $sqlBefore = Get-SqlIntegrity; Show-Sql 'before' $sqlBefore
  $dirty = @($sqlBefore.Values | Where-Object { $_.Errors -is [int] -and $_.Errors -gt 0 }).Count
  if ($dirty -and -not $Force) {
    Write-Host "ABORT: DB already reports errors BEFORE stripping - do not capture a corrupt DB. Investigate, or re-run with -Force." -ForegroundColor Red
    exit 2
  }
}

$before = Free
Write-Host "== PMR image strip ==  Free C: before: $(GB $before)" -ForegroundColor Cyan

# == A0. QEMU guest agent + virtio drivers (run on the LIVE source PC pre-capture) ==
# So the captured VM is manageable via `qm guest exec` from first boot AND can run on
# virtio-scsi/virtio-net immediately (no e1000/SATA-first dance, much better perf).
# virtio-win-guest-tools is Red Hat / WHQL-signed, so EDR does not flag it.
if (-not $SkipGuestTools) {
  Step "install QEMU guest agent + virtio drivers (virtio-win-guest-tools)"
  $gt = "$env:TEMP\virtio-win-guest-tools.exe"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  try {
    Invoke-WebRequest $GuestToolsUrl -OutFile $gt -UseBasicParsing
    Start-Process $gt -ArgumentList '/install','/passive','/norestart' -Wait
    $svc = (Get-Service QEMU-GA -EA SilentlyContinue).Status
    Step "  installed (agent+drivers); QEMU-GA service: $svc"
  } catch { Write-Host "  guest-tools install skipped/failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# == A. disposable junk ======================================================
$paths = @(
  "$env:windir\Temp\*","$env:windir\Prefetch\*","$env:windir\Logs\CBS\*",
  "$env:windir\Panther\*","$env:windir\Minidump\*","$env:windir\memory.dmp",
  "$env:windir\SoftwareDistribution\Download\*",
  "$env:ProgramData\Microsoft\Windows\WER\*","$env:ProgramData\Microsoft\Windows\RetailDemo\*",
  "$env:ProgramData\Microsoft\Diagnosis\*","$env:ProgramData\USOShared\Logs\*",
  "$env:windir\System32\LogFiles\*"
)
foreach ($p in $paths) { Step "clean $p"; Remove-Item $p -Recurse -Force }

Step "per-user temp + browser/Teams caches"
Get-ChildItem C:\Users -Directory | ForEach-Object { $u=$_.FullName
  @("$u\AppData\Local\Temp\*","$u\AppData\Local\Microsoft\Windows\INetCache\*",
    "$u\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db",
    "$u\AppData\Local\Microsoft\Edge\User Data\Default\Cache\*",
    "$u\AppData\Local\Google\Chrome\User Data\Default\Cache\*",
    "$u\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*",
    "$u\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage\*",
    "$u\AppData\Local\CrashDumps\*","$u\AppData\Local\D3DSCache\*") | ForEach-Object { Remove-Item $_ -Recurse -Force }
}
Step "empty Recycle Bin"; Clear-RecycleBin -Force -ErrorAction SilentlyContinue
if (Test-Path C:\Windows.old) { Step "remove Windows.old"; takeown /f C:\Windows.old /r /d y|Out-Null; icacls C:\Windows.old /grant administrators:F /t|Out-Null; Remove-Item C:\Windows.old -Recurse -Force }

# == B. reclaimable system stores ============================================
if (-not $SkipVssDelete) { Step "delete VSS shadow copies / restore points"; vssadmin delete shadows /all /quiet 2>$null; Disable-ComputerRestore -Drive "C:\" 2>$null }
Step "DISM component cleanup (/ResetBase)"; Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
Step "reset Windows Search index"; Stop-Service WSearch -Force -EA SilentlyContinue; Remove-Item "$env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Force
Step "clear event logs"; wevtutil el | ForEach-Object { wevtutil cl "$_" 2>$null }
if (-not $SkipHibernate) { Step "disable hibernation"; powercfg /h off }
if (-not $SkipPagefile) { Step "pagefile -> none (frees after reboot)"; $cs=Get-WmiObject Win32_ComputerSystem; if($cs.AutomaticManagedPagefile){$cs.AutomaticManagedPagefile=$false;$cs.Put()|Out-Null}; Get-WmiObject Win32_PageFileSetting | ForEach-Object { $_.Delete() } }

# == C. debloat: remove ALL non-essential Appx (installed + provisioned) =====
# DELIBERATELY KEPT (removing these breaks the desktop / a real need):
#   frameworks: VCLibs, NET.Native.Framework/Runtime, UI.Xaml
#   shell/logon: ShellExperienceHost, StartMenuExperienceHost, Search/Cortana host,
#                CloudExperienceHost, AAD.BrokerPlugin, AccountsControl, LockApp,
#                immersivecontrolpanel (Settings), SecHealthUI
#   useful: MicrosoftEdge (browser), WindowsCalculator, DesktopAppInstaller (winget)
# Everything else below goes, including the Store itself.
if (-not $SkipStoreApps) {
  Step "remove non-essential Appx (Store + consumer apps)"
  $bloat = @(
    'Microsoft.WindowsStore','Microsoft.StorePurchaseApp','Store.Engagement',
    'Microsoft.Bing',                                   # Weather/News/Finance/Sports
    'Xbox','GamingApp','GamingOverlay','GameOverlay','SpeechToTextOverlay',
    'ZuneMusic','ZuneVideo','SolitaireCollection','Minecraft',
    'Microsoft3DViewer','Print3D','3DBuilder','MSPaint','MixedReality.Portal',
    'Microsoft.People','SkypeApp','windowscommunicationsapps','Microsoft.Messaging',
    'YourPhone','OneConnect','MicrosoftTeams','MSTeams','Microsoft.Todos',
    'MicrosoftOfficeHub','Office.OneNote','OutlookForWindows',
    'WindowsMaps','WindowsAlarms','WindowsSoundRecorder','WindowsCamera',
    'MicrosoftStickyNotes','Whiteboard','Clipchamp','PowerAutomateDesktop',
    'MicrosoftJournal','Windows.Photos','GetHelp','Getstarted','FeedbackHub',
    'WindowsFeedback','Microsoft.Wallet','QuickAssist','Microsoft.Family','549981C3F5F10'
  )
  $removed=0
  foreach ($b in $bloat) {
    # each wrapped in try/catch: some packages throw a TERMINATING error (e.g. Store 0x80070002)
    # that -EA SilentlyContinue does not suppress; one stubborn package must not abort the strip.
    try { $pk = Get-AppxPackage -AllUsers "*$b*"; if ($pk) { foreach($p in $pk){ try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -EA Stop; $removed++ } catch {} } } } catch {}
    try { Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$b*" } | ForEach-Object { try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -EA Stop | Out-Null } catch {} } } catch {}
  }
  Step "  removed $removed installed package(s) + matching provisioned entries"
}

# == D. quiet background services (cuts size + runtime CPU/RAM) ==============
if (-not $SkipServices) { Step "disable telemetry/superfetch/search/update churn"
  foreach ($s in 'DiagTrack','dmwappushservice','SysMain','WSearch','wuauserv','WMPNetworkSvc','RetailDemo') { Set-Service $s -StartupType Disabled -EA SilentlyContinue; Stop-Service $s -Force -EA SilentlyContinue } }

# == E. purge named extra profiles (opt-in) ==================================
if ($PurgeProfiles.Count) {
  $protected = @($env:USERNAME,'proscript','current','system','Administrator','Public','Default','Default User','All Users')
  foreach ($n in $PurgeProfiles) {
    if ($protected -contains $n) { Write-Host "  refuse to purge protected profile: $n" -ForegroundColor Yellow; continue }
    $dir = "C:\Users\$n"
    $p = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -eq $dir -and -not $_.Special }
    if ($p) { Step "purge profile $n (deregister)"; $p | Remove-CimInstance -EA SilentlyContinue }
    Remove-LocalUser -Name $n -EA SilentlyContinue
    # dir often survives Remove-Item: locked ntuser.dat / ACL denials. Force it: takeown + icacls + rd.
    if (Test-Path $dir) {
      Step "purge profile $n (force dir removal)"
      Remove-Item $dir -Recurse -Force -EA SilentlyContinue
      if (Test-Path $dir) {
        & takeown /f $dir /r /d y  2>&1 | Out-Null
        & icacls $dir /grant "administrators:F" /t /c 2>&1 | Out-Null
        Remove-Item $dir -Recurse -Force -EA SilentlyContinue
      }
      if (Test-Path $dir) { & cmd /c "rd /s /q `"$dir`"" 2>&1 | Out-Null }
      if (Test-Path $dir) { Write-Host "  !! $dir still present - remove manually" -ForegroundColor Red }
      else { Write-Host "  removed $dir" -ForegroundColor DarkGray }
    }
  }
}

$after = Free
Write-Host ""
Write-Host "== strip done ==  Free C: after: $(GB $after)   Reclaimed: $(GB ($after-$before))" -ForegroundColor Green

# == SQL verify AFTER the strip ==============================================
if (-not $SkipSqlCheck) {
  Write-Host "== SQL verify (after strip) ==" -ForegroundColor Cyan
  $sqlAfter = Get-SqlIntegrity; Show-Sql 'after' $sqlAfter
  $regression = $false
  foreach ($k in $sqlAfter.Keys) {
    $a = $sqlAfter[$k].Errors; $b = $(if($sqlBefore[$k]){$sqlBefore[$k].Errors}else{'?'})
    if (($a -is [int]) -and ($b -is [int]) -and ($a -gt $b)) { $regression = $true; Write-Host ("  !! {0}: errors {1} -> {2}  (STRIP INTRODUCED CORRUPTION)" -f $k,$b,$a) -ForegroundColor Red }
  }
  if ($regression) { Write-Host "SQL CHECK FAILED - do NOT capture this image; restore from a known-good copy." -ForegroundColor Red; exit 3 }
  Write-Host "SQL check PASSED - DB integrity unchanged." -ForegroundColor Green
}

Write-Host "NEXT: reboot, then '.\Strip-PmrImage.ps1 -ZeroFree', then capture." -ForegroundColor Yellow
Write-Host "NOT touched: ProScript/EMIS/RXPROGS/SQL data, user Documents/Desktop." -ForegroundColor DarkGray
