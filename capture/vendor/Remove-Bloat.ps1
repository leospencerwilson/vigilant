<#
  Remove-Bloat.ps1  -  reusable PMR onboarding debloat
  Built from the whole-PC classification workflow (2026-08-20) on RX54554 (VM 301).
  PATTERN-based (by name / path glob) so it runs on ANY pharmacy PC, not just this box.

  SAFE BY DEFAULT: dry-run unless you pass -Execute. Everything ProScript / EMIS / SQL 2014
  engine + data / NHS-Spine smartcard / .NET+VC++ runtimes / virtio-QEMU is HARD-PROTECTED and
  never touched. Items the audit marked "verify" (Office, Adobe, Java, Chrome, Edge/WebView2,
  printer drivers, the *.bak backups, Windows\Installer cache, the SQL 2019 engine) are NOT in
  here - decide those with Cegedim/EMIS and add them explicitly if approved.

  Usage:
    .\Remove-Bloat.ps1              # dry run - lists what WOULD be removed + reclaim estimate
    .\Remove-Bloat.ps1 -Execute     # actually remove
#>
param([switch]$Execute,[switch]$DeepInstaller)

$ErrorActionPreference = 'Continue'
$logDir = 'C:\wcn-imageprep'; if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
$log = Join-Path $logDir 'bloat.log'
$mode = if ($Execute) { 'EXECUTE' } else { 'DRY-RUN' }
"== Remove-Bloat ($mode) $(Get-Date -f 'yyyy-MM-dd HH:mm:ss') ==" | Set-Content $log -Encoding ASCII
function L($m){ $m | Tee-Object -FilePath $log -Append | Out-Null }
function GBfree(){ [math]::Round((Get-PSDrive C).Free/1GB,2) }

# ---- HARD PROTECT: never remove anything matching (apps AND paths) --------------------------
# SQL protection is VERSION/INSTANCE-AGNOSTIC (do NOT hardcode a year or instance name - other
# pharmacies run 2016/2019 and different instance names). Protects the engine + connectivity, not the
# admin GUIs (SSMS/ADS), which stay removable.
$NEVER = 'proscript|emis|rxsystems|database engine|sql server.*(common files|shared|setup|rsfx|batch|xevent|client tools|t-sql|policies|writer|connectivity)|analysis services ole|ole db provider|ole db driver|odbc driver|native client|\.net|desktop runtime|\.net runtime|visual c\+\+|asp\.net core|dotnet|virtio|qemu guest|spice|qxl|\bnhs\b|oberthur|gemalto|idemia|\bawp\b|classic client|quovadx|identity agent|credential management|drugcomparison|lexon|datastreaming|rx scheduler|vss writer|clr types|usbip'
# Any SQL version/instance data dir (MSSQL<ver>.<INSTANCE>\DATA) + any engine install + ProScript data + EMIS + never a .bak
$PROTECT_PATH = 'C:\\ProScript|C:\\RXPROGS|C:\\PSPRODUCTS|C:\\pssharedarea|EmisHealth|EMIS Health|Microsoft SQL Server\\MSSQL\d+\.|MSSQL\d+\.[^\\]+\\MSSQL\\DATA|\.bak(\b|$)'

# =============================================================================================
# A. APPLICATIONS  (uninstall by DisplayName pattern; quiet; per-app 180s watchdog)
# =============================================================================================
$APP_PATTERNS = @(
  # SQL/DB admin GUIs (NOT the engine or the connectivity drivers)
  'SQL Server Management Studio','Azure Data Studio','Isolated Shell','^SSMS','SSMS Post Install',
  'Visual Studio 2010 Shell','Visual Studio 2010 Prerequisites','Management Studio Language Pack',
  # consumer / MS bloat
  'Copilot','OneDrive','Teams Machine-Wide','Teams Meeting Add-in','PC Health Check',
  'Update Health Tools','HEVC Media Extension','Microsoft Help Viewer','Vulkan Run Time',
  # dev / util
  '^Git$','Revo Uninstaller',
  # OLD-IT remote access / RMM
  'AnyDesk','Chrome Remote Desktop','BeyondTrust','LogMeIn','^Helpdesk$','Datto RMM','CentraStage',
  # physical-hardware stacks useless in a VM
  'Intel\(R\) Management Engine','Intel\(R\) LMS','Intel\(R\) Trusted Connect','Intel\(R\) Chipset',
  'Intel\(R\) Wireless','Intel\(R\) Serial IO','Security Assist','Dynamic Application Loader',
  'RstDowngradeGuard','OptaneDowngradeGuard','Intel\(R\) ME','Realtek Audio','Maxx Audio',
  'SUNIX','Qualcomm','Cypress Semiconductor','Google Update Helper','Upsmon'
)
$keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$installed = foreach($k in $keys){ Get-ItemProperty $k -EA SilentlyContinue | Where-Object DisplayName }
L "`n-- A. applications --"
foreach($pat in $APP_PATTERNS){
  foreach($h in ($installed | Where-Object { $_.DisplayName -match $pat })){
    if($h.DisplayName -match $NEVER){ L "  PROTECT (skip): $($h.DisplayName)"; continue }
    $u=$h.UninstallString; $q=$h.QuietUninstallString; $cmd=$null;$uargs=$null
    if($q){ $cmd='cmd.exe'; $uargs="/c `"$q`"" }
    elseif($u -match 'msiexec'){ $g=[regex]::Match($u,'\{[0-9A-Fa-f\-]+\}').Value; if($g){ $cmd='msiexec.exe'; $uargs="/x $g /qn /norestart" } }
    elseif($u){ $cmd='cmd.exe'; $uargs="/c `"$u`" /S /silent /qn /norestart" }
    if(-not $cmd){ L "  ?? no uninstall string: $($h.DisplayName)"; continue }
    if(-not $Execute){ L "  WOULD uninstall: $($h.DisplayName)"; continue }
    L "  uninstalling: $($h.DisplayName)"
    try{ $p=Start-Process $cmd -ArgumentList $uargs -PassThru -WindowStyle Hidden -EA Stop
         if(-not $p.WaitForExit(180000)){ $p.Kill(); L "    !! 180s timeout -> killed (skipped)" } else { L "    done exit=$($p.ExitCode)" }
    }catch{ L "    !! $($_.Exception.Message)" }
  }
}
# Appx-packaged extras (Claude desktop, HEVC) - Remove-Item can't touch WindowsApps
foreach($ax in 'Claude','HEVCVideoExtension'){
  foreach($pk in (Get-AppxPackage "*$ax*" -EA SilentlyContinue)){
    if($pk.Name -match $NEVER){ continue }
    if(-not $Execute){ L "  WOULD remove appx: $($pk.Name)"; continue }
    try{ Remove-AppxPackage $pk.PackageFullName -EA Stop; L "  removed appx: $($pk.Name)" }catch{ L "  !! appx $($pk.Name): $($_.Exception.Message)" }
  }
}

# =============================================================================================
# B. FILES / DIRS  (path + glob patterns; robust removal)
# =============================================================================================
$PATHS = @(
  'C:\ESD',                                                   # Windows reset media
  'C:\SQL20*',                                                # extracted SQL installer staging (any year; NOT the engine, which lives under Program Files)
  'C:\*\SQL20*Upgrade\SetupFiles',                            # SQL/SSMS installer staging under any vendor folder (NOT ..\Backups\*.bak - that is verify + .bak is PROTECT_PATH)
  'C:\ProgramData\Dell',                                      # Dell driver-download cache
  'C:\ProgramData\Intel',
  'C:\ProgramData\Intel Package Cache*',
  'C:\ProgramData\CentraStage',                               # Datto RMM
  'C:\ProgramData\LogMeIn Rescue Calling Card',
  'C:\Program Files\Git','C:\Program Files\Azure Data Studio','C:\Program Files\Waves',
  'C:\Program Files (x86)\Microsoft SQL Server Management Studio *','C:\Program Files\Microsoft SQL Server Management Studio *',  # any SSMS version
  'C:\Program Files (x86)\Microsoft Visual Studio 10.0',
  'C:\Program Files (x86)\Teams Installer','C:\Program Files (x86)\CentraStage','C:\Program Files (x86)\Realtek',
  'C:\Users\*\Downloads\*.img','C:\Users\*\Downloads\*.iso',  # OS/Office install media
  'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache',           # browser cache
  'C:\Users\*\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel', # Chrome on-device AI models (~4GB)
  'C:\Program Files (x86)\Google\GoogleUpdater\crx_cache',
  'C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\iconcache*',
  'C:\Users\*\.local\share\claude','C:\Users\*\.local\bin\claude.exe',
  'C:\Users\*\AppData\Local\Packages\Claude_*'
)
L "`n-- B. files / dirs --"
foreach($pat in $PATHS){
  foreach($it in (Get-Item $pat -Force -EA SilentlyContinue)){
    $fp=$it.FullName
    if($fp -match $PROTECT_PATH){ L "  PROTECT (skip): $fp"; continue }
    $mb = if($it.PSIsContainer){ [math]::Round(((Get-ChildItem $fp -Recurse -File -Force -EA SilentlyContinue | Measure-Object Length -Sum).Sum)/1MB,0) } else { [math]::Round($it.Length/1MB,0) }
    if(-not $Execute){ L ("  WOULD delete {0,7} MB  {1}" -f $mb,$fp); continue }
    Remove-Item $fp -Recurse -Force -EA SilentlyContinue
    if(Test-Path $fp){ & takeown /f $fp /r /d y 2>&1|Out-Null; & icacls $fp /grant "administrators:F" /t /c 2>&1|Out-Null; Remove-Item $fp -Recurse -Force -EA SilentlyContinue }
    if(Test-Path $fp){ & cmd /c "rd /s /q `"$fp`"" 2>&1|Out-Null }
    if(Test-Path $fp){ L "  !! still present: $fp" } else { L ("  deleted {0,7} MB  {1}" -f $mb,$fp) }
  }
}
# Recycle Bin (all drives)
if($Execute){ Clear-RecycleBin -Force -EA SilentlyContinue; L "  emptied Recycle Bin" } else { L "  WOULD empty Recycle Bin" }
# Windows Defender Application Guard feature (removes the 3x ~350MB WDAG .wim)
$wdag = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -EA SilentlyContinue
if($wdag -and $wdag.State -eq 'Enabled'){
  if(-not $Execute){ L "  WOULD disable optional feature: Windows-Defender-ApplicationGuard" }
  else{ try{ Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart -EA Stop | Out-Null; L "  disabled WDAG feature" }catch{ L "  !! WDAG: $($_.Exception.Message)" } }
}

# =============================================================================================
# C. SERVICES  (stop + delete by name; Edge* left alone - Edge/WebView2 is a verify item)
# =============================================================================================
$SVC = @('AnyDesk','AtherosSvc','CagService','chromoting','CoworkVMService','DellClientManagementService',
  'FileSyncHelper','GoogleUpdater*','Intel(R) Security Assist','isaHelperSvc','IntelGraphicsSoftwareService',
  'MicrosoftCopilotElevationService','OneDrive Updater Service','sra-pin-*','uhssvc','WMPNetworkSvc')
L "`n-- C. services --"
foreach($n in $SVC){
  foreach($s in (Get-Service -Name $n -EA SilentlyContinue)){
    if($s.Name -match $NEVER){ continue }
    if(-not $Execute){ L "  WOULD delete service: $($s.Name)"; continue }
    try{ Stop-Service $s.Name -Force -EA SilentlyContinue; & sc.exe delete $s.Name | Out-Null; L "  deleted service: $($s.Name)" }catch{ L "  !! svc $($s.Name): $($_.Exception.Message)" }
  }
}

# =============================================================================================
# D. AUTOSTART  (Run values + StartUp shortcuts + scheduled tasks)
# =============================================================================================
$RUN_NAMES = @('RtkAudUService','WavesSvc','Jump Client-emishealth.beyondtrustcloud.com-UI-startup','CentraStage')
$RUN_KEYS  = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
$TASK_PATTERNS = @('OneDrive','GoogleUpdater','GoogleUserPEH','Intel(R) Management and Security Status','Upsag_ap','DataSenseLiveTileTask')
L "`n-- D. autostart --"
foreach($rk in $RUN_KEYS){ foreach($nm in $RUN_NAMES){
  if((Get-ItemProperty $rk -Name $nm -EA SilentlyContinue)){
    if(-not $Execute){ L "  WOULD remove Run value: $rk :: $nm" }
    else{ Remove-ItemProperty $rk -Name $nm -EA SilentlyContinue; L "  removed Run value: $nm" }
  } } }
foreach($lnk in (Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*.lnk' -EA SilentlyContinue | Where-Object { $_.Name -match 'AnyDesk' })){
  if(-not $Execute){ L "  WOULD remove startup: $($lnk.Name)" } else { Remove-Item $lnk.FullName -Force -EA SilentlyContinue; L "  removed startup: $($lnk.Name)" }
}
foreach($tp in $TASK_PATTERNS){ foreach($t in (Get-ScheduledTask -EA SilentlyContinue | Where-Object { ($_.TaskName -like "*$tp*" -or $_.TaskPath -like "*$tp*") -and $_.TaskPath -notlike '\Microsoft\Windows\*' })){
  if(-not $Execute){ L "  WOULD delete task: $($t.TaskPath)$($t.TaskName)" }
  else{ try{ Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -EA Stop; L "  deleted task: $($t.TaskName)" }catch{ L "  !! task $($t.TaskName): $($_.Exception.Message)" } }
} }

# =============================================================================================
# E. WINDOWS OS DEEP-CLEAN  (safe; frees space + improves compressibility before capture)
# =============================================================================================
L "`n-- E. windows deep-clean --"
function RunExe($exe,$a,$sec){
  try{
    $p=Start-Process $exe -ArgumentList $a -PassThru -WindowStyle Hidden -EA Stop
    $t=0
    while(-not $p.HasExited){
      if($t -ge $sec){ $p.Kill(); L "    !! $exe timeout ${sec}s"; return }
      Start-Sleep -Seconds 5; $t+=5
      Write-Host ("      ... $exe still working  ({0:mm\:ss})" -f [TimeSpan]::FromSeconds($t)) -ForegroundColor DarkGray
    }
    L ("    $exe done exit=$($p.ExitCode)  ({0}s)" -f $t)
  }catch{ L "    !! ${exe}: $($_.Exception.Message)" }
}
function WipeInside($d){ if(Test-Path $d){ Get-ChildItem $d -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue } }
function Nuke($p){ if(Test-Path $p){ Remove-Item $p -Recurse -Force -EA SilentlyContinue; if(Test-Path $p){ & takeown /f $p /r /d y 2>&1|Out-Null; & icacls $p /grant "administrators:F" /t /c 2>&1|Out-Null; Remove-Item $p -Recurse -Force -EA SilentlyContinue }; if(Test-Path $p){ & cmd /c "rd /s /q `"$p`"" 2>&1|Out-Null } } }

# E1. WinSxS component-store cleanup (DISM)
if($Execute){ L "  DISM StartComponentCleanup /ResetBase (+ /SPSuperseded)"; RunExe 'dism.exe' '/online /Cleanup-Image /StartComponentCleanup /ResetBase' 1800; RunExe 'dism.exe' '/online /Cleanup-Image /SPSuperseded' 900 } else { L "  WOULD DISM /StartComponentCleanup /ResetBase + /SPSuperseded" }

# E2. Windows Update + Delivery Optimization cache
if($Execute){ foreach($s in 'wuauserv','bits','dosvc'){ Stop-Service $s -Force -EA SilentlyContinue }
  foreach($d in 'C:\Windows\SoftwareDistribution\Download','C:\Windows\SoftwareDistribution\DeliveryOptimization','C:\Windows\DeliveryOptimization'){ WipeInside $d }
  L "  cleared Windows Update / Delivery Optimization cache" } else { L "  WOULD clear Windows Update + Delivery Optimization cache" }

# E3. unused optional features (IE LEFT for NHS-legacy safety) + non-English language capabilities
$feats='WindowsMediaPlayer','Printing-XPSServices-Features','FaxServicesClientPackage','WorkFolders-Client','MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root','SMB1Protocol'
foreach($f in $feats){ $st=Get-WindowsOptionalFeature -Online -FeatureName $f -EA SilentlyContinue
  if($st -and $st.State -eq 'Enabled'){ if($Execute){ try{ Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -EA Stop | Out-Null; L "  disabled feature $f" }catch{ L "  !! feature $f" } } else { L "  WOULD disable feature $f" } } }
foreach($cap in (Get-WindowsCapability -Online -EA SilentlyContinue | Where-Object { $_.State -eq 'Installed' -and $_.Name -match '^Language\.' -and $_.Name -notmatch 'en-GB|en-US' })){
  if($Execute){ try{ Remove-WindowsCapability -Online -Name $cap.Name -EA Stop | Out-Null; L "  removed capability $($cap.Name)" }catch{ L "  !! cap $($cap.Name)" } } else { L "  WOULD remove capability $($cap.Name)" } }

# E4. WinRE recovery image
if($Execute){ RunExe 'reagentc.exe' '/disable' 60; Nuke 'C:\Recovery'; Nuke 'C:\Windows\System32\Recovery\Winre.wim'; L "  WinRE disabled + Recovery removed" } else { L "  WOULD disable WinRE + remove C:\Recovery" }

# E5. all-user caches + Windows Temp/Prefetch + Search index
$userCaches = 'AppData\Local\Temp','AppData\Local\Microsoft\Windows\INetCache','AppData\Local\Microsoft\Windows\Explorer','AppData\Local\Microsoft\Windows\WebCache','AppData\Local\Google\Chrome\User Data\*\Cache','AppData\Local\Google\Chrome\User Data\*\Code Cache','AppData\Local\Microsoft\Edge\User Data\*\Cache','AppData\Local\CrashDumps'
if($Execute){
  foreach($u in (Get-ChildItem C:\Users -Directory -EA SilentlyContinue)){
    foreach($rel in $userCaches){ foreach($it in (Get-Item (Join-Path $u.FullName $rel) -Force -EA SilentlyContinue)){ if($it.PSIsContainer){ WipeInside $it.FullName } else { Remove-Item $it.FullName -Force -EA SilentlyContinue } } }
  }
  WipeInside 'C:\Windows\Temp'; WipeInside 'C:\Windows\Prefetch'
  Stop-Service WSearch -Force -EA SilentlyContinue
  Remove-Item 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb' -Force -EA SilentlyContinue
  L "  swept per-user caches + Windows Temp/Prefetch + Search index"
} else { L "  WOULD sweep per-user caches + Windows Temp/Prefetch + Search index (Windows.edb)" }

# E6. logs
if($Execute){ foreach($d in 'C:\Windows\Logs','C:\Windows\Panther','C:\Windows\System32\LogFiles','C:\ProgramData\Microsoft\Windows\WER\ReportQueue','C:\ProgramData\Microsoft\Windows\WER\ReportArchive'){ WipeInside $d }; L "  cleared CBS/Panther/LogFiles/WER logs" } else { L "  WOULD clear CBS/Panther/LogFiles/WER logs" }

# E7. upgrade leftovers
foreach($o in 'C:\Windows.old','C:\$WINDOWS.~BT','C:\$WINDOWS.~WS','C:\$GetCurrent'){ if(Test-Path $o){ if($Execute){ Nuke $o; L "  removed $o" } else { L "  WOULD remove $o" } } }

# E8. Windows\Installer orphan patches (opt-in -DeepInstaller; registry-verified so ProScript/SQL repair packages are kept)
if($DeepInstaller){
  $used = New-Object System.Collections.Generic.HashSet[string]
  foreach($rk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Patches\*'){
    Get-ItemProperty $rk -EA SilentlyContinue | ForEach-Object { if($_.LocalPackage){ [void]$used.Add(([string]$_.LocalPackage).ToLower()) } }
  }
  $orphans = Get-ChildItem 'C:\Windows\Installer' -File -EA SilentlyContinue | Where-Object { $_.Extension -in '.msi','.msp' -and -not $used.Contains($_.FullName.ToLower()) }
  $osz=[math]::Round((($orphans|Measure-Object Length -Sum).Sum)/1GB,2)
  if($Execute){ $orphans | Remove-Item -Force -EA SilentlyContinue; L "  removed $($orphans.Count) orphan installer packages (~$osz GB)" } else { L "  WOULD remove $($orphans.Count) orphan installer packages (~$osz GB)" }
} else { L "  (installer orphan cleanup skipped - pass -DeepInstaller to enable)" }

L "`n== done ($mode). Free C: now: $(GBfree) GB =="
L "Re-run with -Execute to apply. Review 'verify' items (Office/Adobe/Java/Chrome/Edge/printers/.bak/SQL2019 engine) with Cegedim before adding them."
