<#
.SYNOPSIS
    Provisions the Windows victim VM as a monitored SOC endpoint.

.DESCRIPTION
    Run this INSIDE the guest VM, elevated, on a fresh install.

    Four things happen here, in order of how often they get forgotten:

      1. Audit policy. A default Windows install does not log process creation,
         file share access, or scheduled task creation. Half the detections in
         this lab match on events that simply do not exist until this step runs.

      2. Command-line auditing. Even with process-creation auditing on, event
         4688 omits the command line unless this specific registry value is set.
         "The rule works but never fires" is almost always this.

      3. PowerShell logging. Script Block Logging (4104) records the DECODED
         script body, which is what defeats -EncodedCommand obfuscation.

      4. Sysmon + Universal Forwarder. The telemetry source and the shipper.

.PARAMETER SplunkHostIP
    The VirtualBox host-only address of the host machine running Splunk.
    Default 192.168.56.1 is the VirtualBox host-only adapter default.

.EXAMPLE
    .\provision-victim.ps1 -SplunkHostIP 192.168.56.1
#>

[CmdletBinding()]
param(
    [string]$SplunkHostIP   = '192.168.56.1',
    [int]   $SplunkPort     = 9997,
    [string]$StagingPath    = 'C:\lab-staging'
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($m) Write-Host "`n[+] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "    !!  $m" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

#####################################################################
# 1. Advanced audit policy
#####################################################################
Write-Step "Enabling advanced audit policy"

# Subcategory names are locale-dependent; GUIDs are not. Using GUIDs means this
# works on a non-English Windows image without silently no-opping.
$auditSubcategories = @{
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
    '{0CCE922C-69AE-11D9-BED3-505054503030}' = 'Process Termination'
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
    '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff'
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout'
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation'
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
    '{0CCE9236-69AE-11D9-BED3-505054503030}' = 'Computer Account Management'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
    '{0CCE9224-69AE-11D9-BED3-505054503030}' = 'File Share'
    '{0CCE9244-69AE-11D9-BED3-505054503030}' = 'Detailed File Share'
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Other Object Access Events'   # 4698 scheduled tasks
    '{0CCE9228-69AE-11D9-BED3-505054503030}' = 'Sensitive Privilege Use'
    '{0CCE9211-69AE-11D9-BED3-505054503030}' = 'Security System Extension'    # 4697 service install
    '{0CCE9210-69AE-11D9-BED3-505054503030}' = 'Security State Change'
}

foreach ($guid in $auditSubcategories.Keys) {
    $name = $auditSubcategories[$guid]
    $out  = & auditpol.exe /set /subcategory:"$guid" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok $name } else { Write-Warn "$name -> $out" }
}

#####################################################################
# 2. Command-line auditing in 4688
#####################################################################
Write-Step "Enabling command-line capture in process creation events"

$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
Write-Ok "4688 events will now include the full command line"

#####################################################################
# 3. PowerShell logging
#####################################################################
Write-Step "Enabling PowerShell script block, module, and transcription logging"

$psBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

$sbl = "$psBase\ScriptBlockLogging"
if (-not (Test-Path $sbl)) { New-Item -Path $sbl -Force | Out-Null }
Set-ItemProperty -Path $sbl -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
Write-Ok "Script Block Logging (4104) -- records decoded script bodies"

$ml = "$psBase\ModuleLogging"
if (-not (Test-Path $ml)) { New-Item -Path $ml -Force | Out-Null }
Set-ItemProperty -Path $ml -Name 'EnableModuleLogging' -Value 1 -Type DWord
$mlNames = "$ml\ModuleNames"
if (-not (Test-Path $mlNames)) { New-Item -Path $mlNames -Force | Out-Null }
Set-ItemProperty -Path $mlNames -Name '*' -Value '*' -Type String
Write-Ok "Module Logging (4103)"

$ts = "$psBase\Transcription"
if (-not (Test-Path $ts)) { New-Item -Path $ts -Force | Out-Null }
Set-ItemProperty -Path $ts -Name 'EnableTranscripting'    -Value 1 -Type DWord
Set-ItemProperty -Path $ts -Name 'EnableInvocationHeader' -Value 1 -Type DWord
Set-ItemProperty -Path $ts -Name 'OutputDirectory' -Value 'C:\PSTranscripts' -Type String
New-Item -ItemType Directory -Force -Path 'C:\PSTranscripts' | Out-Null
Write-Ok "Transcription -> C:\PSTranscripts"

# Security log defaults to 20 MB and wraps fast under Sysmon-level volume.
# Losing events before the forwarder ships them would be a silent data gap.
Write-Step "Raising event log size limits"
foreach ($log in 'Security','System','Application') {
    & wevtutil.exe sl $log /ms:1073741824
    Write-Ok "$log -> 1 GB"
}
& wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912
Write-Ok "PowerShell/Operational -> 512 MB"

#####################################################################
# 4. Sysmon
#####################################################################
Write-Step "Installing Sysmon"

$sysmonExe = Join-Path $StagingPath 'Sysmon64.exe'
$sysmonCfg = Join-Path $StagingPath 'sysmonconfig.xml'

if (-not (Test-Path $sysmonExe)) { throw "Sysmon64.exe not found at $sysmonExe. Copy the staging folder into the guest first." }
if (-not (Test-Path $sysmonCfg)) { throw "sysmonconfig.xml not found at $sysmonCfg." }

if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    & $sysmonExe -c $sysmonCfg
    Write-Ok "Sysmon already installed -- config updated"
} else {
    & $sysmonExe -accepteula -i $sysmonCfg
    Write-Ok "Sysmon installed with ATT&CK-tagged config"
}

& wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824
Write-Ok "Sysmon/Operational -> 1 GB"

#####################################################################
# 5. Splunk Universal Forwarder
#####################################################################
Write-Step "Installing Splunk Universal Forwarder"

$ufMsi = Join-Path $StagingPath 'splunkforwarder.msi'
$ufDir = 'C:\Program Files\SplunkUniversalForwarder'

if (Test-Path "$ufDir\bin\splunk.exe") {
    Write-Ok "Universal Forwarder already installed"
} else {
    if (-not (Test-Path $ufMsi)) { throw "splunkforwarder.msi not found at $ufMsi." }

    # AGREETOLICENSE + a set admin password are required for a silent install.
    # This password is lab-only and should never be reused.
    $args = @(
        '/i', "`"$ufMsi`"",
        'AGREETOLICENSE=Yes',
        'SPLUNKUSERNAME=admin',
        'SPLUNKPASSWORD=<UF_ADMIN_PASSWORD>',
        "RECEIVING_INDEXER=$($SplunkHostIP):$SplunkPort",
        'WINEVENTLOG_SEC_ENABLE=1',
        'WINEVENTLOG_SYS_ENABLE=1',
        'WINEVENTLOG_APP_ENABLE=1',
        'SERVICESTARTTYPE=auto',
        'LAUNCHSPLUNK=1',
        '/quiet', '/norestart'
    )
    Write-Host "    running msiexec (this takes a minute)..."
    $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Universal Forwarder install failed with exit code $($p.ExitCode)" }
    Write-Ok "Universal Forwarder installed, forwarding to $SplunkHostIP`:$SplunkPort"
}

#####################################################################
# 6. Forwarder inputs
#####################################################################
Write-Step "Deploying forwarder inputs"

$appDir = "$ufDir\etc\apps\soc_lab_inputs\local"
New-Item -ItemType Directory -Force -Path $appDir | Out-Null

$inputs = Join-Path $StagingPath 'inputs.conf'
if (Test-Path $inputs) {
    Copy-Item $inputs -Destination "$appDir\inputs.conf" -Force
    Write-Ok "inputs.conf deployed to soc_lab_inputs app"
} else {
    Write-Warn "inputs.conf not found in staging -- forwarder will only ship the default channels"
}

Write-Step "Restarting the forwarder to pick up config"
& "$ufDir\bin\splunk.exe" restart --accept-license --answer-yes --no-prompt | Out-Null
Write-Ok "Forwarder restarted"

#####################################################################
# Verification
#####################################################################
Write-Step "Verification"

$checks = [ordered]@{
    'Sysmon service running'   = [bool](Get-Service Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
    'Forwarder service running'= [bool](Get-Service SplunkForwarder -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
    'Sysmon events present'    = [bool](Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue)
    'Cmdline auditing on'      = ((Get-ItemProperty $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1)
    'Script block logging on'  = ((Get-ItemProperty $sbl -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1)
}

foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Ok $k } else { Write-Warn "FAILED: $k" }
}

Write-Host "`n[+] Provisioning complete." -ForegroundColor Cyan
Write-Host "    Confirm ingest on the Splunk host with:" -ForegroundColor Gray
Write-Host '      index=sysmon OR index=wineventlog | stats count by host, sourcetype' -ForegroundColor Gray
Write-Host "`n    Then take a VirtualBox snapshot named 'clean-baseline' BEFORE running any atomics." -ForegroundColor Yellow
