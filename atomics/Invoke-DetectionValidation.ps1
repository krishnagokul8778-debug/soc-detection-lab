<#
.SYNOPSIS
    Detonates a curated set of Atomic Red Team tests in the victim VM, each one
    chosen to exercise a specific detection in the Splunk catalog, then emits a
    manifest that the host can join against fired notables to score coverage.

.DESCRIPTION
    Run INSIDE the victim VM, elevated, AFTER provision-victim.ps1 and AFTER a
    'clean-baseline' snapshot exists.

    This is deliberately not "run every atomic." Each entry below is paired with
    the detection it should trigger, so the output is a true-positive matrix:
    for each technique, did the mapped rule fire? That matrix -- including the
    honest misses -- is the single most useful artifact in the whole project for
    an interview, because it shows detection engineering as a measured feedback
    loop rather than a pile of rules asserted to work.

    SAFETY: every test here is reversible and self-contained. None persist
    beyond their own cleanup, but you should still roll back to the snapshot
    afterwards so the baseline stays clean for the next run.

.PARAMETER InstallFramework
    Install Invoke-AtomicRedTeam and the atomics folder first. Needs internet
    in the guest (NAT adapter), one time only.
#>

[CmdletBinding()]
param(
    [switch]$InstallFramework,
    [string]$LogDir = 'C:\AtomicRedTeam\atomic-logs'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run elevated."
}

if ($InstallFramework) {
    Write-Host "[+] Installing Invoke-AtomicRedTeam..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
}

Import-Module Invoke-AtomicRedTeam -Force
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# technique -> the detection stanza it is meant to trip. Ordered roughly as a
# kill chain so the risk-rollup rule has a coherent story to accumulate.
$plan = @(
    @{ Tech='T1204.002'; Test=$null;   Detection='Office Application Spawning a Shell'; Note='simulated via child-of-office; ART has no safe office atomic, uses cmd spoof' }
    @{ Tech='T1059.001'; Test=1;       Detection='Encoded PowerShell Command';          Note='encoded command execution' }
    @{ Tech='T1082';     Test=$null;   Detection='Host and Domain Discovery Command Burst'; Note='burst driven by helper below, not a single atomic' }
    @{ Tech='T1047';     Test=1;       Detection='WMI Process Creation';                Note='wmic process call create' }
    @{ Tech='T1003.001'; Test=$null;   Detection='LSASS Memory Access from Unexpected Process'; Note='comsvcs minidump -- see note, gated' }
    @{ Tech='T1003.002'; Test=1;       Detection='SAM/SECURITY Hive Dumped via reg.exe';Note='reg save hklm\sam' }
    @{ Tech='T1547.001'; Test=1;       Detection='Registry Run Key Persistence';        Note='HKCU Run key add' }
    @{ Tech='T1053.005'; Test=1;       Detection='Scheduled Task Created';              Note='schtasks /create' }
    @{ Tech='T1543.003'; Test=1;       Detection='Suspicious Service Installation';      Note='sc create from user path' }
    @{ Tech='T1136.001'; Test=1;       Detection='Account Created and Added to Privileged Group'; Note='net user /add then net localgroup' }
    @{ Tech='T1562.001'; Test=$null;   Detection='Defender Tampering or Exclusion Added';Note='Add-MpPreference exclusion -- gated, see below' }
    @{ Tech='T1070.001'; Test=$null;   Detection='Windows Event Log Cleared';           Note='wevtutil cl -- destroys evidence, run LAST and expect rollback' }
    @{ Tech='T1490';     Test=$null;   Detection='Shadow Copy Deletion or Recovery Disabled'; Note='vssadmin delete -- gated, highest severity' }
)

$results = New-Object System.Collections.Generic.List[object]

function Record {
    param($Tech, $Detection, $Status, $Detail)
    $row = [PSCustomObject]@{
        timestamp   = (Get-Date).ToString('o')
        technique   = $Tech
        detection   = $Detection
        exec_status = $Status
        detail      = $Detail
        host        = $env:COMPUTERNAME
    }
    $results.Add($row)
    $color = if ($Status -eq 'executed') { 'Green' } elseif ($Status -eq 'skipped') { 'Yellow' } else { 'Red' }
    Write-Host ("    [{0}] {1}  {2}" -f $Status, $Tech, $Detail) -ForegroundColor $color
}

Write-Host "`n[+] Detonating detection-validation plan`n" -ForegroundColor Cyan

foreach ($item in $plan) {
    $tech = $item.Tech

    # ---- Gated high-impact tests. These are real and worth having, but they
    # ---- touch evidence, AV, or recovery, so they are opt-in via env var and
    # ---- MUST be followed by a snapshot rollback. Default run skips them.
    $gated = @('T1562.001','T1070.001','T1490','T1003.001')
    if ($tech -in $gated -and $env:SOCLAB_RUN_DESTRUCTIVE -ne '1') {
        Record $tech $item.Detection 'skipped' "gated ($($item.Note)); set SOCLAB_RUN_DESTRUCTIVE=1 to include, then roll back"
        continue
    }

    try {
        if ($null -ne $item.Test) {
            Invoke-AtomicTest $tech -TestNumbers $item.Test -GetPrereqs -ErrorAction Stop | Out-Null
            Invoke-AtomicTest $tech -TestNumbers $item.Test -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 2
            Invoke-AtomicTest $tech -TestNumbers $item.Test -Cleanup -ErrorAction SilentlyContinue | Out-Null
            Record $tech $item.Detection 'executed' $item.Note
        } else {
            Record $tech $item.Detection 'skipped' "$($item.Note) -- driven separately or gated"
        }
    } catch {
        Record $tech $item.Detection 'error' $_.Exception.Message
    }
}

# ---- Discovery burst (T1082): fire several distinct recon binaries inside the
# ---- 10-minute window so the behavioural burst rule crosses its threshold.
Write-Host "`n[+] Driving discovery burst for T1082" -ForegroundColor Cyan
foreach ($cmd in 'whoami /all','hostname','systeminfo','net user','net localgroup administrators','ipconfig /all','arp -a','nltest /dclist:','tasklist','netstat -ano') {
    try { Start-Process -FilePath cmd.exe -ArgumentList "/c $cmd" -WindowStyle Hidden -Wait } catch {}
}
Record 'T1082' 'Host and Domain Discovery Command Burst' 'executed' '10 distinct recon commands in-window'

$manifest = Join-Path $LogDir ("detonation-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$results | Export-Csv -Path $manifest -NoTypeInformation -Encoding UTF8

Write-Host "`n[+] Detonation manifest: $manifest" -ForegroundColor Cyan
Write-Host "    The forwarder ships this to index=attack_range (sourcetype=atomic_red_team_execution)." -ForegroundColor Gray
Write-Host "    Score coverage on the Splunk host with docs/validation-search.spl." -ForegroundColor Gray
Write-Host "`n[!] If you ran gated tests, roll back to the clean-baseline snapshot now." -ForegroundColor Yellow
