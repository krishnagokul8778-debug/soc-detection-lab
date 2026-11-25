<#
.SYNOPSIS
    Configures the Splunk instance on the host: deploys the detection app,
    enables receiving on 9997, and opens the firewall for the host-only net.
    Run on the HOST after the Splunk MSI finishes.
#>
[CmdletBinding()]
param(
    [string]$SplunkHome = 'C:\Program Files\Splunk',
    [string]$AppSource  = 'C:\Users\krish\soc-detection-lab\splunk\app\soc_detection_lab',
    [int]   $ReceivePort= 9997
)
$ErrorActionPreference = 'Stop'
$splunk = Join-Path $SplunkHome 'bin\splunk.exe'
if (-not (Test-Path $splunk)) { throw "splunk.exe not found at $splunk -- has the MSI finished?" }

function Splunk { param([Parameter(ValueFromRemainingArguments)]$a) & $splunk @a }

Write-Host "[+] Deploying detection app" -ForegroundColor Cyan
$dest = Join-Path $SplunkHome 'etc\apps\soc_detection_lab'
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
Copy-Item $AppSource -Destination $dest -Recurse -Force
Write-Host "    app copied to $dest" -ForegroundColor Green

# Credentials match the silent-install values. Lab-only.
$cred = @('-auth','admin:<SPLUNK_ADMIN_PASSWORD>')

Write-Host "[+] Enabling receiver on $ReceivePort" -ForegroundColor Cyan
Splunk enable listen $ReceivePort @cred | Out-Null

Write-Host "[+] Opening Windows Firewall for indexer + web on the host-only subnet" -ForegroundColor Cyan
foreach ($p in @($ReceivePort, 8000, 8089)) {
    $name = "SOC Lab Splunk $p"
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $p -RemoteAddress '192.168.56.0/24' | Out-Null
    Write-Host "    allowed TCP $p from 192.168.56.0/24" -ForegroundColor Green
}

Write-Host "[+] Restarting Splunk to load the app" -ForegroundColor Cyan
Splunk restart | Out-Null

Write-Host "`n[+] Done. Web UI: http://localhost:8000  (admin / <SPLUNK_ADMIN_PASSWORD>)" -ForegroundColor Cyan
Write-Host "    Confirm forwarder connectivity once the VM is up:" -ForegroundColor Gray
Write-Host "      & '$splunk' list forward-server $($cred -join ' ')" -ForegroundColor Gray
Write-Host "    Then search:  index=sysmon OR index=wineventlog | stats count by host sourcetype" -ForegroundColor Gray
