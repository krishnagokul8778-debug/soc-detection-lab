# Active Directory SOC Lab — Setup (Manual Procedure)

> **⚠️ MANUAL PROCEDURES ONLY.** Every step below was performed **by hand** — typing
> commands into each VM's own console, and clicking through **Splunk Web in the browser**
> for all SIEM configuration. No provisioning automation. This is a runbook to rebuild
> the lab manually from scratch.
>
> Passwords are shown as `<PLACEHOLDERS>` (throwaway lab creds on an isolated host-only
> network — never reuse them).

---

## Resources used

| Host | IP | How it's driven | Role |
|---|---|---|---|
| **DC01** | 192.168.56.5 | server console (PowerShell) | Domain Controller — `soclab.local` |
| **SOC-VICTIM-WIN** | 192.168.56.20 | VM console (PowerShell) | Win11 domain member (target) |
| **Splunk** (on host) | 192.168.56.1 | **web browser → http://192.168.56.1:8000** | SIEM — receiver :9997, web :8000 |
| **Kali** | 192.168.56.102 | Kali terminal | Attacker box (boot only when attacking) |

All VMs sit on the VirtualBox **host-only** network `192.168.56.0/24`.

---

## Step 1 — Build the Server 2022 VM (manual)

1. VirtualBox → new VM: Windows Server 2022 (64-bit), 2048 MB RAM, 64 GB disk.
2. Attach the Server 2022 evaluation ISO → install **Standard (Desktop Experience)**.
3. First logon → set built-in Administrator password to `<DC_ADMIN_PW>`.

> On Windows **Server**, the built-in Administrator is not UAC-token-filtered, so every
> PowerShell you open is already fully elevated.

## Step 2 — Network: host-only NIC + static IP (manual)

With the VM off, add Adapter 2 → Host-only. Then in PowerShell on the server:

```powershell
$nic = Get-NetAdapter | Where-Object MacAddress -eq '<HOSTONLY_NIC_MAC>'
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 192.168.56.5 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 127.0.0.1
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
```

## Step 3 — Promote to a Domain Controller (manual)

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSForest -DomainName 'soclab.local' -DomainNetbiosName 'SOCLAB' -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString '<DSRM_PW>' -AsPlainText -Force) -Force
```

After the auto-reboot, log in as `SOCLAB\Administrator` and confirm:

```powershell
Get-ADDomain | ft DNSRoot,NetBIOSName,DomainMode
Get-Service NTDS,DNS,Netlogon,ADWS | ft Name,Status   # all Running
```

*(Optional, done here)* clean DC name with `netdom computername … /add … /makeprimary` → reboot.

## Step 4 — Create users + attack targets (manual)

```powershell
'alice.hr','bob.it','carol.fin' | ForEach-Object {
  New-ADUser -Name $_ -SamAccountName $_ -Enabled $true -PasswordNeverExpires $true `
    -AccountPassword (ConvertTo-SecureString '<USER_PW>' -AsPlainText -Force)
}
# Kerberoast target (has an SPN)
New-ADUser -Name svc_sql -SamAccountName svc_sql -Enabled $true -PasswordNeverExpires $true `
  -AccountPassword (ConvertTo-SecureString '<SVC_SQL_PW>' -AsPlainText -Force)
setspn -s MSSQLSvc/sql01.soclab.local:1433 svc_sql
# AS-REP roast target (pre-auth disabled)
New-ADUser -Name svc_backup -SamAccountName svc_backup -Enabled $true -PasswordNeverExpires $true `
  -AccountPassword (ConvertTo-SecureString '<SVC_BACKUP_PW>' -AsPlainText -Force)
Set-ADAccountControl -Identity svc_backup -DoesNotRequirePreAuth $true
```

## Step 5 — Enable AD audit logging (manual)

```powershell
# 9242=Kerberos AS(4768) 9240=Kerberos TGS(4769) 923F=Cred Validation(4776)
# 923B=Directory Service Access(4662->DCSync) 9215=Logon 9235=User Mgmt 9237=Group Mgmt
'{0CCE9242-...}','{0CCE9240-...}','{0CCE923F-...}','{0CCE923B-...}',
'{0CCE9215-...}','{0CCE9235-...}','{0CCE9237-...}' | ForEach-Object {
  auditpol /set "/subcategory:$_" /success:enable /failure:enable
}
```
*(e.g. Kerberos AS = `{0CCE9242-69AE-11D9-BED3-505054503030}`.)*

## Step 6 — Install Sysmon + Splunk forwarder on the DC (manual)

On the **DC console**:

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

msiexec /i splunkforwarder.msi AGREETOLICENSE=Yes `
  RECEIVING_INDEXER="192.168.56.1:9997" `
  WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 `
  SPLUNKUSERNAME=admin SPLUNKPASSWORD="<UF_ADMIN_PW>" /quiet

# deploy inputs.conf (Security incl. 4662/4768/4769/4771, System, PowerShell, Sysmon)
# to  <UF>\etc\apps\soc_lab_inputs\local\inputs.conf   then restart, and run as LocalSystem:
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' restart
sc.exe config SplunkForwarder obj= LocalSystem
Stop-Service SplunkForwarder; Start-Service SplunkForwarder
```

## Step 7 — Configure & verify Splunk **in the browser** (manual)

All SIEM work is done in **Splunk Web** — open a browser on the host and go to
**http://192.168.56.1:8000** (log in `admin` / `<SPLUNK_PW>`).

**7a. Make sure Splunk is receiving on 9997** (already on from the base lab — confirm):
1. Top-right **Settings → Forwarding and receiving**.
2. Under **Receive data** click **Configure receiving**.
3. If **9997** isn't listed → **New Receiving Port** → type `9997` → **Save**.

**7b. Confirm the DC's logs are arriving:**
1. Top-left **Apps → Search & Reporting**.
2. Paste into the search bar:
   ```
   index=sysmon OR index=wineventlog host=DC01 | stats count by index, sourcetype
   ```
3. Set the time picker to **Last 15 minutes** → click the green **search** (magnifier).
4. ✅ You should see rows for `WinEventLog:Security`, `WinEventLog:System`, and
   `WinEventLog:Microsoft-Windows-Sysmon/Operational`.

**7c. Confirm the AD-specific events are logging** (run in the same search bar):
```
index=wineventlog host=DC01 EventCode IN (4768,4769,4771,4776,4662)
| stats count by EventCode
```
Seeing 4768/4769 means Kerberos auditing is flowing — the Kerberoasting/AS-REP
detections will have data to match on.

## Step 8 — Domain-join the victim (manual)

On **SOC-VICTIM-WIN** (elevated PowerShell):

```powershell
$nic = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like '192.168.56.*'
Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses 192.168.56.5
nslookup soclab.local 192.168.56.5            # must resolve to 192.168.56.5
Test-NetConnection 192.168.56.5 -Port 389     # TcpTestSucceeded : True
Add-Computer -DomainName soclab.local -Credential (Get-Credential) -Restart   # SOCLAB\Administrator
```
**Verify** from the DC: `Get-ADComputer SOC-VICTIM-WIN` returns
`SOC-VICTIM-WIN.soclab.local`, Enabled True, OperatingSystem populated → join confirmed.

## Step 9 — Prepare the Kali attacker box (manual)

Kali is the machine every AD attack is launched from. It stays **powered off except
during an attack** (RAM budget).

**9a. Network it into the lab.** In VirtualBox → Kali → Settings → Network:
- **Adapter 1 = Host-only** (`192.168.56.0/24`) → this is how it reaches DC01/victim; Kali gets `192.168.56.102`.
- **Adapter 2 = NAT** (optional) → only for installing/updating tools from the internet.

**9b. Confirm it can reach the domain** (Kali terminal):
```bash
ip a                                  # confirm 192.168.56.102 on the host-only NIC
ping -c2 192.168.56.5                  # reach the DC
nmap -Pn -p 53,88,389,445,636 192.168.56.5   # DNS/Kerberos/LDAP/SMB open = it's a DC
```
Point name resolution at the DC when a tool needs it (most take `-dc-ip 192.168.56.5`;
or add `nameserver 192.168.56.5` to `/etc/resolv.conf`, and `192.168.56.5 dc01.soclab.local soclab.local` to `/etc/hosts`).

**9c. Attack tooling used in the incidents** (pre-installed on Kali, install with `apt`/`pipx` if missing):
| Attack | Tool on Kali |
|---|---|
| Domain recon (INC-005) | `bloodhound-python` (or `nxc`/`netexec ldap`) |
| Password spray (INC-006) | `kerbrute` |
| Kerberoasting (INC-007) | `impacket-GetUserSPNs` + `hashcat -m 13100` |
| AS-REP roast (INC-008) | `impacket-GetNPUsers` + `hashcat -m 18200` |
| DCSync (INC-009) | `impacket-secretsdump` |
| Pass-the-Hash (INC-010) | `impacket-psexec` |

Wordlist for the offline cracking steps: `/usr/share/wordlists/rockyou.txt`
(`gunzip` it first if needed).

---

## Operational notes learned during the manual build

- **RAM (16 GB host):** run DC + victim + Splunk together only; boot **Kali only while
  attacking**. Keep DC at 2 GB, victim at 3 GB, or the host thrashes.
- **Saved-state clock skew:** resuming a VM from *save state* days later keeps its old
  clock. A stale DC clock hides its events in the Splunk browser view (timestamped in the
  past) **and** breaks Kerberos (needs <5 min skew). **Fix: cold-boot** the VM so it
  re-reads the real clock. Prefer full shutdown over save state.
- **VirtualBox Manager GUI open** can silently revert `VBoxManage modifyvm` changes —
  close it before changing VM settings.

---

*Setup complete. The attack incidents (INC-005…010) are run from Kali and investigated in
the Splunk browser — see [`AD-SOC-LAB-ROADMAP.md`](AD-SOC-LAB-ROADMAP.md).*
