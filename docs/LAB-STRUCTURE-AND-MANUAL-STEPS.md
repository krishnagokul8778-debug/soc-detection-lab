# SOC Detection Lab — Structure & Manual Setup Steps

**Project:** SOC Detection, Analysis & Incident Response Lab
**Goal (say it this way in interviews):** *"I built a SOC monitoring environment and investigated simulated security incidents using endpoint telemetry and a SIEM."*
**You do every step by hand** and screenshot as you go — screenshots ARE the portfolio.

---

## 0. One correction to the architecture (and why)

Your diagram puts **Splunk on Kali**. That install failed with *"file not supporting the OS"* — that is the **AVX issue**: modern Splunk requires the AVX CPU instruction, and a Linux VM on this host (VirtualBox running under Windows Hyper-V/NEM) doesn't reliably get AVX. It will keep failing there.

**You already have Splunk installed and running on the Windows host, and it works** (the host CPU has AVX). So we make one tiny, honest change and keep everything else:

```
        HOST PC (Windows) ─── runs Splunk = "SOC / SIEM Server"   192.168.56.1
                 ▲                         ▲
                 │ attacks                 │ logs (9997)
        ┌────────┴────────┐       ┌────────┴──────────┐
        │  Kali Linux     │       │  Windows VM        │
        │  Attacker       │──────▶│  Victim (Sysmon+UF)│
        │  192.168.56.10  │ nmap  │  192.168.56.20     │
        └─────────────────┘       └────────────────────┘
```

Kali = attacker. Windows VM = victim with Sysmon + Universal Forwarder. Host = Splunk. Same roles, same data flow, same detections — Splunk just lives on the host instead of Kali. **This is the only deviation from your frozen diagram, and it's forced by hardware.**

---

## 1. Lab structure (fill this table in as you build)

| Role | Machine | Network | IP (target) | Status |
|---|---|---|---|---|
| SIEM / Splunk | **Windows host** | host-only | `192.168.56.1` | ✅ already running |
| Attacker | **Kali VM** | host-only + NAT | `192.168.56.10` | needs host-only NIC added |
| Victim | **Windows VM** (build new) | host-only + NAT | `192.168.56.20` | ❌ to build |

**Credentials (lab only):**
- Splunk Web: `http://localhost:8000` — `admin` / `<SPLUNK_ADMIN_PASSWORD>`
- Splunk receiver port: `9997`
- Universal Forwarder admin: `admin` / `<UF_ADMIN_PASSWORD>`

**Indexes already created in Splunk:** `wineventlog`, `sysmon`, `notable`, `attack_range` (all currently empty — that's expected until the victim ships logs).
**Detections already loaded:** 29 correlation searches (app `soc_detection_lab`). You don't build these; you *trigger* them.

---

## PHASE 1 — Lab Infrastructure (manual)

### 1a. Confirm Splunk is up (host)
Open a browser on the host → `http://localhost:8000` → log in.
📸 Screenshot the Splunk home page. *(This is your "Splunk Server" proof.)*

### 1b. Put Kali on the host-only network
So Kali can reach the victim at `192.168.56.20`.
- VirtualBox Manager → **Kali** → Settings → Network → **Adapter 2** → Enable → *Attached to:* **Host-only Adapter** → Name: *VirtualBox Host-Only Ethernet Adapter* → OK.
- Boot Kali, then in a terminal give that NIC an address (adapter is usually `eth1`):
  ```bash
  sudo ip addr add 192.168.56.10/24 dev eth1
  sudo ip link set eth1 up
  ip a            # confirm 192.168.56.10 is present
  ping -c2 192.168.56.1   # can Kali reach the Splunk host?
  ```
📸 Screenshot `ip a` and the successful ping.

### 1c. Build the Windows victim VM
Get a Windows ISO (the scriptable Win10 Enterprise eval is retired):
- **Windows 10 LTSC 2021 Enterprise eval** (lightest, ~180 days) — Microsoft Evaluation Center, **or**
- **Windows 11 Enterprise eval**.
Save it to `C:\Users\krish\soc-detection-lab\installers\`.

Create the VM by hand in **VirtualBox Manager** (close nothing else is required, just create it in the GUI):
- New → Name `SOC-Victim-Win`, Type Windows, Version Windows 10/11 (64-bit).
- Memory **4096 MB**, **2 CPUs**, disk **60 GB**.
- Settings → Network:
  - **Adapter 1** = NAT (for Windows Update).
  - **Adapter 2** = Host-only Adapter (the log path to Splunk).
- Settings → Storage → attach the ISO to the optical drive → Start → install Windows.
- During setup pick an **offline/local account** (`analyst`), install **Guest Additions** after first boot.

📸 Screenshot the VM running at the desktop.

### 1d. Give the victim a fixed host-only IP (inside the guest)
Elevated PowerShell **in the Windows VM**:
```powershell
Get-NetAdapter | ft Name,InterfaceDescription,Status         # find the host-only NIC's name
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.20 -PrefixLength 24
Test-NetConnection 192.168.56.1 -Port 9997                   # must show TcpTestSucceeded : True
```
If `TcpTestSucceeded` is **False**, the host firewall is blocking 9997 — on the host run once (elevated):
```powershell
New-NetFirewallRule -DisplayName "SOC Lab Splunk 9997" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9997 -RemoteAddress 192.168.56.0/24
```
📸 Screenshot `TcpTestSucceeded : True`.

---

## PHASE 2 — Windows Endpoint Monitoring (manual)

Do these **inside the Windows VM**, elevated PowerShell. This is Sysmon + audit logging.

### 2a. Turn on the Windows auditing that detections need
```powershell
# process creation + logon auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# add the command line to 4688 events (without this, cmdline is blank)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell script-block logging (4104) — decodes obfuscated PowerShell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

### 2b. Install Sysmon
Copy `C:\Users\krish\soc-detection-lab\guest-staging\` from the host into the guest as `C:\lab-staging\` (drag-drop via Guest Additions, or a VirtualBox shared folder). Then:
```powershell
cd C:\lab-staging
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
Get-Service Sysmon64      # Status = Running
```
📸 Screenshot the Sysmon service running.

---

## PHASE 3 — Log Collection: Universal Forwarder → Splunk (manual)

Still inside the Windows VM.

### 3a. Install the Universal Forwarder pointing at the host
```powershell
cd C:\lab-staging
msiexec /i splunkforwarder.msi AGREETOLICENSE=Yes SPLUNKUSERNAME=admin SPLUNKPASSWORD=<UF_ADMIN_PASSWORD> RECEIVING_INDEXER=192.168.56.1:9997 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 /quiet
```

### 3b. Tell the forwarder which logs to ship (so Sysmon lands in the `sysmon` index)
Copy the ready-made inputs file into the forwarder:
```powershell
$app = "C:\Program Files\SplunkUniversalForwarder\etc\apps\soc_lab_inputs\local"
New-Item -ItemType Directory -Force -Path $app | Out-Null
Copy-Item C:\lab-staging\inputs.conf "$app\inputs.conf" -Force
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
```

### 3c. Confirm logs are arriving (on the HOST, in Splunk Web)
Search & Reporting → run:
```
index=sysmon OR index=wineventlog | stats count by host, sourcetype
```
You should see `SOC-Victim-Win` with `WinEventLog:Security`, `WinEventLog:System`, and `WinEventLog:Microsoft-Windows-Sysmon/Operational`.
📸 **This screenshot proves Phases 1–3 are done.**

### 3d. Snapshot the clean victim BEFORE any attack
VirtualBox → SOC-Victim-Win → **Take Snapshot** → name it `clean-baseline`. Reset to this between incidents.

---

## PHASE 4–6 — Attacks → Detection → Investigation (the four incidents)

Run the attack, watch the detection, then investigate with the W-questions. The detections are **already loaded** — you're proving they fire.

### INC-001 — Network Reconnaissance (Nmap)
**Attack (Kali):**
```bash
nmap -sS -sV -p- 192.168.56.20
```
**Detect / investigate (Splunk):**
```
index=sysmon EventCode=3 dest_ip="192.168.56.20"
| stats count values(dest_port) as ports by src_ip
```
Investigate: source IP, dest IP, ports, timestamps, connection frequency. 📸

### INC-002 — Multiple Failed Logins
**Attack:** from Kali or the victim, force ~15 bad logins to a real account (e.g. `crackmapexec smb 192.168.56.20 -u analyst -p wrong1,wrong2,...` or repeated `runas` with a wrong password).
**Detect:** the loaded rule *"T1110 - Failed Logon Burst Followed by Success"* fires. Manual view:
```
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes by host, TargetUserName, IpAddress
| where failures >= 10
```
Investigate: WHO (src IP/user), WHEN (start/end/count), did a success follow? 📸

### INC-003 — PowerShell Activity
**Attack (victim):** run a benign encoded command, e.g.
```powershell
powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA
```
**Detect / investigate:**
```
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| table _time, host, User, ScriptBlockText
```
Point to make: 4104 logs the **decoded** script, defeating the encoding. 📸

### INC-004 — Suspicious Process Chain
**Attack (victim):** spawn `explorer → powershell → cmd` (open PowerShell from Explorer, then launch `cmd` from it).
**Detect / investigate:**
```
index=sysmon EventCode=1
| table _time, User, ParentImage, Image, CommandLine
```
Investigate the parent-child chain: is `cmd.exe` under `powershell.exe` under `explorer.exe` normal for this user? 📸

---

## PHASE 7 — Response (write what you'd do, then do the safe parts)
For a confirmed True Positive:
- **Contain:** disable the account (`Disable-LocalUser analyst`), block the source IP at the host firewall, kill the malicious process.
- **Eradicate:** remove any persistence (run key / scheduled task / service the attacker added).
- **Recover:** revert to the `clean-baseline` snapshot, then re-run the detection search to confirm it's quiet.
📸 Screenshot before/after.

---

## PHASE 8 — Documentation (the deliverable)
For each incident write `docs/incidents/INC-00X.md` containing:
1. Summary (1 line) 2. Timeline 3. The SPL detection + why it fires 4. Investigation (the W-questions) 5. TP/FP verdict 6. Response taken 7. **MITRE ATT&CK ID** 8. Screenshots.

Then organize the GitHub repo per your plan (`01-Architecture`, `02-Windows`, `03-Splunk`, `04-Attack-Simulation`, `05-Detection`, `06-Investigation`, `screenshots/`).

---

## The exact next step
You are at **Phase 1c**: everything host-side (Splunk + detections) is done; Kali just needs a host-only NIC (1b), and the **Windows victim VM does not exist yet — build it.** The moment `index=sysmon | stats count by host` shows `SOC-Victim-Win`, you're at Phase 4 and the rest is running the four incidents.
```

# --- Quick verify commands (paste on the host any time) ---
# Splunk service:   Get-Service Splunkd
# Indexes/events:   curl.exe -sk -u "admin:<SPLUNK_ADMIN_PASSWORD>" "https://localhost:8089/services/data/indexes?output_mode=json" 
# Forwarder seen:   & 'C:\Program Files\Splunk\bin\splunk.exe' list forward-server -auth admin:<SPLUNK_ADMIN_PASSWORD>
```
