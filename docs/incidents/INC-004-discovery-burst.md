# INC-004 — Host & Domain Discovery Command Burst (Suspicious Process Chain)

**Date:** 2026-08-16
**Analyst:** Gokul
**Severity:** Medium (post-access reconnaissance — precursor to further attack)
**Verdict:** ✅ True Positive — reconnaissance burst
**MITRE ATT&CK:** T1082 (System Information Discovery) + T1033/T1016/T1087/T1057

---

## 1. Summary
On `SOC-VICTIM-WIN`, user `analyst` ran **6 distinct reconnaissance tools within ~90
seconds**, all spawned by a single `powershell.exe` parent. This "situational-awareness"
burst is what an operator does immediately after landing on a host. It matched the
behavioural detection **"Host & Domain Discovery Command Burst."**

## 2. The attack (what was run — on the victim, in PowerShell)
```
whoami
hostname
ipconfig /all
systeminfo
tasklist
net user
net localgroup administrators
arp -a
```

## 3. Detection / Investigation (Splunk)

**a) The burst (the detection's logic):**
```
index=sysmon EventCode=1 process_name IN ("whoami.exe","hostname.exe","ipconfig.exe",
  "systeminfo.exe","tasklist.exe","net.exe","net1.exe","arp.exe")
| bin _time span=10m
| stats dc(process_name) as distinct_tools, values(process_name) as tools_used by _time, host, User
| where distinct_tools >= 5
```
Result: `analyst` — **distinct_tools = 6** (`ipconfig, net, net1, systeminfo, tasklist, whoami`) → over the 5-tool threshold.

**b) The process family tree (parent → children):**
```
index=sysmon EventCode=1 ParentImage=*powershell.exe*
| table _time, User, ParentImage, Image, CommandLine | sort _time
```
```
powershell.exe  (parent)
   ├── whoami.exe        07:33:36
   ├── ipconfig.exe /all 07:34:13
   ├── systeminfo.exe    07:34:26
   ├── tasklist.exe      07:34:37
   ├── net.exe user      07:34:44
   └── net.exe localgroup administrators  07:35:09
```

| Who | What | When | Where | How | Malicious? |
|---|---|---|---|---|---|
| `analyst` | 6 recon tools from one shell | 07:33–07:35 (~90s) | SOC-VICTIM-WIN | powershell spawning recon utilities | ✅ TP — recon playbook |

## 4. Key finding — behavioural detection
No single command here is suspicious (admins run `whoami`/`ipconfig` all day). **The signal
is the BURST** — 5+ different recon tools from one user in a short window, from one parent.
This is *behavioural* detection: it catches the human/operator pattern, so it still fires
even if the attacker swaps `net.exe` for a custom tool. That resilience is the whole point.

## 5. Response
- **Look backwards:** what happened right *before* the burst? That's usually the initial
  access (how they got the shell).
- **Look forwards:** recon is followed by credential access or lateral movement — hunt for
  those next.
- **Contain** if unauthorized: isolate the host, disable the account.

## 6. Note for the environment
Sysmon only records the full `Image` path, so a `process_name` field (the filename) and
`parent_process_name` were added to the Splunk app (derived from `Image`/`ParentImage`) —
this is what lets the `process_name IN (...)` detections match.

## 7. Evidence
- `evidence/screenshots/05-inc-004/recon-burst.csv`
- `evidence/screenshots/05-inc-004/process-tree.csv`
- Splunk screenshots (recon burst; process tree)
