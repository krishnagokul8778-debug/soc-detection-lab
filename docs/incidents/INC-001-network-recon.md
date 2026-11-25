# INC-001 — Network Reconnaissance (Nmap Port Scan)

**Date:** 2026-08-15
**Analyst:** Gokul
**Severity:** Low (reconnaissance only, no access gained)
**Verdict:** ✅ True Positive — deliberate scanning activity
**MITRE ATT&CK:** T1046 — Network Service Discovery (Reconnaissance)

---

## 1. Summary
An internal host (`192.168.56.102`) performed a full TCP port scan with service
detection against the Windows endpoint `SOC-VICTIM-WIN` (`192.168.56.20`). The scan
identified Remote Desktop (RDP/3389) as the only exposed service and fingerprinted the
host's OS via the RDP handshake.

## 2. The attack (what was run)
From the Kali attacker:
```
nmap 192.168.56.20 -p- -sV -sC --min-rate 4000
```
- `-p-` scan all 65,535 TCP ports
- `-sV` identify service/version on open ports
- `-sC` run default enumeration scripts
- `--min-rate 4000` send fast

**Attacker result:** only `3389/tcp (ms-wbt-server / RDP)` open; 65,534 ports filtered.
RDP handshake leaked: hostname `SOC-VICTIM-WIN`, `Product_Version 10.0.26100` (Win11 24H2).

## 3. Detection / Investigation (Splunk)
Search used:
```
index=sysmon EventCode=3 SourceIp=192.168.56.102
| table _time, SourceIp, DestinationIp, DestinationPort, Image, Initiated
| sort _time
```
**Evidence found:** Sysmon EventCode 3 (NetworkConnect) recorded **10 inbound
connections** from `192.168.56.102` → `192.168.56.20:3389`, serviced by
`C:\WINDOWS\System32\svchost.exe` (the RDP service host), within a ~2-minute window.

| Who | What | When | Where | How |
|---|---|---|---|---|
| src `192.168.56.102` | 10 rapid connections to RDP/3389 | ~09:06–09:08 UTC | `SOC-VICTIM-WIN` (192.168.56.20) | burst of connections to one service = probing |

## 4. Key analytical finding (detection gap)
The scan touched 65,535 ports, but endpoint telemetry only shows **1** (3389). The
firewall silently dropped the rest, so no connection was established and Sysmon had
nothing to log. **Endpoint logs only capture connections that succeed — detecting a full
port sweep requires network-level monitoring (firewall/IDS logs).**

## 5. Response
- No access was gained; no containment required for this event alone.
- **Action:** RDP (3389) is exposed to the network — recommend restricting it (VPN/allowlist)
  or disabling if unused, as it is a common brute-force target.
- **Watch for follow-on:** recon is usually followed by credential attacks. Monitor for a
  spike in failed RDP logons (Event 4625) from `192.168.56.102` → leads into INC-002.

## 6. Evidence
- Nmap output (attacker side)
- Splunk Sysmon EventCode 3 results (screenshot: `evidence/screenshots/02-inc-001/`)
