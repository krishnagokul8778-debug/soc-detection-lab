# INC-002 — Credential Brute Force (Failed Logon Burst)

**Date:** 2026-08-15
**Analyst:** Gokul
**Severity:** Medium (credential attack against an exposed service)
**Verdict:** ✅ True Positive — brute force — **but CONTAINED (no compromise)**
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

---

## 1. Summary
Following the recon in INC-001 (which found RDP exposed), an internal host
`192.168.56.102` (Kali) attempted to brute-force the local account `analyst` on
`SOC-VICTIM-WIN`. **16 failed logons** were generated in a ~1-minute burst. The attacker
did **not** gain access — Windows' account-lockout policy locked the account after 10
failures, so the remaining attempts (including the correct password) were rejected.

## 2. The attack (what was run)
RDP brute-force tools (`hydra`, `ncrack`) failed against Windows 11's NLA, so the attacker
pivoted to SMB (port 445) using `smbclient` in a loop over a 16-password list (15 wrong +
the real password last):
```
for p in $(cat passwords.txt); do smbclient -L //192.168.56.20 -U "analyst%$p"; done
```

## 3. Detection / Investigation (Splunk)
```
index=wineventlog EventCode=4625
| stats count as failed_attempts by TargetUserName, IpAddress, LogonType
```
| Who (src) | Target user | Attempts | Logon type | Auth |
|---|---|---|---|---|
| `192.168.56.102` (host "KALI") | `analyst` | **16 failed (4625)** | 3 (network) | NTLM |

**Failure-reason breakdown** (`| rex "Failure Reason:\s+(?<reason>[^\r\n]+)" | stats count by reason`):
| Reason | Count |
|---|---|
| Unknown user name or bad password | 10 |
| **Account locked out** | 6 |

**Compromise check:** `index=wineventlog EventCode=4624 IpAddress=192.168.56.102` → **0 results.**
The attacker never authenticated successfully.

| Who | What | When | Where | How | Malicious? |
|---|---|---|---|---|---|
| src 192.168.56.102 | 16 failed logons vs `analyst` | ~12:27 UTC, ~1 min | SOC-VICTIM-WIN | NTLM/SMB password guessing | ✅ TP — brute force |

## 4. Key finding — a defensive control worked
The account-lockout policy (10 failed attempts → account locked) triggered mid-attack.
The last 6 guesses — **including the correct password** — were rejected with
`Account locked out (0xC0000234)`. **The attack was contained by design; no compromise
occurred.**

## 5. Response
- **Containment:** already automatic — account locked by policy. (Real-world follow-up:
  confirm the lockout, and if the source is unauthorized, block `192.168.56.102`.)
- **Hardening:** RDP/SMB are exposed on this host — restrict to VPN/allowlist or disable.
- **Recovery:** unlock `analyst` once the source is confirmed non-malicious (or after the
  lockout window elapses).

## 6. Note for the environment
This investigation drove a real improvement: Windows Security field parsers
(`TargetUserName`, `IpAddress`, `LogonType`, `SubjectUserName`, `SubStatus`) were added to
the Splunk app so events extract automatically and the correlation searches can fire.

## 7. Evidence
- `evidence/screenshots/03-inc-002/bruteforce-4625-investigation.csv`
- Splunk screenshots (brute-force table, failure reasons)
