# INC-006 — Password Spray

**Date:** 2026-09-29 · **Analyst:** Gokul · **Severity:** High
**Verdict:** ✅ True Positive — 3 accounts compromised
**MITRE ATT&CK:** T1110.003 (Password Spraying)

---

## 1. Summary (the 30-second version)
After enumerating the domain (INC-005), the attacker sprayed a **single common password
(`Autumn2026!`)** from Kali (`192.168.56.104`) against every account on the DC. It failed
for most but **cracked three users who shared that weak password** — alice.hr, bob.it,
carol.fin. Spray = one password vs many users (the opposite of brute-force), designed to
avoid lockouts and stay quiet.

## 2. The attack
Run from Kali (SMB/NTLM auth, one password looped over the user list):
```
PASS='Autumn2026!'
for u in Administrator alice.hr bob.it carol.fin svc_sql svc_backup; do
  smbclient -L //192.168.56.5 -U "SOCLAB\$u%$PASS"
done
```
- **Hits** → share list returns (auth accepted): alice.hr, bob.it, carol.fin
- **Misses** → `NT_STATUS_LOGON_FAILURE`: svc_sql, svc_backup

## 3. Detection (Splunk)
Misses log **4625 (failed logon)**, hits log **4624** — both NTLM, LogonType 3, on DC01.
One query shows the whole attack:
```
index=wineventlog host=DC01 (EventCode=4625 OR EventCode=4624) IpAddress=192.168.56.104
| stats values(eval(if(EventCode=4624,Account_Name,null))) as cracked
        values(eval(if(EventCode=4625,Account_Name,null))) as failed
        dc(Account_Name) as total_users by IpAddress
```

| IpAddress | cracked | failed | total_users |
|---|---|---|---|
| 192.168.56.104 | alice.hr, bob.it, carol.fin | svc_sql, svc_backup | 6 |

Spray-vs-brute-force detection (fan-out across users):
```
index=wineventlog host=DC01 EventCode=4625
| stats dc(Account_Name) as users_tried count by IpAddress
| where users_tried >= 5
```

## 4. Key finding
- **Spray fingerprint = one source → many *distinct* users** (high `dc(user)`), low failures
  each. Brute-force is the inverse: one user, many failures.
- **Separate the noise:** results also showed `127.0.0.1` failing on machine accounts
  (`DC01$`, etc.) — that's the DC's own internal chatter, **not** the attack. The real
  signal was the single **external** IP (Kali). Always split "the box talking to itself"
  from a remote source.
- **NTLM + LogonType 3** across many users from a non-domain host = the tell.

## 5. Response
- **3 accounts compromised** → force password resets for alice.hr, bob.it, carol.fin and
  kill the shared weak password.
- Enforce a strong password policy + account lockout threshold; consider MFA.
- **Watch for follow-on:** the attacker now has valid creds → expect privilege escalation
  (Kerberoasting / lateral movement) next → INC-007.

## 6. Evidence
- Kali spray output (3 hits / 2 misses)
- Splunk: 4625 burst + the cracked/failed table from `192.168.56.104`
  (screenshot: `evidence/screenshots/07-inc-006/`)

---
**Interview soundbite:** *"One external IP failed logons across six different accounts in
seconds — that fan-out is a password spray, not brute-force. I pivoted on the source IP,
filtered out the DC's own loopback noise, and showed three accounts fell to the same weak
password on Events 4625 and 4624."*
