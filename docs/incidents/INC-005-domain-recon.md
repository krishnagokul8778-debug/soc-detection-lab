# INC-005 — Active Directory Reconnaissance

**Date:** 2026-09-23 · **Analyst:** Gokul · **Severity:** Medium
**Verdict:** ✅ True Positive — deliberate domain enumeration
**MITRE ATT&CK:** T1087 (Account Discovery), T1069 (Permission Groups Discovery)

---

## 1. Summary (the 30-second version)
A low-privilege domain user, `alice.hr`, was used from the Kali box (`192.168.56.102`)
to **enumerate every account in the domain** against the Domain Controller `DC01`. This
is classic post-foothold reconnaissance — an attacker mapping the domain to plan their
next move (privilege escalation).

## 2. The attack
Run from Kali (Impacket — a BloodHound-style LDAP enumeration):
```
impacket-GetADUsers -all soclab.local/alice.hr:'<lab-password>' -dc-ip 192.168.56.5
```
**Result:** dumped all 8 domain accounts, including the service accounts `svc_sql` and
`svc_backup` — the exact targets for later attacks (Kerberoasting / AS-REP).

## 3. Detection (Splunk)
```
index=wineventlog host=DC01 TargetUserName=alice.hr
```
Returned **2× Event 4624 (successful logon)** on the DC:

| Field | Value | Why it matters |
|---|---|---|
| EventCode | **4624** | account successfully logged on |
| TargetUserName | **alice.hr** | low-priv user (needs no admin to *read* AD) |
| **Logon_Type** | **3** | **network** logon — remote, not at the console |
| **Logon_Process** | **NtLmSsp** | authenticated with **NTLM** (tool behaviour) |
| IpAddress | **192.168.56.102** | source = **Kali** (attacker) |
| _time | both within **1 ms** | machine speed, not a human |

## 4. Key finding
The attacker is a **needle in a haystack**: on the DC, `alice.hr` was the *rarest*
`TargetUserName` (2 events) buried under hundreds of normal machine-account logons
(`DC01$`, `SOC-VICTIM-WIN$`, `SYSTEM`). **The tell isn't the login itself — it's the
combination:** a *user* account doing a *network + NTLM* logon to a *Domain Controller*
at *machine speed* from an *unusual host*. The LDAP queries themselves are barely logged,
so **the authentication is the reliable detection point.**

## 5. Response
- Not a breach yet — recon only, no privileges gained. No containment needed for this event alone.
- **Watch for follow-on:** recon precedes credential attacks. Flag any spike in `4769`
  (Kerberoasting) or `4768` (AS-REP) for the service accounts `alice.hr` just discovered
  → leads into INC-006/007.
- **Detection to keep:** alert on a *user* account with `Logon_Type=3` + `NtLmSsp` to a DC
  from a non-domain host.

## 6. Evidence
- Kali output — full user dump (attacker side)
- Splunk: 2× 4624 for `alice.hr`, LogonType 3 / NtLmSsp / IpAddress 192.168.56.102
  (screenshot: `evidence/screenshots/06-inc-005/`)

---
**Interview soundbite:** *"A low-priv user suddenly network-authenticated to the DC with
NTLM twice in a millisecond from a Linux host — that's not a person, that's BloodHound-style
recon. I caught it on Event 4624 by spotting the rare user account hiding under the machine-account noise."*
