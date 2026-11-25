# Active Directory SOC Lab — Roadmap

**Purpose:** extend the completed SOC Detection Lab with a Windows Server Domain
Controller so we can generate, detect, and investigate **Active Directory attacks**
(Kerberoasting, AS-REP roasting, password spray, DCSync, pass-the-hash) the same way
INC-001…004 covered endpoint attacks.

**Status:** Domain Controller **built and verified** (2026-09-12). AD attack incidents
**not yet run** — this doc is the plan for that phase.

---

## 1. Lab topology (after the AD extension)

```
                        host-only network 192.168.56.0/24
  ┌────────────────┐        ┌────────────────┐        ┌────────────────┐
  │  Kali attacker │        │  SOC-VICTIM-WIN│        │      DC01      │
  │ 192.168.56.102 │        │  192.168.56.20 │        │  192.168.56.5  │
  │ (boot only to  │        │ Win11, domain- │        │ Win Server 2022│
  │  attack)       │        │ joined member  │        │ soclab.local   │
  └───────┬────────┘        └───────┬────────┘        └───────┬────────┘
          │                         │  Sysmon + UF            │ Sysmon + UF
          │                         ▼                         ▼
          │                 ┌───────────────────────────────────────┐
          └────────────────►│   Splunk (SIEM) on host 192.168.56.1   │
                            │   :9997 receiver  ·  :8000 web         │
                            └───────────────────────────────────────┘
```

**RAM plan (16 GB host):** run **DC01 + victim + Splunk** together for detection work;
boot **Kali only while actually attacking**, then power it back off. Use
`VBoxManage controlvm <vm> savestate` to park a VM and free its RAM.

---

## 2. What the DC build already did  ✅

### Domain
- Forest **`soclab.local`**, functional level Windows2016. `Install-ADDSForest`
  installed AD DS **and** DNS on the DC.
- DC hostname cleaned to **`DC01`** (via `netdom computername /add` + `/makeprimary`,
  the supported way to rename a domain controller).
- **Static IP `192.168.56.5/24`** on the host-only NIC (a DC must be static); DNS points
  to itself (`127.0.0.1`). NAT adapter kept for internet.

### Accounts (all lab-only passwords)
| Account | SamAccountName | Purpose | Password |
|---|---|---|---|
| alice.hr, bob.it, carol.fin | same | ordinary users / spray targets | `Autumn2026!` |
| svc_sql | `svc_sql` | **Kerberoast** target — SPN `MSSQLSvc/sql01.soclab.local:1433` | `Password1` |
| svc_backup | `svc_backup` | **AS-REP roast** target — pre-auth disabled | `Welcome1` |
| Administrator | — | domain admin / used for DCSync demo | `<LAB_ADMIN_PW>` |

> The service-account passwords are deliberately weak and present in common wordlists
> (`rockyou.txt`) so the offline cracking step of Kerberoasting/AS-REP actually succeeds.

### Detection pipeline
- **Advanced audit policy** enabled (auditpol subcategory GUIDs): Kerberos
  Authentication Service (4768), Kerberos Service Ticket Operations (4769),
  **Directory Service Access (4662 → DCSync)**, Credential Validation (4776), Logon
  (4624/4625), User Account Management, Security Group Management, plus the endpoint
  set (Process Creation w/ command line, etc.).
- **Sysmon** (olafhartong modular config) + **Splunk Universal Forwarder** →
  `192.168.56.1:9997`. Forwarder runs as **LocalSystem** so it can read the Security
  and Sysmon channels.
- **Inputs** (`C:\lab-staging\inputs.conf`, from `guest-staging/inputs-dc.conf`):
  `index=wineventlog` for Security / System / PowerShell / Directory Service, and
  `index=sysmon` for Sysmon. Security whitelist extended with the AD IDs:
  `4662,4768,4769,4771,4741,4742`.
- **Verified:** Splunk shows `host=DC01` events in `index=wineventlog` and
  `index=sysmon`; Kerberos IDs 4768/4769/4771 and 4776/4688/4624 all landing.

---

## 3. Bridge step — domain-join the victim

Before any AD attack, the victim must be a **domain member** (that's what makes it a
realistic target and puts domain logons on the DC).

On **SOC-VICTIM-WIN** (elevated PowerShell):
```powershell
# 1. Point the victim's DNS at the DC so it can find the domain
Set-DnsClientServerAddress -InterfaceAlias '<host-only NIC>' -ServerAddresses 192.168.56.5

# 2. Join the domain (prompts for domain creds: SOCLAB\Administrator / <LAB_ADMIN_PW>)
Add-Computer -DomainName soclab.local -Restart
```
**Verify after reboot:** `(Get-CimInstance Win32_ComputerSystem).Domain` → `soclab.local`,
and in Splunk you should see event **4624** on `host=DC01` when a domain user logs on to
the victim.

---

## 4. The AD attack incidents (planned INC-005 … INC-010)

Each will be written up in `docs/incidents/` in the existing INC format
(Summary → Attack → Detection/Investigation → Key finding → Response → Evidence),
with Splunk screenshots saved under `evidence/screenshots/`.

### INC-005 — Domain Recon / BloodHound  ·  T1087, T1069
- **Attack (Kali):** `bloodhound-python -u alice.hr -p 'Autumn2026!' -d soclab.local -ns 192.168.56.5 -c All`
  (or `SharpHound` on the victim). Enumerates users, groups, ACLs, sessions via LDAP.
- **Detect (Splunk):** burst of LDAP/directory access from one host; on the DC,
  `index=wineventlog host=DC01 EventCode=4662` and 4624 logon from the recon host.
  ```
  index=wineventlog host=DC01 EventCode=4661 OR EventCode=4662
  | stats count values(ObjectName) by SubjectUserName, _time
  ```
- **Key finding:** recon is noisy at the directory layer but easy to miss without DS
  auditing — this is why 4662 was enabled.

### INC-006 — Password Spray  ·  T1110.003
- **Attack (Kali):** `kerbrute passwordspray -d soclab.local --dc 192.168.56.5 users.txt 'Autumn2026!'`
  — one password against many users (avoids lockout).
- **Detect (Splunk):** many **4771** (Kerberos pre-auth failed) or **4625** across
  *different* target accounts from one source in a short window.
  ```
  index=wineventlog host=DC01 (EventCode=4771 OR EventCode=4625)
  | bucket _time span=5m
  | stats dc(TargetUserName) as users_tried count by _time, IpAddress
  | where users_tried >= 5
  ```
- **Key finding:** spray signature = high *distinct-user* count with low per-user
  failures (the inverse of brute-force).

### INC-007 — Kerberoasting  ·  T1558.003  ⭐
- **Attack (Kali):** `impacket-GetUserSPNs soclab.local/alice.hr:'Autumn2026!' -dc-ip 192.168.56.5 -request`
  → dumps the `svc_sql` service ticket; crack offline: `hashcat -m 13100 hash.txt rockyou.txt`.
- **Detect (Splunk):** **4769** (TGS request) for a service account with
  **encryption type 0x17 (RC4)** — the roasting fingerprint.
  ```
  index=wineventlog host=DC01 EventCode=4769 Ticket_Encryption_Type=0x17
  ServiceName!=krbtgt ServiceName!=*$
  | table _time, TargetUserName, ServiceName, Ticket_Encryption_Type, IpAddress
  ```
- **Key finding:** legitimate modern tickets use AES (0x12); a flood of RC4 TGS requests
  = someone harvesting crackable service tickets.

### INC-008 — AS-REP Roasting  ·  T1558.004
- **Attack (Kali):** `impacket-GetNPUsers soclab.local/ -dc-ip 192.168.56.5 -usersfile users.txt -no-pass`
  → gets `svc_backup`'s AS-REP (works because pre-auth is disabled); crack `hashcat -m 18200`.
- **Detect (Splunk):** **4768** (AS-REQ) with **pre-auth type 0** for the pre-auth-disabled
  account, again often RC4.
  ```
  index=wineventlog host=DC01 EventCode=4768 Pre_Authentication_Type=0
  | table _time, TargetUserName, Pre_Authentication_Type, IpAddress
  ```
- **Key finding:** any account with "do not require pre-auth" is roastable — this
  detection also doubles as a config-drift alert.

### INC-009 — DCSync  ·  T1003.006  ⭐
- **Attack (Kali/victim):** `impacket-secretsdump soclab.local/Administrator:'<LAB_ADMIN_PW>'@192.168.56.5`
  (or Mimikatz `lsadump::dcsync`). Impersonates a DC to replicate password hashes.
- **Detect (Splunk):** **4662** where a *non-DC* account is granted the directory
  replication rights (GUIDs `1131f6aa-…` DS-Replication-Get-Changes /
  `1131f6ad-…` …-All).
  ```
  index=wineventlog host=DC01 EventCode=4662 Properties="*1131f6ad*"
  | search Account_Name!="*$"
  | table _time, Account_Name, Properties, Object_Name
  ```
- **Key finding:** replication should only ever come *from another DC*; a user or
  workstation requesting it is DCSync — one of the highest-signal AD detections.

### INC-010 — Pass-the-Hash / Lateral Movement  ·  T1550.002
- **Attack (Kali):** `impacket-psexec -hashes :<NTLM> soclab.local/Administrator@192.168.56.20`
  using a hash recovered in INC-009.
- **Detect (Splunk):** **4624 Logon Type 9** / NTLM logon with a mismatch between the
  logon account and the source, plus service creation (7045) from psexec.
  ```
  index=wineventlog host=DC01 EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
  | table _time, TargetUserName, IpAddress, WorkstationName
  ```
- **Key finding:** PtH shows as NTLM network logons for accounts that normally use
  Kerberos — the auth package is the tell.

---

## 5. Detections to add to Splunk

Add saved searches for the above to
`splunk/app/soc_detection_lab/default/savedsearches.conf` (same pattern as the existing
29 detections), and add any missing field extractions for AD fields
(`Ticket_Encryption_Type`, `Pre_Authentication_Type`, `ServiceName`, `Properties`) via
`conf-props` if Splunk's default `Field: value` parsing doesn't pick them up.

---

## 6. Credentials & quick reference (lab-only)

| Thing | Value |
|---|---|
| Domain | `soclab.local` (NetBIOS `SOCLAB`) |
| DC01 | `192.168.56.5` · Administrator / `<LAB_ADMIN_PW>` |
| Victim | `192.168.56.20` · analyst / `<LAB_ADMIN_PW>` (join as domain member) |
| Splunk web | `https://192.168.56.1:8000` · admin / `<SPLUNK_PW>` |
| Splunk receiver | `192.168.56.1:9997` |
| Kali | `192.168.56.102` (boot only when attacking) |

> These are throwaway lab credentials on an isolated host-only network. Never reuse them.
