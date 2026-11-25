# SOC Detection Lab

A home detection-engineering lab that instruments a Windows endpoint with Sysmon
and full Windows audit logging, ships the telemetry to Splunk, and runs ~18
correlation searches mapped to **MITRE ATT&CK** — then validates them with
**Atomic Red Team** and scores its own coverage.

The goal is not "collect logs." It's to close the loop from **attacker technique
→ telemetry → detection → measured result**, and to be honest about what misses.

> Built as an interview portfolio project. The talking points are in
> [`docs/INTERVIEW-NARRATIVE.md`](docs/INTERVIEW-NARRATIVE.md) — start there.

---

## Architecture

```
   ┌──────────────────────────── HOST (Windows 11, 16 GB) ───────────────────────────┐
   │                                                                                  │
   │   Splunk Enterprise (60-day trial → Free)                                        │
   │     • :8000  web UI / detection app                                              │
   │     • :9997  receiving indexer  ◄─────────────┐                                  │
   │     • indexes: sysmon · wineventlog · notable · attack_range                     │
   │     • 18 scheduled correlation searches → summary-index `notable` → risk rollup  │
   │                                               │                                  │
   │   host-only net  192.168.56.1/24  ────────────┤                                  │
   └───────────────────────────────────────────────┼──────────────────────────────────┘
                                                   │ 9997/tcp (forwarded events)
   ┌───────────────────────────────────────────────┼──────────────── VirtualBox ─────┐
   │   VICTIM VM (Windows, 4 GB)   192.168.56.x     │                                  │
   │     • Sysmon + olafhartong config (838 ATT&CK-tagged rules)                       │
   │     • Advanced audit policy + 4688 command-line capture                           │
   │     • PowerShell Script Block Logging (4104)                                      │
   │     • Splunk Universal Forwarder ──────────────┘                                  │
   │     • Atomic Red Team (detonation, snapshot-and-rollback)                         │
   └──────────────────────────────────────────────────────────────────────────────────┘
```

Isolation: the victim reaches the host indexer over a **host-only** adapter and
uses NAT only for one-time tool installation. It never routes to the LAN.

---

## Detection catalog

18 correlation searches in
[`splunk/app/soc_detection_lab/default/savedsearches.conf`](splunk/app/soc_detection_lab/default/savedsearches.conf),
each carrying its ATT&CK ID, data source, false-positive notes, and triage steps.

| Tactic | Technique | Detection | Data source |
|--------|-----------|-----------|-------------|
| Credential Access | T1003.001 | LSASS memory access from unexpected process | Sysmon 10 |
| Credential Access | T1003.002 | SAM/SECURITY hive dumped via reg.exe | Sysmon 1 |
| Execution | T1059.001 | Encoded PowerShell command | Sysmon 1 |
| Execution | T1047 | WMI process creation | Sysmon 1 |
| Execution | T1204.002 | Office application spawning a shell | Sysmon 1 |
| Defense Evasion | T1218 | LOLBin execution with network egress | Sysmon 1+3 |
| Defense Evasion | T1070.001 | Windows event log cleared | Security 1102 / System 104 |
| Defense Evasion | T1562.001 | Defender tampering or exclusion added | Sysmon 13+1 |
| Defense Evasion | T1027 | Obfuscated PowerShell script block | PowerShell 4104 |
| Persistence | T1547.001 | Registry Run key persistence | Sysmon 12/13 |
| Persistence | T1053.005 | Scheduled task created | Sysmon 1 / Security 4698 |
| Persistence | T1543.003 | Suspicious service installation | System 7045 / Security 4697 |
| Priv Esc | T1136.001 | Account created + added to privileged group | Security 4720/4732 |
| Cred Access | T1110 | Failed logon burst followed by success | Security 4625/4624 |
| Discovery | T1082 | Host/domain discovery command burst | Sysmon 1 |
| Impact | T1490 | Shadow copy deletion / recovery disabled | Sysmon 1 |
| Lateral Movement | T1021.002 | Remote admin share access | Security 5140 |
| Correlation | multiple | **Risk-based host threshold** | index=notable |

### Linux track (Ubuntu victim → `index=linux`)

11 further correlation searches in
[`splunk/app/soc_detection_lab_linux/default/savedsearches.conf`](splunk/app/soc_detection_lab_linux/default/savedsearches.conf),
over `auditd` + `auth.log` telemetry. Deployed as a **separate Splunk app** that
shares the same `notable` index and risk rollup, so Windows and Linux detections
feed one triage picture. **29 detections total.**

| Tactic | Technique | Detection | Data source |
|--------|-----------|-----------|-------------|
| Credential Access | T1110 | SSH brute force followed by success | auth.log (sshd) |
| Credential Access | T1003.008 | /etc/shadow or passwd accessed | auditd (cred_access) |
| Priv Esc | T1548.003 | Sudoers modified / unauthorized sudo | auditd + auth.log |
| Persistence | T1136.001 | Local account created | auditd + auth.log |
| Execution | T1059.004 | Reverse shell indicators (/dev/tcp hex match) | auditd (proctitle) |
| Execution | T1105 | Curl/wget piped to shell | auditd (execve) |
| Persistence | T1053.003 | Cron persistence | auditd (persist_cron) |
| Persistence | T1543.002 | Systemd service/timer persistence | auditd (persist_systemd) |
| Persistence | T1547.006 | Kernel module loaded | auditd (init_module) |
| Defense Evasion | T1070 | Log / audit tampering | auditd (log_tamper) |
| Discovery | T1082 | Host discovery command burst | auditd (discovery) |

> **Why a Linux victim.** Microsoft decommissioned the standard Windows 10
> Enterprise evaluation (Win10 hit end-of-support Oct 2025), and the remaining
> Win10 LTSC / Win11 evals are sign-in-gated. Ubuntu Server downloads freely and
> makes a cleaner "server victim" for a SOC lab. The Windows detection app is
> retained and still valid — the two OSes coexist on one Splunk indexer.

Linux endpoint setup: [`vm-setup/provision-victim-ubuntu.sh`](vm-setup/provision-victim-ubuntu.sh)
(auditd ATT&CK ruleset + Splunk UF), inputs in
[`vm-setup/inputs-linux.conf`](vm-setup/inputs-linux.conf), detonation via
[`atomics/linux-detonate.sh`](atomics/linux-detonate.sh).

---

## Build order

1. **Host — Splunk:** run [`vm-setup/configure-splunk-host.ps1`](vm-setup/configure-splunk-host.ps1)
   after the MSI finishes. Deploys the app, enables the 9997 receiver, opens the
   firewall to `192.168.56.0/24` only.
2. **VM — victim:** copy the `vm-setup` folder plus `sysmon/bin/Sysmon64.exe`,
   `sysmon/sysmonconfig.xml`, and `installers/splunkforwarder.msi` into the guest
   as `C:\lab-staging`, then run
   [`vm-setup/provision-victim.ps1`](vm-setup/provision-victim.ps1) elevated.
3. **Snapshot** the VM as `clean-baseline`.
4. **Validate:** in the VM run
   [`atomics/Invoke-DetectionValidation.ps1 -InstallFramework`](atomics/Invoke-DetectionValidation.ps1),
   then on the host run [`docs/validation-search.spl`](docs/validation-search.spl)
   to produce the coverage scorecard.
5. **Roll back** to `clean-baseline` if you ran any gated destructive tests.

---

## Design decisions (the interesting part)

- **Collect what you detect on.** The forwarder allowlists specific event IDs
  rather than shipping whole channels — bounded ingest, and it fits the Free-tier
  cap. See [`vm-setup/inputs.conf`](vm-setup/inputs.conf).
- **Behavioural over atomic where affordable.** The discovery-burst rule detects
  the operator's *pattern*, not a tool name, so it survives tool substitution.
- **Telemetry realism.** Command-line auditing and Script Block Logging are off
  by default in Windows; the provisioning script turns them on, because half the
  catalog is blind without them.
- **Risk-based alerting.** Noisy-but-meaningful rules contribute risk instead of
  paging; an analyst is alerted only when one host crosses a threshold across
  multiple techniques. This is the part that reads as senior.
- **Honest about false positives.** [`docs/tuning.md`](docs/tuning.md) documents
  FP volume and tuning per rule instead of hiding it.

## Repository layout

```
soc-detection-lab/
├─ README.md
├─ splunk/app/soc_detection_lab/     Splunk app: detections, indexes, macros
├─ vm-setup/                         host + guest provisioning, forwarder inputs
├─ sysmon/                           Sysmon binaries + ATT&CK-tagged config
├─ atomics/                          Atomic Red Team detonation + validation
├─ docs/                             narrative, tuning notes, coverage search
└─ installers/                       downloaded MSIs (gitignored)
```

## Scope & ethics

Everything runs on an isolated host-only network against a VM you own. Attack
simulation uses Atomic Red Team's reversible tests, executed against a snapshot
you roll back. Do not point any of this at systems you are not authorised to test.
