# SOC Detection Lab — Build Log

A chronological record of building the lab, for the portfolio/GitHub. Screenshots in
`evidence/screenshots/01-lab-build/`.

## Architecture (as built)

```
   KALI (attacker)  ──attacks──▶  WINDOWS 11 VICTIM (Sysmon + UF)
   192.168.56.10                  192.168.56.20
                                        │ logs (9997)
                                        ▼
                              SPLUNK on HOST  192.168.56.1  (SIEM + 29 detections)
```

> Deviation from the original diagram: Splunk runs on the **host**, not on Kali. The
> Splunk-on-Kali install failed the **AVX** CPU requirement (Splunk 9/10 needs AVX, which
> a VirtualBox Linux guest under Hyper-V/NEM doesn't get). The host CPU has AVX, so Splunk
> runs there. Roles are otherwise identical.

## Environment
| Role | Host/VM | OS | IP |
|---|---|---|---|
| SIEM | Host PC | Windows 11 | 192.168.56.1 |
| Attacker | Kali VM | Kali Linux | 192.168.56.10 |
| Victim | SOC-Victim-Win VM | Windows 11 Enterprise LTSC 2024 (eval) | 192.168.56.20 |

VM specs: 4 GB RAM, 2 vCPU, 64 GB disk, UEFI→BIOS, TPM 2.0, NIC1=NAT + NIC2=host-only.

## Build steps (what was done)

1. **Splunk (host)** — Enterprise running; receiver on 9997; 29 ATT&CK-mapped correlation
   searches loaded (apps `soc_detection_lab` + `soc_detection_lab_linux`); indexes
   `wineventlog`, `sysmon`, `notable`, `attack_range`. Firewall opened for 9997/8000/8089
   from 192.168.56.0/24.
2. **Networking** — host-only adapter 192.168.56.1/24; added host-only NIC to Kali.
3. **Windows victim VM** — built via VBoxManage; installed **hands-free** with a custom
   `autounattend.xml` (baked into an ISO) that wipes/partitions the disk, skips OOBE,
   creates a local admin, and silently installs Guest Additions.
   *(Win11 needs TPM 2.0 + EFI; `VBoxManage --tpm-type=2.0` needs the `=` form or it's
   silently ignored. Switched to BIOS/MBR for reliable install.)*
4. **Endpoint provisioning** (`provision-victim.ps1`, run elevated in the guest):
   - Advanced audit policy (process creation, logon, etc.) by GUID
   - Command-line capture in Event 4688
   - PowerShell Script Block Logging (4104)
   - **Sysmon** with olafhartong ATT&CK-tagged config
   - **Splunk Universal Forwarder** → 192.168.56.1:9997, inputs for Security/System/
     PowerShell/Sysmon channels
   - Host-only IP set to 192.168.56.20
5. **Sysmon channel fix** — the UF ran as the restricted virtual account
   `NT SERVICE\SplunkForwarder`, which can read the Security log (via SeSecurityPrivilege)
   but got **access denied (errorCode=5)** subscribing to `Microsoft-Windows-Sysmon/Operational`.
   Fixed by switching the forwarder service to **LocalSystem** and restarting it.

## Verification — telemetry flowing (milestone)

Splunk, `(index=wineventlog OR index=sysmon) | stats count by index, sourcetype`:

| index | sourcetype | count (first ~20 min) |
|---|---|---|
| wineventlog | WinEventLog:Security | 891 |
| sysmon | WinEventLog:Microsoft-Windows-Sysmon/Operational | 319 |
| wineventlog | WinEventLog:Windows Defender/Operational | 49 |
| wineventlog | WinEventLog:Windows PowerShell | 11 |
| wineventlog | WinEventLog:WMI-Activity/Operational | 8 |
| wineventlog | WinEventLog:PowerShell/Operational | 7 |
| wineventlog | WinEventLog:System | 5 |

Forwarder connection: `192.168.56.20 → 192.168.56.1:9997  ESTABLISHED`.

**Result: end-to-end pipeline working — Windows endpoint → Sysmon + UF → Splunk.**
Phases 1–3 of the roadmap complete.

## Next
- Take VirtualBox snapshot `clean-baseline`.
- Run the 4 incidents (recon / failed logins / PowerShell / suspicious process),
  investigate each, document under `docs/incidents/`.
