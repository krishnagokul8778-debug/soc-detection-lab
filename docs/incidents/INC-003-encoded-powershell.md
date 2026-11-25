# INC-003 — Encoded / Obfuscated PowerShell Execution

**Date:** 2026-08-15
**Analyst:** Gokul
**Severity:** Medium (obfuscated execution — technique is inherently suspicious)
**Verdict:** ✅ True Positive — deliberately hidden command (lab test)
**MITRE ATT&CK:** T1059.001 (PowerShell) + T1027 (Obfuscated Files or Information)

---

## 1. Summary
A base64-**encoded** PowerShell command was executed on `SOC-VICTIM-WIN` as user
`analyst`. Attackers encode commands to hide their intent from casual inspection.
PowerShell **Script Block Logging (Event 4104)** captured the **decoded** command,
revealing it was a `whoami` reconnaissance command.

## 2. The attack (what was run)
On the victim:
```
powershell -EncodedCommand dwBoAG8AYQBtAGkA
```
The base64 blob `dwBoAG8AYQBtAGkA` decodes (UTF-16LE) to **`whoami`**.

## 3. Detection / Investigation (Splunk)

**a) The encoded command — Sysmon process creation (Event 1):**
```
index=sysmon EventCode=1 CommandLine=*EncodedCommand*
| table _time, User, ParentImage, Image, CommandLine
```
| User | ParentImage | Image | CommandLine |
|---|---|---|---|
| `analyst` | powershell.exe | powershell.exe | `powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA` |

**b) The DECODED command — PowerShell Script Block Logging (Event 4104):**
```
index=wineventlog EventCode=4104 ScriptBlockText=whoami
| table _time, ComputerName, ScriptBlockText
```
Result: `ScriptBlockText = whoami` on `SOC-VICTIM-WIN`.

| Who | What | Where | How | Malicious? |
|---|---|---|---|---|
| `analyst` | encoded PowerShell → `whoami` | SOC-VICTIM-WIN | base64 `-EncodedCommand` obfuscation | ✅ TP — command was deliberately hidden |

## 4. Key findings
1. **Script Block Logging defeats obfuscation.** Even though the command line was
   unreadable base64, Event 4104 recorded the plaintext `whoami`. Enabling 4104 is what
   makes this possible — without it, we'd only see the encoded blob.
2. **Signal vs. noise.** `index=wineventlog EventCode=4104` returned **606 events / 553
   distinct script blocks** — almost all benign PowerShell internals (module loads,
   `#requires`, prompt functions). The malicious command was a single needle in that
   haystack. Effective detection means **filtering to what matters**, not reading everything.

## 5. Response
- Confirm the source: was this an admin task or unexpected? Here it was a controlled test.
- Real-world follow-up: pull everything the `analyst` session did before/after; encoding a
  trivial `whoami` is a red flag that usually accompanies further tooling.
- Hardening: PowerShell Constrained Language Mode / AMSI / logging (already on) raise the
  bar for obfuscated execution.

## 6. Note for the environment
Added a Script Block Text parser (`ScriptBlockText`) to the Splunk app for
`WinEventLog:Microsoft-Windows-PowerShell/Operational` so decoded commands extract as a
clean, searchable field.

## 7. Evidence
- `evidence/screenshots/04-inc-003/encoded-command-sysmon.csv`
- `evidence/screenshots/04-inc-003/decoded-scriptblock-4104.csv`
- Splunk screenshots (encoded Sysmon event; decoded 4104 script block)
