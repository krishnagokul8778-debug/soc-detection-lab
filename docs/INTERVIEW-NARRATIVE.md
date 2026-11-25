# Interview narrative — SOC Detection Lab

This is the script for talking about the project. An interviewer does not want a
tool tour; they want evidence you think like a defender. Lead with decisions and
trade-offs, not with "I installed Splunk."

## The 30-second pitch

> I built a detection-engineering lab: a Windows endpoint instrumented with
> Sysmon and full Windows audit logging, forwarding to Splunk, where I wrote
> ~18 correlation searches mapped to MITRE ATT&CK. Then I validated them with
> Atomic Red Team and scored my own coverage — including the detections that
> missed and why. The point wasn't to collect logs; it was to close the loop
> from attacker technique to alert to measured detection.

## Five decisions worth explaining

**1. I collect what I detect on, not everything.**
The forwarder allowlists specific event IDs (`inputs.conf`). This keeps a
laptop lab under the Splunk Free 500 MB/day cap, but the real argument is
discipline: unbounded ingest is how you get an unsearchable, expensive SIEM.

**2. Behavioural detection beats atomic where I can afford it.**
The discovery-burst rule (T1082) doesn't look for `net.exe` — it looks for
*five different recon tools from one user in ten minutes*. That survives the
attacker swapping tools, which a string match never does. Contrast it with the
high-precision atomic rules (Office-spawns-shell) and explain when each is right.

**3. Command-line auditing is the thing everyone forgets.**
Half my rules match on process command lines. Windows doesn't log them by
default — it needs both the process-creation audit subcategory *and* a specific
registry value (`provision-victim.ps1` sets both). "The rule works but never
fires" is almost always missing telemetry, not bad logic. Knowing that
distinction is the job.

**4. Script Block Logging defeats encoded PowerShell.**
Event 4104 records the *decoded* script body. An attacker can obfuscate the
command line but not what the engine executes. My obfuscation rule scores the
decoded content against weighted indicators — AMSI bypass weighted heaviest
because it has no benign use.

**5. Risk-based alerting instead of alert-per-rule.**
Individually tuning every rule to zero false positives is impossible, and
trying means either alert fatigue or blind spots. So noisy-but-meaningful rules
(Run keys, discovery) contribute *risk* rather than paging, and an analyst is
alerted only when one host accumulates risk across multiple distinct techniques.
That's how modern SOCs actually operate, and it's the most senior-sounding thing
in the project.

## When they push on weaknesses (they will)

- **"Single endpoint?"** — Correct, and the architecture forwards off-host in
  real time specifically so the log-clearing detection still has data after the
  attacker wipes local logs. Scaling is more forwarders, same indexer.
- **"These would be noisy in production."** — Yes, and `docs/tuning.md` says so
  per rule. I chose to keep them honest rather than tune them into silence, and
  the RBA layer is how I manage that noise.
- **"Free-tier Splunk has no alerting."** — Right; I used the 60-day Enterprise
  trial for scheduled searches, and the detection logic is portable to any SIEM
  because ATT&CK mapping and event IDs are vendor-neutral. The same rules convert
  to Sigma.

## What I'd build next (shows direction)

1. Convert the catalog to **Sigma** so it's SIEM-portable.
2. Add a **domain controller** to the telemetry (you already have DC-1/DC-2 VMs)
   for Kerberoasting (4769) and DCSync detection.
3. Wire notables to a **SOAR** playbook for auto-isolation on the T1490 rule.
