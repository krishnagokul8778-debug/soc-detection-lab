# START HERE — SOC Detection Lab (plain-language master plan)

You are building **one thing**: a small SOC where you attack a Windows machine from Kali,
the attacks show up as logs in Splunk, and you investigate them like an analyst.

That's it. Everything below is just the pieces that make that possible.

---

## The picture (what we're building)

```
   KALI (attacker)  ──attacks──▶  WINDOWS VM (victim)
                                        │ sends logs
                                        ▼
                                  SPLUNK (on your host) ──▶ you investigate
```

- **Kali** = the bad guy. Runs the attacks.
- **Windows VM** = the target. Has Sysmon + a Splunk "forwarder" that ships its logs.
- **Splunk** = your SIEM. Collects the logs and runs 29 detection rules.
- **You** = the SOC analyst who reads the alerts and decides what happened.

---

## Where you ACTUALLY are right now (most of it is done ✅)

| # | Piece | Done? |
|---|---|---|
| 1 | Splunk installed & running (SIEM) | ✅ done |
| 2 | 29 detection rules loaded into Splunk | ✅ done |
| 3 | Log storage (indexes) created | ✅ done |
| 4 | Lab network (192.168.56.x) | ✅ done |
| 5 | Kali VM + connected to lab network | ✅ done |
| 6 | Windows victim VM created (empty shell) | ✅ done |
| 7 | Auto-install file (so Windows installs itself) | ✅ done |
| **8** | **Put Windows INTO that VM** | ⬅️ **YOU ARE STUCK HERE** |
| 9 | Turn on logging + Sysmon + forwarder on Windows | ⬜ Claude does it after step 8 |
| 10 | Confirm logs arrive in Splunk | ⬜ |
| 11 | Run 4 attacks & investigate them | ⬜ |
| 12 | Write it up for your portfolio | ⬜ |

**So the ONLY thing blocking you is step 8: getting a Windows ISO file.**
Nothing else. Once that file exists on your PC, I do almost all the rest.

---

## Step 8 — get a Windows ISO (pick the EASIEST path for you)

You only need **one** of these. Don't overthink it — any of them works.

### Option A — Free, no account, most reliable (RECOMMENDED if VS is confusing)
Windows 11 Enterprise **Evaluation** — a direct, free, official download. No sign-in.
```
https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise
```
Click **Windows 11 Enterprise → ISO – Enterprise → 64-bit**, fill the short form (any details), download.

### Option B — Your Visual Studio subscription (also great, fully licensed)
```
https://my.visualstudio.com/downloads
```
Search `Windows 11 Enterprise` or `Windows 10 Enterprise` → download the 64-bit ISO.

### Option C — Free Windows 10 Evaluation
```
https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise
```

> ❌ Do NOT use random "download Windows ISO" websites. Only the two Microsoft domains above
> (`microsoft.com` and `visualstudio.com`).

**When the download finishes, do just one thing:**
👉 Copy the file's full path and paste it to me. Example:
`C:\Users\krish\Downloads\windows11.iso`

---

## What happens after you paste the path (I do these — you watch)

1. I attach the Windows ISO + the auto-install file to your VM.
2. I start the VM. **Windows installs itself** — no clicking. (~15–25 min)
3. It logs in as a ready-made admin account (`analyst`).
4. I turn on Windows logging, install **Sysmon**, install the **forwarder**.
5. We check Splunk — your victim's logs appear. 🎉 (That proves the whole pipeline.)
6. We run the 4 attacks and investigate each one together.
7. You screenshot + write it up. Project done.

---

## The 4 investigations (the actual "SOC project" part)

Once logs flow, we do these one at a time. Each is: **attack → alert → investigate → verdict.**

1. **Recon** — Kali runs Nmap against Windows. You find the source IP, ports, time.
2. **Failed logins** — many bad passwords, then a success. You spot the brute force.
3. **PowerShell** — a hidden/encoded command runs. You decode what it did.
4. **Suspicious process** — a weird program chain. You judge normal vs malicious.

For each, you answer: **WHO / WHAT / WHEN / WHERE / HOW / is it malicious? / what do we do?**
That mindset is exactly what a SOC L1 interview is testing.

---

## If you feel stuck again, just tell me ONE of these:
- "I got the ISO, path is ___"  → I take over.
- "The download page is confusing" → I'll walk you click-by-click.
- "Which option should I pick?" → Option A (free Win11 eval) is the safest bet.

You're at 60–65% done. The hard thinking is finished. What's left is mostly me driving,
once you hand me that one ISO file.
```

# Quick facts
# Splunk: http://localhost:8000  (admin / <SPLUNK_ADMIN_PASSWORD>)
# Windows VM login (after install): analyst / <VICTIM_PASSWORD>
# Lab network: Splunk host .1  |  Kali .10  |  Windows victim .20
```
