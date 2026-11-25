# Kali → Splunk Log Forwarding (manual, cloned Kali VM)

Set up the **Splunk Universal Forwarder (UF) on Kali** to ship its logs to the
Splunk host. Done by hand on a freshly-cloned Kali machine.

## Facts
- **Kali (attacker):** `192.168.56.102` on the host-only net.
- **Splunk (host):** receiver `192.168.56.1:9997`, web `:8000`, mgmt `:8089`.
- **UF version:** 10.4.2 (Linux x86_64). Kali is Debian-based, so the `.deb`
  would also work — the `.tgz` below installs to `/opt/splunkforwarder`.

## 1. Download the UF (the command used)
```bash
wget -O splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz \
  "https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz"
```

## 2. Install (extract to /opt)
```bash
sudo tar xvzf splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz -C /opt
```

## 3. First start + accept licence, set admin creds
```bash
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

## 4. Point it at the Splunk indexer (9997)
```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.56.1:9997
```

## 5. Tell it which logs to send (Linux monitors)
```bash
# system/auth logs
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
```
(For richer telemetry, add auditd — matches `index=linux` in the lab.)

## 6. Enable boot-start + restart
```bash
sudo /opt/splunkforwarder/bin/splunk enable boot-start
sudo /opt/splunkforwarder/bin/splunk restart
```

## Verify
- On Kali: `sudo /opt/splunkforwarder/bin/splunk list forward-server`
  → should show `192.168.56.1:9997` as **Active**.
- Check TCP: `ss -tnp | grep 9997` → ESTABLISHED to `192.168.56.1`.
- In Splunk Web: search `host=kali*` (or the Kali hostname) → events arriving.

## Cloned-VM gotcha
A cloned Kali keeps the **same hostname + GUID**. Before starting the UF, give
the clone a unique identity or Splunk will merge it with the source host:
```bash
sudo hostnamectl set-hostname kali-forwarder      # unique name
# if UF was ever started on the source image, clear the clone's GUID:
sudo rm /opt/splunkforwarder/etc/instance.cfg      # regenerates on next start
```
