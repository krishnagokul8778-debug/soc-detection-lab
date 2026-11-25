#!/usr/bin/env bash
#
# Provisions the Ubuntu victim VM as a monitored SOC endpoint.
# Run INSIDE the guest, as root (sudo), on a fresh 24.04 server install.
#
# Linux has no single "Sysmon" equivalent that ships by default, so telemetry
# comes from three layers, in order of how much signal they carry:
#   1. auditd  -- syscall-level: execve (with full argv), file access, network.
#                 This is the backbone; most detections match audit.log.
#   2. auth.log -- SSH auth, sudo, su, account changes. Human-readable and the
#                 single richest source for initial-access and privesc.
#   3. syslog/journal -- cron, systemd, kernel module loads.
#
# The Splunk Universal Forwarder for Linux ships all three to the host indexer.
#
# Usage:  sudo ./provision-victim-ubuntu.sh [SPLUNK_HOST_IP]
#         SPLUNK_HOST_IP defaults to 192.168.56.1 (VirtualBox host-only host).

set -euo pipefail

SPLUNK_HOST_IP="${1:-192.168.56.1}"
SPLUNK_PORT="9997"
UF_DEB_URL="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.deb"
STAGING="/opt/lab-staging"

cyan()  { printf '\n\033[1;36m[+] %s\033[0m\n' "$1"; }
ok()    { printf '    \033[0;32mOK  %s\033[0m\n' "$1"; }
warn()  { printf '    \033[1;33m!!  %s\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }

#####################################################################
# 1. auditd + an ATT&CK-oriented ruleset
#####################################################################
cyan "Installing auditd"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y auditd audispd-plugins >/dev/null
ok "auditd installed"

cyan "Deploying audit ruleset"
# A focused ruleset. This is a lab-sized subset of the well-known
# Neo23x0/auditd rules, keyed to the detections in the Linux catalog.
# Each -k key is what the Splunk searches pivot on, so keys and detection
# logic are kept deliberately in sync.
cat > /etc/audit/rules.d/soc-lab.rules <<'RULES'
## Delete existing rules on load, set a large buffer for burst tolerance
-D
-b 8192
-f 1

## --- Execution: capture every process exec with full argv (T1059) ---
## This is the Linux equivalent of Sysmon Event 1 and underpins most rules.
-a always,exit -F arch=b64 -S execve -k proc_exec
-a always,exit -F arch=b32 -S execve -k proc_exec

## --- Credential access: reads of the shadow/passwd files (T1003.008) ---
-w /etc/shadow -p wra -k cred_access
-w /etc/gshadow -p wra -k cred_access
-w /etc/passwd -p wa -k cred_access
-w /etc/security/opasswd -p wa -k cred_access

## --- Persistence: cron, systemd units, shell profiles (T1053.003/T1543.002/T1546.004) ---
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d -p wa -k persist_cron
-w /etc/cron.daily -p wa -k persist_cron
-w /var/spool/cron -p wa -k persist_cron
-w /etc/systemd/system -p wa -k persist_systemd
-w /lib/systemd/system -p wa -k persist_systemd
-w /etc/rc.local -p wa -k persist_init
-w /root/.bashrc -p wa -k persist_profile
-w /root/.profile -p wa -k persist_profile
-w /etc/profile.d -p wa -k persist_profile

## --- Account manipulation (T1136 / T1098) ---
-w /usr/sbin/useradd -p x -k account_mod
-w /usr/sbin/usermod -p x -k account_mod
-w /usr/sbin/groupadd -p x -k account_mod
-w /etc/sudoers -p wa -k priv_sudoers
-w /etc/sudoers.d -p wa -k priv_sudoers

## --- Defense evasion: tampering with the audit trail + logs (T1070) ---
-w /var/log/auth.log -p wa -k log_tamper
-w /var/log/syslog -p wa -k log_tamper
-w /etc/audit/ -p wa -k auditd_tamper
-w /sbin/auditctl -p x -k auditd_tamper
-w /sbin/auditd -p x -k auditd_tamper

## --- Privilege escalation: SUID/SGID changes + known GTFOBins (T1548) ---
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

## --- Discovery: recon binaries (T1082/T1033/T1087) ---
-w /usr/bin/whoami -p x -k discovery
-w /usr/bin/id -p x -k discovery
-w /usr/bin/uname -p x -k discovery
-w /usr/bin/hostname -p x -k discovery
-w /bin/netstat -p x -k discovery
-w /usr/bin/ss -p x -k discovery
-w /usr/bin/who -p x -k discovery

## --- Kernel module loading (T1547.006 / rootkits) ---
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module

## Make the config immutable until reboot (attacker can't quietly edit rules)
-e 2
RULES

augenrules --load 2>/dev/null || { warn "augenrules reported an issue; loading with auditctl"; auditctl -R /etc/audit/rules.d/soc-lab.rules || true; }
systemctl enable --now auditd >/dev/null 2>&1 || systemctl restart auditd
ok "auditd ruleset loaded ($(auditctl -l 2>/dev/null | wc -l) rules active)"

#####################################################################
# 2. Splunk Universal Forwarder
#####################################################################
cyan "Installing Splunk Universal Forwarder"
UF_DIR="/opt/splunkforwarder"
if [ -x "$UF_DIR/bin/splunk" ]; then
    ok "Universal Forwarder already present"
else
    tmp_deb="/tmp/splunkforwarder.deb"
    if [ -f "$STAGING/splunkforwarder.deb" ]; then
        cp "$STAGING/splunkforwarder.deb" "$tmp_deb"
    else
        echo "    downloading UF (.deb)..."
        curl -sSL -o "$tmp_deb" "$UF_DEB_URL"
    fi
    dpkg -i "$tmp_deb" >/dev/null
    ok "Universal Forwarder installed to $UF_DIR"
fi

cyan "Configuring forwarder (accept license, set admin, enable boot-start)"
"$UF_DIR/bin/splunk" start --accept-license --answer-yes --no-prompt \
    --seed-passwd '<UF_ADMIN_PASSWORD>' >/dev/null 2>&1 || true
"$UF_DIR/bin/splunk" enable boot-start -user root >/dev/null 2>&1 || true
"$UF_DIR/bin/splunk" add forward-server "${SPLUNK_HOST_IP}:${SPLUNK_PORT}" \
    -auth admin:'<UF_ADMIN_PASSWORD>' >/dev/null 2>&1 || true
ok "forwarding to ${SPLUNK_HOST_IP}:${SPLUNK_PORT}"

#####################################################################
# 3. Forwarder inputs
#####################################################################
cyan "Deploying inputs"
APP_LOCAL="$UF_DIR/etc/apps/soc_lab_inputs_linux/local"
mkdir -p "$APP_LOCAL"

if [ -f "$STAGING/inputs-linux.conf" ]; then
    cp "$STAGING/inputs-linux.conf" "$APP_LOCAL/inputs.conf"
    ok "inputs.conf deployed from staging"
else
    warn "inputs-linux.conf not staged; writing a built-in default"
    cat > "$APP_LOCAL/inputs.conf" <<INPUTS
[monitor:///var/log/audit/audit.log]
index = linux
sourcetype = linux:audit
disabled = 0

[monitor:///var/log/auth.log]
index = linux
sourcetype = linux_secure
disabled = 0

[monitor:///var/log/syslog]
index = linux
sourcetype = syslog
disabled = 0
INPUTS
fi

# The forwarder runs as root here so it can read audit.log (mode 600). In a
# real deployment you would instead add the splunk user to a group with read
# access, but root-owned UF is the standard simple lab setup.
"$UF_DIR/bin/splunk" restart >/dev/null 2>&1 || true
ok "forwarder restarted"

#####################################################################
# Verification
#####################################################################
cyan "Verification"
systemctl is-active --quiet auditd && ok "auditd running" || warn "auditd NOT running"
"$UF_DIR/bin/splunk" status 2>/dev/null | grep -q running && ok "forwarder running" || warn "forwarder NOT running"
[ -s /var/log/audit/audit.log ] && ok "audit.log is being written" || warn "audit.log empty"

echo
cyan "Provisioning complete."
echo "    Confirm ingest on the Splunk host with:"
echo "      index=linux | stats count by host, sourcetype"
echo
warn "Now shut down and take a VirtualBox snapshot 'clean-baseline' before running any attacks."
