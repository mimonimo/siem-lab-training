#!/bin/bash
# Replace broad execve auditing with a low-noise, targeted ruleset and switch
# auditd to RAW format, then regenerate the dataset cleanly.
set -uo pipefail

echo "[fix] stopping auditd"
systemctl stop auditd 2>/dev/null || true

echo "[fix] writing targeted audit rules"
cat > /etc/audit/rules.d/siem-lab.rules <<'RULES'
## SIEM lab audit ruleset (low-noise, golden-image safe)
-D
-b 8192
-f 1
## Webshell context: process executions by the web service account (www-data=uid 33).
## Static serving never execs, so this stays quiet until a real webshell would run.
-a always,exit -F arch=b64 -F uid=33 -S execve -k webshell_exec
-a always,exit -F arch=b32 -F uid=33 -S execve -k webshell_exec
## Persistence / privilege / tamper watches (fire only on modification: -p wa)
-w /var/www/html/ -p wa -k webroot_write
-w /etc/crontab -p wa -k cron_persist
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/sudoers.d/ -p wa -k priv_esc
-w /usr/bin/ -p wa -k bin_tamper
RULES

echo "[fix] switching auditd log_format ENRICHED -> RAW (ausearch default parses synthesized records)"
sed -i 's/^log_format = .*/log_format = RAW/' /etc/audit/auditd.conf
grep -E '^log_format' /etc/audit/auditd.conf

echo "[fix] regenerating dataset (generator restarts services with clean audit.log)"
python3 /opt/siem-lab/scripts/siem_lab_gen.py
echo "[fix] auditctl -l:"
auditctl -l | sed 's/^/    /'
echo "FIX2_DONE"
