#!/bin/bash
# ============================================================================
# SIEM Lab - Stage 2 infrastructure install (Apache + auditd + rsyslog cron)
# Idempotent. Run as: sudo bash 10_install_infra.sh
# Golden-image safe: no hardcoded IP/hostname.
# ============================================================================
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

LAB=/opt/siem-lab
log() { echo "[install] $*"; }

mkdir -p "$LAB"/{scripts,logs,answers,artifacts}
chmod 750 "$LAB"

log "apt update + install apache2 auditd audispd-plugins curl jq"
apt-get update -qq
apt-get install -y -qq apache2 auditd audispd-plugins curl jq >/dev/null 2>&1
echo "  apache2 : $(dpkg-query -W -f='${Version}' apache2 2>/dev/null || echo MISSING)"
echo "  auditd  : $(dpkg-query -W -f='${Version}' auditd 2>/dev/null || echo MISSING)"
echo "  curl    : $(dpkg-query -W -f='${Version}' curl 2>/dev/null || echo MISSING)"

# --- Apache: enable, confirm combined log format ------------------------------
log "Enabling apache2 and confirming Combined log format"
systemctl enable --now apache2 >/dev/null 2>&1
# The stock apache2.conf ships a 'combined' LogFormat; the default vhost uses it.
grep -h 'LogFormat' /etc/apache2/apache2.conf | sed 's/^/  fmt: /'
echo "  vhost log line:"
grep -h 'CustomLog' /etc/apache2/sites-enabled/*.conf 2>/dev/null | sed 's/^/    /'
# Ensure access log path exists
touch /var/log/apache2/access.log /var/log/apache2/error.log
chown root:adm /var/log/apache2/access.log

# --- auditd: execve audit rules ----------------------------------------------
log "Installing auditd execve rules (process-execution trace)"
cat > /etc/audit/rules.d/siem-lab.rules <<'RULES'
## SIEM lab: trace process executions so webshell-driven commands are logged
-D
-b 8192
-f 1
## execve() on 64-bit and 32-bit
-a always,exit -F arch=b64 -S execve -k exec_trace
-a always,exit -F arch=b32 -S execve -k exec_trace
## watch web-writable webroot for tampering (webshell drop)
-w /var/www/html/ -p wa -k webroot_write
## watch persistence & privileged locations
-w /etc/crontab -p wa -k cron_persist
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/sudoers.d/ -p wa -k priv_esc
-w /usr/bin/ -p wa -k bin_tamper
RULES
augenrules --load 2>/dev/null || true
systemctl enable --now auditd >/dev/null 2>&1
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
echo "  auditd active: $(systemctl is-active auditd 2>/dev/null)"
echo "  loaded rules:"
auditctl -l 2>/dev/null | sed 's/^/    /' | head -20
ls -l /var/log/audit/audit.log 2>/dev/null | sed 's/^/  /'

# --- rsyslog: ensure cron facility is logged ---------------------------------
log "Enabling rsyslog cron facility -> /var/log/cron.log"
cat > /etc/rsyslog.d/50-cron-lab.conf <<'RSY'
# SIEM lab: capture cron execution history to a dedicated file
cron.*    /var/log/cron.log
RSY
touch /var/log/cron.log
chown syslog:adm /var/log/cron.log 2>/dev/null || true
systemctl restart rsyslog >/dev/null 2>&1
echo "  rsyslog active: $(systemctl is-active rsyslog 2>/dev/null)"
echo "  cron.log present: $(test -f /var/log/cron.log && echo yes)"

# --- summary -----------------------------------------------------------------
log "Infra install complete. Service states:"
for s in apache2 auditd rsyslog; do
  printf "  %-10s %s\n" "$s" "$(systemctl is-active $s 2>/dev/null)"
done
echo "INFRA_INSTALL_DONE"
