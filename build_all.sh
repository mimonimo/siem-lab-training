#!/bin/bash
# ============================================================================
# One-command full build of the SIEM training environment.
# Target: a FRESH Ubuntu Server 22.04 LTS VM, with internet, run as root.
#   sudo bash build_all.sh
# Total time ~25-35 min (most of it is the Wazuh all-in-one install).
#
# Produces:
#   * Apache + auditd + rsyslog with a planted compromised-web-server log set
#   * Wazuh 4.11 all-in-one (indexer+manager+dashboard) with the logs ingested
#     into wazuh-alerts-* and wazuh-archives-*, custom rules, index patterns
#   * live demo portal  (systemd siem-demo,   :8080)
#   * student mission portal with auto-grading (systemd siem-portal, :8081)
#   * mission sheet (student) + answer key (instructor) + grading spec
# ============================================================================
set -uo pipefail
[ "$(id -u)" = "0" ] || { echo "run as root:  sudo bash build_all.sh"; exit 1; }
REPO="$(cd "$(dirname "$0")" && pwd)"
LAB=/opt/siem-lab
step(){ echo; echo "############ $* ############"; }

step "stage files"
mkdir -p "$LAB"/{scripts,logs,answers,artifacts,demo,portal}
cp "$REPO"/scripts/*        "$LAB"/scripts/
# several numbered scripts read their inputs from /tmp — stage them there too
cp "$REPO"/scripts/config_wazuh.py "$REPO"/scripts/local_rules.xml /tmp/
cp "$REPO"/demo/*          /tmp/
cp "$REPO"/portal/*        /tmp/
cp "$REPO"/INSTRUCTOR_README.md "$LAB"/ 2>/dev/null || true

step "1. base infra (Apache + auditd + rsyslog)"
bash "$LAB"/scripts/10_install_infra.sh
step "2. targeted audit ruleset + RAW format"
bash "$LAB"/scripts/20_fix_audit.sh

step "3. Wazuh all-in-one install (~10-15 min)"
cd "$LAB"
curl -fsSL -A "Mozilla/5.0" -o wazuh-install.sh "https://packages.wazuh.com/4.11/wazuh-install.sh"
bash wazuh-install.sh -a -i 2>&1 | tee "$LAB"/logs/wazuh-install.log
cd - >/dev/null
systemctl is-active --quiet wazuh-manager || { echo "Wazuh install failed — check logs"; exit 1; }

step "4. Wazuh config (custom rules, archives, vuln-detector off)"
bash "$LAB"/scripts/40_wazuh_config.sh
step "5. dashboard index patterns + wide default time range + tidy views"
bash "$LAB"/scripts/47_dashboard_setup.sh
bash "$LAB"/scripts/48_alerts_pattern.sh
python3 "$LAB"/scripts/config_dashboard.py    # 3 index patterns (archives/alerts/combined) + per-log saved searches

step "6. generate dataset + mission bank (grading spec for portal)"
python3 "$LAB"/scripts/siem_lab_gen.py
python3 "$LAB"/scripts/mission_bank_gen.py

step "7. live demo (:8080) + student portal (:8081)"
bash "$LAB"/scripts/50_demo_deploy.sh
bash "$LAB"/scripts/70_portal_deploy.sh

step "8. authoritative clean ingest + verify (removes build noise)"
bash "$LAB"/scripts/90_finalize_dataset.sh

step "9. finalize dashboard views against ingested data (field cache refresh)"
# Must run AFTER the final ingest so index-pattern field caches are populated
# (empty caches => Discover shows no fields). Also dedups/cleans index patterns.
python3 "$LAB"/scripts/config_dashboard.py

echo
echo "=================================================================="
echo " BUILD COMPLETE"
echo "  student portal : http://<this-ip>:8081/"
echo "  Wazuh dashboard: https://<this-ip>/   (user admin, pw in logs/wazuh-install.log)"
echo "  live demo      : http://<this-ip>:8080/"
echo "  instructor doc : $LAB/INSTRUCTOR_README.md"
echo "=================================================================="
