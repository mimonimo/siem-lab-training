#!/bin/bash
# Apply lab rules + config to the Wazuh manager, validate, then restart.
set -uo pipefail
cp /tmp/config_wazuh.py /opt/siem-lab/scripts/config_wazuh.py
cp /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true
chmod 660 /var/ossec/etc/rules/local_rules.xml

echo "=== edit ossec.conf + filebeat.yml ==="
python3 /opt/siem-lab/scripts/config_wazuh.py

echo "=== validate ruleset/config (wazuh-analysisd -t) ==="
if /var/ossec/bin/wazuh-analysisd -t 2>&1 | tee /tmp/analysisd_test.log | tail -8; then
  if grep -qiE 'ERROR|Configuration error|Invalid' /tmp/analysisd_test.log; then
    echo "!! CONFIG TEST REPORTED ERRORS - NOT restarting manager"; exit 2
  fi
else
  echo "!! analysisd -t failed - NOT restarting manager"; exit 2
fi

echo "=== restart manager + filebeat ==="
systemctl restart wazuh-manager
sleep 6
systemctl restart filebeat 2>/dev/null || true
sleep 3
echo "manager:  $(systemctl is-active wazuh-manager)"
echo "filebeat: $(systemctl is-active filebeat)"
echo "=== custom rules present? ==="
grep -c 'id="1001' /var/ossec/etc/rules/local_rules.xml
echo "CONFIG_APPLY_DONE"
