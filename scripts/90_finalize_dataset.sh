#!/bin/bash
# ============================================================================
# Canonical dataset rebuild + clean Wazuh ingest + mission bank + verify.
# Re-runnable any time to (re)bake a pristine dataset with matching answer key.
# Removes accumulated build noise by rewriting the monitored files clean.
# ============================================================================
set -uo pipefail
SC=/opt/siem-lab/scripts
LOG=/opt/siem-lab/logs/wazuh-install.log
PW=$(grep -oP 'Password:\s*\K.+' "$LOG" 2>/dev/null | tail -1 | tr -d ' \r')
q(){ curl -s -k -u "admin:$PW" "$@"; }
ES=https://127.0.0.1:9200
FILES="/var/log/apache2/access.log /var/log/auth.log /var/log/cron.log /var/log/audit/audit.log"

echo "### [1/5] regenerate clean dataset + manifest"
python3 "$SC/siem_lab_gen.py" | tail -2

echo "### [2/5] snapshot + empty + restart-on-empty + append (clean ingest)"
systemctl stop apache2 auditd rsyslog
mkdir -p /tmp/ds; rm -f /tmp/ds/*
for f in $FILES; do cp -p "$f" "/tmp/ds/$(echo "$f" | tr / _)"; done
for f in $FILES; do : > "$f"; done
q -X DELETE "$ES/wazuh-alerts-*"   >/dev/null; q -X DELETE "$ES/wazuh-archives-*" >/dev/null
: > /var/ossec/logs/archives/archives.json 2>/dev/null || true
systemctl restart wazuh-manager
sleep 25
for f in $FILES; do cat "/tmp/ds/$(echo "$f" | tr / _)" >> "$f"; done
chown root:adm /var/log/apache2/access.log /var/log/audit/audit.log
chown syslog:adm /var/log/auth.log /var/log/cron.log
chmod 640 $FILES
systemctl start rsyslog auditd apache2

echo "### [3/5] regenerate mission bank + refresh portal grading spec"
python3 "$SC/mission_bank_gen.py" | tail -2
# keep the student portal's grading spec in sync with the freshly-baked answers
if [ -d /opt/siem-lab/portal ]; then
  cp /opt/siem-lab/answers/grading_spec.json /opt/siem-lab/portal/grading_spec.json 2>/dev/null || true
  systemctl restart siem-portal 2>/dev/null || true
  echo "  portal grading spec refreshed + siem-portal restarted"
fi

echo "### [4/5] wait for ingest"
sleep 55

echo "### [5/5] verify"
echo "  alerts:   $(q "$ES/wazuh-alerts-*/_count"   | jq -r '.count//0')"
echo "  archives: $(q "$ES/wazuh-archives-*/_count" | jq -r '.count//0')"
echo "  access.log archived: $(q "$ES/wazuh-archives-*/_count" -H 'Content-Type: application/json' -d '{"query":{"match_phrase":{"location":"/var/log/apache2/access.log"}}}' | jq -r '.count//0') / $(wc -l < /var/log/apache2/access.log)"
for t in "198.51.100.23" "search.php" "sqlmap" "loot.tgz"; do
  printf "  archive[%s]=%s\n" "$t" "$(q "$ES/wazuh-archives-*/_count" -H 'Content-Type: application/json' -d "{\"query\":{\"query_string\":{\"query\":\"$t\"}}}" | jq -r '.count//0')"
done
q "$ES/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{"size":0,"query":{"match":{"rule.groups":"siem_lab"}},"aggs":{"r":{"terms":{"field":"rule.id","size":20}}}}' | jq -r '.aggregations.r.buckets[]? | "  custom rule \(.key): \(.doc_count)"'
echo "FINALIZE_DONE"
