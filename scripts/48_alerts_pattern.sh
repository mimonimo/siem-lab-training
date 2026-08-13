#!/bin/bash
LOG=/opt/siem-lab/logs/wazuh-install.log
PW=$(grep -oP 'Password:\s*\K.+' "$LOG" 2>/dev/null | tail -1 | tr -d ' \r')
DB=https://127.0.0.1:443
api(){ curl -s -k -u "admin:$PW" -H 'osd-xsrf: true' -H 'Content-Type: application/json' "$@"; }
echo "create wazuh-alerts-* index pattern:"
api -X POST "$DB/api/saved_objects/index-pattern/wazuh-alerts-star" \
  -d '{"attributes":{"title":"wazuh-alerts-*","timeFieldName":"timestamp"}}' \
  | jq -r '(.id // .error.message // "?")'
echo "final index patterns:"
api "$DB/api/saved_objects/_find?type=index-pattern&fields=title&per_page=50" | jq -r '.saved_objects[]?.attributes.title'
echo "ALERTS_PATTERN_DONE"
