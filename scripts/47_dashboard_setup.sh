#!/bin/bash
# Dashboard UX for novices: create the archives index pattern and widen the
# default time range so pre-loaded events are visible without time-filter fiddling.
set -uo pipefail
LOG=/opt/siem-lab/logs/wazuh-install.log
PW=$(grep -oP 'Password:\s*\K.+' "$LOG" 2>/dev/null | tail -1 | tr -d ' \r')
DB=https://127.0.0.1:443
api(){ curl -s -k -u "admin:$PW" -H 'osd-xsrf: true' -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }

echo "=== wait for dashboard API ==="
for i in $(seq 1 40); do
  code=$(api -o /dev/null -w '%{http_code}' "$DB/api/status" || true)
  [ "$code" = "200" ] && break; sleep 3
done
echo "  dashboard api: $(api -o /dev/null -w '%{http_code}' "$DB/api/status")"

echo "=== existing index patterns ==="
api "$DB/api/saved_objects/_find?type=index-pattern&fields=title&per_page=50" | jq -r '.saved_objects[]?.attributes.title'

echo "=== create wazuh-archives-* index pattern ==="
api -X POST "$DB/api/saved_objects/index-pattern/wazuh-archives-star" \
  -d '{"attributes":{"title":"wazuh-archives-*","timeFieldName":"timestamp"}}' \
  | jq -r '(.id // .error.message // "?") | "  result: \(.)"'

echo "=== widen default time range (now-1y .. now) ==="
api -X POST "$DB/api/opensearch-dashboards/settings" \
  -d '{"changes":{"timepicker:timeDefaults":"{\"from\":\"now-1y\",\"to\":\"now\"}"}}' \
  | jq -r 'if .settings then "  timeDefaults set" else (.error.message // "?") end'

echo "=== confirm index patterns now ==="
api "$DB/api/saved_objects/_find?type=index-pattern&fields=title&per_page=50" | jq -r '.saved_objects[]?.attributes.title'
echo "DASHBOARD_SETUP_DONE"
