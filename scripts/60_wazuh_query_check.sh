#!/bin/bash
# Verify the planted dataset is actually queryable in the Wazuh indexer.
set -uo pipefail
LOG=/opt/siem-lab/logs/wazuh-install.log

# --- resolve admin password -------------------------------------------------
PW=$(grep -oP 'Password:\s*\K.+' "$LOG" 2>/dev/null | tail -1 | tr -d ' \r')
if [ -z "${PW:-}" ]; then
  PW=$(tar -O -xf /opt/siem-lab/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
       | grep -iA2 "name: admin" | grep -oiP "password:\s*'?\K[^'\"]+" | head -1)
fi
if [ -z "${PW:-}" ]; then echo "!! could not resolve admin password"; exit 3; fi
echo "admin password resolved (${#PW} chars)"
ES=https://127.0.0.1:9200
q(){ curl -s -k -u "admin:$PW" "$@"; }   # PW quoted -> special chars safe

# --- wait for indexer health -----------------------------------------------
for i in $(seq 1 40); do
  code=$(q -o /dev/null -w '%{http_code}' "$ES/_cluster/health" || true)
  [ "$code" = "200" ] && break
  sleep 3
done
echo "cluster health: $(q "$ES/_cluster/health" | jq -r '.status // "unreachable"')"

jqn(){ jq -r '.count // (.hits.total.value) // 0'; }

echo "=== index doc counts ==="
echo "  wazuh-alerts-*   : $(q "$ES/wazuh-alerts-*/_count"   | jqn)"
echo "  wazuh-archives-* : $(q "$ES/wazuh-archives-*/_count" | jqn)"

hits(){ # $1=index $2=json query
  q "$ES/$1/_search" -H 'Content-Type: application/json' -d "$2" | jq -r '.hits.total.value // 0'
}
echo "=== evidence queryable in ALERTS ==="
echo "  attacker srcip 198.51.100.23 : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"data.srcip":"198.51.100.23"}}}')"
echo "  webshell cmd= (rule 100101)  : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"rule.id":"100101"}}}')"
echo "  priv_esc (rule 100111)       : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"rule.id":"100111"}}}')"
echo "  cron_persist (rule 100112)   : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"rule.id":"100112"}}}')"
echo "  bin_tamper (rule 100113)     : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"rule.id":"100113"}}}')"
echo "  sqlmap scanner (rule 100102) : $(hits 'wazuh-alerts-*' '{"size":0,"query":{"match":{"rule.id":"100102"}}}')"
echo "  ssh brute force (5710/5712/5720/5763):"
echo "    $(hits 'wazuh-alerts-*' '{"size":0,"query":{"terms":{"rule.id":["5710","5712","5720","5763","5758"]}}}')"

echo "=== full-log searchable in ARCHIVES (all events, not only alerts) ==="
echo "  archives w/ srcip 198.51.100.23 : $(hits 'wazuh-archives-*' '{"size":0,"query":{"match":{"data.srcip":"198.51.100.23"}}}')"
echo "  archives w/ 'search.php'         : $(hits 'wazuh-archives-*' '{"size":0,"query":{"match_phrase":{"full_log":"search.php"}}}')"

echo "=== top siem_lab rules (alerts) ==="
q "$ES/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"match":{"rule.groups":"siem_lab"}},"aggs":{"r":{"terms":{"field":"rule.id","size":20}}}}' \
  | jq -r '.aggregations.r.buckets[]? | "  rule \(.key): \(.doc_count) alerts"'
echo "QUERY_CHECK_DONE"
