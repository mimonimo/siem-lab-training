#!/bin/bash
# Tune OpenSearch (wazuh-indexer) JVM heap. Use ~6g on a 16GB host (20 users).
# Usage: sudo bash tune_heap.sh [6g]
HEAP="${1:-6g}"
JVM=/etc/wazuh-indexer/jvm.options
sed -i -E "s/^-Xms[0-9].*/-Xms${HEAP}/; s/^-Xmx[0-9].*/-Xmx${HEAP}/" "$JVM"
grep -E '^-Xm[sx]' "$JVM"
systemctl restart wazuh-indexer
echo "wazuh-indexer restarted with heap ${HEAP}"
