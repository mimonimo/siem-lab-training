#!/bin/bash
cd /opt/siem-lab
echo "=== try 1: curl -A browser 4.x ==="
curl -fsSL -A "Mozilla/5.0" -o wazuh-install.sh "https://packages.wazuh.com/4.x/wazuh-install.sh" && echo "OK curl 4.x" && wc -c wazuh-install.sh && exit 0
echo "  -> failed"
echo "=== try 2: wget 4.x ==="
wget -q -O wazuh-install.sh "https://packages.wazuh.com/4.x/wazuh-install.sh" && echo "OK wget 4.x" && wc -c wazuh-install.sh && exit 0
echo "  -> failed"
echo "=== probe: what versions exist ==="
for v in 4.11 4.10 4.9 4.8; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "Mozilla/5.0" "https://packages.wazuh.com/${v}/wazuh-install.sh")
  echo "  ${v}/wazuh-install.sh -> HTTP $code"
done
echo "=== try 3: version-pinned (highest 200 above) ==="
for v in 4.11 4.10 4.9; do
  if curl -fsSL -A "Mozilla/5.0" -o wazuh-install.sh "https://packages.wazuh.com/${v}/wazuh-install.sh"; then
     echo "OK pinned $v"; wc -c wazuh-install.sh; exit 0
  fi
done
echo "ALL_DOWNLOAD_ATTEMPTS_FAILED"
exit 1
