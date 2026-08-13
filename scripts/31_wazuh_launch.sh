#!/bin/bash
# Launch the Wazuh all-in-one install detached so it survives the SSH channel.
cd /opt/siem-lab
LOG=logs/wazuh-install.log
: > "$LOG"
echo "START $(date '+%F %T')" >> "$LOG"
setsid bash -c '
  cd /opt/siem-lab
  bash wazuh-install.sh -a -i >> logs/wazuh-install.log 2>&1
  echo "WAZUH_INSTALL_EXITCODE=$?" >> logs/wazuh-install.log
  echo "END $(date +%F\ %T)" >> logs/wazuh-install.log
' </dev/null >/dev/null 2>&1 &
disown
sleep 2
echo "launched; tailing first lines:"
head -5 "$LOG" 2>/dev/null
echo "LAUNCHED_PID_GROUP started. Poll $LOG for progress."
