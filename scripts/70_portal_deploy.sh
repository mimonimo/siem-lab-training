#!/bin/bash
# Deploy the student mission portal (+ courseware + instructor console) and the
# continuous log generator as systemd services.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
P=/opt/siem-lab/portal
mkdir -p "$P"
# portal app + all pages
for f in portal_app.py portal.html guide.html instructor.html; do
  [ -f "/tmp/$f" ] && cp "/tmp/$f" "$P/$f"
done
# self-contained grading spec (independent of answers/)
cp /opt/siem-lab/answers/grading_spec.json "$P/grading_spec.json"
chmod 640 "$P/grading_spec.json"
# continuous log generator
cp /tmp/live_noise.py /opt/siem-lab/scripts/live_noise.py 2>/dev/null || true

python3 -c "import flask" 2>/dev/null || apt-get install -y -qq python3-flask >/dev/null 2>&1

# stable session secret + config (generate once)
if [ ! -f "$P/portal.env" ]; then
  SECRET=$(head -c 24 /dev/urandom | base64 | tr -d '\n')
  cat > "$P/portal.env" <<EOF
PORTAL_SECRET=$SECRET
PORTAL_SPEC=/opt/siem-lab/portal/grading_spec.json
PORTAL_DB=/opt/siem-lab/portal/portal.db
PORTAL_PORT=8081
PORTAL_USERS=20
PORTAL_INSTRUCTOR_KEY=bridgeworks-instructor
PORTAL_STAGE_BREAKS=10,20
PORTAL_UNLOCK_THRESHOLD=0.6
PORTAL_WRONG_PENALTY=2
PORTAL_HINT_PENALTY=1
EOF
  chmod 600 "$P/portal.env"
fi

# always sync Wazuh creds into portal.env (so students see them on the portal)
WPW=$(grep -oP 'Password:\s*\K.+' /opt/siem-lab/logs/wazuh-install.log 2>/dev/null | tail -1 | tr -d ' \r')
grep -q '^PORTAL_WAZUH_USER=' "$P/portal.env" || echo "PORTAL_WAZUH_USER=admin" >> "$P/portal.env"
if [ -n "$WPW" ]; then
  sed -i '/^PORTAL_WAZUH_PASS=/d' "$P/portal.env"
  echo "PORTAL_WAZUH_PASS=$WPW" >> "$P/portal.env"
fi

cat > /etc/systemd/system/siem-portal.service <<'UNIT'
[Unit]
Description=SIEM Lab student mission portal (Flask)
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/siem-lab/portal
EnvironmentFile=/opt/siem-lab/portal/portal.env
ExecStart=/usr/bin/python3 /opt/siem-lab/portal/portal_app.py
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/siem-livelog.service <<'UNIT'
[Unit]
Description=SIEM Lab continuous benign log generator
After=network.target apache2.service
[Service]
Type=simple
User=root
Environment=LIVE_INTERVAL=90
ExecStart=/usr/bin/python3 /opt/siem-lab/scripts/live_noise.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now siem-portal.service
systemctl enable --now siem-livelog.service
sleep 2
echo "siem-portal:  $(systemctl is-active siem-portal)"
echo "siem-livelog: $(systemctl is-active siem-livelog)"
curl -s -o /dev/null -w 'portal /       -> %{http_code}\n' http://127.0.0.1:8081/
curl -s -o /dev/null -w 'guide  /guide  -> %{http_code}\n' http://127.0.0.1:8081/guide
curl -s -o /dev/null -w 'instr  /instructor -> %{http_code}\n' http://127.0.0.1:8081/instructor
echo "PORTAL_DEPLOY_DONE"
