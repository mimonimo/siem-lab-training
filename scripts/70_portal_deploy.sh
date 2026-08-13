#!/bin/bash
# Deploy the student auto-grading mission portal as a systemd service (port 8081).
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
P=/opt/siem-lab/portal
mkdir -p "$P"
cp /tmp/portal_app.py "$P/portal_app.py"
cp /tmp/portal.html   "$P/portal.html"
# self-contained grading spec copy (independent of answers/ which cleanup may remove)
cp /opt/siem-lab/answers/grading_spec.json "$P/grading_spec.json"
chmod 640 "$P/grading_spec.json"

python3 -c "import flask" 2>/dev/null || apt-get install -y -qq python3-flask >/dev/null 2>&1

# stable session secret (generate once)
if [ ! -f "$P/portal.env" ]; then
  SECRET=$(head -c 24 /dev/urandom | base64 | tr -d '\n')
  cat > "$P/portal.env" <<EOF
PORTAL_SECRET=$SECRET
PORTAL_SPEC=/opt/siem-lab/portal/grading_spec.json
PORTAL_DB=/opt/siem-lab/portal/portal.db
PORTAL_PORT=8081
PORTAL_INSTRUCTOR_KEY=bridgeworks-instructor
EOF
  chmod 600 "$P/portal.env"
fi

cat > /etc/systemd/system/siem-portal.service <<'UNIT'
[Unit]
Description=SIEM Lab student mission portal (Flask, auto-grading)
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

systemctl daemon-reload
systemctl enable --now siem-portal.service
sleep 2
echo "siem-portal: $(systemctl is-active siem-portal.service)"
echo "=== smoke test ==="
curl -s -o /dev/null -w 'GET / -> HTTP %{http_code}\n' http://127.0.0.1:8081/
curl -s -w '\n' http://127.0.0.1:8081/api/config | head -c 300
echo "PORTAL_DEPLOY_DONE"
