#!/bin/bash
# Deploy the live-demo Flask app as a systemd service.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=== install Flask ==="
apt-get install -y -qq python3-flask >/dev/null 2>&1
python3 -c "import flask; print('flask', flask.__version__)"

echo "=== place demo files ==="
mkdir -p /opt/siem-lab/demo
cp /tmp/demo_app.py /opt/siem-lab/demo/demo_app.py
cp /tmp/live_demo_target_site.html /opt/siem-lab/demo/live_demo_target_site.html
chmod 644 /opt/siem-lab/demo/*

echo "=== systemd unit ==="
cat > /etc/systemd/system/siem-demo.service <<'UNIT'
[Unit]
Description=SIEM Lab live detection demo (Flask, log-only, no command execution)
After=network.target apache2.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/siem-lab/demo
Environment=DEMO_ACCESS_LOG=/var/log/apache2/access.log
Environment=DEMO_PORT=8080
ExecStart=/usr/bin/python3 /opt/siem-lab/demo/demo_app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now siem-demo.service
sleep 2
echo "siem-demo: $(systemctl is-active siem-demo.service)"
echo "=== smoke test ==="
curl -s -o /dev/null -w 'GET / -> HTTP %{http_code}\n' http://127.0.0.1:8080/
curl -s -X POST http://127.0.0.1:8080/demo/normal | head -c 200; echo
curl -s "http://127.0.0.1:8080/demo/log?n=3" | head -c 300; echo
echo "DEMO_DEPLOY_DONE"
