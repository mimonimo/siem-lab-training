#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# SIEM Lab - live demo backend (Flask)
# Serves the intranet mockup and turns the 3 buttons into REAL access.log
# writes. IMPORTANT: no endpoint ever executes a system command. Each endpoint
# only formats a Combined-format log line (identical to the pre-generated
# dataset, so the existing Wazuh rules fire) and appends it to access.log.
# ============================================================================
import os, random
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, send_from_directory

APP_DIR   = os.path.dirname(os.path.abspath(__file__))
ACCESS_LOG = os.environ.get("DEMO_ACCESS_LOG", "/var/log/apache2/access.log")
KST = timezone(timedelta(hours=9))

# The one external address the "suspicious" button plays the attacker from.
SUSPECT_IP = "203.0.113.66"           # RFC 5737 doc range (matches dataset)
UA_ATTACK  = "Mozilla/5.0 (X11; Linux x86_64) curl/7.81.0"
UA_NORMAL  = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
NORMAL_PATHS = ["/portal/dashboard", "/portal/notices", "/index.html",
                "/api/status", "/docs/guide.html"]

app = Flask(__name__, static_folder=None)

def now_apache():
    return datetime.now(tz=KST).strftime("%d/%b/%Y:%H:%M:%S %z")

def combined(ip, method, path, status, size, ua, referer="-"):
    return (f'{ip} - - [{now_apache()}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')

def append_lines(lines):
    """Append pre-formatted log lines. No shell, no exec - just file I/O."""
    with open(ACCESS_LOG, "a", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")

# ---- static ---------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(APP_DIR, "live_demo_target_site.html")

# ---- demo endpoints (log-only, no command execution) ----------------------- #
@app.route("/demo/normal", methods=["POST"])
def demo_normal():
    ip = f"192.168.208.{random.randint(100,240)}"
    line = combined(ip, "GET", random.choice(NORMAL_PATHS), 200,
                    random.randint(400, 6000), UA_NORMAL)
    append_lines([line])
    return jsonify(detail="정상 GET 요청 1건 기록", added=1, lines=[line])

@app.route("/demo/suspect", methods=["POST"])
def demo_suspect():
    # webshell command-injection pattern (same shape as the planted dataset)
    line = combined(SUSPECT_IP, "GET", "/search.php?cmd=id", 200, 120, UA_ATTACK)
    append_lines([line])
    return jsonify(detail="의심 요청(cmd= 웹셸 패턴) 1건 기록", added=1, lines=[line])

@app.route("/demo/flood", methods=["POST"])
def demo_flood():
    n = 15
    lines = [combined(SUSPECT_IP, "GET", f"/portal/login?try={i}", 401, 210,
                      UA_ATTACK) for i in range(n)]
    append_lines(lines)
    return jsonify(detail=f"짧은 간격 반복 요청 {n}건 기록", added=n, lines=lines[-3:])

@app.route("/demo/log")
def demo_log():
    from flask import request
    n = min(int(request.args.get("n", 15)), 50)
    try:
        with open(ACCESS_LOG, "r", encoding="utf-8", errors="replace") as f:
            tail = f.read().splitlines()[-n:]
    except FileNotFoundError:
        tail = []
    return jsonify(lines=tail)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("DEMO_PORT", "8080")))
