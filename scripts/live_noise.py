#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Continuous benign-log generator. Appends fresh NORMAL log lines (web access,
# mail, firewall) with current timestamps to the monitored files so the dataset
# keeps growing and feels live. Adds NO attack patterns -> no false alerts.
# Run as a systemd service:  siem-livelog.service
import os, time, random
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
ACCESS = "/var/log/apache2/access.log"
MAILL  = "/var/log/mail.log"
UFWL   = "/var/log/ufw.log"
HOST   = os.uname().nodename
INTERVAL = int(os.environ.get("LIVE_INTERVAL", "90"))

PATHS = ["/", "/index.html", "/portal/dashboard", "/portal/notices", "/portal/approval/inbox",
         "/portal/attendance", "/portal/messenger", "/portal/drive/shared", "/api/v1/notices",
         "/api/v1/user/me", "/api/v1/attendance/today", "/api/status", "/css/main.css",
         "/js/app.js", "/img/logo.png", "/favicon.ico", "/docs/guide.html", "/help/faq",
         "/portal/hr/payslip", "/portal/board/free", "/api/v1/approval/count"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
       "Mozilla/5.0 (Linux; Android 14; SM-S911N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36"]
REFS = ["-", "-", "https://portal.bridgeworks.local/portal/dashboard", "https://portal.bridgeworks.local/"]

def now(): return datetime.now(tz=KST)
def append(path, lines):
    try:
        with open(path, "a", encoding="utf-8") as f:
            for l in lines: f.write(l + "\n")
    except Exception:
        pass

def gen_access(n):
    out = []
    for _ in range(n):
        dt = now(); ip = f"192.168.208.{random.randint(100,240)}"
        p = random.choice(PATHS); ua = random.choice(UAS); ref = random.choice(REFS)
        st = random.choices([200,304,200,200,302,404],weights=[10,4,10,10,1,1])[0]
        m = "POST" if p.startswith("/api/") and random.random()<0.2 else "GET"
        sz = 0 if st==304 else random.randint(180,12000)
        out.append(f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{m} {p} HTTP/1.1" {st} {sz} "{ref}" "{ua}"')
    return out

def gen_mail(n):
    out=[]
    for _ in range(n):
        dt=now(); pid=random.randint(1000,9000); qid=f"{random.randint(0x100000,0xFFFFFF):06X}"
        s=random.choice(["hr","it-helpdesk","noreply","payroll"])
        out.append(f'{dt.strftime("%b %e %H:%M:%S")} {HOST} postfix/qmgr[{pid}]: {qid}: from=<{s}@bridgeworks.local>, size={random.randint(2000,90000)}, nrcpt=1 (queue active)')
    return out

def gen_ufw(n):
    out=[]
    for _ in range(n):
        dt=now(); dpt=random.choice([23,2323,5900,1433,8443,3389,445])
        out.append(f'{dt.strftime("%b %e %H:%M:%S")} {HOST} kernel: [UFW BLOCK] IN=ens33 OUT= '
                   f'SRC=203.0.113.{random.randint(2,250)} DST=192.168.208.134 LEN=60 PROTO=TCP '
                   f'SPT={random.randint(30000,60000)} DPT={dpt} WINDOW=1024 SYN URGP=0')
    return out

def main():
    while True:
        append(ACCESS, gen_access(random.randint(4,12)))
        if random.random()<0.6: append(MAILL, gen_mail(random.randint(1,4)))
        if random.random()<0.5: append(UFWL, gen_ufw(random.randint(1,3)))
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
