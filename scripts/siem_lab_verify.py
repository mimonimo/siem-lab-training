#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Self-check for the generated dataset. Run as root: sudo python3 siem_lab_verify.py
import json, os, subprocess, sys

ANSWERS = "/opt/siem-lab/answers"
manifest = json.load(open(f"{ANSWERS}/manifest.json", encoding="utf-8"))

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

print("="*78)
print(f"DATASET SELF-CHECK  (generated {manifest['generated_at']})")
print("="*78)

# --- 1. per-step: token present AND at the recorded line ---------------------
file_cache = {}
def lines_of(path):
    if path not in file_cache:
        with open(path, encoding="utf-8", errors="replace") as f:
            file_cache[path] = f.read().splitlines()
    return file_cache[path]

ok = fail = 0
print("\n[1] 공격 단계 로그 검증 (토큰 존재 + 기록된 라인 일치)")
print(f"{'ID':<9}{'FILE':<28}{'LINE':>5}  {'TOKEN@LINE':<10}{'GREP#':>6}  RESULT")
for s in manifest["steps"]:
    f, ln, tok = s.get("file"), s.get("line"), s["token"]
    if not f:
        print(f"{s['id']:<9}{'(no file)':<28}{'-':>5}"); continue
    ls = lines_of(f)
    at_line = (1 <= (ln or 0) <= len(ls)) and (tok in ls[ln-1])
    grep_n = sum(1 for x in ls if tok in x)
    short = f.replace("/var/log/", "…/")
    res = "OK" if (at_line and grep_n >= 1) else "FAIL"
    if res == "OK": ok += 1
    else: fail += 1
    print(f"{s['id']:<9}{short:<28}{str(ln):>5}  {('yes' if at_line else 'NO'):<10}{grep_n:>6}  {res}")

# --- 2. auditd key search ----------------------------------------------------
print("\n[2] auditd 키별 이벤트 (ausearch -if, 비-TTY 안전)")
print("     주: 학생은 터미널에서 'ausearch -k <key>' 로 조회(TTY면 기본 로그파일 자동 사용).")
for key in ["webshell_exec", "webroot_write", "cron_persist", "bin_tamper"]:
    r = sh(f"ausearch -if /var/log/audit/audit.log -k {key} 2>/dev/null | grep -c 'type=SYSCALL'")
    n = r.stdout.strip() or "0"
    print(f"   ausearch -k {key:<14} -> SYSCALL records: {n}")

# --- 3. inert artifacts: existence, perms, mtime distinct, strings -----------
print("\n[3] 비동작 아티팩트 검증")
for a in manifest["artifacts"]:
    p = a["path"]
    st = sh(f"stat -c '%A %U:%G %y' '{p}' 2>/dev/null").stdout.strip()
    print(f"   {p}\n       stat: {st or 'MISSING'}")
# backup binary distinctness vs a normal /usr/bin file
r1 = sh("stat -c '%Y' /usr/bin/backup 2>/dev/null").stdout.strip()
r2 = sh("stat -c '%Y' /usr/bin/id 2>/dev/null").stdout.strip()
print(f"   /usr/bin/backup mtime={r1}  vs  /usr/bin/id mtime={r2}  "
      f"-> {'DISTINCT' if r1 and r1!=r2 else 'same?'}")
print("   strings /usr/bin/backup (markers):")
r = sh("strings /usr/bin/backup | grep -E 'setuid|authorized_keys|kworker|connect-back'")
for l in r.stdout.strip().splitlines():
    print(f"       {l}")
# confirm webshell is NOT live (php not enabled)
r = sh("a2query -m php 2>/dev/null; ls /etc/apache2/mods-enabled/php* 2>/dev/null")
print(f"   PHP module enabled? {'YES(!)' if r.stdout.strip() else 'no (webshell inert)'}")

# --- 4. noise ratio ----------------------------------------------------------
print("\n[4] 정상/공격 트래픽 비율 (access.log)")
al = lines_of("/var/log/apache2/access.log")
att = sum(1 for l in al if "search.php" in l)
tot = len(al)
print(f"   total={tot}  attack(search.php)={att}  normal={tot-att}  "
      f"ratio≈{round((tot-att)/max(att,1))}:1")

# --- 5. services -------------------------------------------------------------
print("\n[5] 서비스 상태")
for svc in ["apache2", "auditd", "rsyslog"]:
    print(f"   {svc:<10} {sh(f'systemctl is-active {svc}').stdout.strip()}")

print("\n" + "="*78)
print(f"RESULT: {ok} OK / {fail} FAIL")
print("="*78)
sys.exit(1 if fail else 0)
