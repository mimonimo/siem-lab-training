# 실시간 위협 탐지 실습 — 강사 안내서 (INSTRUCTOR)

Wazuh SIEM 기반 침해 로그 분석 CTF 실습 환경입니다. 서버 1대를 **중앙 운영**하며 학생들이
브라우저로 접속해 로그를 분석하고 문제를 풉니다. **모든 공격 아티팩트는 실행되지 않는 더미(inert)** 입니다.

---
## 1. 페이지 · 접속 맵 (다른 서버로 옮겨도 동일)
| 페이지 | URL | 용도 | 인증 |
|---|---|---|---|
| **학생 미션 포털** | `http://<IP>:8081/` | 문제 풀이(자동채점·힌트·단계해금) | user_1..N / 비번=아이디 |
| **교안(courseware)** | `http://<IP>:8081/guide` | 구성도·시나리오·방법론·주의점 | 공개(학생/강사) |
| **강사 콘솔** | `http://<IP>:8081/instructor` | 해설·제출채점·해금관리 | 포털에서 **admin / p@ssw0rd** 로그인 → "강사 콘솔" 버튼 (또는 패스코드 `bridgeworks-instructor`) |
| **Wazuh 대시보드** | `https://<IP>/` (443) | 로그 분석/탐지 | admin / (설치 시 발급, 포털 상단에도 표시) |
| 라이브 데모 | `http://<IP>:8080/` | 버튼→실시간 탐지 시연 | 없음 |
| 사전로그 웹서버 | `http://<IP>/` (Apache) | 로그를 채우는 대상 | 없음 |

> admin 비번: `/opt/siem-lab/logs/wazuh-install.log` 의 `Password:` (배포 정리 전에 별도 기록).
> 학생 계정 수는 `PORTAL_USERS`(기본 20), 강사키는 `/opt/siem-lab/portal/portal.env` 에서 변경.

## 2. 운영 방식 — 중앙 서버 1대
- 20명이 브라우저로 접속. 복제 배포 불필요.
- **네트워크**: VMware를 **Bridged**로 (NAT는 호스트만 접근). 20명 동시 시 RAM 16GB↑ 권장, OpenSearch 힙 6GB.

## 3. 학생 실습 흐름
1. 포털(:8081) 로그인 → **교안** 으로 배경 파악 → 문제 확인(답안 형식·Wazuh 힌트 제공)
2. "Wazuh 대시보드" → Discover에서 저장검색/쿼리로 로그 분석
3. 포털에 답 제출 → 자동채점 + 점수/진행률. 막히면 힌트(소폭 감점), 오답은 감점.
- **단계 해금**: 1단계(Q1~10)→2단계(Q11~20)→3단계(보너스). 이전 단계 60% 완료 시 자동 해금. 찍기·건너뛰기 방지.

## 4. 강사 콘솔 (/instructor)
- **접속**: 포털에서 `admin` / `p@ssw0rd` 로 로그인하면 헤더에 "강사 콘솔" 버튼이 생깁니다(별도 URL·패스코드 암기 불필요).
- **📘 문제 풀이 해설**: 36문항 정답·근거·조회쿼리·힌트·채점방식 + 풀이 단계/분석 관점.
- **📊 제출 현황·채점**: 학생별 제출·점수·리더보드, 판단형(수동) 채점.
- **🔓 해금 관리**: 학생별 현재 단계 확인 + 강제 해금(오버라이드). 자동해금 임계치 60%.

## 5. 시나리오 (교안에 상세)
- 체인 **A→B→E** (공격자 198.51.100.23 / webadmin): 침투→권한상승(sudoers.d)→정보유출(198.51.100.47)
- 미끼 **C**(스캐너 192.0.2.77) · **D**(정상 관리자 192.168.208.50) · **F**(계정 잠금)

## 6. 로그 소스 (7종) + 지속 생성
`access.log·error.log·auth.log·audit/audit.log·cron.log·ufw.log·mail.log`
- 정상 트래픽 대량(웹 접근 ~1,400줄 등) + 이상 로그 소수를 섞어 **needle-in-haystack** 난이도. 클린 재빌드 시 archives ≈ 2,200건.
- `siem-livelog` 서비스가 90초마다 정상 로그를 계속 append → 데이터가 쌓이고 live하게 유지.
- **인덱스 패턴 3개**: `wazuh-archives-*`(전체 로그=정상+이상) · `wazuh-alerts-*`(탐지 알림) · `wazuh-alerts-*,wazuh-archives-*`(통합, 한 번에 보기·난이도↑).
- Wazuh Discover 저장검색: **🚨 탐지 알림 / 🧩 전체 로그 / 🌐 웹 접근 / 🔐 인증 / 🧱 방화벽**.

### 분석 팁 (학생 안내용)
- **Discover의 Time 컬럼 = 수집(적재) 시각**. 사건 순서는 로그 본문의 실제 시각(예: `Aug 13 10:11:32`)으로 판단. 시간 범위는 **Last 1 year**.
- **대문자·특수문자(:)가 든 값**(예: `NOPASSWD:ALL`)은 따옴표 검색이 안 걸릴 수 있음 → 와일드카드 `full_log:*NOPASSWD*` 사용.

## 6-1. 라이브 데모 진행 가이드 (강사 전용 · 학생 화면엔 힌트 없음)
데모 사이트(`http://<IP>:8080/`)는 **실제 사내 포털처럼 보이도록 힌트를 넣지 않았습니다.** 아래 내용을 강의 중 강사가 시연·설명하세요. 모든 동작은 **로그만 기록**하며 시스템 명령을 실행하지 않습니다(inert).

데모 사이트는 **로그인/로그아웃·통합검색·공지/문서 상세·게시판·헬프데스크**가 실제로 동작하는 미니 웹앱입니다. 데모 로그인 계정: **`khw` / `bridge2026`** (로그아웃 후 로그인 화면에서 시연).

**공격 표면 (직접 입력해서 시연)**
| 위치 | 시연 입력 예 | 결과(로그/탐지) |
|---|---|---|
| **홈 검색창** | `id` , `cat /etc/passwd` , `; whoami` | `/search.php?cmd=...` → **rule 100101** (웹셸 명령) |
| **자유게시판 글쓰기** | `<script>alert(1)</script>` , `<img src=x onerror=alert(1)>` | 저장형 **XSS가 브라우저에서 실제 실행** (웹 접근 로그엔 본문 안 남음 → 앱/WAF 로그 필요 설명 포인트) |
| **헬프데스크 1:1 문의** | `whoami` , `wget http://...` | `/helpdesk/run?cmd=...` → **rule 100101** |
| **로그인 폼(무차별 대입)** | 틀린 비밀번호 반복 입력 | `POST /login` **401 반복** → 무차별 대입(brute force) 패턴 |
| **로그인 폼(SQL 인젝션)** | `admin' OR 1=1--` | `/login?username=...` → SQLi payload가 웹 접근 로그에 노출 |

**게시판에 숨겨둔 문제**: 게시글 중 작성자 `guest_7f2c` 글에 **저장형 XSS 페이로드**가 심어져 있습니다(페이지 열면 상단에 "저장형 XSS 실행됨" 표시). "이 게시판에서 이상한 점을 찾아보라"는 과제로 활용하세요.

**실습 콘솔(하단 검정 패널)** — 강사용 빠른 시연 도구:
- 킬 체인 버튼 ①웹셸 → ②다운로드 → ③유출 순서로 눌러 공격 진행을 보여주고, 각 버튼의 **rule 배지**와 **공격 해부 패널**(대상 페이지·메서드·주입 위치·페이로드·출발지)을 설명.
- 기타: 웹 스캐너(rule 100102), 로그인 폭주, 정상 트래픽.
- 콘솔은 **최소화(▁)·드래그로 높이 조절** 가능. 공격 출발지는 모두 `203.0.113.66` → Wazuh에서 `data.srcip:"203.0.113.66"` 로 필터해 실시간 탐지 확인.

**진행 흐름 예시**: 정상 트래픽 몇 번 → 검색창에 `id` 입력(웹셸 탐지) → 킬체인 ①②③ → Wazuh에서 `data.srcip:"203.0.113.66"` 조회 → 게시판 XSS 시연 → "웹 로그로 안 보이는 공격도 있다" 설명.

## 7. 파일 위치 (`/opt/siem-lab/`)
| 항목 | 경로 |
|---|---|
| 학생 문제지 / **정답키(대외비)** | `student/mission_sheet.md` / `answers/mission_answer_key.md` |
| 채점 스펙 / 데이터셋 매니페스트 | `answers/grading_spec.json` / `answers/manifest.json` |
| 포털 앱 (미션·교안·강사) | `portal/portal_app.py` `portal.html` `guide.html` `instructor.html` |
| 데모 앱 | `demo/` (systemd `siem-demo`) |
| 재현 스크립트 전체 | `scripts/` |
| 커스텀 Wazuh 룰 | `/var/ossec/etc/rules/local_rules.xml` (100101~100113) |
| 서비스 | `siem-portal`(8081) `siem-demo`(8080) `siem-livelog`(로그생성) |

## 8. 재빌드 / 검증 (필요 시)
```
sudo bash /opt/siem-lab/scripts/90_finalize_dataset.sh   # 로그 재생성+Wazuh 클린적재+미션뱅크+포털 갱신 (약 3~4분)
sudo python3 /opt/siem-lab/scripts/verify_hints.py       # 힌트 쿼리 전수 검증 (Q32는 라이브데모 전용이라 0건이 정상)
sudo python3 /opt/siem-lab/scripts/verify_solve.py       # 실제 풀이 검증(정답이 조회로 찾아지는지)
sudo python3 /opt/siem-lab/scripts/config_dashboard.py   # 인덱스패턴 3개+저장검색 재설정, 중복/내부패턴 정리
```
- 재빌드는 대량 로그를 **청크로 나눠 천천히 적재**합니다(로그수집기→분석엔진 큐 1024 한계 초과 시 유실 방지). 다른 서버로 옮겨 재빌드해도 전량 적재됩니다.
- MISS로 보이는 소수 문항(공격 지속시간=시각 계산, 로그소스 나열=location 필드, 데모 문항)은 **설계상 파생답**으로 정상입니다.

## 9. 배포/이관 · 업데이트 반영
- **최초 구축(새 서버)**: GitHub clone 후 `sudo bash build_all.sh` (Wazuh 포함 통째로, 25~35분).
- **이후 업데이트 반영(운영 중 서버)**: build_all을 다시 돌리지 마세요(Wazuh 재설치·학생기록 삭제됨). 대신:
  ```
  cd <repo> && git pull
  sudo bash update.sh <모드>        # portal | bank | dash | data | rules | all
  ```
  | 모드 | 언제 | 반영 대상 |
  |---|---|---|
  | `portal` | UI/서버만 바꿈 | portal_app.py·*.html 배포+재시작(기본, 즉시) |
  | `bank` | 문제/채점 바꿈 | mission_bank_gen.py 재생성 |
  | `dash` | 대시보드 설정 | config_dashboard.py |
  | `data` | 로그/시나리오 바꿈 | 90_finalize 클린 재적재(3~4분)+대시보드 |
  | `rules` | Wazuh 커스텀 룰 | local_rules.xml 재적용+재적재 |
  | `all` | 로그+문제+대시보드 한 번에 | data+dash |
  - **portal.db(학생 진행·Q&A)는 모든 모드에서 보존**됩니다. 새 기수 시작 시에는 강사 콘솔 → 사용자·해금 → "전체 초기화".
- **네트워크(외부 접속)** — 포털은 접속 주소(`location.hostname`)+기본포트를 그대로 따르므로 **IP 하드코딩이 없어** 아래 두 방식 모두 설정 변경 없이 동작합니다. 단, VM 방화벽은 열어두세요(`sudo ufw status`; 활성 시 `sudo ufw allow 8081,443,8080,22/tcp`). Wazuh(:443)는 자체 서명 인증서라 브라우저 경고 → "고급 → 계속".
  1. **Bridged (권장, 유선/정상 Wi-Fi)**: VM이 직접 LAN IP를 받음(`hostname -I`). 학생은 `http://<VM-IP>:8081/`.
  2. **NAT + 포트포워딩 (Bridged가 막히는 Wi-Fi 등)**: 호스트(Windows)에서 관리자 PowerShell로 `scripts/win_nat_portforward.ps1` 실행 → 호스트 LAN IP로 공개. 학생은 `http://<호스트 LAN IP>:8081/`. **포트는 1:1(8081/443/8080)로 매핑**해야 Wazuh 버튼(포트 없는 https)이 동작. VM IP가 바뀌면 스크립트의 `$VMIP` 수정 후 재실행. (같은 Wi-Fi의 'AP 격리'가 켜져 있으면 학생↔호스트 통신이 막힐 수 있음 → 유선/공유기 확인)
- 정답키·채점스펙은 비공개로 관리. 학생에겐 포털 접속만 제공.
