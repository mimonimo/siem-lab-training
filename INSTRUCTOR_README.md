# 실시간 위협 탐지 실습 — 강사 안내서 (INSTRUCTOR)

Wazuh SIEM 기반 침해 로그 분석 CTF 실습 환경입니다. 서버 1대를 **중앙 운영**하며 학생들이
브라우저로 접속해 로그를 분석하고 문제를 풉니다. **모든 공격 아티팩트는 실행되지 않는 더미(inert)** 입니다.

---
## 1. 페이지 · 접속 맵 (다른 서버로 옮겨도 동일)
| 페이지 | URL | 용도 | 인증 |
|---|---|---|---|
| **학생 미션 포털** | `http://<IP>:8081/` | 문제 풀이(자동채점·힌트·단계해금) | user_1..N / 비번=아이디 |
| **교안(courseware)** | `http://<IP>:8081/guide` | 구성도·시나리오·방법론·주의점 | 공개(학생/강사) |
| **강사 콘솔** | `http://<IP>:8081/instructor` | 해설·제출채점·해금관리 | 패스코드 `bridgeworks-instructor` |
| **Wazuh 대시보드** | `https://<IP>/` (443) | 로그 분석/탐지 | admin / (설치 시 발급) |
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

## 4. 강사 콘솔 (/instructor, 패스코드)
- **📘 문제 풀이 해설**: 36문항 정답·근거·조회쿼리·힌트·채점방식.
- **📊 제출 현황·채점**: 학생별 제출·점수·리더보드, 판단형(수동) 채점.
- **🔓 해금 관리**: 학생별 현재 단계 확인 + 강제 해금(오버라이드). 자동해금 임계치 60%.

## 5. 시나리오 (교안에 상세)
- 체인 **A→B→E** (공격자 198.51.100.23 / webadmin): 침투→권한상승(sudoers.d)→정보유출(198.51.100.47)
- 미끼 **C**(스캐너 192.0.2.77) · **D**(정상 관리자 192.168.208.50) · **F**(계정 잠금)

## 6. 로그 소스 (7종) + 지속 생성
`access.log·error.log·auth.log·audit/audit.log·cron.log·ufw.log·mail.log`
- `siem-livelog` 서비스가 90초마다 정상 로그를 계속 append → 데이터가 쌓이고 live하게 유지.
- Wazuh Discover 저장검색: **🚨 탐지 알림 / 🌐 웹 접근 / 🔐 인증 / 🧱 방화벽 / 🔎 전체 원문**.
  노이즈 필드(hipaa/pci/audit 상세)는 숨김 처리됨.

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
sudo bash /opt/siem-lab/scripts/90_finalize_dataset.sh   # 로그 재생성+Wazuh 클린적재+미션뱅크+포털 갱신
sudo python3 /opt/siem-lab/scripts/verify_hints.py       # 힌트 쿼리 전수 검증
sudo python3 /opt/siem-lab/scripts/config_dashboard.py   # 대시보드 필드정리+저장검색 재설정
```

## 9. 배포/이관
- 이 환경은 GitHub 스크립트로 **다른 서버에서 통째로 재빌드** 가능(README의 `build_all.sh`).
- 정답키·채점스펙은 비공개로 관리. 학생에겐 포털 접속만 제공.
