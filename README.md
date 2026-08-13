# SIEM 실시간 위협 탐지 실습 환경 (Wazuh · CTF형)

Ubuntu Server 22.04 **한 대를 중앙 운영**하며 20여 명이 브라우저로 접속해, 침해 웹서버의
다양한 보안 로그를 Wazuh SIEM으로 분석하고 문제를 푸는 CTF형 실습 플랫폼입니다.
모든 재현 과정을 스크립트로 담아 다른 서버에서 그대로 재빌드할 수 있습니다.

> ⚠️ 정답 로직(`scripts/mission_bank_gen.py`)이 포함되므로 **공개 저장소면 정답 노출** 주의(private 권장).
> 비밀번호·인증서·세션키·DB는 `.gitignore`로 제외되며 빌드 시 서버마다 새로 생성됩니다.
> 모든 공격 아티팩트는 **실행되지 않는 더미(inert)** 입니다.

## 페이지 맵
| 페이지 | URL | 용도 |
|---|---|---|
| 학생 미션 포털 | `http://<IP>:8081/` | 문제 풀이 — 개인 로그인·자동채점·힌트(감점)·**단계 해금** |
| 교안(courseware) | `http://<IP>:8081/guide` | 네트워크 구성도·시나리오·분석 방법론·주의점 (학생/강사) |
| 강사 콘솔 | `http://<IP>:8081/instructor` | 문제 해설·제출채점·**해금 관리** (패스코드) |
| Wazuh 대시보드 | `https://<IP>/` | 로그 분석/탐지 (admin) |
| 라이브 데모 | `http://<IP>:8080/` | 버튼→실시간 탐지 시연 |

## 빠른 시작 (베어 Ubuntu 22.04에서 전체 재빌드)
```bash
sudo apt-get update && sudo apt-get install -y git
git clone <이 저장소 URL> siem-lab && cd siem-lab
sudo bash build_all.sh          # ~30분 (Wazuh 설치가 대부분), 인터넷 필요
```
완료 후: 포털 `http://<IP>:8081`, 대시보드 `https://<IP>` (admin 비번 = `/opt/siem-lab/logs/wazuh-install.log`).

## 주요 기능
- **7종 로그**: access·error·auth·audit·cron·ufw(방화벽)·mail + `siem-livelog` 데몬이 90초마다 정상 로그 지속 생성.
- **시나리오**: 체인 A(브루트포스→웹셸→다운로드→cron→변조)→B(권한상승)→E(정보유출) + 미끼 C/D/F.
- **문제 36**: 자동채점 25 + 판단형 11. 답안 형식 표기(시각/IP 등), 힌트 3단계(감점), 정답 시 해설(왜 의심·분석 관점).
- **단계 해금**: 1(Q1~10)→2(Q11~20)→3(보너스). 이전 단계 60% 완료 시 자동 해금 + 강사 강제 해금.
- **Wazuh 정리**: 노이즈 필드 숨김 + 로그종류별 저장검색(웹/인증/방화벽/알림/원문).
- **커스텀 룰** 100101~100113 (웹셸·스캐너·권한상승·지속성·변조).

## 학생 흐름
포털 로그인 → 교안으로 배경 파악 → 문제 확인(Wazuh 힌트) → Wazuh Discover 분석 → 답 제출(자동채점).

## 스크립트 (`scripts/`)
| 파일 | 역할 |
|---|---|
| `10_install_infra.sh` / `20_fix_audit.sh` | Apache·auditd·rsyslog / 타깃 audit 룰 + RAW |
| `40_wazuh_config.sh` (+`config_wazuh.py`,`local_rules.xml`) | 로그 수집·아카이브·취약점탐지off·커스텀룰 |
| `47/48_*.sh` + `config_dashboard.py` | 인덱스패턴·시간범위 + 필드정리·저장검색 |
| `siem_lab_gen.py` | 침해 로그 데이터셋 생성기(결정론적, 7종 로그) |
| `mission_bank_gen.py` | 문제지·정답키·채점스펙(형식·힌트·해설·인사이트) |
| `50_demo_deploy.sh` / `70_portal_deploy.sh` | 데모 / 포털·교안·강사·라이브로그 서비스 |
| `90_finalize_dataset.sh` | **정규 재빌드**: 로그 재생성→클린적재→미션뱅크→포털 갱신 |
| `live_noise.py` | 지속 로그 생성 데몬 (systemd `siem-livelog`) |
| `verify_hints.py` | 힌트 Wazuh 쿼리 전수 검증 |
| `95_predeploy_cleanup.sh` | (복제 배포용) 정답·비밀·흔적 제거 — 중앙 운영이면 불필요 |

## 재빌드·검증
```bash
sudo bash /opt/siem-lab/scripts/90_finalize_dataset.sh   # 로그·적재·미션뱅크·포털 한 번에 갱신
sudo python3 /opt/siem-lab/scripts/verify_hints.py       # 힌트 쿼리 검증
```

## 운영(중앙 서버) 준비
- 네트워크 **Bridged**(교내망 라우팅), 20명 동시 시 RAM 16GB↑ + OpenSearch 힙 6GB.
- 강사 안내서: [`INSTRUCTOR_README.md`](INSTRUCTOR_README.md).

---
공격자 IP는 RFC 5737 TEST-NET 대역만 사용합니다.
