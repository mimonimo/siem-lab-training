# SIEM 실시간 위협 탐지 실습 환경 (Wazuh)

대학 사이버보안 실습용 **침해 웹서버 로그 분석 훈련 플랫폼**을 한 번에 재현하는 스크립트 모음입니다.
Ubuntu Server 22.04 한 대에 Wazuh SIEM + 사전 침해 로그 + 라이브 데모 + **자동채점 학생 포털**을 구축합니다.

> ⚠️ 이 저장소에는 **정답 키(`scripts` 실행 시 생성)** 로직이 포함됩니다. 학생에게 저장소 링크를 그대로 주지 마세요.
> 세션키·인증서·비밀번호·런타임 DB는 `.gitignore` 로 제외되며, 빌드 시 각 VM에서 새로 생성됩니다.

## 무엇이 만들어지나
| 구성 | 내용 | 접속 |
|---|---|---|
| 침해 로그 데이터셋 | SSH 브루트포스→웹셸→다운로드→cron→바이너리변조→권한상승→정보유출 + 미끼 3종. **모두 비동작(inert) 더미** | `/var/log/*` |
| Wazuh SIEM | 4.11 all-in-one, 로그를 `wazuh-alerts-*` / `wazuh-archives-*` 에 적재, 커스텀 룰(100101~) | `https://<ip>` (admin) |
| 라이브 데모 | 버튼 클릭 → 실시간 탐지 (명령 실행 없이 로그만 기록) | `http://<ip>:8080` |
| 학생 미션 포털 | 36문항(자동채점 25 + 수동 11), 진행률·점수·리더보드·강사콘솔 | `http://<ip>:8081` |

## 빠른 시작 (베어 Ubuntu 22.04에서 전체 재빌드)
```bash
sudo apt-get update && sudo apt-get install -y git
git clone <이 저장소 URL> siem-lab && cd siem-lab
sudo bash build_all.sh          # ~25-35분 (Wazuh 설치가 대부분), 인터넷 필요
```
완료 후: 학생 포털 `http://<ip>:8081`, 대시보드 `https://<ip>` (admin 비번은 `/opt/siem-lab/logs/wazuh-install.log`).

## 학생 실습 흐름 (사전지식 불필요)
1. 포털(:8081)에서 조 이름 입력 → 문제 확인 (각 문항에 Wazuh 쿼리 힌트)
2. "Wazuh 열기" → Discover 에서 힌트 쿼리로 로그 분석
3. 포털에 답 제출 → 자동채점 + 점수/진행률

## 운영 방식: 중앙 서버 1대
20명이 브라우저로 서버 1대에 접속(복제 배포 불필요). 필요조건:
- **네트워크**: VMware 를 **Bridged** 로 (NAT 는 호스트만 접근). 
- **사양**: 20명 동시 접속 시 RAM 16GB↑ 권장, OpenSearch 힙 6GB (`/etc/wazuh-indexer/jvm.options`).
- 소규모/개발은 현재 사양(8vCPU/8~11GB)으로 충분.

## 스크립트 구성 (`scripts/`)
| 파일 | 역할 |
|---|---|
| `10_install_infra.sh` | Apache + auditd + rsyslog + binutils/curl |
| `20_fix_audit.sh` | 타깃형 auditd 룰(uid=33 webshell_exec + watch) + RAW 포맷 |
| `40_wazuh_config.sh` + `config_wazuh.py` + `local_rules.xml` | 로그 수집 등록, 아카이브 활성화, 취약점탐지 off, 커스텀 룰 |
| `47/48_*.sh` | 대시보드 인덱스 패턴 + 기본 시간범위(now-1y) |
| `siem_lab_gen.py` | 침해 로그 데이터셋 생성기 (결정론적, manifest 출력) |
| `mission_bank_gen.py` | 문제지/정답키/채점스펙(`grading_spec.json`) 생성 |
| `50_demo_deploy.sh` (+`demo/`) | 라이브 데모 systemd |
| `70_portal_deploy.sh` (+`portal/`) | 자동채점 포털 systemd |
| `90_finalize_dataset.sh` | **정규 재빌드**: 로그 재생성→Wazuh 클린 적재→미션뱅크→검증 (언제든 재실행) |
| `95_predeploy_cleanup.sh` | (복제 배포 시) 정답/비밀/빌드흔적 제거 — 중앙 운영이면 불필요 |
| `siem_lab_verify.py`, `60_wazuh_query_check.sh` | 데이터셋/적재 검증 |

## 로그/문제를 다시 굽고 싶을 때
```bash
sudo bash /opt/siem-lab/scripts/90_finalize_dataset.sh
```
로그·Wazuh 적재·문제지/정답키·포털 채점스펙까지 한 번에 갱신됩니다.

## 강사용
자세한 운영/채점/강사콘솔은 [`INSTRUCTOR_README.md`](INSTRUCTOR_README.md) 참고.

---
비동작 원칙: 모든 공격 아티팩트는 실행되지 않는 더미입니다. 실제 악성코드·동작 웹셸·백도어는 없습니다.
공격자 IP는 RFC 5737 TEST-NET 대역만 사용합니다.
