# 실시간 위협 탐지 실습 — 골든 이미지 강사 안내 (INSTRUCTOR)

이 VM은 Wazuh SIEM 실습용 골든 이미지입니다. 사전 침해 로그가 Wazuh에 적재되어 있어,
학생은 대시보드에서 곧바로 증적을 조회·분석하고 미션을 풀 수 있습니다.
**모든 공격 아티팩트는 비동작(inert) 더미입니다 — 실제 실행되는 악성코드는 없습니다.**

## 1. 접속 정보
| 대상 | 주소 | 계정 |
|---|---|---|
| **학생 미션 포털**(자동채점) | http://<VM_IP>:8081/ | 조 이름 입력 |
| Wazuh 대시보드 | https://<VM_IP> (443) | admin / (설치 시 발급된 비밀번호) |
| 라이브 데모 포털 | http://<VM_IP>:8080/ | (없음) |
| 사전 로그 웹서버 | http://<VM_IP>/ (Apache) | (없음) |
| SSH/콘솔 | siem / (공지 비밀번호) | |

## 1-b. 운영 방식 — 중앙 서버 1대 (복제 불필요)
20명이 브라우저로 이 서버 1대에 접속해 실습합니다. 복제 배포하지 않습니다.
- **전제조건**: VMware 네트워크를 **브리지(Bridged)**로 바꿔 교내망에서 이 서버 IP가 라우팅되게 할 것(NAT는 호스트만 접근 가능).
- **권장 사양**: RAM 16GB↑(동시 20명), OpenSearch 힙 6GB로 튜닝(`/etc/wazuh-indexer/jvm.options` -Xms/-Xmx 6144m 후 `systemctl restart wazuh-indexer`).
- 학생 흐름: **포털(:8081)에서 문제 확인 → Wazuh(:443)에서 로그 분석 → 포털에 답 제출(자동채점)**.

## 1-c. 학생 미션 포털 (siem-portal, 포트 8081)
- 학생이 조 이름 입력 후 36문항 풀이. 객관식 25문항 **자동채점**, 판단·토의형 11문항은 **강사 채점**.
- 각 문항에 Wazuh 쿼리 힌트(복사 가능) 제공. 진행률·점수·리더보드 표시.
- **강사 콘솔(API)**: 제출 현황/수동채점.
  - 제출 조회: `http://<VM_IP>:8081/api/instructor/submissions?key=bridgeworks-instructor`
  - 수동 채점: POST `/api/instructor/grade` body `{"key":"bridgeworks-instructor","team":"1조","qno":10,"award":4}`
  - 강사 키 변경: `/opt/siem-lab/portal/portal.env` 의 `PORTAL_INSTRUCTOR_KEY`.
- 제출 데이터: `/opt/siem-lab/portal/portal.db` (sqlite). 채점 스펙: `/opt/siem-lab/portal/grading_spec.json`.
- 문제/로그를 재생성(90_finalize)하면 포털 채점 스펙도 자동 갱신·재시작됩니다.

> admin 비밀번호: 설치 로그 `/opt/siem-lab/logs/wazuh-install.log` 의 `Password:` 라인.
> (배포 정리 시 이 로그를 비우므로 미리 안전한 곳에 기록해 두세요.)

## 2. 학생 실습 흐름 (권장)
1. **강사 시연**: 데모 포털(:8080) 하단 "실습 콘솔"의 [의심스러운 검색 요청] 버튼 클릭
   → 몇 초 뒤 대시보드에 `rule.id:100101`(웹셸 명령 실행) 알림이 뜨는 것을 함께 확인.
2. **학생 재현**: 각자 버튼을 눌러 실시간 탐지를 체감.
3. **본 실습(정적 분석)**: 학생용 문제지로 사전 침해 로그를 분석해 미션 풀이.
   - Discover 인덱스 패턴: `wazuh-alerts-*`(탐지 알림) / `wazuh-archives-*`(모든 로그 검색)
   - 시간 범위는 기본 넓게(최근 1년) 설정됨. 비면 우측 상단 Last 1 year.

## 3. 시나리오 구성 (6개 스토리라인)
- **체인 A→B→E** (동일 공격자 198.51.100.23 / 계정 webadmin):
  - A: SSH 브루트포스 → 웹셸(search.php) → 페이로드 다운로드 → cron 지속성 → /usr/bin/backup 변조
  - B: /etc/sudoers.d/webadmin NOPASSWD 권한 상승
  - E: tar 압축(/tmp/loot.tgz) → curl 외부 유출(198.51.100.47)
- **미끼(대응 판단 훈련)**:
  - C: sqlmap 스캐너(192.0.2.77) — 정찰, 침해 미연결(저위험)
  - D: 정상 관리자 야간 배포(opsadmin/192.168.208.50) — 공격처럼 보이나 정상
  - F: 반복 실패 후 계정 잠금(198.51.100.99) — 방어 성공, 대응 불필요

## 4. 파일 위치
| 항목 | 경로 |
|---|---|
| 학생 문제지(정답 없음) | `/opt/siem-lab/student/mission_sheet.md` |
| **정답 키(대외비)** | `/opt/siem-lab/answers/mission_answer_key.md` |
| 데이터셋 매니페스트(정답 원천) | `/opt/siem-lab/answers/manifest.json`, `manifest_table.md` |
| 재현 스크립트 전체 | `/opt/siem-lab/scripts/` |
| 라이브 데모 앱 | `/opt/siem-lab/demo/` (systemd: `siem-demo`) |
| 커스텀 Wazuh 룰 | `/var/ossec/etc/rules/local_rules.xml` (id 100101~100113) |

## 5. 데이터셋 재빌드 (필요 시)
로그를 새로 굽거나 타임스탬프를 갱신하려면:
```
sudo bash /opt/siem-lab/scripts/90_finalize_dataset.sh
```
→ 로그 재생성 + Wazuh 클린 재적재 + 미션뱅크(문제지/정답키) 재생성 + 검증까지 한 번에.
검증 스크립트만: `sudo python3 /opt/siem-lab/scripts/siem_lab_verify.py`,
Wazuh 조회 검증: `sudo bash /opt/siem-lab/scripts/60_wazuh_query_check.sh`

## 6. 배포 절차 (20대 복제)
1. **배포 전 정리**(정답 노출/빌드 흔적 제거):
   ```
   sudo bash /opt/siem-lab/scripts/95_predeploy_cleanup.sh          # 먼저 dry-run으로 계획 확인
   sudo bash /opt/siem-lab/scripts/95_predeploy_cleanup.sh --confirm
   ```
   → 생성한 `/root/siem-lab-instructor-*.tar.gz`(생성기·정답키 백업)를 **호스트로 복사 후 이미지에서 삭제**.
2. `sudo poweroff` → VM 폴더 복사(또는 OVF export)로 배포.
3. 학생 첫 실행 시 반드시 **"I Copied It(복사했습니다)"** 선택 (MAC/UUID 갱신 — 20대 충돌 방지).
4. 네트워크는 **NAT 유지**. 학생에겐 **문제지만** 배포(정답 키 제외).

## 7. 커스텀 룰 요약
| rule.id | 의미 |
|---|---|
| 100101 | 웹셸 명령 실행 시도 (URL cmd=) |
| 100102 | 웹 스캐너(sqlmap UA) |
| 100103 | 짧은 간격 반복 요청(flood) |
| 100110 | 웹서비스 계정 프로세스 실행(웹셸 경유) |
| 100111 | sudoers.d 변경(권한 상승) |
| 100112 | cron 지속성 등록 |
| 100113 | 시스템 바이너리(/usr/bin) 변조 |

문의/재현은 `/opt/siem-lab/scripts/` 의 번호순 스크립트를 참고하세요.
