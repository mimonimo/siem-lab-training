#!/bin/bash
# ============================================================================
# Apply GitHub updates to a RUNNING server — without reinstalling Wazuh and
# without losing student progress (portal.db / Q&A stay intact).
#
# Workflow:
#   1) (dev)  edit -> git commit -> git push
#   2) (prod) cd <this repo> && git pull
#   3) (prod) sudo bash update.sh <mode>
#
# Modes (pick by what you changed):
#   portal  UI/서버만 (portal_app.py, *.html)          — 즉시, 데이터 유지          [기본]
#   bank    + 문제/채점 변경 (mission_bank_gen.py)       — 문제 재생성
#   dash    + 대시보드 설정 (config_dashboard.py)
#   data    + 로그/시나리오 변경 (siem_lab_gen.py 등)    — 데이터셋 클린 재적재(3~4분)
#   rules   + Wazuh 커스텀 룰 (local_rules.xml)          — 룰 재적용 후 data 재적재
#   all     bank+data+dash 한 번에 (로그+문제+대시보드)
#
# NOTE: 이 스크립트는 Wazuh를 재설치하지 않습니다. 완전 새 서버 최초 구축은
#       build_all.sh 를 쓰세요. portal.db(학생 진행)는 어떤 모드에서도 보존됩니다.
# ============================================================================
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root:  sudo bash update.sh <portal|bank|dash|data|rules|all>"; exit 1; }
REPO="$(cd "$(dirname "$0")" && pwd)"
LAB=/opt/siem-lab
MODE="${1:-portal}"
say(){ echo; echo ">> $*"; }

sync_files(){
  say "저장소 파일 동기화 (scripts, portal, demo)"
  cp "$REPO"/scripts/*.py "$REPO"/scripts/*.sh "$LAB"/scripts/ 2>/dev/null || true
  cp "$REPO"/portal/portal_app.py "$REPO"/portal/*.html "$LAB"/portal/
  cp "$REPO"/demo/* "$LAB"/ 2>/dev/null || true
  cp "$REPO"/INSTRUCTOR_README.md "$LAB"/ 2>/dev/null || true
}
restart_portal(){ systemctl restart siem-portal; echo "   siem-portal 재시작"; }

do_bank(){ say "미션뱅크(문제·채점) 재생성";
  python3 "$LAB"/scripts/mission_bank_gen.py | tail -1
  cp "$LAB"/answers/grading_spec.json "$LAB"/portal/grading_spec.json; }
do_dash(){ say "대시보드 인덱스패턴·저장검색 재설정";
  python3 "$LAB"/scripts/config_dashboard.py | tail -3; }
do_data(){ say "데이터셋 클린 재적재 (약 3~4분, 학생 진행은 유지)";
  bash "$LAB"/scripts/90_finalize_dataset.sh | tail -6; }   # 내부에서 미션뱅크도 갱신
do_rules(){ say "Wazuh 커스텀 룰 재적용";
  cp "$REPO"/scripts/local_rules.xml /var/ossec/etc/rules/local_rules.xml
  chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true
  systemctl restart wazuh-manager; sleep 20; }

sync_files
case "$MODE" in
  portal) restart_portal ;;
  bank)   do_bank; restart_portal ;;
  dash)   do_dash; restart_portal ;;
  data)   do_data; do_dash; restart_portal ;;              # finalize regenerates bank
  rules)  do_rules; do_data; do_dash; restart_portal ;;
  all)    do_data; do_dash; restart_portal ;;
  *) echo "usage: sudo bash update.sh <portal|bank|dash|data|rules|all>"; exit 1 ;;
esac
echo; echo "UPDATE_DONE ($MODE)  ·  포털: http://<IP>:8081/"
