#!/bin/bash
# ============================================================================
# 배포 전 정리 (골든 이미지 → 20대 복제 직전에 강사가 직접 실행)
# 기본은 DRY-RUN. 실제 수행하려면:  sudo bash 95_predeploy_cleanup.sh --confirm
#
# 하는 일:
#   0) 최종 클린 재빌드(90_finalize)로 로그/인덱스에서 빌드 노이즈 제거
#   1) 강사 자료(생성기·정답키·매니페스트) 백업 tarball 생성  → 호스트로 옮길 것
#   2) 이미지에서 정답 노출 자료 제거(생성기·정답키·매니페스트)
#   3) 셸 히스토리 삭제 (가장 흔한 사고)
#   4) Claude Code / node / npm / API 키(~/.claude) 제거(있으면)
#   5) 취약점 탐지 모듈 off 확인 + OpenSearch JVM 힙 1.5G 고정(저사양 클론 대비)
#   6) apt clean, 빌드 로그·임시파일 정리
# 남기는 것: 데모 앱(/opt/siem-lab/demo), 학생 문제지(/opt/siem-lab/student), Wazuh 데이터
# ============================================================================
set -uo pipefail
MODE="${1:-}"
SC=/opt/siem-lab/scripts
STAMP=$(date +%Y%m%d-%H%M)
BACKUP=/root/siem-lab-instructor-${STAMP}.tar.gz

run(){ if [ "$MODE" = "--confirm" ]; then eval "$@"; else echo "   [dry-run] $*"; fi; }

echo "=============================================================="
if [ "$MODE" != "--confirm" ]; then
  echo " DRY-RUN 모드입니다. 실제 실행: sudo bash $0 --confirm"
else
  echo " --confirm: 실제 정리를 수행합니다."
fi
echo "=============================================================="

echo "[0] 최종 클린 재빌드 (로그/인덱스 노이즈 제거)"
run "bash $SC/90_finalize_dataset.sh >/var/log/siem-finalize.log 2>&1 && tail -1 /var/log/siem-finalize.log"

echo "[1] 강사 자료 백업 -> $BACKUP  (★ 이 파일을 호스트로 복사 후 이미지에서 삭제하세요)"
run "tar czf $BACKUP -C /opt/siem-lab scripts answers student 2>/dev/null; chmod 600 $BACKUP; ls -la $BACKUP"

echo "[2] 이미지에서 정답 노출 자료 제거 (생성기/정답키/매니페스트)"
run "rm -rf /opt/siem-lab/answers /opt/siem-lab/scripts"
echo "    (학생 문제지 /opt/siem-lab/student/mission_sheet.md 는 유지 — 별도 배포 권장)"

echo "[3] 셸 히스토리 삭제"
run "for h in /root/.bash_history /home/siem/.bash_history; do : > \$h 2>/dev/null || true; done"
run "history -c 2>/dev/null || true"
run "find /root /home -maxdepth 2 -name '.*_history' -exec truncate -s 0 {} \; 2>/dev/null || true"

echo "[4] Claude Code / node / npm / API 키 제거 (있으면)"
run "rm -rf /root/.claude /home/siem/.claude /root/.config/claude* /home/siem/.config/claude* 2>/dev/null || true"
run "command -v claude >/dev/null && (npm -g uninstall @anthropic-ai/claude-code 2>/dev/null || true) || echo '    claude 미설치'"

echo "[5] 취약점 탐지 off 확인 + OpenSearch JVM 힙 1.5G 고정"
run "grep -A1 '<vulnerability-detection>' /var/ossec/etc/ossec.conf | grep -o '<enabled>[a-z]*</enabled>' | head -1"
run "sed -i -E 's/^-Xms.*/-Xms1536m/; s/^-Xmx.*/-Xmx1536m/' /etc/wazuh-indexer/jvm.options && grep -E '^-Xm' /etc/wazuh-indexer/jvm.options"
run "systemctl restart wazuh-indexer && sleep 20 && echo indexer=\$(systemctl is-active wazuh-indexer)"

echo "[6] apt clean + 빌드 로그/임시파일 정리"
run "apt-get clean"
run "rm -f /tmp/*.sh /tmp/*.py /tmp/manifest.json 2>/dev/null; rm -rf /tmp/ds /tmp/replay 2>/dev/null || true"
run "rm -f /opt/siem-lab/wazuh-install.sh /opt/siem-lab/wazuh-install-files.tar 2>/dev/null || true"
run ": > /opt/siem-lab/logs/wazuh-install.log 2>/dev/null || true"
run ": > /var/log/siem-finalize.log 2>/dev/null || true"

echo "[7] 히스토리 재삭제(정리 명령 흔적 제거)"
run "for h in /root/.bash_history /home/siem/.bash_history; do : > \$h 2>/dev/null || true; done; history -c 2>/dev/null || true"

echo "=============================================================="
echo " 완료. 다음 순서로 배포하세요:"
echo "  1) $BACKUP 를 호스트로 복사 → 확인 후 이미지에서 rm (root 전용이지만 남기지 말 것)"
echo "  2) sudo poweroff 로 완전 종료"
echo "  3) VM 폴더 복사(또는 OVF export)로 20대 배포"
echo "  4) 학생 첫 실행 시 반드시 'I Copied It(복사했습니다)' 선택 (MAC/UUID 갱신)"
echo "  5) 학생용 mission_sheet.md 만 공유폴더 배포 (정답키는 절대 제외)"
echo "=============================================================="
echo "CLEANUP_$([ "$MODE" = "--confirm" ] && echo DONE || echo DRYRUN)"
