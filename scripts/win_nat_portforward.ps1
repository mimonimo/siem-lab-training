# ============================================================================
# (Windows host) VMware NAT 포트포워딩 설정 — Bridged가 안 되는 환경(예: Wi-Fi)에서
# NAT VM의 서비스를 호스트 LAN IP로 외부 공개할 때 사용.
# 반드시 "관리자 권한 PowerShell"에서 실행:
#   powershell -ExecutionPolicy Bypass -File win_nat_portforward.ps1
# 학생은 이후 http://<호스트LAN IP>:8081/ 로 접속. (Wazuh https://<호스트LAN IP>/)
#
# 설계 포인트: 포털 링크는 location.hostname + 기본포트를 따르므로 포트를 1:1로
# (8081->8081, 443->443, 8080->8080) 매핑해야 Bridged와 동작이 동일해집니다.
# ============================================================================
$ErrorActionPreference = 'Stop'
$VMIP = '192.168.208.134'          # NAT VM 주소 (VM에서 `hostname -I` 로 확인)
$conf = 'C:\ProgramData\VMware\vmnetnat.conf'

Copy-Item $conf "$conf.siembak" -Force
$maps = @("8081 = $VMIP`:8081", "443 = $VMIP`:443", "8080 = $VMIP`:8080")
$lines = Get-Content $conf | Where-Object { $_ -notmatch '^\s*(8081|443|8080)\s*=' }
$out = New-Object System.Collections.Generic.List[string]
foreach ($l in $lines) { $out.Add($l); if ($l -match '^\[incomingtcp\]') { $maps | ForEach-Object { $out.Add($_) } } }
Set-Content -Path $conf -Value $out -Encoding ASCII

Restart-Service 'VMware NAT Service' -Force
foreach ($p in 8081, 443, 8080) {
    cmd /c "netsh advfirewall firewall delete rule name=SIEM-Lab-$p" | Out-Null
    cmd /c "netsh advfirewall firewall add rule name=SIEM-Lab-$p dir=in action=allow protocol=TCP localport=$p" | Out-Null
}
Write-Host "완료. 학생 접속: http://<이 PC의 LAN IP>:8081/  (Wazuh https://<LAN IP>/, 데모 :8080)"
Write-Host "현재 포워딩:"; Get-Content $conf | Select-String '208\.|:8081|:8080'
