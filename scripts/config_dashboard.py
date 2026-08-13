#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Declutter Wazuh Discover: hide noisy fields (sourceFilters) + create clean
# per-log-type saved searches. Run as root on the VM.
import json, ssl, base64, re, urllib.request, urllib.error

pw = re.findall(r"Password:\s*(\S+)", open("/opt/siem-lab/logs/wazuh-install.log").read())[-1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()

def api(method, path, body=None):
    req = urllib.request.Request("https://127.0.0.1:443" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"osd-xsrf": "true", "Content-Type": "application/json", "Authorization": AUTH})
    try:
        return json.load(urllib.request.urlopen(req, context=ctx, timeout=30))
    except urllib.error.HTTPError as e:
        return {"__err": e.code, "body": e.read().decode()[:160]}

# --- 1. hide noisy fields on both index patterns --------------------------- #
NOISE = ["rule.hipaa", "rule.pci_dss", "rule.nist_800_53", "rule.gdpr", "rule.tsc",
         "rule.gpg13", "rule.mail", "rule.firedtimes",
         "data.audit.arch", "data.audit.a0", "data.audit.a1", "data.audit.a2",
         "data.audit.a3", "data.audit.a4", "data.audit.egid", "data.audit.euid",
         "data.audit.fsgid", "data.audit.fsuid", "data.audit.gid", "data.audit.sgid",
         "data.audit.suid", "data.audit.ses", "data.audit.tty", "data.audit.items",
         "data.audit.exit", "data.audit.ppid", "data.audit.pid", "data.audit.subj",
         "data.audit.auid", "data.audit.success", "predecoder.timestamp", "agent.id",
         "manager.name", "decoder.parent", "input.type", "rule.info", "rule.frequency"]
sf = [{"value": f} for f in NOISE]
for ip in ("wazuh-alerts-star", "wazuh-archives-star"):
    r = api("PUT", f"/api/saved_objects/index-pattern/{ip}", {"attributes": {"sourceFilters": sf}})
    print(f"index-pattern {ip}: sourceFilters",
          "set" if "__err" not in r else r)

# --- 2. clean per-log-type saved searches ---------------------------------- #
def searchsrc(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

SEARCHES = [
 ("siemlab-alerts", "🚨 탐지 알림", "wazuh-alerts-star",
  ["rule.level","rule.description","data.srcip","data.srcuser","location","full_log"], ""),
 ("siemlab-web", "🌐 웹 접근 로그 (access.log)", "wazuh-archives-star",
  ["data.srcip","data.id","url","full_log"], 'location:"/var/log/apache2/access.log"'),
 ("siemlab-auth", "🔐 인증 로그 (auth.log)", "wazuh-archives-star",
  ["data.srcip","data.dstuser","full_log"], 'location:"/var/log/auth.log"'),
 ("siemlab-fw", "🧱 방화벽 로그 (ufw.log)", "wazuh-archives-star",
  ["full_log"], 'location:"/var/log/ufw.log"'),
 ("siemlab-rawlogs", "🔎 전체 원문 로그", "wazuh-archives-star",
  ["location","full_log"], ""),
]
for sid, title, ipid, cols, query in SEARCHES:
    body = {"attributes": {"title": title, "description": "SIEM Lab 정리된 뷰",
             "hits": 0, "columns": cols, "sort": [["timestamp", "desc"]], "version": 1,
             "kibanaSavedObjectMeta": {"searchSourceJSON": searchsrc(query)}},
            "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                            "type": "index-pattern", "id": ipid}]}
    r = api("POST", f"/api/saved_objects/search/{sid}?overwrite=true", body)
    print(f"  saved search {title}:", "ok" if "__err" not in r else r)

print("CONFIG_DASHBOARD_DONE")
