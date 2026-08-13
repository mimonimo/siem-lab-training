#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Dashboard setup (idempotent): index patterns (+field cache refresh so Discover
# renders), a COMBINED pattern (alerts+archives) for one-shot analysis, per-log
# saved searches, and default columns/time range. Run as root on the VM.
#
# NOTE: OpenSearch Dashboards can't trim the Discover "Available fields" list per
# pattern (sourceFilters only affect doc _source, and pruning the cached field
# list breaks the Wazuh app). So we keep full fields and rely on curated COLUMNS
# + saved searches for a clean analyst view.
import json, ssl, base64, re, urllib.request, urllib.error, urllib.parse

pw = re.findall(r"Password:\s*(\S+)", open("/opt/siem-lab/logs/wazuh-install.log").read())[-1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()
DB = "https://127.0.0.1:443"
def api(method, path, body=None):
    req = urllib.request.Request(DB + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"osd-xsrf":"true","Content-Type":"application/json","Authorization":AUTH})
    try: return json.load(urllib.request.urlopen(req, context=ctx, timeout=45))
    except urllib.error.HTTPError as e: return {"__err":e.code,"body":e.read().decode()[:160]}
def fields_for(title):
    ff = api("GET", "/api/index_patterns/_fields_for_wildcard?pattern="
                    + urllib.parse.quote(title, safe="")
                    + "&meta_fields=_source&meta_fields=_id&meta_fields=_index&meta_fields=_score")
    return ff.get("fields")

# 1) index patterns WITH refreshed field cache (empty cache => Discover shows nothing)
PATTERNS = [("wazuh-alerts-star", "wazuh-alerts-*"),
            ("wazuh-archives-star", "wazuh-archives-*"),
            ("wazuh-all", "wazuh-alerts-*,wazuh-archives-*")]   # combined = 모든 로그 한 번에
for pid, title in PATTERNS:
    f = fields_for(title) or []
    r = api("POST", f"/api/saved_objects/index-pattern/{pid}?overwrite=true",
            {"attributes": {"title": title, "timeFieldName": "timestamp",
                            "fields": json.dumps(f)}})
    print(f"index-pattern {title}: {len(f)} fields", "OK" if "__err" not in r else r)

# 2) tidy per-log-type saved searches (curated columns)
def src(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})
SEARCHES = [
 ("siemlab-alerts", "🚨 탐지 알림", "wazuh-alerts-star",
  ["rule.level","rule.description","data.srcip","data.srcuser","location","full_log"], ""),
 ("siemlab-all", "🧩 전체 로그 (정상+이상)", "wazuh-archives-star",
  ["location","data.srcip","full_log"], ""),
 ("siemlab-web", "🌐 웹 접근 로그", "wazuh-archives-star",
  ["data.srcip","data.id","url","full_log"], 'location:"/var/log/apache2/access.log"'),
 ("siemlab-auth", "🔐 인증 로그", "wazuh-archives-star",
  ["data.srcip","data.dstuser","full_log"], 'location:"/var/log/auth.log"'),
 ("siemlab-fw", "🧱 방화벽 로그", "wazuh-archives-star",
  ["full_log"], 'location:"/var/log/ufw.log"'),
]
for sid, title, ipid, cols, query in SEARCHES:
    r = api("POST", f"/api/saved_objects/search/{sid}?overwrite=true",
            {"attributes": {"title": title, "description": "SIEM Lab 뷰", "hits": 0,
                            "columns": cols, "sort": [["timestamp", "desc"]], "version": 1,
                            "kibanaSavedObjectMeta": {"searchSourceJSON": src(query)}},
             "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                             "type": "index-pattern", "id": ipid}]})
    print(f"  saved search {title}:", "ok" if "__err" not in r else r)

# 3) advanced settings: clean default columns + wide time + all-logs default
api("POST", "/api/opensearch-dashboards/settings",
    {"changes": {"defaultColumns": ["location", "data.srcip", "full_log"],
                 "timepicker:timeDefaults": "{\"from\":\"now-1y\",\"to\":\"now\"}",
                 "defaultIndex": "wazuh-archives-star"}})
print("settings: defaultColumns / timeDefaults(now-1y) / defaultIndex(archives) set")
print("CONFIG_DASHBOARD_DONE")
