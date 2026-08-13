#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# "Actually solve" each auto-graded question: run its Wazuh query and confirm
# the expected answer token appears in the returned logs.
import json, ssl, base64, re, urllib.request, urllib.error

pw = re.findall(r"Password:\s*(\S+)", open("/opt/siem-lab/logs/wazuh-install.log").read())[-1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()

def search(q, size=5):
    body = {"size": size, "query": {"query_string": {"query": q, "analyze_wildcard": True}},
            "_source": ["full_log", "data.srcip", "data.id", "url", "location"]}
    for idx in ("wazuh-archives-*", "wazuh-alerts-*"):
        req = urllib.request.Request(f"https://127.0.0.1:9200/{idx}/_search", method="POST",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": AUTH})
        try:
            h = json.load(urllib.request.urlopen(req, context=ctx, timeout=20))["hits"]["hits"]
            if h: return [x["_source"].get("full_log", "") for x in h]
        except Exception:
            pass
    return []

spec = json.load(open("/opt/siem-lab/answers/grading_spec.json", encoding="utf-8"))
ok = miss = 0
for q in spec["questions"]:
    g = q["grade"]
    if g["mode"] == "manual": continue
    acc = g.get("accept", [])
    wz = q["explain"]["wazuh"]
    logs = " || ".join(search(wz))
    found = [a for a in acc if a.lower() in logs.lower()]
    status = "OK  " if found else "MISS"
    if found: ok += 1
    else: miss += 1
    ev = (logs.split("||")[0][:78]) if logs else "(no result)"
    print(f"Q{q['qno']:>2} [{status}] ans⊂로그:{bool(found)}  q={wz[:38]:<38} → {ev}")
print(f"\n실제 풀이 검증: {ok} OK / {miss} MISS  (MISS는 정답이 쿼리결과 텍스트에 직접 안 보이는 경우 — 파생답/데모 등)")
