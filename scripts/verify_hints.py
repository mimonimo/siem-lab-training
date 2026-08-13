#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Cross-verify: does every question's Wazuh query hint actually return results?
import json, ssl, base64, re, urllib.request, urllib.error

pw = re.findall(r"Password:\s*(\S+)", open("/opt/siem-lab/logs/wazuh-install.log").read())[-1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()

def es(index, q):
    body = {"query": {"query_string": {"query": q, "analyze_wildcard": True}}}
    req = urllib.request.Request(f"https://127.0.0.1:9200/{index}/_count", method="POST",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": AUTH})
    try:
        return json.load(urllib.request.urlopen(req, context=ctx, timeout=20)).get("count", 0)
    except urllib.error.HTTPError as e:
        return f"ERR{e.code}"

spec = json.load(open("/opt/siem-lab/answers/grading_spec.json", encoding="utf-8"))
print(f"{'Q':>3} {'A':>5} {'R':>6}  query")
flagged = []
for q in spec["questions"]:
    wz = q["explain"]["wazuh"]
    # only test queries that look like KQL field:value (skip prose/host-cmd hints)
    testable = bool(re.search(r'\w+:', wz)) and "ausearch" not in wz and "strings" not in wz
    if not testable:
        print(f"{q['qno']:>3} {'--':>5} {'--':>6}  (비쿼리/호스트: {wz[:60]})")
        continue
    a = es("wazuh-alerts-*", wz); r = es("wazuh-archives-*", wz)
    mark = "" if (isinstance(a,int) and a>0) or (isinstance(r,int) and r>0) else "  <== 0 HITS"
    if mark: flagged.append(q['qno'])
    print(f"{q['qno']:>3} {str(a):>5} {str(r):>6}  {wz[:70]}{mark}")
print("\nFLAGGED (0 hits):", flagged or "none")
