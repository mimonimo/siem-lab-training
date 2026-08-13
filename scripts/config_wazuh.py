#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Configure the Wazuh manager for the lab:
#   * monitor the lab log files (dedup existing blocks; read whole file on start)
#   * enable full-event archives (logall_json) so students can search ALL logs
#   * enable filebeat archives module so archives reach the wazuh-archives-* index
import re, shutil, sys, os

OSSEC = "/var/ossec/etc/ossec.conf"
FB    = "/etc/filebeat/filebeat.yml"

TARGETS = [   # (location, log_format)
    ("/var/log/apache2/access.log", "apache"),
    ("/var/log/apache2/error.log",  "apache"),
    ("/var/log/auth.log",           "syslog"),
    ("/var/log/cron.log",           "syslog"),
    ("/var/log/audit/audit.log",    "audit"),
    ("/var/log/syslog",             "syslog"),
]
LOCS = {loc for loc, _ in TARGETS}

def localfile_block(loc, fmt):
    # only-future-events=yes: on a cloned VM (new inode) Wazuh reads from EOF,
    # so the pre-loaded historical alerts (already in the cloned index) are not
    # re-ingested. Historical load is done once at build time via append-ingest.
    return ("  <localfile>\n"
            f"    <log_format>{fmt}</log_format>\n"
            f"    <location>{loc}</location>\n"
            "    <only-future-events>yes</only-future-events>\n"
            "  </localfile>")

# ---- ossec.conf ------------------------------------------------------------ #
shutil.copy(OSSEC, OSSEC + ".labbak")
s = open(OSSEC, encoding="utf-8").read()

# drop any existing <localfile> blocks that point at our target files (no dups)
def strip(m):
    b = m.group(0)
    return "" if any(f"<location>{loc}</location>" in b for loc in LOCS) else b
s = re.sub(r"[ \t]*<localfile>.*?</localfile>\s*", strip, s, flags=re.DOTALL)

# append one controlled ossec_config block with our localfiles
lf = "\n".join(localfile_block(loc, fmt) for loc, fmt in TARGETS)
s = s.rstrip() + "\n\n<ossec_config>\n" + lf + "\n</ossec_config>\n"

# enable archives (all events, matched or not).
# The stock ossec.conf ALREADY ships <logall_json>no</logall_json>, so flip it
# rather than assuming it is absent.
if "<logall_json>" in s:
    s = re.sub(r"<logall_json>\s*no\s*</logall_json>",
               "<logall_json>yes</logall_json>", s)
else:
    s = s.replace("<global>", "<global>\n    <logall_json>yes</logall_json>", 1)

# disable vulnerability detection (closed lab: no CVE feed downloads needed)
s2 = re.sub(r"(<vulnerability-detection>\s*<enabled>)yes(</enabled>)",
            r"\1no\2", s)
if s2 != s:
    print("ossec.conf: vulnerability-detection disabled")
    s = s2

open(OSSEC, "w", encoding="utf-8").write(s)
print("ossec.conf: localfiles set for", len(TARGETS), "files; logall_json enabled")

# ---- filebeat.yml: enable the archives module ------------------------------ #
if os.path.exists(FB):
    shutil.copy(FB, FB + ".labbak")
    fb = open(FB, encoding="utf-8").read()
    fb2 = re.sub(r"(archives:\s*\n\s*enabled:\s*)false", r"\1true", fb)
    if fb2 != fb:
        open(FB, "w", encoding="utf-8").write(fb2)
        print("filebeat.yml: archives module enabled")
    else:
        if "archives:" in fb:
            print("filebeat.yml: archives already enabled (or pattern differs) - check manually")
        else:
            print("filebeat.yml: no archives stanza found - will rely on module defaults")
else:
    print("filebeat.yml not found")
print("CONFIG_WAZUH_DONE")
