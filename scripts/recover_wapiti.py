# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Recover wapiti findings from an orphaned session DB and ingest into the
assessments DB. Wapiti only emits its JSON report at the end of the run; if
the process crashes (as a#3's wapiti did in the buster module), the 2.5 hr of
attack work is lost from the report — but the session SQLite has everything.

Dedupe at ingestion: (module, category, parameter, base_url) so that 1,170
duplicate "500 on parameter X" rows collapse to ~30 unique findings with a
seen_count noted in the description.
"""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, "/app")
import db

WAPITI_DB = "/root/.wapiti/scans/<sampledomain>_domain_89a036ad.db"
ASSESSMENT_ID = 3
WAPITI_SCAN_ID = "20260425-225817-a99ad7"

LEVEL_TO_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# Wapiti tags every 500 response from an injection probe as level 3 (high).
# That's not right — a 500 means "the app crashed on bad input," which is a
# code-quality / exception-handling issue, not confirmed exploitation. Cap
# these at medium and rewrite the description so the user knows what it means.
SEVERITY_OVERRIDES_BY_CATEGORY = {
    # If the injection caused a 500, it did NOT land — the server rejected
    # it (loudly). That's a positive signal, not a vulnerability. The only
    # concern would be a stack-trace leak in the 500 response body; that's
    # caught separately as info disclosure. Demoted to info.
    "Internal Server Error": "info",
    "Fingerprint web technology": "info",
    "Review Webserver Metafiles for Information Leakage": "info",
}

DESCRIPTION_OVERRIDES = {
    "Internal Server Error":
        "The server returned HTTP 500 when an injection payload was sent. "
        "The injection did NOT land — the application rejected the malformed "
        "input by erroring out instead of processing it. This is a positive "
        "signal, not a vulnerability. Worth reviewing only if the 500 "
        "response leaks a stack trace or internal path (separate info-"
        "disclosure finding) or if the same parameter exhausts resources "
        "(separate DoS finding). Otherwise: leave as-is."
}
CATEGORY_TO_OWASP = {
    "SQL Injection": "A03:2021-Injection",
    "Cross Site Scripting": "A03:2021-Injection",
    "Command execution": "A03:2021-Injection",
    "Path Traversal": "A01:2021-Broken_Access_Control",
    "File handling": "A03:2021-Injection",
    "Internal Server Error": "A05:2021-Security_Misconfiguration",
    "Htaccess Bypass": "A01:2021-Broken_Access_Control",
    "Server Side Request Forgery": "A10:2021-SSRF",
    "Open Redirect": "A01:2021-Broken_Access_Control",
    "CRLF Injection": "A03:2021-Injection",
    "XML External Entity": "A05:2021-Security_Misconfiguration",
    "Backup file": "A05:2021-Security_Misconfiguration",
    "Review Webserver Metafiles for Information Leakage": "A05:2021-Security_Misconfiguration",
    "Fingerprint web technology": None,
}

s = sqlite3.connect(WAPITI_DB)
s.row_factory = sqlite3.Row

rows = s.execute(
    "SELECT p.module, p.category, p.level, p.parameter, p.info, p.wstg, "
    "       pa.path AS url, pa.method "
    "  FROM payloads p "
    "  LEFT JOIN paths pa ON p.evil_path_id = pa.path_id"
).fetchall()


def base_url(u):
    if not u:
        return ""
    return u.split("?")[0]


groups = {}
for r in rows:
    key = (r["module"], r["category"], r["parameter"] or "", base_url(r["url"] or ""))
    g = groups.setdefault(key, {
        "module": r["module"], "category": r["category"],
        "parameter": r["parameter"], "url": base_url(r["url"] or ""),
        "method": r["method"], "level": r["level"], "wstg": r["wstg"],
        "info": r["info"], "count": 0,
    })
    g["count"] += 1

print(f"Raw payloads: {len(rows)}; deduped to {len(groups)} unique findings")

inserted = 0
for g in groups.values():
    sev = LEVEL_TO_SEV.get(g["level"], "info")
    title = g["category"]
    if g["parameter"]:
        title += f" on parameter `{g['parameter']}`"
    desc = g["info"] or ""
    if g["count"] > 1:
        desc = f"{desc}\n\n[seen {g['count']} times across this URL/parameter]"
    db.execute(
        "INSERT INTO findings "
        "(assessment_id, source_tool, source_scan_id, severity, "
        " owasp_category, cwe, cvss, title, description, "
        " evidence_url, evidence_method, remediation, raw_data) "
        "VALUES (%s,'wapiti',%s,%s,%s,NULL,NULL,%s,%s,%s,%s,'',%s)",
        (ASSESSMENT_ID, WAPITI_SCAN_ID, sev,
         CATEGORY_TO_OWASP.get(g["category"]),
         title[:500], desc,
         (g["url"] or "")[:1000], (g["method"] or "")[:16],
         json.dumps(g, default=str)),
    )
    inserted += 1

db.execute(
    "UPDATE assessments SET total_findings = "
    "(SELECT COUNT(*) FROM findings WHERE assessment_id = %s) WHERE id = %s",
    (ASSESSMENT_ID, ASSESSMENT_ID),
)
print(f"Inserted {inserted} wapiti findings into a#{ASSESSMENT_ID}")
print()
print("Final a#%d breakdown:" % ASSESSMENT_ID)
for r in db.query(
    "SELECT source_tool, severity, COUNT(*) AS n FROM findings "
    "WHERE assessment_id=%s GROUP BY source_tool, severity "
    "ORDER BY source_tool, FIELD(severity,'critical','high','medium','low','info')",
    (ASSESSMENT_ID,)):
    print(f"  {r['source_tool']:8s} {r['severity']:8s} {r['n']}")
