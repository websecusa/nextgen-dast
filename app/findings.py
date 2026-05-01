# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Per-tool finding parsers. Each parser reads the artifacts that the named tool
produced under /data/scans/<scan_id>/ and yields normalized finding dicts:

  {
    "source_tool": str,
    "severity": "critical|high|medium|low|info",
    "title": str,
    "description": str,
    "owasp_category": Optional[str],
    "cwe": Optional[str],
    "cvss": Optional[str],
    "evidence_url": Optional[str],
    "evidence_method": Optional[str],
    "remediation": Optional[str],
    "raw_data": dict (will be JSON-serialised),
  }

These are intentionally tool-shaped — the LLM consolidation phase will dedupe,
normalize OWASP categories, and assign CVSS where missing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


# Crude CWE → OWASP-2021 mapping for the most common cases. Extend as needed.
OWASP_BY_CWE = {
    "22":  "A01:2021-Broken_Access_Control",
    "284": "A01:2021-Broken_Access_Control",
    "287": "A07:2021-Identification_and_Authentication_Failures",
    "295": "A02:2021-Cryptographic_Failures",
    "311": "A02:2021-Cryptographic_Failures",
    "326": "A02:2021-Cryptographic_Failures",
    "327": "A02:2021-Cryptographic_Failures",
    "352": "A01:2021-Broken_Access_Control",
    "522": "A04:2021-Insecure_Design",
    "611": "A05:2021-Security_Misconfiguration",
    "693": "A05:2021-Security_Misconfiguration",
    "732": "A01:2021-Broken_Access_Control",
    "79":  "A03:2021-Injection",
    "89":  "A03:2021-Injection",
    "94":  "A03:2021-Injection",
    "918": "A10:2021-SSRF",
    "200": "A04:2021-Insecure_Design",
    "601": "A01:2021-Broken_Access_Control",
}

NUCLEI_OWASP_BY_TAG = {
    "exposure": "A05:2021-Security_Misconfiguration",
    "misconfig": "A05:2021-Security_Misconfiguration",
    "default-login": "A07:2021-Identification_and_Authentication_Failures",
    "ssrf": "A10:2021-SSRF",
    "lfi": "A03:2021-Injection",
    "rce": "A03:2021-Injection",
    "sqli": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "xxe": "A05:2021-Security_Misconfiguration",
    "redirect": "A01:2021-Broken_Access_Control",
    "fileupload": "A03:2021-Injection",
    "tech": None,  # info-only
    "cve": None,   # depends, will be set by description
}


# ---- nuclei -----------------------------------------------------------------

def parse_nuclei(scan_dir: Path) -> Iterable[dict]:
    p = scan_dir / "report.jsonl"
    if not p.exists():
        return
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        info = r.get("info", {}) or {}
        sev = (info.get("severity") or "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        owasp = None
        for t in tags:
            if t.lower() in NUCLEI_OWASP_BY_TAG:
                owasp = NUCLEI_OWASP_BY_TAG[t.lower()]
                if owasp:
                    break
        cve = None
        for ref in info.get("classification", {}).get("cve-id", []) or []:
            cve = ref
            break
        cwe = (info.get("classification", {}).get("cwe-id") or [None])
        cwe_id = None
        if cwe and cwe[0]:
            m = re.search(r"\d+", cwe[0])
            if m:
                cwe_id = m.group(0)
        if cwe_id and not owasp:
            owasp = OWASP_BY_CWE.get(cwe_id)
        # Pull the actual HTTP method out of the captured request line.
        # Nuclei's `type` field is the protocol family (http / dns / tcp /
        # ...), NOT the HTTP method — using it as evidence_method made
        # every nuclei finding land with method="HTTP" and tripped the
        # GET/HEAD-only gate on the inline Test button. The first token
        # of the request blob is the real method.
        method = "GET"
        request_blob = r.get("request") or ""
        if request_blob:
            first = request_blob.split(None, 1)[0].upper() if request_blob.split() else ""
            if first in ("GET", "HEAD", "POST", "PUT", "DELETE",
                         "PATCH", "OPTIONS"):
                method = first
        yield {
            "source_tool": "nuclei",
            "severity": sev,
            "title": info.get("name") or r.get("template-id", "nuclei finding"),
            "description": info.get("description") or "",
            "owasp_category": owasp,
            "cwe": cwe_id,
            "cvss": (info.get("classification", {}) or {}).get("cvss-score"),
            "evidence_url": r.get("matched-at") or r.get("host"),
            "evidence_method": method,
            "remediation": info.get("remediation") or "",
            "raw_data": r,
        }


# ---- nikto ------------------------------------------------------------------

NIKTO_LINE = re.compile(r"^\+\s*(?:\[(\d+)\]\s*)?(.+)$")
# Most Nikto findings begin with the affected URL path:
#   "/vendor/composer/installed.json: PHP Composer config file reveals ..."
#   "/login.php: Admin login page/section found."
#   "/: Server is using a wildcard certificate: ..."
# Capture the path as a relative URL so the orchestrator can resolve it
# against the scan target. Without this, every Nikto finding inherited
# the bare-host fallback and the reproduction curl tested the wrong URL.
NIKTO_PATH_PREFIX = re.compile(r"^(\/\S*?):\s+(.+)$")
# Lines Nikto echoes as part of its scan-config header (before the actual
# scan starts) or as bookkeeping at the end. None of these are findings —
# they're Nikto reporting how IT was configured, not anything about the
# target. Each entry is a startswith() prefix; matched lines are dropped.
#
# The "Proxy:" / "SSL Info:" / "Cookie(s):" lines specifically were
# leaking through pre-fix — when the orchestrator runs Nikto via mitmproxy
# they show "Proxy: 127.0.0.1:<port>" which an analyst could easily
# misread as an internal-IP disclosure on the target. They're scan
# bookkeeping; suppress them at ingest.
NIKTO_NOISE = (
    # Connection / target metadata Nikto echoes before scanning starts
    "Server:", "Target IP", "Target Hostname", "Target Port",
    "Proxy:", "SSL Info:", "Cookie:", "Cookies:",
    "Allowed HTTP Methods", "Cipher:", "Site Link",
    # Run-state lines Nikto emits at the bottom of the report
    "Start Time", "End Time", "Scan terminated", "0 errors and",
    "host(s) tested", "Platform:",
)
# Word-boundaried — naive substring matching falsely tagged "force" as RCE,
# "version" matched "adversion", etc. Each hint compiled with \b on either
# side; multi-word hints become space-separated literal phrases.
import re as _re

_NIKTO_SEV_PATTERNS = [
    ("critical", [
        r"\bRCE\b",
        r"\bremote code execution\b",
        r"\bcommand injection\b",
        r"\bdefault credentials\b",
        r"\bdefault password\b",
        r"\bshell upload\b",
    ]),
    ("high", [
        r"\bSQL\s*injection\b",
        r"\bdirectory traversal\b",
        r"\bpath traversal\b",
        r"\bfile disclosure\b",
        r"\bauthentication bypass\b",
        r"\banonymous\b",
        r"\boutdated\b",
        r"\bvulnerable\b",
    ]),
    ("medium", [
        r"\bXSS\b",
        r"\bcross[- ]site\b",
        r"\bopen redirect\b",
        r"\bphpinfo\b",
        r"\bdirectory listing\b",
        r"\bclickjacking\b",
    ]),
    ("low", [
        r"\bsecurity header\b",
        r"\bsuggested security\b",
        r"\bmime[- ]sniffing\b",
        r"\bx-content-type-options\b",
        r"\bstrict-transport\b",
        r"\bx-frame-options\b",
        r"\breferrer-policy\b",
        r"\bpermissions-policy\b",
        r"\bcontent-security-policy\b",
    ]),
]
_NIKTO_SEV_RES = [(sev, [_re.compile(p, _re.IGNORECASE) for p in pats])
                  for sev, pats in _NIKTO_SEV_PATTERNS]

# Status messages nikto emits that aren't findings — they tell you what nikto
# DIDN'T do, or report scan-completion stats. Drop them outright.
#
# The "<N> host(s) tested" and "<N> requests: <M> errors and <K> items
# reported" lines are end-of-scan summary text. They have a leading numeric
# count so a simple startswith() against NIKTO_NOISE misses them — match
# with regex instead.
_NIKTO_STATUS_PATTERNS = [
    _re.compile(p, _re.IGNORECASE) for p in (
        r"^no cgi directories found",
        r"cgi tests skipped",
        r"^no host header",
        r"^server banner changed",
        r"\btests skipped\b",
        r"^scan terminated",
        r"^[\d:]+ start time",
        r"^[\d:]+ end time",
        r"^\d+\s+host\(s\)\s+tested\b",
        r"^\d+\s+requests:\s*\d+\s+errors\s+and\s+\d+\s+items\s+reported\b",
    )
]


def _nikto_severity(text: str) -> str:
    for sev, pats in _NIKTO_SEV_RES:
        for pat in pats:
            if pat.search(text):
                return sev
    return "info"


def _nikto_is_status(text: str) -> bool:
    return any(p.search(text) for p in _NIKTO_STATUS_PATTERNS)


def parse_nikto(scan_dir: Path) -> Iterable[dict]:
    log = scan_dir / "output.log"
    if not log.exists():
        return
    seen: set = set()
    for line in log.read_text(errors="replace").splitlines():
        m = NIKTO_LINE.match(line.strip())
        if not m:
            continue
        text = m.group(2).strip()
        if any(text.startswith(n) for n in NIKTO_NOISE):
            continue
        if _nikto_is_status(text):
            continue
        # Suppress nikto's "Server banner changed from X to mitmproxy ..."
        # warning. We *are* the proxy that mutated the banner — flagging
        # ourselves makes the report look unprofessional and confuses the
        # customer. The real upstream banner is intentionally rewritten by
        # mitmproxy, not by the target.
        if "mitmproxy" in text.lower() and "server banner" in text.lower():
            continue
        if text in seen:
            continue
        seen.add(text)
        sev = _nikto_severity(text)
        # Pull the URL path off the front of the line if present. The
        # orchestrator joins relative paths against the scan target, so
        # the analyst's reproduction curl points at the actual file
        # Nikto flagged (e.g. /vendor/composer/installed.json) rather
        # than the bare host (which often redirects to a login page).
        pmatch = NIKTO_PATH_PREFIX.match(text)
        evidence_url = pmatch.group(1) if pmatch else None
        yield {
            "source_tool": "nikto",
            "severity": sev,
            "title": text[:200],
            "description": text,
            "evidence_url": evidence_url,
            "evidence_method": "GET" if evidence_url else None,
            "owasp_category": "A05:2021-Security_Misconfiguration"
                              if sev in ("low", "info", "medium") else None,
            "raw_data": {"line": text, "id": m.group(1)},
        }


# ---- testssl ----------------------------------------------------------------

TESTSSL_SEV = {
    "OK":       "info",
    "INFO":     "info",
    "LOW":      "low",
    "MEDIUM":   "medium",
    "HIGH":     "high",
    "CRITICAL": "critical",
    "WARN":     "low",
}


TESTSSL_SCAN_SYSTEM_IDS = {
    "engine_problem", "scanProblem", "scanTime", "service",
    "TLS_extensions", "session_ticket", "SSL_sessionID_support",
    "sessionresumption_ticket", "sessionresumption_ID", "cert_keySize",
}

# testssl uses severity=WARN for two genuinely different things:
#   1. an actual TLS posture warning (weak cipher etc.) — keep these
#   2. "I couldn't run this test on this server" — drop these, they're
#      not findings at all. Examples emitted as WARN with these finding
#      texts on the test target:
#        NPN     finding: "not possible for TLS 1.3-only hosts"
#        HSTS_*  finding: "no HSTS header on this hop" (sometimes)
#   The pattern below catches the "test doesn't apply" class. Anchored
#   to the start of the finding text so it doesn't gobble legitimate
#   prose that happens to contain these phrases.
import re as _re_testssl
TESTSSL_NOT_APPLICABLE_RE = _re_testssl.compile(
    r"^\s*("
    r"not possible for TLS 1\.3|"      # NPN, sometimes ALPN
    r"not applicable|"
    r"test not applicable|"
    r"not tested|"
    r"couldn't determine|"
    r"could not determine|"
    r"check not run|"
    r"n/a\b"
    r")",
    _re_testssl.IGNORECASE,
)


def parse_testssl(scan_dir: Path) -> Iterable[dict]:
    p = scan_dir / "report.json"
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(errors="replace"))
    except Exception:
        return
    if not isinstance(data, list):
        data = data.get("scanResult", []) if isinstance(data, dict) else []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        sev_raw = (entry.get("severity") or "INFO").upper()
        # testssl emits an INFO/OK row for every protocol fact, cipher,
        # extension, ALPN value, etc. Those are inventory, not findings.
        if sev_raw in ("OK", "INFO"):
            continue
        # FATAL/WARN inside scan-system identifiers are runner errors, not
        # TLS posture issues.
        if sev_raw in ("FATAL", "WARN") and entry.get("id") in TESTSSL_SCAN_SYSTEM_IDS:
            continue
        finding_text = (entry.get("finding") or "").strip()
        if not finding_text:
            continue
        # "Test doesn't apply on this host" outputs come back as WARN even
        # though they're not security warnings (e.g. NPN on a TLS 1.3-only
        # host). Drop these regardless of severity — they're not findings.
        if TESTSSL_NOT_APPLICABLE_RE.match(finding_text):
            continue
        sev = TESTSSL_SEV.get(sev_raw, "low")
        yield {
            "source_tool": "testssl",
            "severity": sev,
            "title": entry.get("id") or "TLS finding",
            "description": finding_text,
            "owasp_category": "A02:2021-Cryptographic_Failures",
            "cwe": (entry.get("cwe") or "").replace("CWE-", "") or None,
            "cvss": entry.get("cvss"),
            "raw_data": entry,
        }


# ---- wapiti -----------------------------------------------------------------

WAPITI_SEV_BY_LEVEL = {
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

# Wapiti tags every 500 response from an injection probe as level 3. That's
# wrong — a 500 means the injection FAILED to land (the app errored out
# rather than processing the bad input). It's a positive signal, not a
# vulnerability. The only follow-up worth doing is checking the 500 response
# body for a stack-trace leak; that's a separate info-disclosure finding.
WAPITI_SEVERITY_OVERRIDES = {
    "Internal Server Error": "info",
    "Fingerprint web technology": "info",
    "Review Webserver Metafiles for Information Leakage": "info",
}


def parse_wapiti(scan_dir: Path) -> Iterable[dict]:
    rep = scan_dir / "report"
    if not rep.is_dir():
        return
    js = next((p for p in rep.glob("*.json")), None)
    if not js:
        return
    try:
        data = json.loads(js.read_text(errors="replace"))
    except Exception:
        return
    for category, items in (data.get("vulnerabilities") or {}).items():
        for it in items or []:
            level = it.get("level", 1)
            sev = WAPITI_SEV_BY_LEVEL.get(level, "low")
            sev = WAPITI_SEVERITY_OVERRIDES.get(category, sev)
            yield {
                "source_tool": "wapiti",
                "severity": sev,
                "title": category,
                "description": it.get("info") or "",
                "evidence_url": it.get("path"),
                "evidence_method": it.get("method"),
                "remediation": (data.get("classifications") or {})
                               .get(category, {}).get("solution"),
                "raw_data": it,
            }
    for category, items in (data.get("anomalies") or {}).items():
        for it in items or []:
            yield {
                "source_tool": "wapiti",
                "severity": "low",
                "title": f"anomaly: {category}",
                "description": it.get("info") or "",
                "evidence_url": it.get("path"),
                "raw_data": it,
            }


# ---- sqlmap -----------------------------------------------------------------

def parse_sqlmap(scan_dir: Path) -> Iterable[dict]:
    base = scan_dir / "sqlmap"
    if not base.is_dir():
        return
    log = next(base.rglob("log"), None)
    if not log:
        return
    text = log.read_text(errors="replace")
    if "is vulnerable" in text.lower() or "parameter" in text.lower() and "injectable" in text.lower():
        yield {
            "source_tool": "sqlmap",
            "severity": "critical",
            "title": "SQL injection confirmed",
            "description": text[:2000],
            "owasp_category": "A03:2021-Injection",
            "cwe": "89",
            "raw_data": {"log_path": str(log)},
        }


# ---- enhanced_testing -------------------------------------------------------
#
# Reads the verdict files written by scripts.orchestrator.run_enhanced_testing
# (one JSON per probe, under /data/scans/<id>/verdicts/). Each verdict
# whose `validated` is True becomes a finding row. validated=False or
# inconclusive verdicts are NOT findings — they're recorded in the
# scan_dir for audit but don't pollute the assessment's finding list.

# Probe name → severity. The probe's verdict can override via
# `severity_uplift`, but a sensible default per probe family keeps the
# wiring honest when the probe forgets to set one.
ENHANCED_DEFAULT_SEVERITY = {
    # info-disclosure family — usually medium
    "info_directory_listing":          "medium",
    "info_swagger_exposed":            "high",
    "info_metrics_exposed":            "medium",
    "info_verbose_error":              "medium",
    "info_key_material_exposed":       "critical",
    # auth family — high to critical
    "auth_default_admin_credentials":  "critical",
    "auth_vendor_default_credentials": "critical",
    "auth_sql_login_bypass":           "critical",
    "auth_nosql_login_bypass":         "critical",
    "auth_jwt_alg_none":               "critical",
    # path-traversal / file-disclosure
    "path_traversal_extension_bypass": "high",
    # config family
    "config_cors_wildcard":            "high",
}

# Probe name → primary OWASP category. Parallel to the per-probe
# manifest's `validates` field; we copy it here so the parser doesn't
# have to read manifests at parse time.
ENHANCED_OWASP = {
    "info_directory_listing":          "A05:2021-Security_Misconfiguration",
    "info_swagger_exposed":            "A05:2021-Security_Misconfiguration",
    "info_metrics_exposed":            "A05:2021-Security_Misconfiguration",
    "info_verbose_error":              "A05:2021-Security_Misconfiguration",
    "auth_default_admin_credentials":  "A07:2021-Identification_and_Authentication_Failures",
    "auth_vendor_default_credentials": "A07:2021-Identification_and_Authentication_Failures",
    "auth_sql_login_bypass":           "A03:2021-Injection",
    "auth_nosql_login_bypass":         "A03:2021-Injection",
    "auth_jwt_alg_none":               "A07:2021-Identification_and_Authentication_Failures",
    "info_key_material_exposed":       "A02:2021-Cryptographic_Failures",
    "path_traversal_extension_bypass": "A01:2021-Broken_Access_Control",
    "config_cors_wildcard":            "A05:2021-Security_Misconfiguration",
}


def parse_enhanced_testing(scan_dir: Path) -> Iterable[dict]:
    vdir = scan_dir / "verdicts"
    if not vdir.is_dir():
        return
    for vfile in sorted(vdir.glob("*.json")):
        try:
            v = json.loads(vfile.read_text(errors="replace"))
        except Exception:
            continue
        if v.get("validated") is not True:
            continue   # only `validated=True` becomes a finding
        probe_name = vfile.stem
        # Pull a useful evidence URL: the probe's evidence either has
        # a top-level "origin" or a "confirmed" entry with a URL/path.
        ev = v.get("evidence") or {}
        evidence_url = ev.get("origin")
        confirmed = ev.get("confirmed")
        if isinstance(confirmed, list) and confirmed:
            c0 = confirmed[0]
            if isinstance(c0, dict):
                evidence_url = (c0.get("url") or
                                (ev.get("origin", "") + (c0.get("path") or "")) or
                                evidence_url)
        elif isinstance(confirmed, dict):
            evidence_url = (confirmed.get("url") or
                            (ev.get("origin", "") + (confirmed.get("path") or "")) or
                            evidence_url)
        sev = (v.get("severity_uplift") or
               ENHANCED_DEFAULT_SEVERITY.get(probe_name, "medium"))
        yield {
            "source_tool": "enhanced_testing",
            "severity": sev,
            "title": probe_name,
            "description": (v.get("summary") or "")[:4000],
            "owasp_category": ENHANCED_OWASP.get(probe_name),
            "cwe": None,
            "cvss": None,
            "evidence_url": (evidence_url or "")[:1000],
            "evidence_method": "GET",
            "remediation": v.get("remediation") or "",
            "raw_data": v,
        }


# ---- dalfox -----------------------------------------------------------------

def parse_dalfox(scan_dir: Path) -> Iterable[dict]:
    p = scan_dir / "report.json"
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(errors="replace"))
    except Exception:
        return
    items = data if isinstance(data, list) else data.get("results", [])
    for it in items or []:
        if not isinstance(it, dict):
            continue
        # Dalfox occasionally emits empty / partial result objects (e.g.
        # when the JSONL writer flushes mid-scan, or against a target
        # with no fuzzable parameter). Drop anything that doesn't carry
        # the minimum evidence we'd need to claim XSS:
        #   * a URL with at least one path/query segment, AND
        #   * at least one signal that an actual hit occurred
        #     (payload, vulnerable parameter, proof type, message,
        #     response evidence).
        # Without those checks the parser was emitting bare-host XSS
        # findings backed by empty raw_data -- false positives that
        # the validation toolkit then mis-routed to the SQLi probe.
        url = it.get("data") or it.get("url") or ""
        url_has_path = isinstance(url, str) and url.count("/") >= 3
        has_signal = any(it.get(k) for k in
                         ("payload", "param", "type", "message", "evidence"))
        if not url_has_path or not has_signal:
            continue
        sev_raw = (it.get("severity") or "medium").lower()
        sev = sev_raw if sev_raw in ("critical", "high", "medium", "low", "info") else "medium"
        # Build a useful description from whatever Dalfox gave us so
        # the analyst doesn't see a blank Overview pane.
        desc_bits = []
        if it.get("type"):    desc_bits.append(f"Proof type: {it['type']}")
        if it.get("param"):   desc_bits.append(f"Vulnerable parameter: {it['param']}")
        if it.get("payload"): desc_bits.append(f"Payload: {it['payload']}")
        if it.get("message"): desc_bits.append(it["message"])
        yield {
            "source_tool": "dalfox",
            "severity": sev,
            "title": "Cross-site scripting (XSS)",
            "description": "\n".join(desc_bits),
            "owasp_category": "A03:2021-Injection",
            "cwe": "79",
            "evidence_url": url,
            "raw_data": it,
        }


# ---- ffuf -------------------------------------------------------------------
#
# ffuf is a content-discovery fuzzer. Each "result" in its JSON is a path
# the wordlist found on the target. We emit one finding per path; severity
# is bumped from the default `info` for paths that match well-known
# sensitive patterns (.git, .env, admin panels, backups, etc.) so the
# consolidation phase doesn't have to re-derive that signal from the URL.

# Patterns are matched against the LAST path segment (case-insensitive).
# Order matters — first match wins, so put the most-severe categories
# first. Each entry: (compiled regex, severity, title, owasp, cwe).
_FFUF_SENSITIVE = [
    # Source-control / dotfile leakage — direct exposure of the
    # repository or app secrets is critical.
    (re.compile(r"^\.(git|svn|hg|bzr|env|htpasswd|aws|ssh|npmrc|netrc)\b", re.I),
     "critical",
     "Sensitive dotfile/source-control directory exposed",
     "A05:2021-Security_Misconfiguration", "538"),
    # Backup files and database dumps.
    (re.compile(r"\.(bak|backup|old|orig|swp|save|dump|sql|tar|zip|tgz|rar|7z)$", re.I),
     "high",
     "Backup or archive file exposed",
     "A05:2021-Security_Misconfiguration", "530"),
    # Admin / management consoles.
    (re.compile(r"(^|/)(admin|administrator|adminer|phpmyadmin|wp-admin|"
                r"manager|console|dashboard|server-status|server-info|"
                r"jenkins|grafana|kibana)(/|$)", re.I),
     "high",
     "Administrative interface exposed",
     "A05:2021-Security_Misconfiguration", "284"),
    # Configuration files served as static content.
    (re.compile(r"(^|/)(config|conf|settings|web\.config|app\.config|"
                r"\.htaccess|robots\.txt|sitemap\.xml)(/|$)", re.I),
     "medium",
     "Configuration or metadata file exposed",
     "A05:2021-Security_Misconfiguration", "200"),
]


# When ffuf returns 401 or 403 on a sensitive path the path *exists* but
# is access-controlled — that's much less severe than a 200 OK on the same
# path, and titling it "...exposed" / HIGH overstates the finding. We keep
# the discovery as an informational signal (so the analyst still knows the
# attack surface is there) but rewrite title + severity to match reality.
# The new title for each category lives next to the original so the
# downgrade is easy to read and audit.
_FFUF_GATED_TITLE = {
    "Sensitive dotfile/source-control directory exposed":
        "Sensitive dotfile/source-control path discovered (access-protected)",
    "Backup or archive file exposed":
        "Backup or archive file path discovered (access-protected)",
    "Administrative interface exposed":
        "Administrative path discovered (access-protected)",
    "Configuration or metadata file exposed":
        "Configuration or metadata path discovered (access-protected)",
}


def _ffuf_classify(url: str, status: int | None = None) -> tuple[str, str, str, str]:
    """Classify a discovered path. Returns (severity, title, owasp, cwe).

    Falls back to a generic info-level finding for paths that don't match
    any sensitive-pattern category.

    When `status` is 401 or 403, the path is access-controlled rather than
    exposed — we keep the OWASP/CWE classification (it's still useful
    surface-area context) but downgrade the severity to LOW and rewrite
    the title so it doesn't claim the resource is "exposed" when the
    server actually returned a deny."""
    # Match against the URL's path component. Strip query/fragment so a
    # benign /search?q=admin doesn't trip the admin classifier.
    try:
        path = url.split("?", 1)[0].split("#", 1)[0]
    except Exception:
        path = url
    for pattern, sev, title, owasp, cwe in _FFUF_SENSITIVE:
        if pattern.search(path):
            if status in (401, 403):
                # Path exists but is gated — downgrade to LOW and use the
                # discovery-flavored title for this category.
                return ("low",
                        _FFUF_GATED_TITLE.get(title, title),
                        owasp, cwe)
            return sev, title, owasp, cwe
    return ("info",
            "Discovered path (content discovery)",
            "A05:2021-Security_Misconfiguration",
            "200")


def parse_ffuf(scan_dir: Path) -> Iterable[dict]:
    p = scan_dir / "report.json"
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(errors="replace"))
    except Exception:
        return

    # ffuf classifies each hit two ways: (a) sensitive-path matches like
    # /admin, /.git/, /backup → keep as discrete findings (real signal),
    # (b) generic 200/301/302 hits with no sensitive pattern → these are
    # just sitemap entries that inflate the finding count without telling
    # the analyst anything new. We aggregate (b) into one info-severity
    # "Sitemap discovered" row whose description lists every path; (a)
    # still yields one row per hit so the analyst can triage them.
    GENERIC_TITLE = "Discovered path (content discovery)"
    sitemap_paths: list[str] = []
    sitemap_raw: list[dict] = []
    primary_url: str = ""

    # ffuf JSON shape: {"results": [{"url": "...", "status": 301, ...}, ...]}
    for it in data.get("results", []) or []:
        url = it.get("url") or ""
        if not url:
            continue
        status = it.get("status")
        sev, title, owasp, cwe = _ffuf_classify(url, status)
        if title == GENERIC_TITLE:
            # Generic hit — fold into the sitemap aggregate.
            if not primary_url:
                primary_url = url
            status_note = f" ({status})" if status else ""
            sitemap_paths.append(f"{url}{status_note}")
            sitemap_raw.append(it)
            continue
        # Sensitive-pattern hit — emit as its own finding.
        status_note = f" (HTTP {status})" if status else ""
        yield {
            "source_tool": "ffuf",
            "severity": sev,
            "title": title,
            "description": f"{url}{status_note}",
            "owasp_category": owasp,
            "cwe": cwe,
            "evidence_url": url,
            "raw_data": it,
        }

    if sitemap_paths:
        # One info row covers all generic hits. Caps the description so a
        # 5,000-path discovery doesn't blow the DB column.
        joined = "\n".join(sitemap_paths[:200])
        more = (f"\n... and {len(sitemap_paths) - 200} more"
                if len(sitemap_paths) > 200 else "")
        yield {
            "source_tool": "ffuf",
            "severity": "info",
            "title": (f"Sitemap: {len(sitemap_paths)} path(s) discovered "
                      f"via content discovery"),
            "description": ("Paths reachable on the target. These are not "
                            "vulnerabilities themselves but help map "
                            "attack surface.\n\n" + joined + more),
            "owasp_category": "A05:2021-Security_Misconfiguration",
            "cwe": "200",
            "evidence_url": primary_url,
            "raw_data": {"count": len(sitemap_paths), "results": sitemap_raw},
        }


# ---- dispatcher -------------------------------------------------------------

# ---- sca --------------------------------------------------------------------
#
# The SCA stage (scripts/sca_runner.py) writes <scan_dir>/sca/findings.json
# as a list of already-normalized finding dicts. Each entry conforms to
# the same shape every other parser emits, so this parser is mostly a
# JSON load + per-row sanity clamp (severity ∈ allowed enum, raw_data
# round-trippable).

def parse_sca(scan_dir: Path) -> Iterable[dict]:
    p = scan_dir / "sca" / "findings.json"
    if not p.exists():
        return
    try:
        rows = json.loads(p.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(rows, list):
        return
    for r in rows:
        if not isinstance(r, dict):
            continue
        sev = (r.get("severity") or "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        yield {
            "source_tool": "sca",
            "severity": sev,
            "title": (r.get("title") or "")[:500],
            "description": r.get("description") or "",
            "owasp_category": r.get("owasp_category") or
                              "A06:2021-Vulnerable_and_Outdated_Components",
            "cwe": r.get("cwe"),
            "cvss": r.get("cvss"),
            "evidence_url": r.get("evidence_url"),
            "evidence_method": r.get("evidence_method") or "GET",
            "remediation": r.get("remediation") or "",
            "raw_data": r.get("raw_data") or {},
        }


PARSERS = {
    "nuclei":  parse_nuclei,
    "nikto":   parse_nikto,
    "testssl": parse_testssl,
    "wapiti":  parse_wapiti,
    "sqlmap":  parse_sqlmap,
    "dalfox":  parse_dalfox,
    "ffuf":    parse_ffuf,
    "sca":     parse_sca,
    "enhanced_testing": parse_enhanced_testing,
}


def parse_scan(tool: str, scan_dir: Path) -> Iterable[dict]:
    fn = PARSERS.get(tool)
    if fn:
        yield from fn(scan_dir)
