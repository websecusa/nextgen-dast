# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""PDF report generator. WeasyPrint renders report.html → PDF with running
headers/footers + page-X-of-Y. Synchronous in v1; the orchestrator-style
async sweeper pattern can wrap this later if needed."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

import branding as branding_mod
import db
import pqc as pqc_mod


# OWASP Top 10 (2021) — used for per-category grading + heat-map rows.
OWASP_TOP10 = [
    ("A01:2021-Broken_Access_Control",                "Broken Access Control"),
    ("A02:2021-Cryptographic_Failures",               "Cryptographic Failures"),
    ("A03:2021-Injection",                            "Injection"),
    ("A04:2021-Insecure_Design",                      "Insecure Design"),
    ("A05:2021-Security_Misconfiguration",            "Security Misconfiguration"),
    ("A06:2021-Vulnerable_and_Outdated_Components",   "Vulnerable & Outdated Components"),
    ("A07:2021-Identification_and_Authentication_Failures", "Identification & Authentication"),
    ("A08:2021-Software_and_Data_Integrity_Failures", "Software & Data Integrity"),
    ("A09:2021-Security_Logging_and_Monitoring_Failures",  "Logging & Monitoring"),
    ("A10:2021-SSRF",                                 "Server-Side Request Forgery"),
]
OWASP_KEYS = [k for k, _ in OWASP_TOP10]
OWASP_LABELS = dict(OWASP_TOP10)


# Severity → demerit points used by the scoring function. Higher = worse.
# Validated findings hit harder than unvalidated ones (still penalising
# unvalidated so a blizzard of scanner suspicions doesn't get a free pass).
SEV_DEMERIT_VALIDATED = {
    "critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0,
}
SEV_DEMERIT_UNVALIDATED = {
    "critical": 12, "high": 6, "medium": 2.5, "low": 1, "info": 0,
}


def _grade_for(score: int) -> str:
    """100-point scale → letter. Bias toward F because a clean
    non-trivial assessment scoring < 60 means the basics are missing."""
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _grade_color(grade: str) -> str:
    return {"A": "#2c8a4f", "B": "#7bc47f", "C": "#d4a017",
            "D": "#c0392b", "F": "#6b1f1f"}.get(grade, "#5d6770")


def _score_findings(findings: list, *, scope: Optional[str] = None) -> dict:
    """Compute a single 0–100 score from a list of findings. `scope`, when
    provided, restricts the calculation to a single OWASP category — used
    for per-category grades."""
    demerit = 0.0
    contributing = 0
    for f in findings:
        if scope and f.get("owasp_category") != scope:
            continue
        sev = f.get("severity") or "info"
        validated = (f.get("validation_status") == "validated")
        table = SEV_DEMERIT_VALIDATED if validated else SEV_DEMERIT_UNVALIDATED
        demerit += table.get(sev, 0)
        contributing += 1
    score = max(0, int(round(100 - demerit)))
    return {"score": score, "grade": _grade_for(score),
            "color": _grade_color(_grade_for(score)),
            "contributing": contributing}


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = (h or "").lstrip("#")
    if len(h) != 6:
        return (95, 179, 215)  # safe accent fallback
    try:
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    except ValueError:
        return (95, 179, 215)


def _heat_map(findings: list, pdf_brand: dict) -> list[dict]:
    """One row per OWASP category, one column per severity. Cells get a
    pre-computed background color (rgba) so the template stays simple
    and WeasyPrint never has to interpret 8-char hex.

    Always renders all ten OWASP rows so the matrix is comparable across
    assessments. Adds an 'Other' row only when uncategorised findings
    exist."""
    sev_order = ("critical", "high", "medium", "low", "info")
    sev_colors = {
        "critical": pdf_brand["sev_critical"],
        "high":     pdf_brand["sev_high"],
        "medium":   pdf_brand["sev_medium"],
        "low":      pdf_brand["sev_low"],
        "info":     pdf_brand["sev_info"],
    }
    counts: dict[tuple, int] = {}
    for f in findings:
        cat = f.get("owasp_category") or "Other"
        sev = f.get("severity") or "info"
        counts[(cat, sev)] = counts.get((cat, sev), 0) + 1
    max_cell = max(counts.values()) if counts else 1

    has_other = any((f.get("owasp_category") or "Other") == "Other"
                    for f in findings)
    cats = OWASP_KEYS + (["Other"] if has_other else [])

    rows = []
    for cat in cats:
        cells = []
        row_total = 0
        for sev in sev_order:
            n = counts.get((cat, sev), 0)
            row_total += n
            color = sev_colors[sev]
            r, g, b = _hex_to_rgb(color)
            # Floor at 0.18 opacity so even a single finding registers
            # visually; max 0.95 so text stays legible against the cell.
            opacity = 0.18 + (n / max_cell) * 0.77 if n else 0.0
            bg = (f"rgba({r}, {g}, {b}, {opacity:.2f})"
                  if n > 0 else "")
            cells.append({"sev": sev, "n": n, "bg": bg})
        rows.append({
            "category": cat,
            "label": OWASP_LABELS.get(cat, "Other / uncategorised"),
            "cells": cells,
            "total": row_total,
        })
    return rows

REPORTS_DIR = Path("/data/reports")
TEMPLATES_DIR = Path("/app/templates")

env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    extensions=["jinja2.ext.loopcontrols"],
)


def _gather(assessment_id: int) -> Optional[dict]:
    a = db.query_one("SELECT * FROM assessments WHERE id = %s",
                     (int(assessment_id),))
    if not a:
        return None

    # Reports exclude analyst-suppressed findings. They live in the
    # findings table for audit, but they don't get a card in the PDF and
    # don't count toward the cover scorecard / heat map. The query also
    # picks up `status` so we can show a "X excluded false positives"
    # line in the report's audit appendix later if needed.
    all_findings = db.query(
        "SELECT id, source_tool, severity, owasp_category, cwe, cvss, title, "
        "description, evidence_url, evidence_method, remediation, raw_data, "
        "status, "
        "COALESCE(seen_count, 1) AS seen_count, "
        "COALESCE(validation_status, 'unvalidated') AS validation_status "
        "FROM findings WHERE assessment_id = %s "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id",
        (assessment_id,))
    excluded_fp_count = sum(1 for f in all_findings
                            if f.get("status") == "false_positive")
    # The assessment's filter_info toggle (set via the on-screen
    # checkbox) suppresses info-severity rows from the report too. We
    # count the hidden rows for an optional appendix entry but never
    # render the suppressed findings themselves.
    filter_info = bool(a.get("filter_info"))
    excluded_info_count = (
        sum(1 for f in all_findings
            if f.get("status") != "false_positive"
               and f.get("severity") == "info")
        if filter_info else 0
    )
    findings = [f for f in all_findings
                if f.get("status") != "false_positive"
                   and not (filter_info and f.get("severity") == "info")]

    # Decode raw_data JSON for each finding (used for reproduction details).
    for f in findings:
        try:
            f["raw"] = json.loads(f["raw_data"]) if f.get("raw_data") else None
        except Exception:
            f["raw"] = None
        f["repro"] = _repro_for(f)

    sev_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Simple weighted risk score, 0–100 scale.
    raw = (sev_counts["critical"] * 10 + sev_counts["high"] * 5
           + sev_counts["medium"] * 2 + sev_counts["low"] * 1)
    risk_score = min(100, raw)
    if sev_counts["critical"]:
        risk_label = "Critical"
    elif sev_counts["high"]:
        risk_label = "High"
    elif sev_counts["medium"]:
        risk_label = "Medium"
    elif sev_counts["low"]:
        risk_label = "Low"
    else:
        risk_label = "Informational"

    scan_ids = [s for s in (a.get("scan_ids") or "").split(",") if s.strip()]

    # Overall + per-OWASP-category letter grades. Per-category scores let
    # the cover scorecard show "A in Crypto Failures, F in Misconfig" so a
    # CISO sees the shape of the engagement at a glance.
    overall = _score_findings(findings)
    category_scores = []
    for key, label in OWASP_TOP10:
        sc = _score_findings(findings, scope=key)
        category_scores.append({
            "key": key, "label": label,
            **sc,
        })

    pdf_brand = branding_mod.get_pdf()
    heat_map = _heat_map(findings, pdf_brand)

    # Post-quantum cryptography compliance — sourced from the testssl scan
    # included in this assessment (if any). Fully-PQC sites get a +5 bonus
    # to the overall grade.
    pqc = pqc_mod.analyze_assessment(scan_ids)
    if pqc.get("fully_pqc"):
        overall["score"] = min(100, overall["score"] + 5)
        overall["grade"] = _grade_for(overall["score"])
        overall["color"] = _grade_color(overall["grade"])
        overall["pqc_bonus_applied"] = True

    return {
        "a": a,
        "findings": findings,
        "excluded_fp_count": excluded_fp_count,
        "excluded_info_count": excluded_info_count,
        "sev_counts": sev_counts,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "overall_score": overall,
        "category_scores": category_scores,
        "heat_map": heat_map,
        "pqc": pqc,
        "scan_ids": scan_ids,
        "brand": branding_mod.get(),
        "pdf": pdf_brand,
        "now": datetime.now(timezone.utc),
        "report_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
    }


def _shell_q(s: str) -> str:
    """Single-quote a string for safe pasting into a bash one-liner. We
    wrap in single quotes and escape any embedded apostrophes by closing
    the quote, emitting an escaped quote, and reopening — the canonical
    POSIX trick. Empty input becomes ''. Used by every reproduction
    builder so that payloads containing quote characters (e.g. the
    classic SQLi marker `' OR 1=1--`) survive copy-paste verbatim."""
    if s is None:
        return "''"
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _host_port_from_url(url: str) -> tuple[str, int]:
    """Extract (host, port) from a URL, defaulting to 443 for https / 80
    for http when an explicit port isn't carried in the URL. testssl /
    openssl / nmap reproductions need an explicit port, so this is the
    one place that decision is made."""
    try:
        p = urlparse(url)
    except Exception:
        return ("", 443)
    host = p.hostname or ""
    if p.port:
        return (host, int(p.port))
    return (host, 443 if (p.scheme or "").lower() == "https" else 80)


# ---------------------------------------------------------------------------
# Per-tool reproduction builders. Each takes the finding dict (already with
# raw_data decoded into f["raw"]) and returns a dict shaped like:
#
#   {"curl": "...", "hint": "..."}     (any key optional)
#
# The job of each builder is to emit a *real working command* — something
# an analyst can copy-paste and run, that will succeed against the live
# target if the issue is still present and fail / change output once the
# fix is applied. We deliberately favor multiple short commands over one
# clever pipeline so a non-pentester can read the steps.
# ---------------------------------------------------------------------------


def _repro_enhanced_testing(f: dict, raw: dict) -> dict:
    """Reproductions for the enhanced_testing probes. These probes record
    the full evidence — payload, login_path, request_body, audit_log — so
    we can rebuild a faithful curl command without guessing.

    Probes covered: auth_default_admin_credentials, auth_sql_login_bypass,
    info_key_material_exposed, config_cors_wildcard, info_directory_listing,
    info_metrics_exposed, info_verbose_error, path_traversal_extension_bypass.
    Falls through to a generic curl when the probe shape isn't recognised."""
    probe = (raw.get("probe") or "").lower()
    ev = raw.get("evidence") or {}
    confirmed = ev.get("confirmed")
    # `confirmed` is a single dict for single-shot probes (auth checks)
    # and a list of dicts for multi-finding probes (info/cors/keys). We
    # always reduce to a single representative row for the reproduction;
    # the audit_log carries the full list if the analyst wants more.
    first = None
    if isinstance(confirmed, dict):
        first = confirmed
    elif isinstance(confirmed, list) and confirmed:
        first = confirmed[0]
    elif isinstance(ev.get("attempts"), list) and ev["attempts"]:
        first = ev["attempts"][0]
    first = first or {}
    origin = ev.get("origin") or f.get("evidence_url") or ""

    # auth_sql_login_bypass — POST the recorded SQLi payload into the
    # email field and watch for a JWT carrying role='admin'. The probe
    # records the exact payload string; we rebuild the JSON body around
    # it. See finding 834 for the canonical example.
    if probe == "auth_sql_login_bypass":
        login_path = first.get("login_path") or "/rest/user/login"
        payload = first.get("payload") or "' OR 1=1--"
        target = (first.get("url")
                  or (origin.rstrip("/") + login_path if origin else login_path))
        body = json.dumps({"email": payload, "password": "anything"})
        curl = (
            "# Step 1: send the SQL injection payload as the login email.\n"
            "curl -ski -X POST " + _shell_q(target) + " \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d " + _shell_q(body) + "\n"
            "\n"
            "# Step 2: decode the JWT in the response 'authentication.token'\n"
            "# field and confirm the payload claims role='admin'. One-liner:\n"
            "curl -sk -X POST " + _shell_q(target) + " \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d " + _shell_q(body) + " \\\n"
            "  | python3 -c "
            "\"import sys,json,base64;t=json.load(sys.stdin)['authentication']['token'];"
            "p=t.split('.')[1];p+='='*(-len(p)%4);print(json.loads(base64.urlsafe_b64decode(p)))\""
        )
        return {
            "curl": curl,
            "hint": (
                "Vulnerable login form accepted the classic tautology payload "
                f"<code>{html.escape(payload)}</code> and issued an admin JWT. "
                "If the fix is applied, step&nbsp;1 should return HTTP&nbsp;401 "
                "with no <code>authentication.token</code> field, and step&nbsp;2 "
                "will exit non-zero because the JSON path is missing."),
        }

    # auth_default_admin_credentials — replay the exact POST that the
    # probe issued. Pull the recorded credentials out of the evidence so
    # the analyst sees the actual seeded account, not a placeholder.
    if probe == "auth_default_admin_credentials":
        login_path = first.get("login_path") or "/rest/user/login"
        email = first.get("email") or "admin@example.com"
        password = first.get("password") or "<documented-default-password>"
        target = (first.get("url")
                  or (origin.rstrip("/") + login_path if origin else login_path))
        body = json.dumps({"email": email, "password": password})
        curl = (
            "# Step 1: log in with the documented default account.\n"
            "curl -ski -X POST " + _shell_q(target) + " \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d " + _shell_q(body) + "\n"
            "\n"
            "# Step 2: extract the JWT and confirm role='admin'.\n"
            "TOKEN=$(curl -sk -X POST " + _shell_q(target) + " \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d " + _shell_q(body) + " | "
            "python3 -c \"import sys,json;print(json.load(sys.stdin)"
            "['authentication']['token'])\")\n"
            "echo \"$TOKEN\" | awk -F. '{print $2}' | "
            "base64 -d 2>/dev/null | python3 -m json.tool"
        )
        return {
            "curl": curl,
            "hint": (
                "Default credentials <code>"
                f"{html.escape(email)}</code> / <code>"
                f"{html.escape(password)}</code> still work and grant an "
                "administrative session. After rotation, step&nbsp;1 must "
                "return HTTP&nbsp;401 (or 403) with no token in the body."),
        }

    # info_key_material_exposed — list every confirmed path so the analyst
    # can verify each one. The first confirmed entry typically holds the
    # most damaging key (private RSA, signing key, etc.).
    if probe == "info_key_material_exposed":
        paths = []
        if isinstance(confirmed, list):
            paths = [r.get("path") for r in confirmed if r.get("path")]
        elif isinstance(first, dict) and first.get("path"):
            paths = [first["path"]]
        if not paths:
            paths = ["/encryptionkeys/jwt.pub"]
        host = origin.rstrip("/")
        lines = ["# Each path below should return HTTP 403 / 404 once "
                 "the key material is moved out of the document root."]
        for p in paths[:8]:
            full = host + p if host else p
            lines.append("curl -ski -o /dev/null -w '%{http_code} %{size_download}B "
                         + _shell_q(p) + "\\n' " + _shell_q(full))
        lines.append("")
        lines.append("# Spot-check the headline file directly. A signing "
                     "key dump starts with -----BEGIN ... KEY----- :")
        lines.append("curl -sk " + _shell_q(host + paths[0] if host else paths[0])
                     + " | head -3")
        return {
            "curl": "\n".join(lines),
            "hint": (
                f"{len(paths)} key-material path(s) reachable on the public "
                "vhost. Anything returning <code>200</code> with a body "
                "starting <code>-----BEGIN</code> is still exposed."),
        }

    # config_cors_wildcard — replay the OPTIONS preflight the probe sent.
    # The signal is ACAO=* with Authorization in ACAH on an
    # authenticated endpoint, so the analyst confirms by reading the
    # response headers, not the body.
    if probe == "config_cors_wildcard":
        path = first.get("path") or "/"
        target = origin.rstrip("/") + path if origin else path
        curl = (
            "# Replay the CORS preflight against the affected endpoint.\n"
            "curl -ski -X OPTIONS " + _shell_q(target) + " \\\n"
            "  -H 'Origin: https://attacker.example' \\\n"
            "  -H 'Access-Control-Request-Method: GET' \\\n"
            "  -H 'Access-Control-Request-Headers: Authorization' \\\n"
            "  | grep -i '^access-control-'"
        )
        return {
            "curl": curl,
            "hint": (
                "Preflight currently returns "
                "<code>Access-Control-Allow-Origin: *</code> and lists "
                "<code>Authorization</code> in <code>"
                "Access-Control-Allow-Headers</code>. After the fix, "
                "<code>Access-Control-Allow-Origin</code> must echo only "
                "the configured origin (or the response should drop the "
                "header entirely for unauthenticated endpoints)."),
        }

    # info_directory_listing — fetch the path and look for the autoindex
    # marker. We keep two checks: status code (the listing is HTTP 200
    # rather than 403/404) and a body fingerprint (filename in the HTML).
    if probe == "info_directory_listing":
        path = first.get("path") or "/"
        target = origin.rstrip("/") + path if origin else path
        sample = ""
        if isinstance(first.get("files_sample"), list) and first["files_sample"]:
            for entry in first["files_sample"]:
                if entry and entry not in (".", ".."):
                    sample = entry
                    break
        grep_cmd = ("grep -E 'Index of|<title>Index|directory listing' -m1"
                    if not sample
                    else f"grep -F {_shell_q(sample)}")
        curl = (
            "# A correctly-locked directory returns 403 (Apache) / 404 / "
            "an empty 200 — never an HTML index of files.\n"
            "curl -ski " + _shell_q(target) + " | head -20\n"
            "\n"
            "# Grep the body for the autoindex signature.\n"
            "curl -sk " + _shell_q(target) + " | " + grep_cmd
        )
        return {
            "curl": curl,
            "hint": (
                f"Server is currently rendering <code>{html.escape(path)}"
                "</code> as an HTML directory index"
                + (f" (sample filename: <code>{html.escape(sample)}</code>)"
                   if sample else "")
                + ". After <code>autoindex off</code> / "
                "<code>Options -Indexes</code>, the second grep above must "
                "return no match."),
        }

    # info_metrics_exposed — Prometheus exposition. Confirmation is a
    # 200 response with the # HELP / # TYPE comment lines that all
    # Prometheus scrapes carry.
    if probe == "info_metrics_exposed":
        path = first.get("path") or "/metrics"
        target = origin.rstrip("/") + path if origin else path
        curl = (
            "# Prometheus exposition is plain text with leading\n"
            "# '# HELP' and '# TYPE' lines for every metric.\n"
            "curl -ski " + _shell_q(target) + " | head -20\n"
            "\n"
            "# Quantify it: count the metric type declarations.\n"
            "curl -sk " + _shell_q(target) + " | grep -c '^# TYPE'"
        )
        return {
            "curl": curl,
            "hint": (
                "If <code># TYPE ...</code> lines are present, the metrics "
                "endpoint is reachable from this network position. After "
                "the fix, expect HTTP&nbsp;401 / 403 (or no route at all)."),
        }

    # info_verbose_error — fire the exact tickle URL and grep the body
    # for the engine error family the probe matched. The probe records
    # the URL and the matched snippet so we can give a precise grep.
    if probe == "info_verbose_error":
        target = first.get("url") or f.get("evidence_url") or ""
        snippet = first.get("snippet") or first.get("error_family") or "Error"
        curl = (
            "# The URL contains a deliberately broken query that the\n"
            "# scanner found makes the framework leak its stack trace.\n"
            "curl -ski " + _shell_q(target) + "\n"
            "\n"
            "# Grep the response body for the error-family fingerprint.\n"
            "curl -sk " + _shell_q(target) + " | grep -F "
            + _shell_q(snippet)
        )
        return {
            "curl": curl,
            "hint": (
                f"Body currently contains <code>{html.escape(snippet)}</code>. "
                "After switching to the production error handler, the "
                "response must be a generic 5xx page (the grep returns "
                "nothing)."),
        }

    # path_traversal_extension_bypass — fire the bypass URL and confirm
    # the body matches the magic string the probe found (e.g.
    # "dependencies": for a Node package manifest backup).
    if probe == "path_traversal_extension_bypass":
        target = first.get("url") or f.get("evidence_url") or ""
        match = first.get("body_match") or "dependencies"
        what = first.get("what") or "sensitive backup file"
        curl = (
            f"# The URL exploits the %2500 (NUL) bypass to fetch a "
            f"{what}.\n"
            "curl -ski " + _shell_q(target) + " | head -20\n"
            "\n"
            "# Confirm the body contains the fingerprint.\n"
            "curl -sk " + _shell_q(target) + " | grep -F "
            + _shell_q(match)
        )
        return {
            "curl": curl,
            "hint": (
                "Server currently serves the bypassed file (body contains "
                f"<code>{html.escape(match)}</code>). After URL-decoding "
                "the path before the extension check, the request must "
                "return HTTP&nbsp;403 / 404 and the grep must fail."),
        }

    # Generic enhanced_testing fallback — emit a curl against the URL
    # the probe last confirmed against, plus the audit_log so the
    # analyst can see the full attack surface the probe exercised.
    target = first.get("url") or f.get("evidence_url") or ""
    if target:
        return {"curl": "curl -ski " + _shell_q(target),
                "hint": ("Reproduction: send the request above and "
                         "compare the response against the scan capture.")}
    return {}


# Mapping testssl IANA short codes (xc019 etc.) to human-readable cipher
# names. Used to render an openssl s_client one-liner that targets
# exactly the cipher testssl flagged. Covers the codes we have actually
# emitted findings for in production assessments; unknown codes degrade
# to an openssl --list view rather than a wrong cipher.
TESTSSL_CIPHER_BY_CODE = {
    "xc006": "AECDH-NULL-SHA",      # ECDH-anon NULL — no auth, no enc
    "xc015": "ADH-AES128-SHA",      # DH-anon AES128
    "xc018": "AECDH-AES128-SHA",    # ECDH-anon AES128
    "xc019": "AECDH-AES256-SHA",    # ECDH-anon AES256
    "xc009": "ECDHE-ECDSA-AES128-SHA",
    "xc00a": "ECDHE-ECDSA-AES256-SHA",
    "xc023": "ECDHE-ECDSA-AES128-SHA256",
    "xc024": "ECDHE-ECDSA-AES256-SHA384",
    "xc072": "ECDHE-ECDSA-CAMELLIA128-SHA256",
    "xc073": "ECDHE-ECDSA-CAMELLIA256-SHA384",
}


def _testssl_protocol_flag(test_id: str) -> str:
    """testssl ids embed the protocol they tested (e.g. cipher-tls1_2_xCODE
    or cipher_order-tls1_1). Map back to the openssl s_client flag — empty
    string when no specific protocol is encoded in the id."""
    tid = (test_id or "").lower()
    if "tls1_3" in tid: return "-tls1_3"
    if "tls1_2" in tid: return "-tls1_2"
    if "tls1_1" in tid: return "-tls1_1"
    if "tls1" in tid:   return "-tls1"
    return ""


def _repro_testssl(f: dict, raw: dict) -> dict:
    """Reproductions for testssl findings. The test id (raw['id']) tells
    us exactly which protocol/cipher/feature was flagged, so we emit a
    minimum-fuss command — usually openssl s_client with the right flags,
    or a focused testssl re-run for higher-level checks (BREACH,
    overall_grade)."""
    test_id = raw.get("id") or ""
    finding = raw.get("finding") or ""
    host_url = f.get("evidence_url") or ""
    host, port = _host_port_from_url(host_url)
    if not host:
        return {}
    hp = f"{host}:{port}"

    # Cipher checks: e.g. cipher-tls1_xc019, cipher-tls1_2_xc006, etc.
    m = re.match(r"^cipher-(tls1(?:_1|_2|_3)?)_(x[0-9a-fA-F]+)$", test_id)
    if m:
        proto_flag = _testssl_protocol_flag(test_id)
        code = m.group(2).lower()
        cipher = TESTSSL_CIPHER_BY_CODE.get(code)
        cipher_arg = (cipher if cipher else
                      "<see openssl ciphers -V output for code 0x" + code[1:] + ">")
        cipher_q = _shell_q(cipher) if cipher else cipher_arg
        cipher_label = (cipher or f"the cipher with IANA code 0x{code[1:]}")
        cmd_lines = [
            f"# testssl flagged the cipher {cipher_label} on this server.",
            "# A successful handshake here = the cipher is still offered.",
            "# A 'no cipher match' / 'handshake failure' = it has been "
            "removed.",
            "openssl s_client -connect " + _shell_q(hp) + " " + proto_flag
            + " -servername " + _shell_q(host)
            + " -cipher " + cipher_q + " </dev/null 2>&1 | "
            "grep -E 'Cipher|Protocol|alert'",
        ]
        if not cipher:
            cmd_lines.append("")
            cmd_lines.append("# Cipher code not in the local map. List "
                             "the local OpenSSL's view of the same code:")
            cmd_lines.append(f"openssl ciphers -V | grep -i '0x{code[1:].upper()}'")
        return {
            "curl": "\n".join(cmd_lines),
            "hint": (
                f"Server still negotiates <code>{html.escape(cipher_label)}"
                "</code>. After removing it from the cipher list, the "
                "openssl line above should print "
                "<code>:error: ... no cipher match</code>."),
        }

    # cipher_order / cipher_order-tls1*  — server isn't enforcing a
    # cipher preference. nmap's ssl-enum-ciphers is the cleanest way to
    # confirm and shows ordering directly in its output.
    if test_id.startswith("cipher_order"):
        proto_flag = _testssl_protocol_flag(test_id)
        # Per-protocol re-runs use testssl's -p flag (e.g. -p tls1_2);
        # the unscoped 'cipher_order' check rolls up every protocol so
        # we just run the full server preference test (-P) instead.
        if proto_flag:
            testssl_cmd = ("testssl.sh --quiet --color 0 -p "
                           f"{proto_flag.lstrip('-')} {hp}")
        else:
            testssl_cmd = f"testssl.sh --quiet --color 0 -P {hp}"
        return {
            "curl": (
                f"# nmap renders cipher order per protocol — look for the\n"
                f"# 'cipher preference: server' / 'client' / 'indeterminate'\n"
                f"# line under each protocol section.\n"
                f"nmap --script ssl-enum-ciphers -p {port} {host}\n"
                f"\n"
                f"# Or, focused on this protocol with testssl:\n"
                f"{testssl_cmd}"
            ),
            "hint": (
                f"testssl reported: <code>{html.escape(finding)}</code>. "
                "After enabling server-preference and a curated cipher "
                "list, nmap should report "
                "<code>cipher preference: server</code> on each protocol."),
        }

    # cipherlist_NULL / cipherlist_aNULL / cipherlist_OBSOLETED — these
    # ask: does the server even offer this category of cipher? openssl
    # accepts the same category names as a -cipher argument, so we use
    # them directly.
    cipherlist_map = {
        "cipherlist_NULL":      ("NULL",  "NULL ciphers (no encryption)"),
        "cipherlist_aNULL":     ("aNULL", "anonymous-key-exchange ciphers (no auth)"),
        "cipherlist_OBSOLETED": ("LOW:EXPORT:DES:RC4:MD5", "obsoleted weak ciphers"),
        "cipherlist_3DES":      ("3DES",  "3DES (sweet32-vulnerable) ciphers"),
        "cipherlist_AVERAGE":   ("MEDIUM",     "MEDIUM-strength ciphers"),
    }
    if test_id in cipherlist_map:
        cipher_arg, desc = cipherlist_map[test_id]
        return {
            "curl": (
                f"# Server should refuse {desc}. A successful handshake\n"
                f"# below = the category is still offered (vulnerable).\n"
                f"openssl s_client -connect {_shell_q(hp)} -servername "
                f"{_shell_q(host)} -cipher {_shell_q(cipher_arg)} "
                f"</dev/null 2>&1 | grep -E 'Cipher|Protocol|alert'"
            ),
            "hint": (
                f"openssl currently negotiates a cipher in the "
                f"<code>{html.escape(cipher_arg)}</code> family. After the "
                f"fix, expect <code>:error: ... no cipher match</code>."),
        }

    # TLS1 / TLS1_1 — testssl flags these when the protocol is reachable.
    proto_only = {"TLS1": "-tls1", "TLS1_1": "-tls1_1",
                  "SSLv2": "-ssl2", "SSLv3": "-ssl3"}
    if test_id in proto_only:
        flag = proto_only[test_id]
        return {
            "curl": (
                f"# Probe the protocol directly. Successful handshake =\n"
                f"# the protocol is still enabled on this listener.\n"
                f"openssl s_client -connect {_shell_q(hp)} -servername "
                f"{_shell_q(host)} {flag} </dev/null 2>&1 | "
                f"grep -E '^Protocol|^Cipher|alert'"
            ),
            "hint": (
                f"<code>{test_id}</code> is reachable. After disabling it, "
                f"the openssl command should fail with <code>handshake "
                f"failure</code> or <code>protocol version</code>."),
        }

    # BREACH — TLS-level CRIME-family attack against HTTPS responses
    # that are HTTP-compressed. Confirmation: the response carries a
    # Content-Encoding header (gzip/deflate/br).
    if test_id == "BREACH":
        return {
            "curl": (
                f"# BREACH requires the response to be HTTP-compressed.\n"
                f"# Confirmation = the server ECHOes back a Content-Encoding\n"
                f"# header (gzip / deflate / br).\n"
                f"curl -skI --compressed -H 'Accept-Encoding: br, gzip, deflate' "
                f"https://{host}/ | grep -i '^content-encoding'"
            ),
            "hint": (
                "Server still emits <code>Content-Encoding</code> on HTTPS "
                "responses. The fix is normally to disable HTTP compression "
                "for responses that include sensitive tokens (or to "
                "randomise the response body so the side-channel breaks)."),
        }

    # BEAST_CBC_TLS1*: lists the CBC ciphers offered on the named
    # protocol. We confirm by negotiating any CBC cipher on TLS 1.0 / 1.1.
    if test_id.startswith("BEAST_CBC"):
        flag = _testssl_protocol_flag(test_id) or "-tls1"
        return {
            "curl": (
                f"# Force a CBC cipher on the named protocol.\n"
                f"openssl s_client -connect {_shell_q(hp)} -servername "
                f"{_shell_q(host)} {flag} -cipher 'AES:CAMELLIA:!AEAD' "
                f"</dev/null 2>&1 | grep -E 'Cipher|Protocol|alert'"
            ),
            "hint": (
                "Server negotiates a CBC-mode cipher on this legacy "
                "protocol. Disabling TLS 1.0/1.1 (preferred) or removing "
                "all CBC suites from the cipher list resolves both BEAST "
                "and Lucky13."),
        }

    if test_id == "LUCKY13":
        return {
            "curl": (
                f"# Any CBC cipher offered on TLS 1.0/1.1/1.2 with this\n"
                f"# server's MAC implementation is potentially Lucky13-prone.\n"
                f"openssl s_client -connect {_shell_q(hp)} -servername "
                f"{_shell_q(host)} -cipher 'AES256-SHA:AES128-SHA' "
                f"</dev/null 2>&1 | grep -E 'Cipher|Protocol|alert'"
            ),
            "hint": ("After moving to AEAD-only ciphers (AES-GCM, ChaCha20), "
                     "this handshake should fail or only succeed with an "
                     "AEAD cipher in the response."),
        }

    if test_id == "HSTS":
        return {
            "curl": (
                f"# HSTS is a single response header. Missing or short "
                f"max-age = a clear-text downgrade window is open.\n"
                f"curl -skI https://{host}/ | grep -i strict-transport-security"
            ),
            "hint": (
                "Header is currently absent or weak. The CIO benchmark is "
                "<code>Strict-Transport-Security: max-age=63072000; "
                "includeSubDomains; preload</code>."),
        }

    if test_id.startswith("cert_trust"):
        return {
            "curl": (
                f"# Pull the live cert and decode it.\n"
                f"openssl s_client -connect {_shell_q(hp)} -servername "
                f"{_shell_q(host)} -showcerts </dev/null 2>/dev/null | "
                f"openssl x509 -noout -text | "
                f"grep -A1 'Subject Alternative Name'"
            ),
            "hint": (
                f"testssl flagged: <code>{html.escape(finding)}</code>. The "
                "command above shows the SAN list directly so an analyst "
                "can decide whether the wildcard is intentional."),
        }

    if test_id.startswith("FS"):
        return {
            "curl": (
                f"# Forward-secrecy review — testssl --fs scopes the run to\n"
                f"# the FS section of the test matrix.\n"
                f"testssl.sh --fs --color 0 --quiet {_shell_q(hp)}"
            ),
            "hint": (
                f"testssl flagged: <code>{html.escape(finding)}</code>. The "
                "narrowed re-run lists only the FS-relevant rows so the "
                "fix can be validated quickly."),
        }

    if test_id == "overall_grade":
        return {
            "curl": (
                f"# The overall grade is the rolled-up severity of every\n"
                f"# subtest. Re-run the full scan after remediation.\n"
                f"testssl.sh --color 0 --quiet {_shell_q(hp)}"
            ),
            "hint": (
                f"Server currently grades <code>{html.escape(finding)}</code>. "
                "Target an A or A+ — the per-control rows in the same scan "
                "explain which sub-grade is dragging the overall down."),
        }

    # Fallback for testssl ids we haven't special-cased: focused testssl
    # re-run anchored on the host:port the probe targeted.
    return {
        "curl": (
            f"# Focused testssl re-run against the same target.\n"
            f"testssl.sh --color 0 --quiet {_shell_q(hp)} 2>&1 | "
            f"grep -i {_shell_q(test_id)}"
        ),
        "hint": (f"Search the testssl output for the <code>{html.escape(test_id)}</code> "
                 "row — the finding text is the message it printed."
                 if test_id else None),
    }


def _repro_nuclei(f: dict, raw: dict) -> dict:
    """nuclei findings carry the full request/response and a
    template-id. Build both: a faithful curl that replays the request,
    and the nuclei one-liner that re-runs the matcher narrowly."""
    tid = raw.get("template-id") or raw.get("templateID") or ""
    target = (raw.get("matched-at") or raw.get("url") or raw.get("host")
              or f.get("evidence_url") or "")
    template_path = raw.get("template-path") or ""
    method = (raw.get("type") or raw.get("info", {}).get("method")
              or f.get("evidence_method") or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTIONS"):
        method = "GET"
    matcher = raw.get("matcher-name") or ""

    # Build the github URL for the template if we can. The path on disk
    # is something like /root/nuclei-templates/http/exposures/.../foo.yaml
    # — we strip the local prefix to get the repo-relative path.
    template_url = ""
    if template_path:
        marker = "/nuclei-templates/"
        idx = template_path.find(marker)
        if idx >= 0:
            rel = template_path[idx + len(marker):]
            template_url = ("https://github.com/projectdiscovery/"
                            "nuclei-templates/blob/main/" + rel)

    lines = []
    if target:
        lines.append("# Step 1: replay the request manually with curl.")
        # If the raw request is captured, prefer extracting the path /
        # method from it — it carries the exact headers nuclei sent.
        if raw.get("request"):
            lines.append("curl -ski -X " + method + " " + _shell_q(target))
        else:
            lines.append("curl -ski " + _shell_q(target))
        lines.append("")
    if tid and target:
        lines.append("# Step 2: re-run nuclei narrowly. Confirms the matcher "
                     "still fires.")
        lines.append(f"nuclei -id {tid} -target {_shell_q(target)} "
                     "-silent -j")
    if template_url:
        lines.append("")
        lines.append("# Template definition (matcher logic is in here):")
        lines.append("# " + template_url)
    if not lines:
        return {}
    hint_bits = []
    if tid:
        hint_bits.append(f"Nuclei template <code>{html.escape(tid)}</code>")
    if matcher:
        hint_bits.append(f"matcher <code>{html.escape(matcher)}</code>")
    return {
        "curl": "\n".join(lines),
        "hint": ((" / ".join(hint_bits) +
                  ". After the fix, the nuclei re-run should print no JSON "
                  "lines (no match).") if hint_bits else None),
    }


def _repro_wapiti(f: dict, raw: dict) -> dict:
    """Wapiti records the full http_request + curl_command. Prefer the
    captured curl over rebuilding from URL+method, so a multi-header /
    body POST survives. Annotate with the vulnerable parameter when
    known."""
    captured = raw.get("curl_command")
    info = raw.get("info") or ""
    param = raw.get("parameter") or ""
    method = (raw.get("method") or f.get("evidence_method") or "GET").upper()
    path = raw.get("path") or f.get("evidence_url") or "/"
    # Wapiti stores the path relative to the target FQDN. The full URL
    # only lives inside the captured http_request blob (in the Host
    # header) — the evidence_url column also stores the relative path.
    # Pull the host out of http_request first, fall back to evidence_url.
    base_url = f.get("evidence_url") or ""
    host = ""
    http_req = raw.get("http_request") or ""
    if http_req:
        m = re.search(r"^host:\s*([^\s\r\n]+)", http_req,
                      re.IGNORECASE | re.MULTILINE)
        if m:
            host = m.group(1).strip()
    full_url = path if path.startswith("http") else ""
    if not full_url:
        if not host and base_url:
            try:
                p = urlparse(base_url)
                host = p.netloc or ""
            except Exception:
                host = ""
        if host:
            full_url = f"https://{host}{path or '/'}"
        else:
            full_url = path

    if captured:
        cmd = captured.strip()
        # Wapiti's curl_command is double-quoted; convert to -ski to
        # see headers + tolerate self-signed certs in test envs.
        if cmd.startswith("curl ") and " -i" not in cmd and " -I" not in cmd:
            cmd = cmd.replace("curl ", "curl -ski ", 1)
    elif full_url:
        cmd = ("curl -ski"
               + ((" -X " + method) if method != "GET" else "")
               + " " + _shell_q(full_url))
    else:
        return {}

    # Many wapiti checks are header-presence checks (CSP, HSTS, X-Frame).
    # The response headers ARE the signal, so add a grep step that names
    # the header the analyst is verifying.
    info_lower = info.lower()
    grep_target = None
    if "csp" in info_lower or "content security policy" in info_lower:
        grep_target = "content-security-policy"
    elif "strict-transport-security" in info_lower or "hsts" in info_lower:
        grep_target = "strict-transport-security"
    elif "x-frame" in info_lower or "clickjacking" in info_lower:
        grep_target = "x-frame-options"
    elif "x-content-type" in info_lower:
        grep_target = "x-content-type-options"
    elif "referrer-policy" in info_lower:
        grep_target = "referrer-policy"
    elif "permissions-policy" in info_lower:
        grep_target = "permissions-policy"

    out_curl = cmd
    if grep_target:
        out_curl = (
            cmd + "\n\n"
            f"# Header check: this should print a non-empty {grep_target} line "
            "after the fix.\n"
            "curl -skI " + _shell_q(full_url or base_url or "") + " | "
            f"grep -i '^{grep_target}:'"
        )
    hint_parts = []
    if info:
        hint_parts.append(html.escape(info))
    if param:
        hint_parts.append(f"vulnerable parameter <code>{html.escape(param)}</code>")
    return {
        "curl": out_curl,
        "hint": " — ".join(hint_parts) if hint_parts else None,
    }


def _repro_nikto(f: dict, raw: dict) -> dict:
    """Nikto stores a single line of human-readable text per finding plus
    a numeric check id. The line carries the URL path and the diagnostic
    so we can build a curl that reproduces what Nikto saw."""
    line = raw.get("line") or ""
    rid = raw.get("id") or ""
    url = f.get("evidence_url") or ""
    if not url:
        return {}
    head_only = "X-Frame" in line or "header missing" in line.lower() or \
                "Content-Encoding" in line or "banner" in line.lower()
    cmd = ("curl -skI " + _shell_q(url)) if head_only else \
          ("curl -ski " + _shell_q(url) + " | head -40")
    grep = ""
    line_lower = line.lower()
    if "strict-transport-security" in line_lower:
        grep = "\n# Confirm fix: header should now be present.\n" \
               "curl -skI " + _shell_q(url) + " | grep -i strict-transport-security"
    elif "content-security-policy" in line_lower:
        grep = "\n# Confirm fix: header should now be present.\n" \
               "curl -skI " + _shell_q(url) + " | grep -i content-security-policy"
    elif "x-frame-options" in line_lower:
        grep = "\n# Confirm fix: X-Frame-Options should be DENY or SAMEORIGIN.\n" \
               "curl -skI " + _shell_q(url) + " | grep -i x-frame-options"
    elif "permissions-policy" in line_lower:
        grep = "\n# Confirm fix: header should now be present.\n" \
               "curl -skI " + _shell_q(url) + " | grep -i permissions-policy"
    elif "referrer-policy" in line_lower:
        grep = "\n# Confirm fix: header should now be present.\n" \
               "curl -skI " + _shell_q(url) + " | grep -i referrer-policy"
    elif "content-encoding" in line_lower and "deflate" in line_lower:
        grep = "\n# BREACH risk: server should not return Content-Encoding.\n" \
               "curl -skI --compressed " + _shell_q(url) + " | grep -i content-encoding"
    elif "robots.txt" in line_lower:
        grep = "\n# Inspect entries — anything sensitive should be moved.\n" \
               "curl -sk " + _shell_q(url)
    return {
        "curl": cmd + grep,
        "hint": (("Nikto check ID: <code>" + html.escape(rid) + "</code>. ")
                 if rid else "")
                + html.escape(line) if line else None,
    }


def _repro_ffuf(f: dict, raw: dict) -> dict:
    """ffuf finds reachable paths during content discovery. Reproduction
    is a HEAD/GET against the URL, asserting status code matches what
    ffuf saw. After remediation the path should return 401/403/404."""
    url = raw.get("url") or f.get("evidence_url") or ""
    status = raw.get("status")
    length = raw.get("length")
    if not url:
        return {}
    expected = f"HTTP {status}" if status is not None else "HTTP 200"
    return {
        "curl": (
            f"# ffuf saw {expected}"
            + (f" (~{length} bytes)" if length is not None else "")
            + " at this path during content discovery.\n"
            "curl -ski -o /dev/null -w 'HTTP %{http_code}, %{size_download} bytes\\n' "
            + _shell_q(url) + "\n"
            "\n"
            "# Inspect the body if the path looks like it should not be public:\n"
            "curl -sk " + _shell_q(url) + " | head -20"
        ),
        "hint": (
            f"After the fix, expect HTTP&nbsp;401 / 403 / 404 instead of "
            f"<code>{expected}</code>."),
    }


def _repro_dalfox(f: dict, raw: dict) -> dict:
    """Dalfox is an XSS scanner. raw_data is sometimes empty (older
    parser); when present it carries payload + parameter. We always have
    the URL, so emit a dalfox re-run plus a manual curl with the payload
    when available."""
    url = f.get("evidence_url") or ""
    payload = raw.get("payload") or raw.get("data") or ""
    param = raw.get("param") or raw.get("parameter") or ""
    if not url:
        return {}
    lines = [
        "# Step 1: re-run dalfox narrowly against the same URL.",
        "dalfox url " + _shell_q(url) + " --skip-bav --silence",
    ]
    if payload:
        # If we know the payload, build a curl variant the analyst can
        # paste into a browser's address bar to confirm visually.
        lines += [
            "",
            "# Step 2: hit the URL with the recorded XSS payload.",
            "# Reflection in the response body = still vulnerable.",
        ]
        if param and "?" in url:
            lines.append("# (Replace the value of '" + param +
                         "' below with the payload.)")
        lines.append("curl -sk " + _shell_q(url) + " | grep -F " + _shell_q(payload))
    else:
        lines += [
            "",
            "# Inspect the response: any echo of an unsanitised query "
            "or fragment value into the HTML is the smoking gun.",
            "curl -sk " + _shell_q(url) + " | head -40",
        ]
    return {
        "curl": "\n".join(lines),
        "hint": (
            (f"Vulnerable parameter: <code>{html.escape(param)}</code>. "
             if param else "")
            + (f"Payload: <code>{html.escape(payload)}</code>"
               if payload else "Open the URL in a browser to confirm "
               "reflection — dalfox prints the exact payload in its "
               "stdout output.")),
    }


def _repro_sqlmap(f: dict, raw: dict) -> dict:
    """sqlmap stores the parameter and proof type. Build a focused
    re-run that narrows to the parameter rather than letting sqlmap
    crawl the whole site again."""
    url = f.get("evidence_url") or ""
    if not url:
        return {}
    payload = raw.get("payload") or ""
    param = raw.get("param") or raw.get("parameter") or ""
    proof = raw.get("type") or ""
    args = ["sqlmap", "-u", _shell_q(url), "--batch", "--level=2", "--risk=2"]
    if param:
        args += ["-p", _shell_q(param)]
    if proof:
        # Map sqlmap proof types to --technique flags so the re-run
        # converges on the same proof much faster than a full sweep.
        tmap = {"boolean-based blind": "B", "boolean": "B",
                "time-based blind": "T", "time": "T",
                "error-based": "E", "error": "E",
                "union": "U", "stacked": "S", "inline": "Q"}
        techs = "".join({v for k, v in tmap.items()
                         if k in proof.lower()})
        if techs:
            args += [f"--technique={techs}"]
    cmd = " ".join(args)
    extras = []
    if payload:
        extras.append(f"# Recorded payload: {payload}")
    return {
        "curl": (("\n".join(extras) + "\n") if extras else "") + cmd,
        "hint": (
            (f"Vulnerable parameter: <code>{html.escape(param)}</code>. "
             if param else "")
            + ("Proof family: <code>" + html.escape(proof) + "</code>. "
               if proof else "")
            + "After parameterising the query, sqlmap should report "
            "<code>not injectable</code>."),
    }


def _repro_generic(f: dict) -> dict:
    """Last-resort fallback when the source tool isn't recognised. Emits
    a plain curl against the evidence URL — barely useful, but better
    than nothing for an unknown tool."""
    url = f.get("evidence_url") or ""
    if not url:
        return {}
    method = (f.get("evidence_method") or "GET").upper()
    if method in ("GET", "HEAD"):
        return {"curl": "curl -ski " + _shell_q(url)}
    return {"curl": "curl -ski -X " + method + " " + _shell_q(url)}


def _repro_for(f: dict) -> dict:
    """Build a 'reproduction steps' block for one finding, dispatched by
    source tool. Each builder returns {curl, hint}; we then layer on the
    OWASP / CWE references which are tool-agnostic.

    The output is consumed by templates/_finding_reproduce.html and the
    PDF report. The contract: the curl block must be a real working
    command (or sequence of commands) that an analyst can copy-paste and
    run against the live target — same indicator the scanner saw if the
    issue is unfixed, different one if it's been remediated."""
    tool = (f.get("source_tool") or "").lower()
    raw = f.get("raw") or {}

    if tool == "enhanced_testing":
        repro = _repro_enhanced_testing(f, raw)
    elif tool == "testssl":
        repro = _repro_testssl(f, raw)
    elif tool == "nuclei":
        repro = _repro_nuclei(f, raw)
    elif tool == "wapiti":
        repro = _repro_wapiti(f, raw)
    elif tool == "nikto":
        repro = _repro_nikto(f, raw)
    elif tool == "ffuf":
        repro = _repro_ffuf(f, raw)
    elif tool == "dalfox":
        repro = _repro_dalfox(f, raw)
    elif tool == "sqlmap":
        repro = _repro_sqlmap(f, raw)
    else:
        repro = _repro_generic(f)
    if not isinstance(repro, dict):
        repro = {}

    # References: hand-verified canonical URLs per OWASP code. The 2025
    # release renamed most categories so naive 2021→2025 translation 404s
    # for everything except A01. For everyone else we keep the working
    # 2021 URLs. A10 is special-cased — its slug carries the long name
    # in URL-encoded parens. (URLs probed live before being added.)
    OWASP_REFS = {
        "A01": ("A01:2025-Broken Access Control",
                "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/"),
        "A02": ("A02:2021-Cryptographic Failures",
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
        "A03": ("A03:2021-Injection",
                "https://owasp.org/Top10/A03_2021-Injection/"),
        "A04": ("A04:2021-Insecure Design",
                "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
        "A05": ("A05:2021-Security Misconfiguration",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        "A06": ("A06:2021-Vulnerable & Outdated Components",
                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
        "A07": ("A07:2021-Identification & Authentication Failures",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
        "A08": ("A08:2021-Software & Data Integrity Failures",
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
        "A09": ("A09:2021-Security Logging & Monitoring Failures",
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
        "A10": ("A10:2021-Server-Side Request Forgery",
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
    }
    refs = []
    if f.get("owasp_category"):
        m = re.match(r"^(A\d+)", f["owasp_category"])
        if m and m.group(1) in OWASP_REFS:
            refs.append(OWASP_REFS[m.group(1)])
    if f.get("cwe"):
        refs.append((f"CWE-{f['cwe']}",
                     f"https://cwe.mitre.org/data/definitions/{f['cwe']}.html"))
    repro["references"] = refs

    return repro


# File-name policy:
#   /data/reports/<assessment_id>/<safe_fqdn>_<finished_date>_report.pdf
#
# Each assessment gets its own subdirectory. We keep at most ONE PDF per
# assessment — generating a new one purges the old. The filename is
# user-facing (it's what gets downloaded), so it uses the FQDN + finish
# date in YYYY-MM-DD form. The subdirectory keeps two assessments on the
# same FQDN finishing the same day from colliding with each other.
REPORT_FILENAME_RE = re.compile(
    r"^[A-Za-z0-9.-]+_\d{4}-\d{2}-\d{2}_report\.pdf$"
)


def _safe_fqdn(s: str) -> str:
    """Strip everything that isn't a hostname character. Defensive — the
    DB *should* only have valid FQDNs, but the filename ends up in URLs
    and on disk so we sanitize at the boundary."""
    s = (s or "").strip().lower()
    return re.sub(r"[^a-z0-9.\-]", "", s) or "unknown"


def _finished_date(a: dict) -> str:
    """YYYY-MM-DD of the assessment's finish, falling back to start date,
    then today's UTC date if neither timestamp is present."""
    for key in ("finished_at", "started_at", "created_at"):
        ts = a.get(key)
        if ts:
            # ts is a datetime from pymysql, or string if reread from JSON
            if hasattr(ts, "strftime"):
                return ts.strftime("%Y-%m-%d")
            return str(ts)[:10]
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _report_dir(assessment_id: int) -> Path:
    """Per-assessment subdirectory. Resolved so callers can use it for
    path-safety checks against REPORTS_DIR."""
    return REPORTS_DIR / str(int(assessment_id))


def report_filename(a: dict) -> str:
    """Compute the canonical filename for an assessment's PDF report."""
    return f"{_safe_fqdn(a.get('fqdn'))}_{_finished_date(a)}_report.pdf"


def generate(assessment_id: int) -> Optional[Path]:
    data = _gather(assessment_id)
    if not data:
        return None
    a = data["a"]
    rdir = _report_dir(assessment_id)
    rdir.mkdir(parents=True, exist_ok=True)
    tpl = env.get_template("report.html")
    rendered = tpl.render(**data)

    out = rdir / report_filename(a)
    # Purge any prior reports for this assessment — only one PDF is kept
    # per assessment. Includes anything in the subdirectory (covers the
    # legacy filename pattern from earlier releases) plus the new path.
    for stale in rdir.glob("*.pdf"):
        if stale != out:
            try:
                stale.unlink()
            except OSError:
                pass
    # base_url is needed so WeasyPrint can resolve <img src="..."> against
    # local filesystem paths (the branding logos).
    HTML(string=rendered, base_url=str(REPORTS_DIR.parent)).write_pdf(str(out))
    return out


def list_reports(assessment_id: int) -> list[dict]:
    """Returns at most one entry per assessment (we only keep the latest)."""
    rdir = _report_dir(assessment_id)
    if not rdir.exists():
        return []
    out = []
    for p in sorted(rdir.glob("*.pdf"), reverse=True):
        st = p.stat()
        out.append({
            "filename": p.name,
            "size_bytes": st.st_size,
            "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc),
        })
    return out


def delete_report(assessment_id: int, filename: str) -> bool:
    """Delete a generated PDF report. Returns True if a file was removed.
    Validates the filename against the canonical pattern and resolves the
    target path, refusing anything that escapes the per-assessment dir."""
    if not REPORT_FILENAME_RE.match(filename):
        return False
    rdir = _report_dir(assessment_id).resolve()
    target = (rdir / filename).resolve()
    if not str(target).startswith(str(rdir)):
        return False
    if not target.exists():
        return False
    target.unlink()
    return True
