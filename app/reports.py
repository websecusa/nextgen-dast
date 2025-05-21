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
    findings = [f for f in all_findings
                if f.get("status") != "false_positive"]

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


def _repro_for(f: dict) -> dict:
    """Build a 'reproduction steps' block for one finding, in a tool-aware
    way. Returns {curl, hint, references} where each is optional."""
    repro: dict = {}
    tool = f.get("source_tool", "")
    url = f.get("evidence_url") or ""
    method = (f.get("evidence_method") or "GET").upper()
    raw = f.get("raw") or {}

    if tool == "wapiti":
        param = raw.get("parameter") or ""
        # Render a representative curl. Wapiti-stored URLs already include
        # the injected parameter, so this is a "send the same request"
        # template; the user will substitute their session cookie.
        if url:
            curl = ["curl", "-i"]
            if method != "GET":
                curl += ["-X", method]
            curl += ["--cookie", "'<session-cookie>'", f"'{url}'"]
            repro["curl"] = " ".join(curl)
        if param:
            repro["hint"] = f"Vulnerable parameter: <code>{html.escape(param)}</code>"
    elif tool == "nuclei":
        tid = raw.get("template-id") or raw.get("templateID") or ""
        target = raw.get("matched-at") or raw.get("host") or url
        if tid and target:
            repro["curl"] = (
                f"nuclei -id {tid} -target '{target}'\n# template: "
                f"https://github.com/projectdiscovery/nuclei-templates/blob/main/"
            )
            repro["hint"] = f"Nuclei template: <code>{html.escape(tid)}</code>"
        elif target:
            repro["curl"] = f"curl -i '{target}'"
    elif tool == "nikto":
        if url:
            repro["curl"] = f"curl -i '{url}'"
        rid = (raw or {}).get("id")
        if rid:
            repro["hint"] = f"Nikto check ID: <code>{rid}</code>"
    elif tool == "testssl":
        host = url or ""
        if host:
            repro["curl"] = f"testssl.sh '{host}'"
    elif tool == "sqlmap":
        if url:
            repro["curl"] = f"sqlmap -u '{url}' --batch"
    elif tool == "dalfox":
        if url:
            repro["curl"] = f"dalfox url '{url}'"
    else:
        if url:
            repro["curl"] = f"curl -i '{url}'"

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
