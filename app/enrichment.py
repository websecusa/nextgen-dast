# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Finding enrichment: turns a sparse parser output (title + URL + maybe a CWE)
into ticket-ready remediation guidance — long description, impact, numbered
steps, code example, references, user story, and a markdown body suitable
for pasting into Jira / ServiceNow / GitHub Issues.

Lookup order on each finding:
  1. signature → cache hit in `finding_enrichment` (free)
  2. enrichment_catalog static entry           (free, deterministic)
  3. LLM call via the configured endpoint       (paid; cached on success)
  4. minimal stub                                (only when 1–3 all fail)

The cache key is a SHA-256 of (source_tool | normalized title | cwe |
owasp_category) — independent of assessment_id, so the same finding type
across every assessment in the system reuses the same enrichment row. A
manually edited row (`source='manual'`, `is_locked=1`) is never overwritten
by automatic enrichment.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

import db
import enrichment_catalog
import llm as llm_mod


# ---- signature -------------------------------------------------------------

_TITLE_NORM_RE = re.compile(r"\s+")


def normalize_title(title: str) -> str:
    """Lowercase, collapse whitespace, strip surrounding punctuation. Keeps
    the title stable across small formatting variations from the same tool."""
    if not title:
        return ""
    t = title.strip().lower()
    t = _TITLE_NORM_RE.sub(" ", t)
    return t[:500]


def signature(finding: dict) -> str:
    parts = [
        (finding.get("source_tool") or "").lower(),
        normalize_title(finding.get("title") or ""),
        (finding.get("cwe") or "").strip(),
        (finding.get("owasp_category") or "").strip(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# ---- cache lookup / write --------------------------------------------------

def get_cached(sig: str) -> Optional[dict]:
    return db.query_one(
        "SELECT * FROM finding_enrichment WHERE signature_hash = %s", (sig,))


def _insert(sig: str, finding: dict, payload: dict, *, source: str,
            llm_endpoint_id: Optional[int] = None,
            llm_model: Optional[str] = None,
            llm_in_tokens: Optional[int] = None,
            llm_out_tokens: Optional[int] = None) -> int:
    """Write an enrichment row. Returns the new row id. If a row with the
    same signature already exists (race or re-run), returns the existing id."""
    existing = get_cached(sig)
    if existing:
        return existing["id"]
    return db.execute(
        """INSERT INTO finding_enrichment
           (signature_hash, source_tool, title_norm, cwe, owasp_category,
            source, is_locked,
            description_long, impact, remediation_long, remediation_steps,
            code_example, references_json,
            user_story, bug_report_md, jira_summary, suggested_priority,
            llm_endpoint_id, llm_model, llm_in_tokens, llm_out_tokens)
           VALUES (%s,%s,%s,%s,%s,%s,0,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            sig,
            (finding.get("source_tool") or "")[:64],
            normalize_title(finding.get("title") or "")[:512],
            (finding.get("cwe") or None),
            (payload.get("owasp_category") or finding.get("owasp_category") or None),
            source,
            payload.get("description_long") or "",
            payload.get("impact") or "",
            payload.get("remediation_long") or "",
            json.dumps(payload.get("remediation_steps") or []),
            payload.get("code_example") or "",
            json.dumps(payload.get("references") or []),
            payload.get("user_story") or "",
            payload.get("bug_report_md") or build_bug_report_md(finding, payload),
            payload.get("jira_summary") or build_jira_summary(finding, payload),
            payload.get("suggested_priority") or _priority_for(finding),
            llm_endpoint_id, llm_model, llm_in_tokens, llm_out_tokens,
        ),
    )


# ---- ticket-ready body builders --------------------------------------------

_SEV_TO_PRIORITY = {
    "critical": "p0", "high": "p1", "medium": "p2",
    "low": "p3", "info": "p4",
}


def _priority_for(finding: dict) -> str:
    return _SEV_TO_PRIORITY.get((finding.get("severity") or "info").lower(), "p3")


def build_jira_summary(finding: dict, payload: dict) -> str:
    sev = (finding.get("severity") or "info").upper()
    title = finding.get("title") or "security finding"
    s = f"[{sev}] {title}"
    return s[:255]


def build_bug_report_md(finding: dict, payload: dict) -> str:
    """Construct a markdown body that pastes cleanly into Jira / ServiceNow /
    GitHub. Format is intentionally portable."""
    lines: list[str] = []
    sev = (finding.get("severity") or "info").upper()
    title = finding.get("title") or "Security finding"
    lines.append(f"## {title}")
    lines.append("")
    meta_bits = [f"**Severity:** {sev}"]
    if finding.get("owasp_category") or payload.get("owasp_category"):
        meta_bits.append(f"**OWASP:** {finding.get('owasp_category') or payload.get('owasp_category')}")
    if finding.get("cwe"):
        meta_bits.append(f"**CWE:** CWE-{finding['cwe']}")
    if finding.get("cvss"):
        meta_bits.append(f"**CVSS:** {finding['cvss']}")
    if finding.get("source_tool"):
        meta_bits.append(f"**Detected by:** {finding['source_tool']}")
    lines.append("  ".join(meta_bits))
    lines.append("")
    if finding.get("evidence_url"):
        lines.append("### Evidence")
        meth = finding.get("evidence_method") or "GET"
        lines.append(f"`{meth} {finding['evidence_url']}`")
        lines.append("")
    if payload.get("description_long"):
        lines.append("### Description")
        lines.append(payload["description_long"])
        lines.append("")
    if payload.get("impact"):
        lines.append("### Impact")
        lines.append(payload["impact"])
        lines.append("")
    if payload.get("remediation_long"):
        lines.append("### Remediation")
        lines.append(payload["remediation_long"])
        lines.append("")
    steps = payload.get("remediation_steps") or []
    if steps:
        lines.append("### Steps")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
    if payload.get("code_example"):
        lines.append("### Example")
        lines.append("```")
        lines.append(payload["code_example"])
        lines.append("```")
        lines.append("")
    refs = payload.get("references") or []
    if refs:
        lines.append("### References")
        for r in refs:
            lines.append(f"- {r}")
        lines.append("")
    if payload.get("user_story"):
        lines.append("### User story")
        lines.append(f"> {payload['user_story']}")
        lines.append("")
    return "\n".join(lines).strip()


# ---- LLM enrichment --------------------------------------------------------

LLM_SYSTEM_PROMPT = """You are a senior application security engineer writing remediation guidance for a developer who has never seen this finding before. The finding came from an automated scanner; you must turn it into something actionable.

Respond with a single JSON object matching this exact schema (no markdown fences, no commentary):

{
  "description_long": "2-4 sentences: what this finding actually means in plain language. Avoid jargon unless you explain it.",
  "impact": "1-3 sentences: concrete consequences if this is left unfixed. Tie to data, users, or systems.",
  "remediation_long": "1-3 sentences: the strategic fix. The 'how to think about this'.",
  "remediation_steps": ["concrete step 1", "concrete step 2", "..."],
  "code_example": "language-appropriate snippet showing the right way (or '' if not applicable)",
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/...", "vendor docs..."],
  "user_story": "As a <role>, I want <capability> so that <outcome>. One sentence.",
  "suggested_priority": "p0|p1|p2|p3|p4"
}

Steps must be specific enough that a developer can do them without further research. References must be real URLs. Output only the JSON object."""


LLM_USER_TEMPLATE = """Finding from automated scanner:

  Tool: {tool}
  Severity: {severity}
  Title: {title}
  OWASP category: {owasp}
  CWE: {cwe}
  Evidence: {evidence}
  Description from tool: {desc}

Generate the enrichment JSON now."""


def enrich_via_llm(finding: dict, endpoint: dict) -> Optional[dict]:
    """Call the configured LLM and return a parsed payload dict, or None on
    failure. Caller decides what to do with the failure."""
    user = LLM_USER_TEMPLATE.format(
        tool=finding.get("source_tool") or "",
        severity=finding.get("severity") or "",
        title=finding.get("title") or "",
        owasp=finding.get("owasp_category") or "(unknown)",
        cwe=("CWE-" + finding["cwe"]) if finding.get("cwe") else "(none)",
        evidence=(finding.get("evidence_url") or "(none)")[:500],
        desc=(finding.get("description") or "")[:1500],
    )
    backend = endpoint["backend"]
    if backend == "anthropic":
        result = llm_mod.call_anthropic(endpoint["api_key"], endpoint["model"],
                                        LLM_SYSTEM_PROMPT, user,
                                        max_tokens=2048)
    elif backend == "openai_compat":
        extra = {}
        if endpoint.get("extra_headers"):
            try:
                extra = json.loads(endpoint["extra_headers"])
            except Exception:
                extra = {}
        result = llm_mod.call_openai_compat(
            endpoint["base_url"], endpoint["api_key"], endpoint["model"],
            LLM_SYSTEM_PROMPT, user, max_tokens=2048, extra_headers=extra,
        )
    else:
        return None
    if not result.get("ok"):
        return None
    try:
        content = result.get("content", "").strip()
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        payload = json.loads(content)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    payload["_in_tokens"] = result.get("in_tokens")
    payload["_out_tokens"] = result.get("out_tokens")
    return payload


# ---- top-level entry point -------------------------------------------------

def get_or_create(finding: dict, endpoint: Optional[dict]) -> Optional[int]:
    """Return the enrichment_id for this finding, creating it if needed.

    Cache hits short-circuit. On miss: try the static catalog first; if that
    misses, try the LLM (when an endpoint is configured); if that fails too,
    insert a minimal stub so downstream code always has something to render."""
    sig = signature(finding)
    cached = get_cached(sig)
    if cached:
        return cached["id"]

    static = enrichment_catalog.lookup(
        finding.get("source_tool") or "",
        normalize_title(finding.get("title") or ""),
        finding.get("owasp_category"),
    )
    if static:
        return _insert(sig, finding, static, source="static")

    if endpoint:
        payload = enrich_via_llm(finding, endpoint)
        if payload:
            return _insert(
                sig, finding, payload,
                source="llm",
                llm_endpoint_id=endpoint.get("id"),
                llm_model=endpoint.get("model"),
                llm_in_tokens=payload.get("_in_tokens"),
                llm_out_tokens=payload.get("_out_tokens"),
            )

    # Last resort: a stub. Better than blank, and the next assessment with a
    # working LLM endpoint can replace it (since is_locked=0).
    stub = {
        "description_long": (finding.get("description") or
                             f"Automated scanner '{finding.get('source_tool')}' "
                             f"reported: {finding.get('title')}."),
        "impact": "Refer to OWASP / CWE classification for general guidance.",
        "remediation_long": (
            "No specific remediation has been generated yet. Investigate the "
            "evidence URL manually, consult the linked OWASP / CWE resources, "
            "or add a manual entry on this finding to populate guidance for "
            "all future occurrences."),
        "remediation_steps": [],
        "references": [
            f"https://owasp.org/Top10/{finding['owasp_category'].split(':')[0]}_2021/"
            if finding.get("owasp_category") else
            "https://owasp.org/www-project-top-ten/",
        ],
    }
    return _insert(sig, finding, stub, source="static")


# ---- manual override -------------------------------------------------------

EDITABLE_FIELDS = (
    "owasp_category", "cwe", "description_long", "impact",
    "remediation_long", "remediation_steps", "code_example",
    "references_json", "user_story", "bug_report_md", "jira_summary",
    "suggested_priority", "notes",
)


def update_manual(enrichment_id: int, edits: dict, user_id: Optional[int]) -> None:
    """Apply admin edits and mark the row source='manual', is_locked=1 so
    it isn't overwritten by future automatic enrichment."""
    sets: list[str] = []
    args: list = []
    for k, v in edits.items():
        if k not in EDITABLE_FIELDS:
            continue
        sets.append(f"{k} = %s")
        args.append(v)
    if not sets:
        return
    sets.append("source = 'manual'")
    sets.append("is_locked = 1")
    sets.append("edited_by_user_id = %s")
    args.append(user_id)
    args.append(enrichment_id)
    db.execute(
        f"UPDATE finding_enrichment SET {', '.join(sets)} WHERE id = %s",
        tuple(args),
    )


def create_manual_stub(finding: dict, edits: dict,
                       user_id: Optional[int]) -> int:
    """Create a manual enrichment row for a finding signature that doesn't
    yet have one. Used when an admin wants to author guidance up front."""
    sig = signature(finding)
    existing = get_cached(sig)
    if existing:
        update_manual(existing["id"], edits, user_id)
        return existing["id"]
    payload = {
        "description_long": edits.get("description_long", ""),
        "impact": edits.get("impact", ""),
        "remediation_long": edits.get("remediation_long", ""),
        "remediation_steps": edits.get("remediation_steps") or [],
        "code_example": edits.get("code_example", ""),
        "references": edits.get("references") or [],
        "user_story": edits.get("user_story", ""),
        "suggested_priority": edits.get("suggested_priority"),
        "owasp_category": edits.get("owasp_category") or finding.get("owasp_category"),
    }
    new_id = _insert(sig, finding, payload, source="manual")
    db.execute(
        "UPDATE finding_enrichment SET is_locked = 1, edited_by_user_id = %s "
        "WHERE id = %s", (user_id, new_id))
    return new_id


# ---- export helpers (for ticket integrations) ------------------------------

def render_export(enrichment: dict, finding: dict, fmt: str) -> tuple[str, str]:
    """Render a finding+enrichment for export. Returns (content_type, body).
    Supported formats: jira, servicenow, github, csv."""
    fmt = (fmt or "jira").lower()
    if fmt in ("jira", "github", "markdown"):
        return "text/markdown; charset=utf-8", enrichment.get("bug_report_md") or ""
    if fmt == "servicenow":
        # ServiceNow Incident description is plain text or HTML; we ship a
        # plain-text rendering so it pastes everywhere.
        body = re.sub(r"^#+\s*", "", enrichment.get("bug_report_md") or "",
                      flags=re.MULTILINE)
        body = re.sub(r"```", "", body)
        return "text/plain; charset=utf-8", body
    if fmt == "csv":
        # One row, suitable for bulk-import into a tracker.
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["summary", "priority", "severity", "owasp", "cwe",
                    "evidence", "description", "remediation"])
        w.writerow([
            enrichment.get("jira_summary") or finding.get("title") or "",
            enrichment.get("suggested_priority") or "",
            (finding.get("severity") or "").upper(),
            finding.get("owasp_category") or enrichment.get("owasp_category") or "",
            ("CWE-" + finding["cwe"]) if finding.get("cwe") else "",
            finding.get("evidence_url") or "",
            (enrichment.get("description_long") or "").replace("\n", " "),
            (enrichment.get("remediation_long") or "").replace("\n", " "),
        ])
        return "text/csv; charset=utf-8", buf.getvalue()
    return "text/plain; charset=utf-8", enrichment.get("bug_report_md") or ""
