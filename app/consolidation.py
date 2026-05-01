# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Assessment-level LLM consolidation (the "basic" tier roll-up).

Given a finished assessment with raw findings already inserted, this module
asks the LLM to produce:
  - an executive summary (prose, 2-4 paragraphs)
  - an overall risk_score 0-100
  - a short list of top remediation priorities

Cost-optimization rules baked in here, in priority order:

  1. Skip the LLM entirely when there's nothing to summarize. Zero findings
     gets a deterministic stub; we still record an llm_analyses row so the
     UI surfaces the run, but it's free.

  2. Compress findings before sending. A scanner can produce hundreds of
     near-duplicate rows that all point at the same root cause; we group by
     enrichment signature (already deduped at insert time) and send a tight
     bucket per signature: title, severity, owasp, count, sample_url. The
     LLM does not need every individual evidence URL to write a roll-up.

  3. Cap the input. If an assessment somehow ends up with thousands of
     unique signatures, take the top MAX_BUCKETS_FOR_LLM by severity-then-
     count and tell the LLM how many were truncated. The exec summary value
     comes from the worst findings, not the long tail.

  4. Tight output budget. CONSOLIDATE_MAX_OUTPUT_TOKENS keeps the response
     bounded — output tokens are 5x more expensive than input on Opus.

  5. Strict JSON output via a dedicated system prompt — saves the cost of
     re-trying on parse failures, and avoids prose padding that inflates
     output billing.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Optional

import db
import llm as llm_mod


# ---- Tunables ---------------------------------------------------------------
# Hard ceiling on how many distinct signature-buckets we send to the LLM in
# one call. With dedup most assessments come in well under this, so it acts
# as a budget guardrail rather than a normal-case cap.
MAX_BUCKETS_FOR_LLM = 120
# Output token cap. The exec summary + risk score + top priorities fit
# comfortably in 1500. Anything longer is the model padding.
CONSOLIDATE_MAX_OUTPUT_TOKENS = 1500
# Per-bucket text we send to the LLM. Long evidence URLs get truncated since
# the LLM doesn't need the query string to understand the finding.
EVIDENCE_URL_MAX = 200


# ---- Prompts ----------------------------------------------------------------
# The system prompt is intentionally kept under the Anthropic prompt-cache
# minimum (1024 tokens) — caching one call per assessment provides no
# meaningful savings, so we skip the cache_control hassle here. If we ever
# move to per-finding LLM analysis at scale, add cache_system=True there.
CONSOLIDATE_SYSTEM_PROMPT = """You are a senior application security consultant writing the executive summary for a DAST scan report. Your audience is a CISO / security manager who needs to quickly understand: what is the security posture of the scanned application, what are the most important things to fix, and how bad is it overall.

You will receive a deduplicated list of findings produced by automated scanners (testssl, nuclei, nikto, wapiti) and any LLM-assisted findings. Each finding includes title, severity, OWASP category, count (how many times it appeared), and one sample evidence URL.

Respond with a single JSON object matching this exact schema (no markdown fences, no commentary):

{
  "exec_summary": "2-4 short paragraphs of plain English. Lead with the overall posture statement, then the most important systemic patterns (e.g., 'access control is misconfigured at the webserver layer'), then the technical highlights. Avoid restating raw counts that the report already shows. Avoid jargon unless you immediately explain it.",
  "risk_score": <integer 0-100>,
  "top_priorities": [
    {
      "title": "<short imperative phrase, e.g. 'Fix htaccess bypass on vendor endpoints'>",
      "rationale": "<one sentence: why this is the top priority above other findings>",
      "owasp_category": "<the OWASP category most relevant>"
    }
  ]
}

Risk score anchors:
  0-19   = no meaningful issues found
  20-39  = minor hardening opportunities, no exploitable issues
  40-59  = real issues but no clear path to compromise
  60-79  = exploitable weaknesses present, requires urgent remediation
  80-100 = critical issues likely to lead to compromise; treat as incident

Top priorities should be 3-5 items. Order them by what to fix first.

Punctuation: do NOT use em-dashes ("--", "—") or en-dashes ("–"). Use commas, colons, semicolons, or two separate sentences instead. Use US English spelling (e.g. "artifact", not "artefact").

Output only the JSON object."""


CONSOLIDATE_USER_TEMPLATE = """Target: {fqdn}
Profile: {profile}
Total raw findings: {total_findings}
Unique signatures sent below: {n_buckets}{truncation_note}

Findings (already deduplicated; each row aggregates count occurrences):

{buckets}

Generate the consolidation JSON now."""


# ---- Helpers ----------------------------------------------------------------

_SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _now() -> datetime:
    """Naive UTC — pymysql binds this directly to MariaDB DATETIME columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fetch_buckets(aid: int) -> list[dict]:
    """Pull deduplicated finding buckets for an assessment.

    Two findings share a bucket iff they share the same enrichment_id (which
    is what the per-finding pipeline uses to dedup at insert time). For
    findings that never got an enrichment row (shouldn't happen in normal
    flow — get_or_create always returns one), we fall back to grouping by
    title/severity/source_tool so the roll-up still sees them.
    """
    rows = db.query("""
        SELECT
            f.enrichment_id,
            COALESCE(fe.title_norm, f.title)            AS title,
            f.severity,
            f.source_tool,
            COALESCE(fe.owasp_category, f.owasp_category) AS owasp_category,
            COALESCE(fe.cwe, f.cwe)                      AS cwe,
            COUNT(*)                                     AS occurrence_count,
            MIN(f.evidence_url)                          AS sample_url,
            MAX(fe.suggested_priority)                   AS suggested_priority
        FROM findings f
        LEFT JOIN finding_enrichment fe ON fe.id = f.enrichment_id
        WHERE f.assessment_id = %s
        GROUP BY f.enrichment_id, f.title, f.severity, f.source_tool,
                 fe.owasp_category, f.owasp_category, fe.cwe, f.cwe,
                 fe.title_norm
    """, (aid,))
    # Sort: critical first, then by count descending. Stable so the prompt
    # is deterministic across runs of the same assessment.
    rows.sort(key=lambda r: (
        _SEVERITY_ORDER.get(r["severity"], 9),
        -int(r["occurrence_count"] or 0),
        r["title"] or "",
    ))
    return rows


def _compact_buckets(buckets: list[dict]) -> tuple[list[dict], int]:
    """Trim to MAX_BUCKETS_FOR_LLM and shape each bucket to the minimum
    fields the LLM needs. Returns (kept_buckets, truncated_count)."""
    truncated = max(0, len(buckets) - MAX_BUCKETS_FOR_LLM)
    kept = buckets[:MAX_BUCKETS_FOR_LLM]
    compact = []
    for b in kept:
        url = (b.get("sample_url") or "")[:EVIDENCE_URL_MAX]
        compact.append({
            "title": b.get("title") or "",
            "severity": b.get("severity") or "info",
            "tool": b.get("source_tool") or "",
            "owasp": b.get("owasp_category") or "",
            "cwe": b.get("cwe") or "",
            "count": int(b.get("occurrence_count") or 1),
            "sample_url": url,
        })
    return compact, truncated


def _render_buckets_for_prompt(compact: list[dict]) -> str:
    """One bucket per line, fixed order of fields, no trailing whitespace."""
    out = []
    for b in compact:
        out.append(
            f"- [{b['severity'].upper()}] {b['title']}"
            f"  (tool={b['tool']}, owasp={b['owasp'] or '-'}, "
            f"cwe={b['cwe'] or '-'}, count={b['count']}, "
            f"url={b['sample_url'] or '-'})"
        )
    return "\n".join(out)


def _empty_summary() -> dict:
    """Deterministic stub used when an assessment has zero findings.

    No LLM call is made. We still return a dict that mirrors the LLM output
    shape so the rest of the pipeline doesn't need a special case."""
    return {
        "exec_summary": (
            "No findings were produced by the configured scanners. This is "
            "either a clean target or, more commonly, a target where the "
            "scanners could not reach the application (network, auth, or "
            "scope misconfiguration). Verify that the target is reachable "
            "and the auth profile is correct, then re-run the assessment."
        ),
        "risk_score": 0,
        "top_priorities": [],
    }


def _parse_llm_payload(content: str) -> Optional[dict]:
    """Strip markdown fences and parse the JSON object the LLM should have
    returned. Returns None on failure — caller decides how to recover."""
    if not content:
        return None
    s = content.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except json.JSONDecodeError:
        # last-ditch: extract the first {...} object substring
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                v = json.loads(m.group(0))
                return v if isinstance(v, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _strip_dashes(text: str) -> str:
    """Replace em-dashes / en-dashes / double-hyphen-as-dash with commas in
    LLM-produced narrative text. The system prompt forbids these, but
    models occasionally relapse, so we sanitise the output as well.

    Rules:
      * U+2014 (em-dash, "—") and U+2013 (en-dash, "–") become ", ",
        consuming any whitespace that surrounded the dash so we don't
        leave " , " straddling the punctuation.
      * The two-character ASCII "--" becomes ", " ONLY when surrounded by
        word characters (so it doesn't eat list-item dashes or option
        flags inside example commands the LLM might quote).
      * Stray double spaces produced by the substitution are collapsed.
    """
    if not text:
        return text
    # Em / en dash with optional surrounding whitespace -> ", "
    out = re.sub(r"\s*[—–]\s*", ", ", text)
    out = re.sub(r"(?<=\w)\s*--\s*(?=\w)", ", ", out)
    # Collapse runs of whitespace introduced by the substitution. We
    # preserve newlines so paragraph breaks survive.
    out = re.sub(r"[ \t]{2,}", " ", out)
    # ", ," from chained substitutions collapses to a single comma.
    out = re.sub(r",\s*,", ",", out)
    return out


def _validate_payload(payload: dict) -> dict:
    """Coerce / clamp untrusted LLM output to the expected shape and ranges."""
    score_raw = payload.get("risk_score")
    try:
        score = int(score_raw)
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))

    summary = _strip_dashes((payload.get("exec_summary") or "").strip())
    priorities_raw = payload.get("top_priorities") or []
    priorities: list[dict] = []
    if isinstance(priorities_raw, list):
        for p in priorities_raw[:8]:  # never trust the LLM to honor caps
            if not isinstance(p, dict):
                continue
            priorities.append({
                "title": _strip_dashes((p.get("title") or "").strip())[:200],
                "rationale": _strip_dashes((p.get("rationale") or "").strip())[:500],
                "owasp_category": (p.get("owasp_category") or "").strip()[:64],
            })
    return {
        "exec_summary": summary,
        "risk_score": score,
        "top_priorities": priorities,
    }


# ---- Main entrypoint --------------------------------------------------------

def run(aid: int, endpoint: Optional[dict]) -> dict:
    """Run the consolidation pass for one assessment.

    Returns a dict with keys: ok, payload, in_tokens, out_tokens, cost_usd,
    error (if not ok). Always writes one row to llm_analyses (even on the
    free zero-findings path) so the UI can show that consolidation ran.
    Always updates the assessments row with exec_summary / risk_score /
    cost / token totals.

    Caller (the orchestrator) is responsible for setting status='consolidating'
    before invoking and status='done' after.
    """
    assessment = db.query_one(
        "SELECT id, fqdn, profile, total_findings FROM assessments WHERE id=%s",
        (aid,),
    )
    if not assessment:
        return {"ok": False, "error": f"no such assessment {aid}"}

    buckets = _fetch_buckets(aid)
    compact, truncated = _compact_buckets(buckets)

    started_at = _now()

    # Free path: no findings to summarize — emit a deterministic stub and
    # avoid any LLM call. Still record the run for transparency.
    if not compact:
        stub = _empty_summary()
        analysis_id = _record_analysis(
            aid=aid, endpoint=endpoint, status="done",
            in_tokens=0, out_tokens=0, payload=stub,
            started_at=started_at, error_text=None, raw=None,
        )
        _apply_to_assessment(aid, stub, in_tokens=0, out_tokens=0,
                             cost_usd=0.0)
        return {"ok": True, "payload": stub, "in_tokens": 0, "out_tokens": 0,
                "cost_usd": 0.0, "analysis_id": analysis_id, "skipped_llm": True}

    # No endpoint configured — degrade gracefully. The orchestrator only
    # calls us when llm_tier in (basic, advanced), but the endpoint may
    # have been deleted between assessment creation and consolidation.
    if not endpoint:
        err = "no LLM endpoint configured; skipping consolidation"
        analysis_id = _record_analysis(
            aid=aid, endpoint=None, status="error",
            in_tokens=0, out_tokens=0, payload=None,
            started_at=started_at, error_text=err, raw=None,
        )
        return {"ok": False, "error": err, "analysis_id": analysis_id}

    truncation_note = (f"\n(NOTE: {truncated} additional unique signatures "
                       f"were omitted from this list due to volume. They are "
                       f"included in the raw report.)") if truncated else ""

    user_prompt = CONSOLIDATE_USER_TEMPLATE.format(
        fqdn=assessment["fqdn"],
        profile=assessment.get("profile") or "standard",
        total_findings=assessment.get("total_findings") or 0,
        n_buckets=len(compact),
        truncation_note=truncation_note,
        buckets=_render_buckets_for_prompt(compact),
    )

    backend = endpoint.get("backend")
    model = endpoint.get("model") or ""
    if backend == "anthropic":
        result = llm_mod.call_anthropic(
            endpoint["api_key"], model,
            CONSOLIDATE_SYSTEM_PROMPT, user_prompt,
            max_tokens=CONSOLIDATE_MAX_OUTPUT_TOKENS,
        )
    elif backend == "openai_compat":
        extra = {}
        if endpoint.get("extra_headers"):
            try:
                extra = json.loads(endpoint["extra_headers"])
            except Exception:
                extra = {}
        result = llm_mod.call_openai_compat(
            endpoint["base_url"], endpoint["api_key"], model,
            CONSOLIDATE_SYSTEM_PROMPT, user_prompt,
            max_tokens=CONSOLIDATE_MAX_OUTPUT_TOKENS,
            extra_headers=extra,
        )
    else:
        err = f"unknown backend: {backend}"
        _record_analysis(aid=aid, endpoint=endpoint, status="error",
                         in_tokens=0, out_tokens=0, payload=None,
                         started_at=started_at, error_text=err, raw=None)
        return {"ok": False, "error": err}

    in_tokens = int(result.get("in_tokens") or 0)
    out_tokens = int(result.get("out_tokens") or 0)
    cached_in = int(result.get("cache_read_tokens") or 0)
    cost_usd = llm_mod.cost(in_tokens, out_tokens, model,
                            cached_in_tokens=cached_in)

    if not result.get("ok"):
        err = result.get("error") or "LLM call failed"
        _record_analysis(aid=aid, endpoint=endpoint, status="error",
                         in_tokens=in_tokens, out_tokens=out_tokens,
                         payload=None, started_at=started_at,
                         error_text=err, raw=result.get("raw"))
        return {"ok": False, "error": err, "in_tokens": in_tokens,
                "out_tokens": out_tokens, "cost_usd": cost_usd}

    parsed = _parse_llm_payload(result.get("content", ""))
    if not parsed:
        err = "LLM returned unparseable consolidation output"
        _record_analysis(aid=aid, endpoint=endpoint, status="error",
                         in_tokens=in_tokens, out_tokens=out_tokens,
                         payload=None, started_at=started_at,
                         error_text=err, raw=result.get("raw"))
        return {"ok": False, "error": err, "in_tokens": in_tokens,
                "out_tokens": out_tokens, "cost_usd": cost_usd}

    payload = _validate_payload(parsed)
    analysis_id = _record_analysis(
        aid=aid, endpoint=endpoint, status="done",
        in_tokens=in_tokens, out_tokens=out_tokens,
        payload=payload, started_at=started_at,
        error_text=None, raw=result.get("raw"),
    )
    _apply_to_assessment(aid, payload, in_tokens=in_tokens,
                         out_tokens=out_tokens, cost_usd=cost_usd)
    return {"ok": True, "payload": payload, "in_tokens": in_tokens,
            "out_tokens": out_tokens, "cost_usd": cost_usd,
            "analysis_id": analysis_id}


# ---- Persistence ------------------------------------------------------------

def _record_analysis(*, aid: int, endpoint: Optional[dict], status: str,
                     in_tokens: int, out_tokens: int,
                     payload: Optional[dict], started_at: datetime,
                     error_text: Optional[str], raw: Optional[str]) -> int:
    """Insert an llm_analyses row for this consolidation pass.

    target_type='scan' so the same table can hold per-flow analyses (target_
    type='flow') in the advanced tier — no schema migration needed.
    target_id is namespaced 'assessment:<id>' to avoid colliding with raw
    scan IDs that the per-flow path will use."""
    return db.execute("""
        INSERT INTO llm_analyses
            (target_type, target_id, endpoint_id, endpoint_name, model,
             status, request_tokens, response_tokens,
             raw_response, findings_json, error_text,
             created_at, finished_at)
        VALUES ('scan', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        f"assessment:{aid}",
        endpoint.get("id") if endpoint else None,
        endpoint.get("name") if endpoint else None,
        endpoint.get("model") if endpoint else None,
        status,
        in_tokens, out_tokens,
        raw,
        json.dumps(payload) if payload else None,
        error_text,
        started_at, _now(),
    ))


def _apply_to_assessment(aid: int, payload: dict, *,
                         in_tokens: int, out_tokens: int,
                         cost_usd: float) -> None:
    """Persist consolidation output back to the assessments row.

    We add to the existing token / cost columns rather than overwriting,
    so when the per-flow advanced pass runs first it isn't clobbered by
    the roll-up that follows. Existing values default to 0 via COALESCE."""
    db.execute("""
        UPDATE assessments
           SET exec_summary = %s,
               risk_score   = %s,
               llm_in_tokens  = COALESCE(llm_in_tokens, 0)  + %s,
               llm_out_tokens = COALESCE(llm_out_tokens, 0) + %s,
               llm_cost_usd   = COALESCE(llm_cost_usd, 0)   + %s
         WHERE id = %s
    """, (
        _format_summary_for_storage(payload),
        payload.get("risk_score") or 0,
        in_tokens, out_tokens, cost_usd,
        aid,
    ))


def _format_summary_for_storage(payload: dict) -> str:
    """Render the LLM payload to the plain-text exec_summary column.

    The schema stores exec_summary as LONGTEXT, and the existing report
    template renders it with white-space:pre-wrap. So we serialize the
    summary prose and the top-priority list as a readable plain-text
    block — no markdown, no JSON — that humans skim well."""
    parts = [payload.get("exec_summary") or ""]
    priorities = payload.get("top_priorities") or []
    if priorities:
        parts.append("")
        parts.append("Top priorities:")
        for i, p in enumerate(priorities, 1):
            cat = p.get("owasp_category") or ""
            cat_str = f" [{cat}]" if cat else ""
            parts.append(f"  {i}. {p.get('title','')}{cat_str}")
            if p.get("rationale"):
                parts.append(f"     {p['rationale']}")
    return "\n".join(parts).strip()
