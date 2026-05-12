# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Agentic AI deep-dive pass.

Architecture
============
Two distinct modes share the same plumbing:

  - per_finding(aid, finding_id, ...):
      Run a tool-calling LLM agent against a single open finding.
      The agent is seeded with the finding's title / description /
      evidence_url / raw_data, the authorized-role context, and a
      bounded HTTP tool palette. It drives real requests against the
      target to confirm or expand the finding, then emits one or more
      child findings (source_tool='agentic_ai_testing',
      raw_data.agent_mode='per_finding', raw_data.parent_finding_id=<id>).
      Runs against the top-N findings ordered by severity; N is the
      assessment's agentic_deep_dive_count (default 5).

  - free_roam(aid, ...):
      Run a single agent seeded with the role context + an open-
      findings digest + a request-clusters digest, with a larger HTTP
      budget. The agent explores the surface for misses the probes
      and weakness-discovery scenarios didn't cover. Only runs when
      the assessment has agentic_extra=1. Emits findings with
      raw_data.agent_mode='free_roam'.

Both modes use the Anthropic tool-use protocol. The HTTP tool palette
is wrapped around a SafeClient bounded by per-mode request caps and
restricted to the assessment's scope hosts. Write methods are gated
by a payload allowlist (no DELETE, no transfers, no password-reset to
real users). All requests go through the same SafeClient infrastructure
the validation probes use; the session cookie is sourced from
auth.form_login_cookie() the same way challenge_runner does.

Budget
======
Cost accounting flows into llm_analyses the same way
enhanced_ai_testing does. The per-assessment budget cap
(assessments.enhanced_ai_budget_usd) is shared across all LLM passes;
when agentic_extra=1 the cap is automatically doubled at the
orchestrator level so the free-roam pass has its own room.

Model
=====
The model used by the agent is picked from the env var
NEXTGEN_DAST_AGENTIC_MODEL (default 'claude-sonnet-4-6'). The API key
comes from whichever llm_endpoint the assessment is using (must be
an 'anthropic' backend; we fall back to the default endpoint when
the assessment didn't pin one). This makes model swaps a `.env`
edit + restart rather than a code change.

Failure isolation
=================
The orchestrator wraps the agentic pass in a try/except so any
internal failure -- bad tool input from the LLM, transient API
error, JSON parse failure -- never propagates out and blocks the
consolidation pass. Errors are appended to the assessment's
error_text instead.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import db
import dedup as dedup_mod
import enrichment as enrichment_mod
import llm as llm_mod
import llm_budget

logger = logging.getLogger(__name__)

DEFAULT_AGENTIC_MODEL = "claude-sonnet-4-6"

# Hard caps. Per-finding mode keeps its HTTP budget tight because we
# want N parallel agent runs to fit comfortably under the assessment's
# enhanced_ai_budget_usd. Free-roam gets a bigger surface because it
# is explicitly opted into via the "Extra Agentic" checkbox and its
# budget is doubled at the orchestrator level.
PER_FINDING_HTTP_MAX = 25
FREE_ROAM_HTTP_MAX = 80
# Cap on conversation turns. Each turn is one LLM call + zero-or-many
# tool executions. Higher than HTTP_MAX because the LLM may also emit
# `emit_finding` / `finish` tool calls which don't count toward HTTP.
PER_FINDING_TURN_MAX = 30
FREE_ROAM_TURN_MAX = 60
# Cap per-tool-result body so a single huge response can't blow the
# context window. The agent gets enough to reason about; the full
# response is still captured in the proxy log.
TOOL_RESULT_BODY_CHARS = 8000
# Anthropic max_tokens per turn. Tool-use turns are short so 2K is
# fine; the agent can iterate if it needs more.
TURN_MAX_TOKENS = 2048


# ---------------------------------------------------------------------------
# Tool palette
# ---------------------------------------------------------------------------
# Each entry follows Anthropic's tool_use input_schema convention. The
# `name` is what the LLM calls in its tool_use blocks; we dispatch on
# it in _execute_tool below. Keep descriptions tight -- they ride in
# every tool-loop turn's prompt and contribute to input-token cost.

_HTTP_HEADERS_PROP = {
    "type": "object",
    "description": "Optional extra request headers as a flat string->string map.",
    "additionalProperties": {"type": "string"},
}

_HTTP_BODY_PROP = {
    "type": "object",
    "description": "JSON request body. Must be a valid JSON object.",
}

TOOL_PALETTE = [
    {
        "name": "http_get",
        "description": (
            "GET an absolute URL on the target host. Returns "
            "{status, headers, body}. Use this to fetch endpoints, "
            "enumerate collection responses, and confirm hypotheses. "
            "Body is truncated to ~8KB; only the visible portion is "
            "returned to you."),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string",
                        "description": "Absolute URL to fetch."},
                "headers": _HTTP_HEADERS_PROP,
            },
            "required": ["url"],
        },
    },
    {
        "name": "http_post_json",
        "description": (
            "POST an absolute URL with a JSON body. Returns "
            "{status, headers, body}. Use this for mass-assignment "
            "tests, prototype-pollution probes, NoSQL injection on "
            "JSON-body endpoints, and similar write-shaped checks. "
            "Body must be a JSON object; arrays / strings are not "
            "accepted. Destructive payloads (deletions, transfers, "
            "password resets to real users) are rejected by the "
            "safety layer."),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "body": _HTTP_BODY_PROP,
                "headers": _HTTP_HEADERS_PROP,
            },
            "required": ["url", "body"],
        },
    },
    {
        "name": "http_put_json",
        "description": (
            "PUT an absolute URL with a JSON body. Returns "
            "{status, headers, body}. Use for vertical-authorization "
            "probes on existing records and mass-assignment on "
            "update endpoints."),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "body": _HTTP_BODY_PROP,
                "headers": _HTTP_HEADERS_PROP,
            },
            "required": ["url", "body"],
        },
    },
    {
        "name": "http_patch_json",
        "description": (
            "PATCH an absolute URL with a JSON body. Returns "
            "{status, headers, body}. Use for partial-update "
            "endpoints and NoSQL operator injection on PATCH "
            "(e.g. {\"id\": {\"$ne\": \"\"}})."),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "body": _HTTP_BODY_PROP,
                "headers": _HTTP_HEADERS_PROP,
            },
            "required": ["url", "body"],
        },
    },
    {
        "name": "http_options",
        "description": (
            "OPTIONS an absolute URL. Returns {status, headers}. Use "
            "to enumerate accepted methods on an endpoint."),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "emit_finding",
        "description": (
            "Record a confirmed security finding. ONLY call this when "
            "you have verbatim evidence in a captured response that "
            "proves the issue -- a quoted excerpt that shows the "
            "abuse, not a hypothesis. The evidence string must be a "
            "verbatim substring of a response body, request, or "
            "header line you already observed. If you do not have "
            "that, do not call emit_finding -- keep probing or call "
            "finish."),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string",
                              "enum": ["critical", "high", "medium", "low"]},
                "title": {"type": "string",
                           "description": "One-line summary, <=120 chars."},
                "evidence": {"type": "string",
                              "description":
                                  "Verbatim excerpt from a captured response, "
                                  "request, or header that proves the finding."},
                "description": {"type": "string",
                                 "description":
                                     "What was detected and why it matters."},
                "reproduction": {"type": "string",
                                  "description":
                                      "Step-by-step curl / PoC the analyst "
                                      "will run to reproduce. Use fenced code "
                                      "blocks for each command."},
                "remediation": {"type": "string",
                                 "description":
                                     "Concrete fix guidance: config flag, "
                                     "header value, library upgrade, code "
                                     "snippet."},
            },
            "required": ["severity", "title", "evidence", "description"],
        },
    },
    {
        "name": "finish",
        "description": (
            "Terminate the agent loop. Call this when you have either "
            "(a) emitted every finding you have verbatim evidence for, "
            "or (b) exhausted productive probing avenues. Include a "
            "short rationale so an analyst reviewing the run can "
            "understand why you stopped."),
        "input_schema": {
            "type": "object",
            "properties": {
                "rationale": {"type": "string"},
            },
            "required": ["rationale"],
        },
    },
]


# ---------------------------------------------------------------------------
# Safety layer
# ---------------------------------------------------------------------------

# Tokens we refuse to send anywhere -- prevents the agent from
# stumbling into a destructive payload even when the LLM "thinks" it's
# being helpful. These match against the lowercased URL + body string.
_REFUSED_PATH_TOKENS = (
    "/delete", "/destroy", "/remove",
    "/transfer", "/payout", "/withdraw",
    "/reset-password", "/forgot-password",
    "/api/cancel", "/api/refund",
)
# Method-level deny: DELETE is irreversible; we never let the agent
# emit it. POST/PUT/PATCH are allowed but go through the per-payload
# allowlist below.
_REFUSED_METHODS = ("DELETE",)
# Body-substring deny: refuses payloads that look like destructive
# actions regardless of the endpoint path.
_REFUSED_BODY_TOKENS = (
    '"deleted":true', '"delete":true', '"_destroy":', '"isDeleted":true',
    '"transfer_amount"', '"action":"delete"', '"action":"transfer"',
    '"action":"refund"',
)


def _safety_check(method: str, url: str, body: dict | None) -> str:
    """Return an empty string when the call is allowed; otherwise a
    short reason string the tool layer surfaces back to the LLM as
    the tool_result. Errs on the side of refusal -- the agent can
    rephrase and continue without crashing the run."""
    m = (method or "").upper()
    if m in _REFUSED_METHODS:
        return f"refused: method {m} is disabled by the agent safety layer"
    lower_url = (url or "").lower()
    for tok in _REFUSED_PATH_TOKENS:
        if tok in lower_url:
            return (f"refused: URL contains destructive path token "
                    f"{tok!r}; agent cannot exercise it")
    if body is not None:
        try:
            body_str = json.dumps(body, default=str).lower()
        except Exception:
            body_str = ""
        for tok in _REFUSED_BODY_TOKENS:
            if tok in body_str:
                return (f"refused: request body contains destructive "
                        f"token {tok!r}; agent cannot send it")
    return ""


# ---------------------------------------------------------------------------
# SafeClient construction
# ---------------------------------------------------------------------------

def _stop_requested(aid: int) -> bool:
    """Read the operator kill-switch column. Returns True when the
    "Stop agentic_ai_testing" button has been clicked for this
    assessment. A False return on a DB error is intentional: a
    transient query failure must not abort the agent (the alternative
    is to crash the loop on a network blip), so absence of evidence
    is treated as 'keep going'."""
    try:
        row = db.query_one(
            "SELECT agentic_stop_requested FROM assessments "
            "WHERE id=%s", (aid,))
    except Exception:
        return False
    if not row:
        return False
    return int(row.get("agentic_stop_requested") or 0) == 1


def _build_safeclient(scope_hosts: tuple[str, ...],
                      max_requests: int,
                      session_cookie: Optional[str],
                      allow_destructive: bool):
    """Construct a SafeClient bounded for the agent run. Importing
    the toolkit lib lazily avoids hard-binding this module's import
    path to the image-only /app/toolkit location."""
    sys.path.insert(0, "/app/toolkit")
    sys.path.insert(0, str(
        Path(__file__).resolve().parent.parent / "toolkit"))
    # Resolve via the same shim probes use.
    from enhanced_testing.lib import (   # type: ignore
        Probe as _Probe, SafeClient,    # noqa: F401
        Budget, AuditLog)               # noqa: F401
    budget = Budget(
        max_requests=max_requests,
        max_rps=5.0,
        scope_hosts=scope_hosts,
        allow_destructive=allow_destructive,
        dry_run=False,
    )
    audit = AuditLog()
    return SafeClient(budget, audit, cookie=session_cookie), audit, budget


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def _execute_tool(client, tool_name: str, tool_input: dict) -> dict:
    """Dispatch an LLM tool_use call against the SafeClient. Returns
    a dict suitable for serialising into a tool_result content field.

    Tool calls that violate the safety layer return a {"refused": ...}
    payload rather than raising; the LLM gets the reason back and can
    re-plan. SafeClient-internal exceptions (Budget tripped, scope
    violation, network error) are likewise captured into the result
    so a single tool failure never poisons the loop."""
    headers = tool_input.get("headers") or {}
    if tool_name == "http_get":
        url = tool_input.get("url", "")
        refused = _safety_check("GET", url, None)
        if refused:
            return {"refused": refused}
        try:
            r = client.request("GET", url, headers=headers)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        return {
            "status": r.status,
            "headers": dict(r.headers or {}),
            "body": (r.text or "")[:TOOL_RESULT_BODY_CHARS],
            "size": r.size,
        }
    if tool_name in ("http_post_json", "http_put_json", "http_patch_json"):
        method = {"http_post_json": "POST", "http_put_json": "PUT",
                  "http_patch_json": "PATCH"}[tool_name]
        url = tool_input.get("url", "")
        body = tool_input.get("body") or {}
        if not isinstance(body, dict):
            return {"refused": "body must be a JSON object"}
        refused = _safety_check(method, url, body)
        if refused:
            return {"refused": refused}
        try:
            req_headers = {"Content-Type": "application/json", **headers}
            r = client.request(method, url,
                               headers=req_headers,
                               body=json.dumps(body).encode())
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        return {
            "status": r.status,
            "headers": dict(r.headers or {}),
            "body": (r.text or "")[:TOOL_RESULT_BODY_CHARS],
            "size": r.size,
        }
    if tool_name == "http_options":
        url = tool_input.get("url", "")
        refused = _safety_check("OPTIONS", url, None)
        if refused:
            return {"refused": refused}
        try:
            r = client.request("OPTIONS", url, headers=headers)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        return {
            "status": r.status,
            "headers": dict(r.headers or {}),
            "size": r.size,
        }
    if tool_name in ("emit_finding", "finish"):
        # Caller-side handling -- this dispatcher only fields HTTP tools.
        return {"_meta": tool_name, "_input": tool_input}
    return {"error": f"unknown tool {tool_name!r}"}


# ---------------------------------------------------------------------------
# DB writes
# ---------------------------------------------------------------------------

def _insert_agentic_finding(aid: int, parent_finding_id: Optional[int],
                              agent_mode: str, payload: dict,
                              *, dedup_index: Optional[dict] = None
                              ) -> tuple:
    """Insert one LLM-emitted finding row with source_tool=
    'agentic_ai_testing'. Returns a (fid, refusal_reason) tuple:
      - (int, None) on success                     -- row inserted
      - (0, str)    when refused as a duplicate    -- caller reports
                    the reason back to the agent as a tool_result so
                    it pivots instead of retrying
      - (0, None)   when schema-validation failed  -- caller reports
                    a generic schema error to the agent

    `dedup_index` is the {signature: canonical} map built once at the
    top of the run (see `dedup_mod.build_signature_index`). When the
    candidate's signature is already present in the index, the row is
    refused before writing -- the agent gets the canonical id back so
    it can chain into deeper impact instead of duplicating coverage."""
    sev = (payload.get("severity") or "").lower()
    if sev not in ("critical", "high", "medium", "low"):
        return (0, None)
    title = (payload.get("title") or "").strip()[:500]
    if not title:
        return (0, None)
    description = (payload.get("description") or "").strip()
    evidence = (payload.get("evidence") or "").strip()
    reproduction = (payload.get("reproduction") or "").strip()
    remediation = (payload.get("remediation") or "").strip()
    if not description and evidence:
        description = f"Evidence: {evidence}"

    # ---- pre-emit dedup gate ------------------------------------
    # Build a synthetic finding shape so the same compute helper
    # used by the consolidation pass produces the same signature.
    candidate = {
        "title": title,
        "evidence_url": "",
        "raw_data": json.dumps({"llm_evidence": evidence}),
        "owasp_category": "",
    }
    sig = dedup_mod.compute_signature_for_finding(candidate)
    if sig and dedup_index is not None:
        canonical = dedup_index.get(sig)
        if canonical is not None:
            reason = (
                f"Refused as duplicate of finding "
                f"#{canonical['canonical_id']} '{canonical['title']}' "
                f"(already confirmed by {canonical['source_tool']}). "
                "Don't re-emit this bug -- investigate a different "
                "endpoint or chain it into deeper impact "
                "(e.g. exploit the leak you just confirmed instead of "
                "re-reporting it).")
            logger.info(
                "agentic_ai: dedup-refused emit on aid=%s sig=%r "
                "canonical=#%s (%s)",
                aid, sig, canonical["canonical_id"],
                canonical["source_tool"])
            return (0, reason)

    raw = {
        "agent_mode": agent_mode,
        "parent_finding_id": parent_finding_id,
        "llm_evidence": evidence,
        "llm_reproduction": reproduction,
        # Cache the signature on the row so the post-hoc consolidation
        # pass doesn't have to recompute it. Round 4C reads this.
        "dedup_signature_v2": sig,
    }
    db.execute(
        """INSERT INTO findings
               (assessment_id, source_tool, source_scan_id, severity,
                owasp_category, cwe, cvss, title, description,
                evidence_url, evidence_method, remediation, raw_data,
                seen_count)
           VALUES (%s, 'agentic_ai_testing', %s, %s, NULL, NULL, NULL,
                   %s, %s, NULL, NULL, %s, %s, 1)""",
        (aid, f"agentic:{agent_mode}", sev,
         title, description, remediation,
         json.dumps(raw, default=str)))
    new_id = db.query_one("SELECT LAST_INSERT_ID() AS id") or {"id": 0}
    fid = int(new_id.get("id") or 0)
    # Round 4B: enrich crit/high/medium AI-emitted findings so the
    # "Attacker workflow & exploitability" block (likelihood,
    # prerequisites, exploit chain, end-to-end narrative,
    # remediation) renders on these rows the same way it does on
    # deterministic scanner findings. Cache-keyed by signature so 5
    # different agent runs that legitimately emit findings of the
    # same type pay one LLM call total. Low/info findings skip
    # enrichment to keep the bill bounded -- the rich block adds
    # less value at those severities and the volume can spike.
    if fid and sev in ("critical", "high", "medium"):
        try:
            row = db.query_one(
                "SELECT * FROM findings WHERE id=%s", (fid,))
            ep = _resolve_anthropic_endpoint(aid)
            enr_id = enrichment_mod.get_or_create(row, ep)
            if enr_id:
                db.execute(
                    "UPDATE findings SET enrichment_id=%s WHERE id=%s",
                    (enr_id, fid))
        except Exception as e:
            # Enrichment is best-effort -- a transient LLM failure
            # must not lose the finding. The stub path in
            # enrichment.get_or_create also catches most issues.
            logger.warning(
                "agentic_ai: enrichment failed for finding #%s: %r",
                fid, e)
    # Add to the live index so a second agentic emission in the same
    # run can't beat the gate by being faster than the SELECT.
    if fid and sig and dedup_index is not None:
        dedup_index.setdefault(sig, {
            "canonical_id": fid,
            "source_tool": "agentic_ai_testing",
            "severity": sev,
            "title": title,
            "tier": dedup_mod.tier_for("agentic_ai_testing"),
        })
    return (fid, None)


def _record_llm_call(aid: int, target_id: str, mode: str,
                       endpoint_id: Optional[int], model: str,
                       response: dict) -> None:
    """Persist the LLM-call cost into llm_analyses so it feeds the
    on-page cost chip and the per-assessment running totals."""
    in_t = int(response.get("in_tokens") or 0)
    out_t = int(response.get("out_tokens") or 0)
    db.execute(
        """INSERT INTO llm_analyses
               (target_type, target_id, endpoint_id, endpoint_name,
                model, status, request_tokens, response_tokens,
                raw_response, assessment_id)
           VALUES ('enhanced_ai_weakness', %s, %s, %s, %s, 'done',
                   %s, %s, %s, %s)""",
        (target_id, endpoint_id, f"agentic_{mode}", model,
         in_t, out_t,
         (response.get("raw") or "")[:65000], aid))


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------

def _resolve_anthropic_endpoint(aid: int) -> Optional[dict]:
    """Pick the Anthropic endpoint to bill against. Precedence:
      1. The assessment's pinned llm_endpoint_id, IF it's anthropic.
      2. The is_default=1 endpoint, IF it's anthropic.
      3. The first anthropic endpoint by id.
    Returns None when no anthropic endpoint exists -- the agent
    cannot run; the caller logs and skips.
    """
    row = db.query_one(
        "SELECT llm_endpoint_id FROM assessments WHERE id=%s", (aid,))
    if row and row.get("llm_endpoint_id"):
        ep = db.query_one(
            "SELECT * FROM llm_endpoints "
            "WHERE id=%s AND backend='anthropic'",
            (row["llm_endpoint_id"],))
        if ep:
            return ep
    ep = db.query_one(
        "SELECT * FROM llm_endpoints "
        "WHERE backend='anthropic' AND is_default=1 LIMIT 1")
    if ep:
        return ep
    return db.query_one(
        "SELECT * FROM llm_endpoints WHERE backend='anthropic' "
        "ORDER BY id LIMIT 1")


def _agentic_model() -> str:
    """Pick the model name the agent calls Anthropic with. Env var
    override lets ops swap models without touching the codebase --
    e.g. NEXTGEN_DAST_AGENTIC_MODEL=claude-sonnet-5 when the current
    Sonnet release is deprecated."""
    return os.environ.get("NEXTGEN_DAST_AGENTIC_MODEL",
                           DEFAULT_AGENTIC_MODEL)


# ---------------------------------------------------------------------------
# Auth cookie sourcing
# ---------------------------------------------------------------------------

def _get_session_cookie(a: dict) -> Optional[str]:
    """Return the authenticated session cookie (Cookie-header value)
    for the assessment, or None when the assessment has no creds
    configured. We re-use auth.form_login_cookie() so behaviour
    matches the per-finding Challenge route and challenge_runner."""
    if not (a.get("creds_username") and a.get("creds_password")
            and a.get("login_url")):
        return None
    try:
        import auth as auth_mod
    except Exception:
        return None
    try:
        result = auth_mod.form_login_cookie(
            a["login_url"], a["creds_username"], a["creds_password"])
    except Exception as e:
        logger.warning("agentic_ai: form_login_cookie failed: %r", e)
        return None
    if result.get("ok") and result.get("cookie"):
        return result["cookie"]
    return None


# ---------------------------------------------------------------------------
# Tool-call loop
# ---------------------------------------------------------------------------

def _run_loop(*, aid: int, mode: str, parent_finding_id: Optional[int],
              system_prompt: str, seed_user_message: str,
              client, budget, max_turns: int,
              endpoint: dict, model: str,
              dedup_index: Optional[dict] = None) -> dict:
    """Drive the Anthropic tool-use loop. Returns a summary dict:
      {findings_inserted, turns, llm_in, llm_out, errors,
       finish_rationale, dedup_refused}.
    Stops on (a) explicit finish tool call, (b) end_turn stop reason,
    (c) max_turns exceeded, (d) HTTP budget tripped, (e) LLM-call
    error.

    Findings are inserted into the DB as they are emitted so a
    mid-loop crash doesn't lose work.

    `dedup_index` is the live signature -> canonical map built at the
    top of the run. The loop passes it into _insert_agentic_finding
    which both consults and updates it, so duplicate emissions in the
    same run -- the agent re-describing the same bug under a new
    title -- are also caught.
    """
    messages: list[dict] = [
        {"role": "user", "content": seed_user_message}]
    out = {"findings_inserted": 0, "turns": 0,
           "llm_in": 0, "llm_out": 0, "errors": [],
           "finish_rationale": "", "dedup_refused": 0,
           "budget_exhausted": False, "stopped_by_operator": False}
    api_key = endpoint.get("api_key") or ""
    # Round 5A: shared per-assessment budget. The agent's slice is
    # `cap - reservation`; the closing passes (enrichment +
    # consolidation) get the reserved headroom. Check before EACH
    # turn -- not just at the top -- because the agent emits +/- 2K
    # output tokens per turn at Sonnet pricing, easily $0.03-$0.08
    # per turn, so a 30-turn loop can land in the $1-3 range and
    # blow through a small slice if we only checked once.
    budget = llm_budget.get(aid)
    projected = llm_budget.project_turn_cost(model)
    for _ in range(max_turns):
        # Operator-set kill switch (assessments.agentic_stop_requested).
        # Polled per-turn so the "Stop agentic_ai_testing" button on
        # the workspace can abort the loop within a few seconds. We
        # poll the DB rather than using a Python event because the
        # orchestrator + agent live in the same process tree but the
        # button is a request to the OTHER process (the web server),
        # which has no shared-memory channel back. The DB column is
        # the cheapest cross-process signal we have.
        if _stop_requested(aid):
            out["stopped_by_operator"] = True
            out["finish_rationale"] = (
                "stopped by operator via 'Stop agentic_ai_testing' "
                "button; orchestrator will continue to dedup + "
                "consolidation")
            logger.info("agentic_ai: %s -- aid=%s mode=%s",
                        out["finish_rationale"], aid, mode)
            break
        if budget.would_exhaust_pass(projected):
            out["budget_exhausted"] = True
            out["finish_rationale"] = (
                f"budget slice exhausted (spent ${budget.spent:.4f} of "
                f"${budget.cap_usd:.2f} cap; "
                f"${budget.reservation:.2f} reserved for "
                "consolidation/enrichment)")
            logger.info("agentic_ai: %s -- aid=%s mode=%s",
                        out["finish_rationale"], aid, mode)
            break
        out["turns"] += 1
        try:
            resp = llm_mod.call_anthropic_tool_turn(
                api_key=api_key, model=model,
                system=system_prompt,
                messages=messages,
                tools=TOOL_PALETTE,
                max_tokens=TURN_MAX_TOKENS)
        except Exception as e:
            out["errors"].append(f"llm call crashed: {type(e).__name__}: {e}")
            break
        if not resp.get("ok"):
            out["errors"].append(
                f"llm call failed: {resp.get('error') or 'unknown'}")
            break
        # Cost bookkeeping into llm_analyses.
        _record_llm_call(
            aid=aid,
            target_id=(f"agentic_{mode}:f{parent_finding_id}"
                        if parent_finding_id else f"agentic_{mode}"),
            mode=mode, endpoint_id=endpoint.get("id"),
            model=model, response=resp)
        # Record the same call's cost on the shared accumulator so
        # the next iteration's `would_exhaust_pass` check is accurate.
        llm_budget.record(aid, in_tokens=int(resp.get("in_tokens") or 0),
                          out_tokens=int(resp.get("out_tokens") or 0),
                          model=model,
                          cached_in_tokens=int(
                              resp.get("cache_read_tokens") or 0))
        out["llm_in"] += int(resp.get("in_tokens") or 0)
        out["llm_out"] += int(resp.get("out_tokens") or 0)

        content_blocks = resp.get("content_blocks") or []
        # Always echo the assistant turn back into history so
        # subsequent tool_result blocks reference valid tool_use ids.
        messages.append({"role": "assistant", "content": content_blocks})

        stop_reason = resp.get("stop_reason")
        if stop_reason == "end_turn":
            # LLM produced only text, no tool calls. Treat as a
            # graceful stop with no findings of its own this turn.
            break

        # Walk content blocks, executing any tool_use ones.
        tool_results: list[dict] = []
        finish_signal = False
        for block in content_blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "tool_use":
                continue
            tool_id = block.get("id")
            tool_name = block.get("name") or ""
            tool_input = block.get("input") or {}

            if tool_name == "emit_finding":
                fid, refusal = _insert_agentic_finding(
                    aid, parent_finding_id, mode, tool_input,
                    dedup_index=dedup_index)
                if fid:
                    out["findings_inserted"] += 1
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": (
                            f"Recorded finding (id={fid}). Continue "
                            "if you have more verbatim evidence, or "
                            "call `finish` to stop."),
                    })
                elif refusal:
                    # Pre-emit dedup gate matched. The tool_result is
                    # NOT marked is_error -- this isn't a malformed
                    # call, it's a policy outcome the agent should
                    # reason about. Mark only as_error when the schema
                    # check failed (no signature, just a bad row).
                    out["dedup_refused"] += 1
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": refusal,
                    })
                else:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": ("Finding rejected -- severity must "
                                     "be one of critical/high/medium/low "
                                     "and title must be non-empty."),
                        "is_error": True,
                    })
                continue
            if tool_name == "finish":
                finish_signal = True
                out["finish_rationale"] = (
                    tool_input.get("rationale") or "")[:1000]
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": "Acknowledged. Run terminated.",
                })
                continue

            # HTTP-shaped tools.
            try:
                result = _execute_tool(client, tool_name, tool_input)
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            # Truncate the result JSON one last time so a huge body
            # excerpt doesn't sneak past TOOL_RESULT_BODY_CHARS via
            # the JSON-encoding overhead.
            payload = json.dumps(result, default=str)[:TOOL_RESULT_BODY_CHARS + 512]
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": payload,
            })

        if not tool_results:
            # Defensive: stop_reason='tool_use' but no tool_use blocks.
            # Treat as a graceful stop.
            break
        messages.append({"role": "user", "content": tool_results})

        if finish_signal:
            break
        # HTTP budget cap (in addition to the SafeClient internal
        # check, so we can stop early without throwing).
        if getattr(budget, "_requests_made", None) is not None \
                and budget._requests_made >= budget.max_requests:
            out["errors"].append("http budget exhausted")
            break
    return out


# ---------------------------------------------------------------------------
# Mode prompts
# ---------------------------------------------------------------------------

_SHARED_SAFETY_HEADER = """\
You are an authorized DAST agent. You are testing {fqdn} as part of a \
sanctioned security assessment.

NON-NEGOTIABLE OPERATING RULES:
1. You MUST NOT propose, plan, or call any destructive action: DELETE, \
financial transfer, account-lockout brute force, password reset of any \
real user, mass data deletion, or any irreversible change. The safety \
layer will refuse such calls and return them to you as `refused`; do \
not retry with similar payloads.
2. Stay on {fqdn} and its sub-paths. Do not call out to third-party \
hosts.
3. Every finding you emit must carry a VERBATIM evidence excerpt from \
a response, request, or header you actually observed in this run. Do \
not paraphrase. If you cannot quote, do not emit -- keep probing or \
call `finish`.
4. Prefer detection over exploitation. When a non-destructive payload \
proves the hypothesis (synthetic / non-existent IDs, OOB callback \
URL, dry-run flag) use it instead of the destructive variant.
5. State-mutating PoCs (race conditions, mass-assignment writes) MUST \
be tagged "STAGING ONLY -- do not run against production data" inside \
the reproduction text.

AUTHORIZED ROLE CONTEXT (the user whose session captured this telemetry):
{role_context_block}
{authorized_session_note}

Available tools: http_get, http_post_json, http_put_json, \
http_patch_json, http_options, emit_finding, finish.
"""

_PER_FINDING_USER = """\
{already_known_block}

TARGET FINDING TO DEEP-DIVE
============================
id:           {finding_id}
source_tool:  {source_tool}
severity:     {severity}
title:        {title}
evidence_url: {evidence_url}
method:       {evidence_method}

DESCRIPTION
-----------
{description}

RAW DATA (parsed JSON dump)
---------------------------
{raw_data}

ADJACENT FINDINGS (same assessment, top-5 by severity, for context)
=====================================================================
{adjacent_findings}

YOUR TASK
=========
Confirm or expand this finding. Examples of what "expand" looks like:
- If the parent says "BOLA on /api/Recycles/{{id}}", walk a few \
adjacent ids and quote a response that shows cross-user data.
- If the parent says "Mass assignment in /api/Users", PUT the same \
record with a privilege-bearing field and quote the echo-back.
- If the parent reports an exposure (e.g. /metrics), inspect the \
exposed body for credentials, hostnames, internal IPs -- emit one \
finding per discrete leak.

Emit at most 5 child findings. Each must have its own verbatim \
evidence excerpt. When you have nothing more to add, call `finish`.
"""

_FREE_ROAM_USER = """\
You are doing a FREE-ROAM agentic pass over the in-flight scan of \
{fqdn}. You have already completed a per-finding deep-dive of the \
top severity findings; this pass is looking for misses the probes \
and the LLM weakness-discovery scenarios did not surface.

{already_known_block}

OPEN FINDINGS DIGEST (titles only, oldest-to-newest, sample of 30)
====================================================================
{open_findings_digest}

REQUEST CLUSTERS captured during the scan (top-50 by frequency)
================================================================
{request_clusters}

AUTHENTICATED ENDPOINTS
========================
{authenticated_endpoints}

YOUR TASK
=========
Pick areas the existing pass has under-covered and confirm new \
findings with verbatim evidence. Strong candidate areas in our \
experience:
- Mass-assignment on PUT/PATCH endpoints we haven't already flagged \
(send an extra privilege-bearing field; quote the echo-back).
- BOLA on collection / list endpoints we haven't already flagged \
(quote a response row whose ownership field is not the session id).
- Authentication-metadata exposures on /rest/admin/*, /rest/user/*, \
/api/Users, /api/Recycles (quote a record).
- Hardcoded credentials in static asset paths.
- Open redirect / SSRF in URL-processing endpoints.

Emit at most 8 findings, one call per finding. Stop with `finish` \
when you have nothing more with verbatim evidence.
"""


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _format_role_context_block(a: dict) -> str:
    scope = (a.get("role_scope_description") or "").strip()
    rest = (a.get("role_restrictions") or "").strip()
    if not (scope and rest):
        return "(no authorized-role context configured for this assessment)"
    return (
        "AUTHORIZED ROLE (the user whose session captured this telemetry)\n"
        "================================================================\n"
        f"{scope}\n\n"
        "OUT OF SCOPE (capabilities this user must NOT have)\n"
        "===================================================\n"
        f"{rest}")


def _build_system_prompt(fqdn: str, a: dict, has_session: bool) -> str:
    note = ("You have an authenticated session cookie attached to "
            "every HTTP call you make (the captured session for the "
            "authorized role above). Calls go out under that "
            "identity unless you override the Cookie header."
            if has_session else
            "You do NOT have an authenticated session cookie on this "
            "run. HTTP calls go out anonymously.")
    return _SHARED_SAFETY_HEADER.format(
        fqdn=fqdn,
        role_context_block=_format_role_context_block(a),
        authorized_session_note=note,
    )


def _adjacent_findings_digest(aid: int, exclude_id: int) -> str:
    rows = db.query_all(
        "SELECT id, source_tool, severity, title FROM findings "
        "WHERE assessment_id=%s AND id != %s "
        "  AND COALESCE(status,'open') NOT IN "
        "      ('false_positive','fixed','accepted_risk') "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id "
        "LIMIT 5",
        (aid, exclude_id))
    if not rows:
        return "(no adjacent findings)"
    return "\n".join(
        f"  [#{r['id']} {r['severity']}/{r['source_tool']}] "
        f"{(r['title'] or '')[:120]}"
        for r in rows)


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2,
              "low": 3, "info": 4}


def _select_dive_candidates(aid: int, dive_count: int) -> tuple:
    """Round 6: pick the top-N findings worth a per-finding deep-dive.

    Two filters layered on top of the prior 'pick top-N by severity':

    (1) validation_status filter. Skip rows that the auto_validate
        pass + LLM fidelity grader already labeled `validated` or
        `false_positive` -- the agent has nothing to add when the
        deterministic probe already confirmed (or refuted) the
        finding. `inconclusive`, `unvalidated`, and `errored` rows
        ARE eligible since those are where the agent's reasoning
        adds the most value.

    (2) Cross-source clustering by `dedup_signature_v2`. Findings
        that share a signature (e.g. 15 testssl cipher rows that
        all describe the same TLS-endpoint weakness) collapse to a
        single dive candidate -- the canonical row of the cluster
        (lowest tier, highest severity, lowest id) represents the
        cluster. This stops the agent from spending 15 dives on the
        same underlying bug just because the scanner emitted 15
        per-cipher rows.

    Returns (candidates, skip_summary) where:
      - candidates: list of finding dicts ready to dive on, up to
        dive_count items, ordered by severity then id.
      - skip_summary: dict with counts for orchestrator logging:
          {clusters_total, clusters_eligible, clusters_skipped_validated,
           clusters_skipped_false_positive, rows_collapsed_by_dedup,
           dive_count_requested}
    """
    pool = db.query_all(
        "SELECT * FROM findings WHERE assessment_id=%s "
        "  AND COALESCE(status,'open') NOT IN "
        "      ('false_positive','fixed','accepted_risk') "
        "  AND severity IN ('critical','high','medium') "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id",
        (aid,))
    # Cluster by signature; rows with no computable signature each
    # form their own singleton cluster (default to a unique key so
    # they're not merged with each other accidentally).
    clusters: dict = {}
    for f in pool:
        sig = dedup_mod.compute_signature_for_finding(f) or f"_singleton:{f['id']}"
        clusters.setdefault(sig, []).append(f)
    skip_summary = {
        "clusters_total": len(clusters),
        "clusters_eligible": 0,
        "clusters_skipped_validated": 0,
        "clusters_skipped_false_positive": 0,
        "rows_collapsed_by_dedup": max(0, len(pool) - len(clusters)),
        "dive_count_requested": dive_count,
    }
    # Pick canonical per cluster: lowest tier (highest fidelity)
    # wins; tiebreak by severity rank, then lowest id.
    eligible: list = []
    for sig, members in clusters.items():
        members_sorted = sorted(
            members,
            key=lambda r: (dedup_mod.tier_for(r.get("source_tool") or ""),
                            _SEV_RANK.get(
                                (r.get("severity") or "").lower(), 9),
                            int(r.get("id") or 0)))
        canonical = members_sorted[0]
        vs = (canonical.get("validation_status") or "unvalidated").lower()
        if vs == "validated":
            skip_summary["clusters_skipped_validated"] += 1
            continue
        if vs == "false_positive":
            skip_summary["clusters_skipped_false_positive"] += 1
            continue
        # 'inconclusive', 'unvalidated', 'errored' all dive. The
        # inconclusive case is where the agent shines -- probe ran
        # but the verdict was below 0.8 confidence, so a reasoning
        # pass adds real value.
        eligible.append(canonical)
    skip_summary["clusters_eligible"] = len(eligible)
    # Order eligible canonicals: highest severity first, then by id
    # so the ordering is deterministic across re-runs of the same
    # assessment.
    eligible.sort(key=lambda r: (
        _SEV_RANK.get((r.get("severity") or "").lower(), 9),
        int(r.get("id") or 0)))
    return eligible[:dive_count], skip_summary


def run_per_finding(aid: int, fqdn: str, dive_count: int) -> dict:
    """Deep-dive the top-N open findings by severity. Returns a
    summary dict for the orchestrator to log."""
    a = db.query_one("SELECT * FROM assessments WHERE id=%s", (aid,))
    if not a:
        return {"errors": [f"no assessment {aid}"]}
    if dive_count <= 0:
        return {"skipped": "agentic_deep_dive_count is 0"}
    dive_count = min(dive_count, 25)
    endpoint = _resolve_anthropic_endpoint(aid)
    if not endpoint:
        return {"errors": ["no anthropic llm_endpoint available"]}
    model = _agentic_model()
    session_cookie = _get_session_cookie(a)
    candidates, skip_summary = _select_dive_candidates(aid, dive_count)
    if not candidates:
        return {
            "skipped": (
                f"no eligible findings to deep-dive "
                f"(clusters_total={skip_summary['clusters_total']}, "
                f"skipped_validated="
                f"{skip_summary['clusters_skipped_validated']}, "
                f"skipped_false_positive="
                f"{skip_summary['clusters_skipped_false_positive']})"),
            "skip_summary": skip_summary,
        }
    # Round 5A: pre-check the assessment's budget slice. If the
    # weakness pass already burned through the agent's share, skip
    # the per-finding sub-runs entirely so the closing passes get
    # their reserved headroom instead. The orchestrator log records
    # the early-exit reason so an operator can raise the cap if they
    # want more agentic depth on the next run.
    budget = llm_budget.get(aid)
    projected = llm_budget.project_turn_cost(_agentic_model())
    if budget.would_exhaust_pass(projected):
        return {
            "skipped": (f"budget slice exhausted before per-finding "
                         f"pass: spent ${budget.spent:.4f} of "
                         f"${budget.cap_usd:.2f}, "
                         f"${budget.reservation:.2f} reserved"),
        }
    summary = {"runs": 0, "findings_inserted": 0,
                "llm_in": 0, "llm_out": 0,
                "errors": [], "dedup_refused": 0,
                "budget_exhausted": False,
                "stopped_by_operator": False,
                # Round 6: surface candidate-pool stats so an
                # operator looking at the log can see "dove 3 of 15
                # requested; 12 clusters skipped (all already-
                # validated)" without having to reconstruct it from
                # the DB.
                "skip_summary": skip_summary,
                "dive_count_actual": len(candidates)}
    logger.info(
        "agentic_ai: per-finding selection aid=%s requested=%d "
        "clusters_total=%d eligible=%d skipped_validated=%d "
        "skipped_false_positive=%d rows_collapsed_by_dedup=%d "
        "actual_dives=%d",
        aid, dive_count, skip_summary["clusters_total"],
        skip_summary["clusters_eligible"],
        skip_summary["clusters_skipped_validated"],
        skip_summary["clusters_skipped_false_positive"],
        skip_summary["rows_collapsed_by_dedup"],
        len(candidates))
    # Build the live dedup index ONCE for the whole pass. Each
    # per-finding sub-run shares it so an agent emission in run 2
    # is checked against agent emissions in run 1 too. Excludes
    # nothing -- the agent should not duplicate ANY existing
    # finding, regardless of source tier.
    dedup_index = dedup_mod.build_signature_index(aid)
    # Preamble shows non-agentic findings -- the agent already knows
    # its own outputs from the dedup gate; the preamble's job is to
    # surface what OTHER scanners + the LLM weakness pass already
    # confirmed, so the agent doesn't burn a turn re-testing them.
    preamble = dedup_mod.build_already_known_preamble(
        aid, exclude_source_tools={"agentic_ai_testing"})
    for f in candidates:
        # Operator stop signal between dives. Each per-finding dive
        # can run 3-5 minutes, so the inner-loop per-turn check is
        # the main responsiveness gate; this is the coarse backup
        # that catches a click between dives even if the inner
        # check happened to fall right after the previous dive's
        # last turn.
        if _stop_requested(aid):
            summary["stopped_by_operator"] = True
            logger.info(
                "agentic_ai: per-finding loop stopped by operator "
                "after %d runs -- aid=%s", summary["runs"], aid)
            break
        # Re-check budget between dives -- prior runs in this loop
        # may have burned through the slice, and we want subsequent
        # dives to bail out cleanly rather than start a doomed loop.
        if budget.would_exhaust_pass(projected):
            summary["budget_exhausted"] = True
            logger.info(
                "agentic_ai: stopping per-finding loop after %d runs -- "
                "aid=%s spent=$%.4f cap=$%.2f reservation=$%.2f",
                summary["runs"], aid, budget.spent,
                budget.cap_usd or 0.0, budget.reservation)
            break
        client, _audit, sc_budget = _build_safeclient(
            scope_hosts=(fqdn,),
            max_requests=PER_FINDING_HTTP_MAX,
            session_cookie=session_cookie,
            allow_destructive=True)
        sys_prompt = _build_system_prompt(fqdn, a, bool(session_cookie))
        try:
            raw_data_str = json.dumps(
                json.loads(f.get("raw_data") or "{}"),
                indent=2, default=str)[:2000]
        except Exception:
            raw_data_str = (f.get("raw_data") or "")[:2000]
        user_msg = _PER_FINDING_USER.format(
            already_known_block=preamble,
            finding_id=f["id"],
            source_tool=f.get("source_tool") or "",
            severity=f.get("severity") or "",
            title=(f.get("title") or "")[:200],
            evidence_url=f.get("evidence_url") or "",
            evidence_method=f.get("evidence_method") or "",
            description=(f.get("description") or "")[:1500],
            raw_data=raw_data_str,
            adjacent_findings=_adjacent_findings_digest(aid, f["id"]))
        result = _run_loop(
            aid=aid, mode="per_finding", parent_finding_id=f["id"],
            system_prompt=sys_prompt, seed_user_message=user_msg,
            client=client, budget=sc_budget,
            max_turns=PER_FINDING_TURN_MAX,
            endpoint=endpoint, model=model,
            dedup_index=dedup_index)
        summary["runs"] += 1
        summary["findings_inserted"] += result.get("findings_inserted", 0)
        summary["llm_in"] += result.get("llm_in", 0)
        summary["llm_out"] += result.get("llm_out", 0)
        summary["dedup_refused"] += result.get("dedup_refused", 0)
        if result.get("budget_exhausted"):
            summary["budget_exhausted"] = True
        if result.get("errors"):
            summary["errors"].extend(result["errors"])
    return summary


def _request_clusters_digest(aid: int) -> str:
    """Compact view of (method, normalized-path) tuples observed in
    scan findings. Same logic as enhanced_ai._render_request_clusters
    but inlined here to avoid a circular import and to keep this
    module self-contained."""
    import re as _re
    rows = db.query_all(
        "SELECT DISTINCT evidence_method, evidence_url FROM findings "
        "WHERE assessment_id=%s AND evidence_url IS NOT NULL "
        "LIMIT 500", (aid,))
    seen: dict[str, int] = {}
    for r in rows:
        u = r.get("evidence_url") or ""
        if not u:
            continue
        pat = _re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}", u, flags=_re.I)
        pat = _re.sub(r"/\d+", "/{id}", pat)
        pat = _re.sub(r"\?.*$", "", pat)
        method = (r.get("evidence_method") or "GET").upper()
        key = f"{method} {pat}"
        seen[key] = seen.get(key, 0) + 1
    if not seen:
        return "(no request clusters captured)"
    lines = sorted(seen.items(), key=lambda kv: -kv[1])[:50]
    return "\n".join(f"  {n}x  {key}" for key, n in lines)


def _authenticated_endpoints_digest(aid: int) -> str:
    rows = db.query_all(
        "SELECT DISTINCT evidence_method, evidence_url FROM findings "
        "WHERE assessment_id=%s AND evidence_url LIKE '%%/api/%%' "
        "LIMIT 100", (aid,))
    if not rows:
        return "(no authenticated endpoints captured)"
    out = []
    seen = set()
    for r in rows:
        m = (r.get("evidence_method") or "GET").upper()
        u = (r.get("evidence_url") or "").split("?", 1)[0]
        key = f"{m} {u}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f"  {key}")
        if len(out) >= 40:
            break
    return "\n".join(out)


def _open_findings_digest(aid: int) -> str:
    rows = db.query_all(
        "SELECT id, severity, source_tool, title FROM findings "
        "WHERE assessment_id=%s "
        "  AND COALESCE(status,'open') NOT IN "
        "      ('false_positive','fixed','accepted_risk') "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id "
        "LIMIT 30", (aid,))
    if not rows:
        return "(no open findings)"
    return "\n".join(
        f"  [#{r['id']} {r['severity']}/{r['source_tool']}] "
        f"{(r['title'] or '')[:120]}"
        for r in rows)


def run_free_roam(aid: int, fqdn: str) -> dict:
    """Free-roaming agent pass. Only invoked when the assessment has
    agentic_extra=1. Returns a summary dict."""
    a = db.query_one("SELECT * FROM assessments WHERE id=%s", (aid,))
    if not a:
        return {"errors": [f"no assessment {aid}"]}
    if int(a.get("agentic_extra") or 0) != 1:
        return {"skipped": "agentic_extra is 0"}
    endpoint = _resolve_anthropic_endpoint(aid)
    if not endpoint:
        return {"errors": ["no anthropic llm_endpoint available"]}
    model = _agentic_model()
    session_cookie = _get_session_cookie(a)
    # Operator stop signal before free-roam fires its first turn.
    # If the per-finding pass was killed by the button, free-roam
    # would inherit the same kill intent -- there's no concept of
    # "stop deep-dive but run free-roam." Skip the pass entirely.
    if _stop_requested(aid):
        return {"skipped": "stopped by operator before free-roam started"}
    # Round 5A: same pre-check as per-finding. Free-roam is the more
    # expensive pass (80 HTTP / 60 turns) so it's the most likely to
    # be skipped on a budget that's already been heavily used by the
    # weakness pass or by an earlier deep-dive pass.
    fr_budget = llm_budget.get(aid)
    fr_projected = llm_budget.project_turn_cost(model)
    if fr_budget.would_exhaust_pass(fr_projected):
        return {
            "skipped": (f"budget slice exhausted before free-roam "
                         f"pass: spent ${fr_budget.spent:.4f} of "
                         f"${fr_budget.cap_usd:.2f}, "
                         f"${fr_budget.reservation:.2f} reserved"),
        }
    client, _audit, sc_budget = _build_safeclient(
        scope_hosts=(fqdn,),
        max_requests=FREE_ROAM_HTTP_MAX,
        session_cookie=session_cookie,
        allow_destructive=True)
    sys_prompt = _build_system_prompt(fqdn, a, bool(session_cookie))
    # Build the dedup index + preamble for free-roam too. Free-roam
    # is the mode most prone to noise since it has no parent finding
    # to anchor the search, so the dedup gate matters most here.
    dedup_index = dedup_mod.build_signature_index(aid)
    preamble = dedup_mod.build_already_known_preamble(
        aid, exclude_source_tools={"agentic_ai_testing"})
    user_msg = _FREE_ROAM_USER.format(
        fqdn=fqdn,
        already_known_block=preamble,
        open_findings_digest=_open_findings_digest(aid),
        request_clusters=_request_clusters_digest(aid),
        authenticated_endpoints=_authenticated_endpoints_digest(aid))
    result = _run_loop(
        aid=aid, mode="free_roam", parent_finding_id=None,
        system_prompt=sys_prompt, seed_user_message=user_msg,
        client=client, budget=sc_budget,
        max_turns=FREE_ROAM_TURN_MAX,
        endpoint=endpoint, model=model,
        dedup_index=dedup_index)
    return result


# ---------------------------------------------------------------------------
# Convenience for the orchestrator
# ---------------------------------------------------------------------------

def run(aid: int) -> dict:
    """Top-level entry point. Reads the assessment's agentic
    settings and runs the appropriate passes. Errors are captured
    into the summary, not raised."""
    a = db.query_one("SELECT * FROM assessments WHERE id=%s", (aid,))
    if not a:
        return {"errors": [f"no assessment {aid}"]}
    fqdn = a.get("fqdn") or ""
    dive = int(a.get("agentic_deep_dive_count") or 0)
    extra = int(a.get("agentic_extra") or 0)
    summary: dict[str, Any] = {
        "per_finding": None, "free_roam": None, "errors": []}
    try:
        if dive > 0:
            summary["per_finding"] = run_per_finding(aid, fqdn, dive)
    except Exception as e:
        summary["errors"].append(
            f"per_finding crashed: {type(e).__name__}: {e}")
    try:
        if extra == 1:
            summary["free_roam"] = run_free_roam(aid, fqdn)
    except Exception as e:
        summary["errors"].append(
            f"free_roam crashed: {type(e).__name__}: {e}")
    return summary
