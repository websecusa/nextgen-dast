# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Enhanced-AI-Testing pass — the post-scan LLM analytical loop that runs on
the advanced LLM tier.

When does this run?
  - llm_tier == 'advanced' AND a usable LLM endpoint is configured.
  - After every scanner has finished, after the enhanced_testing probe
    pass, and after the auto-validation challenge_runner. By that point
    every finding either has a probe verdict or validation_status =
    'unvalidated'. Runs immediately before consolidation roll-up so any
    new findings emitted here are folded into the executive summary.

Two passes inside one module:

  1. Weakness discovery. For each active row in slot
     'advanced_ai_testing.weakness_discovery', evaluate fire_when against
     the per-assessment telemetry summary. If true, render the user
     template with the placeholders, call the LLM, parse a JSON array of
     findings, and INSERT each into the findings table with
     source_tool='enhanced_ai_testing'. Each scenario gets one LLM call
     that sees the full telemetry; multiple scenarios in the slot run
     sequentially.

  2. Fidelity evaluation. Pull findings WHERE severity != 'info' AND
     validation_status IN ('unvalidated','inconclusive'). Batch into
     groups of N (default 5) and ask the active fidelity prompt to grade
     each batch. For batched verdicts at confidence >= 0.8 we auto-flip
     validation_status to 'validated' / 'false_positive' (mirroring how
     challenge_runner writes its verdicts). Lower-confidence verdicts
     and 'errored' findings are left for human triage.

Cost control
  - Per-scan budget cap (assessments.enhanced_ai_budget_usd) — when the
    accumulated cost would exceed the cap on the next call, we
    short-circuit. Any partial findings already produced are preserved.
  - error_text on the assessment row records the cap-hit so it surfaces
    on the assessment page.

Debug log
  - When the assessment has llm_debug=1, every LLM call (in this module
    and elsewhere — enrichment, consolidation) writes its rendered user
    prompt and full raw response into llm_analyses. The "View LLM Debug
    Log" page reads from there.

Failure isolation
  - This module never raises out of run(). A crash in any single LLM
    call, scenario, or fidelity batch is logged into the assessment's
    error_text and the run continues with the next item. The
    orchestrator's outer try/except is also fenced — a fatal failure
    here cannot lose the underlying scanner findings.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import auth_recapture
import db
import flow_index
import llm as llm_mod
import spa_fallback

logger = logging.getLogger(__name__)


# ---- Tunables ---------------------------------------------------------------

# Per-call output cap. Weakness scenarios produce up to 10 findings each
# with multi-paragraph descriptions / curl recommendations; 4096 tokens
# accommodates that without padding.
WEAKNESS_MAX_OUTPUT_TOKENS = 4096
# Fidelity verdicts are tight (verdict + confidence + reasoning <=400 chars
# per finding). Five findings per call needs no more than this.
FIDELITY_MAX_OUTPUT_TOKENS = 1200
# Hard ceiling on findings included in any single placeholder block.
# Prevents a runaway scan from bloating prompt tokens and cost.
MAX_FINDINGS_IN_PROMPT = 200
# Hard ceiling on the response_samples and authenticated_responses
# blocks — these include raw JSON bodies and balloon prompt size fast.
MAX_RESPONSE_SAMPLES = 30
# When evidence_url / raw_data text is huge, cap individual quotes to
# keep one finding from dominating the prompt.
PER_FINDING_QUOTE_MAX = 800


# ---- Telemetry summary ------------------------------------------------------

def build_telemetry(aid: int) -> dict:
    """Compute the per-assessment telemetry summary used for both
    fire_when evaluation and prompt-placeholder substitution.

    Single DB pass over the findings table; the result is reused across
    every scenario / fidelity batch so the cost is paid once per scan.

    Returned dict has two kinds of keys:
      - boolean flags (has_creds, has_mutating_json_request, …) consumed
        by fire_when expressions
      - placeholder text blocks (request_clusters, mutating_requests, …)
        substituted into the per-scenario user templates

    findings_count is also exposed for fire_when (e.g. "findings_count >= 5").
    """
    a = db.query_one(
        "SELECT id, fqdn, profile, scan_http, scan_https, "
        "creds_username, creds_password, login_url, "
        # Role-aware Enhanced-AI-Testing inputs. Both NULL on assessments
        # that didn't opt into the role-aware pass; render_role_context()
        # below collapses to an empty placeholder block in that case so
        # operator-edited prompts that reference the placeholder still
        # render cleanly.
        "role_scope_description, role_restrictions "
        "FROM assessments WHERE id=%s",
        (aid,))
    if not a:
        return {}

    findings = db.query_all(
        "SELECT id, source_tool, source_scan_id, severity, owasp_category, "
        "cwe, title, description, evidence_url, evidence_method, raw_data, "
        "validation_status "
        "FROM findings WHERE assessment_id=%s "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id",
        (aid,))
    findings_count = len(findings)

    # Pre-decode raw_data once. Many scanners JSON-encode it; downstream
    # heuristics need both the dict view (key inspection) and the string
    # view (substring search), so we materialize both.
    parsed: list[dict] = []
    for f in findings:
        rd_raw = f.get("raw_data")
        rd: Any = {}
        rd_str = ""
        if isinstance(rd_raw, str):
            rd_str = rd_raw
            try:
                rd = json.loads(rd_raw) if rd_raw else {}
            except Exception:
                rd = {}
        elif isinstance(rd_raw, dict):
            rd = rd_raw
            try:
                rd_str = json.dumps(rd_raw)
            except Exception:
                rd_str = str(rd_raw)
        parsed.append({**f, "_raw": rd, "_raw_str": rd_str})

    # ---- Attach response evidence from the proxy capture ------------------
    #
    # Every scanner that runs through the orchestrator is wrapped with our
    # mitmproxy addon (proxy_addon.PentestAddon), which writes flows.jsonl
    # plus per-flow request/response files into /data/scans/<scan_id>/.
    # That capture has been on disk all along — but the per-tool parsers
    # in app/findings.py never plumbed it back into raw_data, so the
    # Enhanced-AI weakness pass saw "(no response bodies captured by
    # scanners)" and, per its verbatim-quote rule, omitted every finding.
    #
    # FlowIndex reads each scan's flows.jsonl, matches by URL+method, and
    # attaches a sanitized response_body_excerpt + status + content-type +
    # interesting-headers slice into each finding's _raw dict. Existing
    # _render_response_samples / _format_one_finding helpers already read
    # those keys, so the LLM prompt populates automatically.
    #
    # Token-economy: the body excerpt is capped at PER_FINDING_QUOTE_MAX
    # bytes per finding, and the prompt's MAX_RESPONSE_SAMPLES already
    # bounds how many of these the LLM ever sees.
    scan_ids = sorted({(f.get("source_scan_id") or "").strip()
                        for f in findings if f.get("source_scan_id")})
    scan_dirs = [Path("/data/scans") / sid for sid in scan_ids if sid]
    flow_idx = flow_index.FlowIndex(scan_dirs)
    attached = flow_index.attach_response_evidence(
        parsed, flow_idx, max_body_bytes=PER_FINDING_QUOTE_MAX)
    if attached:
        logger.info(
            "enhanced_ai: attached response evidence to %d/%d findings "
            "across %d scan(s) (%d flows indexed)",
            attached, len(parsed), flow_idx.scans_loaded,
            flow_idx.flows_loaded)

    # ---- Authenticated re-walk for high-value cluster URLs ----------------
    #
    # Even with credentials configured, scanners do not always probe every
    # adjacent admin / api / settings path. auth_recapture takes the
    # cluster URLs the FlowIndex did NOT cover, scores them by path
    # token (admin > api > users > ... ), and GETs the top
    # MAX_RECAPTURE with the same session cookie the challenge_runner
    # uses, capturing status + headers + body excerpt. Bounded by URL
    # cap and per-body byte cap, so worst-case prompt growth is small.
    #
    # The pass is a no-op when:
    #   - the assessment has no creds, OR
    #   - every high-value cluster URL is already in FlowIndex.
    # Login failure is logged at DEBUG and treated as no-op (recapture is
    # best-effort and must not break telemetry construction).
    cookie_header = auth_recapture.resolve_session_cookie(
        a.get("login_url"), a.get("creds_username"),
        a.get("creds_password"))
    if cookie_header:
        recap_attached = auth_recapture.attach_recaptured_evidence(
            parsed, flow_idx, cookie_header,
            max_body_bytes=PER_FINDING_QUOTE_MAX)
        if recap_attached:
            logger.info(
                "enhanced_ai: auth re-walk attached recaptured evidence "
                "to %d additional finding(s)", recap_attached)

    # Re-materialize _raw_str for any finding whose _raw dict picked up
    # new keys, so the substring-search heuristics downstream see the
    # injected response body too.
    for f in parsed:
        if f["_raw"]:
            try:
                f["_raw_str"] = json.dumps(f["_raw"], default=str)
            except Exception:
                pass

    # ---- SPA-fallback fingerprinting --------------------------------------
    #
    # Many targets (CDN-fronted SPAs) answer every unmatched path with
    # HTTP 200 and the same index.html. Without this guard, scanners
    # like nikto report "X admin interface identified at /X.jsp" purely
    # because the path returned 200, and the LLM weakness pass then
    # extrapolates a CVE chain on top of that false signal. We fingerprint
    # each unique host once per run, mark each finding whose evidence_url
    # body matches the fallback, and surface the warning to the LLM in a
    # dedicated placeholder block so the model knows to discount path-
    # existence inferences on those hosts. The fingerprinter is also
    # stashed on the summary (private key) so _insert_weakness_findings
    # can re-check the LLM's own output for SPA-fallback URLs.
    fingerprinter = spa_fallback.Fingerprinter()
    for host_key in spa_fallback.hosts_in_findings(parsed):
        try:
            fingerprinter.probe_host(host_key)
        except Exception as e:
            logger.warning("spa_fallback probe of %s failed: %r",
                           host_key, e)
    for f in parsed:
        u = f.get("evidence_url") or ""
        f["_spa_fallback"] = bool(u) and fingerprinter.is_fallback(u)

    # ---- Boolean flags consumed by fire_when ------------------------------

    has_creds = bool((a.get("creds_username") or "").strip())
    has_credentialed_traffic = has_creds  # alias kept for prompt clarity

    # Mutating JSON request: at least one finding whose method is in
    # {POST,PUT,PATCH} and whose raw_data carries a JSON-shaped body.
    has_mutating_json_request = any(
        (f.get("evidence_method") or "").upper() in ("POST", "PUT", "PATCH")
        and _looks_jsonish(f["_raw_str"])
        for f in parsed
    )

    # URL-processing endpoint: any finding from an SSRF probe, or any
    # parameter name in raw_data shaped like {url, webhook, image_url,
    # callback, redirect, fetch}.
    has_url_processing_endpoint = any(
        f.get("source_tool") == "enhanced_testing"
        and (f["_raw"].get("evidence", {}) or {}).get("origin")
        and "ssrf" in (f.get("title") or "").lower()
        for f in parsed
    ) or any(_url_param_present(f["_raw"]) for f in parsed)

    # Auth redirect chain: a finding with HTTP 30x evidence and an
    # authorize/openid/saml/oauth path token.
    has_auth_redirect_chain = any(
        re.search(r"/(authorize|oauth|openid|saml|sso)\b",
                  f.get("evidence_url") or "", re.I)
        for f in parsed
    )

    has_swagger_or_sourcemap = any(
        ("swagger" in (f.get("title") or "").lower()
         or "openapi" in (f.get("title") or "").lower()
         or "source map" in (f.get("title") or "").lower())
        for f in parsed
    )

    has_high_value_endpoint = any(
        re.search(r"/(login|signin|logon|password[-_]?reset|forgot|"
                  r"otp|verify|mfa|recover|signup|register)",
                  f.get("evidence_url") or "", re.I)
        for f in parsed
    )

    has_state_mutating_endpoint = any(
        (f.get("evidence_method") or "").upper() in ("POST", "PUT", "PATCH", "DELETE")
        for f in parsed
    )

    # Tenant identifier: an URL/cookie containing org/account/tenant
    # tokens, or a header name of that shape inside raw_data.
    has_tenant_identifier = any(
        re.search(r"\b(org|tenant|account|workspace|team)[_-]?id\b",
                  f.get("evidence_url") or "" + " " + f["_raw_str"], re.I)
        or re.search(r"X-(Org|Tenant|Account|Workspace)-Id",
                     f["_raw_str"], re.I)
        for f in parsed
    )

    # Role-aware Enhanced-AI-Testing inputs. Both fields are populated
    # only when the operator opted into the role-aware pass and the
    # orchestrator's gate (premium + advanced + checkbox) reached this
    # module. Strings are stripped + length-capped at submit time
    # (server.py / api.py), so we trust them here without re-validating.
    #
    # Then run _sanitize_role_text to strip any output-gating directives
    # the operator may have wedged in ("ONLY SHOW FINDINGS WITH A
    # CONFIDENCE SCORE OF 0.75…"). Those directives belong in the code-
    # owned RUNTIME_SAFETY_PREAMBLE, not in role text — when they live in
    # both places the weakness pass collapses to [] because the role
    # directive contradicts the candidate-vs-verdict contract.
    role_scope_text = _sanitize_role_text(
        (a.get("role_scope_description") or "").strip())
    role_restrict_text = _sanitize_role_text(
        (a.get("role_restrictions") or "").strip())
    has_role_context = bool(role_scope_text and role_restrict_text)

    summary = {
        "fqdn": a.get("fqdn") or "",
        "profile": a.get("profile") or "standard",
        "findings_count": findings_count,
        "has_creds": has_creds,
        "has_credentialed_traffic": has_credentialed_traffic,
        "has_mutating_json_request": has_mutating_json_request,
        "has_url_processing_endpoint": has_url_processing_endpoint,
        "has_auth_redirect_chain": has_auth_redirect_chain,
        "has_swagger_or_sourcemap": has_swagger_or_sourcemap,
        "has_high_value_endpoint": has_high_value_endpoint,
        "has_state_mutating_endpoint": has_state_mutating_endpoint,
        "has_tenant_identifier": has_tenant_identifier,
        "has_role_context": has_role_context,
        # Raw text fields, surfaced as placeholders so an operator-
        # edited prompt can quote them directly. The composed
        # role_context_block (built below) is the convenience form.
        "role_scope_description": role_scope_text,
        "role_restrictions": role_restrict_text,
        # Private key (leading underscore) — never substituted as a
        # placeholder, only consulted by post-processing in
        # _insert_weakness_findings to re-check LLM-emitted URLs.
        "_spa_fingerprinter": fingerprinter,
    }

    # ---- Placeholder text blocks ------------------------------------------
    # Each block is rendered once and reused across every scenario that
    # references it. Render lazily-ish: only build blocks the placeholder
    # set declares for the weakness slot, since some are expensive.

    summary["request_clusters"] = _render_request_clusters(parsed)
    summary["auth_findings"] = _render_findings_filtered(
        parsed, lambda f: ("auth" in (f.get("owasp_category") or "").lower()
                            or "auth" in (f.get("source_tool") or "").lower()
                            or _looks_auth_related(f)))
    summary["state_mutating_findings"] = _render_findings_filtered(
        parsed, lambda f: (f.get("evidence_method") or "").upper()
                          in ("POST", "PUT", "PATCH", "DELETE"))
    summary["authenticated_endpoints"] = _render_endpoints_authenticated(
        parsed, has_creds)
    summary["object_id_patterns"] = _render_object_ids(parsed)
    summary["response_samples"] = _render_response_samples(parsed)
    summary["mutating_requests"] = _render_mutating_requests(parsed)
    summary["related_findings"] = _render_findings_filtered(
        parsed, lambda f: True, limit=20)
    summary["input_endpoints"] = _render_endpoints_by_methods(
        parsed, ("POST", "PUT", "PATCH"))
    summary["retrieval_endpoints"] = _render_endpoints_by_methods(
        parsed, ("GET",))
    summary["xss_findings"] = _render_findings_filtered(
        parsed, lambda f: "xss" in (f.get("title") or "").lower()
                          or (f.get("cwe") or "") in ("CWE-79", "79"))
    summary["sqli_findings"] = _render_findings_filtered(
        parsed, lambda f: "sql" in (f.get("title") or "").lower()
                          or (f.get("cwe") or "") in ("CWE-89", "89"))
    summary["auth_redirect_chain"] = _render_auth_redirect_chain(parsed)
    summary["jwt_findings"] = _render_findings_filtered(
        parsed, lambda f: "jwt" in (f.get("title") or "").lower()
                          or "jwt" in (f.get("source_tool") or "").lower())
    summary["oauth_endpoints"] = _render_oauth_endpoints(parsed)
    summary["url_processing_endpoints"] = _render_url_processing(parsed)
    summary["infrastructure_signals"] = _render_infra_signals(parsed)
    summary["ssrf_probe_findings"] = _render_findings_filtered(
        parsed, lambda f: "ssrf" in (f.get("title") or "").lower())
    summary["swagger_excerpt"] = _render_swagger_excerpt(parsed)
    summary["sourcemap_excerpt"] = _render_sourcemap_excerpt(parsed)
    summary["discovered_url_patterns"] = _render_url_patterns(parsed)
    summary["auth_context"] = (
        f"credentialed scan: yes, username='{a.get('creds_username')}', "
        f"login_url='{a.get('login_url') or '(none)'}'"
        if has_creds else "credentialed scan: no")
    summary["state_mutating_endpoints"] = _render_endpoints_by_methods(
        parsed, ("POST", "PUT", "PATCH", "DELETE"))
    summary["high_value_endpoints"] = _render_high_value(parsed)
    summary["tenant_identifiers"] = _render_tenant_ids(parsed)
    summary["authenticated_responses"] = _render_response_samples(
        parsed, only_authenticated=has_creds)
    summary["rate_limit_signals"] = _render_rate_limit_signals(parsed)
    summary["graphql_endpoints"] = _render_findings_filtered(
        parsed, lambda f: "/graphql" in (f.get("evidence_url") or "").lower()
                          or "graphql" in (f.get("title") or "").lower())
    summary["spa_fallback_warning"] = _render_spa_fallback_warning(
        fingerprinter)
    summary["role_context_block"] = _render_role_context(
        role_scope_text, role_restrict_text)

    return summary


def _render_role_context(scope_text: str, restrict_text: str) -> str:
    """Compose the AUTHORIZED ROLE block fed into both prompt passes.

    Returns an empty string when either field is empty so an operator-
    edited prompt that references {role_context_block} on a non-role-
    aware scan still renders cleanly. When populated, the block is a
    bounded, clearly-delimited section the LLM can quote from when
    deciding whether an observed capability is in-scope or an abuse.

    The prefix lines ("AUTHORIZED ROLE", "OUT OF SCPOPE …") are the
    contract the FIDELITY_SYSTEM prompt and the per-scenario user
    templates rely on, so do not rename without updating both.
    """
    if not (scope_text and restrict_text):
        return ""
    return (
        "AUTHORIZED ROLE (the user whose session captured this telemetry)\n"
        "================================================================\n"
        f"{scope_text}\n\n"
        "OUT OF SCOPE (capabilities this user must NOT have)\n"
        "===================================================\n"
        f"{restrict_text}\n"
    )


def _render_spa_fallback_warning(fp: spa_fallback.Fingerprinter) -> str:
    """Emit a placeholder block listing hosts that return the same SPA
    shell (HTTP 200) for arbitrary paths, including paths that look
    like deprecated/exploitable admin consoles. The block is loud and
    explicit so the LLM treats path-existence on these hosts as zero
    evidence — the most common Enhanced-AI false positive class is a
    CDN-fronted SPA where every junk path 200s.

    Returns a fixed "(no SPA fallbacks detected)" line when the run
    found nothing, so the prompt always renders a real string and a
    typo never silently swallows the entire safety block."""
    hosts = fp.affected_hosts()
    if not hosts:
        return "(no SPA-fallback hosts detected on this scan)"
    lines = [
        "WARNING — the following hosts return HTTP 200 with the same",
        "SPA index.html for arbitrary paths, including paths that look",
        "like deprecated admin consoles. A 200 OK on these hosts is NOT",
        "evidence that a particular technology, JSP, .NET handler, or",
        "admin endpoint exists. Do NOT identify a technology or CVE",
        "purely from path existence on these hosts:",
    ]
    for h in hosts:
        sig = fp.host_signature(h) or {}
        lines.append(f"  - {h}  (fallback body size={sig.get('size', 0)})")
    return "\n".join(lines)


# ---- placeholder render helpers --------------------------------------------
# Each helper returns a string suitable for str.format substitution. Empty
# results render as "(none observed)" so the LLM never sees an empty
# placeholder that could be misread as deletion of the section.


def _render_request_clusters(parsed: list[dict]) -> str:
    seen: dict[str, int] = {}
    for f in parsed[:MAX_FINDINGS_IN_PROMPT]:
        u = f.get("evidence_url") or ""
        if not u:
            continue
        # Collapse numeric IDs to {id}, UUIDs to {uuid} for cluster grouping
        pat = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}", u, flags=re.I)
        pat = re.sub(r"/\d+", "/{id}", pat)
        pat = re.sub(r"\?.*$", "", pat)
        method = (f.get("evidence_method") or "GET").upper()
        key = f"{method} {pat}"
        seen[key] = seen.get(key, 0) + 1
    if not seen:
        return "(none observed)"
    lines = sorted(seen.items(), key=lambda kv: -kv[1])
    return "\n".join(f"  {n}x  {key}" for key, n in lines[:80])


def _render_findings_filtered(parsed: list[dict],
                                pred,
                                limit: int = 30) -> str:
    out: list[str] = []
    for f in parsed:
        try:
            if not pred(f):
                continue
        except Exception:
            continue
        out.append(_format_one_finding(f))
        if len(out) >= limit:
            break
    return "\n\n".join(out) or "(none observed)"


def _format_one_finding(f: dict) -> str:
    rd = f.get("_raw_str") or ""
    if len(rd) > PER_FINDING_QUOTE_MAX:
        rd = rd[:PER_FINDING_QUOTE_MAX] + "..."
    method = (f.get("evidence_method") or "").upper() or "GET"
    # If our SPA-fallback probe identified this finding's URL as just
    # the SPA index echo, label it loudly so the LLM does not treat
    # the URL as evidence that a real handler/admin/version exists at
    # that path. The label rides inline with the URL line because that
    # is the line the model anchors its source/sink reasoning on.
    spa_tag = ""
    if f.get("_spa_fallback"):
        spa_tag = ("  [SPA-FALLBACK ECHO — body identical to host index; "
                   "do NOT infer technology presence from this URL]\n")
    return (f"#{f['id']} [{f.get('severity')}] {f.get('title')}\n"
            f"  tool={f.get('source_tool')} cwe={f.get('cwe') or '-'} "
            f"owasp={f.get('owasp_category') or '-'}\n"
            f"  {method} {f.get('evidence_url') or '-'}\n"
            f"{spa_tag}"
            f"  raw_data: {rd or '-'}")


def _render_endpoints_authenticated(parsed: list[dict], has_creds: bool) -> str:
    if not has_creds:
        return "(scan ran unauthenticated; no User A traffic to enumerate)"
    return _render_findings_filtered(
        parsed,
        lambda f: bool(f.get("evidence_url")), limit=40)


def _render_object_ids(parsed: list[dict]) -> str:
    candidates: list[str] = []
    for f in parsed:
        u = f.get("evidence_url") or ""
        for m in re.finditer(r"/(\d{2,})(?=[/?]|$)", u):
            candidates.append(f"  {u}  -> id={m.group(1)}")
        for m in re.finditer(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                u, flags=re.I):
            candidates.append(f"  {u}  -> uuid={m.group(0)}")
        # Look at JSON body keys that smell ID-shaped
        rs = f.get("_raw_str") or ""
        for m in re.finditer(
                r'"(\w*(?:id|uuid|guid|account|tenant|org)[\w_]*)"\s*:\s*"?([\w-]{4,})"?',
                rs, re.I):
            candidates.append(f"  body field: {m.group(1)}={m.group(2)}")
        if len(candidates) >= 60:
            break
    return "\n".join(candidates[:60]) or "(no obvious direct object refs)"


def _render_response_samples(parsed: list[dict],
                              only_authenticated: bool = False) -> str:
    """Render up to MAX_RESPONSE_SAMPLES (status, content-type, headers,
    body excerpt) blocks for findings whose proxy capture surfaced a
    body. The status / content-type / interesting-headers context is
    cheap (a few hundred bytes total) and gives the LLM enough
    fingerprinting signal to disambiguate a real handler from an SPA
    fallback echo without needing to quote the body for tech inference.
    The body itself is what satisfies the verbatim-quote rule for
    vulnerability evidence."""
    out: list[str] = []
    for f in parsed:
        rd = f.get("_raw") or {}
        # Look for response-shaped keys in raw_data — both the canonical
        # key flow_index now writes and the legacy keys some scanners use.
        body = (rd.get("response_body_excerpt")
                or (rd.get("evidence") or {}).get("response_body_excerpt")
                or rd.get("body") or "")
        if not body:
            continue
        body = body if len(body) <= PER_FINDING_QUOTE_MAX else \
                body[:PER_FINDING_QUOTE_MAX] + "..."
        # Header / status preamble — short (~200 bytes typical) but high
        # signal. Status alone tells the LLM whether the URL was
        # accessible, redirected, denied, or errored.
        meta_lines: list[str] = []
        status = rd.get("response_status")
        if status is not None:
            meta_lines.append(f"  status: {status}")
        ctype = rd.get("response_content_type")
        if ctype:
            meta_lines.append(f"  content-type: {ctype}")
        hdrs = rd.get("response_headers_excerpt")
        if hdrs:
            indented = "\n".join(f"    {h}" for h in hdrs.splitlines() if h)
            meta_lines.append(f"  headers:\n{indented}")
        meta = ("\n".join(meta_lines) + "\n") if meta_lines else ""
        out.append(f"#{f['id']} {f.get('evidence_url')}\n"
                   f"{meta}"
                   f"  body: {body}")
        if len(out) >= MAX_RESPONSE_SAMPLES:
            break
    return "\n\n".join(out) or "(no response bodies captured by scanners)"


def _render_mutating_requests(parsed: list[dict]) -> str:
    out: list[str] = []
    for f in parsed:
        method = (f.get("evidence_method") or "").upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        rd = f.get("_raw") or {}
        body = (rd.get("request_body")
                or (rd.get("evidence") or {}).get("request_body") or "")
        if not body and not _looks_jsonish(f.get("_raw_str") or ""):
            continue
        body_quote = body if body else (f.get("_raw_str") or "")[:PER_FINDING_QUOTE_MAX]
        out.append(f"[#{f['id']} {method} {f.get('evidence_url')}]\n"
                   f"  body: {body_quote}")
        if len(out) >= 30:
            break
    return "\n\n".join(out) or "(no mutating JSON requests captured)"


def _render_endpoints_by_methods(parsed: list[dict],
                                   methods: tuple[str, ...]) -> str:
    out: list[str] = []
    seen: set[str] = set()
    for f in parsed:
        m = (f.get("evidence_method") or "GET").upper()
        if m not in methods:
            continue
        # Echo-host pre-filter: this renderer emits URL+method only,
        # with no captured response body to ground the LLM's reasoning.
        # If the URL sits on a host that returns a path-agnostic body
        # (SPA fallback or dead-upstream gateway echo), the URL line
        # itself carries zero technology-presence signal, and inlining
        # an `[SPA-FALLBACK ECHO]` tag has historically not been enough
        # to stop the model from speculating off it. Drop the line
        # entirely so the model literally cannot cite a path that is
        # just the host's default echo. (Body-bearing renderers like
        # _render_response_samples keep their entries because the body
        # is itself useful telemetry.)
        if f.get("_spa_fallback"):
            continue
        url = f.get("evidence_url") or ""
        key = f"{m} {url}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f"  {m} {url}")
        if len(out) >= 80:
            break
    return "\n".join(out) or "(none observed)"


def _render_auth_redirect_chain(parsed: list[dict]) -> str:
    rows: list[str] = []
    for f in parsed:
        u = f.get("evidence_url") or ""
        if not re.search(r"/(authorize|oauth|openid|saml|sso|callback|redirect)",
                         u, re.I):
            continue
        rows.append(f"  {(f.get('evidence_method') or 'GET').upper()} {u}")
        rd = f.get("_raw") or {}
        loc = rd.get("location") or (rd.get("headers") or {}).get("Location")
        if loc:
            rows.append(f"    -> 30x Location: {loc}")
    return "\n".join(rows) or "(no OAuth/OIDC/SAML redirect chain captured)"


def _render_oauth_endpoints(parsed: list[dict]) -> str:
    found: set[str] = set()
    for f in parsed:
        # Same echo-host pre-filter as _render_endpoints_by_methods: a
        # URL on a host that echoes the same body for every path
        # carries no signal that an OAuth/OIDC route is genuinely there.
        if f.get("_spa_fallback"):
            continue
        u = f.get("evidence_url") or ""
        if re.search(r"\.well-known/openid-configuration|/authorize|/token|"
                     r"/userinfo|/jwks|/introspect|/saml/metadata", u, re.I):
            found.add(u)
    return "\n".join(f"  {u}" for u in sorted(found)) or "(none observed)"


def _render_url_processing(parsed: list[dict]) -> str:
    out: list[str] = []
    for f in parsed:
        # Echo-host pre-filter: same rationale as the path-only
        # renderers — a URL-with-param on a host that echoes its
        # default body regardless of input is not actually accepting a
        # URL parameter, just being requested with one.
        if f.get("_spa_fallback"):
            continue
        rd_str = f.get("_raw_str") or ""
        if _url_param_present(f.get("_raw") or {}) or "ssrf" in (
                f.get("title") or "").lower():
            out.append(_format_one_finding(f))
        if len(out) >= 25:
            break
    return "\n\n".join(out) or "(no URL-processing endpoints observed)"


def _render_infra_signals(parsed: list[dict]) -> str:
    bag: dict[str, set[str]] = {}
    interesting = ("server", "x-powered-by", "x-aspnet-version",
                    "x-amz-request-id", "x-azure-ref", "x-goog-",
                    "via", "x-frame-options")
    for f in parsed:
        rd = f.get("_raw") or {}
        headers = (rd.get("headers") or {}) if isinstance(rd, dict) else {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                if any(k.lower().startswith(i) for i in interesting):
                    bag.setdefault(k.lower(), set()).add(str(v)[:200])
        # Also scan error envelopes for stack-trace fingerprints
        body = ""
        if isinstance(rd, dict):
            body = rd.get("response_body_excerpt") or rd.get("body") or ""
        if body:
            for token in ("Spring Boot", "Django", "Rails", "Express",
                           "Flask", "Tomcat", "AKS", "EKS", "GKE",
                           "Kubernetes", "Lambda", "/var/task/"):
                if token in body:
                    bag.setdefault("body_tokens", set()).add(token)
    if not bag:
        return "(no clear infrastructure fingerprints captured)"
    return "\n".join(f"  {k}: {', '.join(sorted(v))[:300]}"
                      for k, v in sorted(bag.items()))


def _render_swagger_excerpt(parsed: list[dict]) -> str:
    for f in parsed:
        title = (f.get("title") or "").lower()
        if "swagger" in title or "openapi" in title:
            return _format_one_finding(f)
    return "(no exposed swagger/openapi endpoint observed)"


def _render_sourcemap_excerpt(parsed: list[dict]) -> str:
    for f in parsed:
        title = (f.get("title") or "").lower()
        if "source map" in title or ".map" in (f.get("evidence_url") or ""):
            return _format_one_finding(f)
    return "(no exposed sourcemap observed)"


def _render_url_patterns(parsed: list[dict]) -> str:
    return _render_request_clusters(parsed)


def _render_high_value(parsed: list[dict]) -> str:
    rows: list[str] = []
    for f in parsed:
        u = f.get("evidence_url") or ""
        if re.search(r"/(login|signin|logon|password[-_]?reset|forgot|"
                     r"otp|verify|mfa|recover|signup|register|2fa)",
                     u, re.I):
            rows.append(_format_one_finding(f))
        if len(rows) >= 25:
            break
    return "\n\n".join(rows) or "(no high-value endpoints observed)"


def _render_tenant_ids(parsed: list[dict]) -> str:
    rows: list[str] = []
    seen: set[str] = set()
    for f in parsed:
        u = f.get("evidence_url") or ""
        rs = f.get("_raw_str") or ""
        for m in re.finditer(
                r"\b((?:org|tenant|account|workspace|team)[_-]?id)\b\s*[:=]\s*[\"']?([\w-]+)",
                u + " " + rs, re.I):
            key = f"{m.group(1)}={m.group(2)}"
            if key in seen:
                continue
            seen.add(key)
            rows.append(f"  {key}  (seen near {u or 'body'})")
        for m in re.finditer(r"X-(Org|Tenant|Account|Workspace)-Id:\s*([^\s\"']+)",
                              rs, re.I):
            key = f"X-{m.group(1)}-Id={m.group(2)}"
            if key in seen:
                continue
            seen.add(key)
            rows.append(f"  header {key}")
    return "\n".join(rows[:60]) or "(no tenant identifiers detected)"


def _render_rate_limit_signals(parsed: list[dict]) -> str:
    rows: list[str] = []
    for f in parsed:
        rs = f.get("_raw_str") or ""
        if any(t in rs for t in ("429", "Retry-After", "X-RateLimit", "rate limit")):
            rows.append(_format_one_finding(f))
        if len(rows) >= 15:
            break
    return "\n\n".join(rows) or "(no 429/Retry-After/rate-limit headers captured)"


def _looks_jsonish(s: str) -> bool:
    s = (s or "").strip()
    return s.startswith("{") and s.endswith("}")


def _looks_auth_related(f: dict) -> bool:
    fields = " ".join(str(f.get(k) or "") for k in ("title", "source_tool", "cwe", "owasp_category"))
    return bool(re.search(r"\b(auth|session|jwt|oauth|sso|saml|login|password|"
                            r"token|cookie|2fa|mfa)\b", fields, re.I))


def _url_param_present(rd: dict) -> bool:
    if not isinstance(rd, dict):
        return False
    flat = json.dumps(rd, default=str).lower()
    return any(p in flat for p in
                ('"url":', '"webhook":', '"image_url":', '"callback":',
                  '"redirect":', '"fetch":', '"target":', '"href":'))


# ---- fire_when expression evaluator ----------------------------------------
# Tiny recursive-descent parser. Tokens: identifiers, integers, comparison
# operators (>=, >, <=, <, =, ==), AND/OR, parens. No general-purpose
# eval — the grammar is closed and parses to a single boolean. Unknown
# identifiers evaluate to False so a typo never fires by accident.

_FIRE_WHEN_TOKEN_RE = re.compile(
    r"\s*(?:(\d+)|(>=|<=|==|!=|>|<|=)|(\(|\))|(AND|OR|and|or)|([A-Za-z_][\w]*))")


def _fire_when_tokenize(expr: str) -> list[tuple[str, str]]:
    pos = 0
    out: list[tuple[str, str]] = []
    while pos < len(expr):
        m = _FIRE_WHEN_TOKEN_RE.match(expr, pos)
        if not m:
            raise ValueError(f"fire_when: unexpected character at {pos}: "
                              f"{expr[pos:pos+10]!r}")
        if m.group(1):
            out.append(("INT", m.group(1)))
        elif m.group(2):
            out.append(("OP", m.group(2)))
        elif m.group(3):
            out.append(("PAREN", m.group(3)))
        elif m.group(4):
            out.append(("BOOLOP", m.group(4).upper()))
        elif m.group(5):
            out.append(("ID", m.group(5)))
        pos = m.end()
    return out


def evaluate_fire_when(expr: str, summary: dict) -> bool:
    """Evaluate a fire_when expression against the telemetry summary.

    Empty / whitespace-only expression always fires (treated as
    "always"). Returns False on any parse / evaluation error so a
    malformed expression entered by an admin can't crash the run — it
    just silently disables the scenario, which the operator will see in
    the AI-Prompts page.
    """
    if not expr or not expr.strip():
        return True
    try:
        tokens = _fire_when_tokenize(expr)
    except Exception as e:
        logger.warning("fire_when tokenize failed (%r): %s", expr, e)
        return False

    # Expression precedence: OR (lowest), AND, comparisons.
    pos = [0]   # mutable index closure

    def peek() -> Optional[tuple[str, str]]:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume() -> tuple[str, str]:
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_atom():
        t = peek()
        if not t:
            raise ValueError("unexpected end of expression")
        if t[0] == "PAREN" and t[1] == "(":
            consume()
            v = parse_or()
            close = consume()
            if close != ("PAREN", ")"):
                raise ValueError(f"expected ')', got {close}")
            return v
        if t[0] == "ID":
            consume()
            ident = t[1]
            # Comparison form: <ident> >= <int>
            nxt = peek()
            if nxt and nxt[0] == "OP":
                op = consume()[1]
                rhs = consume()
                if rhs[0] != "INT":
                    raise ValueError(f"expected integer after {op}, got {rhs}")
                lhs_value = summary.get(ident, 0)
                rhs_value = int(rhs[1])
                try:
                    lhs_int = int(lhs_value)
                except (TypeError, ValueError):
                    return False
                if op == ">=":
                    return lhs_int >= rhs_value
                if op == ">":
                    return lhs_int > rhs_value
                if op == "<=":
                    return lhs_int <= rhs_value
                if op == "<":
                    return lhs_int < rhs_value
                if op in ("==", "="):
                    return lhs_int == rhs_value
                if op == "!=":
                    return lhs_int != rhs_value
                raise ValueError(f"unknown operator {op}")
            return bool(summary.get(ident, False))
        raise ValueError(f"unexpected token: {t}")

    def parse_and():
        v = parse_atom()
        while True:
            nxt = peek()
            if nxt and nxt == ("BOOLOP", "AND"):
                consume()
                # Right side MUST be parsed (and its tokens consumed)
                # before we collapse to a boolean. The earlier form
                # `v = bool(v) and bool(parse_atom())` short-circuited
                # in Python when v was False, leaving the right side's
                # tokens un-consumed, which then surfaced upstream as
                # "trailing tokens after expression". Splitting the
                # parse from the combine forces every operand to be
                # tokenized regardless of the running boolean value.
                right = parse_atom()
                v = bool(v) and bool(right)
            else:
                return v

    def parse_or():
        v = parse_and()
        while True:
            nxt = peek()
            if nxt and nxt == ("BOOLOP", "OR"):
                consume()
                # Same short-circuit hazard as parse_and: when v is
                # already True, Python skips the right operand and
                # leaves its tokens dangling. Parse first, combine
                # after.
                right = parse_and()
                v = bool(v) or bool(right)
            else:
                return v

    try:
        result = parse_or()
        if pos[0] != len(tokens):
            raise ValueError("trailing tokens after expression")
        return bool(result)
    except Exception as e:
        logger.warning("fire_when evaluate failed (%r): %s", expr, e)
        return False


# ---- prompt rendering ------------------------------------------------------

class _SafeDict(dict):
    """Custom dict for str.format_map. Missing keys render as a marker
    string so a typo in a placeholder never crashes the LLM call."""
    def __missing__(self, key):
        return f"{{placeholder=??unknown??:{key}}}"


def render_user_prompt(template: str, summary: dict) -> str:
    """Substitute {placeholders} in the user template against the
    telemetry summary. Missing placeholders render as a marker so the
    LLM sees clearly that the value was not available rather than a
    silent empty string. Curly braces inside the template that are NOT
    part of a placeholder name (e.g. JSON examples) must be doubled —
    same rule as Python's str.format. The seed prompts already follow
    this convention.

    Private summary keys (those whose name starts with '_') are
    deliberately NOT exposed for substitution — they exist only so
    post-processing can read them after the call."""
    public = {k: v for k, v in summary.items() if not k.startswith("_")}
    try:
        return template.format_map(_SafeDict(public))
    except Exception as e:
        logger.warning("render_user_prompt failed: %s; falling back", e)
        return template


# Runtime safety preamble prepended to every weakness-discovery user
# prompt at call time. It re-asserts the anti-hallucination rules
# already present in HEADER, and injects the per-host SPA-fallback
# warning so the LLM sees the warning even when the operator has
# customized the user template to drop the {spa_fallback_warning}
# placeholder. Keeping this in code (not in the seeded HEADER) means
# operators can edit either prompt freely without removing the safety
# floor.
#
# The preamble is also where the candidate-vs-verdict contract lives:
# weakness-pass output is a CANDIDATE list (the fidelity stage validates),
# so the floor is 0.5 with telemetry-only inferences capped at 0.6.
# Putting these rules here (rather than in the operator-editable user
# template or the per-assessment role context) keeps every scan running
# under one consistent contract regardless of what an operator typed
# into the role fields.
_RUNTIME_SAFETY_PREAMBLE = """\
=== RUNTIME SAFETY CONTEXT (do NOT ignore) ===

1. EVIDENCE RULE.
   - Preferred: every value in the `evidence` field is an exact
     substring of the INPUT block above (status / headers / body
     excerpts shown under RESPONSE SAMPLES, or raw_data quoted under
     a finding row).
   - Fallback (when no body excerpt was captured for the URL you are
     reasoning about): cite the finding ID(s) and the request line the
     inference rests on, set the candidate's verdict reasoning to begin
     with the literal phrase "inferred-from-telemetry:", and CAP its
     confidence at 0.6. Never fabricate a body quote that is not in
     the INPUT.

2. PATH EXISTENCE IS NOT EVIDENCE. An HTTP 200 response on a path is
   NOT proof that a particular technology, framework, or admin
   console is deployed. Many CDN-fronted SPAs return the same
   index.html with HTTP 200 for every unmatched path. Do not infer
   JSP, .NET, WordPress, JBoss, JAMon, or any other component, and do
   not propose a CVE chain, purely from the presence of a path or a
   200 status. Require an explicit version banner, error envelope, or
   distinctive body content quoted verbatim from the INPUT.

3. SPA-FALLBACK HOSTS DETECTED THIS RUN
{spa_fallback_warning}

4. CANDIDATE OUTPUT, NOT VERDICTS. Your role here is candidate
   discovery — a downstream fidelity pass will re-evaluate each item
   with stricter rules and assign the final verdict. Emit candidates
   with confidence >= 0.5; do NOT silently drop a candidate just
   because you are unsure. Prefer fewer high-value candidates
   (cross-tenant access, privilege escalation, auth bypass,
   business-logic abuse, unauthenticated mutation, exposure of
   secrets/PII) over many low-value ones.

=== END RUNTIME SAFETY CONTEXT ===

"""


# Operator-supplied role text frequently has output-gating directives
# wedged into it ("ONLY SHOW FINDINGS WITH A CONFIDENCE SCORE OF 0.75
# OR HIGHER", "DON'T REPORT IT", etc.). Those directives belong in the
# code-owned RUNTIME_SAFETY_PREAMBLE — when they live in the role text
# they (a) collide with the candidate-vs-verdict contract above, (b)
# get duplicated across both role_scope and role_restrictions because
# the operator pasted them into both fields, and (c) silently invert
# the weakness pass into a one-shot validator that returns [] when
# evidence is incomplete.
#
# This sanitizer strips the known forms at prompt-render time so that
# already-saved assessments self-heal without requiring a DB migration
# or operator edit. Conservative — only matches the literal output-
# gating phrases, never touches descriptive scope text.
_ROLE_GATING_PHRASES = (
    re.compile(
        r"^\s*ONLY\s+SHOW\s+FINDINGS\s+WITH\s+A\s+CONFIDENCE\s+SCORE\s+"
        r"OF\s+0?\.?\d+\s+OR\s+HIGHER[^\n]*\n?",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*IF\s+CONFIDENCE\s+SCORE\s+IS\s+LESS\s+THAN\s+0?\.?\d+[^\n]*\n?",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*DON.?T\s+REPORT\s+IT[^\n]*\n?",
        re.IGNORECASE | re.MULTILINE,
    ),
)


def _sanitize_role_text(text: str) -> str:
    """Strip output-gating directives from operator-supplied role text.

    These directives live in the prompt preamble (one source of truth);
    when they are also in the role text they fight the preamble's
    candidate-vs-verdict contract and the weakness pass returns []. This
    keeps existing assessments working without forcing the operator to
    re-edit them."""
    if not text:
        return text
    out = text
    for pat in _ROLE_GATING_PHRASES:
        out = pat.sub("", out)
    # Collapse runs of blank lines left behind by the deletions so the
    # role block does not render with awkward gaps.
    out = re.sub(r"\n{3,}", "\n\n", out).strip()
    return out


def _build_runtime_user_prompt(template: str, summary: dict) -> str:
    """Render the operator-editable user template, then prepend the
    runtime safety preamble. The preamble carries the SPA-fallback
    warning and the verbatim-evidence rule so they apply even if an
    operator removed the corresponding placeholder from the
    user_template.

    When the assessment supplied role-aware context, the AUTHORIZED
    ROLE block is appended after the safety preamble (and before the
    operator template) so every weakness-discovery scenario sees it
    regardless of whether the operator quoted {role_context_block} in
    their template. The block is empty (and therefore a no-op) on
    assessments that did not opt into the role-aware pass."""
    rendered = render_user_prompt(template, summary)
    preamble = _RUNTIME_SAFETY_PREAMBLE.format(
        spa_fallback_warning=summary.get("spa_fallback_warning", ""))
    role_block = summary.get("role_context_block") or ""
    if role_block:
        # Wrap the rendered role context in a small reminder so the
        # weakness-discovery model treats authorized capabilities as
        # non-findings. The fidelity prompt has its own, more detailed,
        # treatment of the same idea -- this keeps the weakness pass
        # from emitting findings the fidelity pass would only have to
        # downgrade.
        role_block = (
            "=== AUTHORIZED USER CONTEXT (suppress findings within scope) ===\n"
            + role_block
            + "Capabilities the AUTHORIZED ROLE is permitted to perform are "
              "EXPECTED behavior; do NOT emit findings for them. Emit "
              "findings only for capabilities listed in OUT OF SCOPE, or "
              "for vulnerabilities (XSS, SQLi, IDOR, etc.) that go beyond "
              "anything the role is authorized to do.\n"
              "=== END AUTHORIZED USER CONTEXT ===\n\n")
    return preamble + role_block + rendered


# ---- LLM call wrapper with debug-log capture --------------------------------

def _call_llm(endpoint: dict, system_prompt: str, user_prompt: str, *,
              max_tokens: int, cache_system: bool) -> dict:
    """Dispatch to the right backend. Mirror of the dispatch in
    consolidation.run() — kept inline so this module stays
    self-contained when the consolidation prompt eventually moves into
    ai_prompts as well."""
    backend = (endpoint or {}).get("backend")
    if backend == "anthropic":
        return llm_mod.call_anthropic(
            endpoint["api_key"], endpoint["model"],
            system_prompt, user_prompt,
            max_tokens=max_tokens, cache_system=cache_system)
    if backend == "openai_compat":
        extra: dict = {}
        if endpoint.get("extra_headers"):
            try:
                extra = json.loads(endpoint["extra_headers"])
            except Exception:
                extra = {}
        return llm_mod.call_openai_compat(
            endpoint["base_url"], endpoint["api_key"], endpoint["model"],
            system_prompt, user_prompt,
            max_tokens=max_tokens, extra_headers=extra)
    return {"ok": False, "error": f"unknown backend: {backend}"}


def _record_analysis(*, aid: int, target_type: str, target_id: str,
                      endpoint: Optional[dict], status: str,
                      in_tokens: int, out_tokens: int,
                      payload: Optional[Any],
                      raw: Optional[str], request_prompt: Optional[str],
                      error_text: Optional[str], started_at: datetime) -> int:
    """Insert one llm_analyses row. request_prompt is only stored when
    debug mode is on at the call site (the caller passes None when
    debug is off, so storage is bounded)."""
    return db.execute("""
        INSERT INTO llm_analyses
            (target_type, target_id, assessment_id,
             endpoint_id, endpoint_name, model, status,
             request_tokens, response_tokens,
             request_prompt, raw_response, findings_json, error_text,
             created_at, finished_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        target_type, target_id, aid,
        (endpoint or {}).get("id"),
        (endpoint or {}).get("name"),
        (endpoint or {}).get("model"),
        status, in_tokens, out_tokens,
        request_prompt, raw,
        json.dumps(payload, default=str) if payload is not None else None,
        error_text,
        started_at, datetime.now(timezone.utc).replace(tzinfo=None),
    ))


# ---- budget tracking --------------------------------------------------------

class _BudgetState:
    """Accumulator for per-assessment Enhanced-AI spend.

    Kept as a lightweight class rather than module globals so the
    accountant is per-run; multiple assessments running concurrently
    don't share state. spent and cap are USD floats. tripped is set
    True the first time a call would push us past the cap; downstream
    iterations check tripped() and short-circuit with a graceful note."""

    def __init__(self, cap_usd: Optional[float]):
        # None = no cap (system-default lookup yielded NULL on a fresh DB
        # before the seed config row landed; treat as uncapped to avoid
        # silently disabling the feature).
        self.cap_usd: Optional[float] = cap_usd
        self.spent: float = 0.0
        self.tripped: bool = False
        self.tripped_at_cost: float = 0.0

    def add(self, cost: float) -> None:
        self.spent += float(cost or 0.0)

    def would_trip_on_next(self, projected_cost: float) -> bool:
        if self.cap_usd is None:
            return False
        return (self.spent + projected_cost) > float(self.cap_usd)

    def trip(self) -> None:
        if not self.tripped:
            self.tripped = True
            self.tripped_at_cost = self.spent

    def remaining(self) -> Optional[float]:
        if self.cap_usd is None:
            return None
        return max(0.0, float(self.cap_usd) - self.spent)


def _resolve_budget(aid: int) -> Optional[float]:
    """Resolve the per-assessment cap. Precedence:
      1. assessments.enhanced_ai_budget_usd if set (admin-supplied per-scan).
      2. config['advanced_ai_budget_default_usd'] (system default).
      3. None — uncapped (only happens on a fresh DB before the seed
         insert lands; should not occur in steady state)."""
    a = db.query_one(
        "SELECT enhanced_ai_budget_usd FROM assessments WHERE id=%s", (aid,))
    if a and a.get("enhanced_ai_budget_usd") is not None:
        try:
            return float(a["enhanced_ai_budget_usd"])
        except (TypeError, ValueError):
            pass
    row = db.query_one(
        "SELECT value FROM config WHERE `key`='advanced_ai_budget_default_usd'")
    if row and row.get("value"):
        try:
            return float(row["value"])
        except (TypeError, ValueError):
            return None
    return None


# ---- public entry point -----------------------------------------------------

def build_single_finding_fidelity_prompt(fid: int) -> dict:
    """Render — but do NOT send — the fidelity prompt for a single
    finding. Used by the workspace's "Challenge with LLM" preview step:
    the analyst sees the resolved system + user prompts, optionally
    edits the user prompt, then submits to actually run the call.

    Returns:
        {ok: True, system_prompt, user_prompt, prompt_id, finding_id, fqdn}
    or:
        {ok: False, error, message}
    """
    f = db.query_one(
        "SELECT id, assessment_id, source_tool, severity, owasp_category, "
        "cwe, title, description, evidence_url, evidence_method, raw_data, "
        "validation_status, validation_probe, validation_evidence "
        "FROM findings WHERE id=%s", (fid,))
    if not f:
        return {"ok": False, "error": "not_found",
                "message": f"finding {fid} does not exist"}
    a = db.query_one(
        "SELECT id, fqdn FROM assessments WHERE id=%s",
        (f["assessment_id"],))
    if not a:
        return {"ok": False, "error": "no_assessment"}
    prompt_row = db.query_one(
        "SELECT id, system_prompt, user_template, batch_size "
        "FROM ai_prompts WHERE slot=%s AND is_active=1 "
        "ORDER BY sort_order LIMIT 1",
        ("advanced_ai_testing.fidelity",))
    if not prompt_row:
        return {"ok": False, "error": "no_fidelity_prompt"}
    fqdn = a.get("fqdn") or ""
    batch_text = _render_fidelity_batch([f])
    sys_prompt = (prompt_row["system_prompt"] or "")
    user = render_user_prompt(prompt_row["user_template"], {
        "fqdn": fqdn,
        "findings_batch": batch_text,
    })
    return {
        "ok": True,
        "finding_id": fid,
        "prompt_id": prompt_row["id"],
        "fqdn": fqdn,
        "system_prompt": sys_prompt,
        "user_prompt": user,
    }


def run_single_finding_fidelity(fid: int,
                                  endpoint: Optional[dict],
                                  *,
                                  user_prompt_override: Optional[str] = None) -> dict:
    """Run the fidelity prompt against ONE finding, regardless of source
    tool or current validation status. Used by the per-finding "Challenge
    with LLM" button in the assessment workspace, which needs an
    on-demand re-grade for a row the analyst is questioning.
    Bypasses the bulk-pass exclusions (the source_tool != 'enhanced_ai_testing'
    skip and the validation_status filter) so an analyst can re-evaluate
    even an LLM-emitted row, with the model effectively grading its own
    earlier work in a single-row batch the analyst can review.

    Returns a result dict the HTTP handler renders as JSON:
        {ok, verdict, confidence, severity_adjustment, suggested_severity,
         reasoning, error}
    On any error the function returns {ok=False, error=...} rather than
    raising — the handler turns that into a 4xx/5xx and the caller's
    button shows the failure inline."""
    if not endpoint:
        return {"ok": False, "error": "no_endpoint",
                "message": "No LLM endpoint is configured."}
    f = db.query_one(
        "SELECT id, assessment_id, source_tool, severity, owasp_category, "
        "cwe, title, description, evidence_url, evidence_method, raw_data, "
        "validation_status, validation_probe, validation_evidence "
        "FROM findings WHERE id=%s", (fid,))
    if not f:
        return {"ok": False, "error": "not_found",
                "message": f"finding {fid} does not exist"}
    aid = f["assessment_id"]
    a = db.query_one(
        "SELECT id, fqdn, llm_debug FROM assessments WHERE id=%s", (aid,))
    if not a:
        return {"ok": False, "error": "no_assessment"}
    fqdn = a.get("fqdn") or ""
    debug_on = bool(a.get("llm_debug"))

    prompt_row = db.query_one(
        "SELECT id, system_prompt, user_template, batch_size "
        "FROM ai_prompts WHERE slot=%s AND is_active=1 "
        "ORDER BY sort_order LIMIT 1",
        ("advanced_ai_testing.fidelity",))
    if not prompt_row:
        return {"ok": False, "error": "no_fidelity_prompt"}

    batch_text = _render_fidelity_batch([f])
    sys_prompt = (prompt_row["system_prompt"] or "")
    # If the analyst hand-edited the user prompt in the preview modal,
    # use that verbatim — the system prompt is still the seeded one
    # because allowing edits there would change the output schema and
    # break verdict parsing. Truncated to a sane upper bound so a
    # paste-bomb doesn't blow the model's context.
    if user_prompt_override and user_prompt_override.strip():
        user = user_prompt_override.strip()[:48000]
    else:
        user = render_user_prompt(prompt_row["user_template"], {
            "fqdn": fqdn,
            "findings_batch": batch_text,
        })
    call_started = datetime.now(timezone.utc).replace(tzinfo=None)
    result = _call_llm(endpoint, sys_prompt, user,
                        max_tokens=FIDELITY_MAX_OUTPUT_TOKENS,
                        cache_system=True)
    in_tokens = int(result.get("in_tokens") or 0)
    out_tokens = int(result.get("out_tokens") or 0)

    if not result.get("ok"):
        err = result.get("error") or "LLM call failed"
        _record_analysis(
            aid=aid, target_type="enhanced_ai_fidelity",
            target_id=f"single:{fid}", endpoint=endpoint,
            status="error", in_tokens=in_tokens, out_tokens=out_tokens,
            payload=None, raw=result.get("raw"),
            request_prompt=user if debug_on else None,
            error_text=err, started_at=call_started)
        return {"ok": False, "error": "llm_call_failed", "message": err}

    verdicts = llm_mod.parse_findings(result.get("content") or "") or []
    applied = _apply_fidelity_verdicts([f], verdicts)
    _record_analysis(
        aid=aid, target_type="enhanced_ai_fidelity",
        target_id=f"single:{fid}", endpoint=endpoint,
        status="done", in_tokens=in_tokens, out_tokens=out_tokens,
        payload={"finding_id": fid, "verdicts": verdicts,
                  "evaluated": applied["evaluated"],
                  "auto_flipped": applied["auto_flipped"]},
        raw=result.get("raw") if debug_on else None,
        request_prompt=user if debug_on else None,
        error_text=None, started_at=call_started)

    # Verdicts from the LLM are an array; we sent one finding so we
    # expect one element. Pluck it out so the handler can render it as
    # a single object — easier on the JS than indexing a list.
    v = (verdicts[0] if verdicts and isinstance(verdicts, list) else
         {}) if isinstance(verdicts, list) else {}
    if not isinstance(v, dict):
        v = {}
    return {
        "ok": True,
        "finding_id": fid,
        "verdict": v.get("verdict") or "inconclusive",
        "confidence": v.get("confidence"),
        "severity_adjustment": v.get("severity_adjustment") or "none",
        "suggested_severity": v.get("suggested_severity"),
        "reasoning": v.get("reasoning") or "",
        "auto_flipped": bool(applied.get("auto_flipped")),
        "in_tokens": in_tokens,
        "out_tokens": out_tokens,
    }


def run(aid: int, endpoint: Optional[dict]) -> dict:
    """Top-level pass invoked by the orchestrator. Returns a summary
    dict for logging; never raises."""
    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    summary = {"weakness_findings_inserted": 0,
                "fidelity_evaluated": 0,
                "fidelity_auto_flipped": 0,
                "scenarios_run": 0, "scenarios_skipped": 0,
                "fidelity_batches_run": 0,
                "budget_tripped": False, "errors": []}

    if not endpoint:
        summary["errors"].append("no LLM endpoint configured")
        return summary

    a = db.query_one(
        "SELECT id, fqdn, llm_debug FROM assessments WHERE id=%s", (aid,))
    if not a:
        summary["errors"].append(f"no assessment {aid}")
        return summary
    debug_on = bool(a.get("llm_debug"))

    try:
        telemetry = build_telemetry(aid)
    except Exception as e:
        summary["errors"].append(f"telemetry build failed: {e!r}")
        return summary

    cap = _resolve_budget(aid)
    budget = _BudgetState(cap)

    # ---- weakness-discovery loop ------------------------------------------
    rows = db.query_all(
        "SELECT id, slot, name, system_prompt, user_template, category, "
        "fire_when, sort_order, batch_size FROM ai_prompts "
        "WHERE slot=%s AND is_active=1 ORDER BY sort_order ASC, id ASC",
        ("advanced_ai_testing.weakness_discovery",))

    for row in rows:
        if budget.tripped:
            summary["scenarios_skipped"] += 1
            continue
        if not evaluate_fire_when(row.get("fire_when") or "", telemetry):
            summary["scenarios_skipped"] += 1
            continue

        # Predict the cost of THIS call before issuing it. We don't know
        # the response size yet, so estimate input tokens from prompt
        # length and assume max output. Better to over-estimate and skip
        # a call than to overshoot the budget.
        # _build_runtime_user_prompt prepends the runtime safety
        # preamble (verbatim-evidence rule + SPA-fallback warning) so
        # the rules apply regardless of how the operator has edited
        # the user_template column.
        rendered_user = _build_runtime_user_prompt(
            row["user_template"], telemetry)
        # System prompts only ever take a single substitution ({fqdn}). We
        # used to render via str.format_map, but the FOOTER carries a JSON
        # example with literal "{" / "}" that format_map mistakes for format
        # fields — first one it hits ("severity") raises ValueError and the
        # whole scenario crashes. Plain str.replace sidesteps the format
        # mini-language entirely so braces inside JSON examples (or any
        # operator-pasted content) stay inert.
        sys_prompt = (row["system_prompt"] or "").replace(
            "{fqdn}", telemetry.get("fqdn", ""))
        approx_in = (len(sys_prompt) + len(rendered_user)) // 4
        approx_cost = llm_mod.cost(approx_in, WEAKNESS_MAX_OUTPUT_TOKENS,
                                     endpoint.get("model") or "")
        if budget.would_trip_on_next(approx_cost):
            budget.trip()
            summary["scenarios_skipped"] += 1
            continue

        call_started = datetime.now(timezone.utc).replace(tzinfo=None)
        result = _call_llm(endpoint, sys_prompt, rendered_user,
                            max_tokens=WEAKNESS_MAX_OUTPUT_TOKENS,
                            cache_system=True)
        in_tokens = int(result.get("in_tokens") or 0)
        out_tokens = int(result.get("out_tokens") or 0)
        cached = int(result.get("cache_read_tokens") or 0)
        actual_cost = llm_mod.cost(in_tokens, out_tokens,
                                     endpoint.get("model") or "",
                                     cached_in_tokens=cached)
        budget.add(actual_cost)

        if not result.get("ok"):
            err = result.get("error") or "LLM call failed"
            summary["errors"].append(
                f"weakness scenario {row['name']!r}: {err}")
            _record_analysis(
                aid=aid, target_type="enhanced_ai_weakness",
                target_id=f"prompt:{row['id']}", endpoint=endpoint,
                status="error", in_tokens=in_tokens, out_tokens=out_tokens,
                payload=None, raw=result.get("raw"),
                request_prompt=rendered_user if debug_on else None,
                error_text=err, started_at=call_started)
            continue

        findings = llm_mod.parse_findings(result.get("content") or "") or []
        # Anti-hallucination filter — reject LLM findings whose
        # evidence cannot be located verbatim in the rendered input
        # corpus, and reject any finding whose URL is just an SPA-
        # fallback echo. Pass both the system prompt and the rendered
        # user prompt as the corpus; the LLM is allowed to quote from
        # either.
        kept, dropped = _filter_hallucinations(
            findings, evidence_corpus=sys_prompt + "\n" + rendered_user,
            fingerprinter=telemetry.get("_spa_fingerprinter"))
        if dropped:
            logger.info(
                "enhanced_ai: dropped %d/%d findings from %s as "
                "ungrounded or SPA-fallback hallucinations",
                dropped, dropped + len(kept), row.get("name"))
        inserted = _insert_weakness_findings(aid, row, kept)
        summary["weakness_findings_inserted"] += inserted
        summary["scenarios_run"] += 1
        _record_analysis(
            aid=aid, target_type="enhanced_ai_weakness",
            target_id=f"prompt:{row['id']}", endpoint=endpoint,
            status="done", in_tokens=in_tokens, out_tokens=out_tokens,
            payload={"scenario": row["name"], "inserted": inserted,
                      "findings": findings},
            raw=result.get("raw") if debug_on else None,
            request_prompt=rendered_user if debug_on else None,
            error_text=None, started_at=call_started)

    if budget.tripped:
        summary["budget_tripped"] = True

    # ---- candidate-validation pass ----------------------------------------
    #
    # Weakness-pass findings land with validation_status='unvalidated'.
    # Before the LLM fidelity pass runs (and pays for input tokens to
    # judge each one), give them through the safe-only probe runner --
    # for any candidate whose CWE / title matches a toolkit probe, the
    # probe will execute against the live target and write a verdict
    # into validation_status + validation_evidence. The fidelity prompt
    # already surfaces those fields per-finding, so the LLM grades
    # candidates that have probe evidence with much tighter precision
    # than candidates it must judge from telemetry alone.
    #
    # safe_only=True restricts to read-only probes (manifest declares
    # safety_class='read-only'), so this never mutates target state.
    # The orchestrator already runs the same pass once after scanners
    # finish; re-running here only touches the NEW unvalidated rows
    # produced by the weakness loop because challenge_runner skips any
    # finding whose validation_status is already non-default.
    if summary["weakness_findings_inserted"] > 0:
        try:
            from scripts import challenge_runner as _cr
            _cr.run(aid, safe_only=True)
            summary["candidate_validation_run"] = True
        except Exception as e:
            # Probe failures must not stop the fidelity pass. Surface
            # the error onto the assessment but keep going so the LLM
            # still gets to grade what it produced.
            summary["errors"].append(f"candidate validation failed: {e!r}")
            summary["candidate_validation_run"] = False

    # ---- fidelity loop ----------------------------------------------------
    fidelity_rows = db.query_all(
        "SELECT id, name, system_prompt, user_template, batch_size "
        "FROM ai_prompts WHERE slot=%s AND is_active=1 "
        "ORDER BY sort_order ASC, id ASC LIMIT 1",
        ("advanced_ai_testing.fidelity",))
    if fidelity_rows and not budget.tripped:
        try:
            f_summary = _run_fidelity(aid, endpoint, telemetry,
                                        fidelity_rows[0], budget,
                                        debug_on=debug_on)
            summary["fidelity_evaluated"] = f_summary["evaluated"]
            summary["fidelity_auto_flipped"] = f_summary["auto_flipped"]
            summary["fidelity_batches_run"] = f_summary["batches_run"]
            if f_summary.get("errors"):
                summary["errors"].extend(f_summary["errors"])
        except Exception as e:
            summary["errors"].append(f"fidelity pass crashed: {e!r}")

    if budget.tripped:
        summary["budget_tripped"] = True
        # Surface to the assessment row so the analyst sees it on the page.
        # Append (don't overwrite) any prior error_text the orchestrator wrote.
        prior = db.query_one(
            "SELECT error_text FROM assessments WHERE id=%s", (aid,))
        existing = ((prior or {}).get("error_text") or "").rstrip()
        msg = (f"enhanced_ai_testing budget reached: ${budget.spent:.2f} of "
                f"${budget.cap_usd:.2f}; partial findings retained.")
        new_err = (existing + "\n" + msg).strip() if existing else msg
        db.execute("UPDATE assessments SET error_text = %s WHERE id=%s",
                    (new_err[:65000], aid))

    # Roll the spend onto the assessment row alongside other LLM cost.
    db.execute("""
        UPDATE assessments
           SET llm_cost_usd = COALESCE(llm_cost_usd, 0) + %s
         WHERE id = %s
    """, (round(budget.spent, 6), aid))
    summary["spent_usd"] = round(budget.spent, 6)
    summary["cap_usd"] = budget.cap_usd
    return summary


# ---- weakness finding insertion --------------------------------------------

_SEV_ALLOWED = {"critical", "high", "medium", "low", "info"}

# Minimum evidence quote length we bother to verify. Anything shorter is
# almost certainly a punctuation fragment ('GET', '200', '/api/') that
# would substring-match anywhere and provides no real grounding signal.
# Findings below this threshold pass the verbatim check on length alone.
_VERBATIM_MIN_CHARS = 12

# Maximum quote length checked verbatim. If the LLM emits a 4 KB quote
# we still want a check, but normalizing 4 KB on every finding is
# expensive; 800 chars is plenty to pin a finding to a specific input
# block. (PER_FINDING_QUOTE_MAX matches; reusing the constant feels
# coupled — kept independent so the verbatim-check budget can shrink
# without touching prompt-rendering caps.)
_VERBATIM_MAX_CHARS = 800

# URL extractor for re-checking LLM output against the SPA-fallback
# fingerprinter. We accept either a full https URL or a path token
# the LLM might quote (e.g. "/JAMonAdmin.jsp"). When only a path is
# present we have no host to probe, so the path-only case can only be
# matched against fingerprinted hosts whose URLs the LLM also quoted.
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _normalize_for_verbatim(s: str) -> str:
    """Collapse whitespace runs to single spaces and lowercase. Used by
    the verbatim-evidence check so trivial spacing/case differences
    between the LLM's quote and the corpus do not falsely reject a
    real quote. We deliberately keep punctuation — the LLM's evidence
    still has to be a literal substring modulo spacing."""
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


def _evidence_is_grounded(evidence: str, normalized_corpus: str) -> bool:
    """Return True iff the evidence string is a verbatim (whitespace-
    normalized, case-insensitive) substring of the corpus. Very short
    evidence (< _VERBATIM_MIN_CHARS) is allowed through unconditionally
    — those quotes carry no real grounding signal but are common in
    benign findings (e.g. "200", "no CSP header") and rejecting them
    would over-block. Very long evidence is truncated before
    comparison for performance."""
    if not evidence:
        # Empty evidence is its own bug, handled by the caller's
        # title/severity check; do not double-flag here.
        return True
    norm = _normalize_for_verbatim(evidence)
    if len(norm) < _VERBATIM_MIN_CHARS:
        return True
    if len(norm) > _VERBATIM_MAX_CHARS:
        norm = norm[:_VERBATIM_MAX_CHARS]
    return norm in normalized_corpus


def _finding_cites_spa_fallback(item: dict,
                                 fingerprinter: Optional[Any]) -> bool:
    """Return True iff any URL the LLM mentions in this finding's
    evidence/title/description/recommendation matches the cached SPA-
    fallback signature. We only check fully-qualified URLs (the
    fingerprinter needs a host); bare-path quotes are out of scope
    because they have no host to associate with.

    The fingerprinter caches per-URL probes, so calling is_fallback
    on the same URL multiple times across findings is cheap."""
    if not fingerprinter:
        return False
    blob = " ".join(str(item.get(k) or "") for k in
                     ("evidence", "title", "description", "recommendation"))
    for m in _URL_RE.finditer(blob):
        url = m.group(0).rstrip(".,);'\"")
        try:
            if fingerprinter.is_fallback(url):
                return True
        except Exception as e:
            logger.debug("spa_fallback is_fallback(%s) failed: %r", url, e)
    return False


def _filter_hallucinations(items: list,
                            *, evidence_corpus: str,
                            fingerprinter: Optional[Any]
                            ) -> tuple[list, int]:
    """Split LLM-emitted findings into (kept, dropped_count).

    Two filters apply:
      1. Verbatim-evidence — the `evidence` field must appear (modulo
         whitespace and case) in the input corpus the LLM was given.
         If it does not, the LLM either fabricated the quote or
         paraphrased it past recognition; either way the finding is
         not grounded in the scan data and we drop it.
      2. SPA-fallback citation — any URL in the finding's text that
         our fingerprinter has confirmed is just the SPA index echo
         is treated as fabricated evidence; the finding is dropped.

    Items that are not dicts pass through unchanged for the
    downstream schema check in _insert_weakness_findings to handle.
    """
    if not isinstance(items, list):
        return items, 0
    normalized_corpus = _normalize_for_verbatim(evidence_corpus)
    kept: list = []
    dropped = 0
    for item in items:
        if not isinstance(item, dict):
            kept.append(item)
            continue
        evidence = (item.get("evidence") or "").strip()
        if not _evidence_is_grounded(evidence, normalized_corpus):
            logger.info(
                "enhanced_ai: dropping ungrounded finding %r "
                "(evidence quote not present verbatim in input)",
                (item.get("title") or "")[:80])
            dropped += 1
            continue
        if _finding_cites_spa_fallback(item, fingerprinter):
            logger.info(
                "enhanced_ai: dropping SPA-fallback finding %r "
                "(LLM cited a URL whose body is just the SPA index)",
                (item.get("title") or "")[:80])
            dropped += 1
            continue
        kept.append(item)
    return kept, dropped


# Map an AI weakness-discovery scenario name (the `category` field the
# LLM echoes back per the FOOTER_TEMPLATE in enhanced_ai_prompts.py) to
# an OWASP Top 10 (2021) code. The downstream report pipeline groups
# findings on the OWASP code: per-category demerit math, the heat-map
# rows, the cover scorecard, and the new shared compute_overall_grade()
# pipeline all key off it. Until this map existed the AI was writing
# its scenario label ('bola_idor', 'rate_limit_evasion', etc.) directly
# into `owasp_category`, so AI findings sat in an "Other" bucket and
# never rolled into the right OWASP row.
#
# The fidelity-prompt scenario doesn't appear here because that pass
# regrades EXISTING findings (it doesn't insert new ones), so its
# category never reaches `owasp_category`.
_SCENARIO_TO_OWASP: dict[str, str] = {
    # Authorization failures — direct/function-level access checks.
    "bola_idor":              "A01:2021-Broken_Access_Control",
    "bfla":                   "A01:2021-Broken_Access_Control",
    "tenant_isolation":       "A01:2021-Broken_Access_Control",
    # Injection variants. Second-order injection is still injection
    # for OWASP grouping purposes; the "second-order" twist matters
    # for triage but not for the per-category bucket.
    "second_order_injection": "A03:2021-Injection",
    # Insecure design covers business logic, mass assignment, race
    # conditions, and rate-limit evasion: each is a logic-level flaw
    # rather than an implementation bug, which is the OWASP A04
    # bucket's intent.
    "business_logic":         "A04:2021-Insecure_Design",
    "mass_assignment":        "A04:2021-Insecure_Design",
    "race_condition":         "A04:2021-Insecure_Design",
    "rate_limit_evasion":     "A04:2021-Insecure_Design",
    # Authentication / OAuth flaws.
    "oauth_oidc_flaw":        "A07:2021-Identification_and_Authentication_Failures",
    # SSRF has its own dedicated A10 bucket.
    "ssrf":                   "A10:2021-Server-Side_Request_Forgery",
}


def _scenario_to_owasp(scenario: str) -> str:
    """Translate an AI weakness-discovery scenario name into the OWASP
    Top 10 code the rest of the pipeline expects. Unknown scenarios
    fall back to A04 ('Insecure Design') because every weakness-
    discovery scenario shipped today is fundamentally a design-level
    issue rather than a configuration one — that's the closest
    correct bucket if a future scenario lands without a map entry."""
    if not scenario:
        return ""
    return _SCENARIO_TO_OWASP.get(
        scenario.strip().lower(), "A04:2021-Insecure_Design")


# Patterns that indicate a finding's `evidence` field is just another
# scanner's URL-line claim — i.e. the LLM read a Nikto/Wapiti output
# line and asserted it as evidence without independent grounding.
# Examples seen in the wild on dead-vhost telemetry:
#     "1x  GET https://target/scripts/proxy/w3proxy.dll"
#     "GET https://target/server-status"
#     "https://target/some/path"
#     "/scripts/proxy/w3proxy.dll: MSProxy v1.0 installed."
# Each is just a path assertion. Per the HEADER's G3 grounding rule,
# a finding whose only support is a path-existence claim from another
# scanner must NOT be high/critical. We enforce that mechanically here
# so a model that drifts past the prompt-level rule still produces a
# correct row. Body-bearing evidence (quoted error envelopes, version
# banners, response excerpts) does NOT match — those have braces,
# angle brackets, newlines, or longer quoted text.
_SCANNER_CLAIM_PATTERNS = (
    # nikto-style "<count>x GET <url>"
    re.compile(r"^\s*\d+x?\s+(?:GET|HEAD|POST|PUT|PATCH|DELETE)\s+https?://\S+\s*$",
                re.I),
    # bare "<METHOD> <url>"
    re.compile(r"^\s*(?:GET|HEAD|POST|PUT|PATCH|DELETE)\s+https?://\S+\s*$",
                re.I),
    # bare URL
    re.compile(r"^\s*https?://\S+\s*$", re.I),
    # nikto descriptor line: "/path: <description>" with no quoted body
    re.compile(r"^\s*/\S+\s*:\s*[^{<>\"'\n]+$"),
)


def _g3_downgrade_if_scanner_only(item: dict) -> dict | None:
    """Mechanical enforcement of HEADER rule G3: a finding whose only
    grounding is another scanner's path-existence claim cannot ride at
    high or critical severity. Returns a small audit dict describing
    the action taken (None if no action needed) — caller stamps it
    into raw_data so a downstream reviewer can see the row was
    auto-touched and why."""
    sev = (item.get("severity") or "").lower()
    if sev not in ("high", "critical"):
        return None
    evidence = (item.get("evidence") or "").strip()
    if not evidence:
        # No evidence at all is its own G1 violation; let the caller
        # filter the row, this function only handles the scanner-claim
        # subcase.
        return None
    # Reject body-bearing evidence early — anything with a quoted
    # response body, JSON envelope, or HTML snippet is not a scanner-
    # only claim. Length > 240 also indicates the LLM pasted real
    # content, not a one-line URL.
    if len(evidence) > 240:
        return None
    if any(ch in evidence for ch in ("{", "}", "<", ">", "\"", "\n")):
        return None
    matched = next((p for p in _SCANNER_CLAIM_PATTERNS
                    if p.match(evidence)), None)
    if not matched:
        return None
    # Record the downgrade and rewrite the item in place. Title is
    # prefixed (not replaced) so the downstream UI surfaces the caveat
    # next to the original assertion.
    audit = {
        "g3_auto_downgraded": True,
        "g3_original_severity": sev,
        "g3_match_pattern": matched.pattern,
        "g3_reason": ("evidence is a scanner path-existence line with "
                      "no independent body/banner support"),
    }
    item["severity"] = "low"
    title = (item.get("title") or "").strip()
    if not title.upper().startswith("REQUIRES MANUAL VERIFICATION"):
        item["title"] = ("REQUIRES MANUAL VERIFICATION: " + title)[:500]
    rec = (item.get("recommendation") or "").strip()
    note = ("\n\n_Auto-downgraded by G3 enforcement: this finding was "
            "emitted at " + sev + " severity but its only evidence is "
            "another scanner's path-existence line. Severity reset to "
            "`low` until an analyst quotes a verbatim body, banner, or "
            "error envelope from the response._")
    item["recommendation"] = (rec + note)[:8000]
    return audit


_DEDUP_STOPWORDS = frozenset((
    "the", "a", "an", "is", "are", "in", "on", "of", "to", "for", "and",
    "or", "with", "via", "by", "from", "as", "at", "be", "this", "that",
    "endpoint", "endpoints", "exposed", "unauthenticated", "missing",
    "request", "response", "leak", "leaks", "leaking", "internal",
    "external", "application", "applications", "leakage",
))


_DEDUP_VULN_CLASSES = (
    # Order matters: longer / more specific phrases first so "xss" doesn't
    # win over "stored xss" when the title carries both.
    ("stored_xss",          (r"stored\s+xss",)),
    ("reflected_xss",       (r"reflected\s+xss",)),
    ("dom_xss",             (r"dom[\s-]+xss",)),
    ("xss",                 (r"\bxss\b", r"cross[\s-]+site\s+scripting")),
    ("sqli_union",          (r"union[\s-]+(?:based\s+)?sql", r"union\s+select")),
    ("sqli",                (r"\bsqli\b", r"sql\s+injection")),
    ("nosqli",              (r"nosql\s+injection", r"\bnosqli\b",
                             r"mongo[\s-]*operator", r"\$ne\b")),
    ("xxe",                 (r"\bxxe\b", r"xml\s+external\s+entity")),
    ("ssrf",                (r"\bssrf\b", r"server[\s-]+side\s+request")),
    ("idor_bola",           (r"\bidor\b", r"\bbola\b",
                             r"broken\s+object[\s-]+level\s+authorization",
                             r"object[\s-]+level\s+authorization")),
    ("mass_assignment",     (r"mass[\s-]+assignment", r"auto[\s-]+bind")),
    ("prototype_pollution", (r"prototype[\s-]+pollution", r"__proto__")),
    ("open_redirect",       (r"open[\s-]+redirect",)),
    ("jwt_alg_none",        (r"alg\s*[:=]\s*none",
                             r"alg[\s-]*none",
                             r"signature\s+not\s+verified")),
    ("jwt_no_exp",          (r"no\s+exp(?:iration|iry)?",
                             r"missing\s+(?:`?exp`?|expir)",
                             r"never\s+expir")),
    ("jwt_key_confusion",   (r"key\s+confusion", r"rs256.+hs256",
                             r"hs256.+rs256")),
    ("metrics_exposed",     (r"prometheus[\s/]*metrics", r"/metrics\b")),
    ("swagger_exposed",     (r"swagger", r"openapi", r"/api-docs")),
    ("admin_config_exposed",(r"application[\s-]+configuration",
                             r"/rest/admin",)),
    ("cors_wildcard",       (r"cors\s+wildcard",
                             r"access[\s-]+control[\s-]+allow[\s-]+origin.*\*")),
    ("verbose_error",       (r"verbose\s+error",
                             r"stack\s+trace",
                             r"framework\s+(?:version\s+)?(?:disclos|leak)")),
    ("directory_listing",   (r"directory\s+listing",
                             r"/ftp/?\s|^/ftp\b")),
    ("hardcoded_secret",    (r"hardcoded\s+(?:credentials?|secrets?|"
                             r"passwords?|tokens?)",
                             r"client[\s-]*side\s+(?:credentials?|secrets?)",
                             r"main\.js\s+.*creds?")),
    ("rate_limit_missing",  (r"brute[\s-]+force",
                             r"no\s+rate[\s-]+limit",
                             r"missing\s+rate[\s-]+limit",
                             r"account\s+lockout")),
)


def _classify_vuln_class(haystack: str) -> str:
    """Map a title+evidence string to a coarse vuln-class key. Returns
    '' when no class matched -- the caller falls back to the
    URL+token signature for those rows."""
    for key, patterns in _DEDUP_VULN_CLASSES:
        for pat in patterns:
            if re.search(pat, haystack, re.IGNORECASE):
                return key
    return ""


def _dedup_signature(title: str, evidence: str, owasp: str,
                     severity: str) -> str:
    """Produce a normalised signature for cross-scenario LLM finding
    dedup. Strategy (in order of precedence):
      1. If a vuln-class keyword (xss / sqli / idor / metrics_exposed /
         etc.) AND a URL path are both present in title+evidence, the
         signature is severity|owasp|vuln_class|url_path. This is the
         tight case: rephrasings of "Prometheus /metrics exposed"
         across scenarios collapse into the same bucket regardless of
         descriptive wording.
      2. If only a vuln-class keyword fires, sig is
         severity|owasp|vuln_class (groups every same-class finding
         across this assessment -- aggressive, but appropriate for an
         LLM that has a habit of restating the same bug under multiple
         scenarios).
      3. If only a URL fires, sig is severity|owasp|<url>.
      4. Otherwise, fall back to the sorted content-token set.

    Empty signature ('') disables dedup for that row -- the caller
    inserts unconditionally."""
    haystack = f"{title} {evidence}".lower()
    url_paths = re.findall(r"/[a-z0-9_\-/.]{2,}", haystack)
    # Strip URLs out before classifying words and tokens.
    stripped = re.sub(r"https?://[^\s)>'\"]+|/[a-z0-9_\-/.]+", " ", haystack)
    cls = _classify_vuln_class(haystack)
    primary_url = ""
    if url_paths:
        # Pick the shortest URL path -- usually the most stable
        # canonical form (`/metrics` over `/metrics/foo/bar`).
        primary_url = min(
            {u.rstrip("/.,;:") for u in url_paths},
            key=len)
    if cls and primary_url:
        return f"{severity}|{owasp}|{cls}|{primary_url}"
    if cls:
        return f"{severity}|{owasp}|{cls}"
    if primary_url:
        return f"{severity}|{owasp}|url:{primary_url}"
    words = re.findall(r"[a-z0-9]{3,}", stripped)
    content = sorted({w for w in words if w not in _DEDUP_STOPWORDS})
    if not content:
        return ""
    return f"{severity}|{owasp}|tok:" + "|".join(content)


def _insert_weakness_findings(aid: int, prompt_row: dict,
                                items: list) -> int:
    """Validate + insert LLM-emitted findings as source_tool=
    'enhanced_ai_testing'. Returns count inserted. Skips entries that
    fail the schema check (severity / title) — the LLM occasionally
    emits a stray comment row that would crash the strict NOT NULL
    constraints, and a strict caller would lose every other finding in
    the batch as collateral.

    Cross-scenario dedup: each candidate is reduced to a stable
    signature (severity + owasp_category + sorted content-token set
    drawn from title + llm_evidence with URLs preserved). Signatures
    seen in a prior enhanced_ai_testing finding on this assessment
    cause the candidate to be skipped silently — this prevents the
    `/metrics` exposed finding from emitting four near-duplicate
    rows when multiple weakness-discovery scenarios independently
    surface it. The signature set is loaded once at the top of the
    inserter so the cost is one SELECT per scenario, not per item.

    Runs the mechanical G3 post-processor (`_g3_downgrade_if_scanner_only`)
    before insert so a finding whose only evidence is a scanner URL
    line cannot be persisted at high/critical."""
    if not items or not isinstance(items, list):
        return 0
    # Pre-load signatures for every enhanced_ai_testing finding the
    # assessment has accumulated so far. Includes findings emitted by
    # earlier weakness-discovery scenarios in the same run as well as
    # any findings carried over from re-runs. We do NOT cross-match
    # against probe-emitted findings here -- the LLM may legitimately
    # restate a probe finding with extra reasoning, and the
    # consolidation pass groups by enrichment_id which catches the
    # cross-source case at roll-up time.
    seen_sigs: set[str] = set()
    prior_rows = db.query_all(
        "SELECT title, severity, owasp_category, raw_data "
        "FROM findings "
        "WHERE assessment_id=%s AND source_tool='enhanced_ai_testing'",
        (aid,))
    for pr in prior_rows:
        prior_ev = ""
        try:
            pr_raw = json.loads(pr.get("raw_data") or "{}")
            if isinstance(pr_raw, dict):
                prior_ev = (pr_raw.get("llm_evidence") or "")
        except Exception:
            pr_raw = None
        sig = _dedup_signature(
            pr.get("title") or "", prior_ev,
            pr.get("owasp_category") or "",
            (pr.get("severity") or "").lower())
        if sig:
            seen_sigs.add(sig)

    n = 0
    skipped_dups = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        # Mechanical G3 enforcement runs BEFORE schema validation so
        # the post-processor sees the model-emitted severity, not a
        # default. The function rewrites the dict in place when a
        # downgrade fires; we stash the audit trail on the row so a
        # human reviewer can inspect why a finding ended up at low.
        g3_audit = _g3_downgrade_if_scanner_only(item)
        sev = (item.get("severity") or "").lower()
        if sev not in _SEV_ALLOWED:
            continue
        title = (item.get("title") or "").strip()
        if not title:
            continue
        category = item.get("category") or prompt_row.get("category") or ""
        description = (item.get("description") or "").strip()
        # Output-schema v2: reproduction (test plan) and remediation
        # (fix guide) are now separate fields. Backward compat: if the
        # LLM emitted only the legacy `recommendation` field (operator
        # editing an old prompt body, or a prompt that hasn't been
        # restored yet), treat it as a test plan and leave the
        # remediation column empty so the new "Remediation" UI card
        # simply doesn't render. Reproduction lives in raw_data so it
        # doesn't fight with the existing `remediation` column's
        # historical content; the column is now reserved for the fix
        # guide.
        reproduction = (item.get("reproduction") or "").strip()
        remediation = (item.get("remediation") or "").strip()
        legacy_rec = (item.get("recommendation") or "").strip()
        if legacy_rec and not reproduction:
            reproduction = legacy_rec
            # If `remediation` was also missing, we have no fix guide
            # — leave it empty rather than duplicate the test plan.
        evidence = (item.get("evidence") or "").strip()
        location = (item.get("location") or "").strip().lower()
        # Synthesise a description if the LLM omitted it; keeps the
        # row passable for the analyst page even on terse output.
        if not description and evidence:
            description = f"Evidence: {evidence}"
        # owasp_category gets the OWASP Top 10 code so downstream
        # pipelines (per-category demerit math, heat map, cover
        # scorecard, compute_overall_grade) bucket the row correctly.
        # The original scenario label is preserved in raw_data.
        # llm_category for traceability.
        owasp_code = _scenario_to_owasp(category)

        # Cross-scenario dedup gate. Skip the insert if a previously-
        # emitted enhanced_ai_testing finding on this assessment
        # already carries the same content signature. Add the new
        # signature to the set so duplicates WITHIN this scenario's
        # JSON array also collapse (the LLM sometimes emits a same-
        # bug pair under slightly different titles). Empty signature
        # disables dedup for that row -- usually means the title was
        # a single short generic phrase the heuristic can't bucket.
        sig = _dedup_signature(title, evidence, owasp_code[:64], sev)
        if sig and sig in seen_sigs:
            skipped_dups += 1
            continue
        if sig:
            seen_sigs.add(sig)

        raw = {"llm_scenario": prompt_row.get("name"),
                "llm_prompt_id": prompt_row.get("id"),
                "llm_category": category,
                "llm_evidence": evidence,
                "llm_location": location,
                # Reproduction (test plan) lives in raw_data so the
                # `remediation` column can hold the fix guide without
                # ambiguity. The detail page reads both and renders
                # two separate cards: "To Reproduce" and "Remediation".
                "llm_reproduction": reproduction}
        if g3_audit:
            raw.update(g3_audit)
        db.execute("""
            INSERT INTO findings
                (assessment_id, source_tool, source_scan_id, severity,
                 owasp_category, cwe, cvss, title, description,
                 evidence_url, evidence_method, remediation, raw_data,
                 seen_count)
            VALUES (%s, 'enhanced_ai_testing', %s, %s, %s, NULL, NULL,
                    %s, %s, NULL, NULL, %s, %s, 1)
        """, (
            aid, f"llm:{prompt_row.get('id')}", sev,
            owasp_code[:64],
            title[:500], description, remediation,
            json.dumps(raw, default=str),
        ))
        n += 1
    if skipped_dups:
        logger.info("enhanced_ai dedup: skipped %d duplicate finding(s) "
                    "from prompt #%s (%s)",
                    skipped_dups, prompt_row.get("id"),
                    prompt_row.get("name") or "")
    return n


# ---- fidelity loop ----------------------------------------------------------

def _run_fidelity(aid: int, endpoint: dict, telemetry: dict,
                    prompt_row: dict, budget: _BudgetState, *,
                    debug_on: bool) -> dict:
    """Per-finding fidelity grader, batched. Returns a dict suitable
    for merging into the top-level run() summary."""
    out = {"evaluated": 0, "auto_flipped": 0, "batches_run": 0,
            "errors": []}
    # Selection includes 'errored' so findings the probe pass could not
    # decisively validate or refute (transient network failure, probe
    # subprocess crash, schema mismatch on LLM-emitted rows) still get
    # a shot at LLM triage. The fidelity grader does not need probe
    # evidence -- it judges from the finding's title / evidence /
    # raw_data -- so a probe-erroring verdict is not a reason to skip
    # the row. Without this, any finding that exited challenge_runner
    # in 'errored' state would stay there permanently regardless of
    # how clear-cut the underlying evidence is.
    findings = db.query_all(
        "SELECT id, source_tool, severity, owasp_category, cwe, "
        "title, description, evidence_url, evidence_method, raw_data, "
        "validation_status, validation_probe, validation_evidence "
        "FROM findings WHERE assessment_id=%s "
        "  AND severity != 'info' "
        "  AND validation_status IN ('unvalidated','inconclusive','errored') "
        "ORDER BY FIELD(severity,'critical','high','medium','low'), id",
        (aid,))
    if not findings:
        return out

    # Skip findings the enhanced_ai pass itself just produced — the LLM
    # already emitted a confident verdict on them implicitly. They land
    # at validation_status='unvalidated' otherwise and would be re-graded
    # by the same LLM that just wrote them, which is circular.
    findings = [f for f in findings if f.get("source_tool") != "enhanced_ai_testing"]
    if not findings:
        return out

    batch_size = int(prompt_row.get("batch_size") or 5)
    for i in range(0, len(findings), batch_size):
        if budget.tripped:
            break
        batch = findings[i:i + batch_size]
        batch_text = _render_fidelity_batch(batch)
        sys_prompt = (prompt_row["system_prompt"] or "")
        # Carry the AUTHORIZED ROLE block into the fidelity prompt so
        # the LLM can return verdict='expected_behavior' for findings
        # that merely demonstrate a capability the role is authorized
        # for. Empty string when the operator did not supply role
        # context, so operator-edited templates that quote
        # {role_context_block} render cleanly in both modes.
        user = render_user_prompt(prompt_row["user_template"], {
            "fqdn": telemetry.get("fqdn", ""),
            "findings_batch": batch_text,
            "role_context_block": telemetry.get("role_context_block", ""),
        })
        approx_in = (len(sys_prompt) + len(user)) // 4
        approx_cost = llm_mod.cost(approx_in, FIDELITY_MAX_OUTPUT_TOKENS,
                                     endpoint.get("model") or "")
        if budget.would_trip_on_next(approx_cost):
            budget.trip()
            break

        call_started = datetime.now(timezone.utc).replace(tzinfo=None)
        result = _call_llm(endpoint, sys_prompt, user,
                            max_tokens=FIDELITY_MAX_OUTPUT_TOKENS,
                            cache_system=True)
        in_tokens = int(result.get("in_tokens") or 0)
        out_tokens = int(result.get("out_tokens") or 0)
        cached = int(result.get("cache_read_tokens") or 0)
        actual_cost = llm_mod.cost(in_tokens, out_tokens,
                                     endpoint.get("model") or "",
                                     cached_in_tokens=cached)
        budget.add(actual_cost)
        out["batches_run"] += 1

        if not result.get("ok"):
            err = result.get("error") or "LLM call failed"
            out["errors"].append(f"fidelity batch {i//batch_size}: {err}")
            _record_analysis(
                aid=aid, target_type="enhanced_ai_fidelity",
                target_id=f"batch:{i//batch_size}", endpoint=endpoint,
                status="error", in_tokens=in_tokens, out_tokens=out_tokens,
                payload=None, raw=result.get("raw"),
                request_prompt=user if debug_on else None,
                error_text=err, started_at=call_started)
            continue

        verdicts = llm_mod.parse_findings(result.get("content") or "") or []
        applied = _apply_fidelity_verdicts(batch, verdicts)
        out["evaluated"] += applied["evaluated"]
        out["auto_flipped"] += applied["auto_flipped"]
        _record_analysis(
            aid=aid, target_type="enhanced_ai_fidelity",
            target_id=f"batch:{i//batch_size}", endpoint=endpoint,
            status="done", in_tokens=in_tokens, out_tokens=out_tokens,
            payload={"batch_index": i // batch_size,
                      "verdicts": verdicts,
                      "evaluated": applied["evaluated"],
                      "auto_flipped": applied["auto_flipped"]},
            raw=result.get("raw") if debug_on else None,
            request_prompt=user if debug_on else None,
            error_text=None, started_at=call_started)
    return out


def _render_fidelity_batch(batch: list[dict]) -> str:
    """Render a batch of findings into the text block the fidelity
    prompt's user template expects. One block per finding with all
    fields the LLM needs to grade fidelity, capped to keep prompt
    tokens bounded."""
    blocks: list[str] = []
    for f in batch:
        rd = f.get("raw_data") or ""
        if isinstance(rd, str) and len(rd) > PER_FINDING_QUOTE_MAX:
            rd = rd[:PER_FINDING_QUOTE_MAX] + "..."
        prior = (f.get("validation_status") or "")
        prior_probe = f.get("validation_probe") or "-"
        prior_evidence = f.get("validation_evidence") or ""
        if prior_evidence and len(prior_evidence) > 400:
            prior_evidence = prior_evidence[:400] + "..."
        blocks.append(
            f"=== finding_id={f['id']} ===\n"
            f"source_tool:     {f.get('source_tool')}\n"
            f"severity:        {f.get('severity')}\n"
            f"title:           {f.get('title')}\n"
            f"cwe:             {f.get('cwe') or '-'}\n"
            f"owasp_category:  {f.get('owasp_category') or '-'}\n"
            f"evidence_url:    {f.get('evidence_url') or '-'}\n"
            f"evidence_method: {f.get('evidence_method') or '-'}\n"
            f"prior_probe_verdict: {prior} (probe={prior_probe})\n"
            f"prior_probe_evidence: {prior_evidence or '-'}\n"
            f"description: {(f.get('description') or '')[:500]}\n"
            f"raw_data: {rd or '-'}\n"
        )
    return "\n".join(blocks)


_VERDICT_TO_STATUS = {
    "validated": "validated",
    "false_positive": "false_positive",
    "inconclusive": "inconclusive",
    # 'expected_behavior' is treated as a high-confidence true-positive
    # whose impact is nullified by the authenticated user's authorized
    # role. We map it to validation_status='validated' (the finding is
    # real) but the auto-flip branch ALSO forces severity='info' and
    # records the role-scope verdict via a distinct validation_probe
    # ('enhanced_ai_role_scope') so the analyst can filter for these.
    "expected_behavior": "validated",
}


def _apply_fidelity_verdicts(batch: list[dict],
                                verdicts: list) -> dict:
    """Update validation_status on the findings we just graded.

    Auto-flip only when verdict is 'validated', 'false_positive', or
    'expected_behavior' AND confidence >= 0.8. Anything else (low
    confidence, malformed verdict, 'inconclusive') is annotated into
    validation_evidence with the LLM's reasoning, but the status is
    left alone so a human picks it up.

    For 'expected_behavior' the finding is a real true-positive whose
    impact is nullified by the authorized user role; severity is
    forced to 'info' and validation_probe is set to
    'enhanced_ai_role_scope' so the analyst can filter for the
    role-scope verdicts separately from a regular validated finding.
    The overall `status` is left as-is (not flipped to false_positive)
    so the row still appears in info-severity rollups -- the analyst
    sees what the AI noticed, just at the right severity.

    Severity raise / lower from suggested_severity is NOT auto-applied
    in this first cut for the regular 'validated' verdict — the
    analyst can do it from the finding page if they agree. Recording
    the suggestion in raw_data is enough signal for now."""
    by_id = {f["id"]: f for f in batch}
    out = {"evaluated": 0, "auto_flipped": 0}
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        fid = v.get("finding_id")
        try:
            fid = int(fid)
        except (TypeError, ValueError):
            continue
        f = by_id.get(fid)
        if not f:
            continue
        out["evaluated"] += 1
        verdict = (v.get("verdict") or "").lower()
        try:
            confidence = float(v.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        reasoning = (v.get("reasoning") or "").strip()
        sev_suggest = (v.get("suggested_severity") or "").strip().lower()
        sev_adjust = (v.get("severity_adjustment") or "none").lower()
        evidence_blob = (
            f"Enhanced-AI fidelity:\n  verdict={verdict}\n"
            f"  confidence={confidence:.2f}\n"
            f"  severity_adjustment={sev_adjust} "
            f"(suggested={sev_suggest or '-'})\n"
            f"  reasoning: {reasoning}")
        # Always record the LLM's reasoning, regardless of auto-flip.
        if (verdict in ("validated", "false_positive", "expected_behavior")
                and confidence >= 0.8):
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            # Also apply suggested_severity when the LLM returned a
            # concrete adjustment ("raise" or "lower" + a valid
            # severity name). The model's job in the fidelity grade
            # is to re-evaluate impact; if it says a `high` reflected
            # XSS is actually `info` because the input is sanitized
            # downstream, we apply that. Only fires when verdict is
            # 'validated' — for false_positive we suppress the row
            # entirely, and for expected_behavior we always force
            # info (handled in its own branch below), so severity
            # adjustments are moot in those cases.
            apply_severity = None
            if (verdict == "validated"
                    and sev_adjust in ("raise", "lower")
                    and sev_suggest in _SEV_ALLOWED
                    and sev_suggest != (f.get("severity") or "").lower()):
                apply_severity = sev_suggest
            # On a high-confidence false_positive verdict, ALSO update
            # the finding's overall `status` to 'false_positive' — same
            # action the toolkit-probe /challenge_inline endpoint takes
            # when its probe refutes a finding. This removes the row
            # from severity rollups, the heatmap, and the PDF report
            # without an analyst having to click "Mark false positive"
            # by hand. validated/inconclusive verdicts do NOT touch
            # `status` (we only auto-suppress, never auto-promote).
            if verdict == "expected_behavior":
                # In-scope behavior for the authorized user role.
                # Force severity to 'info' so it stops counting in the
                # critical/high/medium rollups, and tag with a distinct
                # validation_probe so an analyst can filter the role-
                # scope verdicts separately from a regular validated
                # finding. status is left alone (the row stays visible
                # at info-severity, with the LLM's reasoning explaining
                # why it was demoted) so the analyst can review the
                # demotion if desired.
                db.execute(
                    "UPDATE findings SET validation_status='validated', "
                    "validation_probe='enhanced_ai_role_scope', "
                    "validation_run_at=%s, validation_evidence=%s, "
                    "severity='info' "
                    "WHERE id=%s",
                    (now, evidence_blob[:65000], fid))
            elif verdict == "false_positive":
                db.execute(
                    "UPDATE findings SET validation_status=%s, "
                    "validation_probe='enhanced_ai_testing', "
                    "validation_run_at=%s, validation_evidence=%s, "
                    "status='false_positive' "
                    "WHERE id=%s",
                    (_VERDICT_TO_STATUS[verdict], now,
                      evidence_blob[:65000], fid))
            elif apply_severity:
                db.execute(
                    "UPDATE findings SET validation_status=%s, "
                    "validation_probe='enhanced_ai_testing', "
                    "validation_run_at=%s, validation_evidence=%s, "
                    "severity=%s "
                    "WHERE id=%s",
                    (_VERDICT_TO_STATUS[verdict], now,
                      evidence_blob[:65000], apply_severity, fid))
            else:
                db.execute(
                    "UPDATE findings SET validation_status=%s, "
                    "validation_probe='enhanced_ai_testing', "
                    "validation_run_at=%s, validation_evidence=%s "
                    "WHERE id=%s",
                    (_VERDICT_TO_STATUS[verdict], now,
                      evidence_blob[:65000], fid))
            out["auto_flipped"] += 1
        else:
            # Annotate-only path: leave validation_status, but record
            # the LLM's reasoning so the analyst can see it on the
            # finding page. The validation_probe stays NULL so the
            # human still sees this row as in need of review.
            db.execute(
                "UPDATE findings SET validation_evidence=%s "
                "WHERE id=%s",
                (evidence_blob[:65000], fid))
    return out
