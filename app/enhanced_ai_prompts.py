# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Default prompts for the Enhanced-AI-Testing pass.

This module is the source of truth for the eleven prompts seeded into the
`ai_prompts` table on a fresh database. Operators edit prompts through
/admin/ai-prompts; "Restore to default" reads back from this module, so a
deleted or corrupted seeded row can always be brought back.

Two slots are populated:
  - advanced_ai_testing.weakness_discovery — ten scenario prompts that each
    receive the full scan telemetry once and emit a JSON array of findings.
    Multiple scenarios in a slot run sequentially (one LLM call per
    scenario), so adding a new angle of analysis is a database insert,
    not a code change.
  - advanced_ai_testing.fidelity — one default fidelity-evaluator prompt
    that re-grades findings whose probe verdict was 'unvalidated' or
    'inconclusive'. Findings are processed in batches of five per call to
    keep the system prompt cache-warm.

Prompt structure is consistent across scenarios: a shared HEADER carrying
the universal non-destructive operating constraints, a per-scenario body
that defines the persona and analytic task, and a shared FOOTER that
fixes the output schema. Keeping HEADER and FOOTER outside the editable
prompt body means a future safety addition (e.g. "do not propose
prompt-injection payloads against admins") propagates to every scenario
without per-row edits.

`fire_when` is a small expression evaluated against the per-assessment
telemetry summary. Allowed atoms (booleans on the summary dict):
  has_creds, has_mutating_json_request, has_url_processing_endpoint,
  has_auth_redirect_chain, has_swagger_or_sourcemap,
  has_high_value_endpoint, has_state_mutating_endpoint,
  has_tenant_identifier, has_credentialed_traffic
Allowed integer atom: findings_count (compared with >= or > and an int).
Operators: AND, OR, parentheses. Empty/missing fire_when always fires.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Shared boilerplate — head and tail of every weakness-discovery system
# prompt. Concatenated at seed time and at restore time.
# ---------------------------------------------------------------------------

HEADER = """\
You are reviewing telemetry from an authorized DAST scan against {fqdn}. \
Use ONLY the data provided. Do not invent endpoints, fields, or behaviors \
not represented in the input. If the input does not support a finding, omit it.

NON-DESTRUCTIVE CONSTRAINTS (hard requirements on every recommendation you produce):
1. You are NOT executing requests yourself. Recommendations are test plans the human analyst will run. Frame them that way.
2. All proposed payloads must be non-destructive. Do NOT propose: DELETE / DROP / TRUNCATE statements; fund / credit / point transfers; password-reset flows that email real users; account-lockout brute-force sequences; DoS, amplification, or fork-bomb payloads; real cloud-metadata credential exfiltration (use metadata-only paths, never fetch the credential itself); or any other irreversible data mutation.
3. State-mutating PoCs (race conditions, mass assignment, second-order writes) MUST be tagged "STAGING ONLY — do not run against production data" inside the recommendation text.
4. Where a destructive payload would prove a hypothesis, propose the non-destructive detection variant FIRST (idempotent GET for race detection, IMDS metadata path without credential retrieval, out-of-band callback URL — e.g. interactsh / Burp Collaborator — instead of internal-service exploitation, dry-run / preview flags when the API supports them).
5. Prefer detection over exploitation. The goal is verifiable proof of vulnerability, not damage.
"""

# `<CATEGORY>` is replaced per-scenario by the row's category column at
# build time. We keep one copy of the FOOTER and inline the category so a
# scenario rename only touches the row, not the boilerplate.
FOOTER_TEMPLATE = """\

Respond with a JSON array of findings. Each element:
{{
  "severity": "critical|high|medium|low",
  "category": "{category}",
  "title": "one-line summary, <=120 chars",
  "evidence": "exact quote/URL/value from input that motivates this finding, <=500 chars",
  "location": "request|response|headers|body|url|cookie|workflow",
  "description": "your analytical reasoning",
  "recommendation": "concrete remediation, including any test payloads, curl scripts, or PoC scaffolding (use fenced code blocks)"
}}

Limit to 10 findings. If nothing is exploitable, return []. Do not output anything outside the JSON array. Do not wrap in markdown fences.
"""


def _system_prompt(persona_and_task: str, category: str) -> str:
    """Compose HEADER + persona/task body + FOOTER, with the FOOTER's
    category placeholder filled in. Used at seed time and at restore-to-
    default time to produce the system_prompt column value.

    The double-brace literals in FOOTER_TEMPLATE are necessary because the
    USER_TEMPLATE rendering downstream uses str.format with `{fqdn}` and
    other placeholders; keeping the braces escaped here means the user
    can paste the FOOTER text into the editor and edit it without
    needing to know about Python's format-string mini-language."""
    return HEADER + "\n" + persona_and_task + FOOTER_TEMPLATE.format(category=category)


# ---------------------------------------------------------------------------
# Slot constants
# ---------------------------------------------------------------------------
SLOT_WEAKNESS = "advanced_ai_testing.weakness_discovery"
SLOT_FIDELITY = "advanced_ai_testing.fidelity"

# Available {placeholders} per slot — declared in code, not in the DB,
# because they correspond to actual data the orchestrator assembles. Used
# by the AI-Prompts admin page to render a sidebar telling the editor
# which substitutions are valid for the slot they're editing. Unknown
# placeholders in a saved prompt render as the literal string
# "{placeholder=??unknown??}" at runtime so a typo never crashes the run.
PLACEHOLDERS_BY_SLOT: dict[str, set[str]] = {
    SLOT_WEAKNESS: {
        "fqdn", "profile", "request_clusters",
        "auth_findings", "state_mutating_findings",
        "authenticated_endpoints", "object_id_patterns",
        "response_samples", "mutating_requests", "related_findings",
        "input_endpoints", "retrieval_endpoints",
        "xss_findings", "sqli_findings",
        "auth_redirect_chain", "jwt_findings", "oauth_endpoints",
        "url_processing_endpoints", "infrastructure_signals",
        "ssrf_probe_findings", "swagger_excerpt", "sourcemap_excerpt",
        "discovered_url_patterns", "auth_context",
        "state_mutating_endpoints", "high_value_endpoints",
        "tenant_identifiers", "authenticated_responses",
        "rate_limit_signals", "graphql_endpoints",
    },
    SLOT_FIDELITY: {"fqdn", "findings_batch"},
}


# ---------------------------------------------------------------------------
# Per-scenario persona + task bodies. Wrapped by HEADER + FOOTER at seed
# time. Keeping the body editable in isolation means an operator can
# tighten "Severity rubric" or add a new analytical step without
# re-typing the universal safety constraints.
# ---------------------------------------------------------------------------

_BUSINESS_LOGIC_BODY = """\
You are an expert Application Security Penetration Tester. Identify Business Logic Vulnerabilities a standard DAST tool would miss. Reconstruct the logical state machine of the captured workflows and identify the assumptions developers made about ordering of operations.

For each candidate workflow you can reconstruct, propose three to five attack scenarios where dropping a step, replaying a step out of order, or manipulating business-specific variables (negative quantities, reused one-time codes, tampered prices, currency switches) could lead to a logic bypass. Provide step-by-step PoC instructions per hypothesis.

Severity rubric: critical = financial impact (price tampering, free-checkout); high = privilege/state escalation (skipped MFA, bypassed approval); medium = data manipulation; low = race-window only.
"""

_BUSINESS_LOGIC_USER = """\
TARGET
======
{fqdn} ({profile} scan)

REQUEST CLUSTERS (paths and methods grouped by likely workflow)
================================================================
{request_clusters}

AUTHENTICATION-RELATED FINDINGS
=================================
{auth_findings}

STATE-MUTATING FINDINGS
=========================
{state_mutating_findings}
"""


_BOLA_BODY = """\
You are an expert API Security Researcher. The telemetry below was captured under User A's authenticated session.

1. Enumerate every direct object reference in URLs, headers, JSON bodies (user IDs, document UUIDs, account numbers, sequential ints, tenant IDs).
2. Classify each response's semantic sensitivity — user-specific, tenant-specific, or globally shared.
3. Generate a testing matrix mapping each candidate parameter to a swap test the analyst will run with a User B token.

Flag cases where an ID is requested but the response leaks broader metadata than what was asked for (sibling listings, counts, defaults that reveal other tenants' configs).

Severity rubric: critical = arbitrary read/write of other-user sensitive data (PII, financial); high = arbitrary read of other-user data without sensitive fields; medium = metadata leakage on otherwise-secured endpoint; low = enumeration only.

For each finding, the recommendation must be a fenced testing-matrix table with columns: endpoint, parameter, current value, swap target, expected if-vulnerable behavior.
"""

_BOLA_USER = """\
TARGET
======
{fqdn}

AUTHENTICATED ENDPOINTS captured during the scan
==================================================
{authenticated_endpoints}

OBJECT-ID PATTERNS auto-extracted from URLs and bodies
========================================================
{object_id_patterns}

RESPONSE SAMPLES (subset of bodies showing data shape)
========================================================
{response_samples}
"""


_MASS_ASSIGNMENT_BODY = """\
You are an Application Security Engineer specializing in modern MVC and API frameworks (Rails ActiveRecord, Django ORM, Spring Data, Laravel Eloquent, Sequelize). You are reviewing telemetry from an authorized DAST scan to find Mass Assignment / Auto-Binding vulnerabilities that regex scanners cannot detect.

For each mutating request:
1. Infer the underlying entity model and the framework signal that supports your inference.
2. Predict 10–15 hidden or administrative fields plausibly bound on the backend (is_admin, role, owner_id, status, email_verified, wallet_balance, tier).
3. Emit one finding per request with reasonable inference confidence; the recommendation must include three mutated payloads as ready-to-run curl, each tagged "STAGING ONLY".

Severity rubric: critical = privilege-escalation field (is_admin, role, owner_id); high = state-mutation field (status, balance, tier); medium = data-disclosure or relationship-manipulation field.
"""

_MASS_ASSIGNMENT_USER = """\
TARGET
======
{fqdn} ({profile} scan)

MUTATING JSON REQUESTS captured during the scan
================================================
{mutating_requests}

RELATED FINDINGS that may indicate the underlying framework / ORM
==================================================================
{related_findings}
"""


_SECOND_ORDER_BODY = """\
You are a Senior Application Security Architect. Map Second-Order Vulnerabilities by drawing connections between sources (POST/PUT/PATCH ingestion endpoints) and sinks (GET endpoints, report/PDF exports, admin dashboards, async job workers).

For each plausible source→sink pair, generate up to five contextual payloads (XSS for HTML/JS contexts, SQLi for query contexts, SSTI for template contexts) designed to remain dormant on injection but trigger in the sink. Each finding's recommendation must include a validation step (which sink to fetch after which source POST). Tag each PoC "STAGING ONLY".

Severity rubric: critical = stored XSS in admin dashboard; high = stored XSS in user UI / second-order SQLi; medium = stored payload in less-sensitive sink; low = unconfirmed source/sink mapping.
"""

_SECOND_ORDER_USER = """\
TARGET
======
{fqdn}

INPUT ENDPOINTS (sources)
===========================
{input_endpoints}

RETRIEVAL ENDPOINTS (sinks)
=============================
{retrieval_endpoints}

EXISTING REFLECTED-XSS FINDINGS (may indicate stored variants)
================================================================
{xss_findings}

EXISTING SQLI FINDINGS
========================
{sqli_findings}
"""


_OAUTH_BODY = """\
You are an Identity and Access Management Security Expert.

1. Verify presence and cryptographic strength of state, nonce, and PKCE parameters.
2. Identify how redirect_uri is passed; propose five mutation techniques to bypass typical regex validations (null bytes, double URL encoding, schema manipulation like javascript:/data:, parser-confusion paths, trailing-slash differential).
3. If JWTs are present, analyze structure (alg, kid, claims) and recommend specific JWT attacks (alg=none, RSA→HMAC confusion, kid path traversal, weak HMAC key, unverified-email→admin) tailored to this implementation.

Severity rubric: critical = redirect_uri bypass yielding token theft / ATO; high = missing state/PKCE / forgeable JWT; medium = weak nonce / non-rotating session; low = informational protocol drift.
"""

_OAUTH_USER = """\
TARGET
======
{fqdn}

AUTH REDIRECT CHAIN (3xx hops captured during the scan)
=========================================================
{auth_redirect_chain}

JWT-RELATED FINDINGS
======================
{jwt_findings}

OAUTH / OIDC ENDPOINTS (well-known/openid-configuration, authorize, token, userinfo)
=====================================================================================
{oauth_endpoints}
"""


_SSRF_BODY = """\
You are a Cloud Security Penetration Tester. If you cannot infer a specific cloud provider from the signals, fall back to generic SSRF payloads — do NOT assume a provider.

1. From response headers and error envelopes, infer the underlying infrastructure (AWS, GCP, Azure, Kubernetes, on-prem). State your confidence.
2. Generate a prioritized list of SSRF payloads for the inferred environment (IMDSv2 metadata-path requests that demonstrate reach — e.g. a GET to /latest/meta-data/instance-id; never fetch /iam/security-credentials or anything that returns a usable credential. Prefer an analyst-controlled out-of-band domain (interactsh / Burp Collaborator) for blind-SSRF confirmation. Other safe targets: Kubelet read-only ports, GCP metadata, Azure IMDS metadata-only paths, Spring Boot actuator info endpoints).
3. Suggest wrapper / obfuscation bypasses (dict://, gopher://, file://, decimal IPs, octal IPs, IPv6 mapped, DNS rebinding domains).

Severity rubric: critical = inferred environment exposes IMDS/Kubelet without auth; high = SSRF reaching internal services; medium = SSRF reaching external-only with no internal pivot; low = filtered SSRF requiring obfuscation chain.
"""

_SSRF_USER = """\
TARGET
======
{fqdn}

URL-PROCESSING ENDPOINTS
==========================
{url_processing_endpoints}

INFRASTRUCTURE SIGNALS (Server, X-Powered-By, error envelopes, response timing)
================================================================================
{infrastructure_signals}

EXISTING SSRF-RELATED PROBE FINDINGS (may be empty)
=====================================================
{ssrf_probe_findings}
"""


_BFLA_BODY = """\
You are an API Security Analyst. Find Broken Function Level Authorization vulnerabilities by extrapolating undocumented or administrative endpoints from existing patterns — but only patterns supported by the input.

1. From observed API path patterns (e.g. /api/v1/user/), predict equivalents (/api/v1/admin/, /api/internal/, /api/management/, /actuator/, /debug/, legacy /api/v0/).
2. Predict missing HTTP methods on known endpoints (DELETE on GET-only, PUT on POST-only) — frame as detection-only GETs in the recommendation; the analyst will swap method during testing.
3. Predict tenant/scope escalation paths (user→org→admin).

The recommendation must be a fenced curl block (one curl per predicted endpoint) ready to run with a low-privileged Bearer token. Use HEAD or GET for the initial probe so the analyst can verify reachability without state mutation.

Severity rubric: critical = predicted admin endpoint granting role/data escalation; high = predicted internal/debug endpoint with secrets; medium = predicted endpoint revealing other tenants; low = predicted legacy/deprecated version.
"""

_BFLA_USER = """\
TARGET
======
{fqdn}

SWAGGER / OPENAPI EXCERPT (if exposed)
========================================
{swagger_excerpt}

SOURCEMAP / FRONTEND-BUNDLE STRINGS (if exposed)
==================================================
{sourcemap_excerpt}

DISCOVERED URL PATTERNS from scanner output
=============================================
{discovered_url_patterns}

AUTH CONTEXT (scan ran credentialed Y/N, role if known)
=========================================================
{auth_context}
"""


_RACE_CONDITIONS_BODY = """\
You are a Web Application Security Expert specializing in concurrency flaws.

1. Pinpoint the top three state-mutating endpoints most likely to be vulnerable to TOCTOU (coupon redemption, fund transfer, voting, unique-username creation, MFA enrollment, follow/unfollow, single-use token consumption).
2. Explain the logical window between the check and the database commit for each.
3. Provide either a Python script using requests + ThreadPoolExecutor sending 30 identical requests in a single TCP packet (Single-Packet Attack), or an equivalent Turbo Intruder configuration.

Where the natural target is destructive (fund transfer, real-money checkout), substitute an equivalent idempotent or self-reversible target on the same endpoint family if one exists (follow/unfollow, like/unlike, draft create/discard). If no non-destructive equivalent exists, mark the PoC STAGING ONLY and explicitly note that running it on production would cause irreversible state change.

Severity rubric: critical = financial duplication / privilege replication; high = bypass of single-use guards; medium = race producing inconsistent state; low = race with no business consequence.
"""

_RACE_CONDITIONS_USER = """\
TARGET
======
{fqdn}

STATE-MUTATING ENDPOINTS
==========================
{state_mutating_endpoints}

HIGH-VALUE ENDPOINT CANDIDATES (paths matching coupon/transfer/redeem/vote/signup)
====================================================================================
{high_value_endpoints}
"""


_TENANT_ISOLATION_BODY = """\
You are a Multi-Tenant Architecture Security Expert. NOTE: this scan ran as a single tenant. You DO NOT have a Tenant B baseline. Your job is to identify endpoints and response shapes the analyst should re-test as Tenant B, with concrete predictions of what isolation leak each would reveal — not to claim a confirmed cross-tenant breach.

1. Enumerate every tenant identifier in URLs, headers, cookies, response bodies (org_id, account_id, tenant=, X-Tenant-ID, subdomain shards).
2. For each authenticated endpoint that accepts a tenant identifier, classify response shape (per-tenant config, shared metadata, scoped listing, error envelope).
3. Predict whether swapping the tenant identifier would yield: (a) HTTP 403 with a tenant-confirming error, (b) partial object with metadata leakage, (c) full cross-tenant read, (d) unmodified shared response (no leak).

The recommendation must be a fenced testing matrix — endpoint, parameter location, swap target, predicted leak class, why a stock DAST tool would consider it secure.

Severity rubric: critical = predicted full cross-tenant read of sensitive data; high = predicted partial-object leak; medium = error-envelope existence confirmation; low = enumeration only.
"""

_TENANT_ISOLATION_USER = """\
TARGET
======
{fqdn}

TENANT IDENTIFIERS extracted from URLs / headers / cookies / bodies
=====================================================================
{tenant_identifiers}

AUTHENTICATED RESPONSE SAMPLES (subset, with tenant identifier highlighted)
=============================================================================
{authenticated_responses}
"""


_RATE_LIMIT_BODY = """\
You are a Bot Mitigation and API Security Expert.

For each high-value endpoint (login, password reset, OTP, signup, MFA-enroll, account-recovery):
  - GraphQL: construct a payload using GraphQL aliases to execute up to 100 attempts inside a single HTTP POST.
  - REST: provide ~15 IP-spoofing headers (X-Forwarded-For, X-Real-IP, Client-IP, CF-Connecting-IP, True-Client-IP, X-Cluster-Client-IP, X-Originating-IP, etc.) configured for bypass.

Suggest application-layer bypasses keyed off the payload format (null-byte append on username, casing differential, trailing whitespace, Unicode NFKC homoglyphs, query-string injection on form-encoded body) that could trick a rate-limiter's caching key while still parsing on the backend.

If a 429 / Retry-After signal was actually captured, anchor your bypasses to the observed limiter behavior; otherwise propose generic bypasses and say so.

PoCs must use a dedicated test account the analyst owns. Do not enumerate real usernames. Do not exceed the rate limit during normal business hours on production. Tag the PoC STAGING ONLY.

Severity rubric: critical = login/credential-stuffing endpoint with limiter bypass; high = OTP/MFA endpoint bypass; medium = signup/recovery bypass enabling enumeration; low = generic header spoofing on non-credential endpoint.
"""

_RATE_LIMIT_USER = """\
TARGET
======
{fqdn}

HIGH-VALUE ENDPOINTS DISCOVERED
=================================
{high_value_endpoints}

RATE-LIMIT SIGNALS observed (429s, Retry-After, X-RateLimit-*; may be empty)
==============================================================================
{rate_limit_signals}

GRAPHQL ENDPOINTS (if any)
============================
{graphql_endpoints}
"""


# ---------------------------------------------------------------------------
# Fidelity-evaluator prompt (different slot, batched per-finding)
# ---------------------------------------------------------------------------

FIDELITY_SYSTEM = """\
You are a Senior Application Security Engineer triaging findings from an authorized DAST scan. Evaluate the FIDELITY (true-positive likelihood) of each input finding based on the supporting evidence captured.

For each finding, emit exactly one verdict element. Verdicts:
  - "validated"      — evidence clearly supports the finding; confidence >=0.8 means it is a true positive
  - "false_positive" — evidence clearly refutes the finding; confidence >=0.8 means it is scanner noise
  - "inconclusive"   — evidence is ambiguous, contradictory, or insufficient

Be conservative. When in doubt, return "inconclusive". Do NOT mark "validated" unless a specific quote from raw_data, the reconstructed request, or the reconstructed response directly demonstrates the issue.

Respond with a JSON array — one element per input finding, in the same order. Each element:
{
  "finding_id": <integer copy of the input finding's id>,
  "verdict": "validated|false_positive|inconclusive",
  "confidence": 0.0,
  "reasoning": "<=400 chars: name the specific evidence and why it supports the verdict",
  "severity_adjustment": "none|raise|lower",
  "suggested_severity": "critical|high|medium|low|info|null"
}

If evidence is missing entirely, set verdict=inconclusive with confidence <=0.4 and say so in reasoning. Do not output anything outside the JSON array.
"""

FIDELITY_USER = """\
TARGET
======
{fqdn}

FINDINGS TO EVALUATE
======================
{findings_batch}

Apply the verdict criteria from the system prompt and emit exactly one element per finding, in input order.
"""


# ---------------------------------------------------------------------------
# Public default list — consumed by the seed/restore path. Each tuple is
# the row the migration writes into ai_prompts. Ordered by sort_order so
# the table list reads naturally; the slot+sort_order index governs run
# order at scan time regardless of insertion order.
# ---------------------------------------------------------------------------

def _w(name: str, sort: int, fire: str, category: str,
       description: str, body: str, user: str,
       batch_size: int | None = None) -> dict:
    """Build a weakness-discovery default dict. The HEADER + FOOTER
    boilerplate is composed here so a future tightening of the
    operational constraints (e.g. an additional non-destructive rule)
    propagates to every scenario by editing one constant."""
    return {
        "slot": SLOT_WEAKNESS,
        "name": name,
        "description": description,
        "system_prompt": _system_prompt(body, category),
        "user_template": user,
        "category": category,
        "fire_when": fire,
        "sort_order": sort,
        "batch_size": batch_size,
    }


DEFAULTS: list[dict] = [
    _w("Business Logic Vulnerabilities", 10, "findings_count >= 5",
       "business_logic",
       "Reconstruct multi-step workflows from scan telemetry and propose "
       "logic-bypass attack scenarios with PoC steps.",
       _BUSINESS_LOGIC_BODY, _BUSINESS_LOGIC_USER),

    _w("Broken Object Level Authorization", 20,
       "has_creds AND findings_count >= 3", "bola_idor",
       "Enumerate direct object references in authenticated traffic and "
       "produce a swap-test matrix the analyst will run with a User B token.",
       _BOLA_BODY, _BOLA_USER),

    _w("Mass Assignment / Auto-Binding", 30,
       "has_mutating_json_request", "mass_assignment",
       "Infer entity models from mutating JSON requests and predict hidden "
       "or administrative fields the backend may auto-bind.",
       _MASS_ASSIGNMENT_BODY, _MASS_ASSIGNMENT_USER),

    _w("Second-Order Vulnerabilities (Stored XSS / SQLi / SSTI)", 40,
       "has_mutating_json_request AND findings_count >= 5",
       "second_order_injection",
       "Map source endpoints to sink endpoints and generate dormant payloads "
       "designed to trigger only in the sink's execution context.",
       _SECOND_ORDER_BODY, _SECOND_ORDER_USER),

    _w("Multi-Step Authentication and OAuth Flaws", 50,
       "has_auth_redirect_chain", "oauth_oidc_flaw",
       "Analyze captured OAuth/OIDC/SAML redirect chains and JWTs for "
       "implementation flaws (state, nonce, PKCE, redirect_uri bypass, JWT alg/kid).",
       _OAUTH_BODY, _OAUTH_USER),

    _w("Complex Server-Side Request Forgery", 60,
       "has_url_processing_endpoint", "ssrf",
       "Infer underlying cloud/runtime from response signals and produce a "
       "prioritized SSRF payload list with metadata-only (non-credential) PoCs.",
       _SSRF_BODY, _SSRF_USER),

    _w("Broken Function Level Authorization", 70,
       "has_swagger_or_sourcemap OR findings_count >= 10", "bfla",
       "Extrapolate undocumented administrative endpoints from observed API "
       "path patterns and emit ready-to-run curl probes for a low-priv token.",
       _BFLA_BODY, _BFLA_USER),

    _w("Race Conditions (TOCTOU)", 80,
       "has_state_mutating_endpoint", "race_condition",
       "Identify the top state-mutating endpoints likely to be TOCTOU-vulnerable "
       "and produce a Single-Packet-Attack PoC (requests + ThreadPoolExecutor or Turbo Intruder).",
       _RACE_CONDITIONS_BODY, _RACE_CONDITIONS_USER),

    _w("Tenant Isolation Leaks", 90,
       "has_tenant_identifier", "tenant_isolation",
       "Identify tenant identifiers and predict cross-tenant leak classes "
       "the analyst should re-test as Tenant B.",
       _TENANT_ISOLATION_BODY, _TENANT_ISOLATION_USER),

    _w("API Abuse and Rate Limit Evasion", 100,
       "has_high_value_endpoint", "rate_limit_evasion",
       "Construct rate-limiter bypasses (GraphQL aliases, IP-spoofing headers, "
       "application-layer key tricks) for high-value endpoints.",
       _RATE_LIMIT_BODY, _RATE_LIMIT_USER),

    {
        "slot": SLOT_FIDELITY,
        "name": "Fidelity Evaluation (default)",
        "description": ("Per-finding fidelity grader for findings whose probe "
                         "verdict was unvalidated or inconclusive. Emits a "
                         "verdict + confidence + suggested severity."),
        "system_prompt": FIDELITY_SYSTEM,
        "user_template": FIDELITY_USER,
        "category": None,            # fidelity output schema isn't a finding row
        "fire_when": "",              # always-fire when slot is consulted
        "sort_order": 10,
        "batch_size": 5,
    },
]


# ---------------------------------------------------------------------------
# Seeding / restore helpers — consumed by app/server.py boot path and by
# the AI-Prompts admin page's "Restore to default" action.
# ---------------------------------------------------------------------------

def seed_defaults_if_empty(db) -> int:
    """Insert the eleven default rows into ai_prompts on a fresh database.

    No-op if any default row is already present (matched by slot+name).
    Returns the count of newly-inserted rows. Uses INSERT IGNORE so a
    partial seed (e.g. one row pre-existing because an operator imported
    it manually) doesn't crash, and to make the call safe to re-run on
    every container boot.

    On a fresh database the schema-drift auto-healer creates the
    ai_prompts table as part of applying db/schema.sql; this function
    runs immediately after, completing the bootstrap in one boot."""
    inserted = 0
    for row in DEFAULTS:
        existing = db.query_one(
            "SELECT id FROM ai_prompts WHERE slot=%s AND name=%s",
            (row["slot"], row["name"]))
        if existing:
            continue
        db.execute(
            """INSERT INTO ai_prompts
                  (slot, name, description, system_prompt, user_template,
                   category, fire_when, sort_order, batch_size,
                   is_active, is_seeded, version)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, 1)""",
            (row["slot"], row["name"], row["description"],
             row["system_prompt"], row["user_template"],
             row.get("category"), row.get("fire_when") or "",
             row["sort_order"], row.get("batch_size")))
        inserted += 1
    return inserted


def restore_defaults(db, *, only_slot: str | None = None,
                      only_name: str | None = None,
                      updated_by_user_id: int | None = None) -> dict:
    """Restore one or more seeded prompts to their in-code defaults.

    Three call patterns supported by the AI-Prompts admin page:
      - only_name set:  restore that single row (looked up by slot+name).
      - only_slot set:  restore every is_seeded row in that slot.
      - both None:      restore every is_seeded row, all slots. (Used by
                        a "factory reset" that we don't expose in the UI
                        but is available via SQL for emergencies.)

    Restore semantics: UPDATE the existing row's prompt body, user
    template, fire_when, sort_order, and batch_size to the in-code
    default. is_active is left alone (a paused row stays paused). If
    the row was deleted, it is re-INSERTed with is_active=1.

    Returns {"restored": [...names], "reinserted": [...names]}."""
    targets = DEFAULTS
    if only_slot:
        targets = [d for d in targets if d["slot"] == only_slot]
    if only_name:
        targets = [d for d in targets if d["name"] == only_name]

    restored: list[str] = []
    reinserted: list[str] = []
    for row in targets:
        existing = db.query_one(
            "SELECT id, version FROM ai_prompts WHERE slot=%s AND name=%s",
            (row["slot"], row["name"]))
        if existing:
            db.execute(
                """UPDATE ai_prompts
                      SET description = %s,
                          system_prompt = %s,
                          user_template = %s,
                          category = %s,
                          fire_when = %s,
                          sort_order = %s,
                          batch_size = %s,
                          is_seeded = 1,
                          version = version + 1,
                          updated_by_user_id = %s
                    WHERE id = %s""",
                (row["description"], row["system_prompt"],
                 row["user_template"], row.get("category"),
                 row.get("fire_when") or "", row["sort_order"],
                 row.get("batch_size"), updated_by_user_id,
                 existing["id"]))
            restored.append(row["name"])
        else:
            db.execute(
                """INSERT INTO ai_prompts
                      (slot, name, description, system_prompt, user_template,
                       category, fire_when, sort_order, batch_size,
                       is_active, is_seeded, version,
                       created_by_user_id, updated_by_user_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, 1, %s, %s)""",
                (row["slot"], row["name"], row["description"],
                 row["system_prompt"], row["user_template"],
                 row.get("category"), row.get("fire_when") or "",
                 row["sort_order"], row.get("batch_size"),
                 updated_by_user_id, updated_by_user_id))
            reinserted.append(row["name"])
    return {"restored": restored, "reinserted": reinserted}
