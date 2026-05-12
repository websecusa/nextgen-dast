# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cross-source finding dedup.

When several scanners + the LLM weakness pass + the agentic pass all
report the same underlying bug, this module is what decides they are
the same bug. It exists because each source picks its own title /
phrasing -- testssl writes "ANULL ciphers enabled", the LLM writes
"TLS Anonymous Cipher Suites Accepted - No Server Authentication
Possible", the agentic pass writes "TLS aNULL/AECDH Cipher Suites
Enabled" -- and an analyst staring at three pages of the same finding
loses the signal.

Two callers:

  - app/agentic_ai.py and app/enhanced_ai.py use `dedup_signature_v2()`
    + `find_existing_canonical()` to refuse near-duplicate emissions
    BEFORE the row hits the DB. The agent gets a tool_result naming
    the canonical finding it would have duplicated, and can pivot to
    investigating something new or chain it into deeper impact.

  - app/consolidation.py uses `dedup_signature_v2()` to soft-demote
    losers AFTER all sources have written. It picks the highest-tier
    row as canonical and sets `dedup_of=<canonical_id>` on the others.
    Soft demote -- nothing is deleted -- so a mis-clustered signature
    is reversible by clearing the column.

Fidelity tiers (highest precedence first):

  Tier 1 : testssl, nuclei, enhanced_testing
           These tools fire when they have direct evidence of the
           bug (TLS handshake exchange, CVE template match,
           deterministic probe). Trust them.

  Tier 2 : nikto, wapiti, dalfox, sqlmap, ffuf
           Reliable but noisier; sometimes flag patterns rather than
           confirmed bugs.

  Tier 3 : enhanced_ai_testing, agentic_ai_testing
           LLM-emitted with verbatim evidence excerpts. Lowest
           precedence on ties -- the deterministic finding wins, the
           LLM's exploit-chain reasoning gets folded into raw_data on
           the canonical row by the consolidation pass.

Tiers are intentionally simple integers (lower wins) so a single
ORDER BY in SQL can pick the canonical row.
"""
from __future__ import annotations

import json
import re
from typing import Optional

import db


# ---------------------------------------------------------------------------
# Fidelity tiers
# ---------------------------------------------------------------------------

# Lower number = higher precedence on a dedup tie. Sources not listed
# default to TIER_DEFAULT.
FIDELITY_TIERS = {
    # Tier 1 -- deterministic, evidence-based
    "testssl":              1,
    "nuclei":               1,
    "enhanced_testing":     1,
    # Tier 2 -- pattern-based scanners
    "nikto":                2,
    "wapiti":               2,
    "dalfox":               2,
    "sqlmap":               2,
    "ffuf":                 2,
    "sca":                  2,
    # Tier 3 -- LLM-emitted
    "enhanced_ai_testing":  3,
    "agentic_ai_testing":   3,
}

TIER_DEFAULT = 2


def tier_for(source_tool: str) -> int:
    """Return the fidelity tier (1 = highest) for a given source_tool.
    Unknown tools default to TIER_DEFAULT so a new scanner shows up
    mid-pack rather than always winning or always losing."""
    return FIDELITY_TIERS.get((source_tool or "").strip().lower(),
                              TIER_DEFAULT)


# ---------------------------------------------------------------------------
# Vuln-class catalog
# ---------------------------------------------------------------------------

# Coarse vuln-class regex catalog. Maps free-text titles + evidence
# excerpts onto a small set of canonical class keys so "Missing HSTS
# Header", "No HSTS Header Present", and "Missing HTTP Strict-
# Transport-Security header" all map to `hsts_missing`. Order
# matters: longer / more specific phrases first so the looser ones
# don't win when a more specific one also matches.
_DEDUP_VULN_CLASSES = (
    # XSS family
    ("stored_xss",          (r"stored\s+xss",)),
    ("reflected_xss",       (r"reflected\s+xss",)),
    ("dom_xss",             (r"dom[\s-]+xss",)),
    ("xss",                 (r"\bxss\b", r"cross[\s-]+site\s+scripting")),
    # SQL injection family
    ("sqli_union",          (r"union[\s-]+(?:based\s+)?sql", r"union\s+select")),
    ("sqli",                (r"\bsqli\b", r"sql\s+injection")),
    ("nosqli",              (r"nosql\s+injection", r"\bnosqli\b",
                             r"mongo[\s-]*operator", r"\$ne\b")),
    # Server-side / object-level
    ("xxe",                 (r"\bxxe\b", r"xml\s+external\s+entity")),
    ("ssrf",                (r"\bssrf\b", r"server[\s-]+side\s+request")),
    ("idor_bola",           (r"\bidor\b", r"\bbola\b",
                             r"broken\s+object[\s-]+level\s+authorization",
                             r"object[\s-]+level\s+authorization")),
    ("mass_assignment",     (r"mass[\s-]+assignment", r"auto[\s-]+bind")),
    ("prototype_pollution", (r"prototype[\s-]+pollution", r"__proto__")),
    ("open_redirect",       (r"open[\s-]+redirect",)),
    # JWT misuses
    ("jwt_alg_none",        (r"alg\s*[:=]\s*none",
                             r"alg[\s-]*none",
                             r"signature\s+not\s+verified")),
    ("jwt_no_exp",          (r"no\s+exp(?:iration|iry)?",
                             r"missing\s+(?:`?exp`?|expir)",
                             r"never\s+expir")),
    ("jwt_key_confusion",   (r"key\s+confusion", r"rs256.+hs256",
                             r"hs256.+rs256")),
    # Common exposures
    ("metrics_exposed",     (r"prometheus[\s/]*metrics", r"/metrics\b")),
    ("swagger_exposed",     (r"swagger", r"openapi", r"/api-docs")),
    ("admin_config_exposed",(r"application[\s-]+configuration",
                             r"/rest/admin",)),
    ("memories_pii_leak",   (r"/rest/memories", r"memories.*(?:password|hash|"
                             r"pii|deluxetoken|totpsecret)")),
    ("auth_details_leak",   (r"/rest/user/authentication-details",
                             r"authentication[\s-]*details.*expos")),
    # Configuration / headers
    ("cors_wildcard",       (r"cors\s+wildcard",
                             r"access[\s-]+control[\s-]+allow[\s-]+origin.*\*")),
    ("hsts_missing",        (r"hsts", r"strict[\s-]+transport[\s-]+security",
                             # "Plain HTTP serves ... no https redirect",
                             # "plaintext HTTP accepted with no redirect",
                             # etc. The "no/not ... redirect" can have
                             # arbitrary words in between (the protocol
                             # word, "auto-", "to https"). Keep this
                             # generous; false-positive cost is low (the
                             # other heuristics down-rank rare matches).
                             r"plain(?:text)?\s+http",
                             r"http.*(?:no|not)[\s\w]*redirect",
                             r"http.*not\s+redirect")),
    ("tls_null_cipher",     (r"\banull\b", r"\baecdh\b", r"null\s+cipher",
                             r"null[\s-]+encryption", r"anonymous\s+(?:tls\s+)?"
                             r"cipher", r"ecdh_anon")),
    ("tls_weak_cipher",     (r"weak\s+(?:tls\s+)?cipher", r"sweet32",
                             r"3des", r"rc4")),
    # Verbose / framework leaks
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

# Stopwords stripped from the token-set fallback so unrelated findings
# don't accidentally collide on filler words.
_DEDUP_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are",
    "was", "has", "have", "not", "but", "use", "via", "into",
    "any", "all", "may", "can", "could", "would", "should",
    "https", "http",
}


def _classify_vuln_class(haystack: str) -> str:
    """Map a title+evidence string to a coarse vuln-class key. Empty
    string when no class matched -- caller falls back to URL+token."""
    for key, patterns in _DEDUP_VULN_CLASSES:
        for pat in patterns:
            if re.search(pat, haystack, re.IGNORECASE):
                return key
    return ""


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

# Numeric / UUID path segments are normalized so /users/123 and
# /users/456 collapse to the same canonical path. Matches the policy
# `enrichment.signature()` already uses.
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"(?=/|$)", re.IGNORECASE)


def _canonical_path(url: str) -> str:
    """Pull the path off a URL string, strip query/fragment, normalize
    numeric / UUID segments to placeholders. Returns '' on no match."""
    if not url:
        return ""
    # Drop scheme + host so /a/b normalizes the same whether the
    # caller passed https://h/a/b or just /a/b.
    s = re.sub(r"^https?://[^/]+", "", url.strip(), count=1)
    # Drop query + fragment.
    s = re.sub(r"[?#].*$", "", s)
    if not s.startswith("/"):
        # Title-style URL fragment ("/metrics" embedded in a sentence).
        m = re.search(r"/[a-z0-9_\-/.]+", s, re.IGNORECASE)
        s = m.group(0) if m else ""
    s = _UUID_SEGMENT_RE.sub("/{uuid}", s)
    s = _NUMERIC_SEGMENT_RE.sub("/{id}", s)
    # Strip trailing slashes and stray punctuation that may have come
    # from prose ("on /metrics, observed ..." -> "/metrics").
    return s.rstrip("/.,;:")


# Path strings that look like URL paths but are almost always noise
# (MIME-type fragments, file extensions, codec / format identifiers
# captured from response bodies). Returning these as the path
# component would dedupe unrelated findings that just happen to
# mention "/png" or "/zip" anywhere in their evidence.
_PATH_NOISE_BLOCKLIST = frozenset({
    "/png", "/jpg", "/jpeg", "/gif", "/zip", "/json", "/xml",
    "/html", "/css", "/js", "/svg", "/pdf", "/csv", "/text",
    "/octet-stream", "/x-www-form-urlencoded",
})


_HOST_LEVEL_CLASSES = frozenset({
    # These findings describe a property of the server / TLS endpoint /
    # security headers, NOT a specific URL path. Path tokens captured
    # from the title or evidence are spurious for these classes (e.g.
    # "aNULL/AECDH" extracts "/aecdh", which then makes the signature
    # too specific and stops it dedup-ing against the same bug from a
    # source that wrote "anonymous TLS cipher" with no slash). For
    # this set the signature is just the class key.
    "hsts_missing",
    "tls_null_cipher",
    "tls_weak_cipher",
    "cors_wildcard",
})


def dedup_signature_v2(title: str, evidence: str,
                       owasp: str = "") -> str:
    """Severity-FREE dedup signature for cross-source matching.

    Format precedence:
      1. vuln_class|canonical_path  -- tight: rephrasings on the same
         endpoint collapse regardless of wording.
      2. vuln_class                 -- groups same-class findings even
         when paths differ (e.g. HSTS missing applies to the host).
      3. url:<canonical_path>       -- no vuln-class hit but we have a
         path; useful for one-off scanner findings keyed to a path.
      4. tok:<sorted-content-tokens> -- last resort for short titles
         with no path or class match.

    Host-level classes (`_HOST_LEVEL_CLASSES`) intentionally skip the
    path component since a TLS/HSTS finding describes the endpoint
    not a URL path -- the same bug from two sources must collapse
    even when one source's title happens to contain a "/aecdh"-
    looking fragment.

    Vuln-class classification reads ONLY the title. The evidence
    excerpt (esp. for LLM-emitted findings) is too noisy -- a
    response body that happens to contain "Access-Control-Allow-
    Origin: *" headers misfires every finding against that endpoint
    as `cors_wildcard`. The title is the canonical statement of
    what the bug is. Path extraction reads both since the URL of
    interest may appear in either.

    Returns '' when even the token fallback is empty -- caller treats
    that as 'no signature, do not dedup'.

    The owasp field is accepted for API symmetry with the Round-1
    helper but intentionally not folded in here: cross-source dedup
    must work when testssl emits a finding with NULL owasp_category
    against the LLM's same finding emitted with 'A05_Security_
    Misconfiguration'. Severity is omitted for the same reason -- a
    low-fidelity source's 'critical' rating should still collapse
    onto a high-fidelity source's 'high'.
    """
    del owasp  # accepted but unused; see docstring
    title_lc = (title or "").lower()
    # Title-only classification. Avoids false positives from LLM
    # response-body excerpts that happen to contain unrelated
    # vuln-class keywords (CORS header echoes, NULL byte mentions
    # in error traces, etc).
    cls = _classify_vuln_class(title_lc)

    # Path extraction reads title + evidence but FIRST strips out
    # URL host:port prefixes so `https://host/x` doesn't get parsed
    # as `//host/x` (a leading-double-slash path that then collides
    # every finding against the same host onto one bucket).
    haystack_for_paths = f"{title_lc} {(evidence or '').lower()}"
    haystack_for_paths = re.sub(
        r"https?://[^/\s)>'\"]+(?=/|\s|$)", " ",
        haystack_for_paths)
    urls = re.findall(r"/[a-z0-9_\-/.]{2,}", haystack_for_paths)
    primary = ""
    if urls:
        # Shortest path is usually the canonical form (`/metrics`
        # rather than `/metrics/something/foo`). Filter out anything
        # that still has a leading `//` (the URL strip missed it)
        # or that's just a file extension fragment.
        candidates = set()
        for u in urls:
            cp = _canonical_path(u)
            if not cp or cp.startswith("//"):
                continue
            # Reject obvious non-path artifacts: `/png`, `/zip`,
            # `/json` (which come from regex capturing inside MIME
            # types / file extensions in evidence prose).
            if cp.lower() in _PATH_NOISE_BLOCKLIST:
                continue
            candidates.add(cp)
        if candidates:
            primary = min(candidates, key=len)

    if cls in _HOST_LEVEL_CLASSES:
        return f"{cls}"
    if cls and primary:
        return f"{cls}|{primary}"
    if cls:
        return f"{cls}"
    if primary:
        return f"url:{primary}"

    # Token-set fallback uses the TITLE only -- evidence excerpts
    # carry too much noise that would explode the signature space.
    # Strip out URLs / path fragments from the title before tokenizing.
    stripped = re.sub(r"https?://[^\s)>'\"]+|/[a-z0-9_\-/.]+", " ",
                      title_lc)
    words = re.findall(r"[a-z0-9]{4,}", stripped)
    content = sorted({w for w in words if w not in _DEDUP_STOPWORDS})[:12]
    if not content:
        return ""
    return "tok:" + "|".join(content)


def compute_signature_for_finding(finding: dict) -> str:
    """Convenience wrapper: pull the signature inputs off a findings
    row dict (as returned by SELECT * FROM findings) and call
    dedup_signature_v2(). Reads raw_data.llm_evidence when the
    column-level evidence is empty (LLM-emitted findings carry their
    excerpt in raw_data, not evidence_url)."""
    title = (finding.get("title") or "").strip()
    evidence = (finding.get("evidence_url") or "").strip()
    if not evidence:
        rd = finding.get("raw_data")
        if isinstance(rd, (bytes, str)):
            try:
                rd = json.loads(rd)
            except Exception:
                rd = None
        if isinstance(rd, dict):
            evidence = (rd.get("llm_evidence")
                        or rd.get("evidence")
                        or "")
    return dedup_signature_v2(title, str(evidence),
                              finding.get("owasp_category") or "")


# ---------------------------------------------------------------------------
# Pre-emit lookup
# ---------------------------------------------------------------------------

def build_signature_index(aid: int,
                          *, exclude_source_tools: Optional[set] = None,
                          min_tier: int = 1, max_tier: int = 3,
                          include_demoted: bool = False) -> dict:
    """Return a {signature: {canonical_id, source_tool, severity,
    title, tier}} map for the assessment.

    When several findings share a signature, the one with the LOWEST
    tier (highest fidelity) wins. Ties broken by lowest id (the
    earliest written, which is usually the deterministic scanner that
    ran first). Demoted rows (dedup_of IS NOT NULL) are skipped by
    default since the canonical they point at is already in the index.

    Filters:
      exclude_source_tools -- skip rows from these tools (e.g. the
        agent excludes its own prior emissions from the 'already-
        known' preamble when it wants to see only other-source
        findings).
      min_tier / max_tier  -- tier range to scan. Defaults cover
        everything; callers can pass max_tier=2 to look only at
        deterministic + scanner sources.
      include_demoted       -- include rows with dedup_of set. Off by
        default; on only for diagnostic tooling.
    """
    where = [
        "f.assessment_id = %s",
        "COALESCE(f.status, 'open') NOT IN "
        "  ('false_positive','fixed','accepted_risk')",
    ]
    args: list = [aid]
    if not include_demoted:
        where.append("f.dedup_of IS NULL")
    sql = (
        "SELECT f.id, f.source_tool, f.severity, f.title, "
        "       f.evidence_url, f.owasp_category, f.raw_data "
        "FROM findings f "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY f.id"
    )
    rows = db.query_all(sql, tuple(args))
    index: dict = {}
    excl = {(s or "").strip().lower() for s in (exclude_source_tools or set())}
    for r in rows:
        st = (r.get("source_tool") or "").strip().lower()
        if st in excl:
            continue
        t = tier_for(st)
        if t < min_tier or t > max_tier:
            continue
        sig = compute_signature_for_finding(r)
        if not sig:
            continue
        cur = index.get(sig)
        if cur is None or t < cur["tier"] or (
                t == cur["tier"] and r["id"] < cur["canonical_id"]):
            index[sig] = {
                "canonical_id": int(r["id"]),
                "source_tool": st,
                "severity": (r.get("severity") or "").lower(),
                "title": (r.get("title") or "")[:200],
                "tier": t,
            }
    return index


def find_existing_canonical(aid: int, signature: str,
                            *, max_tier: int = 3,
                            exclude_source_tools: Optional[set] = None
                            ) -> Optional[dict]:
    """One-shot lookup for the pre-emit gate. Returns the canonical
    row for a given signature, or None when nothing matches.

    Inefficient if called per-emit -- callers that need to check many
    candidates should pre-build a full signature index with
    `build_signature_index()` and look up locally."""
    if not signature:
        return None
    idx = build_signature_index(
        aid,
        exclude_source_tools=exclude_source_tools,
        max_tier=max_tier)
    return idx.get(signature)


# ---------------------------------------------------------------------------
# Preamble rendering
# ---------------------------------------------------------------------------

# A short prose explanation prepended to the agent's user message so
# the model understands why the bullet list is there and what it
# should do with it. Lives in this module so the wording stays
# consistent across the per-finding pass, the free-roam pass, and the
# enhanced_ai_testing weakness pass.
_ALREADY_KNOWN_HEADER = (
    "ALREADY CONFIRMED BY OTHER SCANNERS\n"
    "====================================\n"
    "These findings are already in this assessment. Do NOT re-test "
    "or re-emit them -- the safety layer will refuse a duplicate "
    "emission with a reference to the canonical id. Spend your "
    "budget on:\n"
    "  - genuinely new bugs the deterministic probes did not cover, OR\n"
    "  - chaining one of the bugs below into a deeper impact "
    "(e.g. use a leaked token from the PII leak to reach an admin "
    "endpoint).\n")


# ---------------------------------------------------------------------------
# Post-hoc cross-source soft demote
# ---------------------------------------------------------------------------

def apply_cross_source_dedup(aid: int) -> dict:
    """Walk every open finding on the assessment, cluster by
    dedup_signature_v2, and set `dedup_of=<canonical_id>` on the
    losers. The canonical row in each cluster is picked by:
      1. Lowest fidelity tier number (testssl/nuclei/enhanced_testing
         beats nikto/wapiti beats enhanced_ai_testing/agentic).
      2. Tie-broken by lowest finding id (earliest written, usually
         the deterministic scanner that ran first).

    Soft demote: nothing is deleted, the loser's raw_data and exploit-
    chain reasoning stay attached to it so an analyst can drill in
    via the canonical row's "see N duplicate findings" disclosure.
    Reversible by clearing `dedup_of` on any mis-clustered row.

    Returns a summary dict {clusters, demoted, untouched} for the
    orchestrator log. The total finding count is unchanged -- the
    rollup at render time is the one that hides demoted rows.
    """
    rows = db.query_all(
        "SELECT id, source_tool, severity, title, evidence_url, "
        "       owasp_category, raw_data, dedup_of "
        "FROM findings "
        "WHERE assessment_id = %s "
        "  AND COALESCE(status,'open') NOT IN "
        "      ('false_positive','fixed','accepted_risk') "
        "ORDER BY id",
        (aid,))
    clusters: dict = {}
    untouched = 0
    for r in rows:
        sig = compute_signature_for_finding(r)
        if not sig:
            untouched += 1
            continue
        bucket = clusters.setdefault(sig, [])
        bucket.append({
            "id": int(r["id"]),
            "source_tool": (r.get("source_tool") or "").strip().lower(),
            "tier": tier_for(r.get("source_tool") or ""),
            "severity": (r.get("severity") or "").lower(),
            "title": (r.get("title") or "")[:200],
            "dedup_of": r.get("dedup_of"),
        })
    demoted = 0
    cluster_count = 0
    for sig, members in clusters.items():
        if len(members) <= 1:
            continue
        # Pick the canonical row. Lowest tier wins; ties go to the
        # lowest id (earliest-written).
        members.sort(key=lambda m: (m["tier"], m["id"]))
        canonical = members[0]
        losers = members[1:]
        cluster_count += 1
        # Clear dedup_of on the canonical in case a prior run picked
        # a different canonical (e.g. testssl wrote AFTER nikto and
        # was demoted onto nikto's row -- next run rebalances).
        if canonical.get("dedup_of"):
            db.execute(
                "UPDATE findings SET dedup_of = NULL WHERE id = %s",
                (canonical["id"],))
        for loser in losers:
            # No-op if dedup_of is already pointing at this canonical.
            if loser.get("dedup_of") == canonical["id"]:
                demoted += 1
                continue
            db.execute(
                "UPDATE findings SET dedup_of = %s WHERE id = %s",
                (canonical["id"], loser["id"]))
            demoted += 1
    return {
        "clusters_demoted": cluster_count,
        "rows_demoted": demoted,
        "rows_untouched": untouched,
        "total_open": len(rows),
    }


def build_already_known_preamble(aid: int,
                                  *, exclude_source_tools: Optional[set] = None
                                  ) -> str:
    """Render the 'already confirmed by other scanners' bullet list
    for injection into an agent / LLM-weakness-pass prompt.

    The list is one line per dedup signature -- so 27 testssl + agent
    duplicates of the same TLS aNULL bug collapse to one bullet.

    `exclude_source_tools` is the set of sources whose findings
    SHOULDN'T appear in the preamble -- typically the LLM is told
    about deterministic scanners' findings but not about its own
    prior emissions (those are handled by within-source dedup that
    runs before this).

    Returns the header + bullet list, or a placeholder string when
    nothing is known yet so the template renderer never sees a bare
    empty section."""
    idx = build_signature_index(
        aid,
        exclude_source_tools=exclude_source_tools,
        max_tier=3)
    if not idx:
        return _ALREADY_KNOWN_HEADER + (
            "(no findings recorded yet from deterministic scanners; "
            "the agent has the full surface to investigate)")
    # Order by tier ascending, then by severity rank, then by id so
    # the highest-fidelity / highest-severity bugs lead the list.
    sev_rank = {"critical": 0, "high": 1, "medium": 2,
                "low": 3, "info": 4}
    items = sorted(
        idx.items(),
        key=lambda kv: (kv[1]["tier"],
                        sev_rank.get(kv[1]["severity"], 5),
                        kv[1]["canonical_id"]))
    lines = [_ALREADY_KNOWN_HEADER]
    for _sig, info in items[:50]:
        lines.append(
            f"  - #{info['canonical_id']} [{info['severity']}] "
            f"{info['title']}  -- {info['source_tool']}")
    if len(idx) > 50:
        lines.append(
            f"  ... plus {len(idx) - 50} more clustered findings")
    return "\n".join(lines)
