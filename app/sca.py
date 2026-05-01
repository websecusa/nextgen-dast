# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Software Composition Analysis (SCA) helpers.

Three responsibilities live here:

  1. Persistence — record observed (ecosystem, name, version) tuples
     into `sca_packages` and per-assessment context into
     `sca_assessment_packages`.

  2. Vulnerability lookup — given an observed package, return any
     matching rows from `sca_vulnerabilities`. Lookup order on each
     query is:
         a. local cache rows (any source)
         b. on-demand LLM gap-fill, when an endpoint is configured
            and no cache row exists
         c. cache the LLM answer (even when negative) so the same
            package is never re-queried within the cache TTL.

  3. Version range resolution — a tiny semver-ish comparator that
     handles the range expressions the cache stores
     (">=1.0.3 <3.5.0", "<3.5.0", "= 1.12.4", "1.x", etc.). Real OSV
     matches arrive pre-resolved from osv-scanner and do not need
     re-evaluation; this comparator only services LLM and retire.js
     entries that ship a free-form range string.

Design rules:
  - The cache is global, not per-assessment. Every customer scan
    benefits from any prior LLM lookup.
  - Manual entries (`source='manual'`, `is_locked=1`) are never
    overwritten by automatic refreshes.
  - Negative LLM answers are cached as `cve_id=NULL, severity='info'`
    rows with `summary='no known vulnerabilities (LLM)'` so the next
    scan can short-circuit without spending tokens.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

import db
import llm as llm_mod


# ---- LLM augmentation prompt ------------------------------------------------

LLM_SYSTEM_PROMPT = """You are a security database lookup service. Given an open-source package and version, return any publicly documented vulnerabilities that affect this exact version.

Return a single JSON object (no markdown fences, no commentary):

{
  "vulnerabilities": [
    {
      "cve_id": "CVE-YYYY-NNNNN" | null,
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx" | null,
      "vulnerable_range": "free-form range string (e.g. '>=1.0.3 <3.5.0')",
      "fixed_version": "first fixed version (e.g. '3.5.0')",
      "severity": "critical|high|medium|low|info",
      "cvss": "CVSS base score as a string, or empty",
      "summary": "one-line summary, <= 240 chars",
      "description": "2-4 sentences explaining the bug",
      "references": ["https://nvd.nist.gov/...", "https://github.com/..."]
    }
  ]
}

If you do not know of any vulnerabilities affecting this exact version, return {"vulnerabilities": []}. Do not invent CVEs. Confidence beats coverage."""


LLM_USER_TEMPLATE = """Package: {name}
Version: {version}
Ecosystem: {ecosystem}

List vulnerabilities affecting this exact version. Return JSON only."""


# ---- version range matcher --------------------------------------------------

_TOK_RE = re.compile(r"\s*(>=|<=|==|=|>|<|\!=)?\s*([0-9A-Za-z\.\-\+]+)\s*")


def _parse_version(v: str) -> tuple:
    """Return a tuple of integers + lexical fallbacks suitable for ordering.
    Coerces non-numeric segments to 0 so 1.0.0-rc1 sorts below 1.0.0 in the
    common case. This is intentionally a *simple* comparator — the OSV path
    handles the strict semver cases for us."""
    if not v:
        return (0,)
    parts: list = []
    for chunk in re.split(r"[.+\-]", v):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            # Numeric prefix wins over lexical tail.
            m = re.match(r"^(\d+)(.*)", chunk)
            if m:
                parts.append(int(m.group(1)))
            else:
                parts.append(-1)  # pre-release / wildcard
    return tuple(parts) or (0,)


def _cmp(a: str, b: str) -> int:
    pa, pb = _parse_version(a), _parse_version(b)
    return (pa > pb) - (pa < pb)


def in_range(version: str, range_str: str) -> bool:
    """Return True if `version` satisfies `range_str`.

    Accepted clauses (whitespace-separated, all must hold):
        >=X, <=X, >X, <X, =X, ==X, !=X
        bare X (treated as =X)
        X.x or X.* (semver wildcard — matches any patch-level)
    Empty / None range means "always matches" (a vulnerability with no
    declared range is treated as affecting every version of the package)."""
    if not range_str or not version:
        return True
    rs = range_str.strip()
    # Wildcard shorthand
    if rs.endswith(".x") or rs.endswith(".*"):
        prefix = rs[:-2]
        return version == prefix or version.startswith(prefix + ".")
    # Multiple clauses joined by spaces or commas
    clauses = [c for c in re.split(r"[\s,]+", rs) if c]
    for c in clauses:
        m = _TOK_RE.fullmatch(c)
        if not m:
            # Unparseable clause => fail open (treat as not matching)
            # so we don't generate spurious findings on garbage data.
            return False
        op, val = m.group(1) or "=", m.group(2)
        d = _cmp(version, val)
        if op == ">=" and not (d >= 0):
            return False
        if op == "<=" and not (d <= 0):
            return False
        if op == ">"  and not (d >  0):
            return False
        if op == "<"  and not (d <  0):
            return False
        if op in ("=", "==") and d != 0:
            return False
        if op == "!=" and d == 0:
            return False
    return True


# ---- package recording ------------------------------------------------------

def record_package(ecosystem: str, name: str, version: str,
                   *, latest_version: Optional[str] = None) -> None:
    """Upsert into sca_packages. Updates last_seen on conflict."""
    if not (ecosystem and name and version):
        return
    db.execute(
        """INSERT INTO sca_packages (ecosystem, name, version, latest_version)
           VALUES (%s, %s, %s, %s)
           ON DUPLICATE KEY UPDATE
             last_seen = CURRENT_TIMESTAMP,
             latest_version = COALESCE(VALUES(latest_version), latest_version)""",
        (ecosystem[:32], name[:255], version[:128], latest_version),
    )


def record_assessment_package(assessment_id: int, ecosystem: str, name: str,
                              version: str, *, source_url: Optional[str],
                              detection_method: str,
                              matched_cves: Optional[list[str]] = None) -> int:
    """Insert one row into sca_assessment_packages. Returns the row id."""
    return db.execute(
        """INSERT INTO sca_assessment_packages
           (assessment_id, ecosystem, name, version,
            source_url, detection_method, matched_cves_json)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (assessment_id, (ecosystem or "")[:32], (name or "")[:255],
         (version or "")[:128], (source_url or "")[:1024],
         (detection_method or "")[:32],
         json.dumps(matched_cves or [])),
    )


# ---- vulnerability cache ---------------------------------------------------

def cached_vulns(ecosystem: str, name: str) -> list[dict]:
    """Return every cached vulnerability row for a package, regardless
    of version. Caller filters by version using in_range()."""
    return db.query(
        "SELECT * FROM sca_vulnerabilities "
        "WHERE ecosystem=%s AND package_name=%s "
        "ORDER BY severity, cve_id",
        (ecosystem[:32], name[:255]),
    )


def matching_vulns(ecosystem: str, name: str, version: str) -> list[dict]:
    """Return cached vulnerabilities affecting (ecosystem, name) at version.
    Excludes the synthetic 'no known vulnerabilities (LLM)' negative cache
    entries so callers don't surface them as findings."""
    rows = cached_vulns(ecosystem, name)
    out: list[dict] = []
    for r in rows:
        if (r.get("source") == "llm" and
                (r.get("summary") or "").startswith("no known")):
            continue
        if in_range(version, r.get("vulnerable_range") or ""):
            out.append(r)
    return out


def upsert_vuln(ecosystem: str, name: str, *, vulnerable_range: str,
                cve_id: Optional[str] = None, ghsa_id: Optional[str] = None,
                severity: str = "unknown", cvss: Optional[str] = None,
                summary: Optional[str] = None, description: Optional[str] = None,
                fixed_version: Optional[str] = None,
                references: Optional[list[str]] = None,
                source: str = "manual",
                llm_endpoint_id: Optional[int] = None,
                llm_model: Optional[str] = None) -> int:
    """Insert or refresh one vulnerability row. Manual entries (existing
    rows with is_locked=1) are NEVER overwritten — the call returns the
    existing row's id unchanged. Returns the affected row's id."""
    sev = (severity or "unknown").lower()
    if sev not in ("critical", "high", "medium", "low", "info", "unknown"):
        sev = "unknown"
    existing = db.query_one(
        "SELECT id, is_locked FROM sca_vulnerabilities "
        "WHERE ecosystem=%s AND package_name=%s "
        "  AND vulnerable_range=%s "
        "  AND IFNULL(cve_id,'') = IFNULL(%s,'') "
        "LIMIT 1",
        (ecosystem[:32], name[:255], (vulnerable_range or "")[:255],
         cve_id),
    )
    if existing and existing.get("is_locked"):
        return existing["id"]
    if existing:
        db.execute(
            """UPDATE sca_vulnerabilities SET
                 ghsa_id=%s, severity=%s, cvss=%s,
                 summary=%s, description=%s,
                 fixed_version=%s, references_json=%s,
                 source=%s, llm_endpoint_id=%s, llm_model=%s,
                 fetched_at=CURRENT_TIMESTAMP
               WHERE id=%s""",
            (ghsa_id, sev, cvss,
             (summary or "")[:512], description or "",
             fixed_version, json.dumps(references or []),
             source, llm_endpoint_id, llm_model,
             existing["id"]),
        )
        return existing["id"]
    return db.execute(
        """INSERT INTO sca_vulnerabilities
             (ecosystem, package_name, vulnerable_range,
              cve_id, ghsa_id, severity, cvss,
              summary, description, fixed_version, references_json,
              source, llm_endpoint_id, llm_model)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (ecosystem[:32], name[:255], (vulnerable_range or "")[:255],
         cve_id, ghsa_id, sev, cvss,
         (summary or "")[:512], description or "",
         fixed_version, json.dumps(references or []),
         source, llm_endpoint_id, llm_model),
    )


# ---- LLM augmentation -------------------------------------------------------

# The negative-cache TTL governs how long we trust an "LLM said no known
# vulns" answer before re-asking. Far enough that we don't burn tokens on
# every scan; short enough that newly disclosed CVEs are picked up on the
# next refresh. Tunable via the config table.
NEGATIVE_CACHE_DAYS_DEFAULT = 30


def _negative_cache_days() -> int:
    try:
        r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                         ("sca_signature_max_age_days",))
        if r and (r.get("value") or "").strip():
            return max(1, int(r["value"]))
    except Exception:
        pass
    return NEGATIVE_CACHE_DAYS_DEFAULT


def _have_recent_negative(ecosystem: str, name: str) -> bool:
    """True iff we have a cached 'no known vulns' answer for this package
    that is still within the negative-cache TTL."""
    row = db.query_one(
        "SELECT fetched_at FROM sca_vulnerabilities "
        "WHERE ecosystem=%s AND package_name=%s "
        "  AND source='llm' AND IFNULL(cve_id,'')='' "
        "  AND summary LIKE 'no known%%' "
        "ORDER BY fetched_at DESC LIMIT 1",
        (ecosystem[:32], name[:255]),
    )
    if not row or not row.get("fetched_at"):
        return False
    fetched = row["fetched_at"]
    if isinstance(fetched, str):
        try:
            fetched = datetime.fromisoformat(fetched)
        except ValueError:
            return False
    age_days = (datetime.utcnow() - fetched).days
    return age_days < _negative_cache_days()


def _llm_call(endpoint: dict, system: str, user: str) -> Optional[str]:
    backend = endpoint["backend"]
    if backend == "anthropic":
        result = llm_mod.call_anthropic(endpoint["api_key"], endpoint["model"],
                                        system, user, max_tokens=1500)
    elif backend == "openai_compat":
        extra = {}
        if endpoint.get("extra_headers"):
            try:
                extra = json.loads(endpoint["extra_headers"])
            except Exception:
                extra = {}
        result = llm_mod.call_openai_compat(
            endpoint["base_url"], endpoint["api_key"], endpoint["model"],
            system, user, max_tokens=1500, extra_headers=extra,
        )
    else:
        return None
    if not result.get("ok"):
        return None
    return result.get("content", "")


def llm_lookup(ecosystem: str, name: str, version: str,
               endpoint: dict) -> list[dict]:
    """Ask the LLM for vulnerabilities affecting this package, parse the
    response, write each vuln (or a negative-cache row) into the cache,
    and return the parsed vulnerability list. Returns [] on any error
    or when the LLM reports no vulnerabilities."""
    if not endpoint:
        return []
    user = LLM_USER_TEMPLATE.format(
        name=name, version=version, ecosystem=ecosystem,
    )
    raw = _llm_call(endpoint, LLM_SYSTEM_PROMPT, user)
    if not raw:
        return []
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
    except Exception:
        return []
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        vulns = []
    if not vulns:
        # Cache the negative answer so we don't re-query on every scan.
        upsert_vuln(
            ecosystem, name,
            vulnerable_range="",
            severity="info",
            summary="no known vulnerabilities (LLM)",
            source="llm",
            llm_endpoint_id=endpoint.get("id"),
            llm_model=endpoint.get("model"),
        )
        return []
    out: list[dict] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        upsert_vuln(
            ecosystem, name,
            vulnerable_range=str(v.get("vulnerable_range") or ""),
            cve_id=(v.get("cve_id") or None),
            ghsa_id=(v.get("ghsa_id") or None),
            severity=str(v.get("severity") or "unknown"),
            cvss=str(v.get("cvss") or "") or None,
            summary=str(v.get("summary") or "")[:512],
            description=str(v.get("description") or ""),
            fixed_version=(v.get("fixed_version") or None),
            references=v.get("references") or [],
            source="llm",
            llm_endpoint_id=endpoint.get("id"),
            llm_model=endpoint.get("model"),
        )
        out.append(v)
    return out


def lookup_or_augment(ecosystem: str, name: str, version: str,
                      endpoint: Optional[dict] = None) -> list[dict]:
    """Return all known vulnerabilities for (ecosystem, name) at version.

    Cache hit short-circuits. On miss, an LLM augmentation runs only when
    an endpoint is supplied and no recent negative-cache entry exists for
    the package. The LLM result is written back to the cache and merged
    with any existing rows before being returned."""
    hits = matching_vulns(ecosystem, name, version)
    if hits:
        return hits
    if not endpoint:
        return []
    if _have_recent_negative(ecosystem, name):
        return []
    llm_lookup(ecosystem, name, version, endpoint)
    return matching_vulns(ecosystem, name, version)


# ---- helpers for the admin page --------------------------------------------

def stats() -> dict:
    """Return a cheap summary for the admin SCA page."""
    out: dict = {}
    try:
        out["packages"] = (db.query_one("SELECT COUNT(*) c FROM sca_packages")
                           or {}).get("c", 0)
        # PyMySQL runs the query through Python's % formatting even when
        # the args tuple is empty, so every literal % in SQL must be
        # escaped as %% — including inside string-literals like LIKE.
        out["vulnerabilities"] = (
            db.query_one("SELECT COUNT(*) c FROM sca_vulnerabilities "
                         "WHERE NOT (source='llm' AND IFNULL(cve_id,'')='' "
                         "          AND summary LIKE 'no known%%')")
            or {}).get("c", 0)
        out["by_source"] = {
            r["source"]: r["c"] for r in db.query(
                "SELECT source, COUNT(*) c FROM sca_vulnerabilities "
                "GROUP BY source")
        }
        out["by_severity"] = {
            r["severity"]: r["c"] for r in db.query(
                "SELECT severity, COUNT(*) c FROM sca_vulnerabilities "
                "WHERE NOT (source='llm' AND IFNULL(cve_id,'')='' "
                "          AND summary LIKE 'no known%%') "
                "GROUP BY severity")
        }
    except Exception:
        pass
    return out
