# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Server-side enumeration + invocation of toolkit probes.

The probes themselves live in /app/toolkit (volume-mounted :ro). This
module just lists them, reads their manifests, and shells out to run one.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

TOOLKIT_DIR = Path("/app/toolkit")
PROBES_DIR = TOOLKIT_DIR / "probes"
# Enhanced-testing probes ship in their own directory because they're
# also invoked during the `premium` scan profile (the orchestrator
# queues them there). They share the same Probe / Verdict / SafeClient
# scaffolding from toolkit/lib, so once a manifest is in place they're
# fully usable as Validate / Challenge probes too — that's how a
# finding emitted by, say, auth_sql_login_bypass during a scan can be
# re-validated on demand by the analyst clicking Challenge.
ENHANCED_PROBES_DIR = Path("/app/enhanced_testing/probes")

# Probe name format guard (used in any path-sensitive lookup).
PROBE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,32}$")

# Top-level OWASP-2021 category prefix (A01:2021- through A10:2021-, plus
# any future year). Used to filter out coarse routing entries from a
# probe's `validates` list — see _routing_cwes() for the full rationale.
_OWASP_TOP_RE = re.compile(r"^A\d{1,2}:\d{4}-", re.IGNORECASE)

# Track manifests we've already warned about so a noisy log doesn't grow
# unbounded across requests. Module-scoped: cleared on container restart.
_OWASP_WARNED: set[str] = set()


def _routing_cwes(validates: list[str] | None) -> list[str]:
    """Return the subset of a probe's `validates` list that is narrow
    enough to drive routing.

    Top-level OWASP-2021 categories ('A01:2021-...' through 'A10:2021-...')
    are filtered out: many parsers default findings to a single top-level
    OWASP (parse_testssl emits A02 for every TLS finding; parse_nikto
    emits A05 for every info finding), so a probe that lists those
    catch-alls in `validates` ends up matching every finding of that
    shape regardless of subject matter — three rounds of regressions
    shipped because this trap is easy to fall into.

    CWE-* entries (CWE-79, CWE-284, CWE-310, ...) are specific enough
    to carry routing signal and are kept verbatim. Anything that
    doesn't start with 'A<digits>:<year>-' passes through.
    """
    return [v for v in (validates or [])
            if v and not _OWASP_TOP_RE.match(v)]


def list_probes() -> list[dict]:
    """Return all probes available to the orchestrator. Walks two
    directories: the canonical toolkit (validation probes invoked from
    the Challenge / Validate UI) and the enhanced-testing tree (probes
    that also run during scans). The enhanced-testing entries are only
    included when a `*.manifest.json` is present next to the probe;
    older probes that don't ship one remain undiscoverable here, which
    is intentional — without a manifest we don't know how to route to
    them anyway."""
    out: list[dict] = []
    seen_names: set[str] = set()
    for probes_dir in (PROBES_DIR, ENHANCED_PROBES_DIR):
        if not probes_dir.is_dir():
            continue
        for manifest_path in sorted(probes_dir.glob("*.manifest.json")):
            try:
                data = json.loads(manifest_path.read_text())
            except Exception:
                continue
            name = (data.get("name")
                    or manifest_path.stem.replace(".manifest", ""))
            # First-seen wins. The toolkit directory is iterated first,
            # so a probe of the same name in enhanced_testing is
            # ignored — keeps the routing deterministic when both
            # trees ship a probe with the same identifier.
            if name in seen_names:
                continue
            script = probes_dir / f"{name}.py"
            if not script.is_file():
                continue
            # Nudge probe authors away from the recurring over-claim
            # trap: if `validates` lists a top-level OWASP category,
            # that entry will be ignored at routing time anyway (see
            # _routing_cwes). Warn once per probe per process so the
            # message is visible but not spammy.
            owasp_entries = [v for v in (data.get("validates") or [])
                             if v and _OWASP_TOP_RE.match(v)]
            if owasp_entries and name not in _OWASP_WARNED:
                _OWASP_WARNED.add(name)
                logger.warning(
                    "probe manifest %r lists top-level OWASP category(ies) "
                    "%r in `validates`. These are ignored for routing — "
                    "they're catch-alls that match every finding of the "
                    "shape and produce false probe matches at scale. Use "
                    "specific CWE-* entries instead, or rely on "
                    "matches_titles for tier-1 routing.",
                    name, owasp_entries,
                )
            data["script_path"] = str(script)
            data["available"] = True
            data["origin"] = ("toolkit" if probes_dir == PROBES_DIR
                              else "enhanced_testing")
            seen_names.add(name)
            out.append(data)
    return out


def get_probe(name: str) -> Optional[dict]:
    if not PROBE_NAME_RE.match(name or ""):
        return None
    for p in list_probes():
        if p["name"] == name:
            return p
    return None


def find_probe_for_finding(finding: dict) -> Optional[dict]:
    """Return the most relevant probe for this finding, or None.

    Match precedence (highest first):
      1. The finding's title appears in the probe's `matches_titles` list
         (case-insensitive substring match — covers 'Htaccess Bypass' vs
         'htaccess bypass' vs 'weak restriction bypassable').
      2. The finding's source_tool is in `matches_tools` AND the finding's
         CWE is in the probe's `validates`. Top-level OWASP categories
         in `validates` are filtered out (see _routing_cwes) — they're
         catch-alls that produce false matches.
      3. The finding's CWE alone is in the probe's `validates`. Same
         OWASP filtering as tier 2.

    The first match wins. This lets the Challenge button surface a probe
    even when the manifest's title list doesn't enumerate every wording
    variant a scanner might emit. A finding whose source tool didn't set
    a CWE will not match tier 2 or 3 — that's intentional, the routing
    needs *some* specific signal beyond a top-level category."""
    title = (finding.get("title") or "").lower()
    tool = (finding.get("source_tool") or "").lower()
    cwe = ("CWE-" + finding["cwe"]) if finding.get("cwe") else ""

    probes = list_probes()

    # Tier 1 — explicit title match
    for p in probes:
        for t in (p.get("matches_titles") or []):
            if t and t.lower() in title:
                return p

    # Tier 2 — tool + specific CWE intersect. CWE only — top-level OWASP
    # entries in validates are filtered out by _routing_cwes because
    # they match every parser-default-tagged finding of that shape.
    if cwe:
        for p in probes:
            tools = [s.lower() for s in (p.get("matches_tools") or [])]
            if tool in tools and cwe in _routing_cwes(p.get("validates")):
                return p

    # Tier 3 — CWE alone. Same OWASP filtering as tier 2.
    if cwe:
        for p in probes:
            if cwe in _routing_cwes(p.get("validates")):
                return p

    return None


def build_finding_config(finding: dict, probe: dict,
                         cookie: Optional[str] = None,
                         extra: Optional[dict] = None) -> dict:
    """Construct the probe-config dict for one finding.

    Single source of truth shared between the per-finding /challenge web
    route (server.py) and the bulk-Challenge runner (scripts/
    challenge_runner.py). The two used to diverge — the bulk runner had
    a stripped-down config that omitted url-absolutization, raw_data
    pass-through, the destructive-method gate for `requires_post`
    probes, and `auth_username`. That made the bulk runner systematically
    fail probes that the manual click validated cleanly (notably
    auth_logout_does_not_invalidate, which needs both the destructive
    gate AND auth_username; and tools that emit path-only evidence_urls,
    which urlparse cannot resolve to a host).

    Centralizing the setup here means a probe's contract is satisfied
    identically by both paths, and a future probe that adds a new
    config key only needs to register it here once.

    The function does NOT run anything — it returns a dict suitable for
    `run_probe(probe['name'], config)`. Callers are responsible for
    timeout selection and verdict-to-status mapping.
    """
    import db                 # late import — toolkit is imported very early
    from urllib.parse import urlparse

    url = finding.get("evidence_url") or ""
    # Some scanners (wapiti, the older nikto formatters) emit evidence
    # URLs as paths only — `/login.php`, `/api/auth`. urllib refuses to
    # send a request without a scheme/host, so the probe would error
    # before its first request. Resolve via the owning assessment's
    # FQDN + scheme. Prefer https when both schemes were scanned;
    # fall back to http only when that's the sole scheme tested.
    if url.startswith("/"):
        aid = finding.get("assessment_id")
        if aid:
            a = db.query_one("SELECT fqdn, scan_http, scan_https "
                             "FROM assessments WHERE id = %s", (aid,))
            if a and a.get("fqdn"):
                scheme = "https" if a.get("scan_https") else (
                    "http" if a.get("scan_http") else "https")
                url = f"{scheme}://{a['fqdn']}{url}"
    parsed = urlparse(url)
    # Lock the probe to the host of the finding so it cannot wander to
    # other assets even if the probe naively follows redirects.
    scope = [parsed.hostname] if parsed.hostname else []

    config: dict = {
        "url": url,
        "method": (finding.get("evidence_method") or "GET").upper(),
        "scope": scope,
        "max_requests": int(probe.get("request_budget_max") or 30),
        "max_rps": 5.0,
        "dry_run": False,
        # Carry source-tool-specific context so probes that need it
        # (testssl test id, nuclei matcher name, wapiti vulnerable
        # parameter, etc.) can extract it from raw_data without the
        # analyst typing it. Probes that don't know about these keys
        # silently absorb them via Probe._config_from_stdin's unknown-
        # key path.
        "title": finding.get("title") or "",
        "raw_data": finding.get("raw_data") or "",
    }

    # Probes whose manifest declares requires_post need the SafeClient
    # destructive-method gate opened. The gate is keyed off the
    # MANIFEST, never the caller, so a forged finding row cannot trick
    # a read-only probe into mutating state.
    if probe.get("requires_post"):
        config["allow_destructive"] = True

    if cookie:
        config["cookie"] = cookie     # consumed by SafeClient via Probe._build_client

    # Pass the assessment's username (NOT password) so identity-aware
    # probes (auth_logout_does_not_invalidate, admin_exposure, etc.)
    # can detect when the username is reflected in a response or use
    # it to construct a follow-up request. Probes hash it before
    # storing in evidence so the credential never lands in the
    # persisted verdict in clear text.
    aid = finding.get("assessment_id")
    if aid:
        a = db.query_one(
            "SELECT creds_username FROM assessments WHERE id = %s", (aid,))
        if a and (a.get("creds_username") or "").strip():
            config["auth_username"] = a["creds_username"].strip()

    if extra:
        config.update(extra)
    return config


def probe_timeout(probe: dict) -> float:
    """Per-probe timeout: typical budget × 2 seconds, clamped 30..120s.

    Centralized so per-finding and bulk paths agree. Any probe whose
    manifest understates `request_budget_typical` will hit the floor;
    any one that overstates it will hit the ceiling. 120s is the upper
    bound because a stuck request can otherwise hang the web request
    or stall the bulk runner mid-batch."""
    typical = int(probe.get("request_budget_typical") or 12)
    return min(120.0, max(30.0, typical * 2.0))


def verdict_to_status(verdict: dict) -> str:
    """Map a probe verdict dict to the `findings.validation_status`
    enum. Single source of truth, replacing the duplicated copy that
    used to live in scripts/challenge_runner.py.

    Distinguishes a real crash (`error` field set — subprocess died,
    safety violation, malformed output) from a soft refusal (probe ran
    cleanly but declined to produce a verdict — `ok=False` with no
    `error`). The earlier behavior collapsed both into `errored`,
    which (a) painted a red badge on a perfectly clean run and (b)
    froze the finding out of subsequent bulk passes. Soft refusals
    are now `inconclusive`; only hard crashes are `errored`.

    Confidence thresholds (Round-9 fidelity hardening):
      - `validated=True`  : require confidence >= 0.7. Below the
        floor, a True verdict is too weak to stamp a green
        'validated' badge on the finding -- fall through to
        'inconclusive' so the analyst (or a tighter probe) can
        decide. Without this floor, a probe that returned
        `validated=True, confidence=0.2` silently validated the
        finding -- the reason a 0.2-confidence finding was visible
        in the UI before this fix landed.
      - `validated=False` : require confidence >= 0.8 to bucket as
        false_positive. Below the floor, treat as inconclusive
        (the probe ran but couldn't refute decisively).
    The two thresholds intentionally differ -- a confident refutation
    is harder evidentially than a confident confirmation, since the
    probe has to prove the absence of every plausible exploit shape;
    asymmetric thresholds reflect that reality."""
    if verdict.get("error"):
        return "errored"
    if not verdict.get("ok", True):
        return "inconclusive"
    v = verdict.get("validated")
    if v is True:
        # Floor on the True branch: a probe that returned True with
        # confidence < 0.7 is too tentative to validate the finding.
        # Treat as inconclusive so the analyst sees the soft verdict
        # rather than a green badge it didn't earn.
        if (verdict.get("confidence") or 0) >= 0.7:
            return "validated"
        return "inconclusive"
    if v is False:
        if (verdict.get("confidence") or 0) >= 0.8:
            return "false_positive"
        return "inconclusive"
    return "inconclusive"


def run_probe(name: str, config: dict, *,
              timeout: float = 60.0) -> dict:
    """Run a probe synchronously, feeding `config` as JSON on stdin and
    parsing its JSON verdict from stdout. Always returns a dict — wraps
    any subprocess error so the caller doesn't need to."""
    p = get_probe(name)
    if not p:
        return {"ok": False, "error": f"unknown probe {name!r}"}
    script = p["script_path"]
    try:
        proc = subprocess.run(
            [sys.executable, script, "--stdin"],
            input=json.dumps(config).encode(),
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "probe timed out"}
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    try:
        result = json.loads(out)
    except Exception:
        return {"ok": False, "error": "probe output was not JSON",
                "stdout": out[:2000], "stderr": err[:2000],
                "exit_code": proc.returncode}
    result["_exit_code"] = proc.returncode
    if err:
        result["_stderr"] = err[:2000]
    return result
