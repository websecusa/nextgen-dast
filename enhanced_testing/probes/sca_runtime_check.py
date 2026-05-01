#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Premium-tier SCA gap-fill probe.

The standard SCA stage (scripts/sca_runner.py) already runs retire.js
against discovered scripts and OSV-Scanner against any exposed
manifest. This probe adds three things on top:

  1. **Versioned-URL fingerprinting** — extracts library + version from
     URLs like /static/jquery-3.4.1.min.js, /node_modules/lodash/4.17.20/
     even when retire.js's body fingerprint missed (e.g. concatenated
     bundle, inlined module).
  2. **Per-package LLM lookup** — for every fingerprinted package, calls
     app/sca.lookup_or_augment(), which short-circuits on cache and only
     hits the LLM for packages with no existing record.
  3. **Verdict aggregation** — reports the highest-severity match found
     so the orchestrator can severity-bump the corresponding
     finding.

Runs only in the `premium` profile via the enhanced_testing pass —
basic and standard tiers get the same SCA findings without the LLM-
augmented gap-fill, which is the cost-bounded behavior we want.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Make app/ importable so we can call sca.lookup_or_augment() and reuse
# the running app's LLM endpoint resolution.
sys.path.insert(0, "/app")
try:
    import sca as sca_mod                    # noqa: E402
    import db as _db                         # noqa: E402
except Exception:
    sca_mod = None  # type: ignore[assignment]
    _db = None      # type: ignore[assignment]


# Match patterns of the form <name>-<version>(.min)?.js anywhere in a URL.
# Version regex deliberately tolerates pre-release suffixes (1.2.3-rc1).
_VERSIONED_URL_RE = re.compile(
    r"/(?P<name>[a-zA-Z][a-zA-Z0-9_.\-]*?)[-_/](?P<ver>\d+(?:\.\d+){1,3}"
    r"(?:[-+][A-Za-z0-9.]+)?)(?:[._-][a-zA-Z0-9]+)?\.js\b"
)
# Also catch /jquery/3.4.1/jquery.min.js (CDN-style path layout).
_CDN_PATH_RE = re.compile(
    r"/(?P<name>[a-zA-Z][a-zA-Z0-9_.\-]+)/(?P<ver>\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?)/[^/]*\.js\b"
)
# <script src> + <link href> harvesters
_SCRIPT_SRC_RE = re.compile(
    r"""<\s*(?:script|link)[^>]*?(?:src|href)\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _llm_endpoint() -> dict | None:
    """Reuse the same endpoint-resolution logic as the orchestrator.
    Falls back to the default endpoint if the assessment didn't pin one."""
    if _db is None:
        return None
    try:
        return _db.query_one("SELECT * FROM llm_endpoints "
                             "WHERE is_default=1 LIMIT 1")
    except Exception:
        return None


class SCARuntimeCheckProbe(Probe):
    name = "sca_runtime_check"
    summary = ("Premium SCA gap-fill: fingerprint JS libraries from "
               "versioned URLs and ask the LLM cache about each.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument("--max-urls", type=int, default=40,
                            help="Cap how many script URLs to inspect")

    def run(self, args, client: SafeClient) -> Verdict:
        # Fetch the page through the SafeClient so the budget / scope
        # checks fire identically to every other probe.
        try:
            r = client.get(args.url)
        except Exception as e:
            return Verdict(ok=False, validated=None,
                           summary=f"failed to fetch {args.url}: {e}",
                           error=str(e))
        body_bytes = r.content if hasattr(r, "content") else (r.body or b"")
        if r.status_code >= 400 or not body_bytes:
            return Verdict(ok=False, validated=None,
                           summary=f"target returned HTTP {r.status_code}")
        body = body_bytes.decode("utf-8", "replace")

        # Collect every script-ish URL so the regex only has to scan
        # plausible candidates (instead of the whole HTML body).
        candidate_urls: list[str] = []
        for m in _SCRIPT_SRC_RE.finditer(body):
            ref = m.group(1).strip()
            if not ref or ref.startswith(("data:", "javascript:", "mailto:")):
                continue
            absolute = urljoin(args.url, ref)
            candidate_urls.append(absolute)
            if len(candidate_urls) >= int(args.max_urls):
                break

        # Fingerprint name+version from the URL pattern. The regex matches
        # are bounded; nothing here costs an HTTP request.
        observed: list[dict] = []
        seen_pkg: set[tuple[str, str]] = set()
        for u in candidate_urls:
            for rx in (_VERSIONED_URL_RE, _CDN_PATH_RE):
                m = rx.search(u)
                if not m:
                    continue
                name = m.group("name").lower().rstrip(".-_")
                version = m.group("ver")
                if not name or name in ("min", "bundle", "vendor"):
                    continue
                key = (name, version)
                if key in seen_pkg:
                    continue
                seen_pkg.add(key)
                observed.append({"name": name, "version": version,
                                 "source_url": u})

        if not observed:
            return Verdict(ok=True, validated=False, confidence=0.5,
                           summary="no versioned JS library URLs detected")

        if sca_mod is None:
            # Fingerprinting still produced useful evidence even without
            # the cache layer — surface it so the analyst sees something.
            return Verdict(
                ok=True, validated=None, confidence=0.6,
                summary=(f"fingerprinted {len(observed)} libraries but the "
                         "SCA cache module is unavailable"),
                evidence={"observed": observed})

        endpoint = _llm_endpoint()
        results: list[dict] = []
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        worst_sev = ""
        any_match = False
        for pkg in observed:
            try:
                vulns = sca_mod.lookup_or_augment(
                    "npm", pkg["name"], pkg["version"], endpoint=endpoint)
            except Exception as e:
                results.append({**pkg, "error": str(e)})
                continue
            results.append({**pkg, "vulns": vulns})
            for v in vulns:
                any_match = True
                sev = (v.get("severity") or "medium").lower()
                if sev_order.get(sev, 0) > sev_order.get(worst_sev, -1):
                    worst_sev = sev

        if not any_match:
            return Verdict(
                ok=True, validated=False, confidence=0.7,
                summary=(f"fingerprinted {len(observed)} libraries; "
                         "no cache or LLM hits"),
                evidence={"observed": results})
        return Verdict(
            ok=True, validated=True, confidence=0.85,
            summary=(f"{len([r for r in results if r.get('vulns')])} "
                     f"library/version pair(s) matched the SCA cache; "
                     f"worst severity {worst_sev}"),
            evidence={"observed": results, "checked_via": "sca.lookup_or_augment"},
            severity_uplift=worst_sev or "medium",
            remediation=(
                "Upgrade the listed libraries past the noted vulnerable "
                "ranges. Where upgrade is impossible, gate the file "
                "behind a CSP that blocks the affected sinks (e.g. "
                "disallow `unsafe-inline` and require SRI)."),
        )


if __name__ == "__main__":
    SCARuntimeCheckProbe().main()
