#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: admin / application configuration endpoint
reachable without authentication.

Apps that ship a "site-wide configuration" view (theme, branding,
OAuth client IDs, feature flags, etc.) routinely forget to gate the
endpoint behind an admin role. The result: an unauthenticated GET
returns operational metadata that helps an attacker map the
application -- OAuth client IDs, internal hostnames, feature toggle
state, third-party integration keys.

This probe walks a small catalog of conventional admin-configuration
paths and emits a finding when an unauthenticated GET returns a JSON
body shaped like a configuration document (top-level `config` /
`application` / `server` keys, or several admin-flavoured field names
nested inside).

Tested against:
  + OWASP Juice Shop  /rest/admin/application-configuration  ->
                      200 OK with a `config` object containing
                      `server`, `application`, `googleOauth`, etc.
  + nginx default site                                         ->
                      Refuted (every candidate path returns 404).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

CANDIDATE_PATHS = (
    # Juice Shop literal.
    "/rest/admin/application-configuration",
    "/rest/admin/configuration",
    # Generic admin / app-config conventions.
    "/api/admin/configuration",
    "/api/admin/config",
    "/api/config",
    "/api/configuration",
    "/api/application/configuration",
    "/api/site/configuration",
    "/api/settings",
    "/api/v1/admin/config",
    "/admin/api/configuration",
    "/internal/configuration",
    "/management/configuration",
)

# Field-name tokens that strongly suggest a configuration document.
# Match on a small set so a random JSON endpoint returning {"status":"ok"}
# doesn't false-positive. We need >= 3 distinct hits across the body to
# call it configuration-shaped.
CONFIG_TOKENS = (
    "config", "application", "server", "googleOauth", "google_oauth",
    "oauth", "frontend", "challenges", "branding", "logo",
    "domain", "smtp", "features", "featureFlag", "tracker",
    "defaultLanguage", "showVersionNumber", "altcoinName",
    "registrationRequiresCaptcha", "loginButtons", "metricsUrl",
    "ctf", "showGitHubLinks",
)


def _looks_like_config(text: str) -> tuple[bool, list[str]]:
    """True iff the response body looks like a configuration document.
    Returns (verdict, list_of_matched_tokens). Decision is based on
    distinct CONFIG_TOKENS hits + a top-level shape check."""
    if not text:
        return False, []
    matched = sorted({tok for tok in CONFIG_TOKENS
                      if re.search(rf'"{re.escape(tok)}"\s*:', text)})
    # Top-level shape: response is a JSON object with a `config`,
    # `application`, or `server` key at the root. Catches the
    # Juice Shop literal envelope {"config": {...}}.
    top_level = False
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        keys = set(doc.keys())
        if keys & {"config", "application", "server",
                    "configuration", "settings"}:
            top_level = True
    return (top_level or len(matched) >= 3), matched


class InfoAdminConfigExposedProbe(Probe):
    name = "info_admin_config_exposed"
    summary = ("Detects unauthenticated access to an admin / application "
               "configuration endpoint that should be gated behind a "
               "privileged role.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional candidate config endpoint path "
                 "(repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(CANDIDATE_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            # Send NO Authorization header. Confirming the unauth gate
            # is missing requires no token. If the server returns 401/
            # 403 the gate works -- log and move on.
            row = {"path": p, "url": url,
                   "status": r.status, "size": r.size}
            if r.status != 200 or not r.body:
                attempts.append(row)
                continue
            shaped, matched = _looks_like_config(r.text or "")
            row["config_tokens"] = matched
            row["body_excerpt"] = (r.text or "")[:400]
            if shaped:
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: admin / application configuration "
                    f"endpoint reachable without authentication on "
                    f"{confirmed['url']} -- response is shaped like a "
                    f"configuration document (tokens: "
                    f"{', '.join(confirmed.get('config_tokens') or []) or 'top-level config envelope'})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Gate every /admin/* (and /api/admin/*) route on "
                    "an authenticated session with an explicit admin "
                    "role. Server-side: reject unauthenticated requests "
                    "with 401 BEFORE serializing the configuration "
                    "object. Audit downstream code paths that consume "
                    "this endpoint's response so removing it does not "
                    "break the frontend -- typically the frontend should "
                    "fetch only the public subset of config from a "
                    "separate /public-config endpoint, and admin-only "
                    "fields (OAuth client IDs, integration keys, "
                    "feature-flag matrix) should never be in the public "
                    "subset."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} admin-configuration "
                     f"paths on {origin}; none returned a configuration-"
                     "shaped JSON body without authentication."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoAdminConfigExposedProbe().main()
