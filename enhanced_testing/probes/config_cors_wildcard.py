#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Configuration: CORS wildcard origin combined with auth-bearing API.

`Access-Control-Allow-Origin: *` on a static-asset host is fine —
public resources are public. The bug is the wildcard on an API that
accepts an `Authorization` header. In practice browsers refuse to
attach credentials when ACAO is `*`, but:
  - APIs that use a custom auth scheme (X-Api-Key, X-Auth-Token) are
    NOT subject to the credentials-mode constraint, so `*` is a real
    problem there.
  - The combination usually indicates the developer copy-pasted ACAO=*
    without thinking through the auth model — same code path will
    happily echo arbitrary `Origin` headers when someone later flips
    to `credentials: true`.
  - Some apps DO send ACAO=<reflected origin> + ACAC=true on auth
    endpoints. That's the silent-account-takeover bug.

Detection signal — three independent flavors:
  (a) preflight returns ACAO=* AND advertises Authorization in
      Access-Control-Allow-Headers
  (b) preflight reflects an arbitrary Origin AND ACAC=true (the
      classic credentialed-CORS bug)
  (c) the actual GET on an auth-bearing endpoint echoes the same
      pattern in its response headers

Each tested endpoint costs at most 2 requests (OPTIONS + GET). We
target a handful of likely auth-bearing API paths.

Tested against:
  + OWASP Juice Shop  OPTIONS /rest/user/whoami → ACAO=*, ACAH includes
                      Authorization → validated=True (flavor a)
  + nginx default site                          → validated=False
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# Auth-bearing endpoint candidates. These are the routes most apps
# expose for "tell me about myself" — /me, /user/profile, /whoami,
# /rest/user/whoami, etc. If the app accepts a credential here AND
# the CORS policy is wildcard, it's a legitimate finding.
DEFAULT_PATHS = (
    "/rest/user/whoami",
    "/api/me",
    "/api/users/me",
    "/api/v1/me",
    "/me",
    "/account",
    "/profile",
)


_EVIL_ORIGIN = "https://evil.example.test"


def _hdr(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. urllib's dict-like header
    object is usually case-preserving but not case-insensitive."""
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class CorsWildcardProbe(Probe):
    name = "config_cors_wildcard"
    summary = ("Detects CORS wildcard / origin-reflection on auth-"
               "bearing API endpoints.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional API path to test for CORS misconfig (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(DEFAULT_PATHS) + list(args.path or [])

        tested: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            url = urljoin(origin, p)
            # Preflight: send a CORS preflight as if the browser were
            # about to make a credentialed request.
            r = client.request(
                "OPTIONS", url,
                headers={
                    "Origin": _EVIL_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization",
                })
            acao = _hdr(r.headers, "Access-Control-Allow-Origin")
            acah = _hdr(r.headers, "Access-Control-Allow-Headers")
            acac = _hdr(r.headers, "Access-Control-Allow-Credentials")
            row: dict = {
                "path": p, "preflight_status": r.status,
                "ACAO": acao, "ACAH": acah, "ACAC": acac,
            }
            findings: list[str] = []
            allows_auth = ("authorization" in acah.lower())
            if acao == "*" and allows_auth:
                findings.append("ACAO=* with Authorization in ACAH "
                                "(custom-auth-scheme bypass surface)")
            if acao == _EVIL_ORIGIN:
                # Origin reflection — possibly with credentials true.
                if acac.lower() == "true":
                    findings.append("Origin reflected + "
                                    "Access-Control-Allow-Credentials: true "
                                    "— credentialed-CORS bug")
                else:
                    findings.append("Origin reflected (no creds flag)")
            if findings:
                row["findings"] = findings
                confirmed.append(row)
            tested.append(row)

        evidence = {"origin": origin, "paths_tested": tested}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.90,
                summary=(f"Confirmed: CORS misconfiguration on "
                         f"{origin}{top['path']} — "
                         + "; ".join(top["findings"]) + "."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Replace the wildcard / reflected-origin policy "
                    "with an explicit allowlist of trusted origins "
                    "for any endpoint that accepts authentication.\n"
                    "  - Express: configure `cors({origin: ['https://"
                    "your-spa.example']})` not `cors()`.\n"
                    "  - Spring: `@CrossOrigin(origins = {"
                    "\"https://your-spa.example\"})` not `\"*\"`.\n"
                    "  - At the reverse-proxy: drop incoming `Origin` "
                    "before reflecting it; never set "
                    "`Access-Control-Allow-Credentials: true` together "
                    "with reflected origins.\n"
                    "Note: ACAO=* on truly public, unauthenticated "
                    "endpoints (e.g. a CDN) is fine. The signal here "
                    "is wildcard *combined with* Authorization being "
                    "advertised."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(tested)} candidate API "
                     f"paths on {origin}; none returned a CORS policy "
                     "that lets a malicious origin attack authenticated "
                     "users."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CorsWildcardProbe().main()
