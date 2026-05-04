#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
CORS: server reflects the request `Origin` back as
`Access-Control-Allow-Origin` AND sets
`Access-Control-Allow-Credentials: true`.

Different from `config_cors_wildcard` (looks for `*` + creds, which
is what most apps misconfigure). Reflected-origin-with-creds is
strictly worse than wildcard-no-creds: per CORS rules the wildcard
form prevents the browser from sending cookies, but a server that
echoes whatever Origin came in lets the attacker page (loaded by
the victim) make credentialled cross-origin requests with the
victim's session.

High-fidelity signal: send `Origin: http://dast-marker-XXXX.example`
to a candidate path; validate when `Access-Control-Allow-Origin`
exactly equals that random value AND `Access-Control-Allow-Credentials`
is `true`.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/", "/api/", "/api/v1/", "/api/me", "/api/users",
    "/oauth/token", "/api/auth/login", "/login",
    "/rest/user/whoami",
)


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v).strip()
    return ""


class CorsReflectedOriginWithCredsProbe(Probe):
    name = "cors_reflected_origin_with_creds"
    summary = ("Detects CORS that reflects the request Origin and "
               "sets Allow-Credentials -- credentialled cross-origin "
               "access from any attacker page.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attacker = (f"http://dast-cors-{secrets.token_hex(6)}."
                    f"example")

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, headers={
                "Origin": attacker})
            allow_origin = _hdr(r.headers, "access-control-allow-origin")
            allow_creds  = _hdr(r.headers,
                                 "access-control-allow-credentials")
            row: dict = {"path": p, "status": r.status,
                         "size": r.size,
                         "allow_origin": allow_origin or None,
                         "allow_creds": allow_creds or None}
            # Fire when Allow-Origin == the marker we sent AND
            # Allow-Credentials == true. Wildcard + creds is a
            # different bug (covered by config_cors_wildcard).
            if (allow_origin == attacker
                    and allow_creds.lower() == "true"):
                row["reflected"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attacker_origin": attacker,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: reflected-origin CORS at "
                    f"{origin}{confirmed['path']}. The server echoed "
                    f"`Access-Control-Allow-Origin: {attacker}` AND "
                    f"`Access-Control-Allow-Credentials: true`. Any "
                    "attacker page the victim visits can make "
                    "credentialled cross-origin requests as the "
                    "victim."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Replace the reflected-origin policy with a "
                    "static allowlist:\n"
                    "  - Express cors middleware: "
                    "  `cors({ origin: ['https://app.example'], "
                    "  credentials: true })`.\n"
                    "  - Spring: `@CrossOrigin(origins = "
                    "  {\"https://app.example\"}, allowCredentials = "
                    "  \"true\")`.\n"
                    "  - Django: `CORS_ALLOWED_ORIGINS = ['https://"
                    "  app.example']`; never `CORS_ALLOW_ALL_ORIGINS "
                    "  = True` together with `CORS_ALLOW_CREDENTIALS "
                    "  = True`.\n"
                    "If you need multi-origin, list the origins "
                    "explicitly. Reflecting the inbound Origin is "
                    "never the right answer."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} paths on "
                     f"{origin} with a marker Origin; no path "
                     "reflected it back with credentials enabled."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CorsReflectedOriginWithCredsProbe().main()
