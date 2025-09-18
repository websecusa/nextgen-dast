#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: 2FA-status endpoint reachable without authentication.

`GET /rest/2fa/status` should require a session — its response leaks
whether 2FA is set up for a user, which feeds account-enumeration
and targeted-phishing campaigns. The endpoint should respond 401
when called with no Authorization header.

Detection signal:
  Unauthenticated GET /rest/2fa/status returns HTTP 200 with a JSON
  envelope (a `setup` boolean is the canonical Juice Shop shape).
  401/403 means correctly gated; 200 with a non-JSON body means we
  hit something that isn't the 2FA endpoint and bail.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEFAULT_PATHS = (
    "/rest/2fa/status",
    "/api/2fa/status",
    "/api/two-factor/status",
)


class Tfa2faStatusProbe(Probe):
    name = "auth_2fa_status_unauthenticated"
    summary = ("Detects /rest/2fa/status reachable without "
               "authentication.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional 2FA status path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(DEFAULT_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size,
                         "body_excerpt": (r.text or "")[:200]}
            if r.status == 200 and r.body:
                # Sanity: ensure the response actually looks like a 2FA
                # status payload (a JSON envelope with a status / setup
                # field). A 200 returning HTML means we hit the wrong
                # route — back off.
                try:
                    doc = json.loads(r.text)
                    if isinstance(doc, dict) and (
                        "setup" in doc or "enabled" in doc
                        or "status" in doc or "twoFactor" in doc
                        or "verified" in doc):
                        row["unauth_leak"] = True
                        confirmed = row
                        attempts.append(row)
                        break
                except json.JSONDecodeError:
                    pass
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: 2FA status endpoint at "
                         f"{origin}{confirmed['path']} responded 200 "
                         "to an unauthenticated request — 2FA presence "
                         "leak feeds account-enumeration."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Gate /rest/2fa/status on an authenticated session. "
                    "Return 401 — not 200 with `setup: false` — when "
                    "no JWT is supplied."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} 2FA status "
                     f"paths on {origin}; none responded 200 to an "
                     "unauthenticated request."),
            evidence=evidence,
        )


if __name__ == "__main__":
    Tfa2faStatusProbe().main()
