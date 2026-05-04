#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Django: DEBUG=True technical-error page reachable on production.

Django's DEBUG=True 404/500 page leaks an enormous amount of
internal state: every middleware, every URL pattern, every view,
every template path tried, the request `META` dict (which
includes session cookies, CSRF tokens, every header), and
sometimes the SECRET_KEY value (when displayed via the locals
table at the offending stack frame).

The page is recognisable by a single string the framework prints
near the bottom: `You're seeing this error because you have
DEBUG = True in your Django settings file. Change that to False,
and Django will display a standard 404 page.`

High-fidelity signal: GET a deliberately-non-existent path; if the
response body contains the DEBUG=True marker AND `Request Method:`
(part of the technical-debug formatting), validate.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEBUG_MARKER = ("You're seeing this error because you have "
                 "DEBUG = True")
ALT_MARKER   = "Request Method:"


class PythonDjangoDebugPageProbe(Probe):
    name = "python_django_debug_page"
    summary = ("Detects Django DEBUG=True technical-error pages "
               "reachable on production -- leaks internal state, "
               "request data, and sometimes SECRET_KEY.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # We need the response body to come from Django's debug
        # path, which fires on:
        #  - 404 from URL resolver
        #  - 500 from any exception in a view
        # Hitting a long random path triggers the 404 flow.
        bad_path = f"/dast-debug-{secrets.token_hex(6)}/"
        candidates = (
            bad_path,
            f"/admin/{secrets.token_hex(6)}/",
            f"/api/{secrets.token_hex(6)}/",
        )

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in candidates:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.body:
                text = r.text or ""
                if DEBUG_MARKER in text and ALT_MARKER in text:
                    row.update({"debug_page": True,
                                 "snippet": text[:300]})
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: Django DEBUG=True page on {origin}. "
                    f"Hitting {confirmed['path']} returned the "
                    "technical-error template, which leaks the URL "
                    "tree, middleware list, request META (including "
                    "auth tokens / cookies), and -- on a 500 -- the "
                    "stack-frame locals which routinely contain "
                    "SECRET_KEY and DB credentials."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Set DEBUG=False in production.\n"
                    "  - settings.py: `DEBUG = "
                    "  os.environ.get('DEBUG', '0') == '1'`\n"
                    "  - Ensure ALLOWED_HOSTS is set; Django refuses "
                    "  to serve when DEBUG=False without it -- the "
                    "  combination is a guard against the same class "
                    "  of mistake.\n"
                    "If SECRET_KEY appeared in any displayed "
                    "traceback (visible in the locals frame), rotate "
                    "it -- a leaked SECRET_KEY signs the session "
                    "cookies for an attacker."),
            )
        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: probed {len(attempts)} non-existent "
                     f"paths on {origin}; no Django DEBUG=True "
                     "technical-error template returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PythonDjangoDebugPageProbe().main()
