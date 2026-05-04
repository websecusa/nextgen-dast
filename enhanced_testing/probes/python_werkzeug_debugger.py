#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Flask / Werkzeug: interactive debugger reachable on production.

`app.run(debug=True)` (or any framework that wraps Werkzeug's
`DebuggedApplication`) leaves an interactive in-browser debugger
at `/console` (or `/debug`, `/__debug__/`). The debugger lets a
caller execute arbitrary Python in the running process -- once
you guess the PIN. Recent Werkzeug versions print the PIN to
stdout; on prod that ends up in logs, captured by anyone with log
access.

Detection signal: GET candidate paths; validate when the body
contains `Werkzeug Debugger` or the inline title
`Console // Werkzeug Debugger`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = ("/console", "/debug", "/__debug__/", "/_werkzeug/",
         "/dev/console")

_SIGS = (
    re.compile(r"<title>\s*Console // Werkzeug Debugger\s*</title>",
               re.I),
    re.compile(r"\bWerkzeug Debugger\s*</a>"),
    re.compile(r"//#\s*werkzeug-debugger"),
)


class PythonWerkzeugDebuggerProbe(Probe):
    name = "python_werkzeug_debugger"
    summary = ("Detects the Werkzeug interactive debugger reachable "
               "on production -- arbitrary-Python primitive on PIN "
               "guess.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional debugger path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                for sig in _SIGS:
                    if sig.search(text):
                        row.update({"matched": sig.pattern,
                                    "snippet": text[:200]})
                        confirmed = row
                        break
                if confirmed:
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: Werkzeug debugger reachable at "
                    f"{origin}{confirmed['path']}. Anyone who can "
                    "guess the PIN runs arbitrary Python inside the "
                    "Flask process; the PIN is generated from "
                    "semi-public machine details, so guessability is "
                    "high."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop running Flask in debug mode in production.\n"
                    "  - app.py: `app.run()` (drop the debug=True).\n"
                    "  - Production should run via gunicorn / uWSGI / "
                    "  Hypercorn, NOT `flask run` / `python app.py`.\n"
                    "  - Set `FLASK_ENV=production` and "
                    "  `FLASK_DEBUG=0`. Disable the debugger "
                    "  explicitly: `WERKZEUG_DEBUG_PIN=off` is NOT "
                    "  enough; the right answer is to never start "
                    "  Werkzeug's debugger middleware on prod.\n"
                    "Audit logs for /console requests during the "
                    "exposure window -- the PIN-guess endpoint is "
                    "/console with the same path, so brute-force "
                    "attempts are visible."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} debugger "
                     f"paths on {origin}; none returned the "
                     "Werkzeug signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PythonWerkzeugDebuggerProbe().main()
