#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Jenkins Groovy script console reachable on the public origin.

`/script` (or its reverse-proxy variants) on a Jenkins instance is
the Groovy script console -- an arbitrary-Groovy-execution surface
running inside the Jenkins JVM. Reachable from a public origin
without auth = trivial RCE; behind weak auth = first-stop pivot
for any insider-threat scenario.

Detection signal: GET candidate paths; validate when the response
title or body matches Jenkins' script-console signature.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = ("/script", "/jenkins/script", "/manage/script",
         "/cgi-bin/jenkins/script")

_SIGS = (
    re.compile(r"<title>\s*Script Console", re.I),
    re.compile(r"Type in an arbitrary Groovy script", re.I),
    re.compile(r"groovy\.lang\.GroovyShell", re.I),
)


class JavaJenkinsScriptConsoleProbe(Probe):
    name = "java_jenkins_script_console"
    summary = ("Detects Jenkins Groovy script console reachable on "
               "the public origin -- arbitrary-code-execution "
               "primitive.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional script-console path to test.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p),
                                follow_redirects=True)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                for sig in _SIGS:
                    if sig.search(text):
                        row["matched"] = sig.pattern
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
                    f"Confirmed: Jenkins script console reachable at "
                    f"{origin}{confirmed['path']}. Anyone who can "
                    "load this URL (anonymously or after weak auth) "
                    "can run arbitrary Groovy inside the Jenkins JVM "
                    "-- complete server takeover, including read of "
                    "every credential Jenkins has stored."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop exposing /script to the public origin.\n"
                    "  - Move Jenkins behind a VPN or hardened SSO "
                    "with hardware MFA.\n"
                    "  - In Jenkins: Manage Jenkins > Configure "
                    "Global Security > require auth for "
                    "`hudson.model.Run.Update`, "
                    "`hudson.model.Computer.Configure`, "
                    "`hudson.model.RootAction`. Even logged-in users "
                    "should NOT have script-console access by "
                    "default.\n"
                    "  - At the edge proxy: outright block /script "
                    "and friends with a 403."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} script-console "
                     f"paths on {origin}; none matched the Jenkins "
                     "signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JavaJenkinsScriptConsoleProbe().main()
