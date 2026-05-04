#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Tomcat ships sample / docs / manager apps in `webapps/` by default.

Leaving `/docs/`, `/examples/`, `/manager/`, `/host-manager/` in
production has two effects: (a) it advertises the exact Tomcat
version (helping CVE-mapping) and (b) several of the example
servlets are documented attack surface for known issues
(`/examples/jsp/snp/snoop.jsp` reveals headers / cookies of any
caller).

Detection signal: GET each path; validate per-path on a Tomcat-
specific signature.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

TARGETS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("/docs/",
     re.compile(r"<title>\s*Apache Tomcat", re.I),
     "Tomcat docs webapp"),
    ("/examples/",
     re.compile(r"<title>\s*Apache Tomcat Examples", re.I),
     "Tomcat examples webapp"),
    ("/examples/jsp/",
     re.compile(r"<title>\s*JSP Samples", re.I),
     "Tomcat JSP samples"),
    ("/examples/servlets/",
     re.compile(r"<title>\s*Servlet Examples", re.I),
     "Tomcat servlet examples"),
    ("/examples/jsp/snp/snoop.jsp",
     re.compile(r"<title>\s*Snoop JSP|Request Information", re.I),
     "Tomcat snoop.jsp (request reflection)"),
    ("/manager/status/all",
     re.compile(r"Apache Tomcat/[0-9]+", re.I),
     "Tomcat manager status"),
    ("/host-manager/html",
     re.compile(r"<title>\s*/host-manager|Tomcat Virtual Host Manager",
                re.I),
     "Tomcat host-manager"),
)


class JavaTomcatExamplesLeftInProbe(Probe):
    name = "java_tomcat_examples_left_in"
    summary = ("Detects Tomcat default webapps (docs / examples / "
               "manager / host-manager / snoop.jsp) left in "
               "production.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for path, pat, label in TARGETS:
            r = client.request("GET", urljoin(origin, path),
                                follow_redirects=True)
            row: dict = {"path": path, "label": label,
                         "status": r.status, "size": r.size}
            if r.status == 200 and r.body and pat.search(r.text or ""):
                row["matched"] = True
                confirmed.append(row)
                attempts.append(row)
                if len(confirmed) >= 3:
                    break
                continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: Tomcat default webapp(s) reachable "
                    f"on {origin}. Top hit: {top['label']} at "
                    f"{top['path']}. {len(confirmed)} default "
                    "webapp(s) responded -- version fingerprint plus "
                    "known-vulnerable-by-default sample servlets are "
                    "exposed."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Remove the default webapps from `webapps/` in "
                    "production:\n"
                    "  rm -rf $CATALINA_HOME/webapps/{docs,examples,"
                    "manager,host-manager}\n"
                    "If you need /manager for ops use, restrict it "
                    "via `<Valve className=\"...RemoteAddrValve\" "
                    "allow=\"127\\.0\\.0\\.\\d+\"/>` in the manager's "
                    "context.xml so only localhost / management network "
                    "can reach it."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} Tomcat default "
                     f"paths on {origin}; none returned the Tomcat "
                     "signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JavaTomcatExamplesLeftInProbe().main()
