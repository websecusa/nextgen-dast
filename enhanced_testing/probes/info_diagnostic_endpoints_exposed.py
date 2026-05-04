#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: framework / server diagnostic endpoints
left exposed.

  - ASP.NET `/trace.axd` and `/elmah.axd` log every recent request
    including headers, cookies, and form bodies (so: every active
    session token).
  - Spring Boot Actuator `/actuator/env` returns every environment
    variable; `/actuator/heapdump` returns the entire JVM heap (every
    request body, every secret, every connection-string in flight).
  - Apache `/server-status` lists every active request URL +
    client IP; `/server-info` enumerates every loaded module.
  - PHP `/cgi-bin/printenv` dumps env vars.
  - Tomcat `/manager/html` is the GUI for deploying WAR files (RCE
    if creds are guessed).

Different from `info_metrics_exposed` (Prometheus only). This probe
sweeps the framework-specific diagnostic surface and pattern-matches
each path against a content-specific signature so we don't false-
positive on a generic 200.

Detection signal:
  GET each path. Validate when the status is 200 AND the body
  matches the per-endpoint signature.

Tested against:
  + OWASP Juice Shop  Express app, none of these endpoints exist
                      -> validated=False.
  + Apps with leftover Actuator / IIS / Tomcat consoles
    -> validated=True.

Read-only: GET only. We never trigger the actuator's heapdump
download (that would be destructive load on the JVM); only its
list endpoint is probed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

TARGETS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("/trace.axd",
     re.compile(r"<title>\s*ASP\.NET Tracing", re.I),
     "ASP.NET trace.axd"),
    ("/elmah.axd",
     re.compile(r"<title>\s*Error Log\s*for", re.I),
     "ELMAH error log"),
    ("/server-status",
     re.compile(r"<title>\s*Apache Status|Apache Server Status",
                re.I),
     "Apache mod_status"),
    ("/server-info",
     re.compile(r"<title>\s*Apache Server Information|Server Settings",
                re.I),
     "Apache mod_info"),
    ("/server-status?auto",
     re.compile(r"^Total Accesses:\s*\d+", re.MULTILINE),
     "Apache mod_status (auto)"),
    ("/actuator",
     re.compile(r'"_links"\s*:\s*\{'),
     "Spring Actuator index"),
    ("/actuator/env",
     re.compile(r'"activeProfiles"|"propertySources"\s*:'),
     "Spring Actuator env"),
    ("/actuator/health",
     re.compile(r'"status"\s*:\s*"(?:UP|DOWN|UNKNOWN)"'),
     "Spring Actuator health"),
    ("/actuator/mappings",
     re.compile(r'"contexts"\s*:\s*\{|"mappings"\s*:'),
     "Spring Actuator mappings"),
    ("/actuator/configprops",
     re.compile(r'"contexts"|"prefix"\s*:'),
     "Spring Actuator configprops"),
    ("/actuator/loggers",
     re.compile(r'"levels"\s*:\s*\['),
     "Spring Actuator loggers"),
    ("/cgi-bin/printenv",
     re.compile(r"^(?:HTTP_HOST|SERVER_NAME)=.*$", re.MULTILINE),
     "cgi-bin/printenv"),
    ("/jolokia/list",
     re.compile(r'"value"\s*:\s*\{|"timestamp"\s*:\s*\d+'),
     "Jolokia JMX list"),
    ("/manager/html",
     re.compile(r"<title>\s*/manager|Tomcat Web Application Manager",
                re.I),
     "Tomcat Manager"),
    ("/host-manager/html",
     re.compile(r"<title>\s*/host-manager|Tomcat Virtual Host Manager",
                re.I),
     "Tomcat Host Manager"),
    ("/console",
     re.compile(r"<title>\s*WebLogic|HAL Management Console", re.I),
     "WebLogic / HAL console"),
    ("/jmx-console",
     re.compile(r"<title>\s*JBoss JMX|JMX Agent View", re.I),
     "JBoss JMX console"),
    ("/_profiler",
     re.compile(r"<title>\s*Symfony Profiler|Profiler\b", re.I),
     "Symfony profiler"),
    ("/debug/vars",
     re.compile(r'^"cmdline"\s*:|^\s*\{\s*"cmdline"\s*:', re.MULTILINE),
     "Go expvar"),
    ("/debug/pprof/",
     re.compile(r"<title>\s*/debug/pprof|profiles:", re.I),
     "Go pprof index"),
)


class InfoDiagnosticEndpointsExposedProbe(Probe):
    name = "info_diagnostic_endpoints_exposed"
    summary = ("Detects framework / server diagnostic endpoints "
               "(trace.axd, elmah.axd, actuator, server-status, "
               "Tomcat manager, etc.) left exposed.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--max-paths", type=int, default=20,
            help="Cap on number of paths tested (default 20).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        cap = max(1, int(args.max_paths or 20))
        for (p, pat, label) in TARGETS[:cap]:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size,
                         "label": label}
            if r.status == 200 and r.body and pat.search(r.text or ""):
                row["signature_match"] = True
                row["snippet"] = (r.text or "")[:200]
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
                    f"Confirmed: diagnostic endpoint exposed at "
                    f"{origin}{top['path']} ({top['label']}). The "
                    "response body matches the endpoint's structural "
                    "signature -- diagnostic data, request headers, "
                    "or environment values are reachable to anonymous "
                    "callers."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable the endpoint in production, or move it "
                    "behind auth + a non-routable network.\n"
                    "  - ASP.NET: `<trace enabled=\"false\"/>` in "
                    "web.config; remove ELMAH or restrict via "
                    "`<location path=\"elmah.axd\">` "
                    "`<allow roles=\"Admin\"/>`.\n"
                    "  - Spring Boot: set "
                    "`management.endpoints.web.exposure.include=health` "
                    "(only the health endpoint stays public). Bind the "
                    "management server to a separate port behind a "
                    "private network with `management.server.port=...`.\n"
                    "  - Apache: comment out `mod_status`/`mod_info` "
                    "from httpd.conf, or restrict via "
                    "`<Location \"/server-status\"> Require ip 127`.\n"
                    "  - Tomcat: remove the manager / host-manager "
                    "webapps from `webapps/`; if needed, restrict via "
                    "`<Valve className=\"...RemoteAddrValve\" "
                    "allow=\"127\\.0\\.0\\.\\d+\"/>`.\n"
                    "Audit the leaked content for active session "
                    "tokens, secrets, or DB strings -- anything "
                    "captured may have been exfiltrated."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} diagnostic "
                     f"endpoint paths on {origin}; none returned "
                     "content matching its structural signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoDiagnosticEndpointsExposedProbe().main()
