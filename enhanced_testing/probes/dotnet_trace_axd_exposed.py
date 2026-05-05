#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
ASP.NET: trace.axd diagnostic handler exposed.

When `<trace enabled="true" />` is set in web.config, ASP.NET's
`/trace.axd` handler captures a recent request log: timestamp, URL,
status code, headers, cookies, ViewState, form fields, and session
state for each request. The default `localOnly="true"` keeps it
limited to the loopback interface, but plenty of deployments either
flipped that to false to debug a remote issue or never set it at
all.

When publicly reachable, this is a near-equivalent to ELMAH in
sensitivity: every recent session cookie is in the dump, plus a full
view of internal request flow.

A neighboring probe (`info_diagnostic_endpoints_exposed`) is the
generic sweep; this one is the focused, high-fidelity trace.axd-only
probe that produces a sharper finding when trace.axd is the actual
hit.

Detection signal:
  GET `/trace.axd` (and a few near-variants); validate when
  status==200 AND body matches the ASP.NET-trace HTML signature
  ("ASP.NET Tracing", "Application Trace", or table headers
  unique to trace.axd output).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/trace.axd",
    "/Trace.axd",
    "/admin/trace.axd",
)

# Strict structural signatures. trace.axd output always has these
# specific phrases / table headers in the rendered HTML.
TRACE_SIGS = (
    re.compile(r"<title>\s*ASP\.NET Tracing\s*</title>", re.I),
    re.compile(r"<h1[^>]*>\s*Application Trace\s*</h1>", re.I),
    re.compile(r"<h2[^>]*>\s*Requests to this Application", re.I),
    re.compile(r"\[\s*clear current trace\s*\]", re.I),
)


class DotnetTraceAxdExposedProbe(Probe):
    name = "dotnet_trace_axd_exposed"
    summary = ("Detects ASP.NET trace.axd publicly accessible -- "
               "recent-request log leaks session state.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in PATHS:
            r = client.request("GET", urljoin(origin, p),
                               follow_redirects=True)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                for sig in TRACE_SIGS:
                    if sig.search(text):
                        row["matched_signature"] = sig.pattern
                        row["snippet"] = text[:200]
                        confirmed = row
                        break
                if confirmed:
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.96,
                summary=(
                    f"Confirmed: ASP.NET trace.axd exposed at "
                    f"{origin}{confirmed['path']}. The trace log "
                    "lists every recent request with its full "
                    "header / cookie / form-data set -- session "
                    "tokens are included in the cookie dump for "
                    "any captured request."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable tracing in production:\n"
                    "  ```xml\n"
                    "  <system.web>\n"
                    "    <trace enabled=\"false\" "
                    "localOnly=\"true\" />\n"
                    "  </system.web>\n"
                    "  ```\n"
                    "If you need traces for a specific debug session, "
                    "scope the trace handler behind authentication:\n"
                    "  ```xml\n"
                    "  <location path=\"trace.axd\">\n"
                    "    <system.web>\n"
                    "      <authorization>\n"
                    "        <allow roles=\"Admin\" />\n"
                    "        <deny users=\"*\" />\n"
                    "      </authorization>\n"
                    "    </system.web>\n"
                    "  </location>\n"
                    "  ```\n"
                    "Treat all session cookies that appear in the "
                    "current trace as compromised; rotate them."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} trace.axd "
                     f"path(s) on {origin}; none returned the "
                     "ASP.NET-trace HTML signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DotnetTraceAxdExposedProbe().main()
