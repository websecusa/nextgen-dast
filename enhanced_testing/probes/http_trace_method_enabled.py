#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
HTTP TRACE method enabled.

The TRACE method echoes the entire request -- headers, body --
back to the client. In legacy browsers and some intermediaries
this enables Cross-Site Tracing (XST): an attacker page makes
the victim issue a TRACE; the response body contains the victim's
Cookie header, which JS can then read despite the cookie being
HttpOnly.

Even where modern browsers block XST, TRACE on production has no
upside and routinely reveals reverse-proxy header rewrites
(`Authorization` re-injected, `X-Forwarded-For` set, etc.) that
help an attacker map the deployment.

Detection signal: send TRACE with a custom marker header;
validate when the response body echoes the marker.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


class HttpTraceMethodEnabledProbe(Probe):
    name = "http_trace_method_enabled"
    summary = ("Detects HTTP TRACE enabled by sending a marker "
               "header and checking whether the response echoes it "
               "in the body.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        marker_name  = f"X-Dast-Trace-{secrets.token_hex(4)}"
        marker_value = f"dast-trace-{secrets.token_hex(8)}"

        # Try TRACE on /, then on /api/ in case / 405s.
        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in ("/", "/api/", "/api/v1/"):
            url = urljoin(origin, p)
            r = client.request("TRACE", url, headers={
                marker_name: marker_value})
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                if marker_value in text:
                    row["echoed"] = True
                    row["snippet"] = text[:200]
                    confirmed = row
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "marker_name": marker_name,
                    "marker_value": marker_value,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: HTTP TRACE enabled at "
                    f"{origin}{confirmed['path']}. The response body "
                    "echoes the marker request header -- standard "
                    "XST primitive plus reverse-proxy header-rewrite "
                    "leak."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Refuse TRACE at the web server / edge:\n"
                    "  - Apache: `TraceEnable Off` in the global "
                    "  config.\n"
                    "  - nginx: refuse non-canonical methods at the "
                    "  reverse proxy: `if ($request_method !~ "
                    "  ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) "
                    "  { return 405; }`.\n"
                    "  - IIS: in web.config, "
                    "  `<system.webServer>"
                    "  <security><requestFiltering>"
                    "  <verbs allowUnlisted=\"false\">"
                    "  <add verb=\"GET\" allowed=\"true\"/>"
                    "  ...</verbs></requestFiltering></security>"
                    "  </system.webServer>`.\n"
                    "  - Cloudflare / AWS WAF: add a managed rule "
                    "  to refuse TRACE."),
            )
        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: TRACE on {origin} did not echo the "
                     "marker header in any response body."),
            evidence=evidence,
        )


if __name__ == "__main__":
    HttpTraceMethodEnabledProbe().main()
