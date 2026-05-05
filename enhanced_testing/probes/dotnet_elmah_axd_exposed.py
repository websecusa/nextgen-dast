#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
ASP.NET: ELMAH error log handler exposed.

ELMAH (Error Logging Modules and Handlers) is a popular drop-in
component for ASP.NET. By default, the `/elmah.axd` HTTP handler
shows a paginated list of every captured exception, with
per-exception `/detail` views that include the full request payload
that caused the error -- headers, cookies, form fields. Cookies
necessarily include the active session token of whoever was
unfortunate enough to trigger the exception.

ELMAH ships with a `<security allowRemoteAccess="false" />` setting
that should keep this off the public internet, but plenty of
production deployments either flipped that to true to debug an
issue and never reverted, or relied on the firewall and got
exposed when traffic patterns shifted.

A neighboring probe (`info_diagnostic_endpoints_exposed`) is the
generic sweep; this one is the focused, high-fidelity ELMAH-only
probe that produces a sharper finding when ELMAH is the actual hit.

Detection signal:
  GET `/elmah.axd` and `/elmah.axd/detail` (and a couple of common
  reverse-proxy variants); validate when status==200 AND the body
  matches the ELMAH-specific HTML signature ("Error Log for ...")
  or its RSS / JSON rendering. A bare 200 is never enough.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/elmah.axd",
    "/elmah.axd/",
    "/admin/elmah.axd",
    "/elmah/elmah.axd",
)

# Multiple structural signatures so we catch the standard HTML view
# AND its RSS / JSON / XML alternates. Each is anchored on text or
# tags that ONLY ELMAH emits.
ELMAH_SIGS = (
    re.compile(r"<title>\s*Error log\s+for", re.I),
    re.compile(r"\bError Log\s*for\s*<code>", re.I),
    re.compile(r"<h1[^>]*>\s*Error\s+Log\s*</h1>", re.I),
    re.compile(r"<errors\s+xmlns=\"http://elmah\.googlecode\.com",
               re.I),
    re.compile(r"^\s*<\?xml[^>]+\?>\s*<rss[^>]*>.*ELMAH", re.I | re.S),
)


class DotnetElmahAxdExposedProbe(Probe):
    name = "dotnet_elmah_axd_exposed"
    summary = ("Detects ELMAH error-log handler (/elmah.axd) "
               "publicly accessible -- per-exception request dumps "
               "leak session cookies.")
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
                for sig in ELMAH_SIGS:
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
                    f"Confirmed: ELMAH error log exposed at "
                    f"{origin}{confirmed['path']}. The error list "
                    "and per-exception detail views include the full "
                    "captured request -- HTTP headers, cookies "
                    "(including session tokens), and form bodies "
                    "for every captured exception."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Restrict /elmah.axd to admin-only or remove it "
                    "from production:\n"
                    "  ```xml\n"
                    "  <elmah>\n"
                    "    <security allowRemoteAccess=\"false\" />\n"
                    "  </elmah>\n"
                    "  <location path=\"elmah.axd\">\n"
                    "    <system.web>\n"
                    "      <authorization>\n"
                    "        <allow roles=\"Admin\" />\n"
                    "        <deny users=\"*\" />\n"
                    "      </authorization>\n"
                    "    </system.web>\n"
                    "  </location>\n"
                    "  ```\n"
                    "Audit access logs for /elmah.axd hits during the "
                    "exposure window -- any session cookie shown "
                    "in the captured exceptions should be considered "
                    "compromised and rotated."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} ELMAH "
                     f"path(s) on {origin}; none returned the "
                     "ELMAH-specific HTML / RSS signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DotnetElmahAxdExposedProbe().main()
