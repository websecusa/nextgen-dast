#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Configuration: HTTPS site missing `Strict-Transport-Security` header.

HSTS pins clients to HTTPS for the configured `max-age` window,
preventing SSL-strip downgrade attacks. An HTTPS site without an
HSTS header still accepts HTTP redirects to itself; a man-in-the-
middle can intercept the first http://-prefixed request and never
let the client upgrade.

Detection signal:
  GET / over HTTPS → no `Strict-Transport-Security` header in the
  response. We only run this probe if the target URL scheme is
  https — running it against an HTTP-only test target gives a
  meaningless "no HSTS" finding.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name_l:
            return v
    return ""


class HstsMissingProbe(Probe):
    name = "config_hsts_missing"
    summary = ("Detects missing Strict-Transport-Security header on "
               "HTTPS endpoints.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        if parsed.scheme != "https":
            return Verdict(
                validated=False, confidence=0.95,
                summary=(f"Skipped: target {args.url!r} is not HTTPS, "
                         "HSTS only applies to HTTPS responses."),
                evidence={"origin": f"{parsed.scheme}://{parsed.netloc}",
                          "scheme": parsed.scheme},
            )
        origin = f"{parsed.scheme}://{parsed.netloc}"
        r = client.request("GET", origin + "/")
        hsts = _hdr(r.headers, "Strict-Transport-Security")
        evidence = {"origin": origin, "status": r.status,
                    "hsts_header": hsts or None,
                    "header_keys_seen": list((r.headers or {}).keys())}
        if not hsts:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: {origin} returned no "
                         "Strict-Transport-Security header — clients "
                         "are unprotected against ssl-strip / "
                         "first-visit-via-http downgrade attacks."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Add `Strict-Transport-Security: max-age=63072000; "
                    "includeSubDomains; preload` (2 years) at the "
                    "reverse proxy or framework level. Submit the "
                    "domain to hstspreload.org once you're certain "
                    "every HTTPS-served subdomain handles the policy "
                    "correctly — that defends even the very first "
                    "visit."),
            )
        return Verdict(
            validated=False, confidence=0.95,
            summary=(f"Refuted: {origin} sends Strict-Transport-"
                     f"Security: {hsts!r}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    HstsMissingProbe().main()
