#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: server / framework banner headers.

Defense-in-depth recommendation (every hardening guide -- Microsoft,
Apache, nginx, Spring, ASP.NET) is to suppress these headers in
production:

  - Server:               nginx/1.18.0, Apache/2.4.41, Microsoft-IIS/10.0
  - X-Powered-By:         PHP/7.4.3, Express, ASP.NET
  - X-AspNet-Version:     4.0.30319
  - X-AspNetMvc-Version:  5.2
  - X-Generator:          Drupal 8 (https://www.drupal.org)
  - Via:                  1.1 vegur (Heroku gateway etc.)

A leaked version string lets an attacker target known CVEs for that
exact build without needing to fingerprint. By itself it isn't a
vulnerability, but it lowers the cost of every later step.

Severity tiering:
  - High when a header reveals BOTH product AND specific version
    number (e.g., `nginx/1.18.0`, `PHP/7.4.3`).
  - Medium when a header reveals only the product name (e.g.,
    `Express`, `ASP.NET`) -- still narrows the attack surface.
  - Refuted when no notable banners present.

Detection signal:
  GET /. Inspect response headers; classify any matching header by
  whether the value carries an explicit version number.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Headers worth flagging. Order matters only for the summary string;
# each is evaluated independently.
BANNER_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "Via",
)

# Anchor on a slash + digit-dot-digit pattern. We deliberately don't
# match a bare digit ("Server: 1") so we don't false-positive on
# obscure header values that happen to contain numbers.
VERSION_RE = re.compile(r"[A-Za-z][A-Za-z0-9_+.-]*[/ ]\d+\.\d+(?:\.\d+)?")


def _hdr(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. urllib lowercases keys
    inconsistently, so do the comparison ourselves."""
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class InfoPoweredByBannerProbe(Probe):
    name = "info_powered_by_banner"
    summary = ("Detects server / framework version banners in "
               "response headers (Server, X-Powered-By, "
               "X-AspNet-Version, etc.).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", default="/",
            help="Path to GET (default '/'). Banners are normally "
                 "consistent across paths.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Two probes -- the root and a path that's likely to hit a
        # different handler (e.g., /favicon.ico). If both surface the
        # same headers we have higher confidence the banner is
        # globally configured rather than a one-off endpoint quirk.
        probe_paths = [args.path or "/", "/favicon.ico"]
        attempts: list[dict] = []
        all_banners: dict[str, str] = {}

        for p in probe_paths:
            r = client.request("GET", urljoin(origin, p))
            row = {"path": p, "status": r.status, "size": r.size,
                   "banners": {}}
            for h in BANNER_HEADERS:
                v = _hdr(r.headers, h)
                if v:
                    row["banners"][h] = v
                    # First-seen wins for the merged set.
                    all_banners.setdefault(h, v)
            attempts.append(row)

        # Classify what we found. A header is "version-bearing" iff
        # its value matches the strict product/version regex.
        version_bearing: list[tuple[str, str]] = []
        product_only: list[tuple[str, str]] = []
        for h, v in all_banners.items():
            if VERSION_RE.search(v):
                version_bearing.append((h, v))
            else:
                product_only.append((h, v))

        evidence = {"origin": origin, "attempts": attempts,
                    "banners_seen": all_banners,
                    "version_bearing": version_bearing,
                    "product_only": product_only}

        if version_bearing:
            top_h, top_v = version_bearing[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: server reveals product + version via "
                    f"`{top_h}: {top_v}`. {len(version_bearing)} "
                    "version-bearing banner(s) and "
                    f"{len(product_only)} product-only banner(s) "
                    "leak. Each tells an attacker exactly which CVE "
                    "list to consult next."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Suppress the headers at the edge / framework "
                    "level:\n"
                    "  - nginx: `server_tokens off;` and "
                    "`more_clear_headers Server X-Powered-By;` (with "
                    "the headers-more module).\n"
                    "  - Apache: `ServerTokens Prod` + `ServerSignature "
                    "Off` in httpd.conf.\n"
                    "  - IIS: remove `X-Powered-By` via "
                    "`<customHeaders><remove name=\"X-Powered-By\" />` "
                    "and use URL Rewrite to scrub `Server`.\n"
                    "  - ASP.NET: `<httpRuntime "
                    "enableVersionHeader=\"false\" />`.\n"
                    "  - Express: `app.disable('x-powered-by')` or "
                    "use `helmet`.\n"
                    "  - Spring Boot: `server.server-header=` (empty)."),
            )
        if product_only:
            top_h, top_v = product_only[0]
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: server reveals product name via "
                    f"`{top_h}: {top_v}`. No explicit version, but "
                    "the product identifier still narrows the attack "
                    "surface for an attacker."),
                evidence=evidence,
                severity_uplift="low",
                remediation=(
                    "Suppress `Server` / `X-Powered-By` / framework "
                    "version headers. See remediation guidance above "
                    "for nginx / Apache / IIS / Express / Spring "
                    "configuration."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: GET {origin}/ returned no notable "
                     "server / framework banner headers."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoPoweredByBannerProbe().main()
