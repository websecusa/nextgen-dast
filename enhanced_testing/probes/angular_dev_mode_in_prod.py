#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Angular: dev-mode build shipped to production.

Production builds (`ng build --configuration=production`) strip
`ngDevMode`, minify the framework code, and inline-compile
templates. A dev-mode build that ends up on a public origin leaks:

  - The full unminified framework source (function names visible).
  - Component template strings (often containing internal API
    paths, feature flag names, and copy that the marketing team
    didn't intend to publish).
  - Source maps (covered separately by `info_source_map_exposed`).
  - Dev-only console warnings that fingerprint the version
    precisely, helping an attacker find CVE-applicable matches.

High-fidelity signal: GET the homepage, parse `<script>` tags,
fetch the largest JS bundle. Validate when the body matches any
of the dev-mode markers.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEV_MARKERS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bngDevMode\s*=\s*true\b"),
     "ngDevMode = true (Angular dev mode flag)"),
    (re.compile(r"Angular is running in development mode"),
     "explicit 'Angular is running in development mode' string"),
    (re.compile(r"\bbootstrapModule\b\s*\("),
     "unminified bootstrapModule( -- production builds rename"),
    (re.compile(r"@__PURE__"),
     "@__PURE__ annotation -- bundler kept Angular's tree-shaking "
     "marker"),
    (re.compile(r'"@angular/core/primitives'),
     "Angular primitives subpath -- only present in dev"),
)

# Common bundle naming patterns -- main, runtime, vendor, polyfills.
SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"',
                        re.I)


class AngularDevModeProbe(Probe):
    name = "angular_dev_mode_in_prod"
    summary = ("Detects Angular bundles built in dev mode shipped "
               "to production -- leaks framework source, version, "
               "and template strings.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--bundle", action="append", default=[],
            help="Additional JS bundle URL/path to fetch.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Fetch homepage; pull bundle URLs.
        r = client.request("GET", urljoin(origin, "/"))
        if r.status != 200 or not r.body:
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: homepage on {origin} "
                         f"returned {r.status}; cannot enumerate "
                         "bundles."),
                evidence={"origin": origin, "homepage_status": r.status},
            )
        bundles = list(SCRIPT_RE.findall(r.text or ""))
        bundles = bundles[:8] + list(args.bundle or [])
        # Resolve relative URLs.
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles]

        attempts: list[dict] = []
        confirmed: dict | None = None
        for url in bundles[:10]:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status == 200 and rb.body:
                text = rb.text or ""
                for pat, label in DEV_MARKERS:
                    if pat.search(text):
                        row.update({"marker": label,
                                     "snippet": text[:200]})
                        confirmed = row
                        break
                if confirmed:
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "bundles_enumerated": len(bundles),
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: Angular dev-mode bundle at "
                    f"{confirmed['bundle']} -- found {confirmed['marker']}. "
                    "Production builds strip these; the deployed "
                    "bundle came from `ng build` without "
                    "`--configuration=production`."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Rebuild for production:\n"
                    "  ng build --configuration=production\n"
                    "  (or ng build --prod on Angular < 12)\n"
                    "Update the deploy pipeline to call this command "
                    "instead of `ng build`. Pair with the existing "
                    "`info_source_map_exposed` fix to also strip "
                    ".js.map files from the static-asset bundle."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: fetched {len(attempts)} bundles on "
                     f"{origin}; none carried Angular dev-mode "
                     "markers."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AngularDevModeProbe().main()
