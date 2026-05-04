#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
AEM: CRXDE Lite / CRX Explorer reachable on the public origin.

CRXDE Lite (`/crx/de/index.jsp`) is the web-based JCR repository
browser bundled with AEM. Reachable to anonymous = full JCR
read; reachable to admin/admin = full JCR write. Adobe's
hardening checklist explicitly lists `/crx/*` as a default-deny
on publish dispatchers; many deployments leave it open by
mistake.

Detection signal: GET candidate paths; validate on the unique
title strings AEM serves -- `<title>CRXDE Lite</title>`,
`<title>CRX Explorer</title>`, or the `Adobe Experience Manager`
HTML banner that no other product produces.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/crx/de/index.jsp",
    "/crx/de/",
    "/crx/explorer/index.jsp",
    "/crx/explorer/diff.jsp",
    "/crx/explorer/browser/index.jsp",
    "/crx/server/crx.default/jcr:root.json",
    "/crx/de",
)

_SIGS = (
    re.compile(r"<title>\s*CRXDE Lite", re.I),
    re.compile(r"<title>\s*CRX Explorer", re.I),
    re.compile(r"Adobe Experience Manager", re.I),
    re.compile(r'"jcr:primaryType"\s*:\s*"rep:root"'),
)


class AemCrxDeLiteProbe(Probe):
    name = "aem_crx_de_lite"
    summary = ("Detects AEM CRXDE Lite / CRX Explorer reachable "
               "on the public origin -- web-based JCR browser, "
               "RCE-equivalent on auth.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional CRXDE path. Repeatable.")

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
                         "size": r.size,
                         "final_url": r.final_url}
            # 401 (auth required) is also a finding -- the auth
            # surface is reachable, which is the bug shape.
            if r.status in (200, 401) and r.body:
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
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: AEM CRX/DE reachable at "
                    f"{origin}{confirmed['path']}. The JCR repository "
                    "browser is exposed on the public origin -- if "
                    "the credentials are anything close to the "
                    "default (admin/admin), the attacker has full "
                    "read/write access to the entire content "
                    "repository."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Per Adobe's hardening checklist, /crx/* must be "
                    "blocked on the publish dispatcher.\n"
                    "  - dispatcher.any: deny rule for `/crx/.*`.\n"
                    "  - On the author tier: keep /crx/* behind a "
                    "  VPN or hardened SSO; never directly internet-"
                    "  reachable.\n"
                    "  - Verify the admin password has been rotated "
                    "  away from `admin/admin` (run the existing "
                    "  `auth_default_admin_credentials` probe).\n"
                    "Audit access logs for /crx/de requests during "
                    "the exposure window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} CRX paths on "
                     f"{origin}; no AEM signature matched."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemCrxDeLiteProbe().main()
