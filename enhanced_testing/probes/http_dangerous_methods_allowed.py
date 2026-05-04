#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
HTTP server advertises dangerous methods on read-only paths.

OPTIONS to a static-asset / docs / public-page path that returns
`Allow: PUT, DELETE, PATCH` (or PROPFIND / MKCOL / MOVE / COPY)
is the canonical "we left WebDAV / a write API on by mistake" tell.
Different from `iis_webdav_methods_enabled` (which targets WebDAV
specifically); this one fires on the general "method should not
be allowed here" pattern across any stack.

Detection signal: OPTIONS each candidate read-only path; validate
when `Allow` includes a write/management method that has no
business being exposed there.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = ("/", "/static/", "/assets/", "/uploads/", "/files/",
         "/images/", "/css/", "/js/", "/public/")

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "PROPFIND",
                      "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK",
                      "PROPPATCH"}


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v).strip()
    return ""


class HttpDangerousMethodsAllowedProbe(Probe):
    name = "http_dangerous_methods_allowed"
    summary = ("Detects dangerous HTTP methods (PUT / DELETE / "
               "PATCH / PROPFIND etc.) advertised as allowed on "
               "read-only paths.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional read-only path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("OPTIONS", urljoin(origin, p))
            allow = _hdr(r.headers, "Allow")
            public = _hdr(r.headers, "Public")
            method_set = set(re.findall(r"[A-Z]+", allow + " " + public))
            dangerous = sorted(method_set & DANGEROUS_METHODS)
            row: dict = {"path": p, "status": r.status,
                         "allow": allow,
                         "public": public,
                         "dangerous_methods": dangerous}
            if dangerous:
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: dangerous HTTP methods advertised "
                    f"on {origin}{confirmed['path']}. Allow contains "
                    f"{confirmed['dangerous_methods']}. PUT / DELETE / "
                    "PATCH on a static-asset path means write access "
                    "is reachable; PROPFIND / MKCOL means WebDAV is "
                    "live."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Restrict the methods at the web tier:\n"
                    "  - Apache: `<LimitExcept GET POST HEAD OPTIONS>"
                    "  Require all denied</LimitExcept>` per "
                    "  <Directory>.\n"
                    "  - nginx: `if ($request_method !~ "
                    "  ^(GET|HEAD|POST|OPTIONS)$) { return 405; }` in "
                    "  the static-content `location`.\n"
                    "  - IIS: web.config request-filtering "
                    "  `<verbs allowUnlisted=\"false\">` with only "
                    "  the verbs you actually need.\n"
                    "If WebDAV is intentional (PROPFIND etc.), it "
                    "must require auth and be confined to a separate "
                    "vhost / port."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: OPTIONS-probed {len(attempts)} "
                     f"read-only paths on {origin}; no Allow / "
                     "Public header advertised dangerous methods."),
            evidence=evidence,
        )


if __name__ == "__main__":
    HttpDangerousMethodsAllowedProbe().main()
