#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
IIS / Apache: WebDAV methods enabled on a public web app.

WebDAV (PROPFIND, MKCOL, MOVE, COPY, LOCK, PUT, DELETE) is
appropriate for file-server workloads but rarely for a public web
application. When enabled on a public origin it gives anyone --
authenticated or not, depending on configuration -- the ability
to enumerate the doc root (PROPFIND), upload files (PUT), and
move them (MOVE) -- a clear path to webshell upload.

Detection signal:
  1. OPTIONS / -- look for any DAV methods in `Allow` OR a `DAV:`
     header.
  2. (Confirm) PROPFIND / with a Depth: 0 header -- look for a
     `<D:multistatus>` XML response.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DAV_METHODS = ("PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK",
                "UNLOCK", "PUT", "DELETE", "PROPPATCH")


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v).strip()
    return ""


class IisWebdavMethodsEnabledProbe(Probe):
    name = "iis_webdav_methods_enabled"
    summary = ("Detects WebDAV methods enabled on a public web "
               "origin -- PROPFIND / PUT / MOVE / DELETE primitives.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # OPTIONS first.
        r = client.request("OPTIONS", urljoin(origin, "/"))
        allow = _hdr(r.headers, "Allow")
        dav_hdr = _hdr(r.headers, "DAV")
        public = _hdr(r.headers, "Public")           # IIS variant
        method_set = re.findall(r"[A-Z]+", allow + " " + public)
        dav_methods_found = sorted(set(method_set) & set(DAV_METHODS))

        attempts: list[dict] = [{
            "kind": "OPTIONS",
            "status": r.status, "allow": allow,
            "dav": dav_hdr,
            "public": public,
            "dav_methods_found": dav_methods_found,
        }]

        confirmed: dict | None = None
        # Confirm with PROPFIND if any DAV-relevant signal showed
        # up. We don't blindly issue PROPFIND if the OPTIONS gave
        # no signal -- saves request budget.
        if dav_methods_found or dav_hdr:
            rp = client.request("PROPFIND", urljoin(origin, "/"),
                                 headers={"Depth": "0",
                                          "Content-Length": "0"})
            row = {"kind": "PROPFIND", "status": rp.status,
                   "size": rp.size}
            text = rp.text or ""
            if rp.status == 207 or "<D:multistatus" in text or \
                    "<multistatus" in text or "xmlns:D=\"DAV:\"" in text:
                row["multistatus"] = True
                confirmed = row
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed or dav_methods_found:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: WebDAV reachable on {origin}. DAV "
                    f"methods exposed via OPTIONS: {dav_methods_found}. "
                    f"PROPFIND on / "
                    f"{'returned <multistatus> XML' if confirmed else 'not confirmed'}. "
                    "WebDAV on a public web app gives PUT / MOVE / "
                    "DELETE primitives that lead to webshell upload."),
                evidence={**evidence,
                           "dav_methods": dav_methods_found,
                           "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable WebDAV on the web tier:\n"
                    "  - IIS: Server Manager > remove WebDAV "
                    "  Publishing role; OR in web.config remove the "
                    "  WebDAVModule and webDAVHandler entries.\n"
                    "  - Apache: comment out `LoadModule dav_module` "
                    "  and `LoadModule dav_fs_module`; remove `Dav On` "
                    "  from any vhost.\n"
                    "  - At the edge: refuse PROPFIND / MKCOL / MOVE "
                    "  / COPY / LOCK / UNLOCK / PROPPATCH at the "
                    "  reverse proxy.\n"
                    "If WebDAV is intentional, it must require auth "
                    "AND be confined to a separate vhost / port."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: OPTIONS on {origin}/ returned no "
                     "DAV-relevant methods or headers."),
            evidence=evidence,
        )


if __name__ == "__main__":
    IisWebdavMethodsEnabledProbe().main()
