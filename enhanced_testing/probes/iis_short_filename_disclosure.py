#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
IIS: 8.3 short-filename disclosure.

Older Windows file systems generate 8.3-format short names
alongside the long names (`Program Files` -> `PROGRA~1`). IIS
exposes this in error responses: a request for an 8.3 prefix that
matches an existing file or directory returns a different status
code than one that doesn't. The differential lets an attacker
enumerate all top-level filenames under the document root, eight
characters at a time.

The technique we use is the standard one (see Soroush Dalili's
research): request `/<prefix>~1*~1.aspx` and compare to a control
prefix.
  - Real prefix match -> HTTP 404 with reason `Not Found`.
  - Real prefix mismatch -> HTTP 404 with reason `Bad Request` or
    different error text.

Detection signal: confirm at least 2 known-shape prefixes
(`aspnet_clien`, `App_Data`, `inetpub`) produce a response
*structurally different* from a randomly-named non-prefix.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common prefixes that exist on a default IIS install. If the IIS
# 8.3 disclosure exists, requests for these will respond
# differently than for our control random.
KNOWN_PREFIXES = (
    "aspnet_client",
    "App_Data",
    "inetpub",
    "wwwroot",
    "windows",
    "webconfig",
    "global~1.asa",
)


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v).strip()
    return ""


class IisShortFilenameDisclosureProbe(Probe):
    name = "iis_short_filename_disclosure"
    summary = ("Detects IIS 8.3 short-filename disclosure by "
               "comparing response shape between known-prefix and "
               "random-prefix tilde-suffixed requests.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Control: a totally random non-prefix.
        control_prefix = "x" + secrets.token_hex(5)
        control_url = (origin + "/" + control_prefix
                       + "~1*~1.aspx")
        rc = client.request("GET", control_url)
        control_signature = (rc.status,
                              _hdr(rc.headers, "X-Powered-By"),
                              _hdr(rc.headers, "Server"))

        # If the server doesn't even look like IIS, bail with a
        # clean negative (no false-positives on nginx).
        srv = control_signature[2].lower()
        if "iis" not in srv and "microsoft" not in srv:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: server header on {origin} "
                         "isn't IIS / Microsoft -- short-filename "
                         "disclosure does not apply."),
                evidence={"origin": origin,
                           "control_signature": control_signature},
            )

        attempts: list[dict] = [{"prefix": control_prefix,
                                  "kind": "control",
                                  "status": rc.status,
                                  "size": rc.size}]
        differing: list[dict] = []
        for prefix in KNOWN_PREFIXES:
            url = origin + "/" + prefix + "~1*~1.aspx"
            r = client.request("GET", url)
            row: dict = {"prefix": prefix, "kind": "candidate",
                         "status": r.status, "size": r.size}
            sig = (r.status,
                    _hdr(r.headers, "X-Powered-By"),
                    _hdr(r.headers, "Server"))
            if sig != control_signature or r.size != rc.size:
                row["differs"] = True
                differing.append(row)
            attempts.append(row)

        evidence = {"origin": origin,
                    "control_signature": control_signature,
                    "attempts": attempts}
        # Need at least 2 differing prefixes to confirm -- single
        # differential could be intermittent.
        if len(differing) >= 2:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: IIS 8.3 short-filename disclosure "
                    f"on {origin}. {len(differing)} of "
                    f"{len(KNOWN_PREFIXES)} known prefixes produced "
                    "responses structurally different from a random "
                    "control. Sample: "
                    f"{[d['prefix'] for d in differing[:3]]}. An "
                    "attacker can enumerate top-level filenames in "
                    "the doc root."),
                evidence={**evidence, "differing": differing},
                severity_uplift="medium",
                remediation=(
                    "Disable 8.3 short-name generation on the "
                    "Windows volume hosting the IIS doc root:\n"
                    "  fsutil 8dot3name set <drive>: 1\n"
                    "Then strip existing short names:\n"
                    "  fsutil 8dot3name strip <drive>:\\inetpub\n"
                    "Or, on the IIS side, install URLScan / "
                    "request-filtering rules that refuse `~` in URLs."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: control + {len(KNOWN_PREFIXES)} "
                     f"prefix probes on {origin}; insufficient "
                     "differential to confirm the 8.3 leak."),
            evidence=evidence,
        )


if __name__ == "__main__":
    IisShortFilenameDisclosureProbe().main()
