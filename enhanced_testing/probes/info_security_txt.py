#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: /.well-known/security.txt reachable.

A `security.txt` file at /.well-known/security.txt is the IETF-
documented (RFC 9116) way for a site to publish its vulnerability
disclosure contact. Its presence is INFORMATIONAL — not itself a
problem — but worth flagging because:
  - It's rarely enumerated by default scanners
  - The disclosure-contact email is itself a useful artefact for
    reporting / coordination
  - Its ABSENCE on a site that claims to have a security program
    is a small posture finding worth recording

Detection signal:
  GET /.well-known/security.txt → 200 with `Contact:` line in body.
  We treat presence as the "validated" signal; absence as a
  refute (this probe always emits a verdict, never errors out).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/.well-known/security.txt",
    "/security.txt",
)
_CONTACT_RE = re.compile(r"^\s*Contact\s*:\s*(\S.+?)\s*$",
                         re.IGNORECASE | re.MULTILINE)


class SecurityTxtProbe(Probe):
    name = "info_security_txt"
    summary = ("Records presence/absence of /.well-known/security.txt "
               "as an informational posture finding.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        for p in PATHS:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row = {"url": url, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                m = _CONTACT_RE.search(r.text or "")
                if m:
                    row["contact"] = m.group(1)
                    return Verdict(
                        validated=True, confidence=0.97,
                        summary=(f"Confirmed: security.txt published at "
                                 f"{url} — Contact: {m.group(1)!r}."),
                        evidence={"origin": origin,
                                  "attempts": attempts + [row]},
                        severity_uplift="info",
                        remediation=(
                            "(Informational.) The presence of a "
                            "well-formed security.txt is a positive "
                            "signal — verify the Contact email is "
                            "monitored and the Expires field hasn't "
                            "lapsed."),
                    )
            attempts.append(row)

        return Verdict(
            validated=False, confidence=0.9,
            summary=(f"Refuted: no /.well-known/security.txt at "
                     f"{origin}. Consider publishing one (RFC 9116) "
                     "so security researchers know how to reach you."),
            evidence={"origin": origin, "attempts": attempts},
            remediation=(
                "Add a /.well-known/security.txt with at least "
                "`Contact: mailto:security@yourdomain` and an "
                "`Expires:` date 12 months from publication. "
                "RFC 9116 has the full schema."),
        )


if __name__ == "__main__":
    SecurityTxtProbe().main()
