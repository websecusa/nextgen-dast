#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Source code disclosure: `.svn/` directory served by the web server.

Older codebases deployed via `svn checkout` on the production server
leave a `.svn/` working-copy state alongside every directory (or, for
1.7+ Subversion, just at the root). Either layout exposes:

  - `.svn/entries`  -- the working-copy entry list. SVN < 1.7 used a
                       text format starting with the literal version
                       number on the first line ("12\n"); 1.7+ stores
                       the format inside `wc.db`.
  - `.svn/wc.db`    -- 1.7+ working-copy state, a SQLite3 file. The
                       first 16 bytes are the SQLite header
                       "SQLite format 3\x00".

High-fidelity rule: a 200 alone is never enough -- many sites return
200 with index.html for any unknown path. We require the body to
match the file's exact structural fingerprint:
  - `.svn/entries` body starts with a version-number line (a small
    integer on a line by itself).
  - `.svn/wc.db` body starts with the SQLite3 magic header bytes.

Detection signal:
  GET each path; validate when at least one returns 200 AND the
  body matches its format-specific signature.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Tuples are (path, body-prefix-bytes-or-None, text-regex-or-None,
# label). The probe accepts either the binary prefix OR a regex match.
TARGETS: tuple[tuple[str, bytes | None, re.Pattern | None, str], ...] = (
    ("/.svn/entries",
     None,
     # SVN < 1.7 entries file. First non-empty line is the format
     # version (a small integer like "10" or "12") on its own.
     re.compile(r"\A\s*\d{1,3}\s*$", re.MULTILINE),
     ".svn/entries (pre-1.7 text format)"),
    ("/.svn/wc.db",
     # SQLite3 magic header. Strict structural check.
     b"SQLite format 3\x00",
     None,
     ".svn/wc.db (1.7+ SQLite working copy)"),
    ("/.svn/format",
     None,
     # Single integer version on its own.
     re.compile(r"\A\s*\d{1,3}\s*$"),
     ".svn/format"),
    ("/.svn/all-wcprops",
     None,
     # all-wcprops files always start with "K <num>\n".
     re.compile(r"\AK\s+\d+\s*$", re.MULTILINE),
     ".svn/all-wcprops"),
)


class InfoSvnDirectoryExposedProbe(Probe):
    name = "info_svn_directory_exposed"
    summary = ("Detects `.svn/` directory served by the web server "
               "(source-code disclosure via svn-extractor).")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for path, prefix, regex, label in TARGETS:
            r = client.request("GET", urljoin(origin, path))
            row: dict = {"path": path, "label": label,
                         "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                matched = False
                if prefix is not None and r.body.startswith(prefix):
                    matched = True
                    row["match"] = "binary-prefix"
                elif regex is not None and regex.search(r.text or ""):
                    matched = True
                    row["match"] = "regex"
                if matched:
                    row["snippet"] = (r.text or "")[:160]
                    confirmed.append(row)
                    attempts.append(row)
                    if len(confirmed) >= 2:
                        break
                    continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.96,
                summary=(
                    f"Confirmed: `.svn/` exposed at {origin}. "
                    f"`{top['path']}` returned 200 with content "
                    f"matching the {top['label']} format. svn-"
                    "extractor / svnpwn can reconstruct the working "
                    "tree, source files, and any historic commits "
                    "the server still has metadata for."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Stop deploying production directly via "
                    "`svn checkout`; deploy clean artifacts instead. "
                    "Until then, block `.svn/` at the edge:\n"
                    "  - nginx: `location ~ /\\.svn { deny all; "
                    "return 404; }`.\n"
                    "  - Apache: `<DirectoryMatch \"\\.svn\"> Require "
                    "all denied </DirectoryMatch>`.\n"
                    "Audit access logs for `.svn/wc.db` and "
                    "`.svn/entries` requests; rotate every committed "
                    "secret."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} `.svn/` paths "
                     f"on {origin}; no response matched an SVN "
                     "file-format signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoSvnDirectoryExposedProbe().main()
