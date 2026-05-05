#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Source code disclosure: `.git/` directory served by the web server.

A common deploy-time mistake is to push the repository's working
directory to the web root (rsync / scp / git clone on the server)
and forget to exclude `.git/`. The web server then happily serves
every git object back to anyone who walks the predictable paths.

From `.git/HEAD` + `.git/config` + `.git/index`, an attacker can
fully reconstruct the source tree using `git-dumper`, recover
hardcoded secrets from earlier commits, and read deployment
metadata from the config.

High-fidelity rule: a 200 alone is not enough -- many SPAs return
200 for any unmatched path with the index.html fallback. We
require both:
  (a) HTTP 200 status, AND
  (b) the response body matches the file's expected structural
      format (e.g., `.git/HEAD` body starts with `ref: refs/heads/`
      or a 40-char hex SHA; `.git/config` body contains the
      `[core]` section header; `.git/index` body starts with the
      DIRC magic bytes).

Detection signal:
  GET each candidate path; validate when at least one returns 200
  AND its body matches the format-specific signature for that file.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Each candidate is (path, body-prefix-bytes-or-None,
# text-regex-or-None, label). The probe accepts either a binary
# prefix match OR a regex match.
TARGETS: tuple[tuple[str, bytes | None, re.Pattern | None, str], ...] = (
    ("/.git/HEAD",
     None,
     # Either symbolic ref ("ref: refs/heads/main\n") or a detached
     # 40-hex SHA followed by a newline.
     re.compile(r"^(?:ref:\s+refs/(?:heads|tags|remotes)/[^\s]+|"
                r"[0-9a-f]{40})\s*$"),
     ".git/HEAD"),
    ("/.git/config",
     None,
     # git config files always contain the [core] section.
     re.compile(r"^\[core\]\s*$", re.MULTILINE),
     ".git/config"),
    ("/.git/index",
     # Git index file magic = "DIRC" followed by 4 bytes of version.
     b"DIRC",
     None,
     ".git/index"),
    ("/.git/logs/HEAD",
     None,
     # logref log lines: <40-hex> <40-hex> <name> <email> <ts> <tz>
     re.compile(r"^[0-9a-f]{40}\s+[0-9a-f]{40}\s+", re.MULTILINE),
     ".git/logs/HEAD"),
    ("/.git/refs/heads/master",
     None,
     re.compile(r"^[0-9a-f]{40}\s*$"),
     ".git/refs/heads/master"),
    ("/.git/refs/heads/main",
     None,
     re.compile(r"^[0-9a-f]{40}\s*$"),
     ".git/refs/heads/main"),
)


class InfoGitDirectoryExposedProbe(Probe):
    name = "info_git_directory_exposed"
    summary = ("Detects `.git/` directory served by the web server "
               "(source-code disclosure via git-dumper).")
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
                    # Snippet for evidence; capped to keep verdict small.
                    row["snippet"] = (r.text or "")[:160]
                    confirmed.append(row)
                    attempts.append(row)
                    # Two confirmed paths = unambiguous; stop early.
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
                    f"Confirmed: `.git/` exposed at {origin}. "
                    f"`{top['path']}` returned 200 with content "
                    f"matching the {top['label']} format. An attacker "
                    "can clone the repository with git-dumper and "
                    "recover the full source tree, including any "
                    "secrets committed to earlier history."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Remove `.git/` from the deployed document root. "
                    "Long-term, deploy from artifacts (CI build "
                    "output) rather than `git clone` on the server.\n"
                    "  - nginx: `location ~ /\\.git { deny all; "
                    "return 404; }`.\n"
                    "  - Apache: `<DirectoryMatch \"\\.git\"> Require "
                    "all denied </DirectoryMatch>`.\n"
                    "  - IIS: add `.git` to Request Filtering "
                    "hidden segments.\n"
                    "After remediation: rotate every secret that was "
                    "ever committed to the repo's history. The "
                    "exposure window may have been long."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} `.git/` paths "
                     f"on {origin}; no response matched a git "
                     "file-format signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoGitDirectoryExposedProbe().main()
