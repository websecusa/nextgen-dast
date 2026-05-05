#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: IDE / OS metadata files served from web root.

Developers commit and operators sometimes deploy editor /
filesystem-state files alongside the application. These contain
project-internal paths, recently-opened files, build configurations,
and (in `.DS_Store`) a complete listing of every file that was ever
in the directory at the time the OS wrote the file -- including ones
that have since been deleted from the deploy.

Targets covered:
  - `/.idea/workspace.xml`     -- JetBrains workspace state (file
                                  paths, run configs, sometimes
                                  database creds in datasource
                                  blocks).
  - `/.vscode/settings.json`   -- VS Code per-folder settings.
  - `/.vscode/launch.json`     -- VS Code debug configurations,
                                  often with hardcoded ports / hosts.
  - `/.DS_Store`               -- macOS Finder metadata; encodes a
                                  full directory listing as binary.
                                  Magic header: \\x00\\x00\\x00\\x01Bud1.
  - `/Thumbs.db`               -- Windows thumbnail cache. OLE2
                                  compound document; magic header
                                  D0 CF 11 E0 A1 B1 1A E1.

High-fidelity rule: 200 + body content matches the file's exact
structural fingerprint (XML root element, JSON top-level shape, or
binary magic bytes). A bare 200 from an SPA fallback is rejected.

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
# label).
TARGETS: tuple[tuple[str, bytes | None, re.Pattern | None, str], ...] = (
    ("/.idea/workspace.xml",
     None,
     re.compile(
         r"<\?xml[^>]+\?>\s*<project\s+version=\"\d+\">|"
         r"<component\s+name=\"(?:RunManager|ChangeListManager|"
         r"PropertiesComponent)\""),
     "JetBrains workspace.xml"),
    ("/.idea/modules.xml",
     None,
     re.compile(r"<component\s+name=\"ProjectModuleManager\""),
     "JetBrains modules.xml"),
    ("/.vscode/settings.json",
     None,
     # VS Code settings.json is JSON whose top-level keys are dotted
     # ("editor.fontSize", "files.exclude" etc.). Strict shape.
     re.compile(r'\A\s*\{\s*"[a-zA-Z]+\.[a-zA-Z][a-zA-Z0-9.\-_]*"\s*:'),
     "VS Code settings.json"),
    ("/.vscode/launch.json",
     None,
     # VS Code launch.json always has top-level "version" + "configurations".
     re.compile(r'"configurations"\s*:\s*\[\s*\{[^}]*"type"\s*:\s*"',
                re.DOTALL),
     "VS Code launch.json"),
    ("/.DS_Store",
     # macOS .DS_Store magic. The 4 zero bytes + "Bud1" magic make
     # this an unambiguous structural match.
     b"\x00\x00\x00\x01Bud1",
     None,
     "macOS .DS_Store"),
    ("/Thumbs.db",
     # OLE2 compound document magic header (Thumbs.db is OLE2).
     b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
     None,
     "Windows Thumbs.db"),
    ("/.project",
     None,
     re.compile(r"<projectDescription>\s*<name>"),
     "Eclipse .project"),
)


class InfoIdeMetadataExposedProbe(Probe):
    name = "info_ide_metadata_exposed"
    summary = ("Detects IDE / OS metadata files (.idea, .vscode, "
               ".DS_Store, Thumbs.db, .project) served from the web "
               "root.")
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
                    # Don't include binary blobs in the snippet --
                    # just a printable ASCII excerpt.
                    excerpt = (r.text or "")[:160]
                    row["snippet"] = "".join(
                        c if 32 <= ord(c) < 127 or c in "\n\t"
                        else "." for c in excerpt)
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
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: IDE / OS metadata exposed at "
                    f"{origin}{top['path']} ({top['label']}). The "
                    "file leaks internal project structure, file "
                    "paths, and (for .DS_Store) a full directory "
                    "listing of every file the developer ever had "
                    "in that folder."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Strip these files from deploys and block them "
                    "at the edge:\n"
                    "  - Build pipeline: ensure .idea/, .vscode/, "
                    ".DS_Store, Thumbs.db, .project are not part of "
                    "the deployable artifact (add to .dockerignore "
                    "/ deploy script's exclude list).\n"
                    "  - nginx: `location ~ /(\\.idea|\\.vscode|"
                    "\\.DS_Store|Thumbs\\.db) { deny all; "
                    "return 404; }`.\n"
                    "  - Apache: `RedirectMatch 404 \"/\\.(idea|"
                    "vscode|DS_Store)|/Thumbs\\.db\"`.\n"
                    "If `.idea/dataSources.xml` was in the leak, "
                    "rotate those database credentials."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} IDE / OS "
                     f"metadata paths on {origin}; no response "
                     "matched the format-specific signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoIdeMetadataExposedProbe().main()
