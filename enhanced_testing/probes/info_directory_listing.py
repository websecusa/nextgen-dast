#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: web-server directory listing exposed on a public
path.

A correctly-configured web server returns 403 (Apache, nginx default) or
404 when a directory is requested without an index document. When
autoindex is on (or the application opts in via Express's serve-index,
http.server, etc.), the server returns an HTML page listing the contents
of the directory. That listing routinely includes filenames the
application doesn't link from anywhere — backups, build artefacts,
credentials, source dumps, easter eggs.

This probe walks a fixed catalogue of paths a real attacker would try
first, looks for the unmistakable directory-listing markers in the
response body, and reports the path + the first half-dozen filenames it
saw. It is read-only (GET), bounded (≤ 30 requests), and deterministic
(matches a regex against the body text).

Tested against:
  + OWASP Juice Shop  /ftp/        →  validated=True   (lists acquisitions.md, eastere.gg, package.json.bak)
  + nginx (autoindex off, default) /assets/ → validated=False
  + Apache (Options -Indexes)      /assets/ → validated=False

Design notes:
  - Markers cover the three most common server-default listings
    (Apache, nginx autoindex, Node.js serve-index/express). We only
    treat a hit as "validated" when at least one marker AND at least
    one anchor-style filename are present, so a generic page that
    happens to contain "Index of" in body text doesn't false-positive.
  - The path catalogue is small on purpose. A wider list belongs in
    a dedicated brute-force probe (info_backup_files.py); this one
    targets *directory listing* specifically.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Make the local lib/ package importable when this script runs as
# subprocess from the orchestrator. Same pattern as the toolkit probes.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import Probe, Verdict, SafeClient   # noqa: E402


# Canonical paths to test. Order matters — generic web roots first, then
# Juice-Shop-/Express-style mounts, then the legacy "files we forgot"
# directories. Stop at the first path that returns a directory listing
# (no point hammering every entry once we've proved the issue).
DEFAULT_PATHS = (
    "/ftp/",            # Juice Shop's known dir-listing mount
    "/uploads/",        # extremely common app upload dir
    "/files/",
    "/static/",         # often locked down, but sometimes not
    "/assets/",
    "/public/",
    "/.git/",           # adjacent finding — see info_git_folder.py for the
                        # specific case; this catches just the listing
    "/backup/",
    "/backups/",
    "/old/",
    "/tmp/",
    "/temp/",
    "/.well-known/",    # rarely indexable; sanity check
)

# Markers that uniquely identify a server-rendered directory listing.
# Each one is paired with the kind of server it implies, so we can put
# that in the verdict's evidence (helps with remediation guidance).
_DIRLIST_MARKERS = (
    (re.compile(r"<title>\s*Index of\s+/", re.IGNORECASE), "Apache (mod_autoindex)"),
    (re.compile(r"<h1>\s*Index of\s+/", re.IGNORECASE),    "Apache (mod_autoindex)"),
    (re.compile(r"<title>\s*listing directory\s+", re.IGNORECASE), "Node.js (serve-index)"),
    (re.compile(r"<h1>\s*Directory listing for\s+/", re.IGNORECASE), "Python http.server"),
    (re.compile(r"<title>\s*Directory listing for\s+/", re.IGNORECASE), "Python http.server"),
    # nginx autoindex generates "<h1>Index of …</h1>" without explicit
    # title, but always wraps the listing in <pre>. The Apache/h1 line
    # above already covers it; this is just belt-and-braces for some
    # caddy / lighttpd / minio variants.
    (re.compile(r"<pre>\s*<a\s+href=\"\.\./\">", re.IGNORECASE), "nginx (autoindex)"),
)

# A directory listing has anchor-style filename entries. We require at
# least one anchor that doesn't go to an external URL. This is what
# stops a generic page like "Index of services" prose from triggering.
_ANCHOR_RE = re.compile(
    r'<a\s+[^>]*href\s*=\s*["\']([^"\':?#]+?)["\']',
    re.IGNORECASE,
)


def _detect_listing(body_text: str) -> tuple[str, list[str]] | None:
    """Return (server_kind, [filenames sample]) when the body is a
    directory listing, else None. Sample capped at 8 filenames so the
    evidence stays compact."""
    server_kind = None
    for pat, kind in _DIRLIST_MARKERS:
        if pat.search(body_text):
            server_kind = kind
            break
    if not server_kind:
        return None
    # Pull anchor targets, drop ones that look like nav links (parent
    # dir, query strings, fragments). We only count relative filenames
    # to avoid being fooled by a page that lists external sites.
    files: list[str] = []
    for m in _ANCHOR_RE.finditer(body_text):
        href = m.group(1)
        if href in ("../", "./", "/"):
            continue
        if href.startswith(("http://", "https://", "//", "mailto:")):
            continue
        files.append(href)
        if len(files) >= 8:
            break
    if not files:
        return None
    return server_kind, files


class InfoDirectoryListingProbe(Probe):
    name = "info_directory_listing"
    summary = ("Detects exposed web-server directory listings on common "
               "paths (autoindex, serve-index, Python http.server).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to test (repeatable). The default "
                 "catalogue covers /ftp/, /uploads/, /backup/, etc.")
        parser.add_argument(
            "--max-paths", type=int, default=15,
            help="Cap on number of paths tested. The probe stops "
                 "early on the first hit anyway.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")

        # Normalise the target to a URL root. The user passes either the
        # site origin (https://example.com/) or any URL on the site —
        # we strip path/query/fragment and walk the catalogue against
        # the origin.
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            return Verdict(ok=False, error=f"--url is not a URL: {args.url!r}")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        paths = list(DEFAULT_PATHS) + [p for p in (args.path or []) if p]
        # De-dupe while preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for p in paths:
            if p in seen:
                continue
            seen.add(p)
            ordered.append(p)
            if len(ordered) >= int(args.max_paths or 15):
                break

        tested: list[dict] = []
        confirmed: list[dict] = []
        for p in ordered:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {
                "path": p, "status": r.status, "size": r.size,
            }
            if r.status == 200 and r.body:
                hit = _detect_listing(r.text)
                if hit:
                    server_kind, files = hit
                    row.update({"directory_listing": True,
                                "server_kind": server_kind,
                                "files_sample": files})
                    confirmed.append(row)
                    tested.append(row)
                    break          # one is enough — verdict is decided
            tested.append(row)

        evidence = {"origin": origin, "paths_tested": tested}

        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: directory listing exposed on "
                         f"{origin}{top['path']} "
                         f"({top['server_kind']}). Visible filenames: "
                         + ", ".join(top["files_sample"][:5])
                         + ("…" if len(top["files_sample"]) >= 5 else "") + "."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable directory autoindex on the affected server. "
                    "  - nginx: ensure `autoindex off;` (the default) — "
                    "remove any `autoindex on;` line.\n"
                    "  - Apache: `Options -Indexes` in the relevant "
                    "<Directory>.\n"
                    "  - Express / Node: remove the `serve-index` "
                    "middleware if present, or restrict it behind auth.\n"
                    "Then audit the directory contents — any files now "
                    "hidden by 403 may have been indexed externally and "
                    "should be moved out of the document root if they "
                    "contain credentials, backups, or source code."),
            )

        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(tested)} common paths on "
                     f"{origin}; no directory listing was returned "
                     "(every response was non-200 or did not match a "
                     "directory-listing template)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoDirectoryListingProbe().main()
