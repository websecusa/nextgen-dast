#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: robots.txt enumerates internal paths.

robots.txt is meant for crawlers; it should ONLY name paths that are
otherwise reachable. Disallowing /admin, /backup, /ftp, etc. tells
the polite crawler to stay away — and tells an attacker exactly
where the interesting stuff lives.

Detection signal:
  GET /robots.txt → 200 with at least one `Disallow: <interesting-
  path>` line. We define "interesting" with a curated list of admin /
  backup / private path tokens.

Tested against:
  + OWASP Juice Shop  /robots.txt has `Disallow: /ftp` →
                      validated=True (high-fidelity probe finding;
                      correlate with info_directory_listing).
  + nginx default site → validated=False (no robots.txt).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Path tokens that, when disallowed in robots.txt, point at admin /
# backup / non-public surface. The check is substring (case-insensitive)
# against the path on each `Disallow:` line.
_HOTSPOTS = (
    "/admin", "/administrator", "/backup", "/backups", "/ftp",
    "/private", "/secret", "/internal", "/.git", "/.svn",
    "/api/admin", "/console", "/phpmyadmin", "/wp-admin", "/server-status",
    "/manager", "/.env", "/db", "/database",
)

_DISALLOW_RE = re.compile(r"^\s*Disallow\s*:\s*(\S+)\s*$",
                          re.IGNORECASE | re.MULTILINE)


class RobotsTxtProbe(Probe):
    name = "info_robots_txt_admin_paths"
    summary = ("Detects robots.txt that enumerates internal admin / "
               "backup / non-public paths.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(origin, "/robots.txt")
        r = client.request("GET", url)
        attempt = {"url": url, "status": r.status, "size": r.size}
        evidence = {"origin": origin, "attempt": attempt}
        if r.status != 200 or not r.body:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no robots.txt at {url} "
                         f"(status {r.status})."),
                evidence=evidence,
            )
        text = r.text or ""
        disallows = [m.group(1) for m in _DISALLOW_RE.finditer(text)]
        attempt["disallow_lines"] = disallows
        hits = [d for d in disallows
                if any(t in d.lower() for t in _HOTSPOTS)]
        attempt["hotspot_hits"] = hits
        if hits:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: robots.txt at {url} discloses "
                         f"{len(hits)} sensitive path(s): "
                         + ", ".join(hits[:6]) + "."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Don't list private paths in robots.txt. The file "
                    "should name only the canonical sitemap and the "
                    "rules for the public crawl surface. Move admin / "
                    "backup endpoints behind authentication AND off "
                    "the public document root — not 'hidden' by an "
                    "advisory file."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: robots.txt at {url} does not list "
                     "sensitive paths."),
            evidence=evidence,
        )


if __name__ == "__main__":
    RobotsTxtProbe().main()
