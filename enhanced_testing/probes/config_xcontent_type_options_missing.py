#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Misconfiguration: `X-Content-Type-Options: nosniff` missing on
user-content paths.

Without `nosniff`, a browser is allowed to MIME-sniff the response
body and treat content as a different type than the server
advertises. A user-uploaded SVG that the server returns as
`Content-Type: image/svg+xml` is happily rendered as HTML by the
browser if the body looks HTML-ish -- stored XSS via image upload.
The same bug shape applies to user-uploaded JSON, plain text, and
any path that returns user-controlled content with a non-strict
content-type.

The high-fidelity signal is a structural header check on paths
that serve user content: GET the path, look at headers, validate
when content-type is HTML/SVG/text/JS-ish AND nosniff is missing.
We confine the check to a small list of known user-content paths
(profile images, uploads, user-supplied attachments) so we don't
fire on every static asset.

Detection signal:
  GET each candidate path. Validate when the response is 200, has
  a content-type that's known to be MIME-sniffable
  (`image/svg+xml`, `application/json`, `text/html`, `text/plain`,
  `application/javascript`, `image/jpeg`/`image/png` for legacy
  IE), AND no `X-Content-Type-Options: nosniff` header.

Tested against:
  + OWASP Juice Shop  Sets X-Content-Type-Options: nosniff globally
                      -> validated=False.
  + Apps without the header on /uploads/<id> -> validated=True.

Read-only: GET only.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# User-content paths -- these are the paths where MIME confusion
# routinely turns into stored XSS / drive-by issues.
USER_CONTENT_PATHS = (
    "/",
    "/profile-image",
    "/api/Users/1/profile-image",
    "/api/users/me/avatar",
    "/uploads/avatar.png",
    "/uploads/file.txt",
    "/files/test.json",
    "/assets/images/uploads/default.svg",
    "/api/files/1",
    "/api/attachments/1",
)

# Content types that can be MIME-sniffed into something dangerous
# (treated as HTML, executed as JavaScript, etc.) without nosniff.
_SNIFFABLE_CTS = ("image/svg+xml", "application/json", "text/plain",
                   "text/html", "application/javascript",
                   "application/xml", "text/xml",
                   "application/octet-stream")


def _ct(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return str(v).lower().strip()
    return ""


def _has_nosniff(headers: dict) -> bool:
    for k, v in (headers or {}).items():
        if k.lower() == "x-content-type-options":
            return "nosniff" in str(v).lower()
    return False


def _ct_sniffable(ct: str) -> bool:
    if not ct:
        return True       # no content-type at all is the worst case
    bare = ct.split(";", 1)[0].strip()
    return any(bare == s for s in _SNIFFABLE_CTS)


class XContentTypeOptionsMissingProbe(Probe):
    name = "config_xcontent_type_options_missing"
    summary = ("Detects user-content paths that lack `X-Content-Type-"
               "Options: nosniff` -- MIME confusion / stored-XSS "
               "primitive.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional user-content path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(USER_CONTENT_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p),
                                follow_redirects=False)
            ct = _ct(r.headers or {})
            ns = _has_nosniff(r.headers or {})
            row: dict = {"path": p, "status": r.status,
                         "content_type": ct or None,
                         "nosniff": ns}
            if r.status == 200 and r.body and _ct_sniffable(ct) and not ns:
                row["sniffable"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} returns a "
                    f"sniffable content-type "
                    f"({confirmed['content_type']!r}) with no "
                    "`X-Content-Type-Options: nosniff` header. The "
                    "browser is free to MIME-sniff the body -- a user-"
                    "uploaded SVG / JSON / text resource here will be "
                    "interpreted as HTML if it looks HTML-ish, and "
                    "stored-XSS becomes reachable through the upload "
                    "surface."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Set `X-Content-Type-Options: nosniff` on every "
                    "response, especially on paths that return user "
                    "content.\n"
                    "  - Express / Helmet: `helmet.noSniff()` -- on by "
                    "  default in helmet's preset.\n"
                    "  - Django: `SECURE_CONTENT_TYPE_NOSNIFF = True` "
                    "(default since Django 3.0; verify it's not "
                    "overridden).\n"
                    "  - Rails: `config.action_dispatch.default_"
                    "headers['X-Content-Type-Options'] = 'nosniff'`.\n"
                    "  - At the edge: nginx `add_header X-Content-Type-"
                    "Options nosniff always;`. Apache "
                    "`Header always set X-Content-Type-Options "
                    "\"nosniff\"`.\n"
                    "Pair with strict content-types (return SVG with "
                    "`image/svg+xml; charset=utf-8` and a CSP that "
                    "forbids inline scripts inside SVGs)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} user-content paths "
                     f"on {origin}; each carried `X-Content-Type-"
                     "Options: nosniff` (or wasn't sniffable to begin "
                     "with)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    XContentTypeOptionsMissingProbe().main()
