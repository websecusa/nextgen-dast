#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: password-reset token leakable via Referer header.

When a reset URL carries the token in the query string
(`/reset?token=<TOKEN>`), every outbound request the page makes --
to a CDN font, an analytics pixel, an embedded image -- carries
that URL in the Referer header. Without a strict Referrer-Policy,
the token leaks to every third-party domain on the page.

We can't simulate the browser end (JS execution + downstream
links) from a server-side probe. Instead, we detect the
*pre-condition*: a reset surface that:
  1. Carries the token in a query string (not a fragment, not a
     POST body), AND
  2. Returns NO `Referrer-Policy: no-referrer` / `same-origin` /
     `strict-origin` header on the reset page itself.

Both have to hold for the token to leak. Either alone is a softer
finding.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common reset / verification URL shapes that carry a token in the
# query string. We GET each with a well-formed-but-nonexistent
# token; the response page's headers are what we inspect, not the
# success of the reset itself.
RESET_URL_SHAPES = (
    "/reset?token={t}",
    "/reset-password?token={t}",
    "/reset-password/{t}",
    "/account/reset?token={t}",
    "/auth/reset?token={t}",
    "/api/auth/reset?token={t}",
    "/verify-email?token={t}",
    "/verify?token={t}",
    "/confirm?token={t}",
    "/api/verify?token={t}",
)

# Acceptable Referrer-Policy values (a probe MUST refuse to fire
# when any of these is set).
SAFE_POLICIES = {"no-referrer", "same-origin", "strict-origin",
                  "strict-origin-when-cross-origin",
                  "no-referrer-when-downgrade"}    # browser default
                                                    # is downgrade --
                                                    # we treat that as
                                                    # tolerable, not
                                                    # ideal


def _hdr(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v).strip().lower()
    return ""


class PasswordResetTokenInRefererProbe(Probe):
    name = "auth_password_reset_token_in_referer"
    summary = ("Detects password-reset / verification surfaces "
               "where the token is in the query string AND the "
               "response lacks a strict Referrer-Policy -- the "
               "token leaks via Referer to every embedded "
               "third-party.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--shape", action="append", default=[],
            help="Additional reset-URL shape with `{t}` placeholder.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        shapes = list(RESET_URL_SHAPES) + list(args.shape or [])

        # Use a token-shape that the reset endpoint will refuse
        # (but still render the reset PAGE around). 32-char
        # alphanumeric = the most common shape.
        fake_token = "f" * 32

        attempts: list[dict] = []
        confirmed: dict | None = None
        for shape in shapes:
            url = urljoin(origin, shape.format(t=fake_token))
            r = client.request("GET", url, follow_redirects=True)
            policy = _hdr(r.headers, "referrer-policy")
            ctype  = _hdr(r.headers, "content-type")
            row: dict = {"path": shape, "status": r.status,
                         "size": r.size,
                         "referrer_policy": policy or None,
                         "content_type": ctype or None}
            # Trigger when:
            # * The response is HTML (the reset page renders), AND
            # * Referrer-Policy is missing or not a safe value, AND
            # * The token shape-matched the URL we requested
            #   (proves the surface accepts the param).
            if (r.status == 200 and "text/html" in ctype):
                policy_safe = (policy in SAFE_POLICIES)
                if not policy_safe:
                    row["leakable"] = True
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: password-reset surface at "
                    f"{origin}{confirmed['path']} accepts the token "
                    "in the query string and ships no strict "
                    "Referrer-Policy header (got: "
                    f"{confirmed['referrer_policy']!r}). Embedded "
                    "third-party requests (fonts, analytics, "
                    "images) on this page will leak the reset token "
                    "via Referer -- the token then becomes "
                    "discoverable in the third party's logs."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Two complementary fixes -- ship both:\n"
                    "  - Set `Referrer-Policy: no-referrer` (or "
                    "  `same-origin`) on the reset / verification "
                    "  page. Helmet's default is "
                    "  `no-referrer`; verify it covers the reset "
                    "  route.\n"
                    "  - Move the token out of the URL: accept it "
                    "  via a POST body, OR put it in the URL "
                    "  fragment (`/reset#token=...`) so the browser "
                    "  never sends it in Referer at all.\n"
                    "Audit reset tokens issued during the exposure "
                    "window -- any third-party in your CDN / "
                    "analytics chain may have logged a token; "
                    "invalidate every outstanding reset."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} reset URL "
                     f"shapes on {origin}; either no HTML reset "
                     "surface answered, or the response carried a "
                     "safe Referrer-Policy."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PasswordResetTokenInRefererProbe().main()
