#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Clickjacking: sensitive page lacks both `X-Frame-Options` and CSP
`frame-ancestors`.

Different from the existing `config_hsts_missing` probe (which
checks HSTS only). This probe checks the two anti-iframe headers --
either is sufficient on its own; the absence of BOTH means the
page can be wrapped in an attacker-controlled iframe and the user's
clicks routed to the attacker's chosen targets. On a login page or
profile-edit page the impact is account takeover with one click.

The high-fidelity signal is structural: parse the response headers,
look for an `X-Frame-Options` value of `DENY` or `SAMEORIGIN`, OR a
CSP `frame-ancestors` directive. If neither is present on a 200
response from a sensitive path, validate.

Detection signal:
  GET each of `/`, `/login`, `/register`, `/profile`,
  `/profile/change-password`, `/admin`. For each 200 response,
  parse XFO and CSP. Validate when XFO is absent / non-restrictive
  AND CSP either absent or missing `frame-ancestors`.

Tested against:
  + OWASP Juice Shop  Sets X-Frame-Options: SAMEORIGIN -> validated=False.
  + Apps relying on a CSP without frame-ancestors but with no XFO
    -> validated=True.

Read-only: GET only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SENSITIVE_PATHS = (
    "/",
    "/login",
    "/register",
    "/profile",
    "/profile/change-password",
    "/admin",
    "/account",
)

# X-Frame-Options values that adequately restrict framing. Anything
# else (e.g. ALLOW-FROM, an empty value, or a missing header) is
# the bug.
_VALID_XFO = {"DENY", "SAMEORIGIN"}

_FRAME_ANCESTORS_RE = re.compile(r"\bframe-ancestors\b\s+([^;]+)", re.I)


def _xfo_value(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "x-frame-options":
            return str(v).strip().upper()
    return ""


def _csp_value(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-security-policy":
            return str(v)
    return ""


def _frame_ancestors_restrictive(csp: str) -> tuple[bool, str]:
    """Return (restrictive, value). 'restrictive' means the CSP
    forbids generic third-party framing -- the value isn't `*` or
    `'self' *`."""
    m = _FRAME_ANCESTORS_RE.search(csp)
    if not m:
        return False, ""
    val = m.group(1).strip()
    # Any non-empty source list other than `*` is restrictive
    # enough; a sole `'none'` or `'self'` is the canonical fix.
    if "*" in val.split():
        return False, val
    if val.lower() in ("'none'", "'self'") or val.startswith("'"):
        return True, val
    # Origin allowlist (e.g. `https://app.example`) is also
    # restrictive (browsers refuse other framers).
    return True, val


class ClickjackingFrameAncestorsProbe(Probe):
    name = "config_clickjacking_frame_ancestors"
    summary = ("Detects pages framable into a clickjacking iframe "
               "because both X-Frame-Options and CSP frame-ancestors "
               "are absent / non-restrictive.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional sensitive path (e.g. '/wallet'). Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(SENSITIVE_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, follow_redirects=False)
            if r.status not in (200, 301, 302, 303, 307, 308):
                attempts.append({"path": p, "status": r.status})
                continue
            xfo = _xfo_value(r.headers or {})
            csp = _csp_value(r.headers or {})
            xfo_ok = xfo in _VALID_XFO
            csp_ok, fa_val = _frame_ancestors_restrictive(csp)
            row: dict = {"path": p, "status": r.status,
                         "xfo": xfo or None, "xfo_ok": xfo_ok,
                         "csp_present": bool(csp),
                         "frame_ancestors": fa_val or None,
                         "csp_ok": csp_ok}
            if r.status == 200 and not xfo_ok and not csp_ok:
                row["framable"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} can be "
                    f"wrapped in a third-party iframe -- "
                    f"X-Frame-Options is "
                    f"{confirmed['xfo'] or 'absent'} and CSP "
                    f"frame-ancestors is "
                    f"{confirmed['frame_ancestors'] or 'absent'}. "
                    "An attacker page can click-jack interactions on "
                    "this page (account-takeover risk on login / "
                    "password-change / admin surfaces)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Set one of the two anti-iframe headers on every "
                    "sensitive page (both is fine).\n"
                    "  - X-Frame-Options: DENY    (no framing at all), or\n"
                    "  - X-Frame-Options: SAMEORIGIN (only same-origin "
                    "framing), or\n"
                    "  - Content-Security-Policy: frame-ancestors 'self' "
                    "(modern, supersedes XFO).\n"
                    "Apply globally via the framework's response-headers "
                    "middleware (helmet for Express, "
                    "django.middleware.clickjacking, "
                    "ActionDispatch::Headers for Rails). Add a "
                    "regression test that fetches the affected page and "
                    "asserts at least one of the headers is present.\n"
                    "Audit the page's interaction surface: any one-click "
                    "state change (password change, email change, "
                    "purchase confirm) should also have a confirmation "
                    "step that the click-jacked user couldn't complete "
                    "blindly."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} sensitive paths "
                     f"on {origin}; each carried either a restrictive "
                     "X-Frame-Options or a CSP frame-ancestors directive."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClickjackingFrameAncestorsProbe().main()
