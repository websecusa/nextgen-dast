#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: server accepts a session id supplied via URL query
string (session-fixation primitive distinct from no-rotation).

Some legacy frameworks (older Servlet containers via URL rewriting,
ASP classic, PHP `session.use_trans_sid=1`) read JSESSIONID /
PHPSESSID / ASP.NET_SessionId from the query string and bind that
id to whatever session the request creates. An attacker who emails
a victim a link with `?JSESSIONID=ATTACKER` pre-seeds the victim's
session with an id the attacker already holds; the moment the
victim authenticates, the attacker rides into the authenticated
session.

The high-fidelity signal: send a request with `?<sessname>=<known>`
to the homepage; observe whether the server (a) issues a
Set-Cookie that echoes our supplied value back, OR (b) accepts the
URL-supplied id without complaint and reflects it in any subsequent
state. A server that ignores or replaces the URL-supplied id is
safe.

We do NOT log in or mutate state — we just look for the binding to
form. That's enough to distinguish a vulnerable URL-rewriting
config from a hardened one.

Detection signal:
  At least one query-string-supplied session name is reflected back
  by the server (Set-Cookie value matches the value we put in the
  URL, OR the server's response includes a session marker that
  echoes our id).
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Session names known to be honored as URL parameters by various
# legacy stacks. Keep this list short and well-known to avoid
# matching unrelated query parameters.
URL_SESSION_NAMES = (
    "JSESSIONID",
    "PHPSESSID",
    "ASPSESSIONID",
    "ASP.NET_SessionId",
    "CFID",
    "CFTOKEN",
)


def _parse_set_cookies(headers: dict) -> dict:
    """Same shape as auth_session_fixation_no_rotation — splits a
    flattened Set-Cookie header on newlines and into name/value."""
    out: dict = {}
    for k, v in (headers or {}).items():
        if k.lower() != "set-cookie":
            continue
        for piece in re.split(r"\n", str(v)):
            piece = piece.strip()
            if not piece:
                continue
            kv = piece.split(";", 1)[0]
            if "=" in kv:
                name, val = kv.split("=", 1)
                out[name.strip()] = val.strip()
    return out


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 12:
        return val[:2] + "*" * max(0, len(val) - 4) + val[-2:]
    return val[:6] + "*" * (len(val) - 10) + val[-4:]


class AuthSessionIdInUrlAcceptedProbe(Probe):
    name = "auth_session_id_in_url_accepted"
    summary = ("Detects servers that accept a session id supplied via "
               "URL query string (URL rewriting / trans-sid).")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args beyond the inherited --url; the
        # session-name list is intentionally fixed to known stacks.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for sname in URL_SESSION_NAMES:
            # A distinctive, attacker-shaped sentinel value. If the
            # server echoes THIS exact value back into a Set-Cookie
            # or session marker, we know it's honoring the URL
            # parameter.
            sentinel = "dast" + secrets.token_hex(12)
            url = urljoin(origin, "/") + f"?{sname}={sentinel}"
            r = client.request("GET", url, follow_redirects=False)
            row: dict = {
                "session_name": sname,
                "supplied_value_masked": _mask(sentinel),
                "status": r.status,
                "size": r.size,
            }
            cookies = _parse_set_cookies(r.headers or {})
            # Two signals we accept as confirmation:
            #   1. Server issues Set-Cookie with our exact sentinel
            #      value bound to the named cookie (URL-to-cookie
            #      promotion).
            #   2. Server reflects our sentinel value in a Set-Cookie
            #      keyed by a related name.
            echoed = False
            echoed_into = None
            if sname in cookies and cookies[sname] == sentinel:
                echoed = True
                echoed_into = sname
            else:
                # Case-insensitive match for header-name quirks
                # (ASP.NET_SessionId vs ASPNET_SessionId etc.).
                for ck, cv in cookies.items():
                    if cv == sentinel:
                        echoed = True
                        echoed_into = ck
                        break
            row["server_set_cookies"] = list(cookies.keys())
            row["echoed_back"] = echoed
            row["echoed_into_cookie"] = echoed_into
            attempts.append(row)
            if echoed:
                confirmed.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: {origin} accepts URL-supplied session "
                    f"id `{top['session_name']}` and binds it to "
                    f"`{top['echoed_into_cookie']}` in Set-Cookie. "
                    "An attacker who plants a link with a known id "
                    "into the victim's browser fixates the session "
                    "before login."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable URL session-id propagation. "
                    "PHP: set `session.use_only_cookies=1` and "
                    "`session.use_trans_sid=0` in php.ini. "
                    "Servlet containers (Tomcat, Jetty): set "
                    "`<tracking-mode>COOKIE</tracking-mode>` in "
                    "web.xml's `<session-config>`. ASP classic: "
                    "rewrite the auth flow to disregard query-string "
                    "session ids and rotate the cookie on login. "
                    "Always rotate the session id at the auth "
                    "boundary (covered by auth_session_fixation_no_rotation)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(URL_SESSION_NAMES)} known "
                     f"URL session names against {origin}; none were "
                     "echoed back into Set-Cookie."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthSessionIdInUrlAcceptedProbe().main()
