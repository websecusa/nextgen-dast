#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Misconfiguration: HTTP Basic auth on a plaintext (non-TLS) URL.

Basic auth ships every authenticated request's credentials as
base64 in the Authorization header. Over HTTPS that's tolerable
(the wire is encrypted). Over plain HTTP it means anyone on the
same Wi-Fi, the same hop, or anywhere on the path can decode the
credentials with one base64-decode -- the credential leaks every
request, not just on login.

The high-fidelity signal is two-part:
  1. The probed URL's scheme is `http://` (not `https://`).
  2. A response from a candidate path returns
     `WWW-Authenticate: Basic ...`, indicating the server expects
     the client to ship Basic credentials.

Detection signal:
  Confirm the input URL's scheme is http. GET each of `/`,
  `/admin`, `/manager`, `/jenkins`, `/grafana`, `/prometheus`,
  `/wp-admin`, `/api`, `/private`. Validate when any response
  carries `WWW-Authenticate: Basic`.

Tested against:
  + OWASP Juice Shop  No Basic realms -> validated=False.
  + Apps fronted by stale Jenkins / Tomcat / phpMyAdmin / nginx
    Basic-auth blocks served over plain HTTP -> validated=True.

Read-only: GET only. No credentials submitted.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/",
    "/admin",
    "/admin/",
    "/manager",
    "/manager/html",
    "/jenkins",
    "/grafana",
    "/prometheus",
    "/wp-admin",
    "/wp-admin/",
    "/api",
    "/private",
    "/internal",
    "/protected",
    "/.htaccess",
)


def _basic_realm(headers: dict) -> str | None:
    """Return the realm of any `WWW-Authenticate: Basic ...` header,
    or None when no Basic challenge is present."""
    for k, v in (headers or {}).items():
        if k.lower() != "www-authenticate":
            continue
        s = str(v).strip()
        if s.lower().startswith("basic"):
            return s
    return None


class BasicAuthOverHttpProbe(Probe):
    name = "config_basic_auth_over_http"
    summary = ("Detects HTTP Basic auth realms served over plaintext "
               "HTTP -- credentials leak in every request.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to probe. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        scheme = (parsed.scheme or "").lower()
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if scheme != "http":
            return Verdict(
                validated=False, confidence=0.90,
                summary=(f"Refuted: scope URL scheme is {scheme!r}, not "
                         "http. Basic-over-plaintext only applies to "
                         "http:// URLs."),
                evidence={"origin": origin, "scheme": scheme},
            )

        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, follow_redirects=False)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            realm = _basic_realm(r.headers or {})
            if realm:
                row.update({"www_authenticate": realm,
                            "basic_realm_present": True})
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "scheme": scheme,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: HTTP Basic realm at "
                    f"{origin}{confirmed['path']} (header: "
                    f"`{confirmed['www_authenticate']}`) is served "
                    "over plaintext http://. Every authenticated "
                    "request leaks the credentials in plain base64 "
                    "to anyone on the network path."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Move the realm behind TLS, or replace Basic with "
                    "a session-cookie / token auth flow.\n"
                    "  - At the edge: serve the affected vhost over "
                    "HTTPS only (`listen 443 ssl;` in nginx; "
                    "auto-redirect 80 -> 443). Add HSTS so subsequent "
                    "browser visits stay encrypted.\n"
                    "  - Replace Basic auth on Jenkins / Grafana / "
                    "phpMyAdmin etc. with their built-in form login + "
                    "session cookies; the cookie can carry "
                    "`Secure; HttpOnly; SameSite=Strict` flags that "
                    "Basic can't.\n"
                    "  - If Basic is mandatory (some legacy clients "
                    "require it), at minimum move the entire realm "
                    "off-network (VPN-only ingress)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} paths on {origin}; "
                     "none returned a `WWW-Authenticate: Basic` header."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BasicAuthOverHttpProbe().main()
