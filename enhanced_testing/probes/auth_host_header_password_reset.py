#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: password-reset link built from request `Host` header.

Many web frameworks expose `request.host` (or `req.headers.host`)
to the password-reset email template. If the application copies that
straight into the reset URL and the operations team forgot to set a
trusted-host allowlist on the edge, an attacker triggers a reset
for the victim while smuggling `Host: dast-marker.example`. The
victim's email then contains
`https://dast-marker.example/reset?token=<TOKEN>`. The victim
clicks the link; the attacker's server records the token; account
takeover.

The high-fidelity *server-side* signal -- without intercepting the
email -- is that the application's reset-request acknowledgement
response sometimes echoes the URL it built. Even when it doesn't,
the response Location / redirect URL on a successful reset will
sometimes carry the marker host. We test both surfaces.

We register a throwaway account first so we never trigger a reset
for a real user. The reset request runs against our own throwaway
email; the response's reflection of our Host marker is the bug.

Detection signal:
  1. Register a throwaway account.
  2. POST `/rest/user/reset-password` (and friends) with body
     `{"email": <our throwaway email>, ...}` AND header
     `Host: dast-marker-XXXX.example`.
  3. Validate when the marker host string appears in the response
     body, in any response header, OR in any redirect Location.

Tested against:
  + OWASP Juice Shop  /rest/user/reset-password validates the
                      security-question answer first; it does not
                      reflect Host into the response. -> validated=False
  + Real apps with Express / Rails / Django default templates
                      built without ALLOWED_HOSTS / trustHost
                      -> validated=True.

Read-only safety: the only POSTs are the throwaway-account
registration and the reset-request against our own email. We
never trigger a reset against a real user.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

RESET_PATHS = (
    "/rest/user/reset-password",
    "/api/auth/forgot-password",
    "/api/auth/password/reset/request",
    "/api/auth/password/forgot",
    "/forgot-password",
    "/reset-password",
    "/password/reset",
)


def _register(client: SafeClient, origin: str) -> tuple[str | None, str | None, dict]:
    """Register a throwaway user; return (email, security_answer, diag).
    Email is unique per run so the reset request only ever targets the
    account we just created."""
    email = f"hostinj-probe-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    answer = "probe-answer"
    diag: dict = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": answer,
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    if r.status not in (200, 201):
        return None, None, diag
    return email, answer, diag


def _scan_for_marker(r, marker: str) -> tuple[bool, str]:
    """Return (hit, where) -- True if marker appears anywhere in
    response body or headers; `where` names which surface."""
    if r.body and marker in r.text:
        return True, "body"
    for k, v in (r.headers or {}).items():
        if marker in str(v):
            return True, f"header:{k}"
    return False, ""


class AuthHostHeaderPasswordResetProbe(Probe):
    name = "auth_host_header_password_reset"
    summary = ("Detects password-reset endpoints that build the reset "
               "URL from the request `Host` header without validation.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--reset-path", action="append", default=[],
            help="Additional password-reset endpoint to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(RESET_PATHS) + list(args.reset_path or [])

        email, answer, reg_diag = _register(client, origin)
        if not email:
            # Without registration we can't safely send a reset
            # request -- it would target a real user. Bail with
            # inconclusive.
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not register a throwaway "
                         f"account on {origin} (status "
                         f"{reg_diag.get('register_status')}); refusing "
                         "to send a reset request to an unknown email."),
                evidence={"origin": origin, "register_diag": reg_diag},
            )

        marker_host = f"dast-marker-{secrets.token_hex(6)}.example"
        body = json.dumps({
            "email": email,
            "answer": answer,             # Juice Shop's security-question shape
            "new": "DoesntMatter-" + secrets.token_hex(4),
            "repeat": "DoesntMatter-" + secrets.token_hex(4),
        }).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request(
                "POST", url, headers={
                    "Content-Type": "application/json",
                    "Host": marker_host,
                    "X-Forwarded-Host": marker_host,    # belt-and-braces
                }, body=body, follow_redirects=False)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            hit, where = _scan_for_marker(r, marker_host)
            if hit:
                row.update({"marker_reflected": True,
                            "where": where,
                            "snippet": (r.text or "")[:300]})
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "email": email,
                    "marker_host": marker_host,
                    "register_diag": reg_diag,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: password-reset endpoint at "
                    f"{origin}{confirmed['path']} reflected the smuggled "
                    f"`Host: {marker_host}` into the {confirmed['where']} "
                    "of its response. The reset URL emailed to the "
                    "victim is built from the unvalidated host header -- "
                    "an attacker can capture every reset token by "
                    "triggering resets against arbitrary email addresses."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Build the reset URL from a static, allowlisted "
                    "host -- never from `request.host` directly.\n"
                    "  - Django: enforce ALLOWED_HOSTS so Django refuses "
                    "to honour an unknown Host header AND build links "
                    "with the configured `SITE_URL`, not "
                    "`request.build_absolute_uri()`.\n"
                    "  - Rails: set `config.action_mailer.default_url_"
                    "options = { host: 'app.example.com' }` and don't "
                    "pass `request.host` to URL helpers.\n"
                    "  - Express / nodemailer: build the URL from "
                    "`process.env.PUBLIC_BASE_URL`, never `req.headers."
                    "host`.\n"
                    "  - At the edge proxy: refuse requests with an "
                    "unknown Host or X-Forwarded-Host (nginx "
                    "`server_name` strict match; Cloudflare host-check "
                    "rule).\n"
                    "Audit reset-token issuance during the exposure "
                    "window -- any token may have been delivered to an "
                    "attacker; invalidate them all."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} reset endpoints "
                     f"on {origin} with a marker Host header; the marker "
                     "did not appear in any response surface."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthHostHeaderPasswordResetProbe().main()
