#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Stored XSS via attacker-controlled request headers persisted into
the user record / audit log / dashboard.

Generalises `xss_stored_lastloginip` (which targets Juice Shop's
True-Client-IP -> user.lastLoginIp persistence). The same bug
shape exists in dozens of other apps: a state-recording action
(login, password change, comment post, support-ticket open) reads
a request header (True-Client-IP, X-Forwarded-For, Referer,
User-Agent, X-Real-IP) and stores it verbatim. The next
admin / user that loads the dashboard / audit log / profile renders
the stored value as HTML, executing the attacker's <iframe>.

High-fidelity signal:
  Send a state-recording action with a marker tag in one of the
  trusted request headers; then GET reflective surfaces and look
  for the marker un-HTML-escaped. The marker is a literal
  <dast-xss-marker-XXXX> tag with random suffix, so any
  un-escaped echo is unambiguous.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

INJECTION_HEADERS = (
    "True-Client-IP", "X-Forwarded-For", "Referer", "User-Agent",
    "X-Forwarded-Host",
)

# State-recording actions to attempt. (path, method, body)
STATE_ACTIONS = (
    ("/rest/user/login",     "POST",   "json"),
    ("/login",               "POST",   "json"),
    ("/rest/saveLoginIp",    "GET",    None),
    ("/api/me/lastlogin",    "GET",    None),
)

# Reflective surfaces to inspect.
VERIFY_PATHS = (
    "/api/Users",
    "/api/users", "/api/users/me", "/api/me",
    "/api/profile", "/api/account",
    "/rest/user/whoami",
    "/admin/audit", "/api/admin/audit",
    "/dashboard",
)


def _register_login(client: SafeClient, origin: str
                     ) -> tuple[str | None, dict, str, str]:
    email = f"xss-hdr-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    return None, diag, email, pw


class XssStoredViaRequestHeadersProbe(Probe):
    name = "xss_stored_via_request_headers"
    summary = ("Detects stored XSS where a trusted request header "
               "(True-Client-IP / X-Forwarded-For / Referer / etc.) "
               "is persisted into the user record or audit surface "
               "without HTML escaping.")
    safety_class = "read-only"

    def add_args(self, parser):
        # Rename to avoid colliding with the base parser's
        # `--header` (which sets extra request headers).
        parser.add_argument(
            "--inject-header", action="append", default=[],
            help="Additional injection header name to try.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers_to_try = list(INJECTION_HEADERS) + list(
            getattr(args, "inject_header", None) or [])

        marker_id = secrets.token_hex(6)
        marker = f"<dast-xss-marker-{marker_id}>"

        # Register a throwaway and capture creds (login uses them).
        _, diag, email, pw = _register_login(client, origin)
        if diag["register_status"] not in (200, 201):
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not register on "
                         f"{origin} ({diag['register_status']})."),
                evidence={"origin": origin, "session": diag},
            )

        # Trigger state-recording actions one per (action, header)
        # combo, with the marker only in that header.
        actions: list[dict] = []
        token: str | None = None
        for hdr in headers_to_try:
            for path, method, kind in STATE_ACTIONS:
                req_headers = {hdr: marker}
                body = None
                if kind == "json":
                    body = json.dumps({"email": email,
                                        "password": pw}).encode()
                    req_headers["Content-Type"] = "application/json"
                r = client.request(method,
                                    urljoin(origin, path),
                                    headers=req_headers, body=body)
                actions.append({"path": path, "method": method,
                                 "header": hdr, "status": r.status,
                                 "size": r.size})
                # Side benefit: capture token from a successful
                # login so verification can be authenticated.
                if (method == "POST" and r.status == 200 and r.body
                        and not token):
                    try:
                        doc = json.loads(r.text) or {}
                        tok = ((doc.get("authentication") or {}).get(
                            "token") if isinstance(doc, dict) else None
                        ) or doc.get("token")
                        if tok:
                            token = tok
                    except json.JSONDecodeError:
                        pass

        # Verify pass.
        verify: list[dict] = []
        confirmed: dict | None = None
        for vp in VERIFY_PATHS:
            r = client.request("GET", urljoin(origin, vp),
                                headers=({"Authorization":
                                          f"Bearer {token}"}
                                         if token else {}))
            row = {"path": vp, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and marker in r.text:
                idx = r.text.find(marker)
                row.update({"marker_un_escaped": True,
                             "snippet": r.text[max(0, idx-60):idx + len(marker) + 60]})
                confirmed = row
                verify.append(row)
                break
            verify.append(row)

        evidence = {"origin": origin, "session": diag,
                    "marker": marker, "actions": actions,
                    "verify": verify}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: stored XSS via request header on "
                    f"{origin}. The marker `{marker}` was injected via "
                    "one of the trusted request headers during a "
                    f"state-recording action and now appears un-HTML-"
                    f"escaped at {confirmed['path']}. Snippet: "
                    f"{confirmed['snippet'][:200]!r}"),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Two layers of defence:\n"
                    "  - Stop trusting the header. The Forwarded-For / "
                    "True-Client-IP family is attacker-controlled "
                    "unless your edge proxy strips and re-emits them. "
                    "Configure the edge to strip inbound values and "
                    "set them itself.\n"
                    "  - HTML-escape every output sink. Modern "
                    "frameworks (React, Angular, Django, Rails) escape "
                    "by default -- audit any explicit `dangerouslySet"
                    "InnerHTML` / `v-html` / `mark_safe` / `raw` use "
                    "on the field.\n"
                    "Pair with a strict CSP (no `'unsafe-inline'` on "
                    "`script-src`) so the HTML escape is the second of "
                    "two defences, not the only one."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(actions)} action/header "
                     f"combinations on {origin}; marker did not "
                     "appear un-escaped on any of "
                     f"{len(VERIFY_PATHS)} reflective surfaces."),
            evidence=evidence,
        )


if __name__ == "__main__":
    XssStoredViaRequestHeadersProbe().main()
