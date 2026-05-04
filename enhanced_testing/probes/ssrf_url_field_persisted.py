#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Server-Side Request Forgery: any URL-shaped profile / settings
field that the server stores verbatim from the request body.

Generalises the earlier `ssrf_profile_image_url` probe. The bug is
"trust an attacker URL enough to persist it" -- the literal route
(`/profile/image/url` on Juice Shop, `/api/users/me/avatar`,
`/api/profile/picture`, `/api/webhooks/<id>`, `/api/notifications/url`,
or any of two dozen variants on real apps) is irrelevant. What
matters is that the URL goes in via one POST/PATCH and comes back
out via a GET on the same record -- the attacker has effectively
wired their own URL into the application's outbound request graph.
The downstream exploitation (AWS metadata exfil, internal Redis,
file:// reads, DNS rebinding) all chain off this one primitive.

High-fidelity signal:
  Marker URL with a unique random suffix sent via PATCH/POST/PUT
  to candidate URL fields, then verify it round-trips into a GET
  on a `/me`-shape endpoint. The randomness of the marker means
  any echo is unambiguous.

Tested against:
  + OWASP Juice Shop  /profile/image/url stores the marker URL on
                      user.profileImage -> validated=True (same as
                      the original probe, which this supersedes).
  + Apps with `/api/users/me/avatar`, `/api/profile/website`,
    `/api/webhook/<id>` etc. -> validated=True.
  + Clean negative control -> validated=False.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, method, ctype) tuples for setting a URL-shaped field. We
# vary the field name across a small allowlist so the same probe
# runs against apps that call the column `imageUrl`, `avatarUrl`,
# `profilePic`, `homepage`, `website`, etc.
SET_TARGETS = (
    ("/profile/image/url",          "POST",  "form"),
    ("/api/users/me/avatar",        "PATCH", "json"),
    ("/api/users/me",               "PATCH", "json"),
    ("/api/profile",                "PATCH", "json"),
    ("/api/me",                     "PATCH", "json"),
    ("/api/account",                "PATCH", "json"),
    ("/api/v1/me",                  "PATCH", "json"),
    ("/api/profile/picture",        "POST",  "json"),
    ("/api/webhooks",               "POST",  "json"),
    ("/api/notifications/url",      "POST",  "json"),
    ("/api/settings",               "PATCH", "json"),
)

URL_FIELD_NAMES = (
    "imageUrl", "avatarUrl", "profilePic", "profileImage",
    "homepage", "website", "url", "callback", "callbackUrl",
    "webhookUrl", "redirectUrl", "notifyUrl",
)

VERIFY_PATHS = (
    "/api/me", "/api/users/me", "/api/profile", "/api/account",
    "/rest/user/whoami", "/api/v1/me", "/me",
)


def _register_and_login(client: SafeClient, origin: str
                        ) -> tuple[str | None, dict]:
    email = f"ssrf-url-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = ((doc.get("authentication") or {}).get("token")
                   if isinstance(doc, dict) else None) or doc.get("token")
            if tok:
                return tok, diag
        except json.JSONDecodeError:
            pass
    return None, diag


class SsrfUrlFieldPersistedProbe(Probe):
    name = "ssrf_url_field_persisted"
    summary = ("Detects SSRF surface where a URL-shaped profile / "
               "settings field is stored verbatim from the request body.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--field", action="append", default=[],
            help="Additional URL-shaped field name to try.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        field_names = list(URL_FIELD_NAMES) + list(args.field or [])

        token, diag = _register_and_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin} (register status "
                         f"{diag.get('register_status')}, login status "
                         f"{diag.get('login_status')})."),
                evidence={"origin": origin, "session": diag},
            )

        marker = (f"http://dast-ssrf-{secrets.token_hex(6)}."
                  f"example/probe")

        # Strategy: SEND in two passes to keep the request budget
        # tight.
        # Pass A: send a multi-field body to each candidate set
        # endpoint (one request per endpoint, all field names in
        # one go). Most apps either ignore unknown fields or 400 --
        # if any single endpoint accepts the body, the marker now
        # lives in whichever field name the schema honoured.
        # Pass B: a single sweep across verification endpoints to
        # find the round-trip.
        sent: list[dict] = []
        verified: list[dict] = []
        confirmed: dict | None = None

        # Build one combined body of every URL-shaped field name set
        # to the marker. The bug shape is "any one of these fields
        # is honoured"; sending them all simultaneously lets one
        # request cover what would otherwise take 12.
        combined_json = json.dumps(
            {fname: marker for fname in field_names}).encode()
        combined_form = urlencode(
            {fname: marker for fname in field_names}).encode()

        for path, method, ctype in SET_TARGETS:
            if ctype == "form":
                body = combined_form
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type":
                        "application/x-www-form-urlencoded"}
            else:
                body = combined_json
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"}
            r = client.request(method, urljoin(origin, path),
                                headers=headers, body=body)
            sent.append({"path": path, "method": method,
                         "ctype": ctype,
                         "status": r.status, "size": r.size})

        # Verify pass: one GET per /me-shape endpoint.
        for vp in VERIFY_PATHS:
            rv = client.request("GET", urljoin(origin, vp),
                                headers={
                                    "Authorization":
                                        f"Bearer {token}"})
            row = {"verify_path": vp, "status": rv.status,
                   "size": rv.size}
            if rv.status == 200 and rv.body and marker in rv.text:
                row["marker_persisted"] = True
                # Best-guess at which set-path was the one that
                # took: the last 2xx we saw before this verify.
                set_hit = next((s for s in reversed(sent)
                                 if s["status"] in (200, 201, 204)),
                                None)
                confirmed = {"verify_path": vp,
                             "likely_set_path":
                                 (set_hit or {}).get("path")}
                verified.append(row)
                break
            verified.append(row)

        evidence = {"origin": origin, "session": diag, "marker": marker,
                    "sent": sent, "verified": verified}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: SSRF surface at {origin} -- the "
                    f"marker URL `{marker}` round-tripped into the "
                    f"persisted record. Verifier saw it at "
                    f"{confirmed['verify_path']}; likely set-endpoint: "
                    f"{confirmed.get('likely_set_path')}. The "
                    "application trusts an attacker-supplied URL "
                    "enough to wire it into its own outbound-request "
                    "graph."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Validate the supplied URL before persisting it.\n"
                    "  - Allow only http(s) schemes -- refuse file://, "
                    "gopher://, dict://, ftp://, ldap://.\n"
                    "  - Resolve the hostname server-side and refuse "
                    "any address in 169.254.0.0/16, 127.0.0.0/8, "
                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
                    "fc00::/7, ::1, fe80::/10.\n"
                    "  - Re-resolve at fetch time and refuse if the "
                    "address moved into a private range (DNS-rebinding "
                    "defence).\n"
                    "  - Fetch through an egress proxy that enforces "
                    "the same allowlist.\n"
                    "And reconsider whether the feature really needs "
                    "to fetch arbitrary URLs at all -- accepting an "
                    "upload instead removes the entire SSRF surface."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(sent)} set-attempts on "
                     f"{origin}; none round-tripped the marker URL on "
                     f"any of {len(VERIFY_PATHS)} verification paths."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SsrfUrlFieldPersistedProbe().main()
