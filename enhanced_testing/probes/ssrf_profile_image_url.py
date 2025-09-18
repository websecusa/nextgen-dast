#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Server-Side Request Forgery: profile-image URL endpoint accepts an
attacker-controlled URL and stores it on the user record.

The classic SSRF surface in app code: a "set my profile picture from
a URL" feature where the server fetches the image. If the server is
willing to fetch ANY URL — including http://169.254.169.254/ (AWS
instance metadata), http://localhost:6379 (Redis), file:///etc/passwd,
or arbitrary internal RFC1918 — an attacker pivots through the
application server into the cloud control plane.

The high-fidelity finding here is that the SUPPLIED URL gets stored
on the user record verbatim. We don't need the underlying fetch to
actually hit AWS metadata for this to be a finding — the server
trusting the URL enough to persist it is the bug; the server fetching
that URL with the application's network identity is the exploitation
that follows.

Detection signal:
  1. Register a throwaway user, log in, capture JWT + user id.
  2. POST /profile/image/url with imageUrl=<distinctive marker URL>.
  3. GET /api/Users/<id>; assert response includes the supplied URL.

The marker URL is unique per run so the verdict is unambiguous.

Tested against:
  + OWASP Juice Shop  POST /profile/image/url accepts the URL and
                      stores it on user.profileImage → validated=True.
  + nginx default site → validated=False (no /profile/image/url route)
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints we'll try in order. Juice Shop's literal route is first.
PROFILE_IMAGE_PATHS = (
    "/profile/image/url",
    "/api/profile/image",
    "/api/users/me/avatar",
)
USER_ENDPOINTS = (
    "/api/Users/{id}",
    "/api/users/{id}",
    "/rest/user/whoami",
)


def _register_and_login(client: SafeClient, origin: str) -> dict:
    """Create a throwaway account and log it in. Returns a dict with
    `email`, `password`, `token`, `user_id`, plus diagnostic fields.
    Each field may be None if the corresponding step failed; the
    caller decides whether the failure is fatal."""
    email = f"ssrf-probe-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-pass-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None}

    reg_body = json.dumps({"email": email, "password": pw,
                           "passwordRepeat": pw,
                           "securityQuestion": {"id": 1},
                           "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=reg_body)
    out["register_status"] = r.status
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            uid = (data or {}).get("id") if isinstance(data, dict) else None
            if uid is None and isinstance(doc, dict):
                uid = doc.get("id")
            out["user_id"] = uid
        except json.JSONDecodeError:
            pass

    login_body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=login_body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = (doc.get("authentication") if isinstance(doc, dict)
                    else None) or {}
            tok = auth.get("token") if isinstance(auth, dict) else None
            if not tok and isinstance(doc, dict):
                tok = doc.get("token")
            out["token"] = tok
            if out["user_id"] is None and isinstance(auth, dict):
                # Juice Shop returns umail+id under authentication.umail
                out["user_id"] = auth.get("uid") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


class SsrfProfileImageUrlProbe(Probe):
    name = "ssrf_profile_image_url"
    summary = ("Detects SSRF surface where a profile-image URL endpoint "
               "stores attacker-supplied URLs on the user record.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--marker-host", default="169.254.169.254",
            help="Host to embed in the supplied imageUrl. The probe NEVER "
                 "actually requires a host that responds; we just check "
                 "whether the server stores the URL we sent.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin} (register status "
                         f"{sess.get('register_status')}, login status "
                         f"{sess.get('login_status')}). The probe needs "
                         "an authenticated session to set a profile URL."),
                evidence={"origin": origin, "session": sess},
            )
        token = sess["token"]
        marker = (f"http://{args.marker_host}/latest/meta-data/probe-"
                  f"{secrets.token_hex(6)}")

        # Try each candidate endpoint until one stores the URL.
        attempts: list[dict] = []
        for path in PROFILE_IMAGE_PATHS:
            url = urljoin(origin, path)
            # Two body shapes — form-encoded (Juice Shop's literal) and
            # JSON. First match wins.
            for ctype, body in (
                ("application/x-www-form-urlencoded",
                 urlencode({"imageUrl": marker}).encode()),
                ("application/json",
                 json.dumps({"imageUrl": marker}).encode()),
            ):
                r = client.request("POST", url, headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": ctype,
                }, body=body)
                attempts.append({"path": path, "ctype": ctype,
                                 "status": r.status, "size": r.size})
                if r.status in (200, 201, 204, 302):
                    break

        # Verify the marker is now persisted on the user record.
        verify_attempts: list[dict] = []
        confirmed: dict | None = None
        for ep in USER_ENDPOINTS:
            url = urljoin(origin, ep.replace("{id}",
                                             str(sess.get("user_id") or "")))
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}",
            })
            row = {"endpoint": url, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and marker in r.text:
                row["marker_persisted"] = True
                confirmed = row
                verify_attempts.append(row)
                break
            verify_attempts.append(row)

        evidence = {"origin": origin, "session": {k: v for k, v in
                    sess.items() if k != "password"},
                    "marker": marker,
                    "set_attempts": attempts,
                    "verify_attempts": verify_attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: SSRF surface at {origin} — the "
                         f"profile-image endpoint accepted "
                         f"{marker!r} and stored it on the user record "
                         f"(visible at {confirmed['endpoint']})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Validate the supplied URL before storing it. At "
                    "minimum:\n"
                    "  - Allow only http(s) schemes — refuse file://, "
                    "gopher://, dict://, ftp://, etc.\n"
                    "  - Resolve the hostname server-side and refuse "
                    "addresses in 169.254.0.0/16, 127.0.0.0/8, "
                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
                    "fc00::/7, ::1, fe80::/10.\n"
                    "  - Re-resolve at fetch time and refuse if the "
                    "address moved into a private range (DNS-rebinding "
                    "defense).\n"
                    "  - Fetch through an egress proxy that enforces "
                    "the same allowlist.\n"
                    "And consider whether the feature really needs to "
                    "fetch arbitrary URLs at all — accepting an upload "
                    "instead removes the entire SSRF surface."),
            )
        return Verdict(
            validated=False, confidence=0.8,
            summary=(f"Refuted: {len(attempts)} profile-image set "
                     f"attempts on {origin}; none persisted the supplied "
                     "URL on the user record."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SsrfProfileImageUrlProbe().main()
