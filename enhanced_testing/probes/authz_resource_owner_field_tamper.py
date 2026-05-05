#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: resource ownership manipulation via owner_id field
tamper.

Many REST APIs accept a writable `owner_id` / `userId` / `user_id`
field on PUT/PATCH and let the client overwrite it without a server-
side check that the new owner is the caller (or that the caller has
permission to reassign ownership). The classic exploit: user A
creates resource X; user B PUTs `{ owner_id: A }` against a resource
B owns, hoping the server will hand it to A — or, more interestingly,
B PUTs against A's resource and silently steals it.

This probe operationalizes the safer half: have B *give away* one of
B's own resources to A by setting owner_id=A in a PUT. Three
corroborating signals must all line up before we declare the bug:

  1. PUT response is 200 / 204 (silent success) AND there's no
     server-side rejection of the field.
  2. Subsequent GET of the resource as A succeeds AND the response
     shows A as the new owner.
  3. Subsequent GET of the same resource by B (the original owner)
     either fails (403/404) or returns a record whose owner_id is
     no longer B.

Two throwaway accounts are created at probe startup; we don't ask
the operator to provide credentials, and we don't reuse the same
accounts across runs. The probe target endpoints are typed
generically (`/api/baskets/{id}`, `/api/notes/{id}`, etc.) so it
works on common Juice-Shop-style test targets.

Detection signal:
  PUT-as-B with owner_id=A returns success AND GET-as-A returns the
  resource AND GET-as-B no longer shows B as owner.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Resource endpoints we'll try in order. The probe creates a
# resource via POST, then tampers via PUT. We use the first endpoint
# that successfully accepts a POST and returns an id.
RESOURCE_ENDPOINTS = (
    # (list_path, item_path_template, post_body_extras)
    ("/api/Feedbacks",   "/api/Feedbacks/{id}",
     {"comment": "probe", "rating": 1}),
    ("/api/notes",       "/api/notes/{id}",
     {"title": "probe", "body": "probe note"}),
    ("/api/items",       "/api/items/{id}",
     {"name": "probe", "description": "probe item"}),
)

# Field names that commonly carry the owner reference. We try each
# in turn against the same resource. Mostly a coverage matter — most
# stacks pick exactly one.
OWNER_FIELDS = ("owner_id", "ownerId", "user_id", "userId", "UserId")


def _register_and_login(client: SafeClient, origin: str,
                         tag: str) -> dict:
    """Create a fresh account; return {token, user_id, email, …}."""
    email = f"owner-tamper-{tag}-{secrets.token_hex(5)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "tag": tag,
                 "token": None, "user_id": None}
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
            out["user_id"] = (auth.get("uid") or auth.get("id")
                              or auth.get("UserId"))
        except json.JSONDecodeError:
            pass
    return out


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}",
            "Content-Type": "application/json"}


def _create_resource(client: SafeClient, origin: str,
                      token: str) -> dict | None:
    """Try each candidate endpoint until one returns a created
    resource id. Returns {endpoint, item_template, id, body} or None."""
    for list_path, item_template, extras in RESOURCE_ENDPOINTS:
        body = dict(extras)
        r = client.request("POST", urljoin(origin, list_path),
                           headers=_bearer(token),
                           body=json.dumps(body).encode())
        if r.status not in (200, 201) or not r.body:
            continue
        try:
            doc = json.loads(r.text) or {}
        except json.JSONDecodeError:
            continue
        node = doc.get("data") if isinstance(doc, dict) else None
        node = node if isinstance(node, dict) else doc
        rid = node.get("id") if isinstance(node, dict) else None
        if rid is not None:
            return {"list_path": list_path, "item_template": item_template,
                    "id": rid, "post_body": body, "post_response": node}
    return None


def _get_resource_owner(client: SafeClient, url: str,
                         token: str) -> tuple[int, object]:
    """GET a resource by URL with a bearer token; return
    (status, owner_value-or-None). owner_value is whichever owner-ish
    field the body contains, normalized to a string for comparison."""
    r = client.request("GET", url, headers=_bearer(token))
    owner = None
    try:
        doc = json.loads(r.text or "")
    except (ValueError, json.JSONDecodeError):
        return r.status, None
    node = doc.get("data") if isinstance(doc, dict) else None
    node = node if isinstance(node, dict) else doc
    if isinstance(node, dict):
        for f in OWNER_FIELDS:
            if f in node and node[f] is not None:
                owner = node[f]
                break
    return r.status, owner


class ResourceOwnerFieldTamperProbe(Probe):
    name = "authz_resource_owner_field_tamper"
    summary = ("Detects writable owner_id field: a non-admin caller "
               "can transfer a resource to another user via PUT.")
    safety_class = "probe"

    def add_args(self, parser):
        # Probe creates its own throwaway accounts; no flags needed
        # for the common case. Operator can pass extra resource paths
        # via env/headers if they want to override.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: two fresh accounts.
        a = _register_and_login(client, origin, "a")
        b = _register_and_login(client, origin, "b")
        if not a.get("token") or not b.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: could not establish two "
                         f"probe accounts on {origin} "
                         f"(a={a.get('login_status')}, "
                         f"b={b.get('login_status')})."),
                evidence={"origin": origin,
                           "user_a_login_status": a.get("login_status"),
                           "user_b_login_status": b.get("login_status")},
            )

        # Step 2: B creates a resource. (Doing this as B keeps the
        # probe defensive: we're transferring B's own resource, not
        # tampering with someone else's data.)
        created = _create_resource(client, origin, b["token"])
        if not created:
            return Verdict(
                validated=False, confidence=0.7,
                summary=(f"Inconclusive: no candidate resource "
                         f"endpoint on {origin} accepted a POST from "
                         "the probe account; cannot demonstrate "
                         "owner-field tamper."),
                evidence={"origin": origin,
                           "user_a_email": a["email"],
                           "user_b_email": b["email"],
                           "tried_endpoints": [e[0] for e in
                                                RESOURCE_ENDPOINTS]},
            )

        item_url = urljoin(origin, created["item_template"].format(
            id=created["id"]))

        # Step 3: B PUTs the resource with owner_id pointing at A.
        # We try OWNER_FIELDS in order but stop on the first put that
        # comes back 200/204 — additional puts would be wasted budget.
        put_attempts: list[dict] = []
        successful_field: str | None = None
        for field in OWNER_FIELDS:
            put_body = dict(created["post_body"])
            put_body[field] = a["user_id"]
            r = client.request("PUT", item_url,
                               headers=_bearer(b["token"]),
                               body=json.dumps(put_body).encode())
            put_attempts.append({"field": field, "status": r.status,
                                  "size": r.size})
            if r.status in (200, 204):
                successful_field = field
                break

        if not successful_field:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: PUT against "
                         f"`{created['item_template']}` rejected "
                         f"every owner-field variant on {origin}."),
                evidence={"origin": origin, "item_url": item_url,
                           "user_a_email": a["email"],
                           "user_b_email": b["email"],
                           "put_attempts": put_attempts},
            )

        # Step 4: GET as A. If A can fetch and the body shows A as
        # the new owner, that's signal #2.
        a_status, a_owner = _get_resource_owner(client, item_url,
                                                  a["token"])
        # Step 5: GET as B. If B no longer fetches successfully OR
        # the body shows a non-B owner, that's signal #3.
        b_status, b_owner = _get_resource_owner(client, item_url,
                                                  b["token"])

        # Compare ids as strings — JWT subjects are sometimes numeric
        # in the auth response and stringified in resource bodies.
        a_id = str(a["user_id"])
        b_id = str(b["user_id"])
        a_now_owns = (a_status == 200 and a_owner is not None
                      and str(a_owner) == a_id)
        b_no_longer_owns = (
            (b_status in (401, 403, 404))
            or (b_status == 200 and b_owner is not None
                and str(b_owner) != b_id)
        )

        evidence = {
            "origin": origin,
            "user_a_email": a["email"], "user_a_id": a["user_id"],
            "user_b_email": b["email"], "user_b_id": b["user_id"],
            "resource": {"item_url": item_url,
                          "id": created["id"],
                          "endpoint": created["list_path"]},
            "put_field": successful_field,
            "put_attempts": put_attempts,
            "a_get": {"status": a_status, "owner_seen": a_owner},
            "b_get": {"status": b_status, "owner_seen": b_owner},
        }

        # Three signals required: PUT succeeded, A sees A as owner,
        # B can no longer claim B-ownership.
        if a_now_owns and b_no_longer_owns:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: resource ownership tamper on "
                         f"{origin} — PUT with `{successful_field}` "
                         f"transferred resource id={created['id']} "
                         f"from user B ({b['email']}) to user A "
                         f"({a['email']}). GET-as-A returns "
                         f"owner={a_owner}; GET-as-B status="
                         f"{b_status}."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Strip the owner / user-id field from PUT/PATCH "
                    "input on the server side. Concrete options:\n"
                    "  - Whitelist accepted fields in the request DTO; "
                    "do not bind user_id from the request body at "
                    "all.\n"
                    "  - On every write, set the owner from the "
                    "authenticated session/JWT subject and ignore any "
                    "client-supplied owner.\n"
                    "  - If reassignment is a real feature, route it "
                    "through a separate `POST /resources/{id}/transfer` "
                    "endpoint with its own authz check (typically "
                    "admin-only)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: PUT with `{successful_field}` "
                     f"returned success on {origin}, but ownership "
                     f"did not transfer (A status {a_status}, "
                     f"A owner {a_owner!r}; B status {b_status}, "
                     f"B owner {b_owner!r})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ResourceOwnerFieldTamperProbe().main()
