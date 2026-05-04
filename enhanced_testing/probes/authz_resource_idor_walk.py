#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: per-resource IDOR via sequential id walk on any
`/api/<resource>/<id>`-shape endpoint.

Generalises the rounds-3-4 family of basket / address / order /
feedback IDOR probes. The bug pattern is identical across all of
those: the controller accepts an integer id in the URL and returns
the matching record without verifying the caller owns it. The
literal resource name is irrelevant -- baskets, orders, addresses,
invoices, projects, files, tickets all share the same code shape
and the same vulnerability profile.

High-fidelity signal:
  Register two throwaway accounts (A and B). As B, walk
  `/api/<resource>/{1..N}`. Validate when the response carries an
  owner identifier (UserId, ownerId, owner_id, customerId, user)
  that's neither B's id nor null/empty -- proof that B is reading
  someone else's record.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Resource name templates. {r} = resource, {id} = numeric id.
PATH_TEMPLATES = (
    "/api/{r}/{id}",
    "/api/v1/{r}/{id}",
    "/rest/{r}/{id}",
)

# Common owned-resource names. We test a handful of
# capitalisations because a /api/baskets vs /api/Baskets shape
# difference is exactly what scanners miss.
RESOURCES = (
    "baskets", "Baskets", "basket",
    "orders", "Orders",
    "addresses", "Addresses", "Addresss",   # the trailing typo
                                              # is Juice Shop's;
                                              # also seen in real
                                              # apps with copy-paste
                                              # schema bugs.
    "invoices", "Invoices",
    "projects", "Projects",
    "files", "Files",
    "documents", "tickets",
    "subscriptions", "favorites",
)

OWNER_FIELDS = ("UserId", "userId", "user_id", "ownerId", "owner_id",
                 "owner", "customerId", "customer_id", "user",
                 "createdBy", "created_by", "authorId")


def _register(client: SafeClient, origin: str
              ) -> tuple[str | None, int | None, dict]:
    email = f"idor-walk-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    uid = None
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            if isinstance(data, dict):
                uid = data.get("id")
        except json.JSONDecodeError:
            pass
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = ((doc.get("authentication") or {}).get("token")
                   if isinstance(doc, dict) else None) or doc.get("token")
            if tok:
                return tok, uid, diag
        except json.JSONDecodeError:
            pass
    return None, uid, diag


def _extract_owner(node, depth: int = 0) -> tuple[str, object] | None:
    """Walk JSON for any OWNER_FIELDS key with a non-null value."""
    if depth > 4:
        return None
    if isinstance(node, dict):
        for k, v in node.items():
            if (isinstance(k, str) and k in OWNER_FIELDS
                    and v not in (None, "", 0)):
                return k, v
        for v in node.values():
            hit = _extract_owner(v, depth + 1)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node[:20]:
            hit = _extract_owner(v, depth + 1)
            if hit:
                return hit
    return None


class AuthzResourceIdorWalkProbe(Probe):
    name = "authz_resource_idor_walk"
    summary = ("Detects per-resource IDOR by walking sequential ids on "
               "common `/api/<resource>/<id>`-shape endpoints as a "
               "throwaway non-admin user.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--resource", action="append", default=[],
            help="Additional resource name to walk.")
        parser.add_argument(
            "--max-id", type=int, default=8)

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        resources = list(RESOURCES) + list(args.resource or [])
        max_id = max(2, int(args.max_id or 8))

        token, own_id, diag = _register(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not register on {origin} "
                         f"({diag.get('register_status')} / "
                         f"{diag.get('login_status')})."),
                evidence={"origin": origin, "session": diag},
            )

        attempts: list[dict] = []
        confirmed: list[dict] = []
        # Quick resource-existence pre-walk: try ?id=1 against each
        # resource on each template; only continue with the
        # combinations that returned 200 with JSON.
        live: list[tuple[str, str]] = []
        for tpl in PATH_TEMPLATES:
            for r_name in resources:
                url = urljoin(origin, tpl.format(r=r_name, id=1))
                rr = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}"})
                if rr.status == 200 and rr.body:
                    try:
                        json.loads(rr.text)
                        live.append((tpl, r_name))
                    except (ValueError, json.JSONDecodeError):
                        continue
        # Now walk ids 2..max_id on each live combination, stopping
        # on first foreign-id hit per combination.
        for tpl, r_name in live:
            for uid in range(2, max_id + 1):
                if own_id is not None and uid == own_id:
                    continue
                url = urljoin(origin, tpl.format(r=r_name, id=uid))
                rr = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}"})
                row: dict = {"path": url, "id": uid,
                             "status": rr.status, "size": rr.size}
                if rr.status == 200 and rr.body:
                    try:
                        doc = json.loads(rr.text)
                    except (ValueError, json.JSONDecodeError):
                        doc = None
                    if doc is not None:
                        owner = _extract_owner(doc)
                        if owner:
                            ofield, oval = owner
                            # Foreign ownership = oval not equal to
                            # our own user id.
                            if (own_id is None
                                    or str(oval) != str(own_id)):
                                row.update({"owner_field": ofield,
                                             "owner_value": oval})
                                confirmed.append(row)
                                attempts.append(row)
                                break
                attempts.append(row)
            if len(confirmed) >= 3:
                break

        evidence = {"origin": origin, "own_user_id": own_id,
                    "session": diag, "live_combinations": live,
                    "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: per-resource IDOR on {origin}. As "
                    f"throwaway user {own_id}, GET {top['path']} "
                    f"returned a record with `{top['owner_field']}`="
                    f"{top['owner_value']!r} (foreign owner). "
                    f"{len(confirmed)} foreign id(s) accessible."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Enforce ownership at the controller layer:\n"
                    "  - The id in the URL must equal the authenticated "
                    "caller's id, OR the caller must hold an admin role.\n"
                    "  - Express: in the route handler, "
                    "`if (record.userId !== req.user.id && !req.user.isAdmin) "
                    "return res.status(403)`.\n"
                    "  - Django REST: override `get_queryset()` to "
                    "filter by `self.request.user`.\n"
                    "  - Spring: `@PreAuthorize` annotation comparing "
                    "`#id == authentication.principal.id`.\n"
                    "Audit access logs for sequential id enumeration "
                    "patterns on the affected endpoint."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: walked ids 2-{max_id} across "
                     f"{len(live)} live resource paths on {origin}; "
                     "no foreign-owner record was returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthzResourceIdorWalkProbe().main()
