#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Excessive data exposure: a public / authenticated feed endpoint
serializes nested User objects with password hashes, email
addresses, and role information for accounts that posted the items.

The OWASP Juice Shop /rest/memories endpoint is the canonical case:
any authenticated user can GET it and receive a JSON array whose
elements include `User: { id, email, password, role, deluxeToken }`
for every memory's author. The bug is in the response serializer
(eager-loaded ORM association returned as-is) rather than the access
control -- the endpoint is supposed to be visible, but the nested
User objects should be reduced to a public profile (username +
profileImage at most) before serialization.

Probe strategy:
  1. Register a fresh low-privilege customer user.
  2. GET a small catalog of feed-style endpoints.
  3. For each successful 200 + JSON-array response, walk the rows
     looking for a `User`-shaped nested object that contains AT LEAST
     ONE sensitive field (password hash, role, deluxeToken,
     totpSecret).
  4. Emit a high finding when a nested User object exposes ANY
     sensitive field. The presence of a single hash leaking through a
     normal-looking feed endpoint is decisive evidence the serializer
     is shipping the full ORM object.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

CANDIDATE_PATHS = (
    "/rest/memories",
    "/api/memories",
    "/rest/feed",
    "/api/feed",
    "/rest/activity",
    "/api/activity",
    "/api/posts",
    "/api/photos",
    "/api/stories",
)
SENSITIVE_USER_FIELDS = (
    "password", "deluxeToken", "totpSecret", "role",
    "lastLoginIp", "lastLoginTime", "securityAnswer")


def _register_login(client: SafeClient, origin: str) -> tuple[str | None, dict]:
    email = f"memexp-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    diag = {"email": email}
    client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({
            "email": email, "password": pw, "passwordRepeat": pw,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode())
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({"email": email, "password": pw}).encode())
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = (doc.get("authentication") or {}).get("token")
            if tok:
                return tok, diag
        except json.JSONDecodeError:
            pass
    return None, diag


def _walk_for_nested_user(node) -> dict | None:
    """Depth-first scan of the parsed JSON looking for a nested
    `User`-shaped object that carries at least one SENSITIVE_USER_FIELDS
    member. Returns the offending object (or None)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("User", "user", "Author", "author", "Owner",
                     "owner") and isinstance(v, dict):
                exposed = sorted(
                    [f for f in SENSITIVE_USER_FIELDS if f in v])
                # Mask the actual value -- we only want the field name.
                if exposed:
                    return {"key": k, "fields": exposed,
                            "id_seen": v.get("id"),
                            "email_seen": v.get("email"),
                            "role_seen": v.get("role")}
            hit = _walk_for_nested_user(v)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node:
            hit = _walk_for_nested_user(v)
            if hit:
                return hit
    return None


class InfoMemoriesExposesNestedUserPiiProbe(Probe):
    name = "info_memories_exposes_nested_user_pii"
    summary = ("Detects feed-shaped endpoints (memories / posts / "
               "activity) that serialize nested User objects with "
               "password hashes / role / token fields.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional candidate feed path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(CANDIDATE_PATHS) + list(args.path or [])

        token, diag = _register_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": diag},
            )

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}"})
            row = {"path": p, "url": url,
                   "status": r.status, "size": r.size}
            if r.status != 200 or not r.body:
                attempts.append(row)
                continue
            try:
                doc = json.loads(r.text)
            except json.JSONDecodeError:
                attempts.append(row)
                continue
            hit = _walk_for_nested_user(doc)
            if hit:
                row["nested_user_hit"] = hit
                row["body_excerpt"] = (r.text or "")[:400]
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "session_email": diag.get("email"),
                    "attempts": attempts}
        if confirmed:
            hit = confirmed["nested_user_hit"]
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: {confirmed['url']} returns a nested "
                    f"`{hit['key']}` object with sensitive fields "
                    f"({', '.join(hit['fields'])}) for at least one "
                    "non-caller account. The serializer is shipping "
                    "the eager-loaded ORM User row instead of a "
                    "public profile shape."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Replace the serializer's eager User pass-through "
                    "with an explicit public-profile shape (allowlist: "
                    "username, profileImage). In ORM terms, define a "
                    "`publicProfile` scope or a DTO that only includes "
                    "the safe columns, and use it everywhere a feed "
                    "endpoint joins to the users table. Verify with a "
                    "regression test that the response NEVER includes "
                    "the password / deluxeToken / role columns even "
                    "when the route is hit by an admin."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} feed-shaped "
                     f"path(s) on {origin}; no response contained a "
                     "nested User object with sensitive fields."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoMemoriesExposesNestedUserPiiProbe().main()
