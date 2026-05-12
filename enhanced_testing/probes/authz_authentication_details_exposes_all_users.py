#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Vertical authorization bypass: /rest/user/authentication-details
returns the full user directory (including authentication metadata
for every account) to any authenticated caller, regardless of role.

The endpoint name implies a per-caller view of authentication state
(my deluxeToken, my lastLoginIp, my totpSecret-presence). In reality
Juice Shop (and several similar e-commerce stacks) implement this as
an unrestricted SELECT over the users table and serialise every row,
including admin accounts and password hashes (sometimes masked,
sometimes not).

Probe strategy:
  1. Register a fresh low-privilege customer user.
  2. GET /rest/user/authentication-details with that token.
  3. If the response is a JSON array of user objects with >= 2
     distinct ids and includes admin-flavoured fields
     (deluxeToken / totpSecret / role=admin), emit a high finding.

The same shape catches several non-Juice-Shop stacks that ship a
similar "give me everyone's auth state" endpoint -- the probe path
is parameterised so operators can add their own variants.
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
    "/rest/user/authentication-details",
    "/api/user/authentication-details",
    "/api/users/authentication-details",
    "/rest/admin/authentication-details",
    "/api/user/auth-details",
)
SENSITIVE_FIELDS = (
    "deluxeToken", "totpSecret", "password", "lastLoginIp",
    "lastLoginTime", "role", "isActive", "securityQuestion",
    "securityAnswer", "id", "email")


def _register_login(client: SafeClient, origin: str) -> tuple[str | None, dict]:
    email = f"authdetail-{secrets.token_hex(6)}@dast.test"
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


class AuthnDetailsExposesAllUsersProbe(Probe):
    name = "authz_authentication_details_exposes_all_users"
    summary = ("Detects /rest/user/authentication-details (and similar) "
               "returning the full user directory + auth metadata to "
               "any authenticated caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional authentication-details endpoint path "
                 "(repeatable).")

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
                         f"session on {origin}; cannot exercise "
                         "authentication-details endpoints."),
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
            rows = doc.get("data") if isinstance(doc, dict) else doc
            if not isinstance(rows, list) or not rows:
                attempts.append(row)
                continue
            distinct_ids = {x.get("id") for x in rows
                            if isinstance(x, dict) and x.get("id") is not None}
            row["row_count"] = len(rows)
            row["distinct_ids"] = sorted(list(distinct_ids))[:8]
            # Did the response include admin-flavoured fields anywhere?
            body_excerpt = (r.text or "")[:600]
            row["body_excerpt"] = body_excerpt
            sensitive_hits = sorted(
                {f for f in SENSITIVE_FIELDS
                 if f'"{f}"' in body_excerpt or f'"{f}":' in body_excerpt})
            row["sensitive_fields"] = sensitive_hits
            # Confirmation: more than one user record AND at least one
            # sensitive field. Filtering by row count keeps a benign
            # "just me" endpoint from false-positiving.
            if len(distinct_ids) >= 2 and sensitive_hits:
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "session_email": diag.get("email"),
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: {confirmed['url']} returned "
                    f"{confirmed.get('row_count')} user records to a "
                    "low-privilege customer session. Each record "
                    "carried authentication-flavoured fields "
                    f"({', '.join(confirmed.get('sensitive_fields') or [])}). "
                    "This is a vertical authorization bypass on an "
                    "endpoint that should be scoped to the caller."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Scope the response to the caller's own user id. "
                    "Either (a) filter the underlying SELECT by "
                    "`UserId = :session.user_id`, or (b) reject the "
                    "request entirely with 403 unless the caller has "
                    "an explicit admin role. Strip sensitive fields "
                    "(deluxeToken, totpSecret, lastLoginIp, password "
                    "hash) from the serializer regardless of role -- "
                    "even an admin viewing user records does not need "
                    "the raw hash."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} authentication-"
                     f"details path(s) on {origin}; none returned a "
                     "multi-user record set to a low-privilege session."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthnDetailsExposesAllUsersProbe().main()
