#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Excessive data exposure: user-listing endpoint returns the stored
password (hash).

A `GET /api/Users` (or `/api/Users/<id>`) response that includes a
`password` field hands the attacker an offline-cracking corpus for
every account in the application. Even a "properly hashed" value
(bcrypt, argon2, scrypt) is a problem: it gives the attacker
unbounded compute against the entire user base, and once any single
hash is cracked the corresponding plaintext is reusable on every
other site that user touches.

The high-fidelity signal is structural: the field name is in a
small allowlist (`password`, `passwordHash`, `pwd`, `pwdHash`) and
the value matches one of the well-known hash-shape regexes. We
deliberately reject empty strings, nulls, and anything that doesn't
look like a stored secret -- a placeholder field with `null` value
isn't itself a leak (it's just a schema artefact) and we don't want
to false-positive on it.

Detection signal:
  1. GET candidate user-list / user-detail endpoints (anonymous).
  2. Parse the JSON; walk every dict for a `password`-shaped key
     whose value matches a stored-hash regex.

Tested against:
  + OWASP Juice Shop  GET /api/Users returns user objects whose
                      `password` field is a 32-char MD5 hash
                      → validated=True with confidence 0.95.
  + nginx default site → validated=False.

Read-only by construction: only GETs and a single registration
POST that creates a throwaway, low-privilege account so the probe
can also detect the BOLP variant where any *authenticated* user
sees the hashes (a common modern API mistake) -- not just the
unauthenticated leak.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that legitimately list users in modern web apps. The
# Juice Shop literal is `/api/Users` (capital U); the others are
# the typical patterns Sequelize / Mongoose / Django REST / Rails
# scaffolding produces.
USER_LIST_PATHS = (
    "/api/Users",
    "/api/users",
    "/api/v1/users",
    "/api/v2/users",
    "/users",
    "/admin/users",
)

# Field names that, when present alongside a hash-shaped value, are
# the bug. Lowercased; we match case-insensitively against keys.
_PASSWORD_FIELD_NAMES = {"password", "passwordhash", "password_hash",
                         "pwd", "pwdhash", "hash", "hashedpassword"}

# Hash-shape regexes. Each one is a complete-string match against the
# field value -- so `passwordHash: "TBD"` does not false-positive
# against the hex regex even though "TBD" is three hex-shape chars.
_HASH_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"^\$2[abxy]\$\d\d\$.{53}$"),                "bcrypt"),
    (re.compile(r"^\$argon2(i|d|id)\$.+\$.+\$.+\$.+$"),      "argon2"),
    (re.compile(r"^\$scrypt\$.+\$.+\$.+$"),                  "scrypt"),
    (re.compile(r"^\$pbkdf2(?:-[\w-]+)?\$.+\$.+\$.+$"),      "pbkdf2"),
    (re.compile(r"^\{SHA(?:256|512)?\}.+={0,2}$"),           "ldap-sha"),
    (re.compile(r"^[a-fA-F0-9]{32}$"),                       "md5-hex"),
    (re.compile(r"^[a-fA-F0-9]{40}$"),                       "sha1-hex"),
    (re.compile(r"^[a-fA-F0-9]{64}$"),                       "sha256-hex"),
    (re.compile(r"^[a-fA-F0-9]{128}$"),                      "sha512-hex"),
)


def _looks_like_hash(value: str) -> str | None:
    """Return the hash kind name if `value` matches a known
    stored-hash shape, else None. Empty / None / non-string values
    return None so a placeholder field doesn't fire."""
    if not isinstance(value, str) or not value:
        return None
    for pat, kind in _HASH_PATTERNS:
        if pat.match(value):
            return kind
    return None


def _walk_for_password(node, depth: int = 0) -> tuple[str, str, str] | None:
    """Walk the parsed JSON looking for a password-shaped key with a
    hash-shaped value. Caps recursion at depth 6 so a pathological
    payload can't blow the stack. Returns
    (field_name, hash_kind, value_excerpt) on hit, else None."""
    if depth > 6:
        return None
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in _PASSWORD_FIELD_NAMES:
                kind = _looks_like_hash(v) if isinstance(v, str) else None
                if kind:
                    return k, kind, v[:40] + ("..." if len(v) > 40 else "")
        for v in node.values():
            hit = _walk_for_password(v, depth + 1)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node[:50]:        # bounded -- a 100k-element list is its own DoS
            hit = _walk_for_password(v, depth + 1)
            if hit:
                return hit
    return None


class ExcessiveDataUsersPasswordProbe(Probe):
    name = "info_excessive_data_users_password"
    summary = ("Detects user-listing endpoints that return the stored "
               "password hash to any caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional user-list path to test (repeatable).")

    def _try_register_and_login(self, client: SafeClient, origin: str
                                 ) -> tuple[str | None, dict]:
        """Best-effort throwaway-account login. Returns (token, diag).
        Token may be None when the app's registration / login flow
        differs; the probe will then run anonymously, which still
        catches the unauthenticated-leak variant."""
        email = f"users-pw-probe-{secrets.token_hex(6)}@dast.test"
        pw    = "Pr0be-" + secrets.token_hex(4)
        diag: dict = {"email": email}
        reg_body = json.dumps({
            "email": email, "password": pw, "passwordRepeat": pw,
            "securityQuestion": {"id": 1}, "securityAnswer": "probe",
        }).encode()
        r = client.request(
            "POST", urljoin(origin, "/api/Users"),
            headers={"Content-Type": "application/json"}, body=reg_body)
        diag["register_status"] = r.status
        login_body = json.dumps({"email": email, "password": pw}).encode()
        r = client.request(
            "POST", urljoin(origin, "/rest/user/login"),
            headers={"Content-Type": "application/json"}, body=login_body)
        diag["login_status"] = r.status
        if r.status == 200 and r.body:
            try:
                doc = json.loads(r.text) or {}
                tok = ((doc.get("authentication") or {}).get("token")
                       if isinstance(doc, dict) else None) or doc.get("token")
                if tok:
                    return tok, diag
            except json.JSONDecodeError:
                pass
        return None, diag

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(USER_LIST_PATHS) + list(args.path or [])

        # Pass 1: anonymous. Most public bugs surface here.
        # Pass 2: authenticated as a throwaway user, to catch BOLP
        # (any logged-in caller, not just admins, sees hashes). The
        # authenticated pass only runs when pass 1 didn't already fire.
        attempts: list[dict] = []
        confirmed: dict | None = None
        token = None
        login_diag: dict = {}

        for pass_idx in (0, 1):
            headers = {}
            if pass_idx == 1:
                token, login_diag = self._try_register_and_login(client, origin)
                if not token:
                    break    # anonymous-only -- already covered in pass 1
                headers["Authorization"] = f"Bearer {token}"
            for p in paths:
                url = urljoin(origin, p)
                r = client.request("GET", url, headers=headers)
                row: dict = {"path": p, "status": r.status,
                             "size": r.size,
                             "auth": "bearer" if pass_idx else "anonymous"}
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except (ValueError, json.JSONDecodeError):
                        doc = None
                    if doc is not None:
                        hit = _walk_for_password(doc)
                        if hit:
                            field, kind, excerpt = hit
                            row.update({"password_field": field,
                                        "hash_kind": kind,
                                        "value_excerpt": excerpt})
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "paths_tested": attempts,
                    "login_diag": login_diag}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} returns "
                    f"a `{confirmed['password_field']}` field with a "
                    f"{confirmed['hash_kind']}-shaped value to any "
                    f"caller. Sample value: "
                    f"{confirmed['value_excerpt']!r}. Every account's "
                    f"password hash is downloadable in this single "
                    f"response -- offline-cracking corpus."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Strip the password / hash field from API "
                    "responses. The field should never leave the "
                    "auth subsystem.\n"
                    "  - Sequelize: add `defaultScope: { attributes: "
                    "{ exclude: ['password'] } }` to the User model.\n"
                    "  - Mongoose: `{ password: { select: false } }` in "
                    "the schema; opt-in via .select('+password') only "
                    "in the login flow.\n"
                    "  - Django REST: remove `password` from "
                    "Meta.fields on UserSerializer (or use "
                    "`extra_kwargs = {'password': {'write_only': "
                    "True}}`).\n"
                    "  - Rails: `User.attributes.except('password_"
                    "digest')` in `as_json` overrides; never serialize "
                    "the model directly.\n"
                    "After the fix, rotate every user's password -- "
                    "the leaked hashes are public and may already have "
                    "been cracked offline."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} user-list paths "
                     f"on {origin}; none returned a password-shaped "
                     "field with a hash-shaped value."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ExcessiveDataUsersPasswordProbe().main()
