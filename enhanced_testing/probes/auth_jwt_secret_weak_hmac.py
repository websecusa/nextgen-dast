#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: HS256 JWT signed with a weak / well-known secret.

Apps that sign JWTs with HS256 use a shared secret. If that secret
is `secret`, `password`, `your-256-bit-secret`, the project name,
or any other value an attacker can guess offline, the attacker can
mint arbitrary tokens — change `sub`, set `role: admin`, extend
`exp` — and present them to the server as valid.

This probe pulls a JWT from a normal login response (or the
operator-supplied --jwt) and tests it against a curated list of
~30 commonly-leaked HMAC secrets. The check is offline: we
recompute the HMAC-SHA256 over `<header>.<payload>` and compare it
against the token's signature in constant time. Only one network
request is required (the login itself); cracking is pure CPU.

We never log the cracked secret in the clear — it's masked first +
last chars only.

Detection signal:
  HMAC-SHA256(`<header>.<payload>`, secret) == decoded signature
  for at least one entry in our wordlist.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as _secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATH = "/api/Users"
LOGIN_PATH = "/rest/user/login"

# Curated wordlist. Kept under 50 entries on purpose — these are
# the secrets that have shown up in published incidents, default
# config files, and example documentation. We do NOT ship a
# dictionary attack tool. If a probe takes too long the budget
# rule is the wrong knob; the right knob is "make secrets random."
COMMON_SECRETS = (
    "secret",
    "Secret",
    "SECRET",
    "password",
    "Password",
    "123456",
    "changeme",
    "your-secret-key",
    "your-256-bit-secret",
    "supersecret",
    "secretkey",
    "jwt-secret",
    "jwt_secret",
    "hmac-secret",
    "hmackey",
    "test",
    "dev",
    "development",
    "production",
    "default",
    "admin",
    "key",
    "private",
    "private-key",
    "myapp",
    "myapp-secret",
    "qwerty",
    "letmein",
    "iloveyou",
    "monkey",
    "abc123",
    "p@ssw0rd",
    "P@ssw0rd",
    "PleaseChangeMe",
    "topsecret",
)


def _b64url_decode(s: str) -> bytes:
    """JWT base64url decoding with the missing padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 6:
        return val[:1] + "*" * (len(val) - 2) + val[-1:]
    return val[:2] + "*" * (len(val) - 4) + val[-2:]


def _try_login_and_extract_jwt(client: SafeClient,
                                origin: str) -> tuple[str | None, dict]:
    """Register a throwaway user and pull a JWT out of the login
    response. Returns (token_or_None, diag)."""
    email = f"jwt-crack-{_secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + _secrets.token_hex(6)
    diag: dict = {"email": email}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    rr = client.request("POST", urljoin(origin, REGISTER_PATH),
                        headers={"Content-Type": "application/json"},
                        body=body)
    diag["register_status"] = rr.status

    # Login (POST), then look for a JWT in either the body or any
    # response cookie that contains three base64-url segments.
    body = json.dumps({"email": email, "password": pw}).encode()
    rl = client.request("POST", urljoin(origin, LOGIN_PATH),
                        headers={"Content-Type": "application/json"},
                        body=body)
    diag["login_status"] = rl.status

    # Body extraction.
    if rl.body:
        try:
            doc = json.loads(rl.text) or {}
            for key in ("authentication", "token", "jwt"):
                if isinstance(doc.get(key), dict):
                    sub = doc[key]
                    for sk in ("token", "jwt", "accessToken",
                               "access_token"):
                        if sk in sub and isinstance(sub[sk], str):
                            return sub[sk], diag
                if isinstance(doc.get(key), str):
                    return doc[key], diag
        except json.JSONDecodeError:
            pass

    # Header extraction (Authorization echo, x-auth-token).
    for hdr_key in ("authorization", "x-auth-token"):
        for k, v in (rl.headers or {}).items():
            if k.lower() == hdr_key and isinstance(v, str):
                v = v.strip()
                if v.lower().startswith("bearer "):
                    v = v[7:]
                if v.count(".") == 2:
                    return v, diag
    return None, diag


class AuthJwtSecretWeakHmacProbe(Probe):
    name = "auth_jwt_secret_weak_hmac"
    summary = ("Detects HS256 JWTs signed with a well-known weak "
               "secret by attempting offline HMAC verification "
               "against a small wordlist.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--jwt", default=None,
            help="JWT to crack instead of registering a probe "
                 "account and pulling one from /login.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        token = args.jwt
        login_diag: dict = {}
        if not token:
            token, login_diag = _try_login_and_extract_jwt(client, origin)
        if not token:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: could not obtain a JWT from "
                         f"{origin} (no --jwt supplied and login "
                         "did not return a recoverable token)."),
                evidence={"origin": origin, "login_diag": login_diag},
            )

        parts = token.split(".")
        if len(parts) != 3:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: token from {origin} is not a "
                         "three-segment JWT."),
                evidence={"origin": origin, "token_segments":
                          len(parts)},
            )
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64url_decode(header_b64))
        except Exception as e:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: JWT header from {origin} is "
                         f"not decodable JSON ({e})."),
                evidence={"origin": origin},
            )
        alg = (header.get("alg") or "").upper()
        if alg != "HS256":
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: JWT alg is `{alg}`, not HS256. "
                         "This probe only checks symmetric HMAC "
                         "signatures."),
                evidence={"origin": origin, "alg": alg,
                          "login_diag": login_diag},
            )

        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            sig = _b64url_decode(sig_b64)
        except Exception as e:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: JWT signature from {origin} "
                         f"is not valid base64url ({e})."),
                evidence={"origin": origin},
            )

        cracked: str | None = None
        for candidate in COMMON_SECRETS:
            mac = hmac.new(candidate.encode(), signing_input,
                           hashlib.sha256).digest()
            # Constant-time compare to avoid leaking timing info to
            # any concurrent observer of the probe process. (We're
            # the only consumer of this output, but it costs nothing
            # to be careful.)
            if hmac.compare_digest(mac, sig):
                cracked = candidate
                break

        evidence = {
            "origin": origin,
            "alg": alg,
            "wordlist_size": len(COMMON_SECRETS),
            "login_diag": login_diag,
        }
        if cracked is not None:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: HS256 JWT issued by {origin} "
                    "verifies against a well-known weak secret "
                    f"(masked: {_mask(cracked)}). An attacker can "
                    "mint arbitrary tokens — change subject, "
                    "elevate role, extend expiry — and the server "
                    "will accept them."),
                evidence={**evidence,
                          "cracked_secret_masked": _mask(cracked)},
                severity_uplift="critical",
                remediation=(
                    "Rotate the JWT signing secret to a 256-bit "
                    "cryptographically random value (not derived "
                    "from the project name or any guessable string). "
                    "Distribute via your secret manager, never "
                    "commit it to source. Better still: switch to "
                    "RS256 or ES256 — asymmetric signatures avoid "
                    "the shared-secret class of attack entirely."),
            )
        return Verdict(
            validated=False, confidence=0.9,
            summary=(f"Refuted: HS256 JWT from {origin} did not "
                     f"verify against the {len(COMMON_SECRETS)}-"
                     "entry weak-secret wordlist. Either the "
                     "secret is strong or this probe's wordlist "
                     "doesn't contain it."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthJwtSecretWeakHmacProbe().main()
