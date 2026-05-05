#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: JWT payload contains PII or other sensitive
material.

JWT payloads are NOT encrypted — they are base64url-encoded JSON,
trivially readable by anyone holding the token (browser localStorage
copy, network log, intermediate proxy log, browser-extension
exfiltration, the user themselves snooping). Anything an app puts
into a JWT claim is therefore disclosed to the holder.

Common bad-shape data found in production JWT payloads:

  - Social Security numbers (US): `\\d{3}-\\d{2}-\\d{4}`.
  - Credit-card numbers (Luhn-validated to avoid noise on
    sequence-shaped fields).
  - Internal-network addresses (`10.`, `172.16-31.`, `192.168.`)
    when present in claim values that aren't IP-shaped by
    intent.
  - Password / secret-shaped claim KEYS (`password`, `secret`,
    `apiKey`).

This probe pulls a JWT from a normal login (or operator-supplied
--jwt), decodes the payload, and inspects every claim against the
above categories. We never log the full PII value — first-six +
last-four masking applies to every hit.

Detection signal:
  At least one claim value matches a strict PII regex (SSN format
  with full anchor, Luhn-valid 13-19 digit sequence, etc.) OR a
  claim KEY matches a secret-shaped name and its value is
  non-empty.
"""
from __future__ import annotations

import base64
import json
import re
import secrets as _secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATH = "/api/Users"
LOGIN_PATH = "/rest/user/login"

# US SSN. Strict shape with anchors so we don't match a
# substring of a longer number.
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# Internal-network IPs. Must be a full IP, not a substring.
_INTERNAL_IP_RE = re.compile(
    r"(?<![\d.])"
    r"(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")(?!\d)"
)

# Email shape — used to flag a claim whose VALUE is an email but
# whose KEY is something unrelated like "data" or "info".
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Sensitive-shape claim KEYS.
_SECRET_KEY_RE = re.compile(
    r"^(?:password|passwd|pwd|secret|api[_-]?key|"
    r"private[_-]?key|client[_-]?secret|token[_-]?secret|"
    r"refresh[_-]?secret|hmac[_-]?key|signing[_-]?key)$",
    re.IGNORECASE,
)

# Standard JWT claim keys we EXPECT to look like ids, dates, or
# scopes — those are the legitimate `email` / `iss` etc. claims.
# When a value flagged as PII appears under one of these keys, we
# don't double-count it (e.g. `email` claim containing an email
# value is by-design).
_LEGIT_KEYS_FOR_EMAIL = {"email", "preferred_username", "upn",
                          "sub", "username", "user", "iss"}


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 6:
        return val[:1] + "*" * max(0, len(val) - 2) + val[-1:]
    if len(val) <= 12:
        return val[:2] + "*" * (len(val) - 4) + val[-2:]
    return val[:6] + "*" * (len(val) - 10) + val[-4:]


def _luhn_valid(num: str) -> bool:
    """Standard Luhn check. Returns False for anything with non-
    digits or out-of-range length."""
    digits = [int(c) for c in num if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    s = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


def _walk_claims(obj, prefix: str = ""):
    """Yield (claim_key_path, value_str) for every leaf value in a
    nested dict. Lists are flattened into [i] indices."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _walk_claims(v, child)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            child = f"{prefix}[{i}]"
            yield from _walk_claims(v, child)
    else:
        yield prefix, "" if obj is None else str(obj)


def _try_login_and_extract_jwt(client: SafeClient,
                                origin: str) -> tuple[str | None, dict]:
    email = f"jwt-pii-{_secrets.token_hex(6)}@dast.test"
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

    body = json.dumps({"email": email, "password": pw}).encode()
    rl = client.request("POST", urljoin(origin, LOGIN_PATH),
                        headers={"Content-Type": "application/json"},
                        body=body)
    diag["login_status"] = rl.status
    if rl.body:
        try:
            doc = json.loads(rl.text) or {}
            for key in ("authentication", "token", "jwt"):
                if isinstance(doc.get(key), dict):
                    sub = doc[key]
                    for sk in ("token", "jwt", "accessToken",
                               "access_token"):
                        if isinstance(sub.get(sk), str):
                            return sub[sk], diag
                if isinstance(doc.get(key), str):
                    return doc[key], diag
        except json.JSONDecodeError:
            pass
    return None, diag


class AuthJwtPiiInClaimsProbe(Probe):
    name = "auth_jwt_pii_in_claims"
    summary = ("Detects PII or secret-shaped data embedded in JWT "
               "payload claims (token contents are not encrypted).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--jwt", default=None,
            help="JWT to inspect instead of registering a probe "
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
                         f"{origin} (no --jwt supplied and login did "
                         "not return a recoverable token)."),
                evidence={"origin": origin, "login_diag": login_diag},
            )

        parts = token.split(".")
        if len(parts) != 3:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: token from {origin} is not a "
                         "three-segment JWT."),
                evidence={"origin": origin,
                          "token_segments": len(parts)},
            )
        try:
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as e:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: JWT payload from {origin} is not "
                         f"decodable JSON ({e})."),
                evidence={"origin": origin},
            )
        if not isinstance(payload, dict):
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: JWT payload from {origin} is not "
                         "a JSON object."),
                evidence={"origin": origin},
            )

        hits: list[dict] = []
        for path, value in _walk_claims(payload):
            if not value:
                continue
            leaf_key = (path.rsplit(".", 1)[-1].split("[")[0]
                        if path else "")

            # Secret-shaped KEY with non-empty value.
            if _SECRET_KEY_RE.match(leaf_key):
                hits.append({
                    "kind": "secret-shaped claim key",
                    "claim_path": path,
                    "value_masked": _mask(value),
                })
                continue

            # SSN.
            m = _SSN_RE.search(value)
            if m:
                hits.append({
                    "kind": "US SSN",
                    "claim_path": path,
                    "value_masked": _mask(m.group(0)),
                })
                continue

            # Internal IP.
            m = _INTERNAL_IP_RE.search(value)
            if m:
                hits.append({
                    "kind": "Internal-network IP",
                    "claim_path": path,
                    "value_masked": _mask(m.group(0)),
                })
                continue

            # Email-as-claim-value with unrelated key.
            m = _EMAIL_RE.search(value)
            if m and leaf_key.lower() not in _LEGIT_KEYS_FOR_EMAIL:
                hits.append({
                    "kind": "Email in unexpected claim",
                    "claim_path": path,
                    "value_masked": _mask(m.group(0)),
                })
                continue

            # Credit-card. Look for a plausible run of 13-19 digits
            # then Luhn-validate. Strict: skip if the value contains
            # alphabetic characters (likely an id, not a CC).
            digits_only = re.sub(r"[^0-9]", "", value)
            if 13 <= len(digits_only) <= 19 \
                    and not re.search(r"[A-Za-z]", value) \
                    and _luhn_valid(digits_only):
                # Avoid false-positive on values that are clearly
                # all-zero or all-same-digit (test data).
                if len(set(digits_only)) > 2:
                    hits.append({
                        "kind": "Luhn-valid PAN candidate",
                        "claim_path": path,
                        "value_masked": _mask(digits_only),
                    })

        evidence = {
            "origin": origin,
            "claim_keys_seen": sorted(payload.keys()),
            "login_diag": login_diag,
            "hits": hits,
        }
        if hits:
            top = hits[0]
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: JWT issued by {origin} contains "
                    f"sensitive data in its (unencrypted) payload — "
                    f"{len(hits)} hit(s); top: "
                    f"{top['kind']} at claim "
                    f"`{top['claim_path']}` (masked: "
                    f"{top['value_masked']})."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "JWT payloads are visible to anyone who holds "
                    "the token. Remove PII (SSN, CC, internal IPs) "
                    "and secrets from the payload — replace each "
                    "with a server-side lookup keyed by `sub`. If "
                    "the token genuinely needs to carry sensitive "
                    "fields, switch to JWE (encrypted JWT) so the "
                    "payload is opaque to the client."),
            )
        return Verdict(
            validated=False, confidence=0.9,
            summary=(f"Refuted: JWT from {origin} payload contained "
                     f"no PII / secret-shaped claims among "
                     f"{len(payload)} top-level fields."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthJwtPiiInClaimsProbe().main()
