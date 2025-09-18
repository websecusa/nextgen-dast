#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: server accepts JWTs whose `exp` is in the past.

A JWT with a past `exp` claim should be rejected by the verifier.
When it isn't, sessions never time out from the server's perspective
— compromised tokens stay valid forever.

The probe needs a real, signed JWT to start with: forging an unsigned
one would be testing a different bug (alg=none — see
auth_jwt_alg_none). So we register a throwaway user, log in, take the
JWT we get back, and SUBSTITUTE its payload for one with `exp = now -
1 day`. Re-encoding the payload changes the signature on a properly-
signed token, so the verifier MUST refuse it. If it doesn't, either
the signature isn't being checked (a different bug) or the exp clock
isn't being checked.

We distinguish the two cases by also tampering with the email claim:
  - If the email-tampered version is also accepted → signature isn't
    checked. We classify this as `signature_not_verified` (same
    severity, different remediation).
  - If only the exp-tampered version is accepted → exp isn't being
    enforced.

Detection signal:
  Re-issue the just-received JWT with `exp` set to a past Unix
  timestamp (preserving signature bytes). Send to whoami → 200 means
  the verifier ignored exp.

Tested against:
  + OWASP Juice Shop — current build re-checks the signature, so the
    probe correctly returns validated=False.
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

WHOAMI_PATH = "/rest/user/whoami"


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"jwt-noexp-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
        except json.JSONDecodeError:
            pass
    return out


def _retro_token(token: str, override_exp: int | None,
                 override_email: str | None = None) -> str | None:
    """Re-encode the payload of `token` with the requested overrides,
    keeping header and signature bytes unchanged. The signature will
    no longer match the new payload — the point of the probe is to
    see if the verifier notices."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if override_exp is not None:
        payload["exp"] = override_exp
    if override_email is not None:
        payload["email"] = override_email
        if isinstance(payload.get("data"), dict):
            payload["data"]["email"] = override_email
    new_payload = _b64url(json.dumps(payload).encode())
    return f"{parts[0]}.{new_payload}.{parts[2]}"


class JwtNoExpirationProbe(Probe):
    name = "auth_jwt_no_expiration"
    summary = ("Detects JWT verifier ignoring `exp` (past timestamps "
               "still accepted).")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]

        past_exp = int(time.time()) - 86400
        retro = _retro_token(token, override_exp=past_exp)
        forged_email = _retro_token(token, override_exp=None,
                                    override_email="control@dast.test")
        if not retro or not forged_email:
            return Verdict(
                validated=False, confidence=0.6,
                summary="Inconclusive: issued token not in JWT shape.",
                evidence={"origin": origin},
            )

        url = urljoin(origin, WHOAMI_PATH)
        r1 = client.request("GET", url, headers={
            "Authorization": f"Bearer {retro}",
        })
        r2 = client.request("GET", url, headers={
            "Authorization": f"Bearer {forged_email}",
        })

        retro_ok  = (r1.status == 200 and (r1.body or b""))
        email_ok  = (r2.status == 200 and (r2.body or b""))

        evidence = {"origin": origin, "exp_test": {
            "status": r1.status, "size": r1.size,
            "body_excerpt": (r1.text or "")[:200],
        }, "signature_test": {
            "status": r2.status, "size": r2.size,
            "body_excerpt": (r2.text or "")[:200],
        }}

        if retro_ok and email_ok:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: signature is not being verified "
                         f"on {origin}{WHOAMI_PATH}. Both an exp-"
                         "tampered AND an email-tampered token were "
                         "accepted — bigger problem than just the "
                         "missing exp check."),
                evidence={**evidence, "subclass": "signature_not_verified"},
                severity_uplift="critical",
                remediation=(
                    "Verify the JWT signature on every request. "
                    "Do NOT decode-without-verify in any user-facing "
                    "code path; if you only want to read claims for "
                    "logging, do that AFTER `verify`. Pair with "
                    "rotating the signing key — every token issued "
                    "during the exposure window may have been forged."),
            )
        if retro_ok and not email_ok:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: server at {origin} accepts a "
                         "JWT with exp set to one day ago — exp clock "
                         "is not being enforced. (Signature check "
                         "still works — the email-tampered control "
                         "was rejected.)"),
                evidence={**evidence, "subclass": "exp_not_enforced"},
                severity_uplift="high",
                remediation=(
                    "Configure the verifier with `exp` validation on. "
                    "PyJWT does this by default; jsonwebtoken (Node) "
                    "needs `{algorithms, ignoreExpiration: false}`. "
                    "Audit token-issue settings — issuing tokens with "
                    "`exp` decades in the future is the same bug."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: server at {origin} rejected both the "
                     "exp-tampered and email-tampered tokens — JWT "
                     "verification is doing its job."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JwtNoExpirationProbe().main()
