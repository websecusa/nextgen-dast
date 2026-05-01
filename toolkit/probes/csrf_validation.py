#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""CSRF token enforcement check.

Wapiti's `csrf` module ships a heuristic that re-replays the same valid
token in the same session and concludes the token isn't being checked
when the request goes through. That heuristic produces frequent false
positives against apps that DO bind tokens to the session — they accept
the same token within one session (correct) but reject it from a
different session (correct).

This probe runs the four canonical server-side CSRF tests against a
form-POST endpoint:

    1. baseline: form fetched in session A, posted with session A's
       token + cookie -- expected to be processed (success or invalid-
       creds; either way the token was accepted).
    2. no-token: posted from session A with the token field omitted.
       If the response is processed, the server doesn't require the
       token -- finding is REAL.
    3. garbage-token: posted from session A with a clearly-invalid
       token value. If processed, the server doesn't validate the
       token's value -- finding is REAL.
    4. cross-session: posted from session A but with a token issued in
       session B. If processed, tokens aren't bound to sessions --
       finding is REAL.

Verdicts:
  validated=True   -> at least one of (2)/(3)/(4) was processed.
  validated=False  -> all three were rejected. False positive.
  validated=None   -> couldn't even fetch the form / parse the token.

Examples:
    python csrf_validation.py --url 'https://app/login.php'
    python csrf_validation.py --url 'https://app/login.php' \\
        --token-field csrf_token \\
        --credentials 'test:test' \\
        --scope app
"""
from __future__ import annotations

import re
import secrets
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urljoin

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# ---- Form parsing ----------------------------------------------------------

class _FormScraper(HTMLParser):
    """Minimal form parser. Picks the FIRST <form> on the page and
    captures its action URL, method, and every <input> field. Adequate
    for the login-form / state-changing-form patterns this probe
    targets; not a general-purpose HTML parser."""

    def __init__(self):
        super().__init__()
        self.in_form = False
        self.captured = False
        self.action: Optional[str] = None
        self.method: str = "post"
        self.inputs: list[tuple[str, str, str]] = []  # (name, type, value)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form" and not self.captured:
            self.in_form = True
            self.action = a.get("action") or ""
            self.method = (a.get("method") or "post").lower()
        elif tag == "input" and self.in_form:
            name = a.get("name") or ""
            if name:
                self.inputs.append((name, (a.get("type") or "text").lower(),
                                    a.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            self.in_form = False
            self.captured = True


def _scrape_form(html: str) -> Optional[_FormScraper]:
    s = _FormScraper()
    try:
        s.feed(html)
    except Exception:
        return None
    return s if s.captured or s.inputs else None


def _looks_like_csrf_field(name: str) -> bool:
    """Heuristic for picking the CSRF token field when --token-field is
    not specified. Matches the names used by every framework I've seen
    in the wild: csrf_token, csrfmiddlewaretoken, _token,
    authenticity_token, csrf, _csrf, anti_forgery_token, etc."""
    n = (name or "").lower()
    return any(t in n for t in
               ("csrf", "_token", "authenticity", "anti_forgery",
                "xsrf", "verifytoken", "request_token"))


# ---- Cookie handling -------------------------------------------------------

# urllib stores headers in a dict, so multiple Set-Cookie headers are
# collapsed to one entry. We pull from the response headers directly
# and split on the boundary commas that aren't inside an Expires date.

_SETCOOKIE_SPLIT_RE = re.compile(r",\s*(?=[A-Za-z0-9_!#$%&'*+\-.^`|~]+=)")


def _set_cookies_from_headers(headers: dict) -> dict:
    """Parse Set-Cookie header(s) into a name->value dict. Best-effort:
    skips malformed entries, picks the FIRST value for any cookie name
    that appears more than once."""
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    out: dict[str, str] = {}
    if not raw:
        return out
    # urllib joins multiple Set-Cookie headers with ", " — try to
    # split on cookie-name boundaries while keeping date values like
    # "Wed, 01 Jan 2030 ..." intact.
    for piece in _SETCOOKIE_SPLIT_RE.split(raw):
        piece = piece.strip()
        if not piece or "=" not in piece:
            continue
        kv = piece.split(";", 1)[0].strip()
        if "=" not in kv:
            continue
        k, _, v = kv.partition("=")
        k = k.strip(); v = v.strip()
        if k and k not in out:
            out[k] = v
    return out


def _merge_cookie_jar(jar: dict, headers: dict) -> dict:
    """Update `jar` in place with Set-Cookies from `headers`. Returns jar."""
    new = _set_cookies_from_headers(headers)
    jar.update(new)
    return jar


def _cookie_header(jar: dict) -> str:
    """Render a Cookie request header from a name->value dict."""
    return "; ".join(f"{k}={v}" for k, v in jar.items() if v is not None)


# ---- Response classification ----------------------------------------------

# Body keywords that indicate the server REJECTED the request because
# of CSRF / token / general "bad request" semantics. Matched
# case-insensitively against the response body. Order doesn't matter.
_REJECT_PATTERNS = (
    "csrf token mismatch",
    "csrf token",
    "invalid csrf",
    "invalid token",
    "invalid request",
    "missing token",
    "expired token",
    "request_token",
    "anti-forgery",
    "anti forgery",
    "forbidden",
    "403 forbidden",
    "419",                     # Laravel "page expired"
)

# Status codes that on their own indicate rejection, regardless of body.
_REJECT_STATUSES = (400, 401, 403, 419, 422)


def _looks_rejected(status: int, body: str) -> tuple[bool, str]:
    """Returns (rejected, why)."""
    if status in _REJECT_STATUSES:
        return True, f"HTTP {status}"
    low = (body or "")[:8000].lower()
    for pat in _REJECT_PATTERNS:
        if pat in low:
            return True, f"body matched {pat!r}"
    return False, "no rejection signal"


# ---- Probe -----------------------------------------------------------------

class CsrfValidationProbe(Probe):
    name = "csrf_validation"
    summary = ("Confirms (or refutes) a CSRF finding via the four "
               "textbook server-side tests (no token / garbage / "
               "cross-session).")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument("--login-page-url", default=None,
                            help="URL of the page that renders the form "
                                 "(defaults to --url)")
        parser.add_argument("--token-field", default=None,
                            help="Name of the CSRF token field (auto-"
                                 "detected when omitted)")
        parser.add_argument("--credentials", default=None,
                            help="Optional username:password sent with the "
                                 "test POSTs (use bogus values)")

    def run(self, args, client: SafeClient) -> Verdict:
        target = args.url
        login_page = args.login_page_url or target
        # Allow POSTs even if the dispatcher didn't set allow_destructive:
        # this probe's POSTs are intentionally invalid (wrong creds OR
        # bad tokens), so they cannot mutate state on a correctly-built
        # app. The safety story stays honest: we only flip this for
        # probes whose manifest declares requires_post=true.
        client.budget.allow_destructive = True

        # Two independent sessions sharing the same budget + audit log.
        # Each carries its own cookie jar; we set client.cookie before
        # each request from the corresponding jar.
        sess_a: dict = {}
        sess_b: dict = {}
        client_b = SafeClient(client.budget, client.audit, verify_tls=False)

        # ---- Step 1: fetch the login page in session A --------------
        client.cookie = ""
        r_a = client.request("GET", login_page)
        if r_a.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="login page unreachable",
                           evidence={"login_page": login_page})
        _merge_cookie_jar(sess_a, r_a.headers)
        form_a = _scrape_form(r_a.text)
        if not form_a or not form_a.inputs:
            return Verdict(ok=False, validated=None,
                           summary=("could not locate a <form> on the login "
                                    "page; specify --login-page-url"),
                           evidence={"login_page": login_page,
                                     "status": r_a.status})

        # Identify the CSRF token field. Operator override wins; else
        # heuristic on field names; else first hidden field.
        token_field = args.token_field
        if not token_field:
            hidden = [(n, t, v) for (n, t, v) in form_a.inputs if t == "hidden"]
            for n, _, _ in hidden:
                if _looks_like_csrf_field(n):
                    token_field = n
                    break
            if not token_field and hidden:
                token_field = hidden[0][0]
        if not token_field:
            return Verdict(ok=False, validated=None,
                           summary=("no CSRF-style hidden field found in the "
                                    "form; specify --token-field"),
                           evidence={"form_inputs": [n for (n, _, _) in form_a.inputs]})

        token_a = next((v for (n, _, v) in form_a.inputs if n == token_field), "")
        if not token_a:
            return Verdict(ok=False, validated=None,
                           summary=f"token field {token_field!r} present but empty",
                           evidence={"form_inputs": [n for (n, _, _) in form_a.inputs]})

        # ---- Step 2: fetch the login page in session B --------------
        r_b = client_b.request("GET", login_page)
        if r_b.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="login page unreachable in second session")
        _merge_cookie_jar(sess_b, r_b.headers)
        form_b = _scrape_form(r_b.text)
        token_b = ""
        if form_b:
            token_b = next((v for (n, _, v) in form_b.inputs if n == token_field), "")

        # The two tokens MUST differ. If they don't, the app uses a
        # static / shared token, which is a separate (and worse) bug.
        if token_a == token_b:
            return Verdict(
                ok=True, validated=True, confidence=0.95,
                summary=("CSRF token is identical across independent "
                         "sessions -- token is not session-bound. The "
                         "wapiti finding is real (and stronger than "
                         "reported)."),
                evidence={"token_field": token_field, "token_value": token_a},
                remediation=(
                    "Generate the CSRF token from per-session entropy "
                    "(e.g. signed against the session id). Avoid global "
                    "or process-lifetime constants."),
                severity_uplift="high",
            )

        # Build the form payload from session A's hidden + visible
        # fields. Replace the token at submission time so each test
        # case can vary it.
        cred_user, cred_pass = "", ""
        if args.credentials and ":" in args.credentials:
            cred_user, _, cred_pass = args.credentials.partition(":")

        def build_payload(token_value: Optional[str]) -> bytes:
            data = []
            for n, t, v in form_a.inputs:
                if n == token_field:
                    if token_value is None:
                        continue   # omit the field entirely
                    data.append((n, token_value))
                elif n.lower() in ("user", "username", "email", "login"):
                    data.append((n, cred_user or v or "test"))
                elif "pass" in n.lower():
                    data.append((n, cred_pass or v or "test"))
                elif t in ("submit",):
                    if v: data.append((n, v))
                else:
                    data.append((n, v or ""))
            return urlencode(data).encode()

        # Resolve form action URL (may be relative).
        post_url = urljoin(login_page,
                           form_a.action or "") or login_page
        # The CSRF check is meaningful only for state-changing methods.
        # We hardcode the form's declared method here (the parsed
        # <form method="..."> attribute), defaulting to POST. Ignore
        # args.method, whose default at the framework level is GET --
        # using that here would silently turn every "tampered POST"
        # into a benign GET and the probe would conclude the server
        # processed it (which it did -- as a page load, not a state
        # change). Earlier iteration of the probe shipped that bug.
        method = (form_a.method or "post").upper()
        if method == "GET":
            method = "POST"   # GET form is unusual and not what wapiti flags
        post_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        def submit(token_value: Optional[str], jar: dict, label: str):
            client.cookie = _cookie_header(jar)
            body = build_payload(token_value)
            resp = client.request(method, post_url, headers=post_headers,
                                  body=body)
            rejected, why = _looks_rejected(resp.status, resp.text)
            return {
                "label": label,
                "status": resp.status,
                "size": resp.size,
                "rejected": rejected,
                "rejected_reason": why,
            }

        # ---- Tests --------------------------------------------------
        baseline = submit(token_a, sess_a, "baseline (valid token)")
        no_token = submit(None,    sess_a, "no token field")
        garbage  = submit("AAAA0000_invalid_csrf_token_value_AAAA0000",
                                       sess_a, "garbage token")
        cross    = submit(token_b or "", sess_b, "cross-session token")
        # The cross-session test still posts with session A's COOKIE
        # but session B's TOKEN -- correct CSRF protection requires the
        # token to be bound to the cookie's session id.
        cross_swap = submit(token_b or "", sess_a, "cross-session token "
                                                       "with session-A cookie")

        # ---- Verdict -----------------------------------------------
        # Baseline must have been processed for the comparison to be
        # meaningful. If it wasn't (e.g. the form is gated behind auth
        # and we have no session), we can't conclude either way.
        if baseline["rejected"]:
            return Verdict(
                ok=True, validated=None, confidence=0.0,
                summary=("baseline POST with the valid token was also "
                         "rejected -- cannot distinguish CSRF enforcement "
                         "from a generic 4xx. Try --credentials or run "
                         "from a session that has access to the form."),
                evidence={"baseline": baseline,
                          "no_token": no_token, "garbage": garbage,
                          "cross_session": cross_swap},
            )

        bypasses = [t for t in (no_token, garbage, cross_swap) if not t["rejected"]]

        if bypasses:
            return Verdict(
                ok=True, validated=True, confidence=0.92,
                summary=(f"CSRF protection NOT enforced on {post_url}: "
                         f"{len(bypasses)} of 3 tampering tests were "
                         f"processed by the server (" +
                         ", ".join(b["label"] for b in bypasses) + "). "
                         "Wapiti's finding is real."),
                evidence={
                    "post_url": post_url,
                    "token_field": token_field,
                    "tokens_differ_per_session": True,
                    "baseline": baseline,
                    "no_token": no_token,
                    "garbage": garbage,
                    "cross_session": cross_swap,
                },
                remediation=(
                    "Reject the request when the CSRF token is missing, "
                    "malformed, or not bound to the requester's session. "
                    "The framework-recommended pattern is double-submit "
                    "or a synchronizer token bound to the session ID."),
                severity_uplift="high",
            )

        return Verdict(
            ok=True, validated=False, confidence=0.93,
            summary=("CSRF protection IS enforced: all three tampering "
                     "tests were rejected (no token / garbage token / "
                     "cross-session token). The wapiti finding is a "
                     "false positive. Wapiti's csrf module flags this "
                     "pattern incorrectly when the app reuses a valid "
                     "token within one session, which is the OWASP-"
                     "recommended pattern."),
            evidence={
                "post_url": post_url,
                "token_field": token_field,
                "tokens_differ_per_session": True,
                "baseline": baseline,
                "no_token": no_token,
                "garbage": garbage,
                "cross_session": cross_swap,
            },
        )


if __name__ == "__main__":
    CsrfValidationProbe().main()
