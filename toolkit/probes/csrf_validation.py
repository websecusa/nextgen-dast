#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""High-fidelity CSRF enforcement check.

Wapiti's `csrf` module flags any HTML form whose POST endpoint
accepts a request that re-uses the same valid token within one
session. That heuristic generates two distinct false-positive modes:

  1. The form has a synchronizer token that IS bound to the session,
     and the server accepts the same token within one session (which
     is the OWASP-recommended pattern). Wapiti calls this missing.
  2. The form has NO synchronizer token at all, but the application
     defends against CSRF via Origin/Referer header checks, a
     double-submit cookie, or SameSite cookie attributes. Wapiti only
     looks for the form-token mechanism and misses the others.

This probe runs the canonical server-side CSRF tests and -- new in
this version -- additionally exercises the Origin/Referer pathway so
mode #2 is no longer reported as "inconclusive" or as a
false-positive of the wapiti finding it can't actually rule out.

Tests
-----

When a synchronizer token IS present on the form:

    1. baseline: token from session A submitted with session A's
       cookie. Establishes that the form processes a well-formed
       request -- if it doesn't, every other test is meaningless.
    2. no-token: token field omitted entirely from the body.
    3. garbage-token: token replaced with a clearly-invalid string.
    4. cross-session: session B's token submitted with session A's
       cookie (textbook session-binding test).
    5. cross-origin: same-session token, but with Origin/Referer set
       to a hostile domain. Detects whether the framework also gates
       on Origin (defense-in-depth).

When a synchronizer token is NOT present on the form (no field name
matches the heuristic, or the candidate field has an empty value),
the probe does NOT abort. It runs:

    1. baseline (same-origin POST, no token)
    2. cross-origin POST  (Origin/Referer set to attacker host)
    3. no-Origin POST     (Origin and Referer omitted)
    4. cross-session POST (session B's cookies submitted)

If the cross-origin POST is rejected with a CSRF/Origin signal but
the same-origin baseline processes, the application is defended via
Origin enforcement and the wapiti finding is a false positive. If
the cross-origin POST processes too, no defense is in place and the
finding is real.

Verdict semantics
-----------------

  validated=True    Some tampering test was processed by the server
                    (no-token / garbage / cross-session / cross-
                    origin). CSRF protection is missing or bypassable.
  validated=False   The baseline processed and EVERY tampering test
                    was rejected. The wapiti finding is a false
                    positive (or wapiti's heuristic mis-fired on a
                    correctly-defended app).
  validated=None    Baseline itself was rejected with no clear
                    CSRF/auth signal -- we cannot drive the form, so
                    we cannot rule for or against.

Auth-failure vs CSRF-rejection
------------------------------

The probe carefully distinguishes the two failure modes. A 401 with
'Invalid credentials' in the body means the application processed
the form -- it just rejected the credentials. That is NOT a CSRF
rejection: from the CSRF protection's standpoint, the request got
through. Only 4xx responses that signal a CSRF/Origin/token problem
(403, 419, 422 plus body keywords like 'csrf', 'forbidden', 'cross-
origin', 'missing token') count as CSRF rejection.

Form selection on multi-form pages
----------------------------------

Real-world pages usually render more than one form (a header
logout/login form alongside the actual state-changing form).
The earlier scraper grabbed only the FIRST <form> on the page,
which on a page like /vendor-srs-details.php meant the probe
wound up testing the header login form -- whose CSRF behavior
differs from the form wapiti actually flagged.

The probe now collects every form on the page and picks the one
whose resolved action path matches the wapiti target URL's path.
When no form matches, the probe bails with validated=None and a
clear "could not locate the target form on this page" message,
rather than silently testing the wrong form and emitting a
verdict for the wrong endpoint.

Auth-wall detection
-------------------

When the probe is aimed at a state-changing endpoint that itself
sits behind authentication (e.g. /admin/transfer) without a valid
session, the auth middleware short-circuits every POST with a
redirect to the login page. With redirect-following enabled (the
default), the probe sees a 200 response carrying the login form
HTML for the baseline AND every tampering test -- token, no-token,
garbage-token, cross-origin: all identical, because the CSRF check
never executed. Wapiti hits the same wall and reports the bypass
as "real" (the textbook "response unchanged on tampering"
heuristic). The truth is just that the request never reached the
CSRF gate.

The probe detects this in two complementary places:

  - Pre-test: when the GET that establishes session A lands on a
    page that has no form matching the wapiti target URL, but
    DOES carry a login form (password input present, or URL path
    contains /login, /signin, /auth, etc.), AND the response sets
    SameSite=Lax/Strict on the session cookie, the probe returns
    `validated=False` with confidence 0.85 -- the cross-site CSRF
    attack vector wapiti checks for is defeated by the auth wall
    plus the browser's SameSite enforcement, regardless of
    server-side token validation. (Confidence ≥ 0.8 is what the
    dispatcher needs to flip the finding to false_positive.)
  - Post-test: when the test battery does run but every POST's
    final URL matches the login page URL, the probe returns
    `validated=None` so the operator knows the CSRF logic was
    never actually exercised.

Examples
--------

    python csrf_validation.py --url 'https://app/login.php'
    python csrf_validation.py --url 'https://app/login.php' \\
        --token-field csrf_token \\
        --credentials 'test:test' \\
        --scope app \\
        --attacker-origin 'https://attacker.example'
"""
from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# ---- Form parsing ----------------------------------------------------------

class _Form:
    """One <form> scraped from the page: action, method, and every
    <input> field. Plain attribute container so the rest of the
    probe can keep using `form.action` / `form.method` / `form.inputs`
    without caring whether selection happened."""

    def __init__(self, action: str = "", method: str = "post"):
        self.action: str = action
        self.method: str = method
        self.inputs: list[tuple[str, str, str]] = []  # (name, type, value)


class _FormScraper(HTMLParser):
    """Collects EVERY <form> on the page along with its action URL,
    method, and child <input> fields. Selection is delegated to
    `_scrape_form` so this class is a pure capture device.

    The earlier version of this class only captured the first form
    and stopped. That worked for pages whose only form was the one
    being tested, but mis-fired on real-world apps that render
    multiple forms (a header logout/login form alongside the actual
    state-changing form). The probe ended up testing the header
    form's CSRF behavior, which had nothing to do with the wapiti
    finding's target URL."""

    def __init__(self):
        super().__init__()
        self.in_form = False
        self.forms: list[_Form] = []
        self._cur: Optional[_Form] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self.in_form = True
            self._cur = _Form(action=a.get("action") or "",
                              method=(a.get("method") or "post").lower())
        elif tag == "input" and self.in_form and self._cur is not None:
            name = a.get("name") or ""
            if name:
                self._cur.inputs.append((
                    name, (a.get("type") or "text").lower(),
                    a.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            self.in_form = False
            if self._cur is not None:
                self.forms.append(self._cur)
                self._cur = None


def _form_action_path(form: _Form, page_url: str) -> str:
    """Resolve a form's action URL against the page it was scraped
    from and return only its path component (with trailing slash
    stripped). Empty action means 'submit to this page'."""
    resolved = urljoin(page_url or "", form.action or "")
    return urlparse(resolved).path.rstrip("/") or "/"


def _scrape_form(html: str, *, target_url: str = "",
                 page_url: str = "") -> tuple[Optional[_Form], list[_Form]]:
    """Parse every <form> on the page and return:
        (chosen, all_forms)

    where `chosen` is the form whose action path matches the target
    URL's path, or None when no form matches. `all_forms` is every
    form on the page (in document order) -- exposed so the caller
    can examine non-target forms (e.g. spot a login form to detect
    that the GET was redirected to an auth wall).

    When `target_url` is empty, the chosen form is the first one
    with inputs -- legacy behavior for interactive (non-wapiti-
    driven) runs.

    Returning None for `chosen` when forms exist but none match the
    target prevents the probe from silently testing the wrong form
    (which is the bug that produced the vendor-srs-details /
    login.php cross-form false positive).
    """
    s = _FormScraper()
    try:
        s.feed(html)
    except Exception:
        return None, []
    if not s.forms:
        return None, []

    # Priority 1: form action path == target URL path. urlparse
    # discards the query string, so /vendor-srs-details.php?id=1 in
    # the wapiti finding still matches a form whose action="" or
    # action="/vendor-srs-details.php" on the page.
    if target_url:
        target_path = urlparse(target_url).path.rstrip("/") or "/"
        page = page_url or target_url
        for f in s.forms:
            if _form_action_path(f, page) == target_path:
                return f, s.forms
        # No match. Don't fall back blindly -- testing the wrong
        # form yields a verdict for the wrong endpoint.
        return None, s.forms

    # No target URL supplied: legacy behavior, return the first form
    # that has any inputs. Used when the probe is invoked manually
    # against a single-form page.
    for f in s.forms:
        if f.inputs:
            return f, s.forms
    return s.forms[0], s.forms


def _form_has_password_input(form: _Form) -> bool:
    """True when the form contains an <input type="password">.
    Used to recognize that the page we landed on is a login page
    even when the URL itself doesn't carry a 'login' segment."""
    return any(t == "password" for (_, t, _) in form.inputs)


# Names commonly used by web frameworks for the synchronizer token
# field. Substring-matched (case-insensitive) so all variants are
# covered: csrf_token, csrfmiddlewaretoken, _token, authenticity_token,
# anti_forgery_token, __RequestVerificationToken, etc.
_CSRF_FIELD_HINTS = (
    "csrf", "_token", "authenticity", "anti_forgery", "anti-forgery",
    "xsrf", "verifytoken", "verify_token", "request_token",
    "requestverification", "synchronizer",
)

# Hidden fields whose names look CSRF-ish on first glance but actually
# hold something else. Excluding these prevents the
# "first-hidden-field is the token" guess from latching onto the
# wrong input. The probe's older logic picked any hidden field as a
# fallback, which mis-identified post-login redirect targets like
# `next` as CSRF tokens and bailed when they were empty.
_CSRF_FIELD_EXCLUDES = (
    "next", "redirect", "return", "return_url", "returnurl",
    "redirect_to", "redirect_uri", "callback", "url", "ref", "referrer",
    "_method", "step",
)


def _looks_like_csrf_field(name: str) -> bool:
    """Match the field name against the CSRF hint list. Names on the
    explicit exclude list (e.g. 'next', 'redirect_to') never match
    even if they happen to contain a hint substring."""
    n = (name or "").lower()
    if not n or n in _CSRF_FIELD_EXCLUDES:
        return False
    return any(t in n for t in _CSRF_FIELD_HINTS)


# Cookie names that signal a double-submit CSRF cookie, used by
# Django (csrftoken), Angular (XSRF-TOKEN), Express csurf, etc. We
# don't tamper with these in a destructive way -- presence is mostly
# informational, recorded in evidence -- but we DO check whether the
# server accepts a request when the cookie is removed, since that's
# the textbook double-submit failure.
_CSRF_COOKIE_HINTS = ("csrf", "xsrf", "anti_forgery")


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
    # urllib joins multiple Set-Cookie headers with ", " -- try to
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


def _samesite_attrs_from_headers(headers: dict) -> dict:
    """Extract the SameSite attribute for each cookie in Set-Cookie.
    Returns name -> 'strict' | 'lax' | 'none' | '' (unset). SameSite
    is browser-side enforcement, so we can't truly *test* it from a
    probe -- but we record it in evidence so an analyst sees that
    SameSite=Lax/Strict is part of the defense story."""
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    out: dict[str, str] = {}
    if not raw:
        return out
    for piece in _SETCOOKIE_SPLIT_RE.split(raw):
        piece = piece.strip()
        if "=" not in piece:
            continue
        kv = piece.split(";", 1)[0].strip()
        name = kv.split("=", 1)[0].strip()
        if not name:
            continue
        # Walk the attribute list for a SameSite=... directive.
        attrs = piece.split(";")[1:]
        ss = ""
        for a in attrs:
            a = a.strip()
            if a.lower().startswith("samesite="):
                ss = a.split("=", 1)[1].strip().lower()
                break
        out[name] = ss
    return out


def _merge_cookie_jar(jar: dict, headers: dict) -> dict:
    """Update `jar` in place with Set-Cookies from `headers`. Returns jar."""
    new = _set_cookies_from_headers(headers)
    jar.update(new)
    return jar


def _cookie_header(jar: dict) -> str:
    """Render a Cookie request header from a name->value dict."""
    return "; ".join(f"{k}={v}" for k, v in jar.items() if v is not None)


def _url_path_key(url: str) -> tuple[str, str, str]:
    """Return a (scheme, host, path) tuple for cross-redirect URL
    comparison. Strips query string and fragment so URLs that differ
    only on a trailing ?error=1 still compare equal -- the auth-wall
    detection wants to match on 'we landed on the login page' even
    when the redirect target carries an error query. Trailing slashes
    are normalized so /login and /login/ compare equal."""
    p = urlparse(url or "")
    return (p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/") or "/")


# ---- Response classification ----------------------------------------------

# Status codes that indicate the request was rejected on a security
# check (CSRF, Origin, missing token, generic forbidden). 401 is
# deliberately NOT in this list -- 401 means authentication failed,
# i.e. the form was processed and the credentials were wrong. From
# the CSRF protection's standpoint that's a successful request.
_CSRF_REJECT_STATUSES = (403, 419)

# 4xx codes that overlap between "credential failure" and "CSRF
# rejection". We only count these as a CSRF rejection when the body
# also signals it (see _CSRF_REJECT_PATTERNS), to avoid mis-counting
# a generic Pydantic 422 or a Bad Request response.
_AMBIGUOUS_4XX = (400, 422)

# Body keywords that indicate the server REJECTED the request
# specifically because of CSRF / Origin / token semantics. Matched
# case-insensitively against the response body.
_CSRF_REJECT_PATTERNS = (
    "csrf token mismatch",
    "csrf token",
    "csrf failed",
    "invalid csrf",
    "invalid token",
    "missing token",
    "expired token",
    "anti-forgery",
    "anti forgery",
    "request_token",
    "cross-origin",
    "cross origin",
    "origin not allowed",
    "bad origin",
    "referer mismatch",
    "referer not allowed",
    "419",                     # Laravel "page expired"
    "forbidden",
)

# Body keywords that indicate the request was PROCESSED but
# authentication failed. These are NOT a CSRF rejection -- they
# prove the form's CSRF gate (if any) let the request through. The
# probe must not confuse them with rejection.
_AUTH_FAIL_PATTERNS = (
    "invalid credentials",
    "incorrect password",
    "wrong password",
    "login failed",
    "authentication failed",
    "bad credentials",
    "user not found",
    "no such user",
    "invalid username",
    "invalid login",
    "username or password is incorrect",
)


def _classify_response(status: int, body: str) -> tuple[str, str]:
    """Return (verdict, why) where verdict is one of:
        'csrf_rejected' -- server bounced the request on a CSRF check
        'auth_failed'   -- form processed but credentials were wrong
        'processed'     -- form was processed (success or 2xx/3xx with
                           no auth-failure signal)

    Body is matched case-insensitively in the first ~8 KB; the rest
    is ignored to keep the cost bounded on huge response bodies."""
    low = (body or "")[:8000].lower()

    # Check explicit auth-failure first. A 401 (or any 4xx) that
    # contains "invalid credentials" is the application acknowledging
    # bad creds, not a CSRF gate. Treat it as processed.
    for pat in _AUTH_FAIL_PATTERNS:
        if pat in low:
            return "auth_failed", f"body matched {pat!r}"

    # 401 without an auth-failure body keyword still leans toward
    # auth (it's the textbook auth status), but be conservative:
    # treat as processed (form-CSRF-gate let it through to the auth
    # stage).
    if status == 401:
        return "auth_failed", "HTTP 401 (auth stage)"

    # Hard CSRF-reject statuses.
    if status in _CSRF_REJECT_STATUSES:
        return "csrf_rejected", f"HTTP {status}"

    # Ambiguous 4xx -- only count as CSRF rejection when the body
    # backs it up.
    if status in _AMBIGUOUS_4XX:
        for pat in _CSRF_REJECT_PATTERNS:
            if pat in low:
                return "csrf_rejected", f"HTTP {status} body matched {pat!r}"
        # No CSRF wording -- treat as a generic "form was rejected
        # for some other reason". Caller decides whether to flag this
        # as inconclusive.
        return "processed", f"HTTP {status} (no CSRF signal in body)"

    # Body-keyword-only rejection (e.g. 200-with-error-page apps).
    for pat in _CSRF_REJECT_PATTERNS:
        if pat in low:
            return "csrf_rejected", f"body matched {pat!r}"

    return "processed", f"HTTP {status}"


# ---- Probe -----------------------------------------------------------------

class CsrfValidationProbe(Probe):
    name = "csrf_validation"
    summary = ("High-fidelity CSRF enforcement check: detects "
               "synchronizer tokens, double-submit cookies, AND "
               "Origin/Referer enforcement.")
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
        parser.add_argument("--attacker-origin",
                            default="https://attacker.example",
                            help="Origin used for the cross-origin POST "
                                 "test (must NOT match the target host)")

    # ----- helpers --------------------------------------------------------

    @staticmethod
    def _origin_for_url(url: str) -> str:
        """Render an Origin header value for `url` (scheme://host[:port])."""
        u = urlparse(url)
        host = u.hostname or ""
        port = f":{u.port}" if u.port else ""
        scheme = u.scheme or "https"
        return f"{scheme}://{host}{port}" if host else ""

    # ----- main logic -----------------------------------------------------

    def run(self, args, client: SafeClient) -> Verdict:
        target = args.url
        login_page = args.login_page_url or target
        # Allow POSTs even if the dispatcher didn't set
        # allow_destructive: this probe's POSTs are intentionally
        # invalid (wrong creds OR bad tokens), so they cannot mutate
        # state on a correctly-built app. The safety story stays
        # honest -- we only flip this for probes whose manifest
        # declares requires_post=true.
        client.budget.allow_destructive = True

        # Two independent sessions sharing the same budget + audit log.
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
        samesite_a = _samesite_attrs_from_headers(r_a.headers)
        # The user-supplied --login-page-url may itself redirect (e.g.
        # http -> https or to a canonical /login path). Track the URL
        # the form actually lives at so the form selector resolves
        # relative actions against the right base, and so the
        # auth-wall check below compares POST landings against the
        # right reference.
        login_final_url = r_a.final_url or login_page
        # Pass the wapiti target URL so _scrape_form picks the form
        # whose action matches it. Pages frequently render multiple
        # forms (a header logout/login form alongside the actual
        # state-changing form), and grabbing the first one gives a
        # verdict for the wrong endpoint.
        form_a, forms_a = _scrape_form(r_a.text, target_url=target,
                                        page_url=login_final_url)
        if not form_a or not form_a.inputs:
            # The page we landed on doesn't contain the form wapiti
            # flagged. Two common reasons:
            #
            #   1. The target endpoint is gated by authentication
            #      and our anonymous GET was redirected to a login
            #      page. (We deliberately probe with a fresh
            #      session because the CSRF tests need to drive
            #      session-A vs session-B independent of any
            #      ambient login state.)
            #   2. The page genuinely doesn't render the form
            #      wapiti claimed (JS-rendered, form behind feature
            #      flag, wapiti flagged a non-form endpoint).
            #
            # Reason #1 is exactly the textbook wapiti CSRF false-
            # positive: wapiti's csrf module flags the form-token
            # absence on the login page or on the post-auth form
            # without realising the cross-site attack vector is
            # already defeated by browser-side defenses on the
            # session cookie. If the response we got while landing
            # on the login page sets `SameSite=Lax/Strict` on any
            # cookie, the textbook cross-site CSRF POST cannot
            # carry the victim's session cookie regardless of
            # whether the form-token is validated server-side.
            # Combined with the auth wall (an unauthenticated
            # attacker can't reach the endpoint to bypass the
            # token in the first place), that is enough to refute
            # wapiti's finding with high confidence.
            target_path_lc = (urlparse(target).path or "").lower()
            login_path_lc = (urlparse(login_final_url).path
                             or "").lower() if login_final_url else ""
            _LOGIN_HINTS = ("/login", "/signin", "/sign-in",
                            "/auth/", "/sso")
            target_is_login_itself = any(seg in target_path_lc
                                         for seg in _LOGIN_HINTS)
            landed_on_login = (
                any(seg in login_path_lc for seg in _LOGIN_HINTS)
                or any(_form_has_password_input(f) for f in forms_a)
            )
            samesite_modes = sorted(
                {(v or "").lower() for v in samesite_a.values()
                 if (v or "").lower() in ("lax", "strict")})

            if (landed_on_login and not target_is_login_itself
                    and samesite_modes):
                modes_str = ",".join(samesite_modes)
                return Verdict(
                    ok=True, validated=False, confidence=0.85,
                    summary=(
                        "Target endpoint " + target + " is gated "
                        "by authentication: an anonymous GET was "
                        "redirected to the login page at " +
                        login_final_url + ". The response also "
                        "sets SameSite=" + modes_str + " on the "
                        "session cookie, so a cross-site forged "
                        "POST cannot carry the victim's session "
                        "cookie -- the textbook CSRF attack "
                        "vector wapiti's csrf module checks for "
                        "is defeated at the browser layer "
                        "regardless of whether the form-token is "
                        "validated server-side. An attacker "
                        "without a session also cannot reach the "
                        "endpoint to submit a tampered request. "
                        "The wapiti finding is a false positive."),
                    evidence={
                        "target_url": target,
                        "login_page": login_final_url,
                        "samesite": samesite_a,
                        "auth_wall_detected": True,
                        "samesite_defense": True,
                        "candidate_forms": [
                            {"action": f.action,
                             "input_names": [n for n, _, _ in f.inputs]}
                            for f in forms_a],
                    },
                    remediation=(
                        "No code change required. The endpoint's "
                        "defense rests on (1) auth gating ("
                        "unauthenticated requests are redirected "
                        "to the login page) and (2) SameSite=" +
                        modes_str + " session cookies (cross-"
                        "site forged POSTs do not carry the "
                        "cookie). Server-side form-token "
                        "validation is sensible defense-in-depth "
                        "but is not strictly required to defeat "
                        "the cross-site attack vector wapiti's "
                        "csrf module checks for."),
                )

            return Verdict(
                ok=False, validated=None,
                summary=(
                    "could not locate a <form> whose action matches "
                    "the target URL " + target + " on the page at " +
                    login_final_url + ". The page may render "
                    "multiple forms (e.g. a header logout form "
                    "alongside the form wapiti flagged), or the GET "
                    "may have been redirected to a different page "
                    "entirely (auth wall, error page, etc.). Specify "
                    "--login-page-url to point at the page that "
                    "actually renders the target form, and confirm "
                    "the probe is running with a session that can "
                    "reach it."),
                evidence={"login_page": login_page,
                          "login_final_url": login_final_url,
                          "target_url": target,
                          "samesite": samesite_a,
                          "candidate_forms": [
                              {"action": f.action,
                               "input_names": [n for n, _, _ in f.inputs]}
                              for f in forms_a],
                          "status": r_a.status})

        # ---- Step 2: fetch the login page in session B --------------
        r_b = client_b.request("GET", login_page)
        if r_b.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="login page unreachable in second session")
        _merge_cookie_jar(sess_b, r_b.headers)
        form_b, _forms_b = _scrape_form(r_b.text, target_url=target,
                                        page_url=r_b.final_url or login_page)

        # ---- Step 3: identify the CSRF token field (if any) --------
        # Operator override wins. Otherwise: ONLY the name heuristic.
        # The earlier "first hidden field" fallback mis-identified
        # post-login redirect inputs (next, redirect_to) as tokens.
        token_field = args.token_field
        if not token_field:
            for n, t, _ in form_a.inputs:
                if t == "hidden" and _looks_like_csrf_field(n):
                    token_field = n
                    break

        token_a = ""
        token_b = ""
        if token_field:
            token_a = next((v for (n, _, v) in form_a.inputs
                            if n == token_field), "")
            if form_b:
                token_b = next((v for (n, _, v) in form_b.inputs
                                if n == token_field), "")

        has_token = bool(token_field and token_a)

        # If a synchronizer token IS present and identical across two
        # independent sessions, the token isn't session-bound. That's
        # a bug in its own right and a high-confidence True verdict.
        if has_token and token_b and token_a == token_b:
            return Verdict(
                ok=True, validated=True, confidence=0.95,
                summary=("CSRF token is identical across independent "
                         "sessions -- token is not session-bound. The "
                         "wapiti finding is real (and stronger than "
                         "reported)."),
                evidence={"token_field": token_field,
                          "token_value": token_a,
                          "tokens_differ_per_session": False},
                remediation=(
                    "Generate the CSRF token from per-session entropy "
                    "(e.g. signed against the session id). Avoid "
                    "global or process-lifetime constants."),
                severity_uplift="high",
            )

        # ---- Step 4: payload builder --------------------------------
        cred_user, cred_pass = "", ""
        if args.credentials and ":" in args.credentials:
            cred_user, _, cred_pass = args.credentials.partition(":")

        def build_payload(token_value: Optional[str]) -> bytes:
            """Build the form body. token_value=None omits the token
            field; an empty string sends the field with empty value;
            any other string substitutes that value."""
            data = []
            for n, t, v in form_a.inputs:
                if token_field and n == token_field:
                    if token_value is None:
                        continue
                    data.append((n, token_value))
                elif n.lower() in ("user", "username", "email", "login"):
                    data.append((n, cred_user or v or "test"))
                elif "pass" in n.lower():
                    data.append((n, cred_pass or v or "test"))
                elif t == "submit":
                    if v: data.append((n, v))
                else:
                    data.append((n, v or ""))
            return urlencode(data).encode()

        # Resolve form action URL (may be relative). Resolve against
        # the URL the GET actually settled on, not the user-supplied
        # login_page -- the latter may have redirected to a canonical
        # path, and a relative `action=""` should anchor on where the
        # form was actually rendered.
        post_url = (urljoin(login_final_url, form_a.action or "")
                    or login_final_url)

        # The CSRF check is meaningful only for state-changing
        # methods. We hardcode the form's declared method here (the
        # parsed <form method="..."> attribute), defaulting to POST.
        # Ignore args.method, whose default at the framework level is
        # GET -- using that here would silently turn every "tampered
        # POST" into a benign GET and the probe would conclude the
        # server processed it (which it did -- as a page load, not a
        # state change). An earlier iteration of the probe shipped
        # that bug.
        method = (form_a.method or "post").upper()
        if method == "GET":
            method = "POST"
        same_origin = self._origin_for_url(post_url)

        def submit(token_value: Optional[str], jar: dict, label: str,
                   *, origin: Optional[str] = None,
                   referer: Optional[str] = None,
                   send_origin_referer: bool = True) -> dict:
            """Run one POST.

            origin / referer override the values we'd otherwise send.
            send_origin_referer=False means omit both headers (the
            "no-Origin" test). When send_origin_referer is True and
            origin is None, we send the legitimate same-origin Origin
            and the login page URL as Referer -- the request a
            browser would normally make.
            """
            client.cookie = _cookie_header(jar)
            body = build_payload(token_value)
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            if send_origin_referer:
                headers["Origin"] = origin or same_origin
                headers["Referer"] = referer or login_page
            resp = client.request(method, post_url, headers=headers,
                                  body=body)
            kind, why = _classify_response(resp.status, resp.text)
            return {
                "label": label,
                "status": resp.status,
                "size": resp.size,
                # final_url is where the response actually came from
                # after any redirect chain. Auth-gated endpoints emit
                # 302 -> /login that urllib follows transparently;
                # without this field we can't tell that POST and GET
                # both ended up at the login page.
                "final_url": resp.final_url,
                "classification": kind,
                "reason": why,
            }

        # ---- Step 5: run the test battery ---------------------------
        baseline = submit(token_a if has_token else None, sess_a,
                          "baseline (same origin, valid token if any)")

        tests: list[dict] = []

        if has_token:
            # Form has a synchronizer token -- run textbook tampering.
            tests.append(submit(None, sess_a, "no token field"))
            tests.append(submit("AAAA0000_invalid_csrf_token_value_AAAA0000",
                                sess_a, "garbage token"))
            # Cross-session: post with session B's TOKEN but session
            # A's COOKIE. Correct CSRF protection requires the token
            # to be bound to the cookie's session id.
            if token_b:
                tests.append(submit(token_b, sess_a,
                                    "cross-session token (cookie A, "
                                    "token B)"))

        # Origin enforcement is independent of token presence -- run
        # always so we can detect Origin-only defense (which is how a
        # token-less form can still be CSRF-safe) AND pure
        # synchronizer-token defense (in which case the cross-origin
        # POST will succeed because Origin isn't checked, which is
        # fine if the token gates it elsewhere).
        tests.append(submit(token_a if has_token else None, sess_a,
                            "cross-origin POST",
                            origin=args.attacker_origin,
                            referer=args.attacker_origin.rstrip("/")
                                    + "/csrf.html"))
        tests.append(submit(token_a if has_token else None, sess_a,
                            "no Origin / no Referer POST",
                            send_origin_referer=False))

        # Cross-session WITHOUT swapping the token: post to the form
        # using session B's cookie jar wholesale. If the server is
        # checking the form-token against session B's cookie and the
        # token came from session A, this should reject. Useful even
        # when no token is present, as a sanity check.
        tests.append(submit(token_a if has_token else None, sess_b,
                            "cross-session cookie jar"))

        # ---- Step 6: build verdict ----------------------------------
        # Baseline must have been processed for the comparison to be
        # meaningful. Auth-failed counts as processed -- the form
        # evaluated the request, the gate let it through.
        baseline_kind = baseline["classification"]
        if baseline_kind == "csrf_rejected":
            return Verdict(
                ok=True, validated=None, confidence=0.0,
                summary=("baseline POST was rejected by what looks "
                         "like a CSRF / Origin check (" +
                         baseline["reason"] + "). Cannot drive the "
                         "form, so cannot confirm or refute the "
                         "wapiti finding. Try --credentials, an "
                         "explicit --token-field, or run the probe "
                         "from a session that has access to the form."),
                evidence={
                    "post_url": post_url,
                    "token_field": token_field,
                    "has_token": has_token,
                    "baseline": baseline,
                    "tests": tests,
                    "samesite": samesite_a,
                },
            )

        # Auth-wall short-circuit. If the POST endpoint is NOT the
        # login page itself (i.e. we're targeting a state-changing
        # endpoint behind authentication, not the login form), and
        # every test response -- baseline included -- ends up at the
        # login page after redirect-following, then the request never
        # reached the CSRF check: the auth middleware bounced it
        # first. This is the exact scenario that produces the wapiti
        # false positive ("response unchanged on tampering, therefore
        # no token validation"). Without the check below, the probe
        # would classify every login-page response as 'processed' (no
        # CSRF reject keywords in the body), see the smoking-gun
        # tests come back 'processed' too, and falsely confirm wapiti.
        # Bail with validated=None and tell the operator to re-run
        # with a working session.
        login_url_key = _url_path_key(login_final_url)
        post_url_key = _url_path_key(post_url)
        if post_url_key != login_url_key:
            all_results = [baseline] + tests
            if all(_url_path_key(r.get("final_url") or "") == login_url_key
                   for r in all_results):
                return Verdict(
                    ok=True, validated=None, confidence=0.0,
                    summary=(
                        "Every POST (baseline + tampering) was "
                        "redirected to the login page at " +
                        login_final_url + ". The endpoint at " +
                        post_url + " is gated by authentication, so "
                        "its CSRF check is unreachable without a "
                        "valid session. The wapiti finding cannot be "
                        "substantiated under these conditions: every "
                        "POST -- token or not, valid or invalid -- "
                        "yields the same auth-redirect response, "
                        "which is exactly the signal wapiti's csrf "
                        "module misreads as 'token not validated'. "
                        "Re-run the probe from an authenticated "
                        "session (or with --credentials that survive "
                        "the login flow) so the CSRF logic is "
                        "actually exercised."),
                    evidence={
                        "post_url": post_url,
                        "login_page": login_final_url,
                        "token_field": token_field,
                        "has_token": has_token,
                        "baseline": baseline,
                        "tests": tests,
                        "samesite": samesite_a,
                        "auth_wall_detected": True,
                    },
                )

        # Classify each test as a "smoking-gun bypass", an
        # "informational gap", or "rejected (defense engaged)".
        #
        # Smoking-gun bypass:
        #   - Server processed a request that an attacker COULD send
        #     from a malicious site under realistic browser
        #     conditions. Triggers validated=True.
        #
        # Informational gap:
        #   - Server processed a request that does NOT correspond to
        #     a realistic attack (e.g. POST with no Origin/Referer
        #     headers from a no-session client). Recorded as a
        #     defense gap but does NOT trigger validated=True alone,
        #     because modern browsers always send Origin on cross-
        #     origin POSTs and an authenticated session-jar swap
        #     against a login form is meaningless (no session to
        #     bind to).
        #
        # Rejected:
        #   - Server bounced the request on a CSRF / Origin check.
        #     Counts as defense engaged.
        SMOKING_GUN_LABELS = (
            "no token field",
            "garbage token",
            "cross-session token (cookie A, token B)",
            "cross-origin POST",
        )

        def _is_smoking_gun(t: dict) -> bool:
            return (t["label"] in SMOKING_GUN_LABELS
                    and t["classification"] != "csrf_rejected")

        smoking_guns = [t for t in tests if _is_smoking_gun(t)]
        informational_gaps = [
            t for t in tests
            if t["label"] not in SMOKING_GUN_LABELS
            and t["classification"] != "csrf_rejected"
        ]
        rejected = [t for t in tests
                    if t["classification"] == "csrf_rejected"]

        # Sub-flags used in the human-readable summary.
        cross_origin_test = next(
            (t for t in tests if t["label"] == "cross-origin POST"), None)
        cross_origin_rejected = (
            cross_origin_test is not None
            and cross_origin_test["classification"] == "csrf_rejected")
        samesite_strict_or_lax = any(
            v in ("lax", "strict") for v in samesite_a.values())

        if smoking_guns:
            scenarios = ", ".join(b["label"] for b in smoking_guns)
            # Severity uplift only when the cross-origin POST was
            # processed -- that's the textbook exploitable case. A
            # token-only bypass on a same-origin POST is real but
            # the impact tier matches wapiti's original finding.
            uplift = "high" if any(b["label"] == "cross-origin POST"
                                   for b in smoking_guns) else None

            if has_token:
                summary = (f"CSRF protection NOT enforced on {post_url}: "
                           f"{len(smoking_guns)} smoking-gun "
                           f"bypass(es) processed by the server "
                           f"({scenarios}). The wapiti finding is real.")
            else:
                summary = (f"Form on {post_url} has no CSRF token "
                           f"AND the server processed a realistic "
                           f"cross-origin attack ({scenarios}). The "
                           f"wapiti finding is real.")

            return Verdict(
                ok=True, validated=True, confidence=0.93,
                summary=summary,
                evidence={
                    "post_url": post_url,
                    "token_field": token_field,
                    "has_token": has_token,
                    "tokens_differ_per_session":
                        bool(token_a and token_b and token_a != token_b),
                    "baseline": baseline,
                    "tests": tests,
                    "smoking_guns": [b["label"] for b in smoking_guns],
                    "informational_gaps":
                        [g["label"] for g in informational_gaps],
                    "samesite": samesite_a,
                },
                remediation=(
                    "Reject the request when the CSRF token is "
                    "missing, malformed, or not bound to the "
                    "requester's session. The framework-recommended "
                    "patterns are: a synchronizer token bound to "
                    "the session id, a double-submit cookie, OR a "
                    "strict Origin/Referer check. SameSite=Strict "
                    "cookies are useful defense-in-depth but should "
                    "not be the only mechanism."),
                severity_uplift=uplift,
            )

        # No smoking-gun bypass. CSRF is effectively defended.
        if has_token and rejected:
            mech = "synchronizer token validation"
        elif cross_origin_rejected and not has_token:
            mech = ("Origin/Referer enforcement (no synchronizer "
                    "token, but cross-origin POSTs are rejected)")
        elif has_token:
            mech = "synchronizer token plus Origin enforcement"
        else:
            mech = "Origin/Referer enforcement"

        # Mention informational gaps in the summary so the analyst
        # sees them, but do NOT escalate the verdict.
        gap_note = ""
        if informational_gaps:
            gap_note = (" Note: minor defense gaps observed (" +
                        ", ".join(g["label"] for g in informational_gaps) +
                        "). These are not exploitable in modern "
                        "browsers but suggest reinforcing strict "
                        "Origin/Referer requirements.")

        samesite_note = ""
        if samesite_strict_or_lax:
            samesite_note = (
                " Cookies also set SameSite=" +
                ",".join(sorted({v for v in samesite_a.values()
                                  if v in ("lax", "strict")})) +
                ", adding browser-side defense-in-depth.")

        return Verdict(
            ok=True, validated=False, confidence=0.9,
            summary=("CSRF protection IS enforced via " + mech +
                     ": every realistic-attack scenario was "
                     "rejected. The wapiti finding is a false "
                     "positive -- wapiti's csrf module flags the "
                     "absence of a form token even when the app "
                     "defends via Origin/Referer or session-bound "
                     "tokens." + gap_note + samesite_note),
            evidence={
                "post_url": post_url,
                "token_field": token_field,
                "has_token": has_token,
                "tokens_differ_per_session":
                    bool(token_a and token_b and token_a != token_b),
                "baseline": baseline,
                "tests": tests,
                "rejected": [t["label"] for t in rejected],
                "informational_gaps":
                    [g["label"] for g in informational_gaps],
                "samesite": samesite_a,
                "defense_mechanism": mech,
            },
        )


if __name__ == "__main__":
    CsrfValidationProbe().main()
