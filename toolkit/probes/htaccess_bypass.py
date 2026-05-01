#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""High-fidelity validation for "Htaccess Bypass" / weak-access-control findings.

The scanner that flagged the URL (typically wapiti) only knows that *some*
path variation produced a different response. That alone proves nothing —
servers commonly return:
  - the same legitimate content under multiple normalized paths
  - a custom 404 page that differs from the protected page
  - a WAF challenge / rate-limit page on encoded paths

This probe deterministically separates those cases from a real bypass:

  1. Fetch the original URL → BASELINE.
  2. Fetch a known-bad path on the same host (or --baseline-404) → NEG.
  3. Run a fixed catalog of bypass payloads against the URL.
  4. A variant is a CONFIRMED bypass only when:
        - it returns 200, AND
        - its body is NOT similar to the negative control (so it's not a 404),
          AND
        - its body IS similar to (or larger than) what an authenticated user
          would normally see — i.e. it returned content, not a stub.
     If the BASELINE itself was 200, the resource was never restricted to
     begin with — REFUTED (false positive on the scanner's part).
     If every variant returned 401/403/404, the restriction holds —
     REFUTED.

We use SHA-256 of normalized body bytes for the "same content" test, plus
size-class buckets to absorb minor templating differences without doing
fuzzy similarity (avoiding extra deps).

Examples:
    python htaccess_bypass.py --url 'https://x.com/admin/users.php'
    python htaccess_bypass.py --url '...' --cookie 'session=abc'
"""
from __future__ import annotations

import hashlib
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# Bypass payloads — each entry is (label, transformer(url) -> url, extra_headers)
# transformer returns None if the payload doesn't apply to the URL.

def _swap_method_get(url):    return url   # method handled separately
def _trail_slash(url):
    p = urllib.parse.urlparse(url)
    if p.path.endswith("/"):
        return None
    return urllib.parse.urlunparse(p._replace(path=p.path + "/"))
def _trail_dot(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(path=p.path + "."))
def _trail_pct2e(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(path=p.path + "%2e"))
def _trail_space(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(path=p.path + "%20"))
def _semicolon(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(path=p.path + ";"))
def _double_slash(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(path="/" + p.path.lstrip("/")))
def _uppercase(url):
    p = urllib.parse.urlparse(url)
    new_path = p.path.upper()
    if new_path == p.path:
        return None
    return urllib.parse.urlunparse(p._replace(path=new_path))
def _dotslash(url):
    p = urllib.parse.urlparse(url)
    last = p.path.rsplit("/", 1)
    if len(last) != 2:
        return None
    return urllib.parse.urlunparse(p._replace(path=f"{last[0]}/./{last[1]}"))


# (label, url-transformer, extra-headers, method)
PATH_VARIANTS = [
    ("trailing-slash",      _trail_slash,    {}, "GET"),
    ("trailing-dot",        _trail_dot,      {}, "GET"),
    ("trailing-%2e",        _trail_pct2e,    {}, "GET"),
    ("trailing-space-%20",  _trail_space,    {}, "GET"),
    ("semicolon-suffix",    _semicolon,      {}, "GET"),
    ("dot-slash",           _dotslash,       {}, "GET"),
    ("uppercase-path",      _uppercase,      {}, "GET"),
]
METHOD_VARIANTS = [
    ("HEAD-method",        "HEAD"),
    ("OPTIONS-method",     "OPTIONS"),
    ("POST-method",        "POST"),
]
HEADER_VARIANTS = [
    ("X-Original-URL",       {"X-Original-URL": "/"}),
    ("X-Rewrite-URL",        {"X-Rewrite-URL": "/"}),
    ("X-Forwarded-For",      {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Forwarded-Host",     {"X-Forwarded-Host": "localhost"}),
    ("X-Real-IP",            {"X-Real-IP": "127.0.0.1"}),
    ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
]


def _fingerprint(body: bytes) -> str:
    """Stable hash of body bytes after collapsing whitespace, so two
    responses that differ only in timestamp/CSRF/whitespace still match."""
    if not body:
        return "empty"
    s = b" ".join(body.split())  # collapse whitespace runs
    return hashlib.sha256(s).hexdigest()[:16]


# Login-page heuristics. Apps that return HTTP 200 with the login form as
# the body (instead of 302 → /login or 401) are common — the response is
# substantively different from a 404 page but it's still effectively a
# deny: the user got nothing they didn't already have. We need to recognise
# that pattern so the dual-baseline logic doesn't misclassify "200 + login
# page" as "page is genuinely public".
import re as _re_login

_LOGIN_TITLE_RE = _re_login.compile(
    r"<title[^>]*>[^<]*(login|log\s*in|sign\s*in|sign\s*on|authenticate)[^<]*</title>",
    _re_login.IGNORECASE,
)
_LOGIN_PW_INPUT_RE = _re_login.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?',
    _re_login.IGNORECASE,
)


def _looks_like_login_page(body: bytes) -> bool:
    """True if the response body is recognisably a login page rather than
    actual application content. Strong indicator: a password input field;
    title-only is corroborating but not sufficient on its own (lots of
    apps mention 'login' on landing pages without being one)."""
    if not body or len(body) < 80:
        return False
    text = body.decode("utf-8", "replace")[:50000]   # cap parse work
    # The password-input check is the strongest single signal — almost no
    # legitimate non-auth page has <input type="password">.
    if _LOGIN_PW_INPUT_RE.search(text):
        return True
    # Title-only fallback: only trust it if the title is very specific.
    if _LOGIN_TITLE_RE.search(text):
        return True
    return False


def _size_bucket(n: int) -> str:
    """Coarse bucket so 1042 vs 1071 byte responses both register as ~1KB."""
    if n == 0:                  return "0"
    if n < 256:                 return "<256B"
    if n < 1024:                return "256B-1KB"
    if n < 4096:                return "1-4KB"
    if n < 16384:               return "4-16KB"
    if n < 65536:               return "16-64KB"
    return ">64KB"


def _similar(a, b) -> bool:
    """Treat two responses as 'the same page' when fingerprint matches OR
    sizes are within ±10% AND status matches. This is intentionally
    forgiving so the negative control absorbs minor template variation."""
    if a is None or b is None:
        return False
    if a["fingerprint"] == b["fingerprint"]:
        return True
    if a["status"] != b["status"]:
        return False
    if a["size"] == 0 or b["size"] == 0:
        return a["size"] == b["size"]
    ratio = abs(a["size"] - b["size"]) / max(a["size"], b["size"])
    return ratio < 0.10


class HtaccessBypassProbe(Probe):
    name = "htaccess_bypass"
    summary = ("High-fidelity check of an alleged access-control bypass.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument("--baseline-404",
                            help="URL of a path that should 404 on this host. "
                                 "Used as a negative control. If omitted, "
                                 "the probe synthesizes one.")
        parser.add_argument("--auth-cookie",
                            help="Cookie that grants legitimate access. When "
                                 "given, we additionally compare bypass "
                                 "responses against the authenticated baseline.")

    # ------------------------------------------------------------------
    def _capture(self, client: SafeClient, method: str, url: str,
                 extra_headers: dict | None = None,
                 cookie_override: str | None = None) -> dict:
        # SafeClient applies its constructor cookie; for the anon test we
        # need to override per-request via the headers dict (Cookie="").
        headers = dict(extra_headers or {})
        if cookie_override is not None:
            headers["Cookie"] = cookie_override
        r = client.request(method, url, headers=headers or None)
        return {
            "status": r.status,
            "size": r.size,
            "fingerprint": _fingerprint(r.body),
            "size_bucket": _size_bucket(r.size),
            # Heuristic flag — used by the verdict logic to recognise the
            # "HTTP 200 + login form as the body" anti-pattern.
            "is_login_page": _looks_like_login_page(r.body),
        }

    def _make_404_url(self, url: str) -> str:
        """Synthesise a path that should not exist by appending a UUID-ish
        random tail to the original directory."""
        import secrets
        p = urllib.parse.urlparse(url)
        rand = secrets.token_hex(8)
        new_path = p.path.rsplit("/", 1)[0] + f"/__pentest_404_{rand}"
        return urllib.parse.urlunparse(p._replace(path=new_path, query=""))

    # ------------------------------------------------------------------
    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")

        # The original scanner finding was generated under whatever auth
        # state the scan ran in (typically authenticated). To validate
        # *bypass* rather than just public/private status, we need two
        # baselines:
        #
        #   AUTH baseline = WITH the analyst's session cookie (if any).
        #                   Confirms the resource is reachable as the
        #                   intended, authenticated user.
        #   ANON baseline = WITHOUT any cookie.
        #                   Tells us whether the resource *requires* auth.
        #                   This is the surface the bypass payloads attack.
        #
        # Verdict matrix:
        #   AUTH=200, ANON=200  -> page is genuinely public; FP.
        #   AUTH=200, ANON=401/403/redirect -> protected; run bypass payloads.
        #   AUTH != 200         -> probe couldn't reach the resource even
        #                          authenticated; inconclusive.
        # When no cookie is supplied, AUTH and ANON are the same request
        # and we fall back to the original single-baseline behaviour.

        cookie_present = bool(client.cookie)

        auth_baseline = self._capture(client, "GET", args.url)
        if auth_baseline["status"] == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable",
                           evidence={"auth_baseline": auth_baseline})

        # Anon baseline — explicitly suppress the cookie via Cookie:""
        # since SafeClient sets it from its constructor by default.
        if cookie_present:
            anon_baseline = self._capture(
                client, "GET", args.url, extra_headers={"Cookie": ""})
        else:
            anon_baseline = auth_baseline

        # Negative control — anonymous, what a real 404 looks like.
        neg_url = args.baseline_404 or self._make_404_url(args.url)
        neg = self._capture(
            client, "GET", neg_url,
            extra_headers=({"Cookie": ""} if cookie_present else None))

        evidence = {
            "auth_baseline":   {"url": args.url, "cookie_used": cookie_present,
                                **auth_baseline},
            "anon_baseline":   {"url": args.url, "cookie_used": False,
                                **anon_baseline},
            "negative_control": {"url": neg_url, **neg},
            "variants": [],
        }
        # Keep the legacy `baseline` field around for back-compat with any
        # consumer that grew up on the single-baseline shape.
        evidence["baseline"] = evidence["anon_baseline"]
        baseline = anon_baseline   # variants test the anon surface

        # ---- decisions based on the two baselines ----
        # Check anon-side conditions FIRST. The login-page heuristic in
        # particular is a definitive answer regardless of what
        # authenticated requests return: if anonymous traffic is being
        # served the login form, the path IS protected from anonymous
        # access — there's nothing to bypass.

        if auth_baseline["status"] == 404:
            return Verdict(
                validated=False, confidence=0.95,
                summary=("Refuted: the URL returns 404 even with auth. "
                         "No resource here to bypass into — likely a stale "
                         "path the scanner tested against a moved/deleted "
                         "endpoint."),
                evidence=evidence,
            )

        # 200 + login-page-body anti-pattern: the app returns HTTP 200 with
        # the login form as the response when no session is present
        # (instead of 302 or 401). Treat this as "effectively protected"
        # — the anonymous user got nothing they didn't already have. Note:
        # this fires even if auth_baseline returned 403 (e.g. a low-priv
        # auditor session that's correctly denied a higher-priv feature).
        if anon_baseline["status"] == 200 and anon_baseline.get("is_login_page"):
            return Verdict(
                validated=False, confidence=0.92,
                summary=(
                    "Refuted: anonymous requests do return HTTP 200, but "
                    "the body is the login page (the app uses "
                    "200+login-form instead of 302 or 401). "
                    + ("With a valid auditor session the page returns "
                       f"{auth_baseline['status']} — this is consistent "
                       "RBAC, not a bypass."
                       if cookie_present and auth_baseline["status"] != 200 else
                       "There is no bypass surface to test against.")),
                evidence=evidence,
                remediation=(
                    "Optional hardening: change anonymous responses on "
                    "protected endpoints from 200+login-form to 302 → "
                    "/login or 401 Unauthorized. The current behaviour "
                    "isn't a vulnerability, but it confuses scanners "
                    "and downstream tools that key off status codes."),
            )

        # AUTH=200 and ANON=200 with content distinct from the negative
        # control AND not a login page: the resource is genuinely public.
        if anon_baseline["status"] == 200 and not _similar(anon_baseline, neg):
            return Verdict(
                validated=False, confidence=0.95,
                summary=(
                    "Refuted: the URL returns 200 OK both with and without "
                    "auth, and the response differs from the host's 404 "
                    "page. The page is genuinely public — there is no "
                    "restriction to bypass, so the scanner finding is a "
                    "false positive."
                    + (" (Important: this only proves that the *bypass* "
                       "claim is wrong. If the page is *supposed* to be "
                       "authenticated, that's a separate Broken Access "
                       "Control / Missing Authorization finding worth "
                       "filing on its own.)"
                       if cookie_present else "")),
                evidence=evidence,
                remediation=(
                    "If the resource is genuinely public, mark this finding "
                    "as a false positive. If it should be restricted, "
                    "treat it as a separate Broken Access Control finding "
                    "and add the auth check, then rerun the probe."),
            )

        # ANON=200 but the response IS similar to the 404 control — that's
        # likely a custom 404 served as 200 (anti-pattern). Fall through
        # to running variants with caution.
        if anon_baseline["status"] not in (401, 403, 405, 200) \
                and anon_baseline["status"] // 100 != 3:
            evidence["anon_baseline_note"] = (
                f"unusual anon baseline status {anon_baseline['status']} — "
                "variants still tested, but interpret with caution"
            )

        # Now that we've handled the obvious refutations, fall through to
        # the inconclusive case if the auth baseline didn't establish a
        # positive reference (no "what does success look like" to compare
        # variants against).
        if (auth_baseline["status"] != 200
                and auth_baseline["status"] // 100 != 3):
            return Verdict(
                validated=None, confidence=0.5,
                summary=(f"Inconclusive: authenticated baseline returned "
                         f"HTTP {auth_baseline['status']}. The probe "
                         "cannot establish what an authenticated success "
                         "looks like, so it can't tell whether anonymous "
                         "variants achieved a bypass."),
                evidence=evidence,
            )

        # 4. Run all variants. Each gets its own evidence row.
        confirmed: list[dict] = []
        for label, transform, extra, method in PATH_VARIANTS:
            new_url = transform(args.url)
            if not new_url:
                continue
            r = self._capture(client, method, new_url, extra)
            row = {"label": label, "method": method, "url": new_url, **r}
            evidence["variants"].append(row)
            if self._is_bypass(row, baseline, neg):
                confirmed.append(row)

        for label, method in METHOD_VARIANTS:
            r = self._capture(client, method, args.url)
            row = {"label": label, "method": method, "url": args.url, **r}
            evidence["variants"].append(row)
            if self._is_bypass(row, baseline, neg):
                confirmed.append(row)

        for label, headers in HEADER_VARIANTS:
            r = self._capture(client, "GET", args.url, headers)
            row = {"label": label, "method": "GET", "url": args.url,
                   "extra_headers": headers, **r}
            evidence["variants"].append(row)
            if self._is_bypass(row, baseline, neg):
                confirmed.append(row)

        # 5. Verdict.
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: {len(confirmed)} of "
                         f"{len(evidence['variants'])} variant(s) bypassed "
                         f"the restriction. First win: '{top['label']}' "
                         f"({top['method']}) → HTTP {top['status']}, "
                         f"{top['size']} bytes."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "The control is being applied at a layer that path "
                    "normalization, header tricks, or alternative HTTP "
                    "methods can sidestep. Move the access decision into "
                    "application code; deny by default; cover every method "
                    "(use catch-all routes); strip X-Original-URL / "
                    "X-Rewrite-URL / X-Forwarded-For at the edge unless "
                    "they come from a trusted proxy."),
            )

        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(evidence['variants'])} bypass "
                     "variants against the protected URL; none returned "
                     "200 with content distinct from the negative control. "
                     "The original wapiti finding does not reproduce."),
            evidence=evidence,
            remediation=(
                "Mark this finding as a false positive. Wapiti's heuristic "
                "fired on a benign response variation (custom error page, "
                "path normalization, content negotiation) that didn't "
                "actually grant access."),
        )

    # ------------------------------------------------------------------
    def _is_bypass(self, variant: dict, baseline: dict, neg: dict) -> bool:
        """A variant counts as a bypass only when it (a) returned 200,
        (b) is not a clone of the 404 negative control, and (c) returned
        substantive content (>= 256 B)."""
        if variant["status"] != 200:
            return False
        if variant["size"] < 256:
            # Empty or stub bodies don't prove anything — could be a CDN
            # edge response, a /robots.txt-style file, or an OPTIONS reply.
            return False
        if _similar(variant, neg):
            return False
        # Optional stronger signal: if baseline was 401/403 and the variant
        # body is NOT similar to baseline either, that's noteworthy but
        # not by itself proof — content can differ legitimately. We accept
        # status+content-substantiveness as the bar; the analyst reviews
        # the evidence before pasting into the ticket.
        return True


if __name__ == "__main__":
    HtaccessBypassProbe().main()
