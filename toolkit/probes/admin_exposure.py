#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""High-fidelity validation for "Administrative interface exposed" findings.

Background
----------
Content-discovery scanners (ffuf, dirb, gobuster, nikto) flag any path that
matches a wordlist of admin-y names (/admin, /server-status, /phpmyadmin,
/jenkins, /grafana, ...) as an "Administrative interface exposed" finding.
That's a high-noise heuristic. The same regex match could mean any of:

  (a) Genuinely exposed admin console — anonymous traffic gets a working
      management page. This is the real vulnerability.
  (b) Gated path — the path exists but the web server returns 401/403 to
      both anonymous AND authenticated traffic (e.g. Apache mod_status
      restricted by IP). NOT a vulnerability.
  (c) The authenticated user's own admin area — anon gets a deny, the
      authenticated session sees a working page. Intended access, not
      exposure. (Whether non-admins should see it is a separate RBAC
      question outside this probe's remit.)
  (d) A marketing/landing page that happens to mention "admin" — public
      content with no privileged surface behind it.

This probe separates those cases by capturing two baselines and looking
for *user-identity reflection* — if the assessment ran with credentials,
the analyst's username should appear somewhere in a real admin page (a
"Welcome, jsmith" header, a user-menu, a profile link). When the
username is reflected we have positive evidence the page is rendering
authenticated content for *that* user.

Privacy
-------
The username travels into the probe via stdin JSON (so it never appears
in `ps aux`) and is *never* echoed back into the verdict in the clear.
What we record is only:
    SHA-256(username) truncated to 16 hex chars
This proves identity reflection without putting the credential — even a
public-looking handle — into the persisted evidence blob.

Verdict matrix
--------------
                 anon=200/sub.   anon=401/403    anon=other
auth=200/sub.    PUBLIC ADMIN    AUTH'D ADMIN    INCONCL.
                 (validated      (refuted on
                  if not login    'exposed';
                  page)           reflection
                                  noted)
auth=401/403     n/a*            GATED (FP)      INCONCL.
auth=other       INCONCL.        INCONCL.        INCONCL.

  * "auth gets denied while anon gets through" is implausible; we mark it
    INCONCLUSIVE and let the analyst eyeball the audit log.

Examples
--------
    python admin_exposure.py --url 'https://x.com/server-status'
    python admin_exposure.py --url '...' --cookie '...' --auth-username 'admin'
"""
from __future__ import annotations

import hashlib
import re
import sys
import urllib.parse
from pathlib import Path

# Probes live in toolkit/probes/; the shared lib is one level up.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# ---------------------------------------------------------------------------
# Heuristics shared with htaccess_bypass. Kept inline (rather than imported)
# so each probe is self-contained — moving probes around between hosts only
# requires the toolkit/lib/ directory, not sibling probe files.
# ---------------------------------------------------------------------------

_LOGIN_TITLE_RE = re.compile(
    r"<title[^>]*>[^<]*(login|log\s*in|sign\s*in|sign\s*on|authenticate)[^<]*</title>",
    re.IGNORECASE,
)
_LOGIN_PW_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?',
    re.IGNORECASE,
)


def _looks_like_login_page(body: bytes) -> bool:
    """True if the response is recognisably a login form rather than the
    actual admin interface. The presence of <input type="password"> is
    almost a definitive tell — legitimate admin pages don't have one."""
    if not body or len(body) < 80:
        return False
    text = body.decode("utf-8", "replace")[:50000]   # cap parse work
    if _LOGIN_PW_INPUT_RE.search(text):
        return True
    if _LOGIN_TITLE_RE.search(text):
        return True
    return False


def _fingerprint(body: bytes) -> str:
    """Stable hash of body bytes after collapsing whitespace, so two
    responses that differ only in CSRF / timestamp / whitespace match."""
    if not body:
        return "empty"
    return hashlib.sha256(b" ".join(body.split())).hexdigest()[:16]


def _size_bucket(n: int) -> str:
    """Coarse size bucket — small differences within a bucket are noise."""
    if n == 0:                  return "0"
    if n < 256:                 return "<256B"
    if n < 1024:                return "256B-1KB"
    if n < 4096:                return "1-4KB"
    if n < 16384:               return "4-16KB"
    if n < 65536:               return "16-64KB"
    return ">64KB"


def _similar(a: dict | None, b: dict | None) -> bool:
    """Two responses are 'the same page' when fingerprint matches OR
    sizes are within 10% AND statuses match. Forgiving on purpose so a
    noise-y custom 404 still gets caught by the negative-control check."""
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


def _hash_username(username: str) -> str:
    """Return a stable, short fingerprint of the username for evidence
    storage. Truncated to 16 hex chars — collision risk is irrelevant
    since this only has to match against the body of one specific
    response, not deanonymise across a set."""
    if not username:
        return ""
    return hashlib.sha256(username.encode("utf-8", "replace")).hexdigest()[:16]


def _identity_reflected(body: bytes, username: str) -> bool:
    """True when the username appears verbatim in the response body.

    Plain substring match, case-insensitive — almost every admin
    template echoes the username one way or another (header greeting,
    user-menu link, profile button, breadcrumb). False negatives are
    fine: a missing reflection just leaves the verdict INCONCLUSIVE
    rather than flipping it to REFUTED, so we don't lose information."""
    if not body or not username or len(username) < 3:
        # Refuse very short usernames — too many false positives ('a',
        # 'ab' would reflect everywhere).
        return False
    try:
        haystack = body.decode("utf-8", "replace").lower()
    except Exception:
        return False
    return username.lower() in haystack


# ---------------------------------------------------------------------------
class AdminExposureProbe(Probe):
    name = "admin_exposure"
    summary = ("Validates whether a path flagged as an 'Administrative "
               "interface exposed' is actually exposed: distinguishes "
               "public admin / authenticated-only admin / gated-by-server "
               "/ misclassified marketing page.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--auth-username",
            default="",
            help="Username the assessment authenticated as. Used to "
                 "detect identity reflection in the response body. "
                 "The probe never echoes the value back — only a 16-hex "
                 "SHA-256 fingerprint is stored in evidence.")
        parser.add_argument(
            "--baseline-404",
            help="Optional URL guaranteed to 404 on this host. If "
                 "omitted, the probe synthesizes one.")

    # ------------------------------------------------------------------
    def _capture(self, client: SafeClient, url: str,
                 cookie_override: str | None = None,
                 username: str = "") -> dict:
        """One GET, summarized into the row shape used throughout the
        verdict matrix. cookie_override="" actively suppresses the
        client's default cookie (anon baseline)."""
        headers = {}
        if cookie_override is not None:
            headers["Cookie"] = cookie_override
        r = client.request("GET", url, headers=headers or None)
        body = r.body or b""
        return {
            "url": url,
            "status": r.status,
            "size": r.size,
            "fingerprint": _fingerprint(body),
            "size_bucket": _size_bucket(r.size),
            "is_login_page": _looks_like_login_page(body),
            # identity_reflected only makes sense when both username and
            # body exist; record it unconditionally so the absence of
            # reflection is also visible to the analyst.
            "identity_reflected": _identity_reflected(body, username),
        }

    def _make_404_url(self, url: str) -> str:
        """A path that should 404 on the host: append a random tag to
        the URL's directory. Random suffix ensures we don't accidentally
        hit a cached path that legitimately exists."""
        import secrets
        p = urllib.parse.urlparse(url)
        new_path = p.path.rsplit("/", 1)[0] + f"/__pentest_404_{secrets.token_hex(8)}"
        return urllib.parse.urlunparse(p._replace(path=new_path, query=""))

    # ------------------------------------------------------------------
    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")

        username = (getattr(args, "auth_username", "") or "").strip()
        cookie_present = bool(client.cookie)

        # AUTH baseline — request as the authenticated analyst.
        auth = self._capture(client, args.url, username=username)
        if auth["status"] == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable",
                           evidence={"auth_baseline": auth})

        # ANON baseline — strip the cookie even if the client has one.
        if cookie_present:
            anon = self._capture(client, args.url, cookie_override="",
                                 username=username)
        else:
            anon = auth   # no cookie was supplied; auth==anon by definition

        # Negative control — what an honest 404 looks like, anonymous so
        # it isn't accidentally rendered as a privileged "not found".
        neg_url = args.baseline_404 or self._make_404_url(args.url)
        neg = self._capture(
            client, neg_url,
            cookie_override="" if cookie_present else None,
            username=username)

        # Build evidence skeleton up front so every return path has the
        # same shape — keeps the workspace UI simple.
        evidence = {
            "auth_baseline":   {**auth,   "cookie_used": cookie_present},
            "anon_baseline":   {**anon,   "cookie_used": False},
            "negative_control": neg,
            "username_fingerprint": _hash_username(username) if username else "",
            "username_present": bool(username),
        }

        # ------------------------------------------------------------------
        # Verdict matrix — see module docstring. We test cases in order
        # of decisiveness (the strongest "no" first, the strongest "yes"
        # next, then the ambiguous middle).
        # ------------------------------------------------------------------

        # Strong refutation: both auth and anon are denied at the web-
        # server layer (401/403). The response is distinct from a real
        # 404 (we still verify that, so we don't accidentally bless a
        # custom 404 served as 403). Apache mod_status restricted by
        # IP, htaccess Require, etc. fall here.
        if (auth["status"] in (401, 403) and anon["status"] in (401, 403)
                and not _similar(auth, neg)):
            return Verdict(
                validated=False, confidence=0.92,
                summary=(
                    f"Refuted: the path returns HTTP {anon['status']} to "
                    "both anonymous and authenticated traffic. The "
                    "response is a real deny page (distinct from the "
                    "host's 404), so the URL exists — but it is gated "
                    "at the web-server / network layer, not exposed. "
                    "The original scanner finding is a false positive."),
                evidence=evidence,
                remediation=(
                    "No remediation required. Mark the finding as a "
                    "false positive. (If you want fewer scanner hits "
                    "on this path, return 404 to anonymous probes "
                    "instead of 403 — but 403 here is correct behavior.)"),
            )

        # 'Exposed to anonymous traffic' — anon got a substantive 200
        # that isn't the host's 404 page and isn't the login form.
        if (anon["status"] == 200 and anon["size"] >= 256
                and not _similar(anon, neg)
                and not anon["is_login_page"]):
            # Authenticated also got 200 with the same content → either
            # a genuinely public page (could be a marketing /admin
            # landing page) or a real public admin console. The body
            # being substantive + not a login form already weighs
            # toward "real admin console", but the analyst should
            # still review.
            confidence = 0.88
            same_as_auth = _similar(anon, auth)
            return Verdict(
                validated=True, confidence=confidence,
                summary=(
                    f"Validated: the path responds to anonymous "
                    f"traffic with HTTP 200 and {anon['size']} bytes "
                    "of substantive content (distinct from the "
                    "host's 404 page and not a login form). "
                    + ("Authenticated and anonymous responses are the "
                       "same page, so the admin surface is fully "
                       "public."
                       if same_as_auth else
                       "Anonymous content is substantively different "
                       "from the authenticated view — partial public "
                       "exposure of the admin surface.")),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Place the admin interface behind authentication "
                    "(or, if it must remain reachable for ops reasons, "
                    "behind a network-layer ACL: VPN, IP allow-list, "
                    "or mTLS). If this is intentionally public — e.g. "
                    "a marketing page that just happens to live at "
                    "/admin — rename the path or mark this finding "
                    "as a false positive."),
            )

        # Authenticated user gets a working page; anonymous user is
        # blocked. This is the textbook "gated by app auth, not
        # exposed" pattern. We use the username-reflection signal to
        # split the verdict between "intended admin area for this
        # user" and "page renders for the user but identity not
        # confirmed".
        if (auth["status"] == 200 and auth["size"] >= 256
                and not auth["is_login_page"]
                and anon["status"] in (302, 401, 403)):
            if username and auth["identity_reflected"]:
                return Verdict(
                    validated=False, confidence=0.85,
                    summary=(
                        "Refuted on 'exposed': the authenticated user "
                        "receives a working admin page and the "
                        "username is reflected in the response body, "
                        "confirming this is the user's intended admin "
                        f"area (HTTP {auth['status']}, "
                        f"{auth['size']} bytes). Anonymous traffic is "
                        f"correctly denied (HTTP {anon['status']}). "
                        "Not an exposure. (Whether the user's role "
                        "should be able to reach this page at all is "
                        "a separate RBAC question outside this "
                        "probe's scope.)"),
                    evidence=evidence,
                )
            # Authenticated 200 but no reflection — we can't tell
            # whether it's a real admin area for this user or a
            # generic page that 200's for any logged-in session.
            # Leave it for human review.
            return Verdict(
                validated=None, confidence=0.55,
                summary=(
                    "Inconclusive: authenticated traffic receives "
                    f"HTTP {auth['status']} ({auth['size']} bytes) "
                    f"and anonymous receives HTTP {anon['status']}, "
                    "so the path *is* gated by app auth — but "
                    + ("the supplied username does not appear in "
                       "the body, so the probe cannot confirm the "
                       "page is rendering authenticated content for "
                       "*this* user (vs a generic logged-in landing "
                       "page that happens to live under an admin path)."
                       if username else
                       "no username was supplied to the probe, so "
                       "identity reflection could not be tested. "
                       "Re-run with a credentialed assessment to "
                       "tighten this verdict.")),
                evidence=evidence,
            )

        # Everything else — odd status pairs, 5xx, edge cases. Surface
        # the data and let the analyst decide.
        return Verdict(
            validated=None, confidence=0.4,
            summary=(
                f"Inconclusive: auth={auth['status']} "
                f"({auth['size']} B), anon={anon['status']} "
                f"({anon['size']} B). The response pair does not "
                "match any of the probe's decisive matrix entries "
                "(public-admin / gated-server / authenticated-user-area). "
                "Inspect the audit log and the raw evidence."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AdminExposureProbe().main()
