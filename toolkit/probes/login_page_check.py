#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""High-fidelity validation for "Admin login page/section found" / similar
login-page-discovery findings emitted by Nikto and friends.

These findings are INFO-severity observations: a tool spotted a login
page at some path. They are NOT vulnerability claims. The right
validation is "is there actually a login form at this URL?" — yes/no,
nothing fancier.

The previous routing sent these to the admin_exposure probe, which is
designed for "is this admin panel publicly reachable?" — a different
question entirely. admin_exposure correctly returned "inconclusive"
because both auth and anon traffic see the same 200 + login form, which
doesn't fit any of its decisive matrix entries.

This probe encodes the same heuristic an analyst applies by hand
(roughly the curl one-liner: `curl -is URL | grep -ie login -ie pass
-ie user`), but parses the HTML instead of grepping so multi-line
attributes and case quirks don't fool it.

Detection signals
-----------------
We count discrete signals from the response. Two or more is enough to
call the page a login form; zero refutes the original finding; one is
inconclusive (possibly a CTA link to /login on a marketing page).

  1. <input type="password">   — single strongest signal. Almost no
                                  legitimate non-auth page has one.
  2. user/email/login input    — <input> whose name or id contains
                                  "user", "email", "login", "account",
                                  or "username".
  3. login-shaped form action  — <form action="..."> where the action
                                  URL contains a login-ish path
                                  segment (login, signin, auth,
                                  authenticate, session).
  4. login keyword in title    — <title> contains "login", "log in",
                                  "sign in", "signin", or "authenticate".
  5. submit button text        — a <button> or <input type="submit">
                                  whose text/value reads "log in",
                                  "sign in", "submit", or "continue"
                                  IN COMBINATION with a password input
                                  (otherwise too noisy on its own).

Examples
--------
    python login_page_check.py --url 'https://example.com/login.php'
    python login_page_check.py --url 'https://example.com/admin/'
"""
from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

# Probes live in toolkit/probes/; the shared lib is one level up.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# ---------------------------------------------------------------------------
# Pre-compiled regexes. Each is intentionally lenient on whitespace and
# attribute order so we don't miss legitimate hits over HTML formatting
# trivia. We don't try to be a full HTML parser — that would pull in
# external deps and over-engineer the check.
# ---------------------------------------------------------------------------

# <input type="password" ...> — quotes optional, anywhere in the tag.
_PW_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?',
    re.IGNORECASE,
)

# <input> whose name or id attribute contains user/email/login keywords.
# Anchored on the attribute name so we don't match arbitrary value text.
_USER_INPUT_RE = re.compile(
    r'<input\b[^>]*\b(?:name|id)\s*=\s*'
    r'["\']?(?:user|email|login|account|username|user_name|userid)[^"\'\s>]*'
    r'["\']?',
    re.IGNORECASE,
)

# <form action="..."> with a login-shaped path. We accept any action URL
# (relative or absolute) where the path component contains one of the
# auth keywords.
_LOGIN_FORM_ACTION_RE = re.compile(
    r'<form\b[^>]*\baction\s*=\s*["\']'
    r'([^"\']*(?:login|signin|sign[-_]?on|sign[-_]?in|authenticate|'
    r'session)[^"\']*)["\']',
    re.IGNORECASE,
)

# <title>...login...</title> — picks up "Login", "Sign In", "Authenticate".
_LOGIN_TITLE_RE = re.compile(
    r'<title[^>]*>\s*([^<]*(?:login|log\s*in|sign\s*in|signin|'
    r'sign\s*on|authenticate)[^<]*)\s*</title>',
    re.IGNORECASE,
)

# Submit-button text. We capture the visible label so the analyst can
# see why this signal fired. Match both <button> and <input type=submit>.
_SUBMIT_BUTTON_RE = re.compile(
    r'(?:<button\b[^>]*>([^<]*(?:log\s*in|sign\s*in|signin|submit|'
    r'continue|enter)[^<]*)</button>'
    r'|<input\b[^>]*\btype\s*=\s*["\']?submit["\']?[^>]*\bvalue\s*=\s*'
    r'["\']([^"\']*(?:log\s*in|sign\s*in|signin|submit|continue|'
    r'enter)[^"\']*)["\'])',
    re.IGNORECASE,
)


def _extract_signals(body: bytes) -> dict:
    """Walk the HTML once and report which signals fired plus the
    matched substring for each (so the verdict's evidence shows the
    analyst exactly why the call was made)."""
    if not body:
        return {"signals": {}, "count": 0, "matches": {}}
    text = body.decode("utf-8", "replace")
    # Cap at 200 KB — login pages are tiny; anything bigger is either a
    # mis-routed dashboard or a SPA shell, neither of which we can
    # reliably classify with regex.
    text = text[:200_000]

    matches: dict[str, str] = {}

    if (m := _PW_INPUT_RE.search(text)):
        matches["password_input"] = m.group(0)[:200]

    if (m := _USER_INPUT_RE.search(text)):
        matches["user_input"] = m.group(0)[:200]

    if (m := _LOGIN_FORM_ACTION_RE.search(text)):
        matches["login_form_action"] = m.group(1)[:200]

    if (m := _LOGIN_TITLE_RE.search(text)):
        matches["login_title"] = m.group(1).strip()[:200]

    # Submit-button signal — only counted when password_input also fired
    # (otherwise too many marketing pages with "Continue" buttons hit it).
    if "password_input" in matches:
        if (m := _SUBMIT_BUTTON_RE.search(text)):
            matches["submit_button"] = (m.group(1) or m.group(2) or "").strip()[:200]

    signals = {k: True for k in matches}
    return {"signals": signals, "count": len(signals), "matches": matches}


class LoginPageCheckProbe(Probe):
    name = "login_page_check"
    summary = ("Validates a 'login page found' finding by fetching the "
               "URL once and counting login-form signals (password "
               "input, user input, form action, page title). Single "
               "request, sub-second, no testssl / browser needed.")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args. --url is provided by the base parser;
        # --cookie is honored if the caller set one (some apps gate even
        # the login page behind a session in odd configurations) but the
        # probe is designed to run anonymously.
        pass

    # ------------------------------------------------------------------
    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")

        # Single GET. Login-page detection works just as well anonymously
        # as authenticated, and most apps redirect a logged-in user away
        # from the login URL anyway — running anon is the right default.
        try:
            r = client.request("GET", args.url)
        except Exception as e:
            return Verdict(
                ok=False, validated=None,
                summary=f"Request failed: {type(e).__name__}: {e}",
                error=str(e),
                evidence={"url": args.url},
            )

        # Status check. 4xx/5xx don't have an HTML body to inspect, so
        # we can't validate the login-form claim. 3xx redirects we
        # follow at the HTTP layer (SafeClient does not auto-follow,
        # but capturing the redirect target is enough for the analyst).
        evidence = {
            "url": args.url,
            "status": r.status,
            "size": r.size,
            "content_type": r.headers.get("Content-Type")
                            or r.headers.get("content-type")
                            or "",
        }

        if r.status in (301, 302, 303, 307, 308):
            # Surface the Location header — a login page that 302s away
            # often means we're already authenticated, or the URL is
            # wrong. Either way, the analyst will want to see it.
            loc = (r.headers.get("Location")
                   or r.headers.get("location") or "")
            evidence["redirect_to"] = loc
            return Verdict(
                ok=True, validated=None, confidence=0.4,
                summary=(f"Inconclusive: GET {args.url} returned "
                         f"HTTP {r.status} → {loc!r}. The probe did "
                         "not follow the redirect, so we can't tell "
                         "what the final page contains. If the redirect "
                         "is to a login URL, mark this finding as "
                         "validated manually."),
                evidence=evidence,
            )

        if r.status >= 400:
            return Verdict(
                ok=True, validated=False, confidence=0.85,
                summary=(f"Refuted: GET {args.url} returned HTTP "
                         f"{r.status}. There is no login form to "
                         "find here — the original scanner finding "
                         "may have predated the page being removed."),
                evidence=evidence,
                remediation=("Mark the original finding as a false "
                             "positive — the URL no longer responds "
                             "with a renderable page."),
            )

        # 2xx — parse signals.
        sig = _extract_signals(r.body or b"")
        evidence.update({
            "signals_fired": list(sig["signals"].keys()),
            "signal_count": sig["count"],
            "matches": sig["matches"],
        })

        if sig["count"] >= 2:
            return Verdict(
                ok=True, validated=True, confidence=0.92,
                summary=(
                    f"Validated: {args.url} is a login page. "
                    f"{sig['count']} of 5 signals fired: "
                    f"{', '.join(sorted(sig['signals'].keys()))}. "
                    "The original scanner finding is correct — there "
                    "is a login form here. This is INFO-level "
                    "informational confirmation, not a vulnerability."),
                evidence=evidence,
                remediation=(
                    "Login pages are normal application surface. No "
                    "remediation needed unless the page lacks "
                    "standard hardening (CSRF token, rate-limiting on "
                    "POST, account-lockout, generic error messages "
                    "that don't enumerate users) — those are separate "
                    "findings to file on their own."),
            )

        if sig["count"] == 0:
            return Verdict(
                ok=True, validated=False, confidence=0.85,
                summary=(
                    f"Refuted: {args.url} returned HTTP {r.status} "
                    f"but the body has no login-form signals "
                    "(no password input, no user/email input, no "
                    "login-shaped form action, no login keyword in "
                    "the title). The page is not a login form."),
                evidence=evidence,
                remediation=(
                    "Mark the original finding as a false positive — "
                    "the URL is not actually a login page."),
            )

        # Exactly one signal — could go either way. Surface the single
        # match and let the analyst look.
        single = list(sig["signals"].keys())[0]
        return Verdict(
            ok=True, validated=None, confidence=0.55,
            summary=(
                f"Inconclusive: {args.url} returned HTTP {r.status} "
                f"with one login-shape signal ({single}) but no "
                "corroborating signals. This often means a marketing "
                "page that links to /login (login-shaped action with "
                "no password input), or an SPA shell that loads its "
                "form via JS. Inspect the body manually to decide."),
            evidence=evidence,
        )


if __name__ == "__main__":
    LoginPageCheckProbe().main()
