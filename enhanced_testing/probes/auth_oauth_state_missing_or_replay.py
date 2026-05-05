#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: OAuth callback accepts missing or replayed `state`.

The OAuth `state` parameter is the only thing that ties an
authorization-code response back to the browser session that
initiated the flow. Without a per-flow random `state` (and a
server-side check that the value coming back matches the value
issued at /authorize-time), the callback endpoint accepts
attacker-pasted codes and binds them to whichever session is
currently making the request — i.e. classic OAuth CSRF.

We test two adjacent failure modes:

  1. Missing state: callback URL is reachable WITHOUT a state
     parameter (server returns 200 / 302 to a logged-in landing
     page or an error message that is NOT "state required").
  2. Replayed state: the same `state=` value is accepted twice in
     a row. Even with a state present, if the value isn't bound
     to a single use the CSRF protection collapses.

We never produce a real OAuth code — we use a placeholder. A
correctly-implemented server should reject our request because
the code is invalid; what we're looking for is the ERROR MESSAGE.
"State missing" / "state mismatch" = good. Anything that processes
our request without first validating state = flagged.

Detection signal:
  GET /<oauth-callback>?code=BOGUS produces a response that does
  NOT mention "state" and does not redirect the user to a
  state-validation error; AND a second request with the same
  state value (if any was needed to elicit a non-error response)
  is also accepted.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common callback path conventions. We only consider a path live if
# a baseline GET to it returns SOMETHING other than 404 — this keeps
# us from flagging static 200 / index-page noise.
# Two well-known shapes plus operator extensions. Keeping the
# default small leaves headroom under the 6-request cap when each
# path costs up to 3 requests (no-state, state, state-replay).
CALLBACK_PATHS = (
    "/oauth/callback",
    "/auth/callback",
)

# Strings the server should mention when state validation runs and
# fails. These are deliberately conservative — well-known framework
# error vocabulary.
_STATE_ERROR_VOCAB = re.compile(
    r"(?:state(?:[ _-])?(?:mismatch|missing|invalid|required)"
    r"|invalid[_ -]?state"
    r"|csrf"
    r"|forg(?:ed|ery)"
    r"|cross[- ]?site)",
    re.IGNORECASE,
)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _looks_like_callback(status: int, body: str) -> bool:
    """A path that exists as an OAuth callback typically:
       - 4xx with an error message (preferred — easy to grep)
       - 302 to login or to an error page
       - 200 with body containing "code", "state", "oauth", etc.
    """
    if status in (400, 401, 403, 422):
        return True
    if status in (301, 302, 303, 307, 308):
        return True
    if status == 200 and any(k in (body or "").lower()
                              for k in ("oauth", "code", "state",
                                        "callback", "redirect")):
        return True
    return False


class AuthOAuthStateMissingOrReplayProbe(Probe):
    name = "auth_oauth_state_missing_or_replay"
    summary = ("Detects OAuth callback endpoints that accept missing "
               "or replayed `state` values (OAuth CSRF).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--callback-path", action="append", default=[],
            help="Additional OAuth callback path to probe. "
                 "Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = list(CALLBACK_PATHS) + list(args.callback_path or [])

        attempts: list[dict] = []
        confirmed: list[dict] = []
        # Bogus code — any real server will reject it. The
        # difference we care about: HOW it rejects.
        bogus_code = "dast" + secrets.token_hex(16)

        for path in candidates:
            base = urljoin(origin, path)

            # Pass 1: callback with code only, NO state.
            url1 = base + f"?code={bogus_code}"
            r1 = client.request("GET", url1, follow_redirects=False)
            if not _looks_like_callback(r1.status, r1.text or ""):
                # Path doesn't look like an OAuth callback at all —
                # skip without flagging.
                attempts.append({"path": path,
                                 "status": r1.status,
                                 "looks_like_callback": False})
                continue

            location = _hdr(r1.headers or {}, "Location")
            body_excerpt = (r1.text or "")[:300]
            mentions_state = bool(_STATE_ERROR_VOCAB.search(
                body_excerpt + " " + (location or "")))

            row = {
                "path": path,
                "no_state": {
                    "status": r1.status,
                    "location": location[:200] if location else "",
                    "mentions_state_validation": mentions_state,
                    "body_excerpt": body_excerpt,
                },
            }

            # Signal A: server accepted the request without ever
            # mentioning state. A 200 or a redirect to a non-error
            # destination both count.
            #
            # Signal B (corroborating): a SECOND request with a
            # supplied-but-bogus state, replayed to itself, is
            # accepted with the same shape.
            state_val = "dast" + secrets.token_hex(8)
            url2 = base + f"?code={bogus_code}&state={state_val}"
            r2a = client.request("GET", url2, follow_redirects=False)
            r2b = client.request("GET", url2, follow_redirects=False)
            replay_same = (r2a.status == r2b.status
                           and r2a.size == r2b.size)
            row["replay_state"] = {
                "first_status": r2a.status, "second_status": r2b.status,
                "first_size": r2a.size, "second_size": r2b.size,
                "replay_identical": replay_same,
            }

            # Only flag when BOTH:
            #   1. no-state attempt did NOT mention state validation;
            #   2. replay returned identical responses (bogus code +
            #      same state accepted twice the same way).
            # These two together are much stronger than either alone:
            # a missing-state-mention could be a generic 500, an
            # identical-replay could be an idempotent 404 page. The
            # two together rule out both noise sources.
            if not mentions_state and replay_same \
                    and r1.status not in (404, 500, 502, 503):
                row["flagged"] = True
                confirmed.append(row)
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: OAuth callback {origin}{top['path']} "
                    "did not enforce a `state` parameter. Request "
                    "without state did not mention state validation "
                    f"(status {top['no_state']['status']}); replayed "
                    "state was accepted with identical response "
                    "shape on both attempts."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Bind every /authorize redirect to a fresh "
                    "cryptographically random `state` value stored "
                    "in the user's session. The callback handler "
                    "must (a) require the state parameter, (b) "
                    "compare it against the session-stored value "
                    "with a constant-time check, and (c) consume "
                    "the value (single-use). Reject requests with "
                    "missing, mismatched, or already-consumed state. "
                    "Combine with PKCE on public clients."),
            )
        return Verdict(
            validated=False, confidence=0.82,
            summary=(f"Refuted: probed {len(candidates)} OAuth callback "
                     f"shapes on {origin}; none accepted a missing-"
                     "state request without complaint."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthOAuthStateMissingOrReplayProbe().main()
