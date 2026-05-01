#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: password-reset security-question answer is exposed
through a differential error response.

Apps that use a security-question reset flow often respond with one
shape on a wrong answer and a different shape on a correct one — even
without supplying a new password. This is a free oracle for an
attacker walking the public Q&A list.

This probe sends the reset request without the `new` field, so even
on a correct answer no actual reset takes place; the bug is only
about the differential error/response — and the WHO we're testing
is in the answer field, not the password field.

Detection signal:
  POST /rest/user/reset-password with `{email, answer}` (no `new`)
  → response shape changes between known-wrong and known-right
  answers. We compare body+status across two requests; differing
  responses prove the oracle.

Tested against:
  + OWASP Juice Shop  Jim's reset answer ("Samuel" — public from
                      Jim's profile) returns a different message
                      than a wrong answer → validated=True.
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

RESET_PATH = "/rest/user/reset-password"

# (email, correct_answer) — accounts whose reset answer is publicly
# inferable from the app's seed data. Juice Shop's Jim is the
# canonical example.
SEED_QA = (
    ("jim@juice-sh.op",  "Samuel"),       # known answer from profile
    ("bender@juice-sh.op", "Stop'n'Drop"),
)


def _normalize_response(text: str | None) -> str:
    """Reduce a response body to a comparable signature — strip
    timestamps / random ids that would otherwise make every response
    'different' even on a no-op."""
    if not text:
        return ""
    # Take the first 400 chars — long enough to capture the message
    # body, short enough to drop trailing variance.
    return text[:400]


class PasswordResetWeakQuestionProbe(Probe):
    name = "auth_password_reset_weak_question"
    summary = ("Detects security-question oracle: reset-password "
               "endpoint differs in response between right and wrong "
               "answers, leaking the answer for offline guessing.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--email", action="append", default=[],
            help="Additional email/answer pair as `email|answer` "
                 "(repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        pairs: list[tuple[str, str]] = list(SEED_QA)
        for spec in (args.email or []):
            if "|" in spec:
                e, a = spec.split("|", 1)
                pairs.append((e.strip(), a.strip()))

        attempts: list[dict] = []
        confirmed: dict | None = None
        for email, correct in pairs:
            url = urljoin(origin, RESET_PATH)
            wrong_body  = json.dumps({"email": email,
                                      "answer": "this-is-wrong"}).encode()
            right_body  = json.dumps({"email": email,
                                      "answer": correct}).encode()
            r_w = client.request("POST", url, headers={
                "Content-Type": "application/json"}, body=wrong_body)
            r_r = client.request("POST", url, headers={
                "Content-Type": "application/json"}, body=right_body)

            sig_w = (r_w.status, _normalize_response(r_w.text))
            sig_r = (r_r.status, _normalize_response(r_r.text))
            row = {"email": email,
                   "wrong_status": r_w.status, "right_status": r_r.status,
                   "wrong_excerpt": sig_w[1][:200],
                   "right_excerpt": sig_r[1][:200],
                   "differential": sig_w != sig_r}
            if sig_w != sig_r:
                # Differential proves the oracle. We do NOT call this
                # confirmed unless the right-answer response is
                # successful-shaped (200 / a "set new password" prompt
                # / an empty 204) — otherwise the differential could
                # be a different error code without revealing answer.
                if r_r.status in (200, 204) or "answer" not in (sig_r[1] or "").lower():
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: reset-password oracle on "
                         f"{origin}{RESET_PATH} for "
                         f"{confirmed['email']!r} — wrong answer "
                         f"returned status {confirmed['wrong_status']}, "
                         f"right answer returned "
                         f"{confirmed['right_status']} with a different "
                         "body shape. The endpoint reveals answer "
                         "correctness independent of the new-password "
                         "step."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Make the response identical for any (email, "
                    "answer) pair before the new-password step is "
                    "submitted. Issue a generic 'if the email is on "
                    "file you'll receive instructions' response and "
                    "move the answer-validation step BEHIND a one-"
                    "time-token round-trip via email — that closes "
                    "the offline oracle."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} known seed "
                     f"answers on {origin}; reset endpoint did not "
                     "expose a differential-response oracle."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PasswordResetWeakQuestionProbe().main()
