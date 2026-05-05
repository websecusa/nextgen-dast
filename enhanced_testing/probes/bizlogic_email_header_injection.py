#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: email header injection via CRLF in form fields that
feed an outgoing email envelope.

When a contact-form / forgot-password / invite-friend / newsletter-
subscribe endpoint takes a user-supplied email address and uses it
as-is in an SMTP envelope (To:, From:, or in a templated header
list), an attacker who can inject a CRLF sequence into the field can
add their own SMTP headers — most commonly `Bcc:` to send copies of
every outgoing message to themselves, or `Subject:` / `Content-Type:`
to take over the email entirely.

The injection vector is the literal bytes `\\r\\n` (CRLF, percent-
encoded as `%0d%0a`) embedded inside the email-shaped value:
`attacker@dast.test\\r\\nBcc: marker@dast.test`.

Detection signal:
  Validated=True only when ALL of:
    1. The endpoint accepts the CRLF-bearing input (HTTP 200/201/204
       — server did not reject the malformed email), AND
    2. The same value is reflected verbatim somewhere in the response
       body / headers (echoed in a confirmation message, or in a
       Location header, or in a templated thank-you page) — proving
       the server stored / used the literal CRLF instead of stripping
       it.

We never validate from a 200 alone; reflection is the second
signal. Without reflection we have no evidence the field actually
made it to the email layer.

Note on safety: the marker email used (`bcc-marker@dast.test`) is
inside the same `dast.test` reserved domain as our other probe
addresses; even if the server actually delivered a Bcc to this
domain it would not leave the operator's network.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly accept a free-form email field. We try
# each in turn; first non-404 wins.
EMAIL_FORM_PATHS = (
    "/api/contact",
    "/api/feedback",
    "/api/users/forgot-password",
    "/api/auth/forgot-password",
    "/rest/user/reset-password",
    "/api/newsletter/subscribe",
    "/api/invite",
    "/api/users/invite",
)

# The injection payload. The marker is a deterministic-but-unique
# token so we can match it precisely in the response.
def _build_payload(marker: str) -> str:
    """Email field with a CRLF and an injected Bcc header. Form-
    encoded callers will URL-encode the CRLF as %0d%0a; JSON callers
    receive the raw \\r\\n bytes."""
    return f"probe-{marker}@dast.test\r\nBcc: bcc-marker-{marker}@dast.test"


def _looks_rejected(status: int, body: str) -> bool:
    """A reasonable email validator either rejects with 4xx OR
    returns 200 with an error-shaped body. We treat clear rejection
    as a refuted outcome rather than a confirmed one."""
    if status >= 400:
        return True
    lc = (body or "").lower()
    return any(token in lc for token in
               ("invalid email", "valid email", "email is not valid",
                "malformed", "invalid input", "validation failed"))


class BizLogicEmailHeaderInjectionProbe(Probe):
    name = "bizlogic_email_header_injection"
    summary = ("Detects email-header injection via CRLF in user-"
               "supplied email fields — attacker can inject Bcc / "
               "Subject / Content-Type into outgoing mail.")
    safety_class = "probe"

    def add_args(self, parser):
        # No probe-specific args; the marker is randomized per run so
        # multiple runs against the same target don't collide.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        marker = secrets.token_hex(4)
        payload = _build_payload(marker)
        # Anchored regex — we want to see our literal CRLF + Bcc in
        # the response, NOT just the email username on its own.
        # The CR and LF may be normalized; accept either raw or
        # percent-encoded forms.
        bcc_marker_re = re.compile(
            r"(?:\r\n|%0[dD]%0[aA]|\\r\\n)\s*Bcc:\s*bcc-marker-" + re.escape(marker),
            re.I,
        )

        attempts: list[dict] = []
        confirmed_attempt: dict | None = None

        for path in EMAIL_FORM_PATHS:
            url = urljoin(origin, path)
            # Standard contact-form shape covers most apps. We
            # include both `email` and a few other common names so
            # the binding layer takes the value regardless of
            # specific parameter naming.
            body = json.dumps({
                "email": payload,
                "address": payload,
                "to": payload,
                "subject": "DAST probe — please ignore",
                "message": f"DAST email-header-injection probe {marker}.",
            }).encode()
            r = client.request("POST", url, headers={
                "Content-Type": "application/json",
            }, body=body)
            if r.status == 404:
                continue

            text = r.text or ""
            location = ""
            for k, v in r.headers.items():
                if k.lower() == "location":
                    location = v
                    break

            reflected = bool(bcc_marker_re.search(text)) or \
                        bool(bcc_marker_re.search(location))
            rejected = _looks_rejected(r.status, text)

            entry = {"path": path, "status": r.status, "size": r.size,
                     "rejected": rejected, "reflected_crlf_bcc": reflected,
                     "location": location[:200],
                     "body_excerpt": text[:200]}
            attempts.append(entry)

            if not rejected and reflected and 200 <= r.status < 400:
                confirmed_attempt = entry
                break

        evidence = {"origin": origin, "marker": marker,
                    "attempts": attempts}

        if confirmed_attempt:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: email-header injection on "
                         f"{origin}{confirmed_attempt['path']}. CRLF + "
                         "Bcc: marker passed through unsanitized "
                         "(status "
                         f"{confirmed_attempt['status']}) and was "
                         "reflected verbatim in the response."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Validate / sanitize the email field before it "
                    "reaches the mail layer:\n"
                    "  - Reject any value containing \\r, \\n, or "
                    "their percent-encoded forms outright (return "
                    "400).\n"
                    "  - Use a strict regex (e.g. RFC5321 dot-atom) "
                    "rather than a permissive substring check.\n"
                    "  - At the SMTP / mail-library layer, pass "
                    "envelope addresses as a structured list, never "
                    "as a templated header string."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: no email-form endpoint on {origin} "
                     "passed CRLF + Bcc through unsanitized "
                     f"({len(attempts)} candidates probed)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicEmailHeaderInjectionProbe().main()
