#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Reflected-XSS confirmation.

Sends a unique nonce as the target parameter and confirms:
  1. The nonce appears verbatim in the response (reflection)
  2. It appears in a context where HTML/JS could execute (not encoded)

If the nonce is reflected but HTML-encoded (`&lt;` etc.), the input is
sanitised — false positive. If it's reflected raw inside `<script>`, an
event handler, or a tag attribute, the issue is real.

Examples (CLI):
    python xss_reflect.py --url 'https://x.com/search?q=foo' --param q
    python xss_reflect.py --url 'https://x.com/p?id=1' --param name \\
        --cookie 'session=abc'
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


def _set_param(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = list(parse_qsl(u.query, keep_blank_values=True))
    found = False
    for i, (k, v) in enumerate(q):
        if k == param:
            q[i] = (k, value)
            found = True
            break
    if not found:
        q.append((param, value))
    return urlunparse(u._replace(query=urlencode(q, doseq=True)))


# Nonce wrapper. The angle brackets / quote let us see whether the app
# encodes them. The 8-hex middle is the unique marker.
def _make_payload(nonce: str) -> str:
    return f"<{nonce}\"'>x"


def _classify_reflection(body_text: str, nonce: str) -> tuple[bool, str]:
    """Returns (executable, context_description)."""
    if nonce not in body_text:
        return False, "no reflection"
    # Look at the context of the FIRST occurrence
    idx = body_text.find(nonce)
    window = body_text[max(0, idx - 80): idx + 80]

    # If we see the angle bracket from our wrapper raw, HTML is unescaped
    has_raw_lt = f"<{nonce}" in body_text
    has_raw_quote = f"\"{nonce}" in body_text or f"'{nonce}" in body_text
    encoded = ("&lt;" + nonce) in body_text or ("&#60;" + nonce) in body_text

    if has_raw_lt:
        return True, f"reflected without HTML-encoding; context: {window!r}"
    if has_raw_quote and re.search(r"<[^>]*=$", body_text[:idx]):
        return True, f"reflected inside attribute, quote breaks out; context: {window!r}"
    if encoded:
        return False, "reflected but HTML-entity-encoded"
    return False, f"reflected but inside safe context; window: {window!r}"


class XssReflectProbe(Probe):
    name = "xss_reflect"
    summary = "Reflected XSS confirmation via unique-nonce injection + context analysis."
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument("--length", type=int, default=8,
                            help="Nonce length in hex chars (default 8)")

    def run(self, args, client: SafeClient) -> Verdict:
        param = args.param
        if not param:
            return Verdict(ok=False, validated=None,
                           summary="--param is required for xss_reflect")

        nonce = "x" + secrets.token_hex(args.length)
        payload = _make_payload(nonce)
        url = _set_param(args.url, param, payload)
        r = client.request(args.method, url)

        if r.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable")

        executable, context = _classify_reflection(r.text, nonce)

        if executable:
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Reflected XSS confirmed in `{param}` — payload "
                         f"`{payload}` reached the response without "
                         f"HTML-encoding."),
                evidence={
                    "nonce": nonce, "payload_sent": payload,
                    "response_status": r.status, "response_size": r.size,
                    "context": context,
                },
                remediation=(
                    "Encode user input on output (HTML-entity encoding "
                    "for HTML context, JSON encoding for script context, "
                    "URL encoding inside href/src). Set a strict "
                    "Content-Security-Policy that disallows inline "
                    "scripts."),
                severity_uplift="high",
            )

        if nonce in r.text:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Parameter `{param}` reflects input but it's "
                         "encoded — XSS not exploitable."),
                evidence={"nonce": nonce, "payload_sent": payload,
                          "context": context},
            )

        return Verdict(
            validated=False, confidence=0.8,
            summary=(f"Parameter `{param}` does not reflect input. "
                     "False positive."),
            evidence={"nonce": nonce, "payload_sent": payload,
                      "response_size": r.size},
        )


if __name__ == "__main__":
    XssReflectProbe().main()
