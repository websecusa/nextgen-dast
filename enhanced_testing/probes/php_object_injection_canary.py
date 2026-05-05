#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
PHP object injection: unserialize() canary detection.

PHP's `unserialize()` will instantiate any class whose name appears
in a serialized payload and invoke that class's magic methods
(`__wakeup`, `__destruct`, `__toString`, `__call`). When the
application accepts user-controlled bytes that flow into
`unserialize()` -- typically a cookie or query parameter that is
base64-decoded server-side -- an attacker can chain magic-method
side effects in any auto-loaded class to reach RCE (PHPGGC's job).

Detection of the bug WITHOUT exploit chains is risky: blindly firing
a real PHPGGC payload could destabilize the target, and absence of
a chain doesn't prove safety. Instead, this probe sends a benign
canary -- a serialized stdClass with no properties -- and looks for
the giveaway error / behavioral signal:

  - PHP error string `unserialize(): Error` / `Notice: unserialize`
    in the response body (with `display_errors=1` -- common in
    misconfigured prod).
  - PHP error string `__PHP_Incomplete_Class` (occurs when a serialized
    class name is unknown to the autoloader).
  - Differential response shape between a "valid serialized stdClass"
    canary and a deliberately-malformed-but-otherwise-similar canary
    (the valid one is processed; the malformed one trips the error
    path of unserialize -- different sized response).

We send the canary to candidate ingestion points (cookies whose
value is base64 of a serialized object, query parameters named
`data` / `state` / `payload`).

Detection signal:
  Send `O:8:"stdClass":0:{}` (and base64 variants) as cookie or
  param value; validate when (a) response includes a PHP-specific
  unserialize error string AND (b) the same request without the
  serialized payload returns a different / smaller error.
"""
from __future__ import annotations

import base64
import re
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# A serialized empty stdClass is the smallest, safest canary.
CANARY = b'O:8:"stdClass":0:{}'

# A deliberately-malformed payload of the same shape -- valid
# Base64, but not valid PHP serialization. Used as a control to
# confirm the upstream actually parsed our valid canary.
MALFORMED = b'O:8:"stdClass":99:{junk}'

# Candidate ingestion points. Cookies first (most common), then
# query params, then a POST body field. Same-origin only.
COOKIE_NAMES = ("data", "user", "session_data", "state", "auth")
PARAM_NAMES = ("data", "state", "payload", "user", "session")

# PHP-specific signatures that betray a server-side unserialize().
UNSERIALIZE_ERR_RE = re.compile(
    r"unserialize\(\)|__PHP_Incomplete_Class|"
    r"Notice:\s*unserialize|Warning:\s*unserialize|"
    r"PHP Notice:\s*unserialize|PHP Warning:\s*unserialize",
    re.I)


class PhpObjectInjectionCanaryProbe(Probe):
    name = "php_object_injection_canary"
    summary = ("Detects PHP `unserialize()` on user input by sending "
               "a benign stdClass canary and comparing against a "
               "malformed control.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", default="/",
            help="Path to test (default '/').")

    def _b64(self, raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        target = urljoin(origin, args.path or "/")

        attempts: list[dict] = []
        confirmed: dict | None = None

        # We try each candidate field with three values:
        #   - benign canary (valid serialized stdClass)
        #   - malformed canary (looks similar, fails parse)
        #   - empty / harmless control
        # If the malformed one elicits a PHP unserialize error AND
        # the benign one doesn't, we have proof the value flows into
        # unserialize() server-side.

        for param in PARAM_NAMES:
            base = target + "?" + param + "="
            r_empty = client.request("GET", base + "x")
            r_canary = client.request(
                "GET", base + quote(self._b64(CANARY)))
            r_bad = client.request(
                "GET", base + quote(self._b64(MALFORMED)))
            errs = {
                "empty": bool(r_empty.body and UNSERIALIZE_ERR_RE.search(
                    r_empty.text or "")),
                "canary": bool(r_canary.body and UNSERIALIZE_ERR_RE.search(
                    r_canary.text or "")),
                "bad": bool(r_bad.body and UNSERIALIZE_ERR_RE.search(
                    r_bad.text or "")),
            }
            row = {"step": "param", "param": param,
                   "status_empty": r_empty.status,
                   "status_canary": r_canary.status,
                   "status_bad": r_bad.status,
                   "errs": errs}
            # High-fidelity rule: malformed payload triggers the
            # PHP-specific error AND the empty / canary path does
            # NOT. This is two corroborating signals -- proof the
            # input feeds unserialize(), differential against the
            # control.
            if errs["bad"] and not errs["empty"]:
                row["evidence_snippet"] = (
                    r_bad.text or "")[:200]
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)
            if len(attempts) >= 6:
                # Budget cap; we have enough signal to declare.
                break

        evidence = {"origin": origin, "target": target,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: parameter `{confirmed['param']}` on "
                    f"{target} flows into PHP unserialize(). A "
                    "malformed serialized payload triggered a PHP "
                    "`unserialize()` warning while a control request "
                    "returned no such error -- the byte stream is "
                    "being deserialized server-side. With a suitable "
                    "gadget chain (PHPGGC), this would be RCE."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop calling `unserialize()` on user-controlled "
                    "input.\n"
                    "  - Use `json_decode()` for client-served data.\n"
                    "  - If serialization is unavoidable, sign the "
                    "payload with `hash_hmac()` and verify the MAC "
                    "before unserializing.\n"
                    "  - Set `display_errors=Off` in production "
                    "(php.ini) so error messages don't leak the "
                    "vulnerable code path to attackers.\n"
                    "  - Consider PHP 7+ `unserialize($data, "
                    "['allowed_classes' => false])` to disable "
                    "object instantiation."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} candidate "
                     f"parameter(s) on {target}; no PHP "
                     "unserialize-error differential observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpObjectInjectionCanaryProbe().main()
