#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Sensitive material persisted in localStorage / sessionStorage.

`localStorage` and `sessionStorage` are reachable from any script
that executes in the page's origin -- including third-party scripts
the app loads, browser extensions, and any JS injected via XSS.
Storing tokens / credentials / PII there means a single XSS becomes
session theft AND credential theft. The right place for tokens is an
HttpOnly Secure SameSite=Strict cookie that the browser hands back
with every request and that JS can never read.

The probe is a static analyzer over the JS bundles linked from the
target's index page. We grep for `localStorage.setItem('K', V)` and
`sessionStorage.setItem('K', V)` calls where the literal key K
matches a sensitivity pattern (token / jwt / password / api[_-]?key /
secret / credit / ssn / auth / session). To stay high-fidelity we
require the value V to be a non-string-literal (an identifier or
member access). Storing the literal string `"undefined"` or
`"placeholder"` under a `token` key is not a leak; storing whatever
`apiResponse.token` contains IS a leak.

Detection signal:
  >=1 setItem call where the key matches a sensitivity pattern AND
  the value is a non-literal expression.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Match `localStorage.setItem('key', value-leading-char)` or its
# sessionStorage twin. Group 1 is the storage type, group 2 the key,
# group 3 the first character of the value expression -- which we use
# downstream to decide if it's a string literal or a code expression.
SETITEM_RE = re.compile(
    r"""(localStorage|sessionStorage)\s*\.\s*setItem\(\s*['"]([^'"]+)['"]\s*,\s*(.)""",
    re.IGNORECASE)

# Sensitivity keywords. Anchored to whole-word-ish boundaries so a
# legitimate key like `tokenizerVersion` doesn't match.
SENSITIVE_KEY_RE = re.compile(
    r"""(?ix)(?:^|[._\-/])
        (token|jwt|bearer|password|passwd|secret|apikey|api[_\-]?key|
         credential|credit|cardno|cardnumber|cvv|ssn|sin|auth|sessionid)
        (?:$|[._\-/])""")

MAX_BUNDLES = 8


class ClientJsLocalStorageSensitiveProbe(Probe):
    name = "clientjs_localstorage_sensitive"
    summary = ("Detects localStorage / sessionStorage setItem calls "
               "writing token-shaped keys with non-literal values.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--bundle", action="append", default=[],
            help="Additional bundle URL/path to scan (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        r = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if r.status == 200 and r.body:
            bundles.extend(SCRIPT_RE.findall(r.text or ""))
        bundles += list(args.bundle or [])
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles[:MAX_BUNDLES]]

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for url in bundles:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status != 200 or not rb.body:
                attempts.append(row)
                continue
            text = rb.text or ""
            local: list[dict] = []
            for m in SETITEM_RE.finditer(text):
                storage, key, lead = m.group(1), m.group(2), m.group(3)
                if not SENSITIVE_KEY_RE.search(key):
                    continue
                # Non-literal RHS check: a string literal starts with
                # `'`, `"`, or `` ` ``. Anything else (identifier, `(`,
                # `JSON.stringify(...)`, etc.) is a code expression and
                # therefore likely carries runtime secret data.
                if lead in ("'", '"', "`"):
                    continue
                local.append({
                    "storage": storage, "key": key,
                    "value_lead": lead,
                })
            if local:
                row["hits"] = local
                confirmed.append({"bundle": url, "hits": local})
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts,
                    "bundles_scanned": len(bundles)}
        if confirmed:
            sample = confirmed[0]["hits"][0]
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: {sum(len(c['hits']) for c in confirmed)} "
                    f"sensitive client-storage write(s) across "
                    f"{len(confirmed)} bundle(s) on {origin}. Example: "
                    f"{sample['storage']}.setItem('{sample['key']}', "
                    f"<expr>)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Move tokens out of Web Storage. The right home "
                    "for an authentication token is an HttpOnly Secure "
                    "SameSite=Strict cookie -- the browser attaches it "
                    "automatically and JS in the page (including any "
                    "XSS-injected script or third-party widget) cannot "
                    "read it. For PII (credit-card, SSN), don't keep "
                    "it client-side at all -- fetch it on demand from "
                    "an authenticated API and bind the response to the "
                    "DOM directly without persisting. If you really "
                    "need offline access to non-sensitive metadata, "
                    "keep using localStorage for THAT, with a strict "
                    "key allowlist enforced by a wrapper."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: scanned {len(bundles)} bundle(s) on "
                     f"{origin}; saw no setItem call writing a "
                     "sensitivity-keyword key with a non-literal value."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsLocalStorageSensitiveProbe().main()
