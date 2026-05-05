#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Client-side DOM XSS sink usage in production JS bundles.

Single-page apps frequently sink user-controlled values into
DOM-write operations (`element.innerHTML = ...`, `document.write(...)`,
`eval(...)`, `new Function(...)`, `setTimeout(<string>, ...)`,
`location.href = ...`). Each of those, when fed an untrusted string,
becomes a DOM-XSS or open-redirect vector that the server's CSP cannot
necessarily block.

The probe is a static analyzer over the JS bundles linked from the
target's index page. To stay high-fidelity we apply two filters that
together kill the common false-positive patterns:

  1. The right-hand-side of an assignment (or the first argument of a
     dynamic-execution call) MUST be a non-string-literal expression --
     i.e. an identifier or member access. `el.innerHTML = "<b>hi</b>"`
     is a static template and is NOT flagged; `el.innerHTML = userText`
     IS flagged.
  2. We require at least 2 distinct sink classes to fire across the
     surveyed bundles before raising validated=True. A single hit on
     one bundle is reported as refuted with the candidate noted, since
     bundle-internal helpers (DOMPurify, framework runtimes) routinely
     contain one such sink that is internally guarded.

Detection signal:
  >=2 distinct sink categories, each on a non-literal RHS, observed
  across the linked bundles of the origin's index page.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Reused from angular_secrets_in_bundle.py: pull <script src="..."> refs
# from the index page. We deliberately keep this loose so minified or
# pre-formatted HTML still matches.
SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Each sink pattern requires the RHS / first-arg to start with an
# identifier-shaped character (letter, underscore, $) -- i.e. NOT a
# quote and NOT a digit. That is the cheap-but-effective way to skip
# string literals like `el.innerHTML = "<b>hi</b>"` while still
# matching `el.innerHTML = unsafeVar` or `el.innerHTML = data.body`.
_IDENT_LEAD = r"[a-zA-Z_$]"

SINK_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(rf"\.innerHTML\s*=\s*{_IDENT_LEAD}"),
     "innerHTML = <expr>"),
    (re.compile(rf"\.outerHTML\s*=\s*{_IDENT_LEAD}"),
     "outerHTML = <expr>"),
    (re.compile(rf"document\.write\(\s*{_IDENT_LEAD}"),
     "document.write(<expr>)"),
    (re.compile(rf"document\.writeln\(\s*{_IDENT_LEAD}"),
     "document.writeln(<expr>)"),
    (re.compile(rf"\beval\(\s*{_IDENT_LEAD}"),
     "eval(<expr>)"),
    (re.compile(rf"\bnew\s+Function\(\s*{_IDENT_LEAD}"),
     "new Function(<expr>)"),
    # setTimeout / setInterval take a string-as-code as their first arg
    # ONLY when the value is a string. We flag the call when the first
    # arg is an identifier (could be a string variable) AND the second
    # arg is a number-shaped delay -- the classic deferred-eval shape.
    (re.compile(rf"\bsetTimeout\(\s*{_IDENT_LEAD}[^,)]*,\s*\d"),
     "setTimeout(<expr>, <delay>)"),
    (re.compile(rf"\bsetInterval\(\s*{_IDENT_LEAD}[^,)]*,\s*\d"),
     "setInterval(<expr>, <delay>)"),
    (re.compile(rf"location\.href\s*=\s*{_IDENT_LEAD}"),
     "location.href = <expr>"),
    (re.compile(rf"location\.replace\(\s*{_IDENT_LEAD}"),
     "location.replace(<expr>)"),
)

MAX_BUNDLES = 8


def _excerpt(text: str, idx: int, span: int = 60) -> str:
    """Return a short, single-line excerpt around offset `idx` so the
    evidence shows context without dumping the full bundle."""
    start = max(0, idx - span)
    end = min(len(text), idx + span)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    return snippet.strip()[:160]


class ClientJsDomXssSinksProbe(Probe):
    name = "clientjs_dom_xss_sinks"
    summary = ("Detects DOM-write / dynamic-eval sinks fed by non-literal "
               "expressions across the linked JS bundles.")
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

        # Step 1: discover bundles. Same approach as
        # angular_secrets_in_bundle.py -- index page + caller overrides.
        r = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if r.status == 200 and r.body:
            bundles.extend(SCRIPT_RE.findall(r.text or ""))
        bundles += list(args.bundle or [])
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles[:MAX_BUNDLES]]

        attempts: list[dict] = []
        # Sink-class -> list of {bundle, excerpt}
        sink_hits: dict[str, list[dict]] = {}
        for url in bundles:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status != 200 or not rb.body:
                attempts.append(row)
                continue
            text = rb.text or ""
            local: list[dict] = []
            for pat, label in SINK_PATTERNS:
                m = pat.search(text)
                if not m:
                    continue
                excerpt = _excerpt(text, m.start())
                local.append({"sink": label, "excerpt": excerpt})
                sink_hits.setdefault(label, []).append({
                    "bundle": url, "excerpt": excerpt,
                })
            row["sinks"] = local
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts,
                    "bundles_scanned": len(bundles)}
        # High-fidelity rule: 2+ distinct sink categories required.
        # A bundle with only one match is far too commonly a benign
        # framework helper guarded internally.
        if len(sink_hits) >= 2:
            sample = []
            for label, hits in list(sink_hits.items())[:4]:
                sample.append({"sink": label,
                               "first_bundle": hits[0]["bundle"],
                               "excerpt": hits[0]["excerpt"]})
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: {len(sink_hits)} distinct DOM-XSS sink "
                    f"categories observed across {len(bundles)} bundle(s) "
                    f"on {origin}, each fed a non-literal expression. "
                    f"Sinks present: {', '.join(sink_hits.keys())}."),
                evidence={**evidence, "sink_hits": sink_hits,
                          "sample": sample},
                severity_uplift="medium",
                remediation=(
                    "Replace each flagged sink with a safe equivalent:\n"
                    "  - `el.innerHTML = userText`  ->  "
                    "`el.textContent = userText` (text only) OR run the "
                    "value through DOMPurify.sanitize before assigning.\n"
                    "  - `document.write(x)` is essentially never safe in "
                    "modern code -- delete the call and emit DOM nodes "
                    "via createElement / textContent instead.\n"
                    "  - `eval(x)` and `new Function(x)` should be "
                    "removed entirely; if you genuinely need late-bound "
                    "code, ship a real plugin loader with an allowlist.\n"
                    "  - `setTimeout(stringExpr, ms)` -- pass a function "
                    "reference, never a string.\n"
                    "  - `location.href = userVal` -- validate the value "
                    "against an allowlist of internal paths or hosts "
                    "before assigning.\n"
                    "Then layer Trusted Types "
                    "(`Content-Security-Policy: require-trusted-types-for "
                    "'script'`) so future regressions throw at runtime."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: scanned {len(bundles)} bundle(s) on "
                     f"{origin}; saw {len(sink_hits)} sink category(ies) "
                     "with non-literal RHS -- not enough to confirm a "
                     "DOM-XSS pattern by static analysis."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsDomXssSinksProbe().main()
