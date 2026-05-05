#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
postMessage handler with no event.origin check.

A `window.addEventListener('message', handler)` (or
`window.onmessage = handler`) registers a callback that fires for ANY
cross-origin frame that owns a reference to this window. If the
handler does not strictly compare `event.origin` against an allowlist,
any embedding page (or popup the app opened) can deliver arbitrary
data into the handler -- often a JSON-RPC-shaped payload that the
handler then routes to internal APIs.

The probe is a static analyzer over the JS bundles linked from the
target's index page. For each `addEventListener('message', ...)` /
`window.onmessage = ...` registration we look at the next ~30 lines
(approximately the handler body for minified / un-minified code
alike) for a strict-equality origin check (`origin === ...`,
`origin == ...`, or `origin !== ...` etc.). Absence of such a check
in the surveyed window is the trigger.

To stay high-fidelity:
  - We require a registration site to actually exist before checking.
  - We require ZERO origin checks within the handler window. A single
    strict-equality `origin ===` anywhere in that window is enough to
    refute the finding for that handler.
  - We require >= 1 unguarded handler across the surveyed bundles to
    raise validated=True. (Just one is sufficient -- one unguarded
    listener is the bug class.)

Detection signal:
  At least one `addEventListener('message',` / `window.onmessage =`
  call with no `origin ===` / `origin ==` strict equality within the
  next 30 lines AND no `origin !==` either.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Two registration shapes. Both with `re.MULTILINE` so we can take a
# line index to slice forward from.
LISTENER_RE = re.compile(
    r"""addEventListener\(\s*['"]message['"]""",
    re.IGNORECASE)
ONMESSAGE_RE = re.compile(
    r"""(?:^|[^.])onmessage\s*=\s*[a-zA-Z_$(]""")

# A strict-equality origin check. We accept identifier-or-attribute
# prefix (`event.origin`, `e.origin`, `msg.origin`, plain `origin`)
# followed by `===`, `!==`, `==`, or `!=`.
ORIGIN_CHECK_RE = re.compile(
    r"""(?:[a-zA-Z_$][\w$]*\.)?origin\s*[!=]={1,2}\s*['"a-zA-Z_$]""")

# Bundle scan cap and forward-window size (in lines).
MAX_BUNDLES = 8
WINDOW_LINES = 30


def _scan_bundle(text: str) -> list[dict]:
    """Find each handler registration and return rows describing
    whether the next-30-lines window contains an origin check."""
    if not text:
        return []
    lines = text.split("\n")
    rows: list[dict] = []
    for i, line in enumerate(lines):
        for pat, label in ((LISTENER_RE, "addEventListener('message',...)"),
                           (ONMESSAGE_RE, "onmessage = ...")):
            if not pat.search(line):
                continue
            window = "\n".join(lines[i:i + WINDOW_LINES])
            has_check = bool(ORIGIN_CHECK_RE.search(window))
            rows.append({
                "kind": label,
                "line": i + 1,
                "has_origin_check": has_check,
                "excerpt": line.strip()[:160],
            })
    return rows


class ClientJsPostMessageNoOriginCheckProbe(Probe):
    name = "clientjs_postmessage_no_origin_check"
    summary = ("Detects window.message handlers registered without a "
               "strict event.origin equality check in the same scope.")
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
        unguarded: list[dict] = []
        guarded_count = 0
        for url in bundles:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status != 200 or not rb.body:
                attempts.append(row)
                continue
            handlers = _scan_bundle(rb.text or "")
            row["handlers"] = handlers
            attempts.append(row)
            for h in handlers:
                if h["has_origin_check"]:
                    guarded_count += 1
                else:
                    unguarded.append({**h, "bundle": url})

        evidence = {"origin": origin, "attempts": attempts,
                    "guarded": guarded_count,
                    "unguarded_count": len(unguarded)}

        if unguarded:
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: {len(unguarded)} window.message "
                    f"handler(s) on {origin} register without a strict "
                    "event.origin equality check within 30 lines. Any "
                    "embedding origin can deliver arbitrary message "
                    "payloads to the handler."),
                evidence={**evidence,
                          "unguarded": unguarded[:5]},
                severity_uplift="medium",
                remediation=(
                    "Inside every `message` listener, validate the "
                    "sender BEFORE doing any work:\n"
                    "  window.addEventListener('message', (e) => {\n"
                    "    if (e.origin !== 'https://your.expected.origin') "
                    "return;\n"
                    "    // safe to use e.data here\n"
                    "  });\n"
                    "Use strict equality (===), match against an "
                    "allowlist of origins, and for very sensitive flows "
                    "also verify `e.source === expectedWindow`. Do NOT "
                    "rely on `e.origin.includes(...)` or substring "
                    "matches -- attacker-controlled subdomains or "
                    "user-info components defeat them."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: scanned {len(bundles)} bundle(s) on "
                     f"{origin}; every observed message handler "
                     f"({guarded_count}) has a strict origin check, "
                     "or no handler is registered at all."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsPostMessageNoOriginCheckProbe().main()
