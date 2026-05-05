#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
JSONP endpoint reflects an attacker-controlled callback name.

A JSONP endpoint wraps its JSON response in a JS function call whose
name is taken from a `callback=` (or `jsonp=`) query parameter. If
the server doesn't validate the callback identifier and serves the
response with a JS-shaped Content-Type, an attacker can:

  - Embed `<script src="victim.com/api?callback=alert(1)//"></script>`
    on their own page and execute JS in the victim's origin context.
  - Append arbitrary JS to the wrapper to read the response from a
    third-party origin (a CSRF on data exfil).

The probe finds candidate JSONP endpoints by static-grep over the
linked JS bundles for URL strings containing `callback=` or
`jsonp=` parameters. For each candidate it issues two requests, one
with `?callback=round12alertcanary` and one with
`?jsonp=round12alertcanary` (the canary is benign, alphabetic, no
parens / no payload).

To stay high-fidelity we require BOTH:
  1. The response body STARTS with `round12alertcanary(` (anywhere
     in the first 2 KiB after stripping leading whitespace and
     /**/-style padding). This proves the callback name was used as
     a JS identifier rather than just echoed inside a JSON string.
  2. The response Content-Type contains `javascript`, `ecmascript`,
     `jsonp`, or `application/x-javascript` -- only then can the
     `<script src=...>` exfil shape actually execute in a browser.

The canary identifier is not a function -- it doesn't exist in any
real environment, so even if the server reflects it the call has no
side effect at scan time.

Detection signal:
  Response body begins with `round12alertcanary(` AND Content-Type is
  a JS-class media type, on any candidate endpoint.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Match URL-shaped strings inside JS bundles that already mention a
# `callback=` or `jsonp=` query parameter. We capture the path portion
# (and any leading existing query) so we can re-issue with our own
# callback value. Only relative-or-absolute, no protocol-relative.
JSONP_URL_RE = re.compile(
    r"""['"`]([/A-Za-z0-9_\-\.~%?&=]*?\?[^'"`]*?\b(?:callback|jsonp)=[^'"`]*)['"`]""",
    re.IGNORECASE)

# Canary identifier: alphabetic, no operator characters, will not
# resolve to anything that exists in either the scanner or the target.
CANARY = "round12alertcanary"

# Body padding patterns that JSONP libraries sometimes emit before the
# wrapper. Strip them before checking the prefix.
BODY_PREFIX_STRIP = re.compile(r"^\s*(?:/\*[^*]*\*/\s*)*")

JS_CONTENT_TYPES = (
    "javascript", "ecmascript", "jsonp", "application/x-javascript",
)

MAX_BUNDLES = 4
MAX_CANDIDATES = 4


def _content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return str(v).lower()
    return ""


def _starts_with_canary_call(body_text: str) -> bool:
    """True if, after stripping JSONP-style /**/ padding and leading
    whitespace, the body begins with `<CANARY>(`. We bound the slice
    to 2 KiB so a megabyte-sized response doesn't dominate the regex
    cost."""
    stripped = BODY_PREFIX_STRIP.sub("", body_text[:2048])
    return stripped.startswith(CANARY + "(")


def _swap_callback(url: str, key: str, value: str) -> str:
    """Return `url` with query parameter `key` set to `value`,
    preserving every other parameter. Used so a discovered URL keeps
    its other selector params intact."""
    parsed = urlparse(url)
    pairs = [(k, value if k.lower() == key.lower() else v)
             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    if not any(k.lower() == key.lower() for k, _ in pairs):
        pairs.append((key, value))
    return parsed._replace(query=urlencode(pairs)).geturl()


class ClientJsJsonpCallbackReflectedProbe(Probe):
    name = "clientjs_jsonp_callback_reflected"
    summary = ("Detects JSONP endpoints that wrap their response with "
               "an attacker-supplied callback identifier and a JS "
               "Content-Type.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--candidate", action="append", default=[],
            help="Additional candidate JSONP URL to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: find candidate JSONP endpoints from the index page +
        # its linked JS bundles. Same-origin only -- we deliberately
        # do NOT follow URLs that resolve to a different host.
        r = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if r.status == 200 and r.body:
            bundles.extend(SCRIPT_RE.findall(r.text or ""))
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b))
                   for b in bundles[:MAX_BUNDLES]]

        candidates: list[str] = []
        for b in bundles:
            rb = client.request("GET", b)
            if rb.status != 200 or not rb.body:
                continue
            for m in JSONP_URL_RE.finditer(rb.text or ""):
                cand = m.group(1)
                full = (cand if cand.startswith(("http://", "https://"))
                        else urljoin(origin, cand))
                # Same-origin guard.
                if urlparse(full).netloc != parsed.netloc:
                    continue
                if full not in candidates:
                    candidates.append(full)
                if len(candidates) >= MAX_CANDIDATES:
                    break
            if len(candidates) >= MAX_CANDIDATES:
                break
        # Caller-supplied candidates take precedence.
        for c in args.candidate or []:
            full = (c if c.startswith(("http://", "https://"))
                    else urljoin(origin, c))
            if urlparse(full).netloc != parsed.netloc:
                continue
            if full not in candidates:
                candidates.insert(0, full)

        attempts: list[dict] = []
        confirmed: dict | None = None
        for url in candidates[:MAX_CANDIDATES]:
            for key in ("callback", "jsonp"):
                probe_url = _swap_callback(url, key, CANARY)
                rp = client.request("GET", probe_url)
                ct = _content_type(rp.headers or {})
                body_text = rp.text or ""
                row = {
                    "candidate": probe_url, "param": key,
                    "status": rp.status, "content_type": ct,
                    "body_excerpt": body_text[:160],
                }
                # Two corroborating signals required.
                if rp.status == 200 \
                        and _starts_with_canary_call(body_text) \
                        and any(token in ct for token in JS_CONTENT_TYPES):
                    row["confirmed"] = True
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin,
                    "candidates_seen": candidates,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: JSONP endpoint at {confirmed['candidate']} "
                    "wraps its response with a caller-supplied callback "
                    f"identifier and serves it as {confirmed['content_type']} "
                    "-- usable as an XSS / data-exfil vector via "
                    "<script src=...>."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "On any endpoint that returns JSONP:\n"
                    "  - Validate the callback identifier with a strict "
                    "regex like `^[A-Za-z_$][\\w$]{0,63}$` and reject "
                    "anything else with HTTP 400.\n"
                    "  - Better, drop JSONP entirely. Modern browsers "
                    "support CORS for cross-origin JSON, which is "
                    "structurally safer (the response is parsed as "
                    "data, not executed as code).\n"
                    "  - If JSONP must stay, pin the response "
                    "Content-Type to `application/javascript` only "
                    "after the identifier check passes, and add "
                    "`X-Content-Type-Options: nosniff`."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(candidates)} JSONP "
                     f"candidate(s) on {origin}; none returned a "
                     f"`{CANARY}(` prefix with a JS Content-Type."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsJsonpCallbackReflectedProbe().main()
