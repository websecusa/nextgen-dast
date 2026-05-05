#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Service Worker imports remote scripts over HTTP (mixed-content / SW
hijacking risk).

A registered Service Worker sits between the browser and the network
for every page in its scope. If the SW pulls in any external script
via `importScripts(...)` over plain HTTP, three failure modes open up:

  1. Mixed-content: most modern browsers will refuse to register the
     SW if the SW itself or its imports are HTTP, but if the host is
     also HTTP, the SW becomes a long-lived MITM target.
  2. Compromise of the imported script (CDN takeover, hostname
     hijacking, expired DNS) gives the attacker persistent in-origin
     code execution -- the SW survives page reloads, can intercept
     fetches, and can serve cached attacker content even after the
     legit script is restored.
  3. Even on HTTPS hosts, importing from a third-party HTTPS URL is a
     supply-chain liability worth flagging via a sibling check; this
     probe is the strict subset: HTTP-only.

This probe also flags an HTTP-imported sub-resource even if the SW
file itself is HTTPS-served -- mixed importScripts is a documented
spec violation that some older browsers historically allowed.

To stay high-fidelity:
  - We require the SW file to actually be served (HTTP 200, JS-class
    content type OR JS-shaped body).
  - We require at least one literal `importScripts(...)` call whose
    URL begins with `http://` (NOT `https://`, NOT a relative path,
    NOT a same-origin path).

Detection signal:
  /sw.js (or /service-worker.js, /serviceworker.js) returns 200 JS
  body that contains a literal `importScripts("http://...")` call.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common locations a Service Worker is published at. We probe each
# until one returns a 200 JS body, then stop.
SW_PATHS = ("/sw.js", "/service-worker.js", "/serviceworker.js",
            "/firebase-messaging-sw.js", "/workbox-sw.js")

# Match an importScripts call's first URL argument. Only literal
# strings -- a dynamic argument is unanalyzable here and we don't
# guess.
IMPORT_RE = re.compile(
    r"""importScripts\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE)

JS_CONTENT_TYPES = ("javascript", "ecmascript", "application/x-javascript")


def _content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_like_js(body_text: str, ct: str) -> bool:
    """JS-class content type, OR body opens with code-shaped tokens.
    The fallback rejects HTML soft-200 not-found pages that some
    edge servers emit."""
    if any(t in ct for t in JS_CONTENT_TYPES):
        return True
    head = body_text.lstrip()[:160]
    if not head:
        return False
    return (head.startswith(("self.", "//", "/*", "import ",
                             "importScripts", "const ", "let ",
                             "var ", "function", "(()", "!function"))
            or "self.addEventListener" in head)


class ClientJsServiceWorkerScopeProbe(Probe):
    name = "clientjs_service_worker_scope"
    summary = ("Detects a Service Worker that pulls remote scripts via "
               "importScripts over HTTP.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--sw-path", action="append", default=[],
            help="Additional SW path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(args.sw_path or []) + list(SW_PATHS)

        attempts: list[dict] = []
        sw_body: str | None = None
        sw_url: str | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url, follow_redirects=False)
            ct = _content_type(r.headers or {})
            body = r.text or ""
            row = {"url": url, "status": r.status,
                   "content_type": ct, "size": r.size}
            if r.status == 200 and body and _looks_like_js(body, ct):
                row["served"] = True
                attempts.append(row)
                sw_body = body
                sw_url = url
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if not sw_body:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no Service Worker found at any of "
                         f"{len(paths)} candidate paths on {origin}."),
                evidence=evidence,
            )

        # Walk the SW body for importScripts calls whose URL is HTTP.
        http_imports: list[str] = []
        all_imports: list[str] = []
        for m in IMPORT_RE.finditer(sw_body):
            target = m.group(1)
            all_imports.append(target)
            if target.lower().startswith("http://"):
                http_imports.append(target)

        evidence["sw_url"] = sw_url
        evidence["imports_seen"] = all_imports

        if http_imports:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: Service Worker at {sw_url} loads "
                    f"{len(http_imports)} script(s) over plain HTTP via "
                    "importScripts. Compromise of any of those URLs "
                    "yields persistent in-origin code execution."),
                evidence={**evidence, "http_imports": http_imports},
                severity_uplift="high",
                remediation=(
                    "Replace every `importScripts('http://...')` call "
                    "with an HTTPS equivalent, and ideally with a "
                    "Subresource-Integrity-style pinning hash (the SW "
                    "spec doesn't natively support SRI for "
                    "importScripts, but you can fetch the script "
                    "yourself, verify the SHA-256 against an embedded "
                    "constant, then `eval` -- or, better, vendor the "
                    "dependency into your own static assets and serve "
                    "it same-origin). Set `Content-Security-Policy: "
                    "worker-src 'self'` to forbid SW registration "
                    "from any script source other than your own "
                    "origin."),
            )
        return Verdict(
            validated=False, confidence=0.88,
            summary=(f"Refuted: Service Worker at {sw_url} contains "
                     f"{len(all_imports)} importScripts call(s); none "
                     "load over plain HTTP."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsServiceWorkerScopeProbe().main()
