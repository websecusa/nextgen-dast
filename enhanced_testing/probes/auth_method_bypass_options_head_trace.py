#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: protected endpoints accept OPTIONS / HEAD / TRACE
without authentication.

Auth filters frequently match on a hard-coded set of methods (GET,
POST, PUT, DELETE) and silently let anything outside that set
through. The classic shape: a Spring Security `antMatchers` rule
that only covers GET, an Express middleware that checks
`req.method === 'GET'`, an IIS URL Rewrite rule that omits the
method from its allow-list. The result is that OPTIONS or HEAD on
the same URL skips the auth filter and either returns the response
body (HEAD that leaks payload bytes) or echoes back metadata that
helps map the protected surface (TRACE that reflects the
Authorization header off a downstream proxy, OPTIONS that lists
allowed methods including admin-only verbs).

We only flag when:
  1. GET on the URL with no auth returns 401/403/302-to-login (the
     endpoint really IS protected for GET); AND
  2. OPTIONS / HEAD / TRACE on the SAME URL returns 200 with body
     content (HEAD with Content-Length > 0) or with an Allow header
     listing privileged methods (OPTIONS).

This is read-only — every method we use is non-mutating by HTTP
semantics, even if a misbehaving server might side-effect on TRACE.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoint hints likely to be protected. Operators can extend via
# --path. We deliberately list paths shaped like admin / user /
# internal endpoints, NOT generic homepage paths.
PROTECTED_HINTS = (
    "/api/users",
    "/api/admin",
    "/admin",
    "/admin/api",
    "/rest/admin/application-version",
    "/api/internal",
    "/api/me",
    "/api/account",
)

# Methods to test. TRACE is intentionally last because some
# WAFs strip the request entirely (status 0) and we don't want to
# spend budget if the host is unreachable.
TEST_METHODS = ("OPTIONS", "HEAD", "TRACE")


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _looks_protected(status: int, location: str, body: str) -> bool:
    """A GET response that says 'login required' counts as
    protected. We're conservative — only well-defined shapes."""
    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308):
        loc = (location or "").lower()
        if any(k in loc for k in ("login", "signin", "sign-in",
                                   "auth", "session")):
            return True
    return False


class AuthMethodBypassOptionsHeadTraceProbe(Probe):
    name = "auth_method_bypass_options_head_trace"
    summary = ("Detects auth filters that skip OPTIONS / HEAD / TRACE — "
               "those methods leak protected content or metadata.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional protected path to test. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = list(PROTECTED_HINTS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: list[dict] = []

        for path in candidates:
            full = urljoin(origin, path)
            # Step 1: confirm GET requires auth.
            rg = client.request("GET", full, follow_redirects=False)
            location = _hdr(rg.headers or {}, "Location")
            protected = _looks_protected(
                rg.status, location, rg.text or "")
            row: dict = {"path": path,
                         "get_status": rg.status,
                         "get_location": location[:120] if location else "",
                         "protected_by_get": protected,
                         "method_results": {}}
            if not protected:
                attempts.append(row)
                continue

            # Step 2: try the alternative methods.
            for m in TEST_METHODS:
                rm = client.request(m, full, follow_redirects=False)
                content_len = _hdr(rm.headers or {}, "Content-Length")
                allow = _hdr(rm.headers or {}, "Allow")
                bypass = False
                signal = None
                # Multiple corroborating signals required for ANY
                # method to qualify as a bypass:
                if m == "HEAD":
                    # HEAD bypass: GET was protected (401/403/redirect)
                    # but HEAD returns 200 AND the response advertises
                    # body bytes via Content-Length > 0. A 200 with
                    # CL=0 is normal for any HEAD response.
                    try:
                        cl = int(content_len) if content_len else 0
                    except ValueError:
                        cl = 0
                    if rm.status == 200 and cl > 0:
                        bypass = True
                        signal = f"HEAD 200 with Content-Length={cl}"
                elif m == "OPTIONS":
                    # OPTIONS bypass: 200 with an Allow header that
                    # lists privileged write verbs. Pure CORS
                    # preflight responses don't count — those don't
                    # carry an Allow header.
                    if rm.status == 200 and allow:
                        privileged = [v.strip().upper() for v in
                                      allow.split(",")]
                        if any(p in privileged
                               for p in ("DELETE", "PUT", "PATCH")):
                            bypass = True
                            signal = (f"OPTIONS 200 Allow: {allow}")
                elif m == "TRACE":
                    # TRACE bypass: 200 AND response body echoes our
                    # request line back (the canonical TRACE-enabled
                    # signature). We look for our exact path in the
                    # body, not just any 200 — the latter is way too
                    # easy to false-positive on default 200s.
                    if rm.status == 200 and path in (rm.text or ""):
                        bypass = True
                        signal = "TRACE 200 reflecting request line"
                row["method_results"][m] = {
                    "status": rm.status,
                    "size": rm.size,
                    "content_length_hdr": content_len,
                    "allow_hdr": allow,
                    "bypass": bypass,
                    "signal": signal,
                }
                if bypass:
                    confirmed.append({"path": path, "method": m,
                                      "signal": signal,
                                      "get_status": rg.status})
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: {origin}{top['path']} requires auth "
                    f"on GET (status {top['get_status']}) but "
                    f"{top['method']} bypasses the filter — "
                    f"{top['signal']}. The auth middleware does not "
                    "cover this method."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Auth filters must match by URL only, never by "
                    "method. Spring Security: replace `antMatchers(\""
                    "/admin/**\")` with `requestMatchers(\"/admin/"
                    "**\")` (or call `.anyRequest().authenticated()`). "
                    "Express: ensure the auth middleware runs before "
                    "the route handlers regardless of `req.method`. "
                    "Disable TRACE at the web-server layer "
                    "(`TraceEnable Off` in Apache, "
                    "`http.server_tokens off` + custom rewrite in "
                    "nginx)."),
            )
        return Verdict(
            validated=False, confidence=0.82,
            summary=(f"Refuted: tested {len(candidates)} candidate "
                     f"paths on {origin} with OPTIONS/HEAD/TRACE; no "
                     "method bypassed authentication on a confirmed-"
                     "protected endpoint."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthMethodBypassOptionsHeadTraceProbe().main()
