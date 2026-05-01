# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""SafeClient — the only way a probe should make HTTP requests.

Wraps urllib so we don't add a new dependency. Enforces:
  - Budget (request count, rate limit, scope, destructive-method gate)
  - Dry-run (record the intent, return a stub response)
  - Audit log (record every request and its outcome)
"""
from __future__ import annotations

import io
import json
import ssl
import time
import http.client
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .safety import AuditLog, Budget, SafetyViolation


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    elapsed_ms: int
    # The URL that produced this response. Equal to the requested URL
    # in the no-redirect case; equal to the final URL after the chain
    # when follow_redirects=True and the server returned a 3xx. Probes
    # that rely on the response coming from a specific path should
    # always check this field rather than trusting their requested URL.
    final_url: str = ""

    @property
    def size(self) -> int:
        return len(self.body or b"")

    @property
    def text(self) -> str:
        try:
            return (self.body or b"").decode("utf-8", "replace")
        except Exception:
            return ""

    def json(self):
        return json.loads(self.text)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Suppress automatic 3xx-following and surface the redirect itself.

    Used when a probe needs to see the redirect response (status code,
    Location header, body) instead of transparently being walked to its
    target. urllib's default HTTPRedirectHandler hides this from us;
    swapping in this subclass at opener-build time keeps every other
    safety / proxy / TLS handler intact while making the redirect
    visible. The redirect is re-raised as an HTTPError so the existing
    error-path in SafeClient.request picks it up unchanged.
    """

    def _stop(self, req, fp, code, msg, headers):
        body = b""
        try:
            body = fp.read()
        except Exception:
            # Body is optional on redirects; treat read errors as empty.
            body = b""
        raise urllib.error.HTTPError(
            req.full_url, code, msg, headers, io.BytesIO(body))

    http_error_301 = _stop
    http_error_302 = _stop
    http_error_303 = _stop
    http_error_307 = _stop
    http_error_308 = _stop


class SafeClient:
    """Tiny HTTP client. Honors an injected Budget + AuditLog. Caller
    constructs once per probe-run and uses it for every request."""

    def __init__(self, budget: Budget, audit: AuditLog,
                 cookie: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 default_headers: Optional[dict] = None,
                 proxy: Optional[str] = None,
                 verify_tls: bool = False,
                 timeout: float = 15.0):
        self.budget = budget
        self.audit = audit
        self.cookie = cookie
        self.user_agent = user_agent or "nextgen-dast-toolkit/1.0"
        self.default_headers = dict(default_headers or {})
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _opener(self, follow_redirects: bool = True):
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": self.proxy, "https": self.proxy,
            }))
        # TLS verification is off by default — DAST clients legitimately
        # need to talk to self-signed test environments. When the user
        # wants to verify, they pass verify_tls=True.
        if not self.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if not follow_redirects:
            # build_opener treats subclasses of the default handlers as
            # replacements, so this swaps out the redirect-following
            # default cleanly without disturbing any other handler.
            handlers.append(_NoRedirectHandler())
        return urllib.request.build_opener(*handlers)

    def request(self, method: str, url: str,
                headers: Optional[dict] = None,
                body: Optional[bytes | str] = None,
                follow_redirects: bool = True) -> Response:
        method = (method or "GET").upper()
        # SAFETY GATES — these MUST run before any network I/O
        self.budget.check_url(url)
        self.budget.check_method(method)
        self.budget.consume_request()

        if self.budget.dry_run:
            self.audit.record(method, url, note="dry-run")
            return Response(status=0, headers={}, body=b"",
                            elapsed_ms=0, final_url=url)

        merged_headers = dict(self.default_headers)
        if self.cookie:
            merged_headers["Cookie"] = self.cookie
        if self.user_agent:
            merged_headers["User-Agent"] = self.user_agent
        if headers:
            merged_headers.update(headers)

        if isinstance(body, str):
            body = body.encode()

        req = urllib.request.Request(url, data=body, method=method,
                                     headers=merged_headers)
        # Default the final URL to the requested URL; overwritten below
        # if urllib reports a different final URL after redirects.
        final_url = url
        t0 = time.monotonic()
        try:
            opener = self._opener(follow_redirects=follow_redirects)
            with opener.open(req, timeout=self.timeout) as resp:
                # IncompleteRead happens when a server promises a longer
                # Content-Length than it actually delivers (Juice Shop's
                # serve-index page does this on /ftp/, for example). The
                # body we received before the truncation is fine for our
                # purposes — preserve it via the .partial attribute.
                try:
                    data = resp.read()
                except http.client.IncompleteRead as ir:
                    data = ir.partial or b""
                hdrs = dict(resp.headers)
                status = resp.status
                # resp.url reflects the final URL after any followed
                # redirects; falls back to the request URL otherwise.
                final_url = getattr(resp, "url", None) or url
        except urllib.error.HTTPError as e:
            try:
                data = e.read() or b""
            except http.client.IncompleteRead as ir:
                data = ir.partial or b""
            hdrs = dict(e.headers or {})
            status = e.code
            final_url = getattr(e, "url", None) or url
        except urllib.error.URLError as e:
            self.audit.record(method, url, status=None, size=0,
                              note=f"network-error: {e.reason}")
            return Response(status=0, headers={}, body=b"",
                            elapsed_ms=int((time.monotonic() - t0) * 1000),
                            final_url=url)
        except http.client.IncompleteRead as ir:
            # Truncated before we even reached resp.read() context.
            data = ir.partial or b""
            hdrs, status = {}, 0
            self.audit.record(method, url, status=None, size=len(data),
                              note="incomplete-read at connect")
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        self.audit.record(method, url, status=status, size=len(data))
        return Response(status=status, headers=hdrs, body=data,
                        elapsed_ms=elapsed_ms, final_url=final_url)

    def get(self, url, **kw):    return self.request("GET",  url, **kw)
    def head(self, url, **kw):   return self.request("HEAD", url, **kw)
    def post(self, url, **kw):   return self.request("POST", url, **kw)
