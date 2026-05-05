#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: WebSocket endpoints accept anonymous connections.

Many apps wire authorization onto their HTTP routes but forget the
WebSocket upgrade path. The WS handshake is a regular HTTP/1.1
GET — same cookies, same headers — and the server's upgrade
handler may complete the handshake (HTTP 101) without checking the
caller's session. Once upgraded, the attacker can send arbitrary
WS frames (channel subscriptions, command messages) that the
in-app authz layer never sees.

Probe approach:
  1. Discover candidate WS paths from the homepage HTML
     (`new WebSocket("/ws")` etc.) plus a small static fallback
     list (`/ws`, `/socket.io/`, `/websocket`).
  2. For each path, send a fully-formed `Upgrade: websocket`
     handshake WITHOUT any cookie / Authorization header. We use
     the SafeClient as the transport; the server's response status
     is what we read.
  3. We require BOTH:
       (a) HTTP 101 Switching Protocols, AND
       (b) the response carries `Upgrade: websocket` + a
           `Sec-WebSocket-Accept` value computed from our nonce
           via the standard RFC 6455 derivation. (b) confirms the
           server actually completed the handshake rather than
           returning a 101 from an unrelated module.
  4. Endpoints that are not WS at all (404/405/200) are recorded
     and the probe refutes cleanly.

Detection signal:
  101 + Upgrade: websocket + correct Sec-WebSocket-Accept on a
  path the handshake provided no cookie / Authorization for.
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# RFC 6455 fixed GUID used in the handshake accept calculation.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Static fallback paths. Expand sparingly — each adds to the
# request budget.
DEFAULT_WS_PATHS = (
    "/ws",
    "/websocket",
    "/socket.io/",
    "/api/ws",
    "/realtime",
)

# Pull `new WebSocket("…")` and `io("…")` strings from the homepage
# JS so we can probe app-specific paths too. The regex is anchored
# on the API surface to avoid scooping up arbitrary URLs.
WS_PATH_RE = re.compile(
    r"""(?ix)
    (?:new\s+WebSocket\s*\(\s*['"]([^'"]+)['"])
    |
    (?:io\s*\(\s*['"]([^'"]+)['"])
    |
    (?:websocketUrl\s*[:=]\s*['"]([^'"]+)['"])
    """
)


def _expected_accept(key_b64: str) -> str:
    """RFC 6455 §1.3: server returns base64(sha1(key + GUID))."""
    digest = hashlib.sha1((key_b64 + WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def _hdr_lookup(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. urllib normalizes some, but not
    all, headers, so we walk every key."""
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return str(v)
    return ""


class WebsocketUnauthenticatedProbe(Probe):
    name = "authz_websocket_unauthenticated"
    summary = ("Detects WebSocket endpoints that complete the handshake "
               "for an unauthenticated caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--ws-path", action="append", default=[],
            help="Additional WebSocket path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1 — gather candidate paths. Homepage scrape is best-
        # effort; on a site that doesn't link a JS bundle from `/`,
        # we fall back to the static list silently.
        candidates: list[str] = list(args.ws_path or [])
        try:
            r = client.request("GET", urljoin(origin, "/"))
            if r.status == 200 and r.body:
                for groups in WS_PATH_RE.findall(r.text or ""):
                    for g in groups:
                        if g and g not in candidates:
                            candidates.append(g)
        except Exception:
            # Homepage fetch failure is not fatal to the probe.
            pass
        for p in DEFAULT_WS_PATHS:
            if p not in candidates:
                candidates.append(p)
        # Cap candidate count so a chatty homepage can't blow the budget.
        candidates = candidates[:5]

        # Phase 2 — handshake each candidate. We construct the
        # canonical Sec-WebSocket-Key (16 random bytes, base64) per
        # request so the server's accept value is uniquely derivable.
        attempts: list[dict] = []
        confirmed: dict | None = None
        for path in candidates:
            # Resolve absolute URL. urljoin handles both absolute and
            # path-only candidates.
            target = (path if path.startswith(("http://", "https://"))
                      else urljoin(origin, path))
            # Same-origin guard: refuse anything that resolved off-host.
            tparsed = urlparse(target)
            if (tparsed.netloc or "").lower() != (parsed.netloc or "").lower():
                attempts.append({"path": path, "skipped": "off-origin",
                                  "resolved": target})
                continue
            nonce = base64.b64encode(secrets.token_bytes(16)).decode()
            expected = _expected_accept(nonce)
            handshake_headers = {
                # Note: we deliberately do NOT set Cookie or
                # Authorization. The probe is *about* the absence of
                # these.
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": nonce,
                "Sec-WebSocket-Version": "13",
                "Origin": origin,
            }
            # follow_redirects=False so a 3xx-to-login is visible as
            # the refutation it represents, not silently followed.
            r = client.request("GET", target,
                               headers=handshake_headers,
                               follow_redirects=False)
            row = {"path": path, "url": target, "status": r.status,
                   "expected_accept": expected,
                   "got_accept": _hdr_lookup(r.headers,
                                              "Sec-WebSocket-Accept"),
                   "got_upgrade": _hdr_lookup(r.headers, "Upgrade")}
            attempts.append(row)
            # All three signals: 101 status, Upgrade header echoed,
            # accept hash matches our derivation. Anything less is a
            # false alarm we explicitly refuse to call.
            if (r.status == 101
                    and row["got_upgrade"].lower() == "websocket"
                    and row["got_accept"].strip() == expected):
                confirmed = row
                break

        evidence = {"origin": origin, "candidates": candidates,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: WebSocket handshake on "
                         f"{confirmed['url']} completed (101 + "
                         "RFC-6455 accept hash matches) without any "
                         "Cookie or Authorization header. Anonymous "
                         "callers can establish a WS session."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Apply the same authorization gate to the WS "
                    "upgrade route as the rest of the API. Concrete "
                    "options:\n"
                    "  - Reject the handshake with 401 if no valid "
                    "session cookie / JWT is presented in the upgrade "
                    "request.\n"
                    "  - Validate `Origin` against an allowlist to "
                    "block cross-site WebSocket hijacking.\n"
                    "  - In Spring `WebSocketHandlerRegistry`, attach "
                    "an `HandshakeInterceptor` that calls "
                    "`Authentication`. In Socket.IO, use the `auth` "
                    "callback in the connection middleware. In ws / "
                    "uWebSockets, gate the upgrade event on a session "
                    "lookup."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} candidate "
                     f"WebSocket path(s) on {origin}; none completed a "
                     "valid RFC-6455 handshake without auth."),
            evidence=evidence,
        )


if __name__ == "__main__":
    WebsocketUnauthenticatedProbe().main()
