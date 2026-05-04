#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
WebSocket: server accepts an arbitrary `Origin` on the upgrade
handshake.

The same-origin policy doesn't apply to WebSockets unless the
server enforces it. A WS server that accepts any `Origin` value on
the HTTP upgrade lets an attacker page (loaded by the victim)
open a WS to the application, authenticated by the victim's
ambient session cookie -- cross-site WebSocket hijacking. The
attacker reads every server-pushed message and can send messages
on the victim's behalf.

The high-fidelity signal is the upgrade response itself. We send
a properly-formed WS upgrade with `Origin: http://dast-attacker.example`
(a hostname that obviously isn't the application) and check
whether the server returns `101 Switching Protocols` with a valid
`Sec-WebSocket-Accept` header. Anything else (400 / 403 / no
upgrade) is the correct, secure response.

We compute Sec-WebSocket-Accept ourselves from the Sec-WebSocket-Key
we send, so we can verify the server's response actually completed
the upgrade rather than just returning a misleading 101.

Detection signal:
  GET <ws-path> with the upgrade header set, plus a foreign Origin.
  Validate when status == 101 AND Sec-WebSocket-Accept matches the
  expected derivation from our Sec-WebSocket-Key.

Tested against:
  + OWASP Juice Shop  socket.io transport on /socket.io/. Returns
                      400 to the raw upgrade because socket.io has
                      its own handshake; validated=False.
  + Apps with a generic ws:// endpoint and no Origin check
    -> validated=True.

Read-only: GET only. The handshake is encoded as POST to the
safety layer (it's a state-changing protocol switch, even if the
WS itself never carries a payload), so the orchestrator entry
needs `requires_post`.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Magic GUID baked into RFC 6455 -- the server appends it to our
# Sec-WebSocket-Key, SHA1s the result, and base64-encodes that to
# produce Sec-WebSocket-Accept. We reproduce the same calculation
# so we can verify the upgrade really completed.
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

WS_PATHS = (
    "/ws",
    "/api/ws",
    "/wss",
    "/socket",
    "/socket.io/?EIO=4&transport=websocket",
)

ATTACKER_ORIGIN_HOST = "dast-ws-attacker.example"


def _expected_accept(key_b64: str) -> str:
    """Compute the Sec-WebSocket-Accept value the server should
    return for a given Sec-WebSocket-Key."""
    s = (key_b64 + WS_MAGIC).encode()
    return base64.b64encode(hashlib.sha1(s).digest()).decode()


class WebsocketOriginValidationProbe(Probe):
    name = "config_websocket_origin_validation"
    summary = ("Detects WebSocket servers that accept upgrades from "
               "any `Origin` header -- cross-site WebSocket hijacking.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--ws-path", action="append", default=[],
            help="Additional WebSocket path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(WS_PATHS) + list(args.ws_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            # Per RFC 6455 the key is 16 random bytes, base64 encoded.
            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
            expected = _expected_accept(ws_key)
            r = client.request("GET", url, headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": ws_key,
                "Origin": f"http://{ATTACKER_ORIGIN_HOST}",
            }, follow_redirects=False)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            # urllib doesn't surface the 101; some servers route it
            # to a 200/400/404 in the proxy. We explicitly look for
            # the 101 + Sec-WebSocket-Accept combo, which is what
            # proves the handshake.
            accept_hdr = ""
            for k, v in (r.headers or {}).items():
                if k.lower() == "sec-websocket-accept":
                    accept_hdr = str(v).strip()
                    break
            row["sec_websocket_accept"] = accept_hdr or None
            row["expected_accept"] = expected
            if r.status == 101 and accept_hdr == expected:
                row["upgrade_completed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin,
                    "attacker_origin": f"http://{ATTACKER_ORIGIN_HOST}",
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} accepts a "
                    f"WebSocket upgrade with Origin "
                    f"`http://{ATTACKER_ORIGIN_HOST}`. Sec-WebSocket-"
                    f"Accept matched the expected derivation -- the "
                    "handshake fully completed. Cross-site WebSocket "
                    "hijacking is reachable from any attacker page the "
                    "victim visits."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Validate `Origin` on every WebSocket upgrade.\n"
                    "  - ws (Node): inspect `request.headers.origin` in "
                    "the `verifyClient` callback and refuse anything "
                    "outside an allowlist.\n"
                    "  - Django Channels: `OriginValidator` middleware "
                    "with `ALLOWED_HOSTS`.\n"
                    "  - Spring: `WebSocketMessageBrokerConfigurer` -- "
                    "register an `OriginInterceptor` with explicit hosts.\n"
                    "  - Generic: refuse upgrades whose Origin doesn't "
                    "match the application's known frontend origins.\n"
                    "Pair with a CSRF token on the WS upgrade itself "
                    "(send the token as the first message; reject the "
                    "connection if missing) so a stolen session cookie "
                    "alone doesn't unlock the channel."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} WS paths on "
                     f"{origin} with a foreign Origin; none completed "
                     "a WebSocket upgrade."),
            evidence=evidence,
        )


if __name__ == "__main__":
    WebsocketOriginValidationProbe().main()
