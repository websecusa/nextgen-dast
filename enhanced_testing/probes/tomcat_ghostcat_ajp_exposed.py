#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Tomcat: AJP connector (port 8009) reachable -- Ghostcat
(CVE-2020-1938) precondition.

Tomcat ships with the AJP/1.3 protocol enabled by default on port
8009. AJP is meant for trusted communication between a front-end
web server and Tomcat -- it grants the AJP client elevated trust
(read arbitrary files, set request attributes, in some cases
include arbitrary files for execution under JSP). Exposing the
AJP port to the public internet was the root of the Ghostcat
vulnerability disclosed in 2020.

A clean fix exists (Tomcat 9.0.31+ binds AJP to 127.0.0.1 by
default and requires a `secret`), but a lot of older deployments
still expose AJP unintentionally because the port wasn't part of
the firewall ruleset.

This probe is a TCP-only check, not HTTP. It opens a single TCP
connection to port 8009 on the same hostname as the input URL,
sends a 4-byte AJP magic-cookie probe, and looks for any response.
We use the stdlib `socket` module rather than `SafeClient` because
this is not an HTTP request -- but we still respect the same
budget discipline (one connection, 2-second timeout, no retries).

High-fidelity rule:
  (a) TCP connect succeeds (port reachable, not closed/filtered);
  (b) the connector returns at least one byte after we send a
      benign AJP CPing-shaped probe -- proves it's an actual AJP
      speaker, not a random TCP service that happens to be on 8009.

Detection signal:
  TCP connect to host:8009; send AJP CPing magic; expect any
  response back. Both must be true.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEFAULT_AJP_PORT = 8009
CONNECT_TIMEOUT = 2.0

# AJP13 CPing packet: magic (0x12 0x34) + length (0x00 0x01) + type
# (0x0a = CPing). The connector's CPong response is 5 bytes
# (0x41 0x42 0x00 0x01 0x09). Tomcat doesn't reply to anything that
# isn't valid AJP framing, so a non-empty reply to this byte
# sequence is a high-fidelity AJP signal.
AJP_CPING = b"\x12\x34\x00\x01\x0a"


class TomcatGhostcatAjpExposedProbe(Probe):
    name = "tomcat_ghostcat_ajp_exposed"
    summary = ("Detects Tomcat AJP connector (port 8009) reachable "
               "-- Ghostcat (CVE-2020-1938) precondition.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--ajp-port", type=int, default=DEFAULT_AJP_PORT,
            help=f"AJP TCP port to probe (default "
                 f"{DEFAULT_AJP_PORT}).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        host = parsed.hostname
        port = int(args.ajp_port or DEFAULT_AJP_PORT)
        if not host:
            return Verdict(ok=False, error="invalid url -- no host")

        # Respect the SafeClient budget for parity with other probes.
        # We don't make an HTTP request through SafeClient, but we
        # still want this single TCP connect to count against the
        # probe's request budget.
        try:
            client.budget.consume_request()
        except Exception as e:
            return Verdict(
                ok=False, validated=None,
                summary=f"safety violation (budget): {e}",
                error=str(e))

        attempt = {"host": host, "port": port,
                   "tcp_connected": False, "ajp_replied": False,
                   "reply_bytes": 0}
        evidence = {"origin": f"{parsed.scheme}://{parsed.netloc}",
                    "attempt": attempt}

        sock = None
        try:
            # Single connection, 2s timeout. No retries.
            sock = socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT)
            attempt["tcp_connected"] = True
            sock.settimeout(CONNECT_TIMEOUT)
            sock.sendall(AJP_CPING)
            # Read up to a small bounded buffer; AJP CPong is 5
            # bytes. Any non-empty reply is sufficient signal.
            try:
                data = sock.recv(64)
            except socket.timeout:
                data = b""
            attempt["reply_bytes"] = len(data) if data else 0
            attempt["ajp_replied"] = bool(data)
            if data:
                # Capture just the first 16 bytes as a hex
                # fingerprint -- never the full content.
                attempt["reply_hex"] = data[:16].hex()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            attempt["error"] = f"{type(e).__name__}: {e}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        if attempt["tcp_connected"] and attempt["ajp_replied"]:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: AJP connector reachable at "
                    f"{host}:{port}. The host accepted a TCP "
                    "connection and replied to an AJP/1.3 CPing "
                    f"probe with {attempt['reply_bytes']} byte(s). "
                    "Anyone routable to this port can issue AJP "
                    "requests with elevated trust -- the precondition "
                    "for Ghostcat (CVE-2020-1938) and adjacent "
                    "AJP-trust abuses."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Either remove AJP entirely or bind it to "
                    "127.0.0.1 with a `secret`:\n"
                    "  ```xml\n"
                    "  <!-- conf/server.xml -->\n"
                    "  <!-- Option A: comment out the connector "
                    "entirely if no front-end uses AJP -->\n"
                    "  <!--\n"
                    "  <Connector protocol=\"AJP/1.3\" "
                    "address=\"::1\" port=\"8009\" "
                    "redirectPort=\"8443\"/>\n"
                    "  -->\n"
                    "  <!-- Option B: keep AJP but bind locally + "
                    "require a shared secret -->\n"
                    "  <Connector protocol=\"AJP/1.3\"\n"
                    "    address=\"127.0.0.1\" port=\"8009\"\n"
                    "    secret=\"<long-random>\" "
                    "secretRequired=\"true\"\n"
                    "    allowedRequestAttributesPattern=\"\"/>\n"
                    "  ```\n"
                    "Upgrade Tomcat to 9.0.31+ / 8.5.51+ / 7.0.100+ "
                    "to pick up the secure-by-default settings."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: AJP probe to {host}:{port} did not "
                     "yield a TCP-connect + AJP-reply pair "
                     f"(connected={attempt['tcp_connected']}, "
                     f"reply_bytes={attempt['reply_bytes']})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    TomcatGhostcatAjpExposedProbe().main()
