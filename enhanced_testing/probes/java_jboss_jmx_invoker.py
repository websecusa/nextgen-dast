#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
JBoss JMX / HTTPInvoker / web-console reachable on the public
origin.

Old (and still surprisingly common in legacy enterprise stacks)
JBoss versions ship a JMX console that lets any caller invoke
arbitrary MBean operations. Reachable to anonymous = direct path
to RCE via the `BSHDeployer` MBean. The HTTPInvoker (`/invoker/
JMXInvokerServlet`, `/invoker/EJBInvokerServlet`) accepts Java
serialised payloads -- a classic deserialisation-RCE primitive.

Detection signal: GET each candidate path; validate per-path on a
known JBoss / web-console signature OR on the binary Java-
serialisation magic (`\\xac\\xed\\x00\\x05`) at the start of the
response body.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Each (path, signature_pattern, label) -- pattern is bytes for
# binary signals, str for HTML title signals.
TARGETS: tuple[tuple[str, str | bytes, str], ...] = (
    ("/jmx-console",                 "JBoss JMX",          "JBoss JMX console"),
    ("/jmx-console/",                "JBoss JMX",          "JBoss JMX console"),
    ("/jmx-console/HtmlAdaptor",     "MBean View",         "JBoss JMX HtmlAdaptor"),
    ("/web-console/",                "JBoss Web Console",  "JBoss web-console"),
    ("/web-console",                 "JBoss Web Console",  "JBoss web-console"),
    ("/invoker/JMXInvokerServlet",   b"\xac\xed\x00\x05",  "JMXInvoker (Java serialisation)"),
    ("/invoker/EJBInvokerServlet",   b"\xac\xed\x00\x05",  "EJBInvoker (Java serialisation)"),
)


class JavaJbossJmxInvokerProbe(Probe):
    name = "java_jboss_jmx_invoker"
    summary = ("Detects exposed JBoss JMX / HTTPInvoker / web-"
               "console paths -- legacy J2EE management surface "
               "that's RCE-on-reach.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional JBoss path to probe.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, sig, label in TARGETS:
            url = urljoin(origin, path)
            r = client.request("GET", url, follow_redirects=True)
            row: dict = {"path": path, "label": label,
                         "status": r.status, "size": r.size}
            if r.status in (200, 401) and r.body:
                if isinstance(sig, bytes):
                    if r.body.startswith(sig):
                        row["matched"] = "java-serialization-magic"
                        confirmed = row
                else:
                    if re.search(sig, r.text or "", re.I):
                        row["matched"] = sig
                        confirmed = row
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: JBoss management surface at "
                    f"{origin}{confirmed['path']} ({confirmed['label']}). "
                    "Path of least resistance to RCE on this stack -- "
                    "MBean invocation (jmx-console) or Java "
                    "deserialisation (invoker servlets)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Decommission the surface or move it off the "
                    "public network.\n"
                    "  - Modern JBoss / WildFly: remove the legacy "
                    "  jmx-console / web-console / invoker WARs "
                    "  (they're not needed for the management API).\n"
                    "  - Upgrade to a version that doesn't ship the "
                    "  classes vulnerable to Java-deserialisation "
                    "  RCE (CVE-2017-12149, CVE-2017-7504, etc.).\n"
                    "  - At the edge: 403 / drop traffic to "
                    "  `/jmx-console`, `/web-console`, `/invoker/*`.\n"
                    "  - Audit any incoming traffic to those paths "
                    "  during the exposure window for actual "
                    "  exploitation."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} JBoss paths "
                     f"on {origin}; none returned the JBoss / "
                     "Java-serialisation signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JavaJbossJmxInvokerProbe().main()
