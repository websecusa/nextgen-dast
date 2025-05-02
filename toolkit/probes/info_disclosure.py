#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Information-disclosure check.

Fetches the target URL once and looks at the response for things a real
attacker could harvest: stack traces, framework version banners, internal
paths, env-var-style secrets, exposed admin / debug endpoints. The
patterns are configurable so a pentester can target a specific stack.

Examples (CLI):
    python info_disclosure.py --url 'https://x.com/error?abc=1'
    python info_disclosure.py --url 'https://x.com/' --pattern 'server: '
    python info_disclosure.py --url '...' --no-default-patterns \\
        --pattern 'Traceback' --pattern 'PHP Fatal'
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# Patterns that map to a real disclosure category. (regex, label, severity)
DEFAULT_PATTERNS = [
    (r"Traceback \(most recent call last\)",   "Python stack trace",     "high"),
    (r"PHP Fatal error|Stack trace:|in /var/www/", "PHP stack trace",     "high"),
    (r"<b>Warning</b>:\s+\w+\(\)",             "PHP runtime warning",     "medium"),
    (r"java\.lang\.\w+Exception",              "Java exception",          "high"),
    (r"at \w+\.\w+\(\w+\.java:\d+\)",          "Java stack trace",        "high"),
    (r"Microsoft \w+ Database Engine",         "MSSQL error",             "medium"),
    (r"You have an error in your SQL syntax",  "MySQL error",             "high"),
    (r"PostgreSQL.*ERROR",                     "PostgreSQL error",        "medium"),
    (r"ORA-\d{5}",                             "Oracle error",            "medium"),
    (r"<title>phpinfo\(\)</title>",            "phpinfo() exposed",       "high"),
    (r"X-Debug-Token",                         "Symfony debug token",     "medium"),
    (r"AKIA[0-9A-Z]{16}",                      "AWS access key in body",  "critical"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key in body", "critical"),
    (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "JWT in body", "medium"),
    (r"DEBUG\s*=\s*True",                      "Django DEBUG=True",       "high"),
    (r"Werkzeug Debugger",                     "Flask debug mode",        "high"),
]


class InfoDisclosureProbe(Probe):
    name = "info_disclosure"
    summary = "Info-disclosure check: scans body + headers for stack traces, secrets, debug pages."
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument("--pattern", action="append", default=[],
                            help="Extra regex pattern to match (repeatable). "
                                 "Match adds to evidence as 'custom'.")
        parser.add_argument("--no-default-patterns", action="store_true",
                            help="Skip the built-in pattern catalog; "
                                 "only use --pattern args.")

    def run(self, args, client: SafeClient) -> Verdict:
        r = client.request(args.method, args.url)
        if r.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable")

        body = r.text
        headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())

        patterns = []
        if not args.no_default_patterns:
            patterns += DEFAULT_PATTERNS
        for p in (args.pattern or []):
            patterns.append((p, "custom", "low"))

        hits = []
        worst = None
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for rx, label, sev in patterns:
            try:
                pat = re.compile(rx, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            m_body = pat.search(body)
            m_hdr = pat.search(headers_blob)
            if m_body or m_hdr:
                where = "body" if m_body else "headers"
                snippet = (m_body or m_hdr).group(0)[:200]
                hits.append({"label": label, "severity": sev,
                             "where": where, "match": snippet})
                if worst is None or sev_rank[sev] > sev_rank[worst]:
                    worst = sev

        if not hits:
            return Verdict(
                validated=False, confidence=0.7,
                summary=("No information-disclosure indicators in response. "
                         "If this finding came from a scanner, it's "
                         "likely benign."),
                evidence={"response_status": r.status,
                          "response_size": r.size,
                          "patterns_checked": len(patterns)},
            )

        return Verdict(
            validated=True, confidence=0.9,
            summary=(f"Information disclosure confirmed: {len(hits)} "
                     f"indicator(s) in the response. Worst severity: {worst}."),
            evidence={"response_status": r.status,
                      "response_size": r.size, "hits": hits},
            remediation=(
                "Disable verbose error pages in production. Strip "
                "framework banners (Server, X-Powered-By). Remove debug "
                "endpoints (phpinfo, Werkzeug, Symfony profiler) before "
                "deploy. Rotate any leaked secrets immediately."),
            severity_uplift=worst,
        )


if __name__ == "__main__":
    InfoDisclosureProbe().main()
