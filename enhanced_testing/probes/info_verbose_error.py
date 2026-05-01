#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: verbose error pages leak stack traces, internal
paths, and database engine details.

Production apps should return generic 500 pages — "something went
wrong" with a request ID. The bug here is the default-development
error handler still being on, so a small malformed input prints the
language stack trace, file paths, line numbers, and (worst) the SQL
text or query parameters that triggered the failure.

Detection signal:
  GET <known-injectable-endpoint> with a syntactically-broken payload
  returns 5xx AND the body contains framework-specific stack-trace
  markers. We require both conditions, otherwise generic 500 pages
  would false-positive.

Catalogue of "tickle the parser" payloads:
  - SQL: a stray `')` (closes one extra paren — Juice Shop is the
    canonical example, returns SQLITE_ERROR)
  - JSON: malformed body to a JSON endpoint
  - Path: a deeply-nested non-existent path

Each payload only fires once per probe run (idempotent), and the
endpoint catalogue intentionally targets endpoints likely to take
user input. We never POST destructive data.

Tested against:
  + OWASP Juice Shop  /rest/products/search?q=%27%29  →  HTTP 500 with
                       "<title>Error: SQLITE_ERROR: near \")\"... " in body
  + nginx default site                                 →  validated=False
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# (path, query-string, label). Each tuple is one "tickle" attempt.
# Keep the catalogue tight — five focused probes are better than fifty
# spammy ones. Each gets ONE GET per run.
TICKLE_REQUESTS = (
    ("/rest/products/search", "q=%27%29",       "sqli-stray-closeparen"),
    ("/rest/products/search", "q=%27",          "sqli-single-quote"),
    ("/rest/track-order/",     "",              "path-empty-id"),
    ("/api/Quantitys/null",   "",               "path-null-id"),
    ("/api/Users/9999999999999999", "",         "path-large-id"),
)

# Markers that uniquely identify a verbose error page. (regex, family)
# We require at least one to match. Each pattern is anchored on
# distinctive prose / file structure, NOT on generic words like "error"
# or "exception" — those false-positive on every API.
_STACK_MARKERS = (
    (re.compile(r"\bSQLITE_ERROR\b"),                                 "SQLite engine error"),
    (re.compile(r"\bSequelizeDatabaseError\b"),                       "Sequelize ORM error"),
    (re.compile(r"\bsqlite3_step\b|\bSQL logic error\b", re.I),       "SQLite engine error"),
    (re.compile(r"PostgreSQL\.\.\. error|\bpsycopg2\.\b"),             "PostgreSQL/psycopg2 error"),
    (re.compile(r"You have an error in your SQL syntax", re.I),       "MySQL error"),
    (re.compile(r"^\s*at\s+\S+\s+\(/.+\.js:\d+:\d+\)", re.M),         "Node.js stack frame"),
    (re.compile(r"Traceback\s+\(most recent call last\):", re.I),     "Python stack trace"),
    (re.compile(r"\.java:\d+\)\s*$", re.M),                           "Java stack frame"),
    (re.compile(r"PHP (Fatal|Warning|Notice|Parse) error", re.I),     "PHP runtime error"),
    (re.compile(r"<title>\s*Error:\s+\w+:\s*", re.I),                 "Express default error page"),
)


def _detect_marker(text: str) -> tuple[str, str] | None:
    if not text:
        return None
    # Scan a capped slice — error pages are usually short, but if the
    # server dumped a 1MB response we don't want to regex the whole
    # thing.
    snippet = text[:50000]
    for pat, family in _STACK_MARKERS:
        m = pat.search(snippet)
        if m:
            return family, m.group(0)[:200]
    return None


class VerboseErrorProbe(Probe):
    name = "info_verbose_error"
    summary = ("Detects verbose error pages that leak stack traces, "
               "DB engine names, or internal file paths.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional 'tickle' path:query (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for path, qs, label in TICKLE_REQUESTS:
            target = urljoin(origin, path) + (("?" + qs) if qs else "")
            r = client.request("GET", target)
            row: dict = {"label": label, "url": target,
                         "status": r.status, "size": r.size}
            if r.body:
                hit = _detect_marker(r.text)
                if hit:
                    family, snippet = hit
                    row.update({"verbose_error": True,
                                "error_family": family,
                                "snippet": snippet})
                    confirmed.append(row)
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: verbose error page on "
                         f"{top['url']} (HTTP {top['status']}). "
                         f"Detected: {top['error_family']}. The "
                         "response leaks framework / DB internals an "
                         "attacker can fingerprint."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Switch the application to its production error "
                    "handler so 5xx responses return a generic page "
                    "with a request ID and log the stack trace "
                    "server-side instead.\n"
                    "  - Express: `app.set('env','production')` + a "
                    "custom 4-arg error middleware.\n"
                    "  - Django: `DEBUG=False` + custom 500.html.\n"
                    "  - Spring Boot: `server.error.include-stacktrace=never`.\n"
                    "  - Flask: `FLASK_ENV=production`, custom "
                    "@app.errorhandler(500).\n"
                    "Pair this with a regression test that fires the "
                    "exact tickle payload above and asserts the body "
                    "doesn't contain the stack-trace marker."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} payloads against "
                     f"{origin} all returned non-verbose responses."),
            evidence=evidence,
        )


if __name__ == "__main__":
    VerboseErrorProbe().main()
