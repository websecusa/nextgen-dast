#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
HTTP response-header injection / response splitting via reflected
URL parameters.

Apps that copy a query parameter into a response header (for
example, ``Location:`` on redirect, ``Content-Disposition:`` on
download, custom ``X-Forwarded-For``-style headers) without
stripping CR/LF accept a payload of the form
``...%0d%0aX-Round12-Canary:%20pwned`` and emit a separate header
``X-Round12-Canary: pwned`` in the response. Once an attacker can
inject a header, full response-splitting (cache poisoning, XSS via
content type, session-cookie injection) follows.

The detection signal is structurally unambiguous: the response
must contain a header whose name we control. We scan
response.headers for ``X-Round12-Canary`` and only flag when an
exact-name match is found.

Detection signal:
  Response includes a header named ``X-Round12-Canary`` (case-
  insensitive exact match) carrying our chosen value.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly reflect a parameter into a response
# header. Each entry is (path, param-name).
TARGETS = (
    ("/redirect",          "url"),
    ("/redirect",          "to"),
    ("/redirect",          "next"),
    ("/api/redirect",      "url"),
    ("/login",             "redirect"),
    ("/logout",            "next"),
    ("/download",          "file"),
    ("/download",          "filename"),
    ("/api/download",      "filename"),
    ("/fetch",             "url"),
    ("/api/fetch",         "url"),
    ("/proxy",             "url"),
)

# The injected header name is unique per-run so a stale cached
# response from a prior probe execution can't fool us.
CANARY_HEADER_PREFIX = "X-Round12-Canary"


def _build_payload(canary_value: str, header_name: str) -> str:
    """Build the CRLF + header injection payload. The leading
    benign value is just so the response looks plausibly redirect-
    able (some apps reject empty Location values before they reach
    the header-write code)."""
    return ("https://example.com/"
            "\r\n" + header_name + ": " + canary_value)


def _has_canary_header(headers: dict, header_name: str
                       ) -> tuple[bool, str]:
    """Returns (found, value) for an exact-name header match in
    the response. Case-insensitive. We require the name to match
    in full — a partial match (e.g. canary substring inside an
    unrelated header value) does not count."""
    target = header_name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return True, v
    return False, ""


class HeaderInjectionResponseSplitProbe(Probe):
    name = "header_injection_response_split"
    summary = ("Detects HTTP response-header injection by injecting a "
               "uniquely-named canary header via CRLF in a reflected "
               "URL parameter.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional 'path|param' to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), n.strip()))

        # Run-unique header name and value.
        run_token = secrets.token_hex(4)
        header_name = f"{CANARY_HEADER_PREFIX}-{run_token}"
        canary_value = "pwned-" + secrets.token_hex(3)

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, pname in targets:
            payload = _build_payload(canary_value, header_name)
            url = (urljoin(origin, path) + "?" +
                    pname + "=" + quote(payload, safe=""))
            # We want to see the redirect itself, not have the
            # client follow it — otherwise the attacker-injected
            # header could be lost on the second hop.
            r = client.request("GET", url, follow_redirects=False)
            found, value = _has_canary_header(r.headers, header_name)
            row: dict = {"path": path, "param": pname,
                          "status": r.status, "size": r.size,
                          "canary_present": found}
            if found and canary_value in value:
                row["canary_value"] = value
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin,
                    "canary_header": header_name,
                    "canary_value": canary_value,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: HTTP response-header injection at "
                    f"{origin}{confirmed['path']}?{confirmed['param']}. "
                    f"The response carried our injected header "
                    f"`{header_name}: {confirmed['canary_value']}` — "
                    "CR/LF in the parameter was passed through to "
                    "the response writer, enabling response splitting "
                    "and downstream cache poisoning."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Strip CR (`\\r`) and LF (`\\n`) from any value "
                    "before writing it into a response header. Modern "
                    "HTTP libraries refuse to write a header value "
                    "containing CRLF — but only if you use the "
                    "library's header API instead of raw write:\n"
                    "  - Java Servlet: `HttpServletResponse.setHeader()` "
                    "throws on CR/LF in modern containers; never "
                    "build the header line manually.\n"
                    "  - Python: don't pass user input to "
                    "`response.headers[]=` without sanitisation.\n"
                    "  - Node Express: `res.setHeader()` rejects CR/LF "
                    "in current versions; ensure you're not "
                    "downstream of a vulnerable proxy.\n"
                    "Allowlist redirect targets to a known set of "
                    "internal paths — never honour arbitrary `?url=` "
                    "values."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(attempts)} path/param "
                     f"combinations on {origin}; no response carried "
                     f"the injected header `{header_name}`."),
            evidence=evidence,
        )


if __name__ == "__main__":
    HeaderInjectionResponseSplitProbe().main()
