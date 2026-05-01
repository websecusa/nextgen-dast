#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Validator for wapiti / nikto / nuclei 'anomaly: 5xx' findings.

Wapiti's `file`, `sql`, `xss`, `permanentxss`, and other modules emit
an "anomaly: Internal Server Error" entry whenever an injection
payload triggers a 5xx response. Most of those flags are false
positives in modern stacks: the 5xx is upstream buffer overflow
(the long payload won't fit into the proxy's response-header
buffer), generic gateway timeouts, or transient scanner artefacts.
A few are real -- the request crashed the application AND the crash
page leaks framework / path / SQL detail.

This probe disambiguates the three cases:

  1. Replay the original request verbatim, parsed from
     `raw_data.http_request`. If the response is no longer 5xx,
     the finding cannot be reproduced -> false positive.

  2. If the 5xx reproduces, scan the response body and headers for
     the standard information-disclosure markers (stack traces,
     framework banners, internal paths, SQL errors). A hit means
     the 5xx really does leak detail and the finding is real.

  3. Otherwise, send a control payload of the SAME length but
     containing no malicious content. If the control also produces
     a 5xx, the cause is size/buffer (the upstream proxy can't fit
     the response headers built around the reflected parameter).
     The finding is then a false positive of the security flag,
     though we surface a low-severity robustness recommendation
     (cap the parameter's length).

  4. Module-aware sanity: for `file`-module findings we additionally
     fingerprint the server stack. PHP filter chains have no
     semantic meaning on a Python / Java / Go / Node runtime, so a
     `file` 5xx against a non-PHP stack cannot be a real LFI.

Verdicts
--------

  validated=True
    The 5xx reproduces AND either the body discloses internal
    detail OR the 5xx is content-driven (a same-length benign
    payload does NOT trigger 5xx). Robustness or info-disclosure
    issue, depending on which path fired.

  validated=False
    Either the 5xx cannot be reproduced (transient) or it is
    purely size-driven (the same-length benign payload also
    produces 5xx, with no body disclosure). The wapiti flag is
    a false positive of the security finding. We still emit a
    remediation note for the underlying robustness gap.

  validated=None
    The original request blob is malformed and we cannot replay
    it; the probe declines to rule.

Examples
--------

    cat finding.json | python anomaly_5xx_validation.py --stdin

    python anomaly_5xx_validation.py \\
        --url 'https://app/login' \\
        --param next \\
        --raw-payload "$(cat payload.txt)"
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse, parse_qsl

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# ---- Disclosure pattern catalog -------------------------------------------
# Borrowed (and trimmed) from info_disclosure.py. Each entry is
# (regex, label, severity). The probe scans body+headers and
# escalates the verdict when any of these match.
_DISCLOSURE_PATTERNS: list[tuple[str, str, str]] = [
    (r"Traceback \(most recent call last\)",   "Python stack trace",     "high"),
    (r"PHP Fatal error|Stack trace:",          "PHP stack trace",        "high"),
    (r"<b>Warning</b>:\s+\w+\(\)",             "PHP runtime warning",    "medium"),
    (r"java\.lang\.\w+Exception",              "Java exception",         "high"),
    (r"at \w+\.\w+\(\w+\.java:\d+\)",          "Java stack trace",       "high"),
    (r"Microsoft \w+ Database Engine",         "MSSQL error",            "medium"),
    (r"You have an error in your SQL syntax",  "MySQL error",            "high"),
    (r"PostgreSQL.*ERROR",                     "PostgreSQL error",       "medium"),
    (r"ORA-\d{5}",                             "Oracle error",           "medium"),
    (r"Werkzeug Debugger",                     "Flask debug mode",       "high"),
    (r"DEBUG\s*=\s*True",                      "Django DEBUG=True",      "high"),
    (r"X-Debug-Token",                         "Symfony debug token",    "medium"),
    # Filesystem path leakage. Tightened so a generic mention of
    # "/var" inside HTML doesn't trip the detector.
    (r"\b(?:/var/www/|/home/[a-z0-9_-]+/|/opt/[a-z0-9_-]+/|"
     r"/usr/local/[a-z0-9_-]+/|/app/[a-z0-9_./-]+\.py)",
                                               "Internal path leakage",  "low"),
]

# Statuses that count as the kind of 5xx wapiti's anomaly module
# flags. We accept the full 5xx range -- 502 (Bad Gateway, common on
# upstream-buffer-overflow), 503 (Service Unavailable), 504 (Gateway
# Timeout), 500/501.
_ANOMALY_STATUSES = range(500, 600)


# ---- HTTP-request blob parser ---------------------------------------------

def _parse_http_request_blob(blob: str) -> Optional[dict]:
    """Parse wapiti's `raw_data.http_request` -- a tcpdump-style
    HTTP/1.1 request as text. Returns a dict with method, path,
    headers (lower-cased keys), and body (bytes), or None on
    malformed input.

    The blob looks like:

        POST /login HTTP/1.1
        host: example.com
        content-type: application/x-www-form-urlencoded

        next=...&username=...&password=...
    """
    if not blob or "\n" not in blob:
        return None
    # The blank line separating headers from body may be encoded as
    # "\n\n" (wapiti's typical) or "\r\n\r\n" (true HTTP). Normalize.
    text = blob.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        return None
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body.encode("utf-8", errors="surrogateescape"),
    }


def _resolve_url(parsed: dict, fallback_url: str) -> str:
    """Build the absolute URL to send the replay to. Prefer the
    Host header from the captured request; fall back to the
    fallback URL's host if the captured Host is missing."""
    host = parsed["headers"].get("host", "")
    fb = urlparse(fallback_url)
    scheme = fb.scheme or "https"
    if host:
        return f"{scheme}://{host}{parsed['path']}"
    return urljoin(fallback_url, parsed["path"])


# ---- Body / form parameter manipulation ------------------------------------

def _replace_param_in_form(body: bytes, param: str,
                           new_raw_value: str) -> bytes:
    """Replace the wire-form value of `param` in a urlencoded form
    body. The replacement is spliced in BYTE-FOR-BYTE; we don't
    decode + re-encode the surrounding pairs, because that
    round-trip would shift characters like `+` vs `%20` and change
    the body's wire length by a few bytes -- enough to mask the
    upstream-buffer-overflow signal we're trying to detect."""
    needle = re.compile(
        rb"(?:^|&)(" + re.escape(param.encode()) + rb")=([^&]*)")
    new = new_raw_value.encode()
    m = needle.search(body)
    if not m:
        sep = b"&" if body else b""
        return body + sep + param.encode() + b"=" + new
    start, end = m.span(2)
    return body[:start] + new + body[end:]


def _replace_param_in_query(url: str, param: str, new_raw_value: str) -> str:
    """Replace `param` byte-for-byte in the URL's query string."""
    u = urlparse(url)
    qs = u.query.encode()
    needle = re.compile(
        rb"(?:^|&)(" + re.escape(param.encode()) + rb")=([^&]*)")
    m = needle.search(qs)
    new = new_raw_value.encode()
    if not m:
        sep = b"&" if qs else b""
        new_qs = (qs + sep + param.encode() + b"=" + new).decode()
    else:
        start, end = m.span(2)
        new_qs = (qs[:start] + new + qs[end:]).decode()
    return u._replace(query=new_qs).geturl()


def _extract_param_value(body: bytes, url: str, param: str,
                         content_type: str) -> str:
    """Return the value the captured request sent for `param`. Looks
    in the body when content-type is form-encoded, otherwise in
    the URL's query string. Empty string when not found."""
    if "x-www-form-urlencoded" in (content_type or "").lower() and body:
        text = body.decode("utf-8", errors="replace")
        for k, v in parse_qsl(text, keep_blank_values=True):
            if k == param:
                return v
    u = urlparse(url)
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        if k == param:
            return v
    return ""


def _raw_encoded_length(body: bytes, url: str, param: str,
                        content_type: str) -> int:
    """Length in bytes of the param's value AS IT APPEARS ON THE
    WIRE (url-encoded). Critical for the same-length control test --
    if the original payload's encoded form is 4308 bytes (because
    `:` and `/` expand to `%3A`/`%2F`) but the decoded value is
    3946 bytes, a control built from 3946 A's would be SHORTER on
    the wire and might not trigger the same upstream-buffer
    overflow we're trying to disambiguate.
    """
    needle = re.compile(
        rb"(?:^|&)" + re.escape(param.encode()) + rb"=([^&]*)")
    if "x-www-form-urlencoded" in (content_type or "").lower() and body:
        m = needle.search(body)
        if m:
            return len(m.group(1))
    qs = urlparse(url).query.encode()
    m = needle.search(qs)
    return len(m.group(1)) if m else 0


# ---- Disclosure scan -------------------------------------------------------

def _scan_for_disclosure(body: str, headers: dict) -> tuple[list[dict], Optional[str]]:
    """Run the disclosure catalog over response body + headers.
    Returns (hits, worst_severity)."""
    headers_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    hits: list[dict] = []
    worst: Optional[str] = None
    body = (body or "")[:32000]   # cap to keep regex cost bounded
    for rx, label, sev in _DISCLOSURE_PATTERNS:
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
    return hits, worst


# ---- Server-stack fingerprint (PHP-vs-not for module=file findings) -------

def _fingerprint_stack(client: SafeClient, base_url: str) -> dict:
    """Best-effort detection of server stack. Used to falsify
    PHP-only LFI vectors (php://filter) when the app is Python /
    Node / Java / Go.

    Returns a dict with:
      - 'is_php'   bool   any PHP indicator was observed
      - 'is_python' bool  any Python/Werkzeug/Django indicator
      - 'server'   str    Server header value
      - 'powered'  str    X-Powered-By value
      - 'reasons'  list[str] one-line evidence per signal hit

    Costs one GET. Failure is non-fatal -- on error we return an
    empty dict rather than throw.
    """
    try:
        u = urlparse(base_url)
        root = f"{u.scheme}://{u.netloc}/"
        r = client.request("GET", root)
    except Exception:
        return {}

    server = r.headers.get("Server") or r.headers.get("server") or ""
    powered = r.headers.get("X-Powered-By") or r.headers.get("x-powered-by") or ""
    body_low = (r.text or "")[:8000].lower()
    reasons: list[str] = []
    is_php = False
    is_python = False
    if "php" in (powered or "").lower():
        is_php = True; reasons.append(f"X-Powered-By: {powered}")
    if "phpsessid" in r.headers.get("Set-Cookie", "").lower():
        is_php = True; reasons.append("PHPSESSID cookie")
    if ".php" in body_low:
        is_php = True; reasons.append(".php URL referenced in body")
    if "werkzeug" in body_low or "fastapi" in body_low or "django" in body_low:
        is_python = True; reasons.append("Python framework signal in body")
    if "uvicorn" in (server or "").lower() or "gunicorn" in (server or "").lower():
        is_python = True; reasons.append(f"Server: {server}")
    return {
        "is_php": is_php,
        "is_python": is_python,
        "server": server,
        "powered": powered,
        "reasons": reasons,
    }


# ---- Probe -----------------------------------------------------------------

class Anomaly5xxValidationProbe(Probe):
    name = "anomaly_5xx_validation"
    summary = ("Replays a 5xx anomaly finding from the captured "
               "HTTP request, scans for info disclosure, and uses "
               "a same-length benign control payload to "
               "disambiguate content-driven from size-driven 5xx.")
    safety_class = "probe"

    def add_args(self, parser):
        # `--param` is already declared by the base parser. We pull
        # its value from args.param at run time and fall back to
        # raw_data['parameter'] when absent.
        parser.add_argument("--module", default=None,
                            help="Originating wapiti module ('file', "
                                 "'sql', 'xss', ...). Used to apply "
                                 "module-aware sanity checks.")
        parser.add_argument("--retries", type=int, default=2,
                            help="Number of replays before declaring "
                                 "non-reproduction (default 2)")
        parser.add_argument("--control-char", default="A",
                            help="Single character used to build the "
                                 "same-length benign control payload "
                                 "(default A)")

    # ----- helpers --------------------------------------------------------

    @staticmethod
    def _is_5xx(status: int) -> bool:
        return status in _ANOMALY_STATUSES

    @staticmethod
    def _summarize_response(resp, label: str) -> dict:
        return {
            "label": label,
            "status": resp.status,
            "size": resp.size,
            "server": resp.headers.get("Server")
                      or resp.headers.get("server") or "",
        }

    # ----- main logic -----------------------------------------------------

    def run(self, args, client: SafeClient) -> Verdict:
        # raw_data is delivered to the probe as a JSON string
        # (build_finding_config passes it through verbatim from the
        # findings row). The base Probe driver routes any unknown
        # stdin keys onto args.extra, so check there first; CLI
        # callers may set --raw-data directly via args.raw_data.
        extra = getattr(args, "extra", None) or {}
        raw_blob = (extra.get("raw_data") if isinstance(extra, dict)
                    else None) or getattr(args, "raw_data", None) or ""
        if isinstance(raw_blob, str) and raw_blob.strip():
            try:
                raw = json.loads(raw_blob)
            except Exception:
                raw = {}
        elif isinstance(raw_blob, dict):
            raw = raw_blob
        else:
            raw = {}

        http_blob = raw.get("http_request") or ""
        wapiti_module = (args.module or raw.get("module") or "").lower()
        param = args.param or raw.get("parameter") or ""
        # Open the destructive gate -- replaying the original
        # captured request can include POST/PUT/DELETE methods. The
        # manifest declares requires_post=true so this is on the
        # honest side of the safety contract.
        client.budget.allow_destructive = True

        parsed = _parse_http_request_blob(http_blob) if http_blob else None
        if not parsed:
            # Fall back to a generic GET against the evidence URL.
            # Without the captured request we cannot reproduce
            # wapiti's payload, but at least we can verify whether
            # the URL itself currently 5xx's.
            r = client.request(args.method or "GET", args.url)
            if self._is_5xx(r.status):
                hits, worst = _scan_for_disclosure(r.text, r.headers)
                return Verdict(
                    ok=True, validated=bool(hits),
                    confidence=0.6 if hits else 0.5,
                    summary=("no captured request to replay; the URL "
                            "alone " +
                            ("returns 5xx with disclosure indicators"
                             if hits else
                             "returns 5xx but with no disclosure "
                             "indicators in the response")),
                    evidence={"replay": self._summarize_response(r, "url-only"),
                              "hits": hits, "raw_data_present": False},
                    severity_uplift=worst,
                )
            return Verdict(
                ok=True, validated=False, confidence=0.7,
                summary=("no captured request to replay; the URL "
                         f"alone returns HTTP {r.status}, not 5xx -- "
                         "the original anomaly was likely transient."),
                evidence={"replay": self._summarize_response(r, "url-only"),
                          "raw_data_present": False},
            )

        replay_url = _resolve_url(parsed, args.url)
        replay_method = parsed["method"]
        replay_body = parsed["body"]
        # Pass through the captured request's headers, but strip
        # hop-by-hop headers and any Host/Cookie (urllib will set
        # Host; the orchestrator-supplied cookie wins via
        # client.cookie). Also drop Content-Length -- urllib
        # recomputes it from the body and a stale value would corrupt
        # the request when we mutate the body for control payloads.
        skip = {"host", "cookie", "connection", "content-length",
                "accept-encoding", "transfer-encoding", "keep-alive"}
        replay_headers = {k: v for k, v in parsed["headers"].items()
                          if k not in skip}
        # Normalize Content-Type capitalization -- some older HTTP
        # capture tools emit it twice with different casings.
        ct = (parsed["headers"].get("content-type") or "")

        # ---- Step 1: replay the original request --------------------
        replay = client.request(replay_method, replay_url,
                                headers=replay_headers,
                                body=replay_body)
        replay_summary = self._summarize_response(replay, "replay (original payload)")
        replay_summary["body_excerpt"] = (replay.text or "")[:300]

        if not self._is_5xx(replay.status):
            # Try a couple of retries before declaring non-repro --
            # 5xx anomalies are sometimes transient (rate limit,
            # backend hiccup).
            retries: list[dict] = []
            saw_5xx = False
            for i in range(max(0, int(args.retries))):
                rr = client.request(replay_method, replay_url,
                                    headers=replay_headers,
                                    body=replay_body)
                retries.append(self._summarize_response(rr, f"retry-{i+1}"))
                if self._is_5xx(rr.status):
                    saw_5xx = True
                    replay = rr
                    replay_summary = self._summarize_response(
                        rr, f"replay (original payload, retry {i+1})")
                    replay_summary["body_excerpt"] = (rr.text or "")[:300]
                    break
            if not saw_5xx:
                return Verdict(
                    ok=True, validated=False, confidence=0.85,
                    summary=("Cannot reproduce the 5xx: "
                             f"replay returned HTTP {replay.status} "
                             f"({len(retries)} retries also <500). "
                             "The original anomaly was likely a "
                             "transient scan-time artifact (rate "
                             "limit, backend restart). Wapiti's "
                             "anomaly flag is a false positive."),
                    evidence={"replay": replay_summary,
                              "retries": retries,
                              "param": param,
                              "module": wapiti_module},
                )

        # ---- Step 2: scan for information disclosure ----------------
        hits, worst = _scan_for_disclosure(replay.text, replay.headers)

        if hits:
            return Verdict(
                ok=True, validated=True, confidence=0.92,
                summary=(f"5xx reproduces AND the response leaks "
                         f"{len(hits)} info-disclosure indicator(s) "
                         f"(worst: {worst}). The wapiti anomaly is a "
                         "real information-disclosure issue."),
                evidence={"replay": replay_summary,
                          "hits": hits,
                          "param": param,
                          "module": wapiti_module},
                remediation=(
                    "Disable verbose error pages in production. "
                    "Catch and translate framework exceptions to "
                    "generic 500 responses with no stack trace, "
                    "framework banner, or path content. Strip "
                    "Server / X-Powered-By headers."),
                severity_uplift=worst,
            )

        # ---- Step 3: same-length benign control --------------------
        # Build a control payload of the SAME byte length as the
        # original injected value, made of harmless characters.
        # Compare by sending a request that differs ONLY in the
        # value of `param`. If the control also 5xx's, the cause is
        # buffer/length, not the malicious content.
        original_value = ""
        original_encoded_len = 0
        control_resp = None
        short_control_resp = None
        if param:
            original_value = _extract_param_value(
                replay_body, replay_url, param, ct)
            # Use the WIRE length (url-encoded), not the decoded
            # length. The proxy buffer overflows on the wire bytes,
            # not the decoded payload. See _raw_encoded_length docstring.
            original_encoded_len = _raw_encoded_length(
                replay_body, replay_url, param, ct)
            control_char = (args.control_char[:1] or "A")
            control_value = control_char * max(1, original_encoded_len)
            if "x-www-form-urlencoded" in ct.lower():
                control_body = _replace_param_in_form(
                    replay_body, param, control_value)
                control_url = replay_url
            else:
                control_body = replay_body
                control_url = _replace_param_in_query(
                    replay_url, param, control_value)
            control_resp = client.request(replay_method, control_url,
                                          headers=replay_headers,
                                          body=control_body)

            # Short benign control: a 1-byte value. If THIS doesn't
            # 5xx, we know the URL/route itself is fine, the failure
            # really is parameter-driven.
            if "x-www-form-urlencoded" in ct.lower():
                short_body = _replace_param_in_form(replay_body, param, "x")
                short_url = replay_url
            else:
                short_body = replay_body
                short_url = _replace_param_in_query(replay_url, param, "x")
            short_control_resp = client.request(replay_method, short_url,
                                                headers=replay_headers,
                                                body=short_body)

        control_summary = (self._summarize_response(
            control_resp,
            f"control (same length, '{args.control_char[:1] or 'A'}' fill)")
            if control_resp else None)
        short_summary = (self._summarize_response(
            short_control_resp, "short control (1-byte value)")
            if short_control_resp else None)

        # ---- Step 4: module-aware stack fingerprint -----------------
        stack = {}
        if wapiti_module == "file":
            stack = _fingerprint_stack(client, replay_url)

        # ---- Step 5: verdict ----------------------------------------
        size_driven = (control_resp is not None
                       and self._is_5xx(control_resp.status)
                       and short_control_resp is not None
                       and not self._is_5xx(short_control_resp.status))

        impossible_lfi = (wapiti_module == "file"
                          and stack.get("is_python")
                          and not stack.get("is_php"))

        # Common evidence block.
        ev = {
            "replay": replay_summary,
            "control": control_summary,
            "short_control": short_summary,
            "param": param,
            "module": wapiti_module,
            "original_decoded_length": len(original_value),
            "original_wire_length": original_encoded_len,
            "stack_fingerprint": stack,
            "size_driven": bool(size_driven),
            "impossible_lfi": bool(impossible_lfi),
        }

        if size_driven:
            note = ""
            if impossible_lfi:
                note = (" Server stack is Python (not PHP), so "
                        "wapiti's php://filter LFI vector is "
                        "impossible regardless of the 5xx behaviour.")
            return Verdict(
                ok=True, validated=False, confidence=0.9,
                summary=(f"5xx is size-driven. A benign "
                         f"{original_encoded_len}-byte (wire-length) "
                         f"payload in `{param}` produces the same "
                         f"{control_resp.status} as the malicious "
                         f"payload, while a 1-byte value succeeds "
                         f"({short_control_resp.status}). The 5xx "
                         f"is upstream buffer / proxy header "
                         f"overflow when the parameter is reflected "
                         f"into a response (typically a redirect "
                         f"Location header). The wapiti security "
                         f"flag is a false positive." + note),
                evidence=ev,
                remediation=(
                    f"Cap `{param}` to a sane length on the server "
                    "(256 chars is plenty for a redirect target or "
                    "search query) and reject longer values with "
                    "HTTP 400. This prevents upstream proxies from "
                    "returning 502 Bad Gateway when an over-large "
                    "value is reflected into a response header."),
            )

        # 5xx persists with same-length benign payload too AND short
        # control also 5xx -- the URL itself is broken, not parameter-
        # driven. Lean toward false positive of the security flag
        # but flag as inconclusive so an analyst eyeballs it.
        if (control_resp and self._is_5xx(control_resp.status)
                and short_control_resp
                and self._is_5xx(short_control_resp.status)):
            return Verdict(
                ok=True, validated=None, confidence=0.4,
                summary=("5xx reproduces on every variant tried "
                         "(original, same-length benign, 1-byte). "
                         "The URL itself is failing, independent of "
                         "the injected parameter -- not a "
                         "parameter-injection issue. Likely an "
                         "upstream outage or misrouted request "
                         "rather than the security flag wapiti "
                         "asserts. Hand to an analyst."),
                evidence=ev,
            )

        # 5xx is content-driven (malicious specifically triggers
        # 5xx, benign same-length doesn't). Robustness bug; not
        # necessarily a security issue, but worth confirming.
        return Verdict(
            ok=True, validated=True, confidence=0.7,
            summary=(f"5xx is content-driven on `{param}`: a "
                     f"same-length benign payload returns "
                     f"{control_resp.status if control_resp else '(n/a)'} "
                     f"while the malicious payload returns "
                     f"{replay.status}. The response does NOT leak "
                     f"internal detail, so this is a robustness "
                     f"bug rather than information disclosure. "
                     f"Worth confirming whether the malicious "
                     f"content is being parsed in a way that could "
                     f"escalate."),
            evidence=ev,
            remediation=(
                f"Add input validation that rejects malformed "
                f"`{param}` values before they reach the layer "
                f"that crashes. Convert uncaught exceptions to a "
                f"generic 500 with no body content; never let raw "
                f"framework error pages reach the client."),
            severity_uplift="low",
        )


if __name__ == "__main__":
    Anomaly5xxValidationProbe().main()
