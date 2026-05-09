# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
FlowIndex — read the per-scan mitmproxy capture (flows.jsonl + flows/*_response.txt)
written by app/proxy_addon.py and expose response evidence keyed by (method, URL).

Why this exists
---------------
Every scanner (nuclei, wapiti, nikto, ffuf, dalfox, sqlmap, testssl) runs
through the proxy addon, which writes one line per HTTP exchange into
flows.jsonl plus the raw request/response on disk under flows/. That data is
already on disk — it just was never plumbed into the LLM telemetry. Without
response bodies, the Enhanced-AI weakness pass has nothing to satisfy its
verbatim-quote rule and returns []. With response bodies attached to the
matching finding, the same prompt produces real candidates without any rule
relaxation.

Token economy
-------------
The index attaches to each finding only what enhanced_ai already chose to
quote: the four fields _render_response_samples / _format_one_finding read
(response_body_excerpt, response_status, response_content_type,
response_headers_excerpt). Each excerpt is capped at PER_FINDING_QUOTE_MAX
bytes (default 800) and sanitized for rotating secrets (CSRF tokens, session
cookies, long base64 chunks) before being shown to the LLM. Bodies are
loaded lazily — opening the response file only when a finding actually
matches a flow.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)


# Default per-finding quote cap. Mirrors PER_FINDING_QUOTE_MAX in
# enhanced_ai.py — kept duplicated so flow_index has no upward import.
_DEFAULT_BODY_MAX = 800

# Headers the LLM finds useful for fingerprinting / vuln inference. Kept
# small so we don't blow the per-finding budget on bookkeeping headers
# (Date, Connection, Content-Length, etc.). Lower-cased for lookup.
_INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "via",
    "location",
    "www-authenticate",
    "set-cookie",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
)


# ---- sanitization -----------------------------------------------------------
# Patterns that scrub rotating secrets out of bodies / headers BEFORE the
# excerpt is sent to the LLM. The point isn't to defeat a determined leak
# (the body went through the LLM provider regardless); it's to keep
# session-bound tokens out of the assistant's training data and out of any
# stored debug logs.

# anti-CSRF / form tokens — long hex / base64 next to a token-shaped name.
_CSRF_TOKEN_RE = re.compile(
    r"(csrf[_-]?token|authenticity[_-]?token|xsrf[_-]?token|"
    r"__requestverificationtoken)"
    r"\s*[=:]\s*[\"']?([A-Za-z0-9+/=_\-]{20,})[\"']?",
    re.IGNORECASE,
)

# session cookie values quoted in HTML (rare but happens on error pages).
_SESSION_COOKIE_RE = re.compile(
    r"(session(?:id)?|jsessionid|phpsessid|asp\.net[_-]sessionid|"
    r"connect\.sid|laravel_session|tprm_session)"
    r"\s*[=:]\s*[\"']?([A-Za-z0-9+/=._%\-]{16,})[\"']?",
    re.IGNORECASE,
)

# bearer tokens / API keys quoted in body
_BEARER_RE = re.compile(
    r"(bearer\s+|apikey[=:\s]+|api[_-]?key[=:\s]+|access[_-]?token[=:\s]+)"
    r"([A-Za-z0-9._\-]{16,})",
    re.IGNORECASE,
)

# base64-ish runs longer than 200 chars (embedded images, blobs). Replaced
# with a marker so the LLM sees there *was* a blob without paying for it.
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")


def _sanitize(text: str) -> str:
    """Strip rotating secrets from a body or header excerpt.

    Conservative — only known token-name-prefixed patterns are touched, so
    we don't accidentally redact a legitimate substring the LLM needs to
    quote. The LONG_BASE64 sweep at the end catches embedded blobs that
    would otherwise dominate the per-finding quote budget."""
    if not text:
        return text
    text = _CSRF_TOKEN_RE.sub(r"\1=<REDACTED>", text)
    text = _SESSION_COOKIE_RE.sub(r"\1=<REDACTED>", text)
    text = _BEARER_RE.sub(r"\1<REDACTED>", text)
    text = _LONG_BASE64_RE.sub("<base64-blob>", text)
    return text


# ---- URL normalization ------------------------------------------------------
# Findings carry URLs like "https://host/path?q=v" while flows.jsonl records
# "https://host:443/path?q=v". Normalize both sides to a stable lookup key:
# (METHOD, scheme://host[:non-default-port]/path).

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_url(url: str) -> str:
    """Drop default ports + querystring + fragment so finding URLs match
    flow URLs even when one side carries an explicit :443 / :80 or a
    cache-busting query string."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    netloc = parts.netloc
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        try:
            if port and int(port) == _DEFAULT_PORTS.get(parts.scheme.lower()):
                netloc = host
        except ValueError:
            pass
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/",
                        "", ""))


def _normalize_method(method: Optional[str]) -> str:
    return (method or "GET").strip().upper() or "GET"


# ---- response-file parsing --------------------------------------------------

def _split_headers_body(text: str) -> tuple[str, str]:
    """Split a dump_response()-formatted file into (headers_block, body).

    proxy_addon.dump_response writes status_line + CRLF-joined headers + a
    blank line + body. Tolerate LF-only too in case a future change relaxes
    the line ending."""
    for sep in ("\r\n\r\n", "\n\n"):
        idx = text.find(sep)
        if idx != -1:
            return text[:idx], text[idx + len(sep):]
    return text, ""


def _interesting_headers_excerpt(headers_block: str) -> str:
    """Pull out only the headers in _INTERESTING_HEADERS, joined on
    newlines. Order preserved from the response. Short by design — the
    LLM uses these to disambiguate tech stack / auth posture without
    paying for the full header section."""
    if not headers_block:
        return ""
    lines = headers_block.splitlines()
    # Drop the HTTP/x.y status line if present (first line, no colon).
    out: list[str] = []
    for line in lines:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() in _INTERESTING_HEADERS:
            out.append(f"{name.strip()}: {value.strip()}")
    return "\n".join(out)


# ---- public API -------------------------------------------------------------

class FlowRecord:
    """A single matched flow, lazy about loading the response body off
    disk (the body file may be 100 KB on the wire and we only ever quote
    the first ~800 bytes)."""

    __slots__ = ("status_code", "content_type", "response_size",
                 "_response_path")

    def __init__(self, status_code: Optional[int], content_type: str,
                 response_size: int, response_path: Optional[Path]):
        self.status_code = status_code
        self.content_type = content_type
        self.response_size = response_size
        self._response_path = response_path

    def body_and_headers(self, max_body_bytes: int = _DEFAULT_BODY_MAX
                         ) -> tuple[str, str]:
        """Read the response file, split off headers, sanitize and trim
        the body. Returns ("", "") if the file is missing or unreadable —
        the caller should treat that as "no evidence captured" and skip
        attaching anything for this finding."""
        if not self._response_path or not self._response_path.exists():
            return "", ""
        try:
            text = self._response_path.read_text(encoding="utf-8",
                                                   errors="replace")
        except OSError as e:
            logger.debug("flow_index: read failed for %s: %r",
                         self._response_path, e)
            return "", ""
        headers_block, body = _split_headers_body(text)
        body = _sanitize(body).strip()
        if len(body) > max_body_bytes:
            body = body[:max_body_bytes] + "..."
        return body, _interesting_headers_excerpt(headers_block)


class FlowIndex:
    """Read flows.jsonl from one or more scan dirs and expose a lookup
    keyed by (METHOD, normalized URL).

    Designed to be built once per assessment (in build_telemetry) and
    queried per-finding."""

    def __init__(self, scan_dirs: Iterable[Path]):
        self._by_key: dict[tuple[str, str], FlowRecord] = {}
        # Path-only fallback: some scanners record findings with the bare
        # host as evidence_url, or a relative path that didn't get resolved
        # on insert. Path-only matching is a last resort because two flows
        # with the same path on different hosts will collide.
        self._by_path: dict[tuple[str, str], FlowRecord] = {}
        self.scans_loaded = 0
        self.flows_loaded = 0
        for sdir in scan_dirs:
            self._load_scan(sdir)

    def _load_scan(self, scan_dir: Path) -> None:
        log_path = scan_dir / "flows.jsonl"
        if not log_path.exists():
            return
        flows_dir = scan_dir / "flows"
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._index_record(rec, flows_dir)
        except OSError as e:
            logger.debug("flow_index: open failed for %s: %r", log_path, e)
            return
        self.scans_loaded += 1

    def _index_record(self, rec: dict, flows_dir: Path) -> None:
        method = _normalize_method(rec.get("method"))
        url = rec.get("url") or ""
        if not url:
            return
        norm = _normalize_url(url)
        if not norm:
            return
        resp_file = rec.get("response_file") or ""
        path = flows_dir / resp_file if resp_file else None
        flow = FlowRecord(
            status_code=rec.get("status_code"),
            content_type=(rec.get("response_content_type") or "").strip(),
            response_size=int(rec.get("response_size") or 0),
            response_path=path,
        )
        key = (method, norm)
        # First flow wins. proxy_addon already deduplicates by
        # host:status:size:method, so collisions here are rare and
        # represent the same probe-shape — keeping the first preserves
        # the earliest captured body.
        if key not in self._by_key:
            self._by_key[key] = flow
        path_key = (method, _path_only(norm))
        if path_key not in self._by_path:
            self._by_path[path_key] = flow
        self.flows_loaded += 1

    def lookup(self, method: Optional[str], url: Optional[str]
               ) -> Optional[FlowRecord]:
        """Find the flow for this finding's URL+method, falling back to a
        path-only match when the (host, port) pair didn't line up."""
        if not url:
            return None
        m = _normalize_method(method)
        norm = _normalize_url(url)
        flow = self._by_key.get((m, norm))
        if flow is not None:
            return flow
        return self._by_path.get((m, _path_only(norm)))


def _path_only(url: str) -> str:
    """Strip scheme+host so the path-only fallback can match a finding
    whose evidence_url got recorded as a path or a different host."""
    try:
        parts = urlsplit(url)
        return parts.path or "/"
    except Exception:
        return url


def attach_response_evidence(parsed_findings: list[dict],
                              index: FlowIndex,
                              max_body_bytes: int = _DEFAULT_BODY_MAX
                              ) -> int:
    """For each finding in parsed_findings, look up a matching captured
    flow and inject response_body_excerpt / response_status /
    response_content_type / response_headers_excerpt into the finding's
    `_raw` dict (the dict-view of raw_data already materialized by
    enhanced_ai.build_telemetry).

    Mutates `parsed_findings` in place. Returns the number of findings
    that received any response evidence so callers can log + telemetrize.

    Existing keys in `_raw` are NOT overwritten — if the scanner already
    captured a body excerpt (some nuclei templates do), keep the
    scanner's version."""
    attached = 0
    for f in parsed_findings:
        rd = f.get("_raw")
        if not isinstance(rd, dict):
            continue
        # If a previous run / scanner already populated the canonical key,
        # leave it alone. Avoids stomping on bespoke evidence.
        if rd.get("response_body_excerpt"):
            continue
        flow = index.lookup(f.get("evidence_method"), f.get("evidence_url"))
        if flow is None:
            continue
        body, hdrs = flow.body_and_headers(max_body_bytes=max_body_bytes)
        if not body and not hdrs and flow.status_code is None:
            # Nothing usable to attach.
            continue
        if body:
            rd["response_body_excerpt"] = body
        if hdrs:
            rd["response_headers_excerpt"] = hdrs
        if flow.status_code is not None:
            rd["response_status"] = flow.status_code
        if flow.content_type:
            rd["response_content_type"] = flow.content_type
        attached += 1
    return attached
