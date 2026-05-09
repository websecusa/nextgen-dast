# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authenticated re-walk of cluster URLs the scanners did not probe.

Why this exists
---------------
When credentials are configured, every scanner already runs through the
mitmproxy addon, so flows.jsonl carries an authenticated response for every
URL each scanner actually hit. flow_index.FlowIndex picks those up and the
LLM weakness pass quotes them.

The gap this module fills: high-value paths the scanners NEVER probed --
admin consoles, API surfaces, and settings/user-management routes adjacent
to discovered cluster patterns. ffuf with the right wordlist is the long-
term answer; this module is the short-term lift, capped tightly so the
extra request volume and prompt tokens stay bounded.

Token / request budget
----------------------
- Hard cap of MAX_RECAPTURE URLs per assessment (default 20). The cap is
  enforced AFTER URL scoring so we recapture the highest-value targets
  first; lower-value paths are dropped.
- Single GET per URL (no probing, no follow-redirects). Recorded into
  the same response_body_excerpt / response_status / response_headers_
  excerpt fields the LLM prompt already renders, so no new placeholder
  block and no new render helper is needed.
- Only fires when (a) credentials are configured AND (b) at least one
  high-value cluster URL is missing from FlowIndex. Skipping the pass
  outright is the most common case and costs nothing.
"""
from __future__ import annotations

import http.cookiejar
import logging
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Optional

import flow_index

logger = logging.getLogger(__name__)


# Hard ceiling on URLs we re-walk per assessment. Each URL costs one HTTP
# request + ~1-2 KB of input tokens to the LLM (status + content-type +
# headers excerpt + body excerpt, capped at PER_FINDING_QUOTE_MAX). With
# the default of 20, the worst-case prompt impact is ~30 KB extra input
# tokens — well under one cache-block at most providers.
MAX_RECAPTURE = 20

# Per-request timeout (seconds). Recapture is best-effort — a slow target
# should not hold up the LLM pass.
REQUEST_TIMEOUT = 8.0

# User-Agent for recapture GETs. Distinct from the scanner UA so the
# captures show up clearly in the target's access logs as recapture
# traffic, not scanner traffic.
RECAPTURE_UA = ("nextgen-dast/2.1.1 (auth-recapture; "
                "https://hackrange.com)")

# Regex matching path tokens that signal a high-value re-walk target.
# Anchored at word boundaries so /admin and /api/admin match but
# /administrator-tips and /restraining do not (the words "admin",
# "user", "config" appear inside benign paths surprisingly often).
_HIGH_VALUE_PATTERNS = (
    re.compile(r"(^|/)admin(/|$)", re.I),
    re.compile(r"(^|/)administrator(/|$)", re.I),
    re.compile(r"(^|/)api(/|$)", re.I),
    re.compile(r"(^|/)users?(/|$)", re.I),
    re.compile(r"(^|/)accounts?(/|$)", re.I),
    re.compile(r"(^|/)settings?(/|$)", re.I),
    re.compile(r"(^|/)config(uration)?(/|$)", re.I),
    re.compile(r"(^|/)dashboard(/|$)", re.I),
    re.compile(r"(^|/)console(/|$)", re.I),
    re.compile(r"(^|/)manage(ment)?(/|$)", re.I),
    re.compile(r"(^|/)assessment(s)?(/|$)", re.I),
    re.compile(r"(^|/)grc[-_]?", re.I),
    re.compile(r"(^|/)tenant(s)?(/|$)", re.I),
    re.compile(r"(^|/)organization(s)?(/|$)", re.I),
)


def _path_score(url: str) -> int:
    """Heuristic priority for re-walk ordering. Higher = more important.

    The scoring is intentionally crude — it just decides which targets
    win when MAX_RECAPTURE is binding. Each high-value pattern adds 1;
    paths matching multiple categories (e.g. /api/admin) win over
    single-category paths. Returns 0 for paths matching no pattern,
    which the caller should treat as 'do not recapture'."""
    score = 0
    try:
        path = urllib.parse.urlsplit(url).path or ""
    except Exception:
        return 0
    for pat in _HIGH_VALUE_PATTERNS:
        if pat.search(path):
            score += 1
    return score


def _candidate_urls(parsed_findings: list[dict],
                     index: flow_index.FlowIndex) -> list[str]:
    """Pick high-value cluster URLs that are NOT already in FlowIndex.

    Walks the parsed findings (already URL-clustered by the time this
    runs in build_telemetry), keeps unique URLs, scores each, and
    returns the top MAX_RECAPTURE by score. URLs that scored 0 (no
    high-value token in the path) are excluded entirely — recapturing
    /app/js/core.min.js gains nothing.

    Excludes URLs the FlowIndex already has so we never recapture a
    response that flow_index.attach_response_evidence would have
    surfaced for free."""
    seen: set[str] = set()
    candidates: list[tuple[int, str]] = []
    for f in parsed_findings:
        url = (f.get("evidence_url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        # Skip non-HTTP shapes (TCP port findings render as host:port).
        if not (url.startswith("http://") or url.startswith("https://")):
            continue
        # Already captured by some scanner — re-walking would duplicate
        # the existing flow.
        if index.lookup(f.get("evidence_method"), url) is not None:
            continue
        score = _path_score(url)
        if score == 0:
            continue
        candidates.append((score, url))
    candidates.sort(key=lambda kv: -kv[0])
    return [url for _, url in candidates[:MAX_RECAPTURE]]


def _get_with_session(url: str, cookie_header: str,
                       timeout: float = REQUEST_TIMEOUT
                       ) -> Optional[tuple[int, str, str, str]]:
    """GET `url` with the supplied Cookie header, returning
    (status_code, content_type, body, headers_block) or None on error.

    No redirect follow — we want the immediate response shape so the LLM
    can reason about gates (302 to login, 401, 403, etc.). TLS
    verification is disabled to mirror scanner behaviour (most internal
    targets ship self-signed certs).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handler = urllib.request.HTTPSHandler(context=ctx)
    # No-redirect handler so we observe the actual gate response.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):  # noqa: ARG002
            return None
    opener = urllib.request.build_opener(handler, _NoRedirect())

    headers = {"User-Agent": RECAPTURE_UA, "Accept": "*/*"}
    if cookie_header:
        headers["Cookie"] = cookie_header
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            ctype = resp.headers.get("content-type", "")
            body_bytes = resp.read(64 * 1024)  # 64 KB ceiling, then cap below
            body = body_bytes.decode("utf-8", "replace")
            headers_block = "\r\n".join(f"{k}: {v}" for k, v
                                          in resp.headers.items())
    except urllib.error.HTTPError as e:
        # 4xx / 5xx still carry an interpretable body — capture it.
        status = e.code
        ctype = e.headers.get("content-type", "") if e.headers else ""
        try:
            body_bytes = e.read(64 * 1024)
            body = body_bytes.decode("utf-8", "replace")
        except Exception:
            body = ""
        headers_block = ("\r\n".join(f"{k}: {v}" for k, v
                                       in e.headers.items())
                          if e.headers else "")
    except (urllib.error.URLError, socket.timeout, ConnectionError,
             ssl.SSLError) as e:
        logger.debug("auth_recapture: GET %s failed: %r", url, e)
        return None
    except Exception as e:
        logger.debug("auth_recapture: GET %s unexpected error: %r", url, e)
        return None
    return status, ctype, body, headers_block


def attach_recaptured_evidence(parsed_findings: list[dict],
                                 index: flow_index.FlowIndex,
                                 cookie_header: str,
                                 max_body_bytes: int) -> int:
    """Pick high-value cluster URLs missing from FlowIndex, GET each
    with the session cookie, sanitize, and inject the response evidence
    into every parsed finding whose URL matches a recapture target.

    Mutates `parsed_findings` in place. Returns the number of findings
    that received recaptured evidence so callers can log it.

    Token economy: capped at MAX_RECAPTURE URLs by score, single GET
    per URL, body capped at max_body_bytes. The injected fields are
    the same canonical keys flow_index uses, so the prompt-rendering
    side stays unchanged."""
    if not cookie_header:
        return 0
    targets = _candidate_urls(parsed_findings, index)
    if not targets:
        return 0
    logger.info("auth_recapture: re-walking %d high-value cluster URL(s) "
                "missing from scanner capture", len(targets))

    by_url: dict[str, dict] = {}
    for url in targets:
        result = _get_with_session(url, cookie_header)
        if result is None:
            continue
        status, ctype, body, headers_block = result
        body = flow_index._sanitize(body).strip()
        if len(body) > max_body_bytes:
            body = body[:max_body_bytes] + "..."
        headers_excerpt = flow_index._interesting_headers_excerpt(
            headers_block)
        by_url[url] = {
            "response_status": status,
            "response_content_type": (ctype or "").strip(),
            "response_body_excerpt": body,
            "response_headers_excerpt": headers_excerpt,
        }

    if not by_url:
        return 0

    attached = 0
    for f in parsed_findings:
        url = (f.get("evidence_url") or "").strip()
        if not url or url not in by_url:
            continue
        rd = f.get("_raw")
        if not isinstance(rd, dict):
            continue
        # Don't stomp on evidence the scanner-side flow already
        # provided — flow_index ran first and is authoritative.
        if rd.get("response_body_excerpt"):
            continue
        for k, v in by_url[url].items():
            if v not in ("", None):
                rd[k] = v
        attached += 1
    return attached


def resolve_session_cookie(login_url: Optional[str],
                            username: Optional[str],
                            password: Optional[str]) -> str:
    """One-shot session-cookie resolver shared with challenge_runner.
    Returns the Cookie header value, or empty string if any input is
    missing or the login fails. Errors are swallowed (logged at DEBUG)
    because recapture is best-effort and must not break telemetry
    construction."""
    if not (login_url and username and password):
        return ""
    try:
        import auth as auth_mod
        result = auth_mod.form_login_cookie(login_url, username, password)
    except Exception as e:
        logger.debug("auth_recapture: login crashed: %r", e)
        return ""
    if not result.get("ok"):
        logger.debug("auth_recapture: login failed: %s",
                       result.get("error"))
        return ""
    return result.get("cookie") or ""
