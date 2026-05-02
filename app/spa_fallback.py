# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Per-host SPA-fallback (and dead-host) fingerprinter.

Many modern front-ends (React/Vue/Angular SPAs behind a CDN, S3+CloudFront,
Cloudflare Pages) answer every unmatched path with HTTP 200 and the same
`index.html` body. That defeats the simplest "does this URL exist?" check
that a lot of scanners (and the Enhanced-AI-Testing weakness-discovery
LLM) rely on: a 200 status code on `/JAMonAdmin.jsp` or `/wp-admin` does
not prove that JAMon or WordPress is actually deployed — the front-end
just returned its SPA shell.

The same pattern occurs at non-200 statuses too. A misconfigured upstream
behind a managed gateway (MuleSoft Cloudhub, AWS API Gateway, Azure APIM,
CloudFront with a dead origin) will return the gateway's templated error
page — typically HTTP 502 with a fixed body — for *every* path on the
vhost, so a Nikto signature firing because that body happens to contain
a substring it recognizes is a pure false positive. This module catches
both forms by requiring all junk-path probes to agree on (status, body)
rather than being hard-pinned to status==200.

This module computes, per host, a body signature for that fallback. With
the signature in hand, a caller can ask "is this specific path just the
SPA fallback?" and discard inferences that depend on path existence
without body inspection.

Usage shape inside enhanced_ai.py:

    from spa_fallback import (
        Fingerprinter,
    )

    fp = Fingerprinter()
    fp.probe_host("https://damageportal.hercrentals.com")
    fp.is_fallback("https://damageportal.hercrentals.com/JAMonAdmin.jsp")
    fp.affected_hosts()  # list of hosts whose 200s are unreliable

The fingerprinter is intentionally side-effect-free w.r.t. the database
and never raises out of its public API: probing failures yield "host has
no detected SPA fallback" rather than a crash, because the consumer is
running inside the orchestrator and a network blip on a single host must
not abort the whole Enhanced-AI pass.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)


# Time budget per HTTP call. Probing happens once per unique host at
# the start of an Enhanced-AI run; we want it to be quick and graceful
# rather than block on a slow target.
_REQUEST_TIMEOUT_SECONDS = 8.0

# Maximum body bytes we read for hashing. Hashing the entire payload is
# overkill — the SPA shell is usually under 50 KB and the first 64 KB
# is more than enough to distinguish it from any real content.
_MAX_BODY_BYTES = 65536

# Maximum hosts we will fingerprint per assessment. Bounds the worst-
# case time/cost when a scan touched a hundred different subdomains.
_MAX_HOSTS_PER_RUN = 30

# Number of distinct junk paths we sample to declare a fallback. Two
# samples is the sweet spot: one sample can collide with a static asset
# that happens to 200-OK; three is wasteful when the first two already
# agree. We require both samples to produce the same body and to be
# byte-identical, OR to differ only by a small variance (CDN injects
# request IDs into HTML comments — see _looks_like_fallback).
_FALLBACK_SAMPLES = 2

# User-Agent presented during fingerprinting. Looks like a generic
# browser so a WAF doesn't return a different page for "scanner-like"
# clients (which would itself look like a fallback and pollute the
# signature). Important: deliberately not "nextgen-dast" here.
_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/127.0.0.0 Safari/537.36")


def _host_key(url_or_host: str) -> str:
    """Normalize a URL or bare host into a 'scheme://host' key. Used
    to dedupe the cache and to look up cached fingerprints from a
    full URL the caller hands us.

    Defaults to https when no scheme is present — every target the
    DAST tool runs against is internet-facing and the http variant
    almost always redirects to https anyway."""
    if "://" in url_or_host:
        parts = urlsplit(url_or_host)
        scheme = parts.scheme or "https"
        netloc = parts.netloc
    else:
        scheme = "https"
        netloc = url_or_host
    return f"{scheme}://{netloc}".rstrip("/")


def _random_probe_path() -> str:
    """A path guaranteed not to exist on any real application. The
    leading and trailing tokens make the probe self-identifying in a
    target's access log, which helps the analyst correlate a
    fingerprint result with traffic later if they go looking."""
    token = secrets.token_hex(8)
    return f"/__nextgen_dast_spa_fallback_probe_{token}.invalid"


def _http_get(url: str) -> tuple[int, bytes]:
    """Plain GET that tolerates self-signed certificates (target boxes
    are often staging with mis-issued certs) and never follows
    redirects — a 30x to /login is interesting on its own and means
    the host is NOT serving a single-shell SPA fallback.

    Returns (status, body_bytes). status=0 means 'transport failed'.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        # Suppress automatic redirect handling. urllib's default behavior
        # is to chase 30x; we explicitly want to see the unredirected
        # status because a redirect implies path-aware routing, which
        # is the opposite of an SPA fallback.
        def redirect_request(self, *_a, **_kw):
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )
    req = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT,
                      "Accept": "text/html,*/*;q=0.8"})
    try:
        with opener.open(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(_MAX_BODY_BYTES)
    except urllib.error.HTTPError as e:
        # 4xx/5xx is a real status — treat as legitimate response.
        try:
            body = e.read(_MAX_BODY_BYTES) or b""
        except Exception:
            body = b""
        return e.code, body
    except Exception as e:
        logger.debug("spa_fallback: GET %s failed: %r", url, e)
        return 0, b""


def _hash(body: bytes) -> str:
    """Stable digest for body comparison. SHA-256 is overkill for a
    collision domain of ~30 hosts, but it's the same hash already
    used elsewhere in the codebase so we keep one primitive."""
    return hashlib.sha256(body).hexdigest()


def _looks_like_fallback(samples: list[tuple[int, bytes]]) -> bool:
    """Decide whether two junk-path responses constitute a path-agnostic
    echo (SPA fallback OR dead-upstream gateway error). The rule is
    byte-identical bodies served at the SAME status code. We also
    accept a near-match for CDNs that inject a request-ID comment
    into the HTML — same status, same length, identical first and
    last 1024 bytes after stripping common request-ID tokens.

    Status agreement matters: two 404s with identical bodies are also
    an echo (a static "not found" page returned for every path), which
    is just as misleading for path-existence reasoning as the 200-SPA
    case. The only forbidden outcome is "transport failed" (status 0),
    where we have no signal to fingerprint against."""
    if len(samples) < 2:
        return False
    statuses = [s for s, _ in samples]
    # Transport failures carry no signal — a host we couldn't reach
    # twice tells us nothing about its path-handling behavior.
    if any(st == 0 for st in statuses):
        return False
    # All probes must agree on the status code. A mix (200 + 404) means
    # the host is path-aware: one path was real, the other was not.
    if len(set(statuses)) != 1:
        return False
    bodies = [b for _, b in samples]
    # Empty body is suspicious (no content to compare); treat as
    # 'not a fallback' to err on the side of keeping data.
    if any(len(b) == 0 for b in bodies):
        return False
    # Strict equality short-circuit.
    if all(b == bodies[0] for b in bodies):
        return True
    # Lengths must match within a small tolerance for the request-ID
    # injection case (Cloudflare/CloudFront occasionally embed a
    # cf-ray-style token in HTML comments).
    lens = [len(b) for b in bodies]
    if max(lens) - min(lens) > 64:
        return False
    # Compare head and tail; the middle is where the variable token
    # would be.
    head, tail = 1024, 1024
    for b in bodies[1:]:
        if b[:head] != bodies[0][:head] or b[-tail:] != bodies[0][-tail:]:
            return False
    return True


class Fingerprinter:
    """Per-run cache of SPA-fallback signatures. One instance per
    Enhanced-AI run. Use probe_host() to populate, then is_fallback()
    or affected_hosts() to query.

    Thread-safety: not designed for it. Enhanced-AI runs serially
    inside a single orchestrator thread."""

    def __init__(self) -> None:
        # host_key -> {"signatures": [hash, ...], "size": int} or None
        # None means "we tried and there's no fallback here".
        self._cache: dict[str, dict | None] = {}
        # host_key -> set of paths we've already tested (avoid retests
        # when a host has many findings on similar paths).
        self._path_results: dict[str, dict[str, bool]] = {}

    # -- public API -------------------------------------------------------

    def probe_host(self, url_or_host: str) -> dict | None:
        """Send the junk-path probes for a host and cache the result.
        Returns the signature dict on success, None otherwise.

        Idempotent: subsequent calls return the cached result without
        re-probing."""
        key = _host_key(url_or_host)
        if key in self._cache:
            return self._cache[key]
        if len(self._cache) >= _MAX_HOSTS_PER_RUN:
            logger.info("spa_fallback: host cap reached (%d), skipping %s",
                        _MAX_HOSTS_PER_RUN, key)
            self._cache[key] = None
            return None

        samples: list[tuple[int, bytes]] = []
        for _ in range(_FALLBACK_SAMPLES):
            url = key + _random_probe_path()
            samples.append(_http_get(url))

        if _looks_like_fallback(samples):
            sigs = sorted({_hash(b) for _, b in samples})
            # status is guaranteed identical across samples by
            # _looks_like_fallback's set-of-1 check, so any sample's
            # status is the canonical one. Stored on the sig so
            # is_fallback() can match status alongside body hash —
            # otherwise a real 200 page that happened to share a body
            # length with a 502 echo would be miscategorized.
            sig = {
                "signatures": sigs,
                "size": len(samples[0][1]),
                "host": key,
                "status": samples[0][0],
            }
            self._cache[key] = sig
            logger.info(
                "spa_fallback: %s returns identical body for arbitrary "
                "paths (status=%d, size=%d, sigs=%s)",
                key, sig["status"], sig["size"], sigs)
            return sig

        self._cache[key] = None
        return None

    def is_fallback(self, url: str) -> bool:
        """Return True iff the body served at `url` is byte-identical
        to the cached SPA-fallback signature for that host. Performs
        one HTTP GET if we have not seen this exact URL before, then
        caches the result.

        Returns False if:
          - the host hasn't been probed (or had no detected fallback);
          - the request fails for transport reasons;
          - the body differs from the fallback signature.

        False does not mean "the path is real" — it means "we cannot
        confirm it's a fallback echo".
        """
        key = _host_key(url)
        sig = self._cache.get(key)
        if not sig:
            return False
        per_host = self._path_results.setdefault(key, {})
        if url in per_host:
            return per_host[url]
        status, body = _http_get(url)
        # Match BOTH status and body hash. The SPA-200 case and the
        # gateway-502 case use the same comparator now; sig["status"]
        # is whatever status the host's path-agnostic echo happens to
        # use. .get() because pre-existing in-memory sigs from older
        # boots may not carry the status field — treat absent as 200
        # so legacy caches keep behaving as before.
        expected_status = sig.get("status", 200)
        result = (status == expected_status
                  and _hash(body) in set(sig["signatures"]))
        per_host[url] = result
        if result:
            logger.info("spa_fallback: %s matches host echo signature "
                        "(status=%d)", url, status)
        return result

    def affected_hosts(self) -> list[str]:
        """Return every host_key for which we have a cached SPA-fallback
        signature. Consumers feed this into the LLM prompt as a warning
        block so the model knows path-existence claims on those hosts
        carry no signal."""
        return [k for k, v in self._cache.items() if v]

    def affected_count(self) -> int:
        return sum(1 for v in self._cache.values() if v)

    def host_signature(self, url_or_host: str) -> dict | None:
        return self._cache.get(_host_key(url_or_host))


def hosts_in_findings(findings: list[dict]) -> list[str]:
    """Helper for the orchestrator: pull the unique host_key set out of
    a findings list, in the order each host first appeared. Caller is
    expected to feed the result one-at-a-time into Fingerprinter.
    probe_host(). Order is preserved so the per-run host cap deletes
    later hosts rather than earlier ones — earlier findings tend to
    carry the highest-severity scanner output and are the ones the
    LLM weighs most."""
    seen: dict[str, None] = {}
    for f in findings or []:
        u = f.get("evidence_url") if isinstance(f, dict) else None
        if not u or not isinstance(u, str):
            continue
        k = _host_key(u)
        if k not in seen:
            seen[k] = None
    return list(seen.keys())
