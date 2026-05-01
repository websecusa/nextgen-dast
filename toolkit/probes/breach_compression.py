#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""BREACH-attack pre-condition validator.

Nikto (and similar scanners) flag any response carrying a
`Content-Encoding: gzip|deflate|br` header as "vulnerable to BREACH".
Compression is necessary for BREACH but not sufficient. A real BREACH
attack needs ALL of the following on the same response:

  1. HTTP-level compression  (Content-Encoding gzip / deflate / br)
  2. The response is served over TLS
     (BREACH targets the TLS layer; plain HTTP is irrelevant)
  3. Attacker-influenced reflected content in the body
     (so the attacker can probe a guess byte-by-byte)
  4. A secret-looking value in the same response
     (CSRF token, JWT, anti-CSRF cookie value, hidden hi-entropy field)

This probe checks each precondition in turn. The verdict reports which
preconditions were observed and which were missing, so a pentester can
either dismiss the finding (typical case for static asset URLs) or
escalate it for manual exploitation work.

Examples (CLI):
    python breach_compression.py --url 'https://target/'
    python breach_compression.py --url 'https://target/search?q=hello'
    python breach_compression.py --url 'https://target/' --reflect-param q
"""
from __future__ import annotations

import gzip
import re
import sys
import secrets
import zlib
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# Encodings that BREACH/CRIME-class side-channel attacks target. The
# `identity` and `chunked` values are NOT compression and are ignored.
COMPRESSION_ENCODINGS = {"gzip", "deflate", "br", "compress", "zstd"}

# Header to send so the server actually compresses. SafeClient does not
# add Accept-Encoding by default, so without this the server returns
# identity-encoded bytes and the BREACH precondition check would always
# fail — a false negative on the very thing this probe is meant to detect.
ACCEPT_ENCODING = "gzip, deflate, br"

# Patterns that look like a secret an attacker would want to extract via
# BREACH. Order matters only for the evidence label — every match is
# recorded. Patterns are intentionally a little loose: false positives
# here only INCREASE the validated severity; under-matching would let a
# real BREACH target slip through as "no secrets present".
SECRET_PATTERNS = [
    # CSRF tokens via meta tag (Rails / Laravel / Django style)
    (r'<meta[^>]+name=["\']csrf[-_]?token["\'][^>]+content=["\']([A-Za-z0-9+/_\-=]{16,})["\']',
     "csrf_token_meta"),
    # CSRF tokens via hidden input
    (r'<input[^>]+name=["\'][^"\']*(?:csrf|authenticity|xsrf|nonce)[^"\']*["\'][^>]+value=["\']([A-Za-z0-9+/_\-=]{12,})["\']',
     "csrf_token_hidden_input"),
    # Generic high-entropy hidden inputs (likely tokens)
    (r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([A-Za-z0-9+/_\-=]{32,})["\']',
     "hidden_high_entropy"),
    # JWT in the body
    (r'\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b',
     "jwt_in_body"),
    # Bearer-token style values reflected in JSON or HTML
    (r'"(?:access_token|api_key|session|sessionId)"\s*:\s*"([A-Za-z0-9+/_\-=\.]{20,})"',
     "json_token_field"),
]


def _add_query_param(url: str, name: str, value: str) -> str:
    """Append name=value to the URL's query string. Preserves any
    existing parameters (so reflection probes work on URLs that already
    carry user input)."""
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    q.append((name, value))
    return urlunparse(u._replace(query=urlencode(q, doseq=True)))


def _content_encoding(headers: dict) -> str:
    """Pull Content-Encoding out of a response in a header-name-case-
    insensitive way. Returns the first non-identity encoding token in
    lowercase, or '' when no compression is in use."""
    for k, v in (headers or {}).items():
        if k.lower() == "content-encoding":
            for token in str(v).split(","):
                token = token.strip().lower()
                if token and token != "identity":
                    return token
    return ""


def _decode_body(raw: bytes, encoding: str) -> str:
    """Decode a (possibly compressed) response body to text.

    The reflection scan and secret-pattern scan must run on the
    *uncompressed* HTML — pattern matches on compressed bytes are
    meaningless. Brotli isn't in the stdlib; if the response is br-encoded
    and the brotli module isn't installed we fall back to leaving the
    bytes as-is and let the caller record it as 'undecoded'."""
    if not raw:
        return ""
    try:
        if encoding == "gzip":
            raw = gzip.decompress(raw)
        elif encoding == "deflate":
            # Some servers send raw DEFLATE, others send zlib-wrapped
            # DEFLATE. Try the wrapped form first, fall back to raw.
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        elif encoding == "br":
            try:
                import brotli  # type: ignore
                raw = brotli.decompress(raw)
            except Exception:
                pass  # leave raw bytes; downstream will treat as undecoded
        elif encoding == "zstd":
            try:
                import zstandard  # type: ignore
                raw = zstandard.ZstdDecompressor().decompress(raw)
            except Exception:
                pass
    except Exception:
        # If decompression itself blows up, return the raw bytes as text
        # so we at least preserve evidence of the encoding header.
        pass
    return raw.decode("utf-8", "replace")


class BreachCompressionProbe(Probe):
    name = "breach_compression"
    summary = ("Validates a Nikto-style BREACH finding by checking all "
               "preconditions: TLS + compression + reflection + a "
               "secret-looking value in the same response.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument("--reflect-param", default="breach_probe",
                            help="Query-param name used to probe for "
                                 "reflected input (default 'breach_probe').")
        parser.add_argument("--require-tls", action="store_true",
                            help="If set, treat plain-HTTP targets as "
                                 "definitively NOT exploitable. Default "
                                 "behavior is to flag the missing TLS but "
                                 "still report compression observations.")

    def run(self, args, client: SafeClient) -> Verdict:
        url = args.url
        scheme = urlparse(url).scheme.lower()
        is_tls = scheme == "https"
        # Force the server to compress when it's willing to. Without an
        # explicit Accept-Encoding header SafeClient sends none, and many
        # servers fall back to identity — yielding a false-negative on
        # the compression precondition that this probe exists to test.
        accept_enc = {"Accept-Encoding": ACCEPT_ENCODING}

        # ----- Step 1: baseline fetch ------------------------------------
        baseline = client.request(args.method, url, headers=accept_enc)
        if baseline.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable")

        encoding = _content_encoding(baseline.headers)
        body = _decode_body(baseline.body, encoding)
        body_size = baseline.size

        preconditions = {
            "tls": is_tls,
            "compression": encoding in COMPRESSION_ENCODINGS,
            "reflection": False,
            "secret_present": False,
        }
        details: dict = {
            "scheme": scheme,
            "content_encoding": encoding or "(none)",
            "response_status": baseline.status,
            "response_size": body_size,
        }

        # If compression isn't even on this response, Nikto's flag is
        # already moot — no point burning more requests.
        if not preconditions["compression"]:
            return Verdict(
                validated=False, confidence=0.9,
                summary=("No HTTP-level compression observed on this "
                         "response — BREACH is not applicable. Nikto's "
                         "flag may have come from a different resource "
                         "on the same host."),
                evidence={"preconditions": preconditions, **details},
                remediation=(
                    "If a different endpoint on this host returns a "
                    "compressed response containing both reflected input "
                    "and a secret, run this probe against that URL."),
            )

        # ----- Step 2: reflection probe ---------------------------------
        marker = "brP_" + secrets.token_hex(6)
        probe_url = _add_query_param(url, args.reflect_param, marker)
        probed = client.request(args.method, probe_url, headers=accept_enc)
        probed_body = _decode_body(probed.body,
                                   _content_encoding(probed.headers))
        details["reflection_marker"] = marker
        details["reflection_probe_url"] = probe_url
        details["reflection_probe_status"] = probed.status
        if probed.status and probed.status != 0 and marker in probed_body:
            preconditions["reflection"] = True
            # Keep only a small slice — the body can be huge and this is
            # a probe, not an exfil tool.
            idx = probed_body.find(marker)
            details["reflection_excerpt"] = probed_body[
                max(0, idx - 60):idx + len(marker) + 60
            ]

        # ----- Step 3: secret-shaped content in the BASELINE response ---
        # We look at the baseline (not the probed URL) because a real
        # BREACH attack targets a response that the victim's browser
        # would naturally fetch — i.e., one that contains the victim's
        # own secret.
        secret_hits: list[dict] = []
        for rx, label in SECRET_PATTERNS:
            try:
                pat = re.compile(rx, re.IGNORECASE)
            except re.error:
                continue
            m = pat.search(body)
            if m:
                # Record the label and a redacted snippet of the match
                # context — never the full secret value.
                grp = m.group(1) if m.groups() else m.group(0)
                redacted = (grp[:4] + "..." + grp[-2:]) if len(grp) > 8 else "***"
                secret_hits.append({"type": label, "value_preview": redacted})
        if secret_hits:
            preconditions["secret_present"] = True
            details["secrets_seen"] = secret_hits

        # ----- Verdict synthesis -----------------------------------------
        all_present = all(preconditions.values())
        partial_count = sum(1 for v in preconditions.values() if v)

        if all_present:
            return Verdict(
                validated=True, confidence=0.85,
                summary=("All four BREACH preconditions observed: TLS, "
                         "HTTP compression, reflected input, and a "
                         "secret-shaped value in the same response. "
                         "This finding warrants manual exploitation work."),
                evidence={"preconditions": preconditions, **details},
                remediation=(
                    "Mitigate by one or more of: disable HTTP-level "
                    "compression for responses that contain secrets; "
                    "separate secrets from attacker-influenced content "
                    "(e.g., serve CSRF tokens via a header instead of "
                    "embedded HTML); add per-request length masking by "
                    "padding responses to a random length; rotate CSRF "
                    "tokens every request so a side-channel guess is "
                    "useless once observed."),
                severity_uplift="high",
            )

        # Pre-condition is present but exploitation pre-reqs are not all
        # met — this is the common case for the typical Nikto flag.
        if not preconditions["tls"] and args.require_tls:
            return Verdict(
                validated=False, confidence=0.95,
                summary=("Target is plain HTTP. BREACH targets the TLS "
                         "layer, so this finding does not apply."),
                evidence={"preconditions": preconditions, **details},
            )

        missing = [k for k, v in preconditions.items() if not v]
        return Verdict(
            validated=False, confidence=0.7,
            summary=(f"Compression is enabled, but {len(missing)} of 4 "
                     f"BREACH preconditions are missing ({', '.join(missing)}). "
                     f"The Nikto flag is a precondition observation, "
                     f"not a confirmed vulnerability."),
            evidence={"preconditions": preconditions,
                      "preconditions_met": partial_count,
                      **details},
            remediation=(
                "If this resource ever starts reflecting user input AND "
                "embedding a secret (e.g., a CSRF token) on the same "
                "page, the finding becomes exploitable. Until then it "
                "is a hardening recommendation, not an exploitable bug. "
                "If you want belt-and-suspenders, disable compression "
                "for endpoints that return secrets or pad responses to "
                "a random length."),
        )


if __name__ == "__main__":
    BreachCompressionProbe().main()
