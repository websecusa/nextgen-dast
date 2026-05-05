#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: session-token RNG quality / entropy analysis.

A session id only protects what it gates if guessing it is
infeasible. Tokens minted by a weak RNG (Math.random, an LCG seeded
with a time stamp, an incrementing counter, or a hash of a small
input space) collapse to a small effective key space and can be
walked. Symptoms an off-line analyzer can see without ever guessing
the secret are: very low Shannon entropy per character, repeating
substrings across independently-issued tokens, or the same character
class dominating the token (e.g. all hex with low byte diversity).

This probe issues 50 independent unauthenticated GETs to `/`, picks
a session-shaped Set-Cookie name, and harvests one fresh value from
each response. We then compute Shannon entropy across the
concatenated tokens, look for repeating prefixes / suffixes that
suggest a counter or timestamp, and check character-class diversity.
We refuse to fire a verdict at all if we couldn't sample at least 30
tokens — too few samples make any statistical statement noise.

Detection signal:
  At least 30 fresh tokens collected AND Shannon entropy
  < 3.5 bits/char AND a structural giveaway present (repeating
  prefix across >= 60% of samples OR very low character-class
  diversity).
"""
from __future__ import annotations

import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# How many independent unauthenticated GETs we issue to harvest
# tokens. Capped here AND in the manifest budget.
DEFAULT_SAMPLES = 50
MIN_SAMPLES_FOR_VERDICT = 30
ENTROPY_THRESHOLD_BITS_PER_CHAR = 3.5

# Cookie name hints — same shape as auth_session_fixation_no_rotation.
# Case-insensitive substring match.
_SESSION_COOKIE_HINTS = ("session", "sessid", "sid",
                         "phpsessid", "connect.sid",
                         "asp.net_sessionid", "jsessionid",
                         "_session_id")


def _looks_like_session_cookie(name: str) -> bool:
    nl = (name or "").lower()
    return any(h in nl for h in _SESSION_COOKIE_HINTS)


def _parse_set_cookies(headers: dict) -> dict:
    """Return {name: value} for every Set-Cookie line."""
    out: dict = {}
    for k, v in (headers or {}).items():
        if k.lower() != "set-cookie":
            continue
        for piece in re.split(r"\n", str(v)):
            piece = piece.strip()
            if not piece:
                continue
            kv = piece.split(";", 1)[0]
            if "=" in kv:
                name, val = kv.split("=", 1)
                out[name.strip()] = val.strip()
    return out


def _shannon_entropy(s: str) -> float:
    """Bits per character. 0 for empty input. log2(N) is the ceiling
    for an N-character alphabet drawn uniformly."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def _mask(val: str) -> str:
    """First 6 + last 4 with asterisks in the middle. Matches the
    masking convention used by angular_secrets_in_bundle."""
    if not val:
        return ""
    if len(val) <= 12:
        return val[:2] + "*" * max(0, len(val) - 4) + val[-2:]
    return val[:6] + "*" * (len(val) - 10) + val[-4:]


def _common_prefix_count(samples: list[str], length: int) -> tuple[str, int]:
    """Return the longest fixed-length prefix shared by the most
    samples, and the count. Used to detect counter / timestamp
    leakage at the head of each token."""
    if not samples:
        return "", 0
    counts: Counter = Counter()
    for s in samples:
        if len(s) >= length:
            counts[s[:length]] += 1
    if not counts:
        return "", 0
    pref, n = counts.most_common(1)[0]
    return pref, n


class AuthSessionTokenEntropyProbe(Probe):
    name = "auth_session_token_entropy"
    summary = ("Detects session tokens minted with a weak RNG by "
               "measuring Shannon entropy and repeating-prefix structure "
               "across many fresh tokens.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--samples", type=int, default=DEFAULT_SAMPLES,
            help=f"Number of fresh tokens to harvest (default "
                 f"{DEFAULT_SAMPLES}, hard-capped by request budget).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        n_target = max(MIN_SAMPLES_FOR_VERDICT, int(args.samples))

        # Each independent GET / produces (we hope) a fresh
        # Set-Cookie. We do NOT replay the cookie we just received —
        # we need the server to mint a brand-new id every time.
        tokens: list[str] = []
        cookie_name: str | None = None
        for _ in range(n_target):
            r = client.request("GET", urljoin(origin, "/"),
                               follow_redirects=False)
            if r.status == 0:
                # Network error; bail rather than let bad data taint
                # the entropy calc.
                break
            cookies = _parse_set_cookies(r.headers or {})
            if not cookie_name:
                # Lock onto the first session-shaped cookie name we
                # see; subsequent requests must produce the same name
                # for the sample to be comparable.
                cookie_name = next((n for n in cookies
                                    if _looks_like_session_cookie(n)), None)
            if cookie_name and cookie_name in cookies:
                val = cookies[cookie_name]
                if val and val not in tokens:
                    # Distinct values only — repeats would distort
                    # the entropy in our favor.
                    tokens.append(val)

        evidence_base = {"origin": origin,
                         "session_cookie_name": cookie_name,
                         "samples_collected": len(tokens),
                         "samples_target": n_target}

        if not cookie_name:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no session-shaped cookie issued by "
                         f"{origin}/. Likely a JWT-in-body or stateless "
                         "API — token-RNG analysis doesn't apply."),
                evidence=evidence_base,
            )

        if len(tokens) < MIN_SAMPLES_FOR_VERDICT:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: only collected {len(tokens)} "
                         f"distinct `{cookie_name}` values from {origin} "
                         f"(need >= {MIN_SAMPLES_FOR_VERDICT}). Not "
                         "enough samples to make an entropy claim."),
                evidence=evidence_base,
            )

        # Concatenate for global entropy across all samples.
        joined = "".join(tokens)
        entropy = _shannon_entropy(joined)
        # Per-character class diversity — a healthy random hex token
        # uses 16 distinct chars; base64 uses ~64. Far fewer = bug.
        unique_chars = len(set(joined))
        # Common-prefix structure: a counter or timestamp leaks here.
        prefix6, prefix6_count = _common_prefix_count(tokens, 6)
        prefix6_ratio = prefix6_count / len(tokens)

        # Average per-token entropy as a sanity cross-check.
        per_token_entropies = [_shannon_entropy(t) for t in tokens]
        mean_per_token = sum(per_token_entropies) / len(per_token_entropies)

        analysis = {
            "joined_length": len(joined),
            "shannon_bits_per_char": round(entropy, 3),
            "mean_per_token_entropy": round(mean_per_token, 3),
            "unique_chars": unique_chars,
            "common_prefix_6": prefix6,
            "common_prefix_6_count": prefix6_count,
            "common_prefix_6_ratio": round(prefix6_ratio, 3),
            "entropy_threshold": ENTROPY_THRESHOLD_BITS_PER_CHAR,
            "first_token_masked": _mask(tokens[0]),
            "last_token_masked": _mask(tokens[-1]),
        }
        evidence = {**evidence_base, "analysis": analysis}

        # Two corroborating signals required: low entropy AND a
        # structural giveaway. Either one alone is too noisy on its
        # own (e.g. legitimate hex-only tokens are low-alphabet but
        # cryptographically fine).
        low_entropy = entropy < ENTROPY_THRESHOLD_BITS_PER_CHAR
        repeating_prefix = prefix6_ratio >= 0.60 and prefix6_count >= 18
        narrow_alphabet = unique_chars <= 8
        structural_flag = repeating_prefix or narrow_alphabet

        if low_entropy and structural_flag:
            reasons = []
            if repeating_prefix:
                reasons.append(
                    f"{prefix6_count}/{len(tokens)} tokens share the "
                    f"6-char prefix `{prefix6}` "
                    f"({int(prefix6_ratio * 100)}%)")
            if narrow_alphabet:
                reasons.append(
                    f"alphabet collapsed to {unique_chars} distinct "
                    "characters across all samples")
            return Verdict(
                validated=True, confidence=0.88,
                summary=(f"Confirmed: weak session-token RNG on "
                         f"{origin}. {len(tokens)} fresh "
                         f"`{cookie_name}` values yield "
                         f"{entropy:.2f} bits/char (threshold "
                         f"{ENTROPY_THRESHOLD_BITS_PER_CHAR}); "
                         f"{'; '.join(reasons)}."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Mint session ids from a CSPRNG — `secrets.token_hex(32)` "
                    "in Python, `crypto.randomBytes(32)` in Node, "
                    "`SecureRandom.hex(32)` in Ruby, "
                    "`RandomNumberGenerator.GetBytes` in .NET. Tokens "
                    "should be at least 128 bits of entropy (32 hex / "
                    "22 base64 chars) drawn uniformly from the full "
                    "alphabet. Never derive ids from time stamps, "
                    "user ids, request counters, or `Math.random` — "
                    "those are not cryptographically secure sources."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(tokens)} `{cookie_name}` samples "
                     f"on {origin} show {entropy:.2f} bits/char and "
                     f"no structural giveaway "
                     f"(prefix-share {int(prefix6_ratio * 100)}%, "
                     f"alphabet {unique_chars} chars)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthSessionTokenEntropyProbe().main()
