#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cryptography: token-verification endpoint compares with a non-
constant-time `==` instead of HMAC compare.

If a server uses Python `==`, JavaScript `===`, Java `String.equals`,
or PHP `==` to verify a token byte-by-byte, the function returns
faster when the FIRST byte differs than when the LAST byte differs —
the comparison short-circuits on the first mismatch. An attacker
measures response time across mutations at different byte positions
and recovers the token one byte at a time.

This probe sends 30 token-verification requests (5 trials × 6 byte
positions across the token width) with one byte mutated at a known
position per trial, all against the same endpoint with the same
otherwise-correct (placeholder) token shape. We compare the mean
response time per byte position. If the variance ACROSS positions is
materially larger than the variance WITHIN a position, the comparison
short-circuits and the bug is real.

Statistical gate (high-fidelity):
  stddev(per-position means) > 2 × pooled within-position stddev
  AND mean-of-means > 5 ms (so we don't fire on noise alone).

Detection signal:
  Across-position stddev exceeds within-position stddev by 2×, with
  the per-position means stretched over a meaningful absolute range.
"""
from __future__ import annotations

import secrets
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly verify a token argument and return 200 vs
# 4xx based on its validity. We try them in order; first responder
# (200 or 401/403 with a stable shape) wins.
TOKEN_PATHS = (
    "/api/verify",
    "/api/verify-token",
    "/api/auth/verify",
    "/api/token/verify",
    "/auth/verify",
    "/verify",
    "/api/2fa/verify",
    "/api/otp/verify",
)

# Token width and which byte positions to sample. We pick six
# positions spread across a 32-byte token: front, near-front, middle,
# past-middle, late, last. If the comparison short-circuits, the
# response time should be a monotone-rising function of position.
TOKEN_LEN = 32
POSITIONS = (0, 4, 12, 20, 28, 31)
TRIALS_PER_POSITION = 5
ACROSS_OVER_WITHIN_RATIO = 2.0
ABS_MEAN_FLOOR_MS = 5.0


def _build_token(base: bytes, pos: int, mutation: int) -> str:
    """Return the base token with byte `pos` XOR'd by `mutation`. The
    mutation is the same per call, so a position's runs are roughly
    apples-to-apples; only the byte location varies meaningfully."""
    out = bytearray(base)
    out[pos] ^= mutation
    return out.hex()


def _try_endpoint(client: SafeClient, base_url: str,
                  token: str) -> tuple[int, int, int]:
    """Send one verification request. Returns (status, size, ms)."""
    # Try as a query parameter — most lightweight verifier endpoints
    # accept `?token=...`. If the endpoint expects POST JSON, the
    # caller can switch over after the discovery phase tells us so.
    url = f"{base_url}?token={token}"
    t0 = time.monotonic()
    r = client.request("GET", url)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return r.status, r.size, elapsed_ms


class CryptoTimingTokenCompareProbe(Probe):
    name = "crypto_timing_token_compare"
    summary = ("Detects token-verification endpoints whose response "
               "time scales with the matching prefix length — "
               "indicating a non-constant-time comparison.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--token-path", action="append", default=[],
            help="Additional verification endpoint to try (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(TOKEN_PATHS) + list(args.token_path or [])

        # Discover an endpoint that responds at all. We DON'T need a
        # 200 — even a stable 401 / 403 distinguishes between matching-
        # and-wrong tokens via response time. We do refuse pure 0s
        # (no network) and 404s (no handler).
        base_token = secrets.token_bytes(TOKEN_LEN)
        chosen_path = None
        chosen_url = None
        for p in paths:
            url = urljoin(origin, p)
            status, _size, _ms = _try_endpoint(
                client, url, base_token.hex())
            if status not in (0, 404, 405):
                chosen_path = p
                chosen_url = url
                break

        if not chosen_url:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no token-verification endpoint "
                         f"responded on {origin}; cannot probe timing."),
                evidence={"origin": origin, "tried_paths": list(paths)},
            )

        # Collect timings: for each position, run TRIALS_PER_POSITION
        # samples. We INTERLEAVE positions across trials so any
        # short-term system jitter affects all positions roughly
        # equally.
        per_pos: dict[int, list[int]] = {p: [] for p in POSITIONS}
        for trial in range(TRIALS_PER_POSITION):
            for pos in POSITIONS:
                # Same XOR mutation each call so we're measuring
                # "differs at byte N" consistently.
                token = _build_token(base_token, pos, 0xFF)
                _status, _size, ms = _try_endpoint(
                    client, chosen_url, token)
                per_pos[pos].append(ms)

        # Statistics. Across-position spread vs pooled within-position.
        means: list[float] = [statistics.mean(per_pos[p])
                              for p in POSITIONS]
        across_stddev = statistics.pstdev(means) if len(means) > 1 else 0.0
        # Pooled within-position stddev (mean of per-position stddevs).
        # Each position needs >=2 samples for a stddev to be meaningful;
        # TRIALS_PER_POSITION = 5 satisfies that.
        within_stddevs = [
            statistics.pstdev(per_pos[p]) if len(per_pos[p]) > 1 else 0.0
            for p in POSITIONS]
        within_pooled = (statistics.mean(within_stddevs)
                         if within_stddevs else 0.0)
        mean_of_means = statistics.mean(means) if means else 0.0

        # Statistical gates:
        ratio = ((across_stddev / within_pooled)
                 if within_pooled > 0 else float("inf"))
        gate_ratio = ratio >= ACROSS_OVER_WITHIN_RATIO
        gate_floor = mean_of_means >= ABS_MEAN_FLOOR_MS

        evidence = {
            "origin": origin, "endpoint": chosen_url,
            "endpoint_path": chosen_path,
            "positions": list(POSITIONS),
            "trials_per_position": TRIALS_PER_POSITION,
            "per_position_samples_ms": {str(p): per_pos[p]
                                          for p in POSITIONS},
            "per_position_mean_ms":
                {str(p): round(statistics.mean(per_pos[p]), 2)
                 for p in POSITIONS},
            "across_position_stddev_ms": round(across_stddev, 2),
            "within_position_stddev_pooled_ms": round(within_pooled, 2),
            "ratio_across_over_within": round(ratio, 2),
            "ratio_threshold": ACROSS_OVER_WITHIN_RATIO,
            "mean_of_means_ms": round(mean_of_means, 2),
            "abs_floor_ms": ABS_MEAN_FLOOR_MS,
        }

        if gate_ratio and gate_floor:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(f"Confirmed: token-verification timing leak on "
                         f"{chosen_url} — across-position stddev "
                         f"{across_stddev:.1f} ms vs within-position "
                         f"pooled stddev {within_pooled:.1f} ms (ratio "
                         f"{ratio:.1f}×). Per-position means stretch "
                         f"around {mean_of_means:.1f} ms, consistent "
                         "with a short-circuiting comparison."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Replace the equality check with a constant-time "
                    "comparator that runs over the full input length:\n"
                    "  - Python: `hmac.compare_digest(a, b)`.\n"
                    "  - Node: `crypto.timingSafeEqual(Buffer.from(a), "
                    "Buffer.from(b))` (lengths must match — pad first).\n"
                    "  - Java: `MessageDigest.isEqual(a, b)`.\n"
                    "  - PHP: `hash_equals($a, $b)`.\n"
                    "  - .NET: `CryptographicOperations.FixedTimeEquals"
                    "(a, b)`.\n"
                    "Pair with a server-side rate limit so even a "
                    "weakened oracle is impractical."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: token timing on {chosen_url} — "
                     f"across-pos stddev {across_stddev:.1f} ms vs "
                     f"within-pos pooled {within_pooled:.1f} ms "
                     f"(ratio {ratio:.1f}, mean {mean_of_means:.1f} "
                     "ms); thresholds not crossed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CryptoTimingTokenCompareProbe().main()
