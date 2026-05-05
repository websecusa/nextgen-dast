#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cryptography: ASP.NET padding-oracle on `WebResource.axd` /
`ScriptResource.axd` (the POET / CVE-2010-3332 surface).

Old ASP.NET (before MS10-070) returned distinguishable responses for
ciphertexts that decrypted to invalid PKCS#7 padding versus valid
padding-but-bad-MAC. The classic distinguisher is HTTP 500 (padding
exception) vs HTTP 404 (decrypted, but the requested resource id was
unknown). The oracle lets an attacker decrypt the `__VIEWSTATE` /
config / forms-auth ticket without knowing the key.

We do NOT exploit the oracle — that would require thousands of
requests and would mutate the target's auth state. Instead we ASK
whether the oracle exists by sending a small set of crafted requests
and asking: "do at least three distinguishable response classes
appear, and is the distinguisher reproducible?"

Test design:
  1. We need a real `?d=` parameter to start from. Approach: generate
     a synthetic ciphertext shape (16 bytes IV + 16 bytes ciphertext,
     URL-safe base64) so the parameter parses. Older ASP.NET will
     attempt to decrypt it, hit a padding error, and return one
     class of response. Different byte-flips of the same input will
     either hit padding errors (same class) or hit a "valid padding,
     bogus content" path (different class).
  2. Send 12 such requests per axd handler with one byte mutated at
     varying positions. Cluster responses by (status, body-hash-
     prefix).
  3. Repeat the SAME request triplet a second time as a
     reproducibility check.

Detection criteria — ALL must be true for validated=True:
  (a) the .axd handler exists (status != 404 / 0 on at least one
      probe — i.e. the framework is wired up),
  (b) at least 3 distinct response classes were observed across the
      mutated requests, AND
  (c) the same triplet of mutations produced the SAME class on the
      reproducibility round (within tolerance — exact match).

Detection signal:
  >= 3 distinct response classes on .axd?d=<mutated> AND a fixed
  (request, response-class) mapping that is stable across two trials.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# The two axd handlers historically vulnerable to POET. Either one is
# enough — newer ASP.NET still ships these, but with the patched
# constant-time response.
AXD_PATHS = ("/WebResource.axd", "/ScriptResource.axd")

# Number of mutated requests per handler per trial. 6 mutations × 2
# trials × 2 handlers = 24 requests max — well within request_budget.
MUTATIONS_PER_TRIAL = 6


def _b64u_encode(b: bytes) -> str:
    """ASP.NET .axd `d` uses base64url-ish encoding (no padding, no
    `+`/`/`). Match what the framework expects so the parser at least
    accepts our string and the cipher path runs."""
    s = base64.urlsafe_b64encode(b).decode().rstrip("=")
    return s


def _flip_byte(buf: bytes, idx: int) -> bytes:
    """Flip a single byte (XOR 0xFF) at a given index. Used to walk
    different ciphertext positions through the decrypt path."""
    if idx < 0 or idx >= len(buf):
        return buf
    out = bytearray(buf)
    out[idx] ^= 0xFF
    return bytes(out)


def _classify(status: int, body: bytes) -> str:
    """A response class is (status_code, hash-prefix-of-first-256-
    bytes-of-body). Hashing the body prefix dedupes content-equivalent
    responses while keeping the class string compact."""
    h = hashlib.sha256(body[:256]).hexdigest()[:8]
    return f"{status}:{h}"


class CryptoPaddingOracleAspnetAxdProbe(Probe):
    name = "crypto_padding_oracle_aspnet_axd"
    summary = ("Detects an ASP.NET padding oracle via "
               "WebResource.axd / ScriptResource.axd response-class "
               "differential.")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args — the test surface is fixed.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # The base ciphertext: 16 bytes IV + 16 bytes ct. Random per
        # run so we don't keep hitting the same cache entry, but
        # FIXED across the two trials within this run so we can
        # compare class assignments deterministically.
        seed = secrets.token_bytes(32)

        attempts: list[dict] = []
        confirmed: dict | None = None

        for path in AXD_PATHS:
            base_url = urljoin(origin, path)

            # Two trials — same mutation set, verify the class
            # mapping is reproducible.
            trial_classes: list[list[str]] = []
            trial_statuses: list[list[int]] = []
            handler_present = False

            for trial in range(2):
                classes: list[str] = []
                statuses: list[int] = []
                for i in range(MUTATIONS_PER_TRIAL):
                    # Walk byte 0, 4, 8, 12, 15, 16 of the ciphertext —
                    # mix of IV and CT positions. Deterministic across
                    # trials.
                    pos_table = (0, 4, 8, 12, 15, 16)
                    pos = pos_table[i % len(pos_table)]
                    payload = _flip_byte(seed, pos)
                    qs = _b64u_encode(payload)
                    # Add a benign `t=` cache-buster so we exercise the
                    # decrypt path freshly each trial. The framework
                    # ignores unknown parameters.
                    url = (f"{base_url}?d={qs}"
                           f"&t={trial}-{i}-{secrets.token_hex(2)}")
                    r = client.request("GET", url)
                    statuses.append(r.status)
                    classes.append(_classify(r.status, r.body or b""))
                    # If we ever see a non-zero status, the handler
                    # exists and is wired up — minimum precondition.
                    if r.status not in (0, 404):
                        handler_present = True
                trial_classes.append(classes)
                trial_statuses.append(statuses)

            distinct = set(trial_classes[0])
            n_distinct = len(distinct)
            stable = trial_classes[0] == trial_classes[1]
            row = {"axd_path": path,
                   "handler_present": handler_present,
                   "trial1_classes": trial_classes[0],
                   "trial2_classes": trial_classes[1],
                   "trial1_statuses": trial_statuses[0],
                   "trial2_statuses": trial_statuses[1],
                   "n_distinct_classes": n_distinct,
                   "stable_across_trials": stable}

            # The triple lock: handler exists, >= 3 distinct response
            # classes, and the mapping repeats.
            if handler_present and n_distinct >= 3 and stable:
                row["confirmed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: padding-oracle differential on "
                         f"{origin}{confirmed['axd_path']} — "
                         f"{confirmed['n_distinct_classes']} distinct "
                         "response classes observed across mutated "
                         "ciphertexts, stable across two trials. The "
                         "handler distinguishes valid- from invalid-"
                         "padding decrypt paths."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Apply MS10-070 (and the ongoing roll-ups for "
                    "ASP.NET) so the framework returns a uniform error "
                    "for any decrypt failure regardless of cause.\n"
                    "Verification: with the patch applied, the same "
                    "test should produce a single response class for "
                    "all mutations.\n"
                    "Defence in depth: rotate the machineKey, refresh "
                    "all forms-auth tickets and ViewState-signed "
                    "blobs, and audit logs for AES-CBC decrypt failures "
                    "spanning the unpatched window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} .axd handlers on "
                     f"{origin}; no padding-oracle differential met the "
                     "3-class + reproducibility gate."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CryptoPaddingOracleAspnetAxdProbe().main()
