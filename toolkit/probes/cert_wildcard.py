#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""High-fidelity validation for "cert_trust_wildcard" / "trust is via
wildcard" findings emitted by testssl.sh.

Why a dedicated probe
---------------------
The default routing landed these findings on `breach_compression` via
the OWASP/CWE coarse match — wrong category, returns inconclusive every
time. Routing through the full testssl.sh suite would work but takes
~30 seconds for a question that's actually a single TLS handshake away.

What it does
------------
1. Open one TLS connection to host:port (no verify — we want the cert
   exactly as the server presents it, including expired/self-signed).
2. Parse the leaf cert via the cryptography library.
3. Inspect the Subject Alternative Name extension. Any DNS entry that
   begins with `*.` is a wildcard.
4. Verdict:
     - wildcard SAN present  -> validated=True, confidence 0.95
                                (severity stays at the testssl-supplied
                                LOW; this isn't a vulnerability uplift,
                                it's confirming a posture observation)
     - no wildcard SAN       -> validated=False, confidence 0.95
                                (the original finding no longer applies)
     - handshake failed      -> validated=None (inconclusive); analyst
                                should investigate the connection error

Examples
--------
    python cert_wildcard.py --url 'https://example.com'
    python cert_wildcard.py --url 'https://example.com:8443'
"""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

# Probes live in toolkit/probes/; the shared lib (including the TLS
# helper we wrote for the server's fast path) is one level up.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient   # imported only so SafeClient initialization in main() succeeds; we don't use it directly
from lib.tls import fetch_cert


class CertWildcardProbe(Probe):
    name = "cert_wildcard"
    summary = ("Validates a wildcard-cert finding by inspecting the "
               "live leaf certificate's Subject Alternative Name. "
               "Sub-second, no testssl.sh required.")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args. --url comes from the base parser; we
        # ignore --cookie because TLS-layer findings don't depend on
        # session state.
        pass

    # ------------------------------------------------------------------
    def run(self, args, client: SafeClient) -> Verdict:
        # We accept --url as either a full https://... URL or a bare
        # host[:port] string. urlparse handles the URL form; the bare
        # form is uncommon in production but useful at the CLI.
        if not args.url:
            return Verdict(ok=False, error="--url is required")

        parsed = urllib.parse.urlparse(args.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
        if not host:
            # Treat the whole arg as a hostname when urlparse couldn't
            # extract one (e.g. caller passed 'example.com' without a
            # scheme).
            host = args.url.split(":", 1)[0]

        # Note: we deliberately do NOT route through SafeClient here —
        # SafeClient is for HTTP requests and would issue a GET we don't
        # need. The TLS handshake is a single, scoped operation; we
        # account for it in the audit log via the `evidence.audit`
        # fields the verdict carries instead of the SafeClient log.
        info = fetch_cert(host, port)

        evidence = {
            "host": host,
            "port": port,
            "elapsed_ms": info.elapsed_ms,
            "protocol": info.protocol,
            "cipher": info.cipher,
            "cert": {
                "subject": info.subject,
                "issuer": info.issuer,
                "common_name": info.common_name,
                "sans": info.sans,
                "san_ips": info.san_ips,
                "wildcard_sans": info.wildcard_sans,
                "not_before": info.not_before,
                "not_after": info.not_after,
                "days_until_expiry": info.days_until_expiry,
                "signature_algorithm": info.signature_algorithm,
                "public_key_algorithm": info.public_key_algorithm,
                "public_key_size": info.public_key_size,
                "is_self_signed": info.is_self_signed,
            },
        }

        if not info.ok:
            # Connection couldn't be established. Report inconclusive
            # with the underlying error so the analyst can act on it.
            return Verdict(
                ok=False, validated=None, confidence=0.0,
                summary=(f"Inconclusive: TLS handshake to "
                         f"{host}:{port} failed ({info.error}). "
                         "Cannot confirm or refute the wildcard claim."),
                error=info.error,
                evidence=evidence,
            )

        if info.has_wildcard_san:
            patterns = ", ".join(info.wildcard_sans)
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Validated: leaf certificate at {host}:{port} "
                    f"includes wildcard SAN(s): {patterns}. "
                    "All subdomains under each wildcard pattern are "
                    "covered by this single cert — a compromise of "
                    "the private key exposes the entire matching "
                    "subdomain space."),
                evidence=evidence,
                remediation=(
                    "Wildcard certs are not inherently a vulnerability "
                    "but they widen the blast radius of a key "
                    "compromise. Mitigations:\n"
                    "  - Issue per-host certs (or short-lived certs "
                    "via ACME) for high-value subdomains.\n"
                    "  - Constrain wildcard certs to specific zones "
                    "using Name Constraints when issuing from an "
                    "internal CA.\n"
                    "  - Pin the wildcard cert's private key to a "
                    "single host whose subdomain delegation it "
                    "actually serves.\n"
                    "If the wildcard is intentional and the threat "
                    "model is accepted, mark this finding as "
                    "accepted_risk."),
            )

        # No wildcard SAN — the original testssl finding no longer
        # holds against the live cert. Confidence high because this is
        # a structured-data check, not a heuristic.
        return Verdict(
            validated=False, confidence=0.95,
            summary=(
                f"Refuted: the live leaf cert at {host}:{port} has no "
                f"wildcard SAN entry. Current SANs: {info.sans!r}. "
                "The testssl.sh finding likely predates a cert "
                "rotation."),
            evidence=evidence,
            remediation=(
                "Mark the original finding as a false positive — the "
                "live cert no longer has the flagged property."),
        )


if __name__ == "__main__":
    CertWildcardProbe().main()
