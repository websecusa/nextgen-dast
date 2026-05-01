#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: cryptographic key material reachable on a
public path.

When a deploy leaves /encryptionkeys/, /keys/, /id_rsa, /server.key,
/.ssh/, or similar in the document root, an attacker walks off with
the application's signing key and forges anything that depends on it
(JWTs, signed cookies, signed URLs, OAuth assertions). This is the
"key in the webroot" bug class — separate from a directory listing
finding because the file is *individually fetchable* by name and the
content is unambiguous (`-----BEGIN ... PRIVATE KEY-----` etc.).

This probe walks a fixed catalogue of paths every deploy should
verify is NOT public, fetches each, and looks for canonical key-
material markers in the response body. A confirmed hit is
unambiguous — the body literally contains a private key or a
signing-relevant public key.

Tested against:
  + OWASP Juice Shop  /encryptionkeys/premium.key  →  validated=True
                      (50-byte AES key)
                      /encryptionkeys/jwt.pub      →  RSA public key
                      (used by the JWT signer; hand to attacker for
                      key-confusion attacks)
  + nginx default site                              →  validated=False
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Paths every reasonable web app should NOT serve. The catalogue is
# small and curated — directory-fuzzing belongs in a separate brute-
# force probe (info_backup_files); this one targets *named* paths that
# are documented to host secrets when exposed.
DEFAULT_PATHS = (
    # Juice Shop's literal paths
    "/encryptionkeys/",
    "/encryptionkeys/premium.key",
    "/encryptionkeys/jwt.pub",
    # generic key-material webroot leaks
    "/keys/",
    "/server.key",
    "/server.pem",
    "/private.key",
    "/private.pem",
    "/id_rsa",
    "/id_rsa.pub",
    "/id_ed25519",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/ssl/",
    "/ssl/server.key",
    "/ssl/private.key",
    "/cert/",
    "/cert/server.key",
    "/key.pem",
    "/cert.pem",
    "/.gnupg/secring.gpg",
)

# Markers that uniquely identify cryptographic key material in the
# response body. Each is anchored on a header that PEM/OpenSSH/etc.
# universally use; nothing in normal HTML/JSON looks like these.
_KEY_MARKERS = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
     "PEM private key"),
    (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),    "OpenSSH private key"),
    (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),  "PGP private key"),
    (re.compile(r"^ssh-(?:rsa|ed25519|dss|ecdsa) AAAA", re.MULTILINE), "SSH public key (authorized_keys-style)"),
    (re.compile(r"-----BEGIN RSA PUBLIC KEY-----"),         "RSA public key (signing key)"),
    (re.compile(r"-----BEGIN PUBLIC KEY-----"),             "PEM public key (signing key)"),
    # AES-shaped hex-or-base64 blobs of key-typical lengths. Conservative
    # — only fires when the body is short and looks like nothing else
    # (no HTML tags, no JSON braces, just key-bytes).
    (re.compile(r"^[A-Za-z0-9+/=]{32,200}\s*$"), "AES-shaped key blob"),
)


def _detect_key_material(body_text: str) -> tuple[str, str] | None:
    if not body_text or len(body_text) > 50000:
        # Files >50KB aren't keys — they're disk dumps. Different probe.
        return None
    snippet = body_text.strip()
    for pat, kind in _KEY_MARKERS:
        m = pat.search(snippet)
        if m:
            # Cap returned snippet to avoid persisting the whole key.
            return kind, m.group(0)[:120] + ("…" if len(m.group(0)) > 120 else "")
    return None


class KeyMaterialExposedProbe(Probe):
    name = "info_key_material_exposed"
    summary = ("Detects cryptographic key material (private keys, SSH "
               "keys, signing public keys, AES blobs) reachable on "
               "documented webroot paths.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(DEFAULT_PATHS) + list(args.path or [])

        tested: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                hit = _detect_key_material(r.text)
                if hit:
                    kind, snippet = hit
                    row.update({"is_key_material": True,
                                "key_kind": kind,
                                "snippet": snippet})
                    confirmed.append(row)
            tested.append(row)

        evidence = {"origin": origin, "paths_tested": tested}
        if confirmed:
            kinds = sorted({c["key_kind"] for c in confirmed})
            paths_seen = sorted({c["path"] for c in confirmed})
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: cryptographic key material exposed "
                         f"on {origin} — "
                         + ", ".join(paths_seen)
                         + f" ({'/'.join(kinds)})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Move the key file out of the document root. "
                    "Application-signing keys belong in a key store "
                    "(KMS, Vault, or encrypted at rest with the "
                    "kernel keyring), not on the static-asset path "
                    "served by your reverse proxy. After rotating "
                    "the exposed key:\n"
                    "  - Invalidate every session/cookie/JWT signed "
                    "with the old key.\n"
                    "  - Check application logs for unauthorised use "
                    "of forged tokens during the exposure window.\n"
                    "  - Add a deploy-time check that fails the "
                    "build if any of /encryptionkeys, /keys, /id_rsa, "
                    "/server.key, etc. is reachable on the public "
                    "vhost."),
            )
        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: tested {len(tested)} canonical "
                     f"key-material paths on {origin}; none returned "
                     "a recognisable key blob."),
            evidence=evidence,
        )


if __name__ == "__main__":
    KeyMaterialExposedProbe().main()
