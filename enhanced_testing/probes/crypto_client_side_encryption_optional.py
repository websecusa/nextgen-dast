#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cryptography: front-end "encrypts the password before send", but the
backend ALSO accepts plaintext on the same wire — the client-side
encryption is decorative.

Apps that wrap login passwords in `CryptoJS.AES.encrypt(...)` or
`forge.pkcs1.encrypt(...)` are usually trying to hide the password
from network observers (which is what TLS is for). The real harm is
when the backend simultaneously accepts the plaintext password under
the same field name — meaning an attacker who phishes a credential or
captures one outside HTTPS can replay it without bothering with the
client crypto. The "encryption" is then security theatre AND a
misdirection that hides the real authentication wire format.

This probe is two-phase:

  Phase 1 (read-only) — fetch the homepage's JS bundles and grep for
  client-side crypto invocations on a login-shaped flow. We need to
  see at least one of the structural markers (`CryptoJS.AES.encrypt`
  / `forge.pkcs1` / `bcrypt.hashSync` / `RSA.encrypt` / `JSEncrypt`)
  AND a login submission (a `POST` to a `/login` / `/auth` URL) for
  the bug class to apply.

  Phase 2 (POST) — send a login attempt to that endpoint with the
  password as raw plaintext (no client-side wrapping). If the server
  returns 200 with the auth shape (token, JWT, set-cookie session, or
  a JSON body containing `authentication`/`token`), the backend
  accepts plaintext and the client-side encryption is decorative.

Detection criteria — ALL must be true for validated=True:
  (a) JS bundle contains a strong client-side crypto marker AND a
      login URL,
  (b) plaintext POST to that URL returns 200 with one of the auth
      shapes (`Set-Cookie: ...session...`, `Authorization`-shaped
      body, `token` in body, JWT-pattern in body), AND
  (c) the SAME credentials produce a non-200 (4xx) when sent to a
      bogus endpoint or with a wrong password — proves the 200 wasn't
      a generic catch-all.

We use `--target-email` defaulted to `admin@juice-sh.op` matching the
project's seed-account convention. The probe never registers new
accounts.

Detection signal:
  Login JS uses client-side crypto AND backend accepts a plaintext
  password POST AND a wrong-password baseline returns 4xx.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Markers in JS that indicate front-end password crypto. Each is a
# library-specific call that doesn't appear by accident — these are
# all imported APIs, not generic words.
CRYPTO_RE = re.compile(
    r"(CryptoJS\.AES\.encrypt|"
    r"CryptoJS\.SHA\d+|"
    r"forge\.pkcs1\.|"
    r"forge\.pki\.|"
    r"new\s+JSEncrypt\s*\(|"
    r"bcrypt\.hashSync|"
    r"\bsjcl\.encrypt|"
    r"window\.crypto\.subtle\.encrypt)",
    re.I)

# Login URL discovery — relative URLs the JS POSTs to.
LOGIN_URL_RE = re.compile(
    r'["\'](/(?:[\w\-./]*?(?:login|signin|sign-in|auth|authenticate))'
    r'(?:\?[\w\-=&]*)?)["\']', re.I)

SCRIPT_RE = re.compile(
    r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Auth-success shapes in a JSON / cookie response.
AUTH_SUCCESS_BODY_RE = re.compile(
    r'"(authentication|token|access_token|sessionToken)"\s*:\s*"',
    re.I)
JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\."
                         r"[A-Za-z0-9_-]+\b")


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _looks_like_auth_success(status: int, headers: dict, body: str) -> bool:
    """Three-way OR — any one of these is enough on its own to
    classify an auth response as successful, but we ALSO require
    status == 200."""
    if status != 200:
        return False
    cookie = _hdr(headers, "Set-Cookie") or ""
    if re.search(r"(session|token|jwt|auth)=", cookie, re.I):
        return True
    if AUTH_SUCCESS_BODY_RE.search(body or ""):
        return True
    if JWT_LIKE_RE.search(body or ""):
        return True
    return False


class CryptoClientSideEncryptionOptionalProbe(Probe):
    name = "crypto_client_side_encryption_optional"
    summary = ("Detects backends that accept plaintext passwords on a "
               "login flow whose JS performs client-side encryption.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--target-email", default="admin@juice-sh.op",
            help="Email to attempt against (default: admin@juice-sh.op). "
                 "Must be a documented seed account.")
        parser.add_argument(
            "--target-password", default="admin123",
            help="Plaintext password to send (default: a documented "
                 "seed-account password).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # --- Phase 1 — JS analysis ---
        index = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if index.status == 200 and index.body:
            bundles = SCRIPT_RE.findall(index.text or "")
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles[:5]]

        crypto_marker = None
        login_urls: set[str] = set()
        scanned: list[dict] = []
        for url in bundles:
            # Same-origin only — refuse off-origin bundles.
            if urlparse(url).netloc != parsed.netloc:
                scanned.append({"bundle": url, "skipped": "off-origin"})
                continue
            rb = client.request("GET", url)
            row = {"bundle": url, "status": rb.status, "size": rb.size}
            if rb.status == 200 and rb.body:
                text = rb.text or ""
                m = CRYPTO_RE.search(text)
                if m and not crypto_marker:
                    crypto_marker = m.group(0)
                    row["crypto_marker"] = crypto_marker
                for lm in LOGIN_URL_RE.finditer(text):
                    login_urls.add(lm.group(1))
            scanned.append(row)

        evidence_phase1 = {"origin": origin,
                            "bundles_scanned": scanned,
                            "crypto_marker": crypto_marker,
                            "login_urls_found": sorted(login_urls)[:5]}

        if not crypto_marker or not login_urls:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no client-side encryption marker "
                         f"AND login endpoint pair found in JS bundles "
                         f"on {origin}; bug class does not apply."),
                evidence=evidence_phase1,
            )

        # --- Phase 2 — plaintext login + wrong-password baseline ---
        # Iterate at most 3 candidate login URLs; first that
        # round-trips to the auth-success shape wins.
        plaintext_payload = json.dumps({
            "email": args.target_email,
            "password": args.target_password,
        }).encode()
        wrong_payload = json.dumps({
            "email": args.target_email,
            "password": "wrong-on-purpose-round12",
        }).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for login_url in sorted(login_urls)[:3]:
            target = urljoin(origin, login_url)
            # Plaintext attempt.
            r = client.request("POST", target, headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            }, body=plaintext_payload)
            success = _looks_like_auth_success(
                r.status, r.headers, r.text or "")
            row = {"login_url": login_url,
                   "plaintext_status": r.status,
                   "plaintext_looks_like_auth": success,
                   "plaintext_size": r.size}
            if success:
                # Baseline: same path, wrong password should NOT look
                # like an auth success. This guards against an
                # endpoint that returns 200 to anything (a catch-all).
                br = client.request("POST", target, headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }, body=wrong_payload)
                baseline = _looks_like_auth_success(
                    br.status, br.headers, br.text or "")
                row["baseline_status"] = br.status
                row["baseline_looks_like_auth"] = baseline
                if not baseline:
                    row["confirmed"] = True
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {**evidence_phase1, "phase2_attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: client-side crypto marker "
                         f"`{crypto_marker}` is present in the JS, but "
                         f"{origin}{confirmed['login_url']} also "
                         "accepts a plaintext password POST and returns "
                         "an authenticated response. The wrong-password "
                         "baseline returns a non-auth response, so the "
                         "200 isn't a catch-all."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Decide which wire format the login endpoint accepts "
                    "and enforce ONLY that one:\n"
                    "  - If the client-side crypto is meant to bind the "
                    "credential to a specific session/nonce, refuse "
                    "submissions that don't carry the expected "
                    "ciphertext shape.\n"
                    "  - More commonly, drop the client-side crypto "
                    "entirely. TLS already protects the wire; the JS "
                    "wrapping just complicates auditability without "
                    "adding security.\n"
                    "Audit the auth pipeline for any other path that "
                    "branches on input shape — wherever the backend "
                    "accepts two formats, an attacker only has to "
                    "satisfy the simpler one."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: client-side crypto marker present, but "
                     f"plaintext login on {len(attempts)} candidate "
                     f"endpoints did not yield an authenticated "
                     "response distinct from a wrong-password baseline."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CryptoClientSideEncryptionOptionalProbe().main()
