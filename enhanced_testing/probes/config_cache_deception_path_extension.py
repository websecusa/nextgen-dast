#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cache deception: sensitive routes cacheable via extension confusion.

Many CDNs cache responses on the basis of the URL ending alone --
anything ending in `.css`, `.js`, `.png`, `.gif`, `.json`. When the
back-end framework's catch-all routing returns the same authenticated
content for `/account/profile.css` as for `/account/profile`, the
CDN happily caches the per-user content on the suffixed path. The
next visitor to `/account/profile.css` reads the previous user's
PII from the cache.

The high-fidelity signal pairs two facts:
  1. The suffixed and bare paths return the same response body
     (similarity score > threshold), AND
  2. The response carries a cacheable header set
     (`Cache-Control: public`, or no `Cache-Control` and no
     `Pragma: no-cache`, or an explicit `s-maxage`/`max-age` > 0).

Detection signal:
  1. Register / log in a throwaway user (so the bare path returns
     personalised content).
  2. GET `/<base>` and `/<base>.css` (and `.js`, `.png`).
  3. Validate when the .css response status is 200, the body
     overlaps significantly with the bare-path response, AND the
     headers permit caching.

Tested against:
  + OWASP Juice Shop  Bare /profile is HTML; /profile.css 404s
                      because Express doesn't catch .css fall-through
                      -> validated=False.
  + Apps with Rails / Django catch-all routing returning HTML on
    .css suffix paths -> validated=True.

Read-only: only register, login, and GET. The probe does not POST
to or otherwise modify any cache.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Sensitive paths that should never be cacheable. Bare path is what
# the suffixed paths get compared against.
TARGETS = (
    "/profile",
    "/account",
    "/me",
    "/dashboard",
    "/api/me",
    "/api/users/me",
    "/rest/user/whoami",
)

SUFFIXES = (".css", ".js", ".json", ".png", ".gif", ".jpg")

# Header tokens that explicitly forbid caching by intermediaries.
_NOCACHE_TOKENS = ("private", "no-store", "no-cache",
                    "must-revalidate", "max-age=0")


def _is_cacheable(headers: dict) -> tuple[bool, str]:
    """Return (cacheable, reason). Cacheable is True when the
    response header set permits a CDN cache to store and reuse it.
    The pessimistic call is False -- when in doubt, treat as not
    cacheable to keep false positives down."""
    if not headers:
        return True, "no headers (default-cacheable assumption)"
    cc = ""
    for k, v in headers.items():
        if k.lower() == "cache-control":
            cc = str(v).lower()
            break
    if any(tok in cc for tok in _NOCACHE_TOKENS):
        return False, f"cache-control: {cc}"
    if "public" in cc or re.search(r"max-age=\s*[1-9]\d*", cc) or "s-maxage" in cc:
        return True, f"cache-control: {cc}"
    if not cc:
        # Many CDNs treat absent Cache-Control as cacheable. Still a
        # finding -- the absence of a no-store header is the bug.
        return True, "no Cache-Control header"
    return False, f"cache-control: {cc}"


def _similarity(a: str, b: str) -> float:
    """Cheap shingled-token similarity score (0-1). Avoids importing
    difflib so the probe runtime stays small. We split into 5-char
    shingles, intersect, and Jaccard-score."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    shingles_a = {a[i:i+5] for i in range(0, len(a) - 4, 5)}
    shingles_b = {b[i:i+5] for i in range(0, len(b) - 4, 5)}
    if not shingles_a or not shingles_b:
        return 0.0
    inter = shingles_a & shingles_b
    union = shingles_a | shingles_b
    return len(inter) / len(union)


def _register_and_login(client: SafeClient, origin: str
                        ) -> tuple[str | None, dict]:
    email = f"cache-decep-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = ((doc.get("authentication") or {}).get("token")
                   if isinstance(doc, dict) else None) or doc.get("token")
            if tok:
                return tok, diag
        except json.JSONDecodeError:
            pass
    return None, diag


class CacheDeceptionPathExtensionProbe(Probe):
    name = "config_cache_deception_path_extension"
    summary = ("Detects sensitive routes that return the same content "
               "under a cacheable file-extension suffix -- cache-"
               "deception primitive.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional sensitive base path (e.g. '/portfolio'). "
                 "Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        targets = list(TARGETS) + list(args.target or [])

        token, diag = _register_and_login(client, origin)
        # Authenticated body is what makes the cache deception
        # interesting; we still try anonymously when login fails so
        # the probe isn't fully blocked.
        auth_headers = ({"Authorization": f"Bearer {token}"}
                        if token else {})

        attempts: list[dict] = []
        confirmed: dict | None = None
        for base in targets:
            r_base = client.request("GET", urljoin(origin, base),
                                    headers=auth_headers)
            if r_base.status != 200 or not r_base.body:
                continue
            base_text = r_base.text or ""
            for sfx in SUFFIXES:
                r_sfx = client.request("GET", urljoin(origin, base + sfx),
                                       headers=auth_headers)
                row: dict = {"base": base, "suffix": sfx,
                             "base_status": r_base.status,
                             "suffix_status": r_sfx.status,
                             "base_size": r_base.size,
                             "suffix_size": r_sfx.size}
                if r_sfx.status != 200 or not r_sfx.body:
                    attempts.append(row)
                    continue
                sim = _similarity(base_text, r_sfx.text or "")
                row["similarity"] = round(sim, 3)
                cacheable, why = _is_cacheable(r_sfx.headers or {})
                row["cacheable"] = cacheable
                row["cache_reason"] = why
                if sim >= 0.7 and cacheable:
                    row["deception"] = True
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "session_diag": diag,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: cache-deception surface at "
                    f"{origin}{confirmed['base']}{confirmed['suffix']}. "
                    f"The suffixed path returned a 200 with body "
                    f"similarity {confirmed['similarity']} to the bare "
                    f"path AND cacheable headers "
                    f"({confirmed['cache_reason']}). A CDN keyed on the "
                    "extension will store and reuse the per-user body."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Stop the back-end from returning sensitive HTML on "
                    "static-extension paths, OR force `Cache-Control: "
                    "private, no-store` on every authenticated response.\n"
                    "  - Express / Rails / Django: register a strict "
                    "router that 404s suffixed paths (`/profile.css`, "
                    "etc.) instead of falling through to the catch-all.\n"
                    "  - At the edge: configure the CDN to NOT cache "
                    "responses carrying an `Authorization` header, "
                    "regardless of URL extension.\n"
                    "  - On every authenticated response, set "
                    "`Cache-Control: private, no-store, max-age=0` -- "
                    "the cache must never be allowed to store it.\n"
                    "Audit the cache for poisoned entries: bust the CDN "
                    "for `/<base>.<ext>` paths during the exposure "
                    "window."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} base/suffix "
                     f"combinations on {origin}; no suffixed path "
                     "returned cacheable content matching the bare-path "
                     "body."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CacheDeceptionPathExtensionProbe().main()
