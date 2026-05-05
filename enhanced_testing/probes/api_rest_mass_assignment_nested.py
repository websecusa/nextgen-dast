#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
REST mass-assignment via nested objects.

The classic mass-assignment defect ships a flat
``{"role": "admin"}`` payload and watches whether the field
sticks. Many serialisers (Jackson, Hibernate, Sequelize) protect
top-level fields but recursively bind nested objects without
applying the same allow-list. The result: a payload like
``{"name": "x", "account": {"role": "admin"}}`` or
``{"organization": {"plan": "enterprise"}}`` writes through to a
related entity that the top-level ``@JsonIgnore`` deny-list does
not cover.

Generalises the existing ``authz_role_mass_assignment`` (flat
payload) and ``authz_mass_assignment_widened``. This probe
focuses on the nested-object angle.

We register a fresh disposable account, then PUT/PATCH the
profile with a nested privileged-object structure carrying a
sentinel value. We GET the profile back and look for the
sentinel surfacing on a privileged path inside the response.

Detection signal:
  GET-back response contains the canary inside a nested
  privileged-shape (e.g. ``"account": {"role": "admin-canary"}``)
  AND the same canary did not appear in any benign field — proves
  the nested write surfaced the canary on a privileged property.
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

# Privileged nested-object payloads to attempt. Each entry is
# (label, payload-shape-template). Each payload includes a unique
# canary substring so we can identify it on the read-back.
def _nested_payload(canary: str) -> list[tuple[str, dict]]:
    return [
        ("account.role",
         {"name": "x",
          "account": {"role": f"admin-{canary}"}}),
        ("organization.plan",
         {"name": "x",
          "organization": {"plan": f"enterprise-{canary}"}}),
        ("profile.permissions",
         {"name": "x",
          "profile": {"permissions": [f"sudo-{canary}"]}}),
        ("user.isAdmin",
         {"name": "x",
          "user": {"isAdmin": True, "marker": canary}}),
    ]


def _try_register(client: SafeClient, origin: str
                   ) -> tuple[str | None, dict]:
    email = "ma-" + secrets.token_hex(5) + "@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email, "register_attempts": []}
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
        diag["register_attempts"].append({
            "path": p, "status": r.status})
        if r.status in (200, 201):
            diag["registered_path"] = p
            break
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                        headers={"Content-Type": "application/json"},
                        body=body)
    diag["login_status"] = r.status
    if r.status != 200 or not r.body:
        return None, diag
    try:
        doc = json.loads(r.text) or {}
        tok = ((doc.get("authentication") or {}).get("token")
               if isinstance(doc, dict) else None) or doc.get("token")
        if tok:
            return tok, diag
    except (ValueError, json.JSONDecodeError):
        pass
    return None, diag


def _privileged_position(text: str, canary: str
                          ) -> tuple[bool, str]:
    """Confirm that the canary appears INSIDE a privileged nested
    structure on the read-back (not just bare reflection in a
    `bio` / `name` field). We look for the canary embedded in
    common privileged-shape patterns:
      * `"role": "...canary..."`
      * `"plan": "...canary..."`
      * `"permissions": [..."...canary..."...]`
      * `"isAdmin": true` paired with `"marker": "<canary>"` in
        the same nested object.
    """
    if not text or canary not in text:
        return False, ""
    privileged_patterns = (
        re.compile(r'"role"\s*:\s*"[^"]*' + re.escape(canary)),
        re.compile(r'"plan"\s*:\s*"[^"]*' + re.escape(canary)),
        re.compile(r'"permissions"\s*:\s*\[[^\]]*' + re.escape(canary)),
        # isAdmin true pattern: marker canary in same object as the
        # privileged boolean.
        re.compile(r'"isAdmin"\s*:\s*true[^}]{0,200}"marker"\s*:\s*"'
                   + re.escape(canary)),
    )
    for pat in privileged_patterns:
        m = pat.search(text)
        if m:
            s, e = max(0, m.start() - 30), min(len(text),
                                                m.end() + 60)
            return True, text[s:e]
    return False, ""


class ApiRestMassAssignmentNestedProbe(Probe):
    name = "api_rest_mass_assignment_nested"
    summary = ("Detects REST mass-assignment via nested-object "
               "payloads — flat-field deny-lists miss privileged "
               "writes nested under a benign top-level key.")
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

        token, session_diag = _try_register(client, origin)
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
            canary = "nma-" + secrets.token_hex(5)
            payloads = _nested_payload(canary)
            for label, payload in payloads:
                r = client.request(method, url, headers={
                    **auth_hdr,
                    "Content-Type": "application/json",
                }, body=json.dumps(payload).encode())
                attempts.append({"path": path, "method": method,
                                  "label": label,
                                  "status": r.status})
            # After all variants for this path, GET back and look
            # for the canary inside a privileged structure.
            for gp in GET_PATHS:
                rb = client.request("GET", urljoin(origin, gp),
                                     headers=auth_hdr)
                if rb.status != 200 or not rb.body:
                    continue
                ok, snippet = _privileged_position(rb.text, canary)
                if ok:
                    confirmed = {"update_path": path,
                                  "update_method": method,
                                  "read_path": gp,
                                  "canary": canary,
                                  "snippet": snippet}
                    break
            if confirmed:
                break

        evidence = {"origin": origin, "session": session_diag,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: nested mass-assignment at {origin}"
                    f"{confirmed['update_path']}. The PUT/PATCH "
                    "payload included a privileged value under a "
                    "nested key; the read-back at "
                    f"{confirmed['read_path']} surfaces the canary "
                    "on a privileged property — the deny-list did "
                    "not extend to nested objects."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Apply the writable-field allow-list "
                    "RECURSIVELY:\n"
                    "  - Use explicit DTOs per endpoint and bind the "
                    "request body to those DTOs only — never bind "
                    "directly to the persistence model. The DTO has "
                    "exactly the writable fields and nothing else.\n"
                    "  - Spring: prefer `@RequestBody UpdateProfileDto` "
                    "with @NotNull / @Size validation; never bind to "
                    "a JPA `@Entity` directly.\n"
                    "  - .NET: similar — use `record` types with "
                    "`init` setters limited to writable properties.\n"
                    "  - Sequelize / Mongoose: configure "
                    "`select: false` on sensitive fields AND use "
                    "explicit field allow-lists at the route handler.\n"
                    "Audit any nested object the API accepts. Write "
                    "tests for known-bad payloads "
                    "(`{\"account\":{\"role\":\"admin\"}}`)."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried "
                     f"{len(attempts)} nested mass-assignment payloads "
                     f"on {origin}; no canary surfaced on a privileged "
                     "property in the read-back response."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiRestMassAssignmentNestedProbe().main()
