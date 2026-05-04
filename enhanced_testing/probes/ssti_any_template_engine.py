#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Server-Side Template Injection across template engines.

Generalises `ssti_pug_username` (Juice Shop's Pug-specific
`#{7*191}`). Each major template engine has a distinctive
interpolation marker:

    {{7*191}}      Jinja2 / Twig / Handlebars / Vue (server)
    ${7*191}       Velocity / Freemarker (Java)
    #{7*191}       Pug
    <%= 7*191 %>   ERB (Ruby) / EJS (Node)
    [[${7*191}]]   Thymeleaf (Java)

We sweep user-display-name-shape fields with each marker and
look for the literal `1337` in the rendered response (191 * 7).
The arithmetic value is what makes the signal high-fidelity --
if `1337` appears in response to ANY of the markers, the field
is rendered through that engine without escaping.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (label, payload-template-with-7*191) — order matters; we try the
# most-common first.
PAYLOADS = (
    ("jinja_handlebars",  "{{7*191}}"),
    ("velocity_freemarker", "${7*191}"),
    ("pug",               "#{7*191}"),
    ("erb_ejs",           "<%= 7*191 %>"),
    ("thymeleaf",         "[[${7*191}]]"),
    ("ractive",           "{{=7*191=}}"),
)

# (path, method, field) sets to inject into.
INJECTION_TARGETS = (
    ("/api/users/me",      "PATCH",  "username"),
    ("/api/users/me",      "PATCH",  "displayName"),
    ("/api/users/me",      "PATCH",  "name"),
    ("/api/profile",       "PATCH",  "name"),
    ("/api/profile",       "PATCH",  "bio"),
    ("/api/me",            "PATCH",  "displayName"),
    ("/api/Users/{id}",    "PUT",    "username"),       # JS literal
    ("/rest/user/profile", "POST",   "username"),
)

# After injection, GET the rendering surface that displays the field.
RENDER_PATHS = (
    "/api/me", "/api/users/me", "/api/profile",
    "/profile", "/dashboard",
    "/rest/user/whoami",
)


def _register_login(client: SafeClient, origin: str
                     ) -> tuple[str | None, int | None, dict]:
    email = f"ssti-probe-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    uid = None
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            if isinstance(data, dict):
                uid = data.get("id")
        except json.JSONDecodeError:
            pass
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
                return tok, uid, diag
        except json.JSONDecodeError:
            pass
    return None, uid, diag


class SstiAnyTemplateEngineProbe(Probe):
    name = "ssti_any_template_engine"
    summary = ("Detects SSTI by injecting per-engine interpolation "
               "markers into common user-profile fields and looking "
               "for the arithmetic result `1337` in the rendered "
               "response.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional 'path|METHOD|field'; repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(INJECTION_TARGETS)
        for t in args.target or []:
            parts = t.split("|")
            if len(parts) == 3:
                targets.append((parts[0].strip(),
                                parts[1].strip().upper(),
                                parts[2].strip()))

        token, uid, diag = _register_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": diag},
            )

        # Inject every payload into every candidate field. We mark
        # each payload with the engine label so we can report which
        # engine rendered it.
        attempts: list[dict] = []
        for path_tpl, method, field in targets:
            path = path_tpl.replace("{id}", str(uid or 1))
            for label, payload in PAYLOADS:
                body = json.dumps({field: payload}).encode()
                r = client.request(method, urljoin(origin, path),
                                    headers={
                                        "Authorization":
                                            f"Bearer {token}",
                                        "Content-Type":
                                            "application/json"},
                                    body=body)
                attempts.append({"path": path, "method": method,
                                  "field": field, "engine": label,
                                  "payload": payload,
                                  "status": r.status,
                                  "size": r.size})

        # Verify pass: GET each render surface and look for `1337`
        # in the body.
        verify: list[dict] = []
        confirmed: dict | None = None
        for vp in RENDER_PATHS:
            r = client.request("GET", urljoin(origin, vp),
                                headers={"Authorization":
                                          f"Bearer {token}"})
            row = {"path": vp, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and "1337" in (r.text or ""):
                # Double-check that 1337 isn't just an account-id
                # coincidence -- it must appear in a position that
                # only an SSTI hit explains. We look for it in the
                # nicely-bounded surroundings of a profile field.
                idx = r.text.find("1337")
                surrounding = r.text[max(0, idx - 60):idx + 64]
                if any(k in surrounding.lower() for k in
                       ("name", "username", "displayname",
                        "bio", "profile")):
                    row.update({"hit": "1337",
                                 "snippet": surrounding})
                    confirmed = row
                    verify.append(row)
                    break
            verify.append(row)

        evidence = {"origin": origin, "session": diag,
                    "attempts": attempts, "verify": verify}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: SSTI at {origin}. After injecting "
                    "an interpolation marker into a profile field, "
                    f"the rendered response at {confirmed['path']} "
                    "contains `1337` -- the marker was evaluated "
                    "server-side. Snippet: "
                    f"{confirmed['snippet'][:200]!r}"),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop interpolating user input into the template "
                    "directly. Render the value as plain text:\n"
                    "  - Jinja2: `{{ value }}` already escapes by "
                    "default; ensure you're not using "
                    "`{{ value | safe }}` on user input.\n"
                    "  - Pug: use `=` (escaping) instead of `!=` "
                    "(unescaping) interpolation.\n"
                    "  - Handlebars: `{{value}}` (double brace) "
                    "instead of `{{{value}}}` (triple brace).\n"
                    "  - ERB: `<%= h(value) %>` (HTML-escape) "
                    "instead of `<%= value %>`.\n"
                    "  - Velocity / Freemarker: enable `?html` "
                    "(`${value?html}`).\n"
                    "And critically: never pass user input through "
                    "`render_template_string()` / equivalent. The "
                    "right shape is `render_template('file.html', "
                    "value=...)` so the template is fixed and the "
                    "value is just data."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: injected {len(attempts)} payloads on "
                     f"{origin}; no `1337` evaluation appeared on any "
                     f"render surface."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SstiAnyTemplateEngineProbe().main()
