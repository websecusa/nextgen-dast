#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: mass-assignment of privileged fields beyond just
`role`.

Widens `authz_role_mass_assignment` (which only checks `role`).
Modern apps use a richer privilege vocabulary: `is_admin`,
`isAdmin`, `isSuperUser`, `permissions`, `groups`, `plan`, `tier`,
`verified`, `emailVerified`, `suspended`, `balance`, `credit`,
`accessLevel`, `userType`. The bug shape is identical (POST'd
field gets persisted) but ANY of these privileged fields
qualifies.

High-fidelity signal:
  POST registration with a body containing every privileged-shape
  field at once. Inspect the response for any one of those values
  echoed back. The bug fires per-field; we report which field(s).
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATHS = (
    "/api/Users",
    "/api/users",
    "/register",
    "/api/register",
    "/api/auth/register",
    "/api/v1/users",
)

# Each (field_name, privileged_value, predicate) -- predicate is a
# function that takes the parsed-JSON value and returns True when
# the privileged form is set.
PRIV_FIELDS: tuple[tuple[str, object, str], ...] = (
    ("role",          "admin",       "string"),
    ("isAdmin",       True,          "true"),
    ("is_admin",      True,          "true"),
    ("isSuperUser",   True,          "true"),
    ("isStaff",       True,          "true"),
    ("permissions",   ["*"],         "list-star"),
    ("groups",        ["administrators"], "list-admin"),
    ("plan",          "enterprise",  "string"),
    ("tier",          "premium",     "string"),
    ("verified",      True,          "true"),
    ("emailVerified", True,          "true"),
    ("suspended",     False,         "false"),
    ("balance",       999999,        "number"),
    ("credit",        999999,        "number"),
    ("accessLevel",   "admin",       "string"),
    ("userType",      "admin",       "string"),
)


def _matches(value: object, expected: object, predicate: str) -> bool:
    if predicate == "string":
        return isinstance(value, str) and value == expected
    if predicate == "true":
        return value is True
    if predicate == "false":
        return value is False
    if predicate == "list-star":
        return isinstance(value, list) and "*" in value
    if predicate == "list-admin":
        return (isinstance(value, list)
                and any(isinstance(s, str)
                          and s.lower() in {"admin", "administrators",
                                              "administrator"}
                          for s in value))
    if predicate == "number":
        return isinstance(value, (int, float)) and value >= 1000
    return False


def _walk_for_priv(node, depth: int = 0) -> list[tuple[str, object]]:
    """Return list of (field_name, value) where the privileged
    value is set in the response. Walks 1-2 levels."""
    if depth > 3 or not isinstance(node, dict):
        return []
    found: list[tuple[str, object]] = []
    for fname, fval, pred in PRIV_FIELDS:
        if fname in node and _matches(node[fname], fval, pred):
            found.append((fname, node[fname]))
    for v in node.values():
        if isinstance(v, dict):
            found.extend(_walk_for_priv(v, depth + 1))
    return found


class AuthzMassAssignmentWidenedProbe(Probe):
    name = "authz_mass_assignment_widened"
    summary = ("Detects mass-assignment of privileged fields at "
               "registration -- not just `role`, but is_admin / "
               "permissions / groups / plan / tier / verified / "
               "balance / credit and other common privilege "
               "vocabulary.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--register-path", action="append", default=[],
            help="Additional registration endpoint to try.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(REGISTER_PATHS) + list(args.register_path or [])

        email = f"massassign-{secrets.token_hex(6)}@dast.test"
        pw    = "Pr0be-" + secrets.token_hex(4)
        body_dict: dict = {
            "email": email,
            "password": pw,
            "passwordRepeat": pw,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }
        for fname, fval, _ in PRIV_FIELDS:
            body_dict[fname] = fval
        body = json.dumps(body_dict).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Content-Type": "application/json"}, body=body)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status in (200, 201) and r.body:
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    doc = None
                if isinstance(doc, dict):
                    hits = _walk_for_priv(doc)
                    if hits:
                        row.update({"granted":
                            [{"field": f, "value": v} for f, v in hits],
                            "snippet": (r.text or "")[:300]})
                        confirmed = row
                        attempts.append(row)
                        break
            attempts.append(row)

        evidence = {"origin": origin, "register_email": email,
                    "attempts": attempts}
        if confirmed:
            granted_str = ", ".join(
                f"{g['field']}={g['value']!r}" for g in confirmed["granted"])
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: mass-assignment at "
                    f"{origin}{confirmed['path']} -- the registration "
                    f"endpoint accepted privileged field(s): "
                    f"{granted_str}. The new account "
                    f"{email!r} carries those privileges from the "
                    "request body."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Whitelist the fields the registration endpoint "
                    "may set. Privileged fields (role, is_admin, "
                    "permissions, groups, plan, tier, verified, "
                    "balance, credit) must come from server-side "
                    "logic, never the request body.\n"
                    "  - Sequelize: define a `pick`-list before "
                    "  `User.create()`.\n"
                    "  - Mongoose: typed schema + "
                    "  `User.create({ email, password })` -- never "
                    "  `User.create(req.body)`.\n"
                    "  - Django REST: `extra_kwargs = {'is_admin': "
                    "  {'read_only': True}}`.\n"
                    "  - Rails: `params.require(:user).permit(:email, "
                    "  :password)` (strong params).\n"
                    "Audit existing user records during the exposure "
                    "window for unexpected privilege values."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} registration "
                     f"endpoints on {origin}; none honoured any "
                     "privileged field on registration."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthzMassAssignmentWidenedProbe().main()
