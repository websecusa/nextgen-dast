#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: broken object property level authorization
(BOPLA / API3:2023) — `?fields=` selector returns hidden columns.

Some APIs implement a `?fields=…` (or `?include=`, `?select=`)
projection helper that simply forwards the field list to the ORM
without filtering against an allowlist of fields the caller is
allowed to see. Asking for `password_hash` or `ssn` then leaks the
underlying column.

Probe approach:
  1. Register a fresh probe account, log in, capture token.
  2. Establish a control read of the user object via the standard
     "me" endpoint with no `fields=` parameter; record which fields
     are present in the normal response.
  3. Issue the inflated request with a fields list that includes
     unambiguously-sensitive names that should NEVER be returned
     (`password_hash`, `ssn`, `mfa_secret`, …).
  4. Issue the same inflation as a GraphQL query if the endpoint
     responds.
  5. Declare a finding only when (a) the inflated response returns
     200, (b) at least one truly-sensitive field appears with a
     non-null value, AND (c) that field was NOT in the control
     response (the normal response shape didn't already include it).

Detection signal:
  inflated GET returns 200 + response contains a sensitive field
  whose value is non-null AND the same field was absent from the
  control response.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# "Me" / self-profile endpoints in priority order.
ME_PATHS = (
    "/api/users/me",
    "/api/user/me",
    "/api/me",
    "/rest/user/whoami",
    "/api/users/{id}",
)

# Sensitive field names. These are explicit enough that a real API
# response containing them with non-null values is almost certainly
# a leak — no false-positive risk from generic terms like "name".
SENSITIVE_FIELDS = (
    "password",
    "password_hash",
    "passwordHash",
    "passwordDigest",
    "ssn",
    "socialSecurityNumber",
    "mfa_secret",
    "totpSecret",
    "totp_secret",
    "creditCardNumber",
    "credit_card_number",
    "apiKey",
    "api_key",
    "internalNotes",
    "internal_notes",
)

# Inflation parameter names commonly understood by API helpers.
FIELD_PARAMS = ("fields", "include", "select", "expand")

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"bopla-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
            out["user_id"] = (auth.get("uid") or auth.get("id"))
        except json.JSONDecodeError:
            pass
    return out


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/json"}


def _flatten_keys(node, out: set) -> None:
    """Walk a JSON tree and collect every key seen at any depth."""
    if isinstance(node, dict):
        for k, v in node.items():
            out.add(k)
            _flatten_keys(v, out)
    elif isinstance(node, list):
        for item in node:
            _flatten_keys(item, out)


def _walk_for_field(node, field: str) -> list[object]:
    found: list[object] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == field and v is not None and v != "":
                found.append(v)
            else:
                found.extend(_walk_for_field(v, field))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_for_field(item, field))
    return found


def _mask(value: object) -> str:
    s = str(value)
    if len(s) <= 12:
        return s
    return s[:6] + "*" * max(0, len(s) - 10) + s[-4:]


class ObjectPropertyFieldInflationProbe(Probe):
    name = "authz_object_property_field_inflation"
    summary = ("Detects broken object-property-level authorization: "
               "`?fields=` selector returns hidden user columns like "
               "password_hash and ssn.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--me-path", action="append", default=[],
            help="Additional self-profile endpoint to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: throwaway account + token.
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: probe could not register / "
                         f"log in on {origin} "
                         f"(register={sess.get('register_status')}, "
                         f"login={sess.get('login_status')})."),
                evidence={"origin": origin,
                           "register_status": sess.get("register_status"),
                           "login_status": sess.get("login_status")},
            )

        token = sess["token"]
        candidate_paths = list(ME_PATHS) + list(args.me_path or [])

        # Step 2: control read — find a "me" endpoint that responds and
        # capture its baseline field set.
        control_path: str | None = None
        control_keys: set[str] = set()
        control_attempts: list[dict] = []
        for path in candidate_paths:
            url = urljoin(origin, path.format(id=sess.get("user_id") or ""))
            r = client.request("GET", url, headers=_bearer(token))
            row = {"path": path, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    doc = None
                if isinstance(doc, (dict, list)):
                    keys: set[str] = set()
                    _flatten_keys(doc, keys)
                    control_path = path
                    control_keys = keys
                    row["baseline_key_count"] = len(keys)
                    control_attempts.append(row)
                    break
            control_attempts.append(row)

        if not control_path:
            return Verdict(
                validated=False, confidence=0.7,
                summary=(f"Inconclusive: no self-profile endpoint on "
                         f"{origin} returned a usable JSON baseline; "
                         "cannot evaluate field inflation."),
                evidence={"origin": origin,
                           "control_attempts": control_attempts},
            )

        # Step 3: REST inflation. We bundle every sensitive field name
        # into one comma-separated value per request, and try each
        # `fields` / `include` / `select` parameter name. Stop on the
        # first leak.
        sensitive_csv = ",".join(SENSITIVE_FIELDS)
        leaks: list[dict] = []
        rest_attempts: list[dict] = []
        base = urljoin(origin, control_path.format(
            id=sess.get("user_id") or ""))
        for param in FIELD_PARAMS:
            sep = "&" if "?" in base else "?"
            url = base + sep + param + "=" + sensitive_csv
            r = client.request("GET", url, headers=_bearer(token))
            row = {"channel": "rest", "param": param,
                   "status": r.status, "size": r.size}
            rest_attempts.append(row)
            if r.status != 200 or not r.body:
                continue
            try:
                doc = json.loads(r.text)
            except (ValueError, json.JSONDecodeError):
                continue
            for field in SENSITIVE_FIELDS:
                vals = _walk_for_field(doc, field)
                if not vals:
                    continue
                # Two-signal gate: field was NOT in the control
                # baseline, and the inflated response returns it
                # populated. If it WAS in the baseline, this isn't a
                # property-level authz finding — it's a different
                # bug class (sensitive data in default response,
                # already covered elsewhere).
                if field in control_keys:
                    continue
                leaks.append({"channel": "rest", "param": param,
                               "field": field, "value_count": len(vals),
                               "sample_excerpt": _mask(vals[0])})
            if leaks:
                break

        # Step 4: GraphQL equivalent — only if no REST leak yet, to
        # bound budget. We ask for the same sensitive fields on a
        # `me { … }` root selection.
        graphql_attempts: list[dict] = []
        if not leaks:
            gql_query = "{ me { %s } }" % " ".join(SENSITIVE_FIELDS)
            for gpath in GRAPHQL_PATHS:
                url = urljoin(origin, gpath)
                body = json.dumps({"query": gql_query}).encode()
                r = client.request("POST", url, headers={
                    **_bearer(token),
                    "Content-Type": "application/json",
                }, body=body)
                row = {"channel": "graphql", "path": gpath,
                       "status": r.status, "size": r.size}
                graphql_attempts.append(row)
                if r.status != 200 or not r.body:
                    continue
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    continue
                data = doc.get("data") if isinstance(doc, dict) else None
                if not data:
                    continue
                for field in SENSITIVE_FIELDS:
                    vals = _walk_for_field(data, field)
                    if vals and field not in control_keys:
                        leaks.append({"channel": "graphql",
                                       "path": gpath,
                                       "field": field,
                                       "value_count": len(vals),
                                       "sample_excerpt": _mask(vals[0])})
                if leaks:
                    break

        evidence = {"origin": origin,
                    "session_email": sess["email"],
                    "control_path": control_path,
                    "control_key_count": len(control_keys),
                    "control_attempts": control_attempts,
                    "rest_attempts": rest_attempts,
                    "graphql_attempts": graphql_attempts}

        if leaks:
            top = leaks[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: object-property authz inflation "
                         f"on {origin} — `{top['channel']}` request "
                         f"with `{top.get('param') or top.get('path')}` "
                         f"returned hidden field `{top['field']}` "
                         f"(value masked: {top['sample_excerpt']}). "
                         "This field was not present in the control "
                         "response."),
                evidence={**evidence, "leaks": leaks},
                severity_uplift="high",
                remediation=(
                    "Maintain a server-side allowlist of fields the "
                    "API may project, and ignore any name in the "
                    "client-supplied `fields=` parameter that isn't "
                    "on the list. Concrete options:\n"
                    "  - Define a serializer / DTO that lists exactly "
                    "the public fields; never serialize the model "
                    "object directly.\n"
                    "  - In Hibernate / JPA, use entity views or "
                    "@JsonIgnore on sensitive columns. In Sequelize, "
                    "use `attributes: { exclude: [...] }` or a default "
                    "scope that hides them.\n"
                    "  - Add an integration test that asserts the "
                    "/me endpoint with `?fields=password_hash` returns "
                    "400 or 200-without-the-field."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(rest_attempts)} REST "
                     f"and {len(graphql_attempts)} GraphQL inflation "
                     f"variants on {origin}; no sensitive field "
                     "appeared that wasn't already in the baseline."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ObjectPropertyFieldInflationProbe().main()
