#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Audit log integrity: an authenticated endpoint that records the
client IP into the user's `lastLoginIp` (or equivalent audit-trail
field) trusts a client-supplied HTTP header (True-Client-IP,
X-Forwarded-For, X-Real-IP) instead of the TCP connection's source.

The OWASP Juice Shop /rest/saveLoginIp is the canonical case: it
reads `True-Client-IP` from the request and writes that value to the
user record, allowing any authenticated session to forge its own
recorded source IP. The impact is on audit / forensic attribution,
not on access control -- but defenders relying on `lastLoginIp` to
detect impossible-travel / unfamiliar-network sign-ins will see
attacker-controlled values.

Probe strategy:
  1. Register a fresh user (so the audit trail change affects only
     a probe account, never a real one).
  2. Capture the baseline `lastLoginIp` by GETting /api/Users/<id>.
  3. Issue a request to /rest/saveLoginIp (or similar) with
     True-Client-IP: 10.0.0.1 set.
  4. Re-GET the user record. If the stored `lastLoginIp` now reads
     `10.0.0.1`, the header was honored.

The probe leaves the probe user with `lastLoginIp=10.0.0.1` -- a
canary value the analyst can recognise.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

SAVE_PATHS = (
    "/rest/saveLoginIp",
    "/rest/saveLoginIP",
    "/api/saveLoginIp",
    "/rest/user/saveLoginIp",
)
PROFILE_PATHS = (
    "/api/Users/{uid}",
    "/api/users/{uid}",
    "/rest/user/whoami",
)
SPOOFABLE_HEADERS = (
    ("True-Client-IP", "10.0.0.1"),
    ("X-Forwarded-For", "10.0.0.2"),
    ("X-Real-IP", "10.0.0.3"),
    ("X-Originating-IP", "10.0.0.4"),
    ("CF-Connecting-IP", "10.0.0.5"),
)


def _register_login(client: SafeClient, origin: str) -> dict:
    email = f"ipspoof-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None}
    client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({
            "email": email, "password": pw, "passwordRepeat": pw,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode())
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({"email": email, "password": pw}).encode())
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = (doc.get("authentication") or {})
            out["token"] = auth.get("token")
            out["user_id"] = auth.get("bid") or auth.get("UserId") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


def _read_login_ip(client: SafeClient, origin: str, token: str,
                   user_id) -> tuple[str | None, dict]:
    for tmpl in PROFILE_PATHS:
        path = tmpl.format(uid=user_id) if "{uid}" in tmpl else tmpl
        if "{uid}" in tmpl and user_id is None:
            continue
        r = client.request("GET", urljoin(origin, path), headers={
            "Authorization": f"Bearer {token}"})
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        body = doc.get("data") if isinstance(doc, dict) and "data" in doc else doc
        if isinstance(body, dict):
            user = body.get("user") if isinstance(body.get("user"), dict) else body
            ip = user.get("lastLoginIp") or user.get("last_login_ip")
            if isinstance(ip, str):
                return ip, {"profile_path": path}
    return None, {}


class ConfigTrueClientIpSpoofableProbe(Probe):
    name = "config_true_client_ip_spoofable"
    summary = ("Detects audit-trail / lastLoginIp recording endpoints "
               "that trust client-supplied IP headers (True-Client-IP, "
               "X-Forwarded-For, X-Real-IP).")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sess = _register_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        user_id = sess.get("user_id")

        baseline_ip, _ = _read_login_ip(client, origin, token, user_id)

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path in SAVE_PATHS:
            for hdr_name, hdr_value in SPOOFABLE_HEADERS:
                url = urljoin(origin, path)
                r = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}",
                    hdr_name: hdr_value,
                })
                row = {"path": path, "header": hdr_name,
                       "value": hdr_value,
                       "status": r.status, "size": r.size}
                if r.status != 200:
                    attempts.append(row)
                    continue
                stored_ip, _ = _read_login_ip(
                    client, origin, token, user_id)
                row["stored_ip_after"] = stored_ip
                if stored_ip == hdr_value:
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "baseline_ip": baseline_ip, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: audit-trail IP recording on "
                    f"{origin}{confirmed['path']} honored attacker-"
                    f"supplied header `{confirmed['header']}: "
                    f"{confirmed['value']}` -- the user record now "
                    f"shows lastLoginIp={confirmed['stored_ip_after']!r}. "
                    "Authenticated callers can forge their own audit "
                    "trail value."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="low",
                remediation=(
                    "Derive the client IP from the TCP connection "
                    "(`req.socket.remoteAddress` in Node, "
                    "`request.META['REMOTE_ADDR']` in Django, etc.) "
                    "rather than from client-supplied HTTP headers. "
                    "If you operate behind a trusted reverse proxy "
                    "that populates X-Forwarded-For, validate that "
                    "the immediate hop is on a trusted-IP allowlist "
                    "before reading the header, and reject the header "
                    "when the request arrives from anything else. "
                    "Combine the recorded IP with additional context "
                    "(user-agent, timestamp, session id) so forensic "
                    "attribution does not hinge on a single spoofable "
                    "value."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} (path, header) "
                     f"combinations on {origin}; no spoofed IP value "
                     "was written to the audit trail."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ConfigTrueClientIpSpoofableProbe().main()
