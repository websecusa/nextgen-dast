#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: forced-browsing returns the user list with hashes.

The classic A01 (Broken Access Control) issue — endpoints that ought
to require authentication serve their data to anyone who knows the
URL. The high-fidelity finding is the user list specifically: it
returns email addresses and password hashes, which together feed
offline cracking and credential-stuffing campaigns.

This probe issues an unauthenticated GET against the /api/Users
endpoint family and asserts both:
  (a) the response is HTTP 200 with a JSON-array body
  (b) at least one element has both an email and a password-shaped
      field (hash, salt, etc.)
The dual signal stops us from false-positiving on a stub
`/api/Users` that returns `[]` on demo deploys.

Tested against:
  + OWASP Juice Shop  /api/Users returns the seeded user list
                      including admin@juice-sh.op and bcrypt-style
                      hashes → validated=True.
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that, when unauthenticated, should return 401/403. A 200
# with a body shaped like a user list is the bug.
USER_LIST_PATHS = (
    "/api/Users",
    "/api/users",
    "/rest/users",
    "/api/v1/users",
    "/admin/users",
    "/users",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PW_FIELD_KEYS = {"password", "passwordHash", "password_hash",
                  "hashedPassword", "passwd", "pwd"}


def _looks_like_user_list(text: str) -> tuple[bool, dict]:
    """Return (is_user_list, evidence). True only when the body parses
    as a JSON envelope containing AT LEAST ONE record with an email-
    shaped field AND a password-shaped field."""
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return False, {}
    rows = []
    if isinstance(doc, list):
        rows = doc
    elif isinstance(doc, dict):
        # Common envelopes: {data: [...]}, {users: [...]}.
        for k in ("data", "users", "items", "results"):
            if isinstance(doc.get(k), list):
                rows = doc[k]; break
    if not rows:
        return False, {}
    sample_emails: list[str] = []
    has_pw = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        # email present
        for k in ("email", "Email", "username", "userName", "user_email"):
            v = row.get(k)
            if isinstance(v, str) and _EMAIL_RE.match(v):
                sample_emails.append(v)
                break
        # password-shaped field present
        for k in row:
            if k in _PW_FIELD_KEYS or "password" in k.lower():
                has_pw = True
                break
    if sample_emails and has_pw:
        return True, {"emails_seen": sample_emails[:5],
                      "row_count": len(rows)}
    return False, {}


class ForceBrowseUserListProbe(Probe):
    name = "authz_admin_section_force_browse"
    summary = ("Detects unauthenticated access to the user list "
               "(emails + password hashes) via forced browsing.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional admin/user-list path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(USER_LIST_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                ok, found = _looks_like_user_list(r.text)
                if ok:
                    row.update({"force_browse_succeeded": True, **found})
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: unauthenticated GET on "
                         f"{origin}{confirmed['path']} returned "
                         f"{confirmed.get('row_count','?')} user "
                         f"records with both email and password-shaped "
                         f"fields. Sample: "
                         + ", ".join(confirmed.get("emails_seen", [])) + "."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Gate the user-list endpoint behind authentication "
                    "AND an authorization check (admin only). The "
                    "current default of 'no auth required' is the OWASP "
                    "A01:2021 textbook example.\n"
                    "Strip the password / passwordHash / salt fields "
                    "from any serialized user record — even an admin "
                    "rarely needs the raw hash returned in JSON. ORM "
                    "serializers should default-deny these fields.\n"
                    "Rotate every password reachable in the dump — "
                    "assume the hashes were captured during the "
                    "exposure window and run a force-rotate-on-next-"
                    "login flow for affected accounts."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} user-list paths "
                     f"on {origin}; none returned an unauthenticated "
                     "user dump."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ForceBrowseUserListProbe().main()
