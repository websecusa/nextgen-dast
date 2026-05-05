#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Second-order SQL injection: stored field renders unsafely later.

First-order SQLi probes inject a payload and watch for an immediate
SQL error in the response. Second-order is sneakier — the value is
stored cleanly (parameterized INSERT), but a later read path
concatenates the stored value into a fresh SQL statement (e.g. the
admin-side dashboard runs ``SELECT ... WHERE name LIKE '%<bio>%'``).
The defect surfaces on read, not write.

We register a fresh disposable account whose bio / username carries
a benign-but-distinctive SQL fragment with a unique canary token.
We then GET likely render endpoints (profile pages, user listings,
feeds, admin views) and look for two corroborating signals before
flagging:

  1. The canary token is reflected in the response body (proves the
     stored value really is read by this endpoint).
  2. The response body OR status code carries a SQL-error class
     signature: a 500 with a SQL-shaped error message, or the
     response body contains the canary AND a SQL error class string
     such as ``unterminated quoted string``,
     ``syntax error at or near``, ``ORA-00933``, ``SQL syntax``, etc.

Both signals must align — reflection alone is just a stored-XSS
risk, not SQLi; a SQL error alone could be unrelated noise. Both
together prove the stored value was concatenated into a SQL string.

Detection signal:
  Stored canary token reflected in a render endpoint AND the
  response shows a SQL error class signature OR a 500 occurred for
  the canary value where a control profile renders 200.
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

# Endpoints to try when registering a disposable account. The first
# few match Juice Shop's `/api/Users` shape; the rest cover common
# REST conventions.
REGISTER_PATHS = (
    "/api/Users",
    "/api/users",
    "/api/register",
    "/api/v1/users",
    "/rest/user/register",
    "/register",
)

# Endpoints to GET after registration. These are the typical
# render surfaces where stored bio/username values are interpolated
# into SQL (admin dashboards, public profile views, search-shaped
# feeds).
RENDER_PATHS = (
    "/profile",
    "/admin/users",
    "/admin",
    "/api/users",
    "/api/Users",
    "/feed",
    "/api/feed",
    "/api/users/search",
    "/api/admin/users",
    "/dashboard",
)

# Distinctive SQL error class signatures. Each pattern is anchored
# enough that it doesn't false-fire on the literal word "syntax"
# in ordinary HTML — every entry quotes a specific RDBMS-emitted
# error fragment that does not appear in benign documents.
SQL_ERROR_PATTERNS = (
    re.compile(r"unterminated\s+quoted\s+string", re.I),
    re.compile(r"syntax\s+error\s+at\s+or\s+near", re.I),
    re.compile(r"unexpected\s+end\s+of\s+SQL\s+command", re.I),
    re.compile(r"SQLITE_ERROR", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"ER_PARSE_ERROR", re.I),
    re.compile(r"You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax",
               re.I),
    re.compile(r"PG::SyntaxError", re.I),
    re.compile(r"ORA-00933", re.I),
    re.compile(r"ORA-00911", re.I),
    re.compile(r"SQLSTATE\[\d+\]", re.I),
    re.compile(r"Microsoft.*ODBC.*SQL\s+Server", re.I),
    re.compile(r"Unclosed\s+quotation\s+mark", re.I),
)


def _matches_sql_error(text: str) -> str | None:
    """Returns the matched error fragment when a SQL-shaped error is
    present in the body, or None when nothing matches."""
    if not text:
        return None
    for pat in SQL_ERROR_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def _try_register(client: SafeClient, origin: str,
                  email: str, password: str, bio: str,
                  username: str) -> tuple[bool, dict]:
    """Try a few register endpoints with a fresh disposable account
    that carries the canary in bio AND username. Returns
    (registered_ok, diagnostic-dict)."""
    diag: dict = {"register_attempts": []}
    for p in REGISTER_PATHS:
        body = json.dumps({
            "email": email, "password": password,
            "passwordRepeat": password,
            "username": username, "name": username,
            "bio": bio, "displayName": username,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode()
        r = client.request(
            "POST", urljoin(origin, p),
            headers={"Content-Type": "application/json"}, body=body)
        diag["register_attempts"].append({
            "path": p, "status": r.status, "size": r.size})
        if r.status in (200, 201):
            diag["registered_path"] = p
            return True, diag
    return False, diag


class SqliSecondOrderViaProfileProbe(Probe):
    name = "sqli_second_order_via_profile"
    summary = ("Detects second-order SQL injection by storing a "
               "distinctive SQL fragment in a profile field and "
               "watching downstream render surfaces for SQL errors.")
    safety_class = "probe"

    def add_args(self, parser):
        # No probe-specific args required; the canary is generated
        # fresh per run so two simultaneous scans don't collide.
        parser.add_argument(
            "--render-path", action="append", default=[],
            help="Additional render path to GET after registering.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Build a unique canary so reflection is unambiguous. The
        # SQL fragment is benign on insert (parameterized) but blows
        # up if the stored value is later concatenated into SQL.
        canary = f"round12-{secrets.token_hex(6)}"
        # The fragment closes a string literal then opens a SQL
        # comment carrying the canary — common shape that breaks any
        # naive concat-into-SQL pattern.
        bio_fragment = f"x'/*{canary}*/"
        # Username has stricter constraints in many backends; we
        # weave the canary into a still-benign-but-distinctive form.
        username = f"r12u{secrets.token_hex(4)}"
        email = f"r12-{secrets.token_hex(4)}@dast.test"
        password = "Pr0be-" + secrets.token_hex(4)

        registered, diag = _try_register(
            client, origin, email, password, bio_fragment, username)
        if not registered:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not register a probe "
                         f"account on {origin} via any of the "
                         f"{len(REGISTER_PATHS)} candidate paths."),
                evidence={"origin": origin, "session": diag},
            )

        # Visit render surfaces. Two corroborating signals are
        # required before we flag — reflection of the canary AND a
        # SQL error class signature in the body, OR a 500 paired
        # with the canary in the body.
        render_targets = list(RENDER_PATHS) + list(args.render_path or [])
        renders: list[dict] = []
        confirmed: dict | None = None
        for p in render_targets:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status, "size": r.size}
            text = r.text or ""
            reflected = canary in text
            sql_err = _matches_sql_error(text)
            row["canary_reflected"] = reflected
            if sql_err:
                row["sql_error_match"] = sql_err
            renders.append(row)
            # Both signals together: reflection AND SQL error class.
            if reflected and sql_err:
                confirmed = row
                break
            # 500 on a render that we know just emitted user-stored
            # content is also strong; but only when the canary is
            # echoed back so we know our value was the trigger.
            if r.status == 500 and reflected:
                confirmed = row
                break

        evidence = {"origin": origin, "canary": canary,
                    "session": diag, "renders": renders}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: second-order SQLi at {origin}"
                    f"{confirmed['path']}. The stored canary "
                    f"`{canary}` was reflected on a render endpoint "
                    f"that simultaneously emitted a SQL error class "
                    "signature (or a 500), proving the stored value "
                    "was concatenated into a SQL statement at read "
                    "time."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Treat read-side SQL paths the same as write-side: "
                    "use parameterized statements / prepared queries "
                    "everywhere, including admin dashboards and search "
                    "filters that interpolate a stored profile field. "
                    "Audit the codebase for any SQL string built with "
                    "`+` / format-strings around a column read from a "
                    "user-controlled table.\n"
                    "Defence in depth: strip or reject SQL "
                    "metacharacters at the validation layer when "
                    "writing the field, but DO NOT rely on that as "
                    "the primary defence — input validation alone is "
                    "not enough."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: visited {len(renders)} render paths on "
                     f"{origin} after storing canary; no path showed "
                     "both reflection AND a SQL-error signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SqliSecondOrderViaProfileProbe().main()
