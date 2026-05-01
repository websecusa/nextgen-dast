# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
RESTful API for nextgen-dast.

Surface
=======
Mounted at /api/v1 (under the optional UI_ROOT_PATH prefix).

  POST /api/v1/scans              create an assessment, returns the new scan_id
  GET  /api/v1/scans              list recent assessments
  GET  /api/v1/scans/{id}         status + summary of one assessment
  GET  /api/v1/scans/{id}/results findings, JSON or CSV (?format=csv)
  GET  /api/v1/openapi.json       OpenAPI 3.0 service definition
  GET  /api/v1/postman.json       Postman v2.1 collection
  GET  /api/v1/docs               Swagger UI playground for the API
  GET  /api/v1/health             liveness probe (no auth)

Authentication
==============
Token-based. Tokens are presented in the `Authorization: Bearer <token>`
header (also accepted: `X-API-Token: <token>`).

Token format is OUI-style (12 hex octets, colon-separated):

    4E:47:44:A1:B2:C3:D4:E5:F6:07:18:29
    \\______/ \\___________________________/
       |                |
       NGD vendor       72 bits of random secret
       prefix (fixed)

The first three octets ("4E:47:44" = ASCII "NGD") identify the issuing
product, the remaining nine octets carry the random secret. We store
ONLY the SHA-256 hash of the canonical (uppercase, colon-separated)
token plus the first six octets in the clear, so a DB read never yields
a usable credential.

IP whitelisting
===============
Every token row carries an `allowed_ips` list. The list is comma-
separated and accepts plain IPs (`203.0.113.4`) and CIDR ranges
(`10.0.0.0/8`). Empty list = fail-closed (no callers permitted). The
client's source IP must match at least one entry, or the request is
rejected 403. The client IP is taken from the connection's
`request.client.host` after consulting the standard reverse-proxy
headers (`X-Forwarded-For`, `X-Real-IP`) if the deployment puts a
trusted proxy in front of uvicorn.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               StreamingResponse)
from pydantic import BaseModel, Field

import db
import schedules as schedules_mod


# ---------------------------------------------------------------------------
# Token format helpers
# ---------------------------------------------------------------------------

# Three-octet vendor prefix burned into every token issued by this product.
# 4E 47 44 = ASCII "NGD" (nextgen-dast). Choosing a printable ASCII triplet
# makes tokens self-identifying when seen in logs / proxy traces.
NGD_OUI_PREFIX = "4E:47:44"

# Total octet count in the token (3 vendor + 9 secret = 12). Each octet
# is two hex chars separated by colons, so the canonical string length is
# 12*2 + 11 = 35 characters.
TOKEN_OCTETS = 12
TOKEN_SECRET_OCTETS = TOKEN_OCTETS - 3

TOKEN_RE = re.compile(
    r"^[0-9A-F]{2}(?::[0-9A-F]{2}){" + str(TOKEN_OCTETS - 1) + r"}$"
)


def generate_token() -> str:
    """Mint a fresh OUI-format API token. Returned in the canonical
    UPPER:HEX:OCTET format. The first three octets are always the NGD
    vendor prefix; the remaining nine octets carry 72 bits of secret
    drawn from `secrets.token_bytes`, which uses the OS CSPRNG."""
    secret = secrets.token_bytes(TOKEN_SECRET_OCTETS)
    secret_str = ":".join(f"{b:02X}" for b in secret)
    return f"{NGD_OUI_PREFIX}:{secret_str}"


def normalize_token(raw: str) -> Optional[str]:
    """Accept tokens regardless of case and of whether the caller used
    colons, hyphens, or no separators. Returns the canonical
    UPPERCASE:COLON form, or None if the input cannot be coerced into
    `TOKEN_OCTETS` valid hex octets.
    """
    if not raw:
        return None
    s = raw.strip().upper()
    # Strip any "Bearer " prefix the caller may have left in.
    if s.lower().startswith("bearer "):
        s = s[7:].strip().upper()
    # Allow either separator, or none.
    s = s.replace("-", "").replace(":", "").replace(" ", "")
    if len(s) != TOKEN_OCTETS * 2:
        return None
    if not re.fullmatch(r"[0-9A-F]+", s):
        return None
    canonical = ":".join(s[i:i + 2] for i in range(0, len(s), 2))
    return canonical if TOKEN_RE.match(canonical) else None


def hash_token(token_canonical: str) -> str:
    """SHA-256 hex digest of the canonical token. Stored in api_tokens.
    token_hash so the secret never sits in the DB in plaintext."""
    return hashlib.sha256(token_canonical.encode("ascii")).hexdigest()


def token_prefix(token_canonical: str) -> str:
    """Return the first six octets of a canonical token (vendor prefix
    + first 3 random octets). Stored in api_tokens.prefix and shown in
    the management UI so an admin can identify a token at a glance
    without needing the secret half."""
    parts = token_canonical.split(":")
    return ":".join(parts[:6])


# ---------------------------------------------------------------------------
# IP whitelist helpers
# ---------------------------------------------------------------------------

def parse_allowed_ips(raw: str) -> list[str]:
    """Split a comma/whitespace-separated allowed-ips field into a clean
    list. Each entry is validated as either a single IP address or a
    CIDR range. Invalid entries are dropped (they cannot match anything
    anyway)."""
    if not raw:
        return []
    out: list[str] = []
    for piece in re.split(r"[,\s]+", raw.strip()):
        if not piece:
            continue
        try:
            ipaddress.ip_network(piece, strict=False)
        except ValueError:
            continue
        out.append(piece)
    return out


def ip_allowed(client_ip: str, allowed: list[str]) -> bool:
    """True if `client_ip` matches at least one entry in `allowed`. An
    empty `allowed` list always returns False (fail-closed). Any
    malformed entries are skipped silently."""
    if not allowed or not client_ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in allowed:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if ip_obj in net:
            return True
    return False


def real_client_ip(request: Request) -> str:
    """Resolve the caller's source IP. Honors X-Forwarded-For (first
    address) and X-Real-IP only if the immediate connection is from
    127.0.0.1 — i.e. a trusted local reverse proxy. Direct internet
    callers can't spoof their IP this way because the immediate hop
    won't be loopback."""
    direct = request.client.host if request.client else ""
    if direct in ("127.0.0.1", "::1"):
        xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if xff:
            return xff
        xri = request.headers.get("x-real-ip", "").strip()
        if xri:
            return xri
    return direct


# ---------------------------------------------------------------------------
# Token authentication
# ---------------------------------------------------------------------------

def authenticate_request(request: Request,
                         authorization: Optional[str],
                         x_api_token: Optional[str]) -> dict:
    """Resolve the bearer token + caller IP into an api_tokens row.
    Raises HTTPException(401/403) on any failure. On success returns the
    full token row and updates last_used_{at,ip} so admins can see
    which keys are live."""
    # Accept either header. Authorization wins because it is the
    # convention; X-API-Token is provided as a convenience for clients
    # that can't override Authorization (e.g. some chained proxies).
    raw = ""
    if authorization:
        raw = authorization.strip()
    elif x_api_token:
        raw = x_api_token.strip()
    if not raw:
        raise HTTPException(401, "missing API token")
    canonical = normalize_token(raw)
    if not canonical:
        raise HTTPException(401, "malformed API token")
    if not canonical.startswith(NGD_OUI_PREFIX + ":"):
        # Fast reject for tokens that don't carry the NGD vendor prefix.
        raise HTTPException(401, "token vendor prefix not recognised")
    row = db.query_one(
        "SELECT * FROM api_tokens WHERE token_hash = %s LIMIT 1",
        (hash_token(canonical),))
    if not row or row.get("disabled"):
        raise HTTPException(401, "invalid or disabled API token")
    allowed = parse_allowed_ips(row.get("allowed_ips") or "")
    client_ip = real_client_ip(request)
    if not ip_allowed(client_ip, allowed):
        # Per the requirements: a token is ONLY usable from its
        # whitelisted IPs. The error names the IP so the operator can
        # add it cleanly without trial and error.
        raise HTTPException(403,
            f"source IP {client_ip!r} is not whitelisted for this token")
    db.execute(
        "UPDATE api_tokens SET last_used_at = %s, last_used_ip = %s "
        "WHERE id = %s",
        (datetime.now(timezone.utc).replace(tzinfo=None),
         client_ip[:64], row["id"]),
    )
    return row


# ---------------------------------------------------------------------------
# Token management (used by the admin UI in server.py)
# ---------------------------------------------------------------------------

def list_tokens() -> list[dict]:
    """Return all tokens for the management page. Never returns the
    secret half (it's not stored). `prefix` is sufficient to identify a
    row visually."""
    return db.query(
        "SELECT id, label, prefix, allowed_ips, disabled, "
        "last_used_at, last_used_ip, created_at, notes "
        "FROM api_tokens ORDER BY id DESC")


def create_token(label: str, allowed_ips: str,
                 created_by_user_id: Optional[int] = None,
                 notes: str = "") -> tuple[int, str]:
    """Mint and persist a new token. Returns (id, plaintext_token). The
    plaintext is only available at this moment, ever; the caller MUST
    show it to the operator immediately and then forget it."""
    label = (label or "").strip()[:128] or "unnamed"
    allowed = parse_allowed_ips(allowed_ips or "")
    token = generate_token()
    tid = db.execute(
        "INSERT INTO api_tokens "
        "(label, prefix, token_hash, allowed_ips, created_by_user_id, notes) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (label, token_prefix(token), hash_token(token),
         ",".join(allowed), created_by_user_id, (notes or "").strip()[:2000]),
    )
    return tid, token


def update_token(token_id: int, *, allowed_ips: Optional[str] = None,
                 disabled: Optional[bool] = None,
                 label: Optional[str] = None,
                 notes: Optional[str] = None) -> None:
    """Patch a token row. Each field is optional; pass only what changes."""
    sets: list[str] = []
    params: list[Any] = []
    if allowed_ips is not None:
        sets.append("allowed_ips = %s")
        params.append(",".join(parse_allowed_ips(allowed_ips)))
    if disabled is not None:
        sets.append("disabled = %s")
        params.append(1 if disabled else 0)
    if label is not None:
        sets.append("label = %s")
        params.append((label or "").strip()[:128] or "unnamed")
    if notes is not None:
        sets.append("notes = %s")
        params.append((notes or "").strip()[:2000])
    if not sets:
        return
    params.append(int(token_id))
    db.execute(f"UPDATE api_tokens SET {', '.join(sets)} WHERE id = %s",
               params)


def delete_token(token_id: int) -> None:
    db.execute("DELETE FROM api_tokens WHERE id = %s", (int(token_id),))


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class CreateScanRequest(BaseModel):
    """Body of POST /api/v1/scans. `fqdn` is the only required field;
    everything else mirrors defaults from the web /assess form."""
    fqdn: str = Field(..., examples=["app.example.com",
                                     "app.example.com:8443"])
    application_id: Optional[str] = Field(
        None, max_length=128,
        description="Caller-supplied identifier for the application "
                    "under test (free-form, e.g. CMDB ID).",
        examples=["APP-1234"])
    profile: str = Field(
        "standard",
        description="Scan profile: quick | standard | thorough | premium",
        examples=["standard"])
    llm_tier: str = Field(
        "none",
        description="LLM analysis tier: none | basic | advanced",
        examples=["none"])
    scan_http: bool = Field(True, description="Probe http:// URLs")
    scan_https: bool = Field(True, description="Probe https:// URLs")
    llm_endpoint_id: Optional[int] = Field(
        None, description="Specific LLM endpoint id (else default)")
    user_agent_id: Optional[int] = Field(
        None, description="User-Agent profile id (else default)")
    creds_username: Optional[str] = Field(
        None, description="Application username for authenticated scan")
    creds_password: Optional[str] = Field(
        None, description="Application password for authenticated scan")
    login_url: Optional[str] = Field(
        None, description="Form-POST login URL (used with creds)")
    keep_only_latest: bool = Field(
        False,
        description="When true, the orchestrator's finalize step deletes "
                    "every other completed (done/error/cancelled) "
                    "assessment for the same FQDN once this scan finishes. "
                    "In-flight scans are never touched.")


class CreateScheduleRequest(BaseModel):
    """Body of POST /api/v1/schedules. Mirrors CreateScanRequest plus the
    cron expression and schedule-only knobs."""
    name: str = Field(..., examples=["nightly app.example.com"])
    fqdn: str = Field(..., examples=["app.example.com",
                                     "app.example.com:8443"])
    cron_expr: str = Field(
        ...,
        description="Standard 5-field cron expression in UTC. "
                    "Validated by croniter.",
        examples=["0 2 * * *"])
    application_id: Optional[str] = Field(None, max_length=128)
    profile: str = Field("standard")
    llm_tier: str = Field("none")
    scan_http: bool = Field(True)
    scan_https: bool = Field(True)
    llm_endpoint_id: Optional[int] = None
    user_agent_id: Optional[int] = None
    creds_username: Optional[str] = None
    creds_password: Optional[str] = None
    login_url: Optional[str] = None
    start_after: Optional[str] = Field(
        None,
        description="ISO-8601 datetime; the schedule never fires before "
                    "this moment.")
    end_before: Optional[str] = Field(
        None,
        description="ISO-8601 datetime; once the wall clock passes this, "
                    "the schedule stops firing.")
    enabled: bool = Field(True)
    skip_if_running: bool = Field(
        True,
        description="If a same-FQDN assessment is still in flight when a "
                    "tick is due, skip this round (next_run_at still "
                    "advances).")
    keep_only_latest: bool = Field(
        False,
        description="Carries through to every materialized assessment so "
                    "the orchestrator's finalize step auto-deletes prior "
                    "completed scans for the same FQDN.")


class UpdateScheduleRequest(BaseModel):
    """Body of PATCH /api/v1/schedules/{id}. Every field is optional;
    omitted fields are left untouched. cron_expr / start_after changes
    trigger a recompute of next_run_at."""
    name: Optional[str] = None
    fqdn: Optional[str] = None
    cron_expr: Optional[str] = None
    application_id: Optional[str] = Field(None, max_length=128)
    profile: Optional[str] = None
    llm_tier: Optional[str] = None
    scan_http: Optional[bool] = None
    scan_https: Optional[bool] = None
    llm_endpoint_id: Optional[int] = None
    user_agent_id: Optional[int] = None
    creds_username: Optional[str] = None
    creds_password: Optional[str] = None
    login_url: Optional[str] = None
    start_after: Optional[str] = None
    end_before: Optional[str] = None
    enabled: Optional[bool] = None
    skip_if_running: Optional[bool] = None
    keep_only_latest: Optional[bool] = None


class CreateScanResponse(BaseModel):
    """Echoed back from POST /api/v1/scans."""
    scan_id: int
    fqdn: str
    application_id: Optional[str] = None
    status: str
    profile: str
    llm_tier: str
    created_at: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1", tags=["nextgen-dast"])

LOGS_DIR = Path("/data/logs")


def _opt_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _normalize_fqdn(raw: str) -> str:
    s = (raw or "").strip().lower()
    s = re.sub(r"^https?://", "", s).split("/", 1)[0]
    return s


def _serialize_assessment(a: dict) -> dict:
    """Coerce a DB row into a JSON-serialisable dict. datetime fields
    become ISO 8601 strings; integer / null fields pass through."""
    out: dict[str, Any] = {}
    for k, v in a.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif isinstance(v, (bytes, bytearray)):
            out[k] = v.decode("utf-8", "replace")
        else:
            out[k] = v
    return out


def _public_assessment_fields(a: dict) -> dict:
    """Whitelisted subset of the assessments row exposed to API callers.
    We deliberately omit credentials and worker pids."""
    s = _serialize_assessment(a)
    keep = ("id", "fqdn", "application_id", "scan_http", "scan_https",
            "profile", "llm_tier", "status", "current_step",
            "scan_ids", "total_findings", "risk_score",
            "exec_summary", "llm_cost_usd", "llm_in_tokens",
            "llm_out_tokens", "error_text",
            "created_at", "started_at", "finished_at")
    return {k: s.get(k) for k in keep}


def _spawn_orchestrator(aid: int) -> None:
    """Detached orchestrator subprocess, identical to the web /assess
    flow. Stdout/stderr land in /data/logs/orchestrator_<id>.log so the
    caller can inspect them after the fact."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / f"orchestrator_{aid}.log"
    log_fh = open(log_path, "ab", buffering=0)
    subprocess.Popen(
        ["python", "-m", "scripts.orchestrator", str(aid)],
        stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/app",
    )


# ---- Auth dependency -------------------------------------------------------
#
# We use a small helper (not a FastAPI dependency) so the route bodies stay
# readable and so the same middleware exposes both header names in the
# OpenAPI definition.

def _require_token(request: Request,
                   authorization: Optional[str],
                   x_api_token: Optional[str]) -> dict:
    return authenticate_request(request, authorization, x_api_token)


# ---- Routes ----------------------------------------------------------------

@router.get("/health", summary="Liveness probe (no auth)")
def api_health():
    return {"ok": True, "service": "nextgen-dast", "version": "2.1.1"}


@router.get("/lookups",
            summary="Live id->label maps + enum descriptions (no auth)")
def api_lookups():
    """Help-modal data source for the playground.

    Returns the live id->label maps for the integer-typed FK fields
    (`llm_endpoint_id`, `user_agent_id`) plus the static enum tables
    (`profile`, `llm_tier`, `format`). The playground at /api/v1/docs
    fetches this on load so the help modal can show
    "id 3 = anthropic-claude-opus-4-7" instead of forcing the operator
    to guess valid integers.

    No auth required: the data here is operational metadata (labels,
    not secrets, no API keys). Mirrors the no-auth posture of /docs
    and /openapi.json so the playground works before the operator has
    minted a token.
    """
    llm_endpoints: list[dict] = []
    user_agents: list[dict] = []
    if db.healthy():
        for r in db.query(
                "SELECT id, name, model, backend, is_default "
                "FROM llm_endpoints ORDER BY is_default DESC, name"):
            tag = " (default)" if r.get("is_default") else ""
            llm_endpoints.append({
                "id": r["id"],
                "label": f"{r['name']} — {r['model']} [{r['backend']}]{tag}",
                "name": r["name"],
                "model": r["model"],
                "backend": r["backend"],
                "is_default": bool(r.get("is_default")),
            })
        for r in db.query(
                "SELECT id, label, is_default FROM user_agents "
                "ORDER BY is_default DESC, label"):
            tag = " (default)" if r.get("is_default") else ""
            user_agents.append({
                "id": r["id"],
                "label": f"{r['label']}{tag}",
                "is_default": bool(r.get("is_default")),
            })
    return {
        "llm_endpoints": llm_endpoints,
        "user_agents": user_agents,
        "profiles": [
            {"value": "quick",
             "label": "~5 min — testssl + nuclei (curated tags)"},
            {"value": "standard",
             "label": "~30-60 min — testssl + nuclei + nikto + wapiti default"},
            {"value": "thorough",
             "label": "hours — standard + wapiti -m all + sqlmap on detected forms"},
            {"value": "premium",
             "label": "slowest — thorough + sqlmap + dalfox + in-house high-fidelity probe pass"},
        ],
        "llm_tiers": [
            {"value": "none",
             "label": "scanners only, no LLM, no extra cost"},
            {"value": "basic",
             "label": "rollup + executive summary (~$5-10 / scan)"},
            {"value": "advanced",
             "label": "per-flow deep analysis + rollup (~$50-100 / scan)"},
        ],
        "formats": [
            {"value": "json", "label": "structured JSON (default)"},
            {"value": "csv",
             "label": "RFC 4180 CSV (comma delimiter, CRLF line endings)"},
        ],
    }


@router.post("/scans", response_model=CreateScanResponse,
             status_code=201, summary="Create a new scan")
def api_create_scan(
    body: CreateScanRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Queue a new assessment. The orchestrator runs detached, so this
    endpoint returns immediately with the scan id. Poll
    `GET /api/v1/scans/{id}` for status, then
    `GET /api/v1/scans/{id}/results` once the status is `done`."""
    _require_token(request, authorization, x_api_token)
    fqdn = _normalize_fqdn(body.fqdn)
    if not fqdn:
        raise HTTPException(400, "fqdn required")
    if body.profile not in ("quick", "standard", "thorough", "premium"):
        raise HTTPException(400, "invalid profile")
    if body.llm_tier not in ("none", "basic", "advanced"):
        raise HTTPException(400, "invalid llm_tier")
    application_id = (body.application_id or "").strip()[:128] or None
    aid = db.execute(
        """INSERT INTO assessments
           (fqdn, scan_http, scan_https, profile, llm_tier, llm_endpoint_id,
            user_agent_id, creds_username, creds_password, login_url,
            application_id, keep_only_latest, status)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'queued')""",
        (fqdn,
         1 if body.scan_http else 0,
         1 if body.scan_https else 0,
         body.profile, body.llm_tier,
         _opt_int(body.llm_endpoint_id),
         _opt_int(body.user_agent_id),
         (body.creds_username or None),
         (body.creds_password or None),
         (body.login_url or None),
         application_id,
         1 if body.keep_only_latest else 0),
    )
    _spawn_orchestrator(aid)
    row = db.query_one(
        "SELECT id, fqdn, application_id, status, profile, llm_tier, "
        "created_at FROM assessments WHERE id = %s", (aid,))
    return JSONResponse(status_code=201, content={
        "scan_id": row["id"],
        "fqdn": row["fqdn"],
        "application_id": row.get("application_id"),
        "status": row["status"],
        "profile": row["profile"],
        "llm_tier": row["llm_tier"],
        "created_at": row["created_at"].isoformat()
            if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
    })


@router.get("/scans", summary="List recent scans")
def api_list_scans(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    application_id: Optional[str] = Query(
        None, description="Filter by caller-supplied application_id"),
    fqdn: Optional[str] = Query(
        None,
        description="Filter by target FQDN. Substring match (case-insensitive); "
                    "use the bare host (and optional :port). Any leading "
                    "http:// or https:// is stripped before matching.",
        examples=["app.example.com", "127.0.0.1:10001"]),
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Return up to `limit` recent assessments (newest first).

    Optional filters:
      * `application_id` — exact match on the caller-supplied identifier.
      * `fqdn` — case-insensitive substring match on the target hostname,
        so the same call works for both `app.example.com` and
        `app.example.com:8443`.
    """
    _require_token(request, authorization, x_api_token)
    where_parts: list[str] = []
    params: list[Any] = []
    if application_id:
        where_parts.append("application_id = %s")
        params.append(application_id.strip()[:128])
    if fqdn:
        # Match the same normalisation as POST /scans: drop scheme,
        # lowercase. Use LIKE so callers can pass a hostname without
        # the port and still match port-suffixed rows.
        f = re.sub(r"^https?://", "", fqdn.strip().lower()).split("/", 1)[0]
        if f:
            where_parts.append("LOWER(fqdn) LIKE %s")
            params.append(f"%{f[:255]}%")
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    params.append(int(limit))
    rows = db.query(
        f"SELECT id, fqdn, application_id, profile, llm_tier, status, "
        f"total_findings, risk_score, created_at, started_at, finished_at "
        f"FROM assessments {where} ORDER BY id DESC LIMIT %s",
        params)
    return {"scans": [_serialize_assessment(r) for r in rows]}


@router.get("/scans/{scan_id}", summary="Status of one scan")
def api_get_scan(
    scan_id: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    _require_token(request, authorization, x_api_token)
    a = db.query_one("SELECT * FROM assessments WHERE id = %s", (scan_id,))
    if not a:
        raise HTTPException(404, f"no scan with id {scan_id}")
    return _public_assessment_fields(a)


def _findings_for(scan_id: int) -> list[dict]:
    return db.query(
        "SELECT id, source_tool, source_scan_id, severity, owasp_category, "
        "cwe, cvss, title, description, evidence_url, evidence_method, "
        "remediation, status, "
        "COALESCE(validation_status, 'unvalidated') AS validation_status, "
        "COALESCE(seen_count, 1) AS seen_count, "
        "created_at "
        "FROM findings WHERE assessment_id = %s "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id",
        (scan_id,))


@router.get("/scans/{scan_id}/results",
            summary="Findings for a scan, JSON or CSV")
def api_scan_results(
    scan_id: int,
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    include_false_positives: bool = Query(
        False, description="Include findings the analyst marked as false positives"),
    include_info: bool = Query(
        True,
        description="Include info-severity findings. Defaults to true. "
                    "Set false to mirror what an assessment with the "
                    "'hide info-severity findings' toggle on would emit."),
    include_accepted_risk: bool = Query(
        False,
        description="Include findings the analyst marked as accepted-risk "
                    "(archived). Defaults to false so the playground / "
                    "default API call returns only the actionable list."),
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Pull every finding produced by the assessment. Supports `format=json`
    (default) and `format=csv`. CSV is RFC 4180-compliant: comma
    delimiter, double-quote quoting, CRLF line endings.

    Filters:
      * `include_false_positives` — default false; matches the score
        rollup and the PDF report.
      * `include_info` — default true; set false to suppress the
        info-severity rows (the same suppression the per-assessment
        'hide info-severity findings' toggle applies to the on-screen
        view and the generated PDF).
      * `include_accepted_risk` — default false; set true to include
        findings the analyst archived as accepted-risk. Default
        excludes them so the response mirrors what an oncall would
        consider actionable.
    """
    _require_token(request, authorization, x_api_token)
    a = db.query_one("SELECT id, fqdn, application_id, profile, status, "
                     "total_findings, finished_at "
                     "FROM assessments WHERE id = %s", (scan_id,))
    if not a:
        raise HTTPException(404, f"no scan with id {scan_id}")
    rows = _findings_for(scan_id)
    if not include_false_positives:
        rows = [r for r in rows if r.get("status") != "false_positive"]
    if not include_accepted_risk:
        rows = [r for r in rows if r.get("status") != "accepted_risk"]
    if not include_info:
        rows = [r for r in rows if r.get("severity") != "info"]

    if format == "csv":
        buf = io.StringIO()
        # The same header set, in the same order, gets emitted regardless
        # of how many findings exist, so the CSV is loadable into BI
        # tools without sniffing.
        cols = ["scan_id", "application_id", "finding_id", "severity",
                "source_tool", "owasp_category", "cwe", "cvss", "title",
                "evidence_url", "evidence_method", "validation_status",
                "status", "seen_count", "remediation", "description",
                "created_at"]
        writer = csv.writer(buf, dialect="excel")
        writer.writerow(cols)
        for f in rows:
            writer.writerow([
                a["id"], a.get("application_id") or "",
                f["id"], f["severity"], f["source_tool"],
                f.get("owasp_category") or "", f.get("cwe") or "",
                f.get("cvss") or "", f.get("title") or "",
                f.get("evidence_url") or "", f.get("evidence_method") or "",
                f.get("validation_status") or "", f.get("status") or "",
                f.get("seen_count") or 1, f.get("remediation") or "",
                (f.get("description") or "").replace("\r", " ").replace("\n", " "),
                f["created_at"].isoformat() if hasattr(f.get("created_at"), "isoformat")
                    else str(f.get("created_at") or ""),
            ])
        filename = f"scan-{scan_id}-results.csv"
        return PlainTextResponse(
            buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return {
        "scan": _public_assessment_fields(a),
        "findings": [_serialize_assessment(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# Service definitions: OpenAPI + Postman
# ---------------------------------------------------------------------------

def _api_base_url(request: Request) -> str:
    """Build the externally-visible base URL for the API. Honors the
    UI_ROOT_PATH prefix (e.g. `/test`) so the OpenAPI / Postman
    definitions are clickable straight from the playground."""
    root = os.environ.get("UI_ROOT_PATH", "").rstrip("/")
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}{root}"


# ---------------------------------------------------------------------------
# Scheduled scans (REST surface mirroring the /schedules web UI)
#
# The lifespan sweeper materializes each due schedule into a real assessment
# and spawns its orchestrator. These endpoints CRUD the schedule rows; they
# never touch the assessments table directly.
# ---------------------------------------------------------------------------

def _serialize_schedule(s: dict) -> dict:
    """DB row → JSON-safe dict. datetime / date columns become ISO strings;
    NULLs pass through. Mirrors `_serialize_assessment`."""
    out: dict[str, Any] = {}
    for k, v in s.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    # Decorate with a 3-fire preview so callers can sanity-check their cron
    # expression without re-running croniter on the client side.
    out["next_runs"] = [
        d.isoformat()
        for d in schedules_mod.preview_runs(s.get("cron_expr") or "", 3)
    ]
    return out


@router.post("/schedules", status_code=201,
             summary="Create a scheduled scan")
def api_create_schedule(
    body: CreateScheduleRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Create a cron-driven scan recipe. The lifespan sweeper materializes
    each due fire into a normal `/api/v1/scans` row; poll those for
    progress as usual. Validation errors are returned as 400 with the
    croniter / field-validation message in `detail`."""
    _require_token(request, authorization, x_api_token)
    try:
        sid = schedules_mod.create(body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    row = schedules_mod.get(sid)
    return JSONResponse(status_code=201, content=_serialize_schedule(row))


@router.get("/schedules", summary="List scheduled scans")
def api_list_schedules(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    _require_token(request, authorization, x_api_token)
    return {"schedules": [_serialize_schedule(s)
                          for s in schedules_mod.list_all()]}


@router.get("/schedules/{sid}", summary="Fetch one schedule")
def api_get_schedule(
    sid: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    _require_token(request, authorization, x_api_token)
    row = schedules_mod.get(sid)
    if not row:
        raise HTTPException(404, "schedule not found")
    return _serialize_schedule(row)


@router.patch("/schedules/{sid}", summary="Update a scheduled scan")
def api_update_schedule(
    sid: int,
    body: UpdateScheduleRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Partial update — every field is optional, omitted fields are left
    alone. Updating cron_expr or start_after recomputes next_run_at."""
    _require_token(request, authorization, x_api_token)
    if not schedules_mod.get(sid):
        raise HTTPException(404, "schedule not found")
    # Drop None fields so they don't overwrite existing values.
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        schedules_mod.update(sid, payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _serialize_schedule(schedules_mod.get(sid))


@router.delete("/schedules/{sid}", status_code=204,
               summary="Delete a scheduled scan")
def api_delete_schedule(
    sid: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    _require_token(request, authorization, x_api_token)
    if not schedules_mod.get(sid):
        raise HTTPException(404, "schedule not found")
    schedules_mod.delete(sid)
    return JSONResponse(status_code=204, content=None)


@router.post("/schedules/{sid}/run", status_code=202,
             summary="Run a scheduled scan now (one-off)")
def api_run_schedule(
    sid: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
):
    """Materializes the schedule into an assessment immediately, without
    touching `next_run_at` — the regular cron cadence is undisturbed.
    Returns 202 with the new scan id so the caller can poll
    `/api/v1/scans/{scan_id}` as usual."""
    _require_token(request, authorization, x_api_token)
    aid = schedules_mod.spawn_one_off(sid)
    if aid is None:
        raise HTTPException(404, "schedule not found")
    return JSONResponse(status_code=202, content={"scan_id": aid,
                                                  "schedule_id": sid})


@router.get("/openapi.json", summary="OpenAPI 3.0 service definition")
def api_openapi(request: Request):
    """Self-contained OpenAPI 3.0 doc. We build it by hand (rather than
    relying on FastAPI's auto-generator on the parent app) so we can
    guarantee the file describes ONLY the /api/v1 surface and nothing
    on the web UI side. No auth required to fetch the definition; the
    operator may want to wire it into Postman/Swagger before they have
    a token."""
    base = _api_base_url(request)
    return _openapi_doc(base)


@router.get("/postman.json", summary="Postman v2.1 collection")
def api_postman(request: Request):
    """Postman collection mirroring the OpenAPI doc. Importable into
    Postman Desktop or postman.com directly. Sets the `apiToken`
    collection variable so the operator only edits one place to use
    every request."""
    base = _api_base_url(request)
    return _postman_collection(base)


@router.get("/docs", response_class=HTMLResponse,
            summary="Swagger UI playground")
def api_docs(request: Request):
    """Swagger UI playground served from this image.

    Asset strategy:
      * The Swagger UI CSS + JS bundle are vendored into the docker
        image at build time (see Dockerfile) and served from
        /static/swagger-ui/. No outbound internet or third-party CDN
        is required at runtime, which matters for air-gapped or CSP-
        locked deployments where loading from cdn.jsdelivr.net would
        leave the page blank.
      * The OpenAPI doc URL is computed server-side from UI_ROOT_PATH
        so the relative-URL trap (page at `/docs` resolving against
        `/docs/` if the user appended a trailing slash) cannot blank
        the page.
    """
    root = (os.environ.get("UI_ROOT_PATH") or "").rstrip("/")
    return HTMLResponse(_swagger_ui_html(root))


# ---------------------------------------------------------------------------
# OpenAPI document builder
# ---------------------------------------------------------------------------

def _openapi_doc(base_url: str) -> dict:
    """Hand-rolled OpenAPI 3.0.3 document. Mirrors the routes above."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "nextgen-dast API",
            "version": "2.1.1",
            "description":
                "RESTful interface to nextgen-dast. All endpoints other "
                "than /health require an OUI-format token in the "
                "`Authorization: Bearer …` header. Tokens are restricted "
                "to a whitelist of source IPs configured by the issuing "
                "admin.",
            "contact": {
                "name": "Tim Rice",
                "email": "tim.j.rice@hackrange.com",
            },
        },
        "servers": [{"url": base_url, "description": "this deployment"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "OUI",
                    "description":
                        "12-octet OUI-format token, e.g. "
                        "`4E:47:44:A1:B2:C3:D4:E5:F6:07:18:29`. "
                        "Issued via the /admin/api-tokens page.",
                },
                "xApiToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Token",
                    "description": "Alternative to Authorization: Bearer.",
                },
            },
            "schemas": _openapi_schemas(),
        },
        "security": [{"bearerAuth": []}, {"xApiToken": []}],
        "paths": _openapi_paths(),
    }


def _openapi_schemas() -> dict:
    return {
        "CreateScanRequest": {
            "type": "object",
            "required": ["fqdn"],
            "properties": {
                "fqdn":             {"type": "string",
                                     "example": "app.example.com"},
                "application_id":   {"type": "string", "maxLength": 128,
                                     "example": "APP-1234",
                                     "description":
                                         "Optional caller-supplied app "
                                         "identifier (CMDB ID, etc.)."},
                "profile":          {"type": "string",
                                     "enum": ["quick", "standard",
                                              "thorough", "premium"],
                                     "default": "standard"},
                "llm_tier":         {"type": "string",
                                     "enum": ["none", "basic", "advanced"],
                                     "default": "none"},
                "scan_http":        {"type": "boolean", "default": True},
                "scan_https":       {"type": "boolean", "default": True},
                "llm_endpoint_id":  {"type": "integer", "nullable": True},
                "user_agent_id":    {"type": "integer", "nullable": True},
                "creds_username":   {"type": "string", "nullable": True},
                "creds_password":   {"type": "string", "nullable": True,
                                     "format": "password"},
                "login_url":        {"type": "string", "nullable": True,
                                     "format": "uri"},
                "keep_only_latest": {"type": "boolean", "default": False,
                                     "description":
                                         "When true, the orchestrator "
                                         "deletes every other completed "
                                         "(done/error/cancelled) "
                                         "assessment for the same FQDN "
                                         "once this scan finishes. "
                                         "In-flight scans are never "
                                         "touched."},
            },
        },
        "CreateScanResponse": {
            "type": "object",
            "properties": {
                "scan_id":        {"type": "integer"},
                "fqdn":           {"type": "string"},
                "application_id": {"type": "string", "nullable": True},
                "status":         {"type": "string"},
                "profile":        {"type": "string"},
                "llm_tier":       {"type": "string"},
                "created_at":     {"type": "string", "format": "date-time"},
            },
        },
        "ScanStatus": {
            "type": "object",
            "properties": {
                "id":                {"type": "integer"},
                "fqdn":              {"type": "string"},
                "application_id":    {"type": "string", "nullable": True},
                "status":            {"type": "string",
                                      "enum": ["queued", "running",
                                               "consolidating", "done",
                                               "error", "cancelled",
                                               "deleting"]},
                "current_step":      {"type": "string", "nullable": True},
                "profile":           {"type": "string"},
                "llm_tier":          {"type": "string"},
                "scan_ids":          {"type": "string", "nullable": True},
                "total_findings":    {"type": "integer", "nullable": True},
                "risk_score":        {"type": "integer", "nullable": True},
                "exec_summary":      {"type": "string", "nullable": True},
                "llm_cost_usd":      {"type": "number", "nullable": True},
                "llm_in_tokens":     {"type": "integer", "nullable": True},
                "llm_out_tokens":    {"type": "integer", "nullable": True},
                "error_text":        {"type": "string", "nullable": True},
                "created_at":        {"type": "string", "format": "date-time"},
                "started_at":        {"type": "string", "format": "date-time",
                                      "nullable": True},
                "finished_at":       {"type": "string", "format": "date-time",
                                      "nullable": True},
            },
        },
        "Finding": {
            "type": "object",
            "properties": {
                "id":                {"type": "integer"},
                "source_tool":       {"type": "string"},
                "source_scan_id":    {"type": "string"},
                "severity":          {"type": "string",
                                      "enum": ["critical", "high",
                                               "medium", "low", "info"]},
                "owasp_category":    {"type": "string", "nullable": True},
                "cwe":               {"type": "string", "nullable": True},
                "cvss":              {"type": "string", "nullable": True},
                "title":             {"type": "string"},
                "description":       {"type": "string", "nullable": True},
                "evidence_url":      {"type": "string", "nullable": True},
                "evidence_method":   {"type": "string", "nullable": True},
                "remediation":       {"type": "string", "nullable": True},
                "status":            {"type": "string"},
                "validation_status": {"type": "string"},
                "seen_count":        {"type": "integer"},
                "created_at":        {"type": "string", "format": "date-time"},
            },
        },
        "ScanResults": {
            "type": "object",
            "properties": {
                "scan":     {"$ref": "#/components/schemas/ScanStatus"},
                "findings": {"type": "array",
                             "items": {"$ref": "#/components/schemas/Finding"}},
            },
        },
        "ScanList": {
            "type": "object",
            "properties": {
                "scans": {"type": "array",
                          "items": {"$ref": "#/components/schemas/ScanStatus"}},
            },
        },
        "CreateScheduleRequest": {
            "type": "object",
            "required": ["name", "fqdn", "cron_expr"],
            "properties": {
                "name": {"type": "string"},
                "fqdn": {"type": "string",
                         "example": "app.example.com"},
                "cron_expr": {"type": "string",
                              "example": "0 2 * * *",
                              "description":
                                  "5-field UTC cron expression."},
                "application_id": {"type": "string", "nullable": True},
                "profile": {"type": "string",
                            "enum": ["quick", "standard",
                                     "thorough", "premium"],
                            "default": "standard"},
                "llm_tier": {"type": "string",
                             "enum": ["none", "basic", "advanced"],
                             "default": "none"},
                "scan_http": {"type": "boolean", "default": True},
                "scan_https": {"type": "boolean", "default": True},
                "llm_endpoint_id": {"type": "integer", "nullable": True},
                "user_agent_id": {"type": "integer", "nullable": True},
                "creds_username": {"type": "string", "nullable": True},
                "creds_password": {"type": "string", "nullable": True},
                "login_url": {"type": "string", "nullable": True},
                "start_after": {"type": "string",
                                "format": "date-time",
                                "nullable": True},
                "end_before": {"type": "string",
                               "format": "date-time",
                               "nullable": True},
                "enabled": {"type": "boolean", "default": True},
                "skip_if_running": {"type": "boolean", "default": True},
                "keep_only_latest": {"type": "boolean", "default": False,
                                     "description":
                                         "Carries through to every "
                                         "materialized assessment so the "
                                         "orchestrator's finalize step "
                                         "auto-deletes prior completed "
                                         "scans for the same FQDN."},
            },
        },
        "UpdateScheduleRequest": {
            "type": "object",
            "description":
                "Partial update — every field is optional. Updating "
                "cron_expr or start_after recomputes next_run_at.",
            "properties": {
                "name": {"type": "string"},
                "fqdn": {"type": "string"},
                "cron_expr": {"type": "string"},
                "application_id": {"type": "string", "nullable": True},
                "profile": {"type": "string"},
                "llm_tier": {"type": "string"},
                "scan_http": {"type": "boolean"},
                "scan_https": {"type": "boolean"},
                "llm_endpoint_id": {"type": "integer", "nullable": True},
                "user_agent_id": {"type": "integer", "nullable": True},
                "creds_username": {"type": "string", "nullable": True},
                "creds_password": {"type": "string", "nullable": True},
                "login_url": {"type": "string", "nullable": True},
                "start_after": {"type": "string", "format": "date-time",
                                "nullable": True},
                "end_before": {"type": "string", "format": "date-time",
                               "nullable": True},
                "enabled": {"type": "boolean"},
                "skip_if_running": {"type": "boolean"},
                "keep_only_latest": {"type": "boolean"},
            },
        },
        "Schedule": {
            "type": "object",
            "description":
                "Scheduled-scan recipe. `next_runs` is a server-rendered "
                "preview computed by croniter so callers don't need to "
                "duplicate cron parsing.",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "fqdn": {"type": "string"},
                "cron_expr": {"type": "string"},
                "profile": {"type": "string"},
                "llm_tier": {"type": "string"},
                "enabled": {"type": "boolean"},
                "skip_if_running": {"type": "boolean"},
                "keep_only_latest": {"type": "boolean"},
                "next_run_at": {"type": "string", "format": "date-time",
                                "nullable": True},
                "last_run_at": {"type": "string", "format": "date-time",
                                "nullable": True},
                "last_assessment_id": {"type": "integer", "nullable": True},
                "next_runs": {"type": "array",
                              "items": {"type": "string",
                                        "format": "date-time"},
                              "description":
                                  "Server-computed preview of the next "
                                  "few firings for sanity checks."},
            },
        },
        "ScheduleList": {
            "type": "object",
            "properties": {
                "schedules": {"type": "array",
                              "items": {"$ref": "#/components/schemas/Schedule"}},
            },
        },
        "Error": {
            "type": "object",
            "properties": {
                "detail": {"type": "string"},
            },
        },
    }


def _openapi_paths() -> dict:
    err_responses = {
        "401": {"description": "missing or invalid token",
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}}}},
        "403": {"description": "source IP not whitelisted for this token",
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}}}},
        "404": {"description": "no such scan",
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}}}},
    }
    return {
        "/api/v1/health": {
            "get": {
                "summary": "Liveness probe (no auth required)",
                "security": [],
                "responses": {
                    "200": {"description": "ok",
                            "content": {"application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "ok": {"type": "boolean"},
                                        "service": {"type": "string"},
                                        "version": {"type": "string"},
                                    },
                                }}}},
                },
            },
        },
        "/api/v1/lookups": {
            "get": {
                "summary": "Live id->label maps + enum value tables",
                "description":
                    "Returns the id->label mapping for the integer-typed "
                    "fields (`llm_endpoint_id`, `user_agent_id`) and the "
                    "static enum value tables for `profile`, `llm_tier`, "
                    "and `format`. Powers the help modal in /api/v1/docs. "
                    "No auth required.",
                "security": [],
                "responses": {
                    "200": {"description": "lookup tables",
                            "content": {"application/json": {}}},
                },
            },
        },
        "/api/v1/scans": {
            "post": {
                "summary": "Create a new scan",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/CreateScanRequest"}}},
                },
                "responses": {
                    "201": {"description": "scan queued",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateScanResponse"}}}},
                    **err_responses,
                },
            },
            "get": {
                "summary": "List recent scans",
                "parameters": [
                    {"name": "limit", "in": "query",
                     "schema": {"type": "integer", "default": 50,
                                "minimum": 1, "maximum": 500}},
                    {"name": "application_id", "in": "query",
                     "schema": {"type": "string"},
                     "description":
                         "Exact match on the caller-supplied "
                         "application_id."},
                    {"name": "fqdn", "in": "query",
                     "schema": {"type": "string",
                                "example": "app.example.com"},
                     "description":
                         "Case-insensitive substring match on the "
                         "target FQDN. Pass the bare host (with "
                         "optional :port). Leading http:// or https:// "
                         "is stripped before matching."},
                ],
                "responses": {
                    "200": {"description": "scan list",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanList"}}}},
                    **err_responses,
                },
            },
        },
        "/api/v1/scans/{scan_id}": {
            "get": {
                "summary": "Status of one scan",
                "parameters": [
                    {"name": "scan_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {"description": "status",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanStatus"}}}},
                    **err_responses,
                },
            },
        },
        "/api/v1/scans/{scan_id}/results": {
            "get": {
                "summary": "Findings for a scan, JSON or CSV",
                "parameters": [
                    {"name": "scan_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                    {"name": "format", "in": "query",
                     "schema": {"type": "string",
                                "enum": ["json", "csv"], "default": "json"}},
                    {"name": "include_false_positives", "in": "query",
                     "schema": {"type": "boolean", "default": False},
                     "description":
                         "Include findings the analyst marked as "
                         "false positive. Default false."},
                    {"name": "include_info", "in": "query",
                     "schema": {"type": "boolean", "default": True},
                     "description":
                         "Include info-severity findings. Default "
                         "true. Set false to mirror the per-assessment "
                         "'hide info-severity findings' toggle."},
                    {"name": "include_accepted_risk", "in": "query",
                     "schema": {"type": "boolean", "default": False},
                     "description":
                         "Include findings the analyst marked as "
                         "accepted-risk (archived). Default false so "
                         "the response is just the actionable list."},
                ],
                "responses": {
                    "200": {
                        "description": "findings",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanResults"}},
                            "text/csv": {
                                "schema": {"type": "string",
                                           "format": "binary"}},
                        },
                    },
                    **err_responses,
                },
            },
        },
        "/api/v1/schedules": {
            "post": {
                "summary": "Create a scheduled scan",
                "description":
                    "Create a cron-driven scan recipe. The lifespan "
                    "sweeper materializes each due fire into a normal "
                    "/api/v1/scans row; poll those for progress.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/CreateScheduleRequest"}}},
                },
                "responses": {
                    "201": {"description": "schedule created",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/Schedule"}}}},
                    **err_responses,
                },
            },
            "get": {
                "summary": "List scheduled scans",
                "responses": {
                    "200": {"description": "schedule list",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/ScheduleList"}}}},
                    **err_responses,
                },
            },
        },
        "/api/v1/schedules/{schedule_id}": {
            "get": {
                "summary": "Fetch one schedule",
                "parameters": [
                    {"name": "schedule_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {"description": "schedule",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/Schedule"}}}},
                    **err_responses,
                },
            },
            "patch": {
                "summary": "Update a scheduled scan",
                "description":
                    "Partial update — every field is optional. Updating "
                    "cron_expr or start_after recomputes next_run_at.",
                "parameters": [
                    {"name": "schedule_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/UpdateScheduleRequest"}}},
                },
                "responses": {
                    "200": {"description": "updated",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/Schedule"}}}},
                    **err_responses,
                },
            },
            "delete": {
                "summary": "Delete a scheduled scan",
                "parameters": [
                    {"name": "schedule_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
                "responses": {
                    "204": {"description": "deleted"},
                    **err_responses,
                },
            },
        },
        "/api/v1/schedules/{schedule_id}/run": {
            "post": {
                "summary": "Run a scheduled scan now (one-off)",
                "description":
                    "Materializes the schedule into an assessment "
                    "immediately. Does not affect next_run_at.",
                "parameters": [
                    {"name": "schedule_id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
                "responses": {
                    "202": {"description": "queued",
                            "content": {"application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "scan_id": {"type": "integer"},
                                        "schedule_id": {"type": "integer"},
                                    },
                                }}}},
                    **err_responses,
                },
            },
        },
        "/api/v1/openapi.json": {
            "get": {
                "summary": "OpenAPI 3.0 service definition",
                "security": [],
                "responses": {"200": {"description": "openapi doc"}},
            },
        },
        "/api/v1/postman.json": {
            "get": {
                "summary": "Postman v2.1 collection",
                "security": [],
                "responses": {"200": {"description": "postman collection"}},
            },
        },
        "/api/v1/docs": {
            "get": {
                "summary": "Swagger UI playground",
                "security": [],
                "responses": {"200": {"description": "html"}},
            },
        },
    }


# ---------------------------------------------------------------------------
# Postman collection builder
# ---------------------------------------------------------------------------

def _postman_collection(base_url: str) -> dict:
    """Postman v2.1 collection. Importing this in Postman creates one
    folder with five requests; the operator only needs to set the
    `apiToken` collection variable to be ready to call every endpoint."""
    coll_id = "4e474400-2111-4dad-9eef-nextgendast21"
    auth_block = {
        "type": "bearer",
        "bearer": [
            {"key": "token", "value": "{{apiToken}}", "type": "string"},
        ],
    }
    def url(path: str, query: Optional[list[dict]] = None) -> dict:
        full = f"{base_url}{path}"
        item = {"raw": full, "host": [base_url],
                "path": [p for p in path.lstrip("/").split("/") if p]}
        if query:
            item["query"] = query
            item["raw"] = full + "?" + "&".join(
                f"{q['key']}={q.get('value','')}" for q in query)
        return item

    return {
        "info": {
            "_postman_id": coll_id,
            "name": "nextgen-dast 2.1.1",
            "description": (
                "RESTful interface to the nextgen-dast scanner. Set "
                "the `apiToken` collection variable to your OUI-format "
                "token, then run any request. Tokens are restricted "
                "to whitelisted source IPs by the issuing admin."),
            "schema":
                "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": auth_block,
        "variable": [
            {"key": "apiToken",
             "value": "4E:47:44:00:00:00:00:00:00:00:00:00",
             "type": "string"},
            {"key": "baseUrl", "value": base_url, "type": "string"},
        ],
        "item": [
            {
                "name": "Health (no auth)",
                "request": {
                    "method": "GET", "auth": {"type": "noauth"},
                    "header": [], "url": url("/api/v1/health"),
                },
            },
            {
                "name": "Create scan",
                "request": {
                    "method": "POST", "header": [
                        {"key": "Content-Type", "value": "application/json"}],
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps({
                            "fqdn": "app.example.com",
                            "application_id": "APP-1234",
                            "profile": "standard",
                            "llm_tier": "none",
                            "scan_http": True,
                            "scan_https": True,
                        }, indent=2),
                        "options": {"raw": {"language": "json"}},
                    },
                    "url": url("/api/v1/scans"),
                },
            },
            {
                "name": "List scans",
                "request": {
                    "method": "GET", "header": [],
                    "url": url("/api/v1/scans",
                               [{"key": "limit", "value": "20"}]),
                },
            },
            {
                "name": "Get scan status",
                "request": {
                    "method": "GET", "header": [],
                    "url": url("/api/v1/scans/1"),
                    "description":
                        "Replace the trailing 1 with the scan_id "
                        "echoed by Create scan.",
                },
            },
            {
                "name": "Scan results (JSON)",
                "request": {
                    "method": "GET", "header": [],
                    "url": url("/api/v1/scans/1/results",
                               [{"key": "format", "value": "json"}]),
                },
            },
            {
                "name": "Scan results (CSV)",
                "request": {
                    "method": "GET", "header": [],
                    "url": url("/api/v1/scans/1/results",
                               [{"key": "format", "value": "csv"}]),
                },
            },
            {
                "name": "OpenAPI definition (no auth)",
                "request": {
                    "method": "GET", "auth": {"type": "noauth"},
                    "header": [], "url": url("/api/v1/openapi.json"),
                },
            },
        ],
    }


# ---------------------------------------------------------------------------
# Swagger UI playground
# ---------------------------------------------------------------------------

def _swagger_ui_html(root_path: str = "") -> str:
    """Static HTML page that mounts Swagger UI against our OpenAPI doc.

    Both the CSS and the JS are loaded from `/static/swagger-ui/` —
    the assets are vendored into the image at build time, so the page
    works on hosts with no outbound internet and on deployments whose
    Content-Security-Policy blocks third-party CDNs (which is the most
    common reason this page renders blank).

    `root_path` is the UI_ROOT_PATH prefix (e.g. `/test`). Both the
    asset URLs and the OpenAPI doc URL are absolute so they resolve
    correctly regardless of whether the operator visited the docs URL
    with or without a trailing slash.
    """
    css = f"{root_path}/static/swagger-ui/swagger-ui.css"
    js = f"{root_path}/static/swagger-ui/swagger-ui-bundle.js"
    # Field-help layer (circle "?" icons + modal). Adds per-field
    # tooltips that explain enum values, sample inputs, and live
    # id->label tables for the integer FK fields. Loaded after
    # Swagger UI so it can decorate the rendered DOM.
    help_css = f"{root_path}/static/api-help.css"
    help_js = f"{root_path}/static/api-help.js"
    openapi_url = f"{root_path}/api/v1/openapi.json"
    postman_url = f"{root_path}/api/v1/postman.json"
    # The <noscript> + #fallback block guarantees the operator never
    # sees a stark blank page: even if the bundle fails to load (CSP,
    # 404, AV interception), the links to the raw OpenAPI / Postman
    # files and a curl-able health probe remain usable.
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>nextgen-dast API playground</title>
  <link rel="stylesheet" href="{css}">
  <link rel="stylesheet" href="{help_css}">
  <style>
    body {{ margin: 0; background: #fafafa; }}
    .topbar {{ display: none; }}
    .ngd-banner {{
      background: #1b232b; color: #d8dee5;
      padding: .8em 1.2em; font: 600 14px/1.4 -apple-system, system-ui,
        "Segoe UI", sans-serif;
    }}
    .ngd-banner small {{ color: #8a96a3; font-weight: 400; margin-left: .8em; }}
    .ngd-banner a {{ color: #5fb3d7; text-decoration: none; }}
    /* Always-visible fallback. Hidden once Swagger UI inits successfully. */
    #fallback {{ max-width: 720px; margin: 2em auto; padding: 1.2em 1.6em;
                 font: 14px/1.5 -apple-system, system-ui, sans-serif;
                 color: #1f2630; background: #fff;
                 border: 1px solid #dde2eb; border-radius: 6px; }}
    #fallback h2 {{ margin-top: 0; font-size: 1.05em; }}
    #fallback code {{ background: #f3f5f8; padding: 1px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="ngd-banner">
    nextgen-dast 2.1.1 API
    <small>Live playground.
      <a href="{openapi_url}">openapi.json</a> ·
      <a href="{postman_url}">postman.json</a></small>
  </div>

  <div id="swagger-ui"></div>

  <div id="fallback">
    <h2>Swagger UI did not load</h2>
    <p>The interactive playground failed to initialize. Common causes:
      strict Content-Security-Policy blocking <code>/static/swagger-ui/*</code>,
      an antivirus rewriting JS, or the static-files mount being
      offline.</p>
    <p>You can still drive the API directly:</p>
    <ul>
      <li><a href="{openapi_url}">OpenAPI 3.0 definition</a> (machine-readable)</li>
      <li><a href="{postman_url}">Postman v2.1 collection</a> (import into Postman)</li>
      <li><code>curl -H "Authorization: Bearer YOUR-TOKEN" {openapi_url.replace('/openapi.json', '/health')}</code></li>
    </ul>
    <p>Issue tokens at <a href="{root_path}/admin/api-tokens">{root_path}/admin/api-tokens</a>.</p>
  </div>

  <script src="{js}"></script>
  <script>
    // Hide the fallback once Swagger UI has rendered. If the bundle
    // failed to load (network / CSP), the script tag above doesn't
    // execute and the fallback stays visible.
    (function () {{
      if (typeof SwaggerUIBundle !== 'function') return;
      var fb = document.getElementById('fallback');
      if (fb) fb.style.display = 'none';
      window.ui = SwaggerUIBundle({{
        url: {json.dumps(openapi_url)},
        dom_id: '#swagger-ui',
        deepLinking: true,
        tryItOutEnabled: true,
        persistAuthorization: true,
      }});
    }})();
  </script>
  <script src="{help_js}"></script>
</body>
</html>
"""
