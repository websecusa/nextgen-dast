# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
mitmproxy addon for the pentest proxy.

For every flow:
  - writes a JSON line to /data/logs/flows.jsonl (summary + findings)
  - writes /data/flows/<id>_request.txt and /data/flows/<id>_response.txt
    in raw HTTP-message format for LLM / human review

Findings detected:
  - JWT-shaped tokens
  - AWS / Google / Stripe / GitHub / generic API keys
  - SSN-shaped values
  - Email addresses
  - Credit-card-shaped numerics (loose, no Luhn check)
  - Cookies missing Secure / HttpOnly / SameSite
  - Missing security response headers
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx, http

DEFAULT_FLOWS_DIR = Path("/data/flows")
DEFAULT_FLOW_LOG = Path("/data/logs/flows.jsonl")

# Out-of-band callback / housekeeping services used by various scanners.
# Their responses aren't probes against the user's target — they're the
# scanner's own infrastructure. Skip findings analysis on these hosts, and
# tag the flow so the UI can hide them by default.
OOB_HOST_SUFFIXES = (
    "oast.online", "oast.fun", "oast.me", "oast.pro", "oast.site",
    "oast.us", "oast.live", "interact.sh",
    "checkip.amazonaws.com",          # nuclei's "what's my IP" probe
)

# Status codes we drop entirely — never write txt files, never log to
# flows.jsonl. 404/405/410 are "you found nothing" — keeping them is dead
# disk + dead LLM tokens.
SKIP_STATUS = {404, 405, 410}

# ---- detectors --------------------------------------------------------------

PATTERNS = [
    ("jwt",            re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret",     re.compile(r"(?i)aws(.{0,20})?(secret|key)[\"'\s:=]+([A-Za-z0-9/+=]{40})")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_live",    re.compile(r"\b(?:sk|pk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("github_token",   re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack_token",    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key",    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("ssn",            re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("email",          re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("credit_card",    re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("authorization",  re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic|token)\s+[A-Za-z0-9._\-+/=]{8,}")),
    ("password_field", re.compile(r"(?i)\"password\"\s*:\s*\"[^\"]+\"")),
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def scan_text(label: str, text: str, findings: list, max_examples: int = 3) -> None:
    if not text:
        return
    sample = text if len(text) < 500_000 else text[:500_000]
    for name, pat in PATTERNS:
        matches = pat.findall(sample)
        if not matches:
            continue
        flat = []
        for m in matches:
            if isinstance(m, tuple):
                m = " ".join(p for p in m if p)
            flat.append(m if len(m) <= 80 else m[:80] + "…")
            if len(flat) >= max_examples:
                break
        findings.append({
            "where": label,
            "type": name,
            "count": len(matches),
            "examples": flat,
        })


def cookie_findings(headers, where: str, findings: list) -> None:
    for name, value in headers.items(multi=True) if hasattr(headers, "items") else []:
        if name.lower() != "set-cookie":
            continue
        v = value.lower()
        missing = []
        if "secure" not in v:
            missing.append("Secure")
        if "httponly" not in v:
            missing.append("HttpOnly")
        if "samesite" not in v:
            missing.append("SameSite")
        if missing:
            findings.append({
                "where": where,
                "type": "cookie_flags_missing",
                "missing": missing,
                "cookie": value.split(";")[0],
            })


def missing_security_headers(headers, findings: list) -> None:
    present = {k.lower() for k in headers.keys()}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    if missing:
        findings.append({
            "where": "response_headers",
            "type": "missing_security_headers",
            "missing": missing,
        })


# ---- raw-message dumping ----------------------------------------------------

def _decode_body(message) -> str:
    try:
        return message.get_text(strict=False) or ""
    except Exception:
        try:
            return message.content.decode("utf-8", "replace") if message.content else ""
        except Exception:
            return f"<{len(message.content or b'')} bytes binary>"


def dump_request(req: http.Request, fid: str, flows_dir: Path) -> str:
    lines = [f"{req.method} {req.path} HTTP/{req.http_version.split('/')[-1] if '/' in req.http_version else req.http_version}"]
    for k, v in req.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    body = _decode_body(req)
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    path = flows_dir / f"{fid}_request.txt"
    path.write_text(text, encoding="utf-8")
    return body


def dump_response(resp: http.Response, fid: str, flows_dir: Path) -> str:
    if resp is None:
        return ""
    status_line = f"HTTP/{resp.http_version.split('/')[-1] if '/' in resp.http_version else resp.http_version} {resp.status_code} {resp.reason or ''}".rstrip()
    lines = [status_line]
    for k, v in resp.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    body = _decode_body(resp)
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    path = flows_dir / f"{fid}_response.txt"
    path.write_text(text, encoding="utf-8")
    return body


# ---- mitmproxy hook ---------------------------------------------------------

class PentestAddon:

    # Per-scan hard cap: after this many flows, we stop writing txt files
    # entirely and only emit count-summary lines. Prevents a runaway scanner
    # from filling the disk (a#3's wapiti wrote 16 GB of redundant probes).
    DEFAULT_PROBE_CAP = 25_000

    def __init__(self):
        self.flows_dir = DEFAULT_FLOWS_DIR
        self.flow_log = DEFAULT_FLOW_LOG
        self.probe_cap = self.DEFAULT_PROBE_CAP
        # Per-scan in-memory dedup: signature → (first_flow_id, count)
        # Signature = host:status:size:method. The first matching flow is
        # written in full; subsequent matches are dropped (only the running
        # count is kept).
        self._sigs: dict[str, dict] = {}
        # Total flows written to disk so far this scan.
        self._written: int = 0
        # Total flows skipped because of dedup or cap.
        self._skipped_dedup: int = 0
        self._skipped_cap: int = 0

    def load(self, loader):
        loader.add_option("flows_dir", str, str(DEFAULT_FLOWS_DIR),
                          "Directory to write per-flow request/response txt files")
        loader.add_option("flow_log_path", str, str(DEFAULT_FLOW_LOG),
                          "Path to flows.jsonl summary log")
        loader.add_option("probe_cap", int, self.DEFAULT_PROBE_CAP,
                          "Stop writing flow files after this many unique probes")

    def configure(self, updates):
        if "flows_dir" in updates:
            self.flows_dir = Path(ctx.options.flows_dir)
            self.flows_dir.mkdir(parents=True, exist_ok=True)
        if "flow_log_path" in updates:
            self.flow_log = Path(ctx.options.flow_log_path)
            self.flow_log.parent.mkdir(parents=True, exist_ok=True)
        if "probe_cap" in updates:
            self.probe_cap = int(ctx.options.probe_cap)

    def done(self):
        """Emit a summary at scan end so the user sees what was deduped."""
        if not self._sigs and not self._skipped_dedup and not self._skipped_cap:
            return
        try:
            with open(self.flow_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "_summary": True,
                    "written": self._written,
                    "skipped_dedup": self._skipped_dedup,
                    "skipped_cap": self._skipped_cap,
                    "unique_signatures": len(self._sigs),
                    "top_dedup": sorted(
                        ({"sig": k, "count": v["count"], "first": v["first"]}
                         for k, v in self._sigs.items() if v["count"] > 1),
                        key=lambda r: -r["count"])[:20],
                }, default=str) + "\n")
        except Exception:
            pass

    def response(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response

        # Drop "found nothing" responses outright — saves disk and LLM tokens.
        if resp is not None and resp.status_code in SKIP_STATUS:
            return

        host = (req.pretty_host or "").lower()
        status = resp.status_code if resp else 0
        size = len(resp.content or b"") if resp else 0
        sig = f"{host}:{status}:{size}:{req.method}"

        # Capture-time response-size dedup. The first probe with a given
        # signature is written in full; subsequent matches are dropped on the
        # floor and only counted. 100 SQLi probes that all return the 9 KB
        # home page become one written flow plus a counter.
        existing = self._sigs.get(sig)
        if existing is not None:
            existing["count"] += 1
            self._skipped_dedup += 1
            return

        # Per-scan probe cap — refuse to write past the limit.
        if self._written >= self.probe_cap:
            self._skipped_cap += 1
            return

        # short, sortable id: time + 6 hex
        fid = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self._sigs[sig] = {"first": fid, "count": 1}
        self._written += 1

        req_body = dump_request(req, fid, self.flows_dir)
        resp_body = dump_response(resp, fid, self.flows_dir) if resp else ""

        is_oob = any(host == s or host.endswith("." + s) or host.endswith(s)
                     for s in OOB_HOST_SUFFIXES)

        findings: list = []
        if not is_oob:
            # request side
            scan_text("request_url", req.pretty_url, findings)
            for k, v in req.headers.items(multi=True):
                scan_text(f"request_header:{k}", v, findings)
            scan_text("request_body", req_body, findings)

            if resp is not None:
                for k, v in resp.headers.items(multi=True):
                    scan_text(f"response_header:{k}", v, findings)
                scan_text("response_body", resp_body, findings)
                cookie_findings(resp.headers, "response_headers", findings)
                missing_security_headers(resp.headers, findings)

        record = {
            "id": fid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client": getattr(flow.client_conn, "peername", None) and ":".join(map(str, flow.client_conn.peername)),
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "request_size": len(req.content or b""),
            "request_content_type": req.headers.get("content-type", ""),
            "status_code": resp.status_code if resp else None,
            "response_size": len(resp.content or b"") if resp else 0,
            "response_content_type": resp.headers.get("content-type", "") if resp else "",
            "duration_ms": int(((flow.response.timestamp_end if resp and resp.timestamp_end else time.time()) -
                                (req.timestamp_start or time.time())) * 1000),
            "findings": findings,
            "is_oob": is_oob,
            # LLM batch selector clusters on this — host:status:size.
            # 611 probes returning the same 9407-byte home page get one
            # representative analyzed, not 611 identical "no finding"
            # answers from the model.
            "response_sig": (f"{host}:{resp.status_code if resp else 0}:"
                             f"{len(resp.content or b'') if resp else 0}"),
            "request_file": f"{fid}_request.txt",
            "response_file": f"{fid}_response.txt",
        }

        try:
            with open(self.flow_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except Exception as e:
            ctx.log.error(f"flow log write failed: {e}")

        if findings:
            ctx.log.warn(f"[{fid}] {req.method} {req.pretty_url} -> "
                         f"{resp.status_code if resp else '?'} :: "
                         f"{len(findings)} finding(s): "
                         f"{','.join(sorted({f['type'] for f in findings}))}")


addons = [PentestAddon()]
