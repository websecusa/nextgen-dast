# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""PQC (post-quantum cryptography) compliance scoring.

Reads a testssl JSON report and decides how ready the target is for the
post-quantum era. Same shape as quready.com / Cloudflare's PQC score.

Checks (each weighted; total 100):
  - TLS 1.3 offered                   (10)
  - No downgrade risk: legacy TLS not offered     (20)
  - PQC key exchange present (X25519+ML-KEM-768)  (30)
  - ML-KEM-768 specifically negotiated            (10)
  - Strong cipher: TLS_AES_256_GCM_SHA384         (20)
  - OpenSSL TLS 1.3 accurate (proto-support 100)  (10)

If ALL six pass, grade = A and the report's overall grade gets a +5 bonus
for full quantum-safety. Anything less still scores out of 100 with a
letter grade so partial PQC readiness is visible.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

PQC_PATTERNS = ("MLKEM", "ML-KEM", "ML_KEM", "mlkem", "kyber", "KYBER",
                "x25519_kyber", "X25519MLKEM", "x25519mlkem")
ML_KEM_768_PATTERNS = ("MLKEM768", "ML-KEM-768", "ML_KEM_768",
                       "X25519MLKEM768", "x25519mlkem768")


def _starts_offered(finding: str) -> bool:
    """testssl writes 'offered' / 'offered (OK)' / 'offered with ...' for
    supported protocols and 'not offered' for unsupported. Use a leading
    match so 'not offered' isn't a false positive."""
    f = (finding or "").strip().lower()
    return f.startswith("offered")


def empty() -> dict:
    """Default zero-data shape so the template renders cleanly even when
    no testssl scan exists for the assessment."""
    return {
        "has_data": False, "score": 0, "grade": "—",
        "color": "#6c757d", "fully_pqc": False, "bonus": 0,
        "negotiated_kex": "",
        "negotiated_cipher": "",
        "checks": [],
    }


def analyze_entries(entries: list) -> dict:
    """Score a list of testssl JSON entries. Returns a dict suitable for
    direct rendering."""
    if not entries:
        return empty()

    # Protocol support
    proto = {p: False for p in ("SSLv2", "SSLv3", "TLS1", "TLS1_1",
                                "TLS1_2", "TLS1_3")}
    for e in entries:
        eid = e.get("id", "")
        if eid in proto:
            proto[eid] = _starts_offered(e.get("finding", ""))

    tls13_offered = proto["TLS1_3"]
    no_downgrade = not any(proto[k] for k in
                           ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2"))

    # Supported TLS 1.3 ciphers
    cipher_text = ""
    for e in entries:
        if e.get("id") == "supportedciphers_TLSv1_3":
            cipher_text = e.get("finding", "") or ""
            break
    strong_cipher = "TLS_AES_256_GCM_SHA384" in cipher_text

    # Search every finding for any PQC marker — testssl's exposure of
    # X25519+ML-KEM varies by version. We look at the supported groups
    # output, the negotiated key share extension, and any cipher line.
    pqc_blob = ""
    for e in entries:
        eid = e.get("id", "")
        f = e.get("finding", "") or ""
        if any(p in f for p in PQC_PATTERNS) or any(p in eid for p in PQC_PATTERNS):
            pqc_blob = f
            break
    pqc_kex = bool(pqc_blob)
    mlkem_768 = any(p in pqc_blob for p in ML_KEM_768_PATTERNS) \
                or any(p.lower() in pqc_blob.lower() for p in ML_KEM_768_PATTERNS)

    # OpenSSL TLS 1.3 accurate — testssl's own protocol-support score.
    # When this is 100 we know the upstream stack speaks TLS 1.3 cleanly
    # (no version-mismatch confusion).
    proto_score = 0
    for e in entries:
        if e.get("id") == "protocol_support_score":
            try:
                proto_score = int((e.get("finding") or "0").strip())
            except ValueError:
                pass
            break
    openssl_accurate = proto_score >= 90 and tls13_offered

    # Negotiated cipher (top of supported list, useful for the report)
    negotiated_cipher = ""
    for e in entries:
        if e.get("id") == "cipher_negotiated":
            negotiated_cipher = (e.get("finding") or "").strip()
            break
    if not negotiated_cipher and cipher_text:
        negotiated_cipher = cipher_text.split()[0] if cipher_text else ""

    # Score
    score = 0
    if tls13_offered:    score += 10
    if no_downgrade:     score += 20
    if strong_cipher:    score += 20
    if pqc_kex:          score += 30
    if mlkem_768:        score += 10
    if openssl_accurate: score += 10

    fully_pqc = (tls13_offered and no_downgrade and strong_cipher
                 and pqc_kex and mlkem_768 and openssl_accurate)
    bonus = 5 if fully_pqc else 0

    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else: grade = "F"

    color = {"A": "#2c8a4f", "B": "#7bc47f", "C": "#d4a017",
             "D": "#c0392b", "F": "#6b1f1f"}[grade]

    checks = [
        {"name": "TLS 1.3 offered",
         "ok": tls13_offered, "weight": 10,
         "detail": "Required for any PQC key exchange to be possible"},
        {"name": "No downgrade — legacy TLS (1.0/1.1/1.2/SSLv3) NOT offered",
         "ok": no_downgrade, "weight": 20,
         "detail": "An attacker who can downgrade renders PQC moot"},
        {"name": "Strong cipher TLS_AES_256_GCM_SHA384 supported",
         "ok": strong_cipher, "weight": 20,
         "detail": (cipher_text or "(cipher list not reported)")[:120]},
        {"name": "PQC key exchange present (ML-KEM / Kyber hybrid)",
         "ok": pqc_kex, "weight": 30,
         "detail": (pqc_blob or "No ML-KEM / Kyber markers in testssl output")[:120]},
        {"name": "ML-KEM-768 specifically",
         "ok": mlkem_768, "weight": 10,
         "detail": "X25519+ML-KEM-768 is the IETF-codified hybrid"},
        {"name": "OpenSSL TLS 1.3 accurate (protocol-support score ≥ 90)",
         "ok": openssl_accurate, "weight": 10,
         "detail": f"testssl protocol_support_score: {proto_score}"},
    ]

    return {
        "has_data": True,
        "score": score, "grade": grade, "color": color,
        "fully_pqc": fully_pqc, "bonus": bonus,
        "negotiated_cipher": negotiated_cipher,
        "negotiated_kex": pqc_blob[:120] if pqc_blob else "",
        "checks": checks,
    }


def analyze_from_scan_dir(scan_dir: Path) -> dict:
    p = Path(scan_dir) / "report.json"
    if not p.exists():
        return empty()
    try:
        data = json.loads(p.read_text())
    except Exception:
        return empty()
    if isinstance(data, dict):
        data = data.get("scanResult") or data.get("results") or []
    if not isinstance(data, list):
        return empty()
    return analyze_entries(data)


def analyze_assessment(scan_ids: list, scans_root: str = "/data/scans") -> dict:
    """Find the testssl scan in the assessment's scan_ids list and analyze it.
    Returns empty() if no testssl scan is present (e.g., http-only quick run)."""
    for sid in scan_ids or []:
        meta_path = Path(scans_root) / sid / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        if meta.get("tool") == "testssl":
            return analyze_from_scan_dir(Path(scans_root) / sid)
    return empty()
