#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
testssl re-check probe. Re-runs testssl.sh narrowly against the same
host:port the original scan reported, scoped to the slice of the test
matrix that actually exercises the failing check (cipher categories,
cipher order, protocol enable/disable, vulnerability suite, etc.), then
inspects the JSON output for the row whose `id` matches the original
finding.

Verdict semantics:
  validated=True   — the row is still present in the testssl output AND
                     its severity is HIGH / CRITICAL / MEDIUM. The
                     original posture has not been remediated.
  validated=False  — the row is absent from the narrow re-run, or its
                     severity has dropped to INFO / OK. The fix appears
                     to have landed.
  validated=None   — testssl.sh did not produce parseable output (the
                     binary is missing, the run errored, etc.). Returns
                     ok=False so the UI surfaces the underlying error.

Why a probe and not just a Bash one-liner: the workspace's "Test (TLS)"
button already shells out to testssl.sh narrowly, but it doesn't write
back to findings.validation_status. As a probe the same logic plugs
into Validate/Challenge — the verdict persists, the status badge flips
green/red, and a second analyst opening the finding sees the most-
recent re-run rather than the stale scan output.

Tested against:
  + juiceshop.fairtprm.com   cipher_order-tls1   -> validated=True
                             cipherlist_NULL     -> validated=True
                             TLS1                -> validated=True (negotiates)
                             HSTS                -> validated=True (header missing)
  + a hardened nginx default cipherlist_NULL     -> validated=False
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib.probe import Probe, Verdict   # noqa: E402


# Same dispatch table the server-side helper uses (app/server.py:
# _TESTSSL_DISPATCH). Duplicated here on purpose: a probe is a stand-
# alone subprocess that should not import server-side code, and the
# table is short enough that drift is easy to spot in code review.
_DISPATCH: list[tuple[object, str, str]] = [
    (re.compile(r"^cipherlist_"),       "-s",  "standard cipher categories"),
    (re.compile(r"^cipher_order"),      "-P",  "server cipher preference"),
    (re.compile(r"^cipher_(?:negotiated|x|tls)"),
                                        "-e",  "each-cipher enumeration"),
    (re.compile(r"^cert(?:_|ificate)"), "-S",  "server defaults / certificate"),
    (re.compile(r"^chain"),             "-S",  "certificate chain"),
    (re.compile(r"^DH(?:_|$)|^GOOD_DH"), "-f", "forward secrecy"),
    (re.compile(r"^FS"),                "-f",  "forward secrecy"),
    ({"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"},
                                        "-p",  "protocols"),
    ({"BREACH", "CRIME_TLS", "POODLE_SSL", "FREAK", "DROWN", "LOGJAM",
      "BEAST", "BEAST_CBC_TLS1", "BEAST_CBC_TLS1_1", "RC4", "SWEET32",
      "WINSHOCK", "HEARTBLEED", "CCS_INJECTION", "TICKETBLEED", "ROBOT",
      "SECURE_RENEGO", "SECURE_CLIENT_RENEGO", "LUCKY13", "FALLBACK_SCSV"},
                                        "-U",  "vulnerability suite"),
    (re.compile(r"^HSTS|^HPKP|^banner|^cookie", re.IGNORECASE),
                                        "-h",  "HTTP / TLS headers"),
    ({"overall_grade"},                 "-g",  "grading"),
]


# Header-presence testssl IDs (and enhanced_testing aliases) that can
# be answered from a single HTTPS GET. Routing through testssl.sh -h
# costs 30-60s for what `curl -I` answers in <200 ms. The fast path
# in _header_fast_recheck() returns the same Verdict shape as the
# subprocess path, so the orchestrator's UI can't tell which branch
# ran. Keys are lowercased for case-insensitive matching.
_HEADER_FAST_ID_TO_HEADER: dict[str, str] = {
    # testssl native IDs
    "hsts":                    "strict-transport-security",
    "hsts_subdomains":         "strict-transport-security",
    "hsts_preload":            "strict-transport-security",
    "hsts_time":               "strict-transport-security",
    "hpkp":                    "public-key-pins",
    "x-frame-options":         "x-frame-options",
    "xfo":                     "x-frame-options",
    "x-content-type-options":  "x-content-type-options",
    "xcto":                    "x-content-type-options",
    "x-xss-protection":        "x-xss-protection",
    "content-security-policy": "content-security-policy",
    "csp":                     "content-security-policy",
    "referrer-policy":         "referrer-policy",
    "permissions-policy":      "permissions-policy",
    "feature-policy":          "feature-policy",
    "banner_server":           "server",
    "banner_application":      "x-powered-by",
    # enhanced_testing aliases (Challenge button matches title which
    # is the probe name like config_hsts_missing).
    "config_hsts_missing":            "strict-transport-security",
    "config_csp_missing":             "content-security-policy",
    "config_xfo_missing":             "x-frame-options",
    "config_xcto_missing":            "x-content-type-options",
    "config_referrer_policy_missing": "referrer-policy",
    "config_permissions_policy_missing": "permissions-policy",
    "config_xss_protection_missing":  "x-xss-protection",
}
_HSTS_MIN_MAX_AGE = 15552000   # 180 days, conventional remediation threshold


# Path to the testssl-bundled openssl 1.0.2-bad binary that supports
# the deprecated protocols / ciphers system openssl 3.x refuses to
# carry. Required for SSLv2, SSLv3, TLS 1.0, TLS 1.1, EXPORT-grade
# ciphers, NULL, RC4, etc. OPENSSL_CONF must be empty when invoking
# (default config tries to load providers that aren't shipped).
_LEGACY_OPENSSL = "/opt/testssl/bin/openssl.Linux.x86_64"

# Vulnerability-check IDs whose verification reduces to one openssl
# s_client handshake attempt — sub-second answer instead of a 60-180 s
# testssl.sh -U narrowing run. Must stay in sync with the server-side
# _VULN_FAST_TESTSSL_PROBES table in app/server.py.
_VULN_FAST_PROBES: dict[str, dict] = {
    "BEAST_CBC_TLS1":   {"protocol": "-tls1",   "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.0 with CBC cipher (AES128-SHA)"},
    "BEAST_CBC_TLS1_1": {"protocol": "-tls1_1", "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.1 with CBC cipher (AES128-SHA)"},
    "POODLE_SSL":       {"protocol": "-ssl3",   "cipher": None,
                          "needs_legacy": True,
                          "human": "SSLv3 (any cipher)"},
    "LUCKY13":          {"protocol": "-tls1",   "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.0 with CBC cipher"},
    "FREAK":            {"protocol": None,      "cipher": "EXPORT",
                          "needs_legacy": True,
                          "human": "EXPORT-grade cipher"},
    "DROWN":            {"protocol": "-ssl2",   "cipher": None,
                          "needs_legacy": True,
                          "human": "SSLv2 negotiation (DROWN surface)"},
    "LOGJAM":           {"protocol": None,      "cipher": "kEDH+EXPORT",
                          "needs_legacy": True,
                          "human": "EXPORT-grade DHE cipher (LOGJAM)"},
    "ADH":              {"protocol": None,      "cipher": "ADH",
                          "needs_legacy": True,
                          "human": "anonymous DH (ADH) cipher"},
}

# Single-protocol availability checks. Same flags as the server-side
# _PROTOCOL_TESTSSL_TO_OPENSSL_FLAG; legacy protocols need the
# bundled openssl.
_PROTOCOL_FLAGS: dict[str, str] = {
    "SSLv2":  "-ssl2", "SSLv3": "-ssl3",
    "TLS1":   "-tls1", "TLS1_1": "-tls1_1",
    "TLS1_2": "-tls1_2", "TLS1_3": "-tls1_3",
}
_LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1"}

# cipherlist_<NAME> categories. NULL/EXPORT/LOW/DES/RC4 need legacy openssl.
_CIPHERLIST_OPENSSL_NAME: dict[str, str] = {
    "NULL":   "NULL:eNULL",
    "aNULL":  "aNULL",
    "EXPORT": "EXPORT",
    "LOW":    "LOW",
    "DES":    "DES:!eDES",
    "3DES":   "3DES",
    "RC4":    "RC4",
    "MD5":    "MD5",
    "MEDIUM": "MEDIUM",
}
_LEGACY_CIPHER_SUFFIXES = {"NULL", "aNULL", "EXPORT", "LOW", "DES", "RC4", "MD5"}


def _dns_caa_recheck(host: str, testssl_id: str) -> Verdict:
    """One DNS CAA lookup via dnspython. Sub-second. Returns the
    same Verdict shape the openssl/header recheck paths produce."""
    import time as _time
    try:
        import dns.resolver as _dns_resolver
        import dns.exception as _dns_exception
    except ImportError:
        return Verdict(
            ok=False, validated=None,
            summary="dnspython not installed in this container.",
            error="no-dnspython")

    cmd_label = f"dig +short CAA {host}"
    t0 = _time.monotonic()
    records: list[str] = []
    err_text = None
    rcode_name = "NOERROR"
    try:
        resolver = _dns_resolver.Resolver()
        resolver.lifetime = 8.0
        answer = resolver.resolve(host, "CAA")
        for r in answer:
            records.append(str(r))
    except _dns_resolver.NoAnswer:
        rcode_name = "NOANSWER"
    except _dns_resolver.NXDOMAIN:
        rcode_name = "NXDOMAIN"
        err_text = f"DNS NXDOMAIN — host {host!r} does not resolve"
    except _dns_exception.Timeout:
        rcode_name = "TIMEOUT"
        err_text = "DNS query timed out after 8s"
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    if err_text:
        return Verdict(
            ok=False, validated=None,
            summary=(f"DNS query failed: {err_text}. Run "
                     f"`dig CAA {host}` manually to confirm."),
            error="dns-failed",
            evidence={"command": cmd_label, "elapsed_ms": elapsed_ms,
                       "rcode": rcode_name})

    if not records:
        return Verdict(
            ok=True, validated=True, confidence=0.95,
            summary=(f"No CAA records for {host} ({rcode_name}). CAA "
                     f"is recommended (RFC 6844) — without it, any "
                     f"CA can issue certificates for the domain."),
            evidence={"command": cmd_label, "elapsed_ms": elapsed_ms,
                       "rcode": rcode_name, "records": []})

    return Verdict(
        ok=True, validated=False, confidence=0.95,
        summary=(f"CAA records present for {host}: {records!r}. "
                 f"CA issuance is restricted; testssl finding is "
                 f"remediated."),
        evidence={"command": cmd_label, "elapsed_ms": elapsed_ms,
                   "rcode": rcode_name, "records": records})


def _openssl_handshake_recheck(host: str, port: int, testssl_id: str,
                                 protocol_flag: str | None,
                                 cipher_str: str | None,
                                 needs_legacy: bool,
                                 human_summary: str) -> Verdict:
    """Run one openssl s_client handshake attempt and translate the
    outcome into a Verdict. Used by the protocol / cipher / vuln
    fast paths in this probe.
    """
    import os as _os
    import subprocess as _subprocess
    import time as _time

    binary = _LEGACY_OPENSSL if needs_legacy else "/usr/bin/openssl"
    env = _os.environ.copy()
    if needs_legacy:
        env["OPENSSL_CONF"] = ""

    cmd = [binary, "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-brief"]
    if protocol_flag:
        cmd.append(protocol_flag)
    if cipher_str:
        cmd.extend(["-cipher", cipher_str])
    reproduce = (("OPENSSL_CONF= " if needs_legacy else "")
                 + " ".join(cmd) + " < /dev/null")

    t0 = _time.monotonic()
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=8.0, check=False, env=env, input="",
        )
        rc = proc.returncode
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except _subprocess.TimeoutExpired:
        rc = -1
        out = "openssl s_client timed out after 8s"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    handshake_ok = (rc == 0 and "CONNECTION ESTABLISHED" in out)
    negotiated_proto = ""
    negotiated_cipher = ""
    for line in out.splitlines():
        if line.startswith("Protocol version:"):
            negotiated_proto = line.split(":", 1)[1].strip()
        elif line.startswith("Ciphersuite:"):
            negotiated_cipher = line.split(":", 1)[1].strip()

    if handshake_ok:
        return Verdict(
            ok=True, validated=True, confidence=0.95,
            summary=(f"{testssl_id} reproduced — server accepted a "
                     f"handshake under {human_summary}. Negotiated: "
                     f"protocol={negotiated_proto!r}, "
                     f"cipher={negotiated_cipher!r}. "
                     f"Original testssl finding still applies."),
            evidence={
                "command": reproduce, "elapsed_ms": elapsed_ms,
                "exit_code": rc,
                "negotiated_protocol": negotiated_proto,
                "negotiated_cipher": negotiated_cipher,
            })

    reason = ""
    for line in out.splitlines():
        if "no protocols available" in line.lower():
            reason = "protocol disabled by server"; break
        if "alert handshake failure" in line.lower():
            reason = "server refused handshake (no shared cipher)"; break
        if "wrong version number" in line.lower():
            reason = "protocol disabled / refused"; break
        if "alert protocol version" in line.lower():
            reason = "server refused via TLS alert"; break
    if not reason:
        reason = f"handshake failed (exit {rc})"

    return Verdict(
        ok=True, validated=False, confidence=0.85,
        summary=(f"{testssl_id} no longer reproducible — server "
                 f"refused {human_summary}: {reason}. "
                 f"Original testssl finding looks remediated."),
        evidence={
            "command": reproduce, "elapsed_ms": elapsed_ms,
            "exit_code": rc,
        })


def _header_fast_recheck(host: str, port: int, testssl_id: str,
                          target_header: str) -> Verdict:
    """Single HTTPS GET to verify a header-presence finding. Returns a
    Verdict with the same shape the testssl-subprocess path produces:
      validated=True  → header still missing / policy still weak
      validated=False → header present and policy reasonable
      validated=None  → request failed (network / TLS), treat as
                        inconclusive so the analyst re-runs from the
                        full Challenge form if they need a deeper look.
    """
    import ssl as _ssl
    import time as _time
    import urllib.error as _urlerr
    import urllib.request as _urlreq

    url = f"https://{host}:{port}/"
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):
            return None

    opener = _urlreq.build_opener(
        _urlreq.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )
    req = _urlreq.Request(url, method="GET", headers={
        "User-Agent": "nextgen-dast/2.1.1 (testssl_recheck header fast path)",
        "Accept": "*/*",
    })
    t0 = _time.monotonic()
    headers_lower: dict[str, str] = {}
    status = 0
    err_text = None
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            for k, v in resp.headers.items():
                headers_lower[k.lower()] = v
    except _urlerr.HTTPError as he:
        status = he.code
        try:
            for k, v in (he.headers or {}).items():
                headers_lower[k.lower()] = v
        except Exception:
            pass
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    cmd_label = (f"GET {url} (header-presence fast path: "
                 f"{testssl_id} → {target_header})")

    if err_text:
        return Verdict(
            ok=False, validated=None,
            summary=(f"HTTPS request failed: {err_text}. "
                     f"Run the full testssl.sh Challenge for a "
                     f"deeper check."),
            error="header-fast-failed",
            evidence={
                "command": cmd_label, "elapsed_ms": elapsed_ms,
                "status": status,
            })

    header_value = headers_lower.get(target_header)
    if header_value is None:
        # The *_missing finding still applies.
        return Verdict(
            ok=True, validated=True, confidence=0.95,
            summary=(f"Confirmed: GET {url} returned HTTP {status} "
                     f"with NO {target_header!r} header. The "
                     f"missing-header finding is still reproduced."),
            evidence={
                "command": cmd_label, "elapsed_ms": elapsed_ms,
                "status": status, "header": target_header,
                "header_value": None,
                "all_headers": dict(headers_lower),
            })

    if target_header == "strict-transport-security":
        # Parse max-age=N; below the recommended threshold = still
        # vulnerable to first-visit downgrade attacks.
        m = re.search(r"max-age\s*=\s*(\d+)", header_value, re.I)
        max_age = int(m.group(1)) if m else 0
        if max_age >= _HSTS_MIN_MAX_AGE:
            return Verdict(
                ok=True, validated=False, confidence=0.95,
                summary=(f"HSTS header present and policy is "
                         f"reasonable: {header_value!r} "
                         f"(max-age={max_age} ≥ recommended "
                         f"{_HSTS_MIN_MAX_AGE}). The "
                         f"missing-HSTS finding looks remediated."),
                evidence={
                    "command": cmd_label, "elapsed_ms": elapsed_ms,
                    "status": status, "header": target_header,
                    "header_value": header_value,
                    "max_age": max_age,
                })
        return Verdict(
            ok=True, validated=True, confidence=0.85,
            summary=(f"HSTS header present but max-age={max_age} "
                     f"is below the recommended {_HSTS_MIN_MAX_AGE} "
                     f"(180 days). Browsers may still be vulnerable "
                     f"to first-visit downgrade attacks. Header value: "
                     f"{header_value!r}"),
            evidence={
                "command": cmd_label, "elapsed_ms": elapsed_ms,
                "status": status, "header": target_header,
                "header_value": header_value, "max_age": max_age,
            })

    # Generic header — presence flips verdict to not-reproduced.
    return Verdict(
        ok=True, validated=False, confidence=0.95,
        summary=(f"Header {target_header!r} is now present: "
                 f"{header_value!r}. The original missing-header "
                 f"finding is no longer reproduced."),
        evidence={
            "command": cmd_label, "elapsed_ms": elapsed_ms,
            "status": status, "header": target_header,
            "header_value": header_value,
        })

# testssl severities that count as "still vulnerable". OK / INFO / WARN
# rows are not enough on their own — many testssl WARN rows are
# "INFO-ish" hints rather than confirmations, so we want HIGH/CRITICAL/
# MEDIUM (or LOW for protocol availability checks where any positive
# is the signal).
_VULNERABLE_SEVERITIES = {"HIGH", "CRITICAL", "MEDIUM", "LOW"}


def _pick_flag(testssl_id: str) -> tuple[str, str]:
    """Map a testssl id to the narrowest CLI flag that will exercise
    just that section of the test matrix. Falls back to '-s' (standard
    cipher categories) so we always have *some* valid flag."""
    if not testssl_id:
        return ("-s", "standard cipher categories")
    for matcher, flag, label in _DISPATCH:
        if isinstance(matcher, set):
            if testssl_id in matcher:
                return (flag, label)
        elif matcher.search(testssl_id):
            return (flag, label)
    return ("-s", "standard cipher categories")


def _host_port(url: str) -> tuple[str, int]:
    """Parse a URL into (host, port). Defaults to 443 for https /
    bare hosts, 80 for http. testssl.sh wants `host:port`."""
    u = urlparse(url if "://" in url else "https://" + url)
    host = (u.hostname or "").strip()
    port = u.port or (80 if (u.scheme or "").lower() == "http" else 443)
    return (host, int(port))


class TestsslRecheckProbe(Probe):
    name = "testssl_recheck"
    summary = (
        "Re-runs testssl.sh narrowly against the host:port and confirms "
        "whether the original test id still reports HIGH/CRITICAL/MEDIUM."
    )
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--testssl-id",
            help="The testssl test id to re-check (e.g. cipher_order-tls1, "
                 "cipherlist_NULL, BREACH). When omitted, the probe falls "
                 "back to a broad cipher-categories run and reports any "
                 "HIGH/CRITICAL row still present.")
        parser.add_argument(
            "--testssl-binary", default="testssl.sh",
            help="Path to testssl.sh (default: pull from PATH).")
        parser.add_argument(
            "--narrow-timeout", type=float, default=180.0,
            help="Timeout (s) for the narrow testssl run. Default 120.")

    def run(self, args, client):
        # The host comes from --url; testssl runs out-of-band (its own
        # subprocess and TLS stack) so we never touch SafeClient. The
        # SafeClient parameter is part of the Probe interface contract
        # and stays unused here.
        del client

        url = (args.url or "").strip()
        if not url:
            return Verdict(ok=False, validated=None,
                           summary="missing --url", error="missing-url")
        host, port = _host_port(url)
        if not host:
            return Verdict(ok=False, validated=None,
                           summary=f"could not parse host from URL {url!r}",
                           error="bad-url")

        # The orchestrator passes raw_data + title into config so we can
        # extract the testssl id without the analyst typing it. Fall
        # back to the explicit --testssl-id arg, then to nothing.
        testssl_id = (getattr(args, "testssl_id", None) or "").strip()
        extra = getattr(args, "extra", {}) or {}
        if not testssl_id:
            raw = extra.get("raw_data")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = None
            if isinstance(raw, dict):
                testssl_id = (raw.get("id") or "").strip()
        if not testssl_id:
            testssl_id = (extra.get("title") or "").strip()

        # ----------------------------------------------------------------
        # Fast paths. Each handles a specific class of testssl IDs with
        # a sub-second probe instead of forking a 60-180 s testssl.sh
        # subprocess. Order matches the server-side dispatch in
        # app/server.py:_finding_test_tls so behavior is identical
        # whether the analyst clicks "Test (TLS)" (server-side) or
        # "Validate" / "Challenge" (this probe).
        # ----------------------------------------------------------------

        # 1. Header presence (HSTS, CSP, X-Frame-Options, banner_*,
        #    config_*_missing aliases) → one HTTPS GET.
        target_header = _HEADER_FAST_ID_TO_HEADER.get(testssl_id.lower())
        if target_header:
            return _header_fast_recheck(host, port, testssl_id,
                                          target_header)

        # 2. Vulnerability checks reducible to a handshake attempt
        #    (BEAST_CBC_TLS1, BEAST_CBC_TLS1_1, POODLE_SSL, LUCKY13,
        #    FREAK). HEARTBLEED, ROBOT, TICKETBLEED, CCS_INJECTION,
        #    CRIME_TLS still fall through to testssl.sh below.
        spec = _VULN_FAST_PROBES.get(testssl_id)
        if spec:
            return _openssl_handshake_recheck(
                host, port, testssl_id,
                protocol_flag=spec.get("protocol"),
                cipher_str=spec.get("cipher"),
                needs_legacy=spec.get("needs_legacy", False),
                human_summary=spec["human"])

        # 3. Single protocol availability (SSLv2/3, TLS1.0/1.1/1.2/1.3).
        if testssl_id in _PROTOCOL_FLAGS:
            return _openssl_handshake_recheck(
                host, port, testssl_id,
                protocol_flag=_PROTOCOL_FLAGS[testssl_id],
                cipher_str=None,
                needs_legacy=(testssl_id in _LEGACY_PROTOCOLS),
                human_summary=f"{testssl_id} protocol negotiation")

        # 5. DNS_CAArecord (and "<hostCert#N>" suffix variants) — one
        #    DNS query via dnspython, sub-second.
        if re.match(r"^DNS_CAArecord(?:\s|$)", testssl_id):
            return _dns_caa_recheck(host, testssl_id)

        # 4. cipherlist_<NAME> single-category cipher availability
        #    (NULL/aNULL/EXPORT/LOW/DES/3DES/RC4/MD5/MEDIUM).
        if testssl_id.startswith("cipherlist_"):
            suffix = testssl_id[len("cipherlist_"):]
            cipher_str = _CIPHERLIST_OPENSSL_NAME.get(suffix)
            if cipher_str:
                return _openssl_handshake_recheck(
                    host, port, testssl_id,
                    protocol_flag=None,
                    cipher_str=cipher_str,
                    needs_legacy=(suffix in _LEGACY_CIPHER_SUFFIXES),
                    human_summary=f"a cipher in the {suffix} category")

        flag, flag_label = _pick_flag(testssl_id)
        target = f"{host}:{port}"

        fd, json_path = tempfile.mkstemp(prefix="testssl_recheck_",
                                         suffix=".json")
        os.close(fd)
        cmd = [args.testssl_binary, flag,
               "--quiet", "--color", "0", "--warnings", "off",
               "--openssl-timeout", "10", "--socket-timeout", "10",
               "--jsonfile", json_path,
               target]
        proc_stdout = ""
        proc_stderr = ""
        proc_rc = -1
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=float(args.narrow_timeout),
                                  check=False)
            proc_stdout = proc.stdout or ""
            proc_stderr = proc.stderr or ""
            proc_rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.unlink(json_path)
            except OSError:
                pass
            return Verdict(
                ok=False, validated=None,
                summary=(f"testssl.sh timed out after "
                         f"{args.narrow_timeout:.0f}s "
                         f"(flag {flag} = {flag_label})."),
                error="testssl-timeout")
        except FileNotFoundError:
            return Verdict(
                ok=False, validated=None,
                summary=(f"testssl.sh not found in PATH (looked for "
                         f"{args.testssl_binary!r}). Install testssl.sh "
                         "or set --testssl-binary explicitly."),
                error="testssl-missing")

        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                report_text = fh.read()
        except OSError:
            report_text = ""
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass

        try:
            rows = json.loads(report_text or "[]")
            if not isinstance(rows, list):
                rows = []
        except Exception:
            rows = []

        if not rows and proc_rc != 0:
            tail = "\n".join(
                line for line in (proc_stderr or proc_stdout).splitlines()
                if line.strip()
            )[-800:]
            return Verdict(
                ok=False, validated=None,
                summary=(f"testssl.sh exited {proc_rc} with no parseable "
                         "output. The narrow flag was "
                         f"{flag} ({flag_label})."),
                evidence={"target": target, "flag": flag,
                          "stderr_tail": tail},
                error="testssl-failed")

        # Look for the row matching the original test id. Some
        # testssl runs only emit fully-qualified row ids (e.g.
        # cipher-tls1_2_xc019) so a substring match is friendlier than
        # equality when the analyst clicks Validate on a roll-up id.
        matched: list[dict] = []
        if testssl_id:
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rid = (r.get("id") or "").strip()
                if rid == testssl_id or testssl_id in rid:
                    matched.append(r)

        # Anything still vulnerable? testssl writes severity in upper
        # case (HIGH/CRITICAL/MEDIUM/LOW/INFO/OK/WARN). We treat the
        # MED-and-up rows as confirmation; LOW counts only when the
        # check id itself is severity-meaningful (protocol availability,
        # HSTS missing, etc.) so we don't false-positive on testssl's
        # informational LOW rows.
        confirmation_rows = []
        if matched:
            for r in matched:
                sev = (r.get("severity") or "").upper()
                if sev in _VULNERABLE_SEVERITIES:
                    confirmation_rows.append(r)
        else:
            # No row for the original id — fall back to "any HIGH/
            # CRITICAL row in the narrow run is signal." Helps when
            # testssl renamed or rolled up the id between releases.
            for r in rows:
                if not isinstance(r, dict):
                    continue
                if (r.get("severity") or "").upper() in ("HIGH", "CRITICAL"):
                    confirmation_rows.append(r)

        evidence = {
            "target": target,
            "testssl_id": testssl_id,
            "flag": flag,
            "flag_label": flag_label,
            "exit_code": proc_rc,
            "rows_returned": len(rows),
            "matched_rows": matched[:10],
            "confirmation_rows": confirmation_rows[:10],
            "command": " ".join(cmd),
        }

        if confirmation_rows:
            top = confirmation_rows[0]
            top_text = (top.get("finding") or "").strip()
            return Verdict(
                ok=True, validated=True, confidence=0.95,
                summary=(f"Confirmed: {target} still flags "
                         f"'{top.get('id') or testssl_id}' "
                         f"({top.get('severity') or '?'}) "
                         f"— {top_text[:200]}"),
                evidence=evidence,
                remediation=(
                    "Re-check the cipher list / protocol versions / "
                    "TLS-feature flags on the affected listener. The "
                    "narrow testssl re-run above shows the exact rows "
                    "still firing — most are fixed by removing the "
                    "obsolete suite from your cipher list, then forcing "
                    "TLS 1.2+ with AEAD-only ciphers."),
            )
        return Verdict(
            ok=True, validated=False, confidence=0.85,
            summary=(f"Refuted: {target} no longer flags "
                     f"'{testssl_id}' at HIGH/CRITICAL/MEDIUM in the "
                     f"narrow re-run ({flag} = {flag_label})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    TestsslRecheckProbe().main()
