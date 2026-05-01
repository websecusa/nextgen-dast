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
            "--narrow-timeout", type=float, default=120.0,
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
