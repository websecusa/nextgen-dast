#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Bulk-challenge runner.

Walks every finding in an assessment that (a) is currently `open` and
unvalidated, and (b) has a toolkit probe matched to it, and runs the
matched probe against each one. Updates the finding's validation_status
+ validation_evidence, and flips status='false_positive' when the probe
is confident the finding is a false positive.

Spawned by the web UI as a detached subprocess:
    python -m scripts.challenge_runner <assessment_id>
    python -m scripts.challenge_runner --safe-only <assessment_id>

`--safe-only` restricts the run to probes whose manifest declares
`safety_class: read-only`. This is the mode the orchestrator invokes
automatically at the end of every scan: read-only probes never modify
target state, so they are safe to fire without analyst confirmation
and they pre-eliminate scanner false positives before the analyst
opens the assessment. The full bulk-Challenge button (no flag) still
runs every matched probe class.

The web UI re-uses the same `current_step` field on the assessments row
that the orchestrator uses, so the existing /assessment/<id>/status
polling reflects bulk-challenge progress with no extra plumbing.

Auth: the runner re-uses the assessment's stored creds via
auth.form_login_cookie() exactly the same way the per-finding Challenge
button does. Login happens ONCE for the whole batch — every probe in
this run shares the same session cookie, so we don't hammer the login
endpoint with N parallel re-logins. If the session expires mid-batch
(server-side timeout), the next probe's authenticated baseline will
return a non-2xx and the verdict will fall through to 'inconclusive',
which is the safe behavior; the analyst can re-run or click the per-
finding Challenge button for those.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, "/app")
import db                              # noqa: E402
import auth as auth_mod                # noqa: E402
import toolkit as toolkit_mod          # noqa: E402


def _now():
    """Naive UTC for pymysql DATETIME bindings."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _verdict_to_status(verdict: dict) -> str:
    """Same mapping as server._verdict_to_status — duplicated here so
    this script can run standalone without importing the FastAPI app.

    Distinguish a real crash (`error` field set — subprocess exception,
    safety violation) from a soft refusal (probe ran cleanly but
    declined to produce a verdict — `ok=False`, no error). The earlier
    revision lumped both into 'errored', which had two bad effects:
    the analyst saw a red badge for a perfectly clean run that just
    needed different inputs, and the next bulk pass would skip those
    findings as terminal even though they were re-runnable. Soft
    refusals now collapse to 'inconclusive'.
    """
    if verdict.get("error"):
        return "errored"
    if not verdict.get("ok", True):
        return "inconclusive"
    v = verdict.get("validated")
    if v is True:
        return "validated"
    if v is False:
        if (verdict.get("confidence") or 0) >= 0.8:
            return "false_positive"
        return "inconclusive"
    return "inconclusive"


def _build_probe_config(finding: dict, probe: dict,
                        cookie: Optional[str]) -> dict:
    """Same shape that server._run_finding_probe produces."""
    from urllib.parse import urlparse
    parsed = urlparse(finding.get("evidence_url") or "")
    config: dict = {
        "url": finding.get("evidence_url") or "",
        "method": (finding.get("evidence_method") or "GET").upper(),
        "scope": [parsed.hostname] if parsed.hostname else [],
        "max_requests": int(probe.get("request_budget_max") or 30),
        "max_rps": 5.0,
        "dry_run": False,
    }
    if cookie:
        config["cookie"] = cookie
    return config


def _step(aid: int, msg: str) -> None:
    """Write a one-line progress message to assessments.current_step
    so the web UI's existing /status polling can show progress."""
    db.execute("UPDATE assessments SET current_step = %s WHERE id = %s",
               (msg[:255], aid))


def run(aid: int, safe_only: bool = False) -> None:
    a = db.query_one("SELECT * FROM assessments WHERE id = %s", (aid,))
    if not a:
        print(f"[challenge_runner] no assessment {aid}", flush=True)
        sys.exit(2)

    # The current_step messages share a prefix that distinguishes the
    # automatic post-scan run from a manually-triggered bulk Challenge.
    # The web UI's status polling shows it verbatim.
    label = "auto_validate" if safe_only else "challenge_all"

    # 1. Resolve a session cookie ONCE for the whole batch. We re-use
    # auth.form_login_cookie() so the failure-mode diagnostics are the
    # same shape the per-finding Challenge route emits.
    session_cookie: Optional[str] = None
    auth_diag: dict = {"source": "anonymous",
                       "reason": "no creds + no manual cookie"}
    if (a.get("creds_username") and a.get("creds_password")
            and a.get("login_url")):
        _step(aid, f"{label}: logging in")
        result = auth_mod.form_login_cookie(
            a["login_url"], a["creds_username"], a["creds_password"])
        if result.get("ok"):
            session_cookie = result["cookie"]
            auth_diag = {
                "source": "form-login",
                "redacted_cookie": auth_mod.redact_cookie(result["cookie"]),
                "login_diagnostics": result.get("diagnostics") or {},
            }
        else:
            auth_diag = {
                "source": "anonymous",
                "reason": "form-login failed",
                "login_error": result.get("error"),
                "login_diagnostics": result.get("diagnostics") or {},
            }

    # 2. Enumerate candidate findings — open + has an evidence URL +
    # severity is actionable + validation_status is non-terminal. Info-
    # severity rows are skipped because they're reconnaissance signal
    # rather than vulnerabilities and burning probe budget on them
    # dilutes the run. Validation states are split into terminal vs
    # re-runnable: 'validated' and 'false_positive' are terminal (the
    # probe already gave a confident verdict and the analyst should
    # review manually before re-firing), while 'errored' and
    # 'inconclusive' are re-runnable — a transient probe failure or a
    # bad first attempt should NOT freeze the finding out of every
    # subsequent bulk run, which is the trap the per-finding Challenge
    # button avoided but this filter previously walked into.
    findings = db.query(
        "SELECT * FROM findings WHERE assessment_id = %s "
        "  AND COALESCE(status,'open') = 'open' "
        "  AND COALESCE(validation_status,'unvalidated') "
        "      NOT IN ('validated','false_positive') "
        "  AND severity IN ('critical','high','medium','low') "
        "  AND evidence_url IS NOT NULL AND evidence_url <> '' "
        "ORDER BY FIELD(severity,'critical','high','medium','low'), id",
        (aid,))

    # 3. Filter to ones that have a probe match. In safe-only mode we
    # additionally require the matched probe to be classified
    # `read-only` — anything that injects payloads or modifies state
    # falls back to the manual Challenge button, where the analyst
    # sees the budget and confirms before it runs.
    plan: list[tuple[dict, dict]] = []
    for f in findings:
        p = toolkit_mod.find_probe_for_finding(f)
        if not p:
            continue
        if safe_only and (p.get("safety_class") != "read-only"):
            continue
        plan.append((f, p))

    total = len(plan)
    if not total:
        _step(aid, f"{label}: no eligible findings (skipped or no probes)")
        print("[challenge_runner] nothing to do", flush=True)
        return

    print(f"[challenge_runner] aid={aid} mode={label} eligible={total} "
          f"auth_source={auth_diag.get('source')}", flush=True)

    # 4. Run each probe. Light pacing between findings to be polite to
    # the target — the per-probe SafeClient already rate-limits per
    # max_rps but we add a 0.5s gap between findings on top of that.
    counts = {"validated": 0, "false_positive": 0,
              "inconclusive": 0, "errored": 0}
    for i, (f, p) in enumerate(plan, 1):
        _step(aid, f"{label}: running probe {i}/{total} "
                   f"({p['name']} on finding #{f['id']})")
        config = _build_probe_config(f, p, session_cookie)
        # per-probe timeout from manifest typical budget × 2, clamped 30..120s
        typical = int(p.get("request_budget_typical") or 12)
        timeout = min(120.0, max(30.0, typical * 2.0))
        try:
            verdict = toolkit_mod.run_probe(p["name"], config, timeout=timeout)
        except Exception as e:
            verdict = {"ok": False, "error": f"{type(e).__name__}: {e}"}

        # Decorate with auth diagnostics + scrub any echoed Cookie headers.
        if isinstance(verdict, dict):
            verdict.setdefault("auth", {}).update(auth_diag)
            for entry in verdict.get("audit_log") or []:
                if "headers" in entry:
                    entry["headers"].pop("Cookie", None)

        new_status = _verdict_to_status(verdict)
        counts[new_status] = counts.get(new_status, 0) + 1

        # Same write logic as the per-finding route: flip findings.status
        # too when the verdict is a confident false positive.
        if new_status == "false_positive":
            db.execute(
                "UPDATE findings SET validation_status = %s, "
                "validation_probe = %s, validation_run_at = NOW(), "
                "validation_evidence = %s, status = 'false_positive' "
                "WHERE id = %s",
                (new_status, p["name"][:64],
                 json.dumps(verdict, default=str)[:65000], f["id"]))
        else:
            db.execute(
                "UPDATE findings SET validation_status = %s, "
                "validation_probe = %s, validation_run_at = NOW(), "
                "validation_evidence = %s WHERE id = %s",
                (new_status, p["name"][:64],
                 json.dumps(verdict, default=str)[:65000], f["id"]))

        time.sleep(0.5)

    summary = (f"{label}: done — {counts['validated']} validated, "
               f"{counts['false_positive']} false-positive, "
               f"{counts['inconclusive']} inconclusive, "
               f"{counts['errored']} errored")
    _step(aid, summary)
    print(f"[challenge_runner] {summary}", flush=True)


if __name__ == "__main__":
    # Argv shapes:
    #   challenge_runner.py <assessment_id>
    #   challenge_runner.py --safe-only <assessment_id>
    args = sys.argv[1:]
    safe_only = False
    if args and args[0] == "--safe-only":
        safe_only = True
        args = args[1:]
    if len(args) != 1 or not args[0].isdigit():
        print("usage: challenge_runner.py [--safe-only] <assessment_id>",
              file=sys.stderr)
        sys.exit(2)
    run(int(args[0]), safe_only=safe_only)
