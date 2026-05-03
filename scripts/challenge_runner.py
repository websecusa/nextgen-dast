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


# Verdict→status mapping and probe-config construction live in the
# shared toolkit module so the bulk runner and the per-finding /challenge
# route stay byte-identical. Earlier revisions duplicated this logic
# here and the two copies drifted: the bulk version omitted url-
# absolutization, raw_data pass-through, the destructive-method gate,
# and auth_username, which made the bulk runner systematically fail
# probes (auth_logout_does_not_invalidate, config_hsts_missing on
# path-only evidence URLs, etc.) that the per-finding click validated
# cleanly. Sharing the helpers makes that class of bug structurally
# impossible.


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

    # 2. Enumerate every open finding in the assessment with an
    # evidence URL, then bucket each one as eligible / skipped-by-
    # reason. We pull all severity levels and statuses up front (rather
    # than filtering in SQL) so the counts can be reported back to the
    # operator — the previous version filtered silently in SQL, which
    # made bulk runs look like they had simply "done nothing" when in
    # reality dozens of findings had been screened out.
    #
    # Skip rules:
    #   * info-severity     → reconnaissance signal, not vulnerabilities;
    #                         probing them produces noise and drains
    #                         budget without analyst value.
    #   * already-terminal  → validation_status in (validated,
    #                         false_positive). The probe already gave a
    #                         confident verdict; re-running on every
    #                         bulk pass would burn budget and pollute
    #                         the audit log. Re-runnable states
    #                         (inconclusive, errored, unvalidated)
    #                         flow through to the eligible bucket.
    #   * non-open status   → fixed / accepted_risk / false_positive on
    #                         findings.status — the analyst already
    #                         dispositioned the row. Skipping respects
    #                         that and avoids re-opening a closed
    #                         triage decision.
    #   * no probe match    → no toolkit probe is registered for this
    #                         (source_tool, owasp, cwe) combination.
    candidates = db.query(
        "SELECT * FROM findings WHERE assessment_id = %s "
        "  AND evidence_url IS NOT NULL AND evidence_url <> '' "
        "ORDER BY FIELD(severity,'critical','high','medium','low','info'), id",
        (aid,))

    # Lazy import of the fast-path classifier from server.py. Lets the
    # bulk runner also benefit from the deterministic urllib / openssl
    # / nmap / dnspython paths — without it, findings whose fast-path
    # exists but whose toolkit probe doesn't (header-missing rows from
    # nikto / wapiti / nuclei / LLM) would silently get bucketed as
    # "no_probe" and skipped. Same classifier the per-finding
    # Challenge button uses so the bulk pass and the manual click
    # always agree on what's eligible.
    try:
        from server import (
            _finding_has_fast_path as _has_fast_path,
            _dispatch_finding_fast_path as _dispatch_fast_path,
            _fast_path_response_to_verdict as _fast_path_to_verdict,
        )
    except Exception as _imp_err:
        print(f"[challenge_runner] WARN: fast-path import failed: "
              f"{_imp_err!r} — bulk run will skip fast-path-only "
              f"findings (no_probe bucket)", flush=True)
        _has_fast_path = lambda _f: False  # noqa: E731
        _dispatch_fast_path = None
        _fast_path_to_verdict = None

    skip_counts = {"info": 0, "terminal": 0, "non_open": 0, "no_probe": 0}
    # plan entries are (finding, probe_or_None). probe=None means
    # "use the fast-path dispatcher instead of a toolkit probe".
    plan: list[tuple[dict, Optional[dict]]] = []
    for f in candidates:
        if (f.get("severity") or "").lower() == "info":
            skip_counts["info"] += 1
            continue
        vs = (f.get("validation_status") or "unvalidated").lower()
        if vs in ("validated", "false_positive"):
            skip_counts["terminal"] += 1
            continue
        st = (f.get("status") or "open").lower()
        if st != "open":
            skip_counts["non_open"] += 1
            continue
        # Decode raw_data once so the fast-path classifier sees a
        # structured `raw` field (it inspects raw['id'] for testssl
        # IDs alongside title patterns).
        if f.get("raw_data") and not f.get("raw"):
            try:
                f["raw"] = json.loads(f["raw_data"])
            except Exception:
                f["raw"] = None
        p = toolkit_mod.find_probe_for_finding(f)
        if not p:
            # Before bucketing as no_probe, check whether the fast
            # path can handle this finding. Most header / cookie /
            # cipher / cert / DNS_CAA findings from non-testssl tools
            # land here — without this check, the bulk runner
            # silently dropped them.
            if _has_fast_path(f) and _dispatch_fast_path is not None:
                plan.append((f, None))   # probe=None signals fast-path
                continue
            skip_counts["no_probe"] += 1
            continue
        # safe-only mode adds one more filter: the matched probe must
        # be classified read-only. Stateful probes only run via the
        # manual per-finding Challenge button, where the analyst sees
        # the budget and confirms.
        if safe_only and (p.get("safety_class") != "read-only"):
            skip_counts["no_probe"] += 1
            continue
        plan.append((f, p))

    total = len(plan)
    skipped_total = sum(skip_counts.values())
    skip_summary = (f"skipped {skipped_total}: "
                    f"{skip_counts['terminal']} already-validated, "
                    f"{skip_counts['info']} info, "
                    f"{skip_counts['non_open']} closed-status, "
                    f"{skip_counts['no_probe']} no-probe")

    if not total:
        _step(aid, f"{label}: nothing to run — {skip_summary}")
        print(f"[challenge_runner] aid={aid} mode={label} eligible=0 "
              f"{skip_summary}", flush=True)
        return

    print(f"[challenge_runner] aid={aid} mode={label} eligible={total} "
          f"{skip_summary} auth_source={auth_diag.get('source')}", flush=True)

    # 4. Run each probe. Light pacing between findings to be polite to
    # the target — the per-probe SafeClient already rate-limits per
    # max_rps but we add a 0.5s gap between findings on top of that.
    counts = {"validated": 0, "false_positive": 0,
              "inconclusive": 0, "errored": 0}
    for i, (f, p) in enumerate(plan, 1):
        # Branch by entry type: probe=None means use the fast-path
        # dispatcher (header / cookie / cert / protocol / cipher /
        # vuln / DNS) instead of a toolkit probe subprocess.
        if p is None:
            probe_label = "fast_path"
            _step(aid, f"{label}: running probe {i}/{total} "
                       f"(fast_path on finding #{f['id']})")
            try:
                resp = _dispatch_fast_path(f)
                if resp is None:
                    # Defensive — has_fast_path said yes but dispatcher
                    # returned None. Treat as errored so the analyst
                    # can investigate; don't silently skip.
                    verdict = {"ok": False, "error": "dispatcher_miss"}
                else:
                    verdict = _fast_path_to_verdict(resp)
            except Exception as e:
                verdict = {"ok": False,
                            "error": f"{type(e).__name__}: {e}"}
        else:
            probe_label = p["name"][:64]
            _step(aid, f"{label}: running probe {i}/{total} "
                       f"({p['name']} on finding #{f['id']})")
            # Shared config + timeout + verdict mapping with the per-finding
            # /challenge route. See toolkit.build_finding_config for what
            # gets populated; the bulk runner used to have its own stripped-
            # down version, which was the root cause of probes (auth_logout,
            # config_hsts on path-only urls, etc.) silently erroring under
            # bulk Challenge while the per-finding click validated them.
            config = toolkit_mod.build_finding_config(
                f, p, cookie=session_cookie)
            timeout = toolkit_mod.probe_timeout(p)
            try:
                verdict = toolkit_mod.run_probe(
                    p["name"], config, timeout=timeout)
            except Exception as e:
                verdict = {"ok": False,
                            "error": f"{type(e).__name__}: {e}"}

        # Decorate with auth diagnostics + scrub any echoed Cookie headers.
        if isinstance(verdict, dict):
            verdict.setdefault("auth", {}).update(auth_diag)
            for entry in verdict.get("audit_log") or []:
                if "headers" in entry:
                    entry["headers"].pop("Cookie", None)

        new_status = toolkit_mod.verdict_to_status(verdict)
        counts[new_status] = counts.get(new_status, 0) + 1

        # Same write logic as the per-finding route: flip findings.status
        # too when the verdict is a confident false positive.
        if new_status == "false_positive":
            db.execute(
                "UPDATE findings SET validation_status = %s, "
                "validation_probe = %s, validation_run_at = NOW(), "
                "validation_evidence = %s, status = 'false_positive' "
                "WHERE id = %s",
                (new_status, probe_label,
                 json.dumps(verdict, default=str)[:65000], f["id"]))
        else:
            db.execute(
                "UPDATE findings SET validation_status = %s, "
                "validation_probe = %s, validation_run_at = NOW(), "
                "validation_evidence = %s WHERE id = %s",
                (new_status, probe_label,
                 json.dumps(verdict, default=str)[:65000], f["id"]))

        time.sleep(0.5)

    # Final summary includes both run counts and skip-reason counts so
    # the operator can see at a glance why "Challenge all" did N of M
    # — e.g. "done: 4 validated, 0 fp, 1 inconclusive, 0 errored;
    # skipped 8: 6 already-validated, 2 info" makes the gap legible.
    summary = (f"{label}: done — {counts['validated']} validated, "
               f"{counts['false_positive']} false-positive, "
               f"{counts['inconclusive']} inconclusive, "
               f"{counts['errored']} errored; {skip_summary}")
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
