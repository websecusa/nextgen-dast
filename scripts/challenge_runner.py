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

Scoring policy (must stay in sync with reports._score_findings):
  * Errored verdicts are retried up to ERROR_RETRY_ATTEMPTS times
    (currently 3) so a transient subprocess crash or network blip
    doesn't park a real finding in the errored bucket.
  * Inconclusive verdicts force severity='info' on the finding so the
    UI / report / heatmap stop showing a critical/high badge the
    probe couldn't prove. The original severity is preserved in
    raw_data.original_severity for analyst review.
  * Only `validated` findings ever contribute to the score; the
    challenge pass is therefore on the critical path of every scan
    (called by the orchestrator before status='done' is written).
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
    #   * false_positive    → validation_status == 'false_positive'.
    #                         Either the probe was confident the
    #                         finding wasn't real OR the analyst
    #                         clicked "Mark false positive". Either
    #                         way it's intentional triage, and bulk
    #                         re-running could undo that suppression
    #                         if the probe later changes its mind.
    #                         (validated is NOT skipped here -- when
    #                         a probe is updated, previously-validated
    #                         findings need to be re-evaluated against
    #                         the new logic, otherwise stale verdicts
    #                         live on forever. The write path below
    #                         guards against a flaky re-run degrading
    #                         a confident validated verdict.)
    #   * non-open status   → fixed / accepted_risk / false_positive on
    #                         findings.status — the analyst already
    #                         dispositioned the row. Skipping respects
    #                         that and avoids re-opening a closed
    #                         triage decision.
    #   * no probe match    → no toolkit probe is registered for this
    #                         (source_tool, owasp, cwe) combination.
    # No evidence_url filter here on purpose: LLM-emitted findings
    # often omit the top-level evidence_url and embed the test URL
    # inside raw_data.llm_reproduction / llm_evidence instead, and
    # _dispatch_finding_fast_path will derive a target host from those
    # (or fall back to the assessment fqdn) for header / cookie / TLS
    # checks. The classifier is the source of truth for "can we run a
    # fast path?"; rejecting URL-less findings at the SQL layer would
    # silently skip them and disagree with the per-finding Challenge
    # button.
    candidates = db.query(
        "SELECT * FROM findings WHERE assessment_id = %s "
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

    skip_counts = {"info": 0, "false_positive": 0, "non_open": 0,
                    "no_probe": 0}
    # plan entries are (finding, probe_or_None). probe=None means
    # "use the fast-path dispatcher instead of a toolkit probe".
    plan: list[tuple[dict, Optional[dict]]] = []
    for f in candidates:
        if (f.get("severity") or "").lower() == "info":
            skip_counts["info"] += 1
            continue
        vs = (f.get("validation_status") or "unvalidated").lower()
        if vs == "false_positive":
            # Confident refutation OR analyst override -- both are
            # intentional triage. Don't undo it on a bulk pass. To
            # re-evaluate a false_positive, the analyst clicks the
            # per-finding Challenge button.
            skip_counts["false_positive"] += 1
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
                    f"{skip_counts['false_positive']} false-positive, "
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
    #
    # Each probe gets up to ERROR_RETRY_ATTEMPTS total attempts when the
    # verdict comes back 'errored' (subprocess crash, network blip,
    # transient SafeClient failure). Two extra retries on top of the
    # first attempt brings the bulk pass in line with the scoring
    # policy: only validated findings count, and the analyst should not
    # see a flaky one-shot run drop a real exploit into the errored
    # bucket. Retries are bounded so a persistently broken probe still
    # finishes the batch in reasonable time. Inconclusive verdicts are
    # NOT retried here — those are decisive enough (the probe ran, the
    # evidence was ambiguous) and the analyst can manually re-challenge.
    ERROR_RETRY_ATTEMPTS = 3
    counts = {"validated": 0, "false_positive": 0,
              "inconclusive": 0, "errored": 0}

    def _run_once(finding, probe):
        """Execute one attempt of (finding, probe). probe=None routes
        to the fast-path dispatcher. Returns a verdict dict; never
        raises (any exception is wrapped into a verdict with
        error=type:msg so the caller can decide whether to retry)."""
        if probe is None:
            try:
                resp = _dispatch_fast_path(finding)
                if resp is None:
                    # Defensive — has_fast_path said yes but dispatcher
                    # returned None. Treat as errored so the analyst
                    # can investigate; don't silently skip.
                    return {"ok": False, "error": "dispatcher_miss"}
                return _fast_path_to_verdict(resp)
            except Exception as e:
                return {"ok": False,
                        "error": f"{type(e).__name__}: {e}"}
        # Shared config + timeout + verdict mapping with the per-finding
        # /challenge route. See toolkit.build_finding_config for what
        # gets populated; the bulk runner used to have its own stripped-
        # down version, which was the root cause of probes (auth_logout,
        # config_hsts on path-only urls, etc.) silently erroring under
        # bulk Challenge while the per-finding click validated them.
        cfg = toolkit_mod.build_finding_config(
            finding, probe, cookie=session_cookie)
        tout = toolkit_mod.probe_timeout(probe)
        try:
            return toolkit_mod.run_probe(probe["name"], cfg, timeout=tout)
        except Exception as e:
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}"}

    for i, (f, p) in enumerate(plan, 1):
        # Branch by entry type for the status line: probe=None means
        # use the fast-path dispatcher (header / cookie / cert /
        # protocol / cipher / vuln / DNS) instead of a toolkit probe
        # subprocess.
        if p is None:
            probe_label = "fast_path"
            _step(aid, f"{label}: running probe {i}/{total} "
                       f"(fast_path on finding #{f['id']})")
        else:
            probe_label = p["name"][:64]
            _step(aid, f"{label}: running probe {i}/{total} "
                       f"({p['name']} on finding #{f['id']})")

        # Run, with retries when the verdict bucket is 'errored'.
        # Each retry waits a short, growing delay so a target that's
        # briefly overloaded gets time to recover.
        verdict = _run_once(f, p)
        new_status = toolkit_mod.verdict_to_status(verdict)
        attempts = 1
        while new_status == "errored" and attempts < ERROR_RETRY_ATTEMPTS:
            print(f"[challenge_runner] errored attempt {attempts}/"
                  f"{ERROR_RETRY_ATTEMPTS} on finding #{f['id']} "
                  f"(probe={probe_label}, error="
                  f"{verdict.get('error') if isinstance(verdict, dict) else 'unknown'!r}) "
                  "— retrying", flush=True)
            _step(aid, f"{label}: retry {attempts}/{ERROR_RETRY_ATTEMPTS - 1} "
                       f"on finding #{f['id']} ({probe_label})")
            time.sleep(1.0 * attempts)
            verdict = _run_once(f, p)
            new_status = toolkit_mod.verdict_to_status(verdict)
            attempts += 1

        # Decorate with auth diagnostics + scrub any echoed Cookie headers.
        if isinstance(verdict, dict):
            verdict.setdefault("auth", {}).update(auth_diag)
            if attempts > 1:
                # Surface retry count in evidence so the analyst can see
                # this verdict took N tries (helpful when triaging an
                # 'errored' that finally landed on inconclusive).
                verdict["challenge_attempts"] = attempts
            for entry in verdict.get("audit_log") or []:
                if "headers" in entry:
                    entry["headers"].pop("Cookie", None)

        counts[new_status] = counts.get(new_status, 0) + 1

        # No-downgrade guard. We re-run validated findings (so a
        # probe-update can re-classify stale verdicts), but a flaky
        # network re-run that returns inconclusive / errored MUST NOT
        # wipe out a previously-confident validated verdict. Apply the
        # new verdict only when it's at least as decisive as the old
        # one. The hierarchy is: false_positive / validated  >>
        # inconclusive / errored. (The earlier per-finding behavior
        # always wrote unconditionally; that's fine for an explicit
        # analyst click but unsafe under bulk where one transient
        # connection failure could erase dozens of confident verdicts.)
        prior_vs = (f.get("validation_status") or "unvalidated").lower()
        if (prior_vs == "validated"
                and new_status in ("inconclusive", "errored")):
            print(f"[challenge_runner] preserving validated verdict on "
                  f"finding #{f['id']} -- new run was {new_status} "
                  f"(probe={probe_label}, will not downgrade)",
                  flush=True)
            time.sleep(0.5)
            continue

        # Same write logic as the per-finding route: flip findings.status
        # too when the verdict is a confident false positive. An
        # inconclusive verdict additionally downgrades the finding's
        # severity to 'info' — the scoring policy is validated-only, and
        # an unprovable finding should not present in the UI with a
        # critical/high badge it didn't earn. The original severity is
        # preserved in raw_data.original_severity so an analyst who
        # later re-challenges can see what the scanner originally
        # claimed.
        if new_status == "false_positive":
            db.execute(
                "UPDATE findings SET validation_status = %s, "
                "validation_probe = %s, validation_run_at = NOW(), "
                "validation_evidence = %s, status = 'false_positive' "
                "WHERE id = %s",
                (new_status, probe_label,
                 json.dumps(verdict, default=str)[:65000], f["id"]))
        elif new_status == "inconclusive":
            original_sev = (f.get("severity") or "info").lower()
            if original_sev != "info":
                # Stash the original severity in raw_data so the
                # downgrade is reversible and auditable. raw_data is a
                # JSON TEXT column.
                try:
                    raw_obj = json.loads(f.get("raw_data") or "{}")
                    if not isinstance(raw_obj, dict):
                        raw_obj = {"_wrapped": raw_obj}
                except Exception:
                    raw_obj = {}
                raw_obj.setdefault("original_severity", original_sev)
                new_raw = json.dumps(raw_obj, default=str)[:65000]
                db.execute(
                    "UPDATE findings SET validation_status = %s, "
                    "validation_probe = %s, validation_run_at = NOW(), "
                    "validation_evidence = %s, severity = 'info', "
                    "raw_data = %s WHERE id = %s",
                    (new_status, probe_label,
                     json.dumps(verdict, default=str)[:65000],
                     new_raw, f["id"]))
            else:
                db.execute(
                    "UPDATE findings SET validation_status = %s, "
                    "validation_probe = %s, validation_run_at = NOW(), "
                    "validation_evidence = %s WHERE id = %s",
                    (new_status, probe_label,
                     json.dumps(verdict, default=str)[:65000], f["id"]))
        else:
            # Special case: a probe that errors out against an
            # enhanced_ai_testing-source finding is almost always a
            # schema mismatch (the LLM emits a vulnerability
            # description without a probe-shaped evidence_url, so the
            # toolkit probe or fast-path dispatcher cannot construct a
            # valid request) rather than a real refutation. Writing
            # 'errored' onto these rows traps them in a non-default
            # validation_status that the LLM fidelity grader then
            # skips, leaving the LLM's most actionable findings stuck
            # in limbo. Preserve the prior validation_status (typically
            # the default 'unvalidated') so the fidelity loop and the
            # UI both see them as still triageable; record what the
            # probe attempted in validation_evidence so an analyst can
            # see why no verdict landed.
            if (new_status == "errored"
                    and (f.get("source_tool") or "").lower() == "enhanced_ai_testing"):
                db.execute(
                    "UPDATE findings SET "
                    "validation_probe = %s, validation_run_at = NOW(), "
                    "validation_evidence = %s WHERE id = %s",
                    (probe_label,
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
