# Toolkit — finding validation probes

_Author: Tim Rice <tim.j.rice@hackrange.com>_

This directory holds **validation probes** — small, dynamic, single-purpose
scripts that take an *unvalidated finding* (something a scanner suspects)
and produce a *confirmed* or *rejected* verdict with concrete evidence.

The goal: turn "scanner thinks this might be SQLi" into "yes, here are the
two requests that prove it" or "no, the response is identical regardless
of payload — false positive, dismiss."

This is the next-gen-DAST half of the project. Scanners enumerate
suspicions; the toolkit confirms them.

## Design rules

1. **Every probe is a standalone CLI tool.** A human pentester can pull
   any probe out of this directory and run it directly against any target,
   passing arguments. No hard-coded targets, no app-specific assumptions.
2. **Two invocation modes:**
   - **CLI flags** — `python probes/sqli_boolean.py --url '...' --param id`
   - **`--stdin` JSON** — for machine-to-machine use (orchestrator → probe).
     The probe reads `{ url, method, param, cookie, headers, ... }` from stdin
     and writes a JSON verdict to stdout.
3. **JSON in / JSON out.** The verdict is always machine-readable so the
   LLM consolidation phase, the orchestrator, and the report renderer all
   speak the same language.
4. **Safety is non-optional.** Every probe goes through the `safety` lib
   for: hard request-count cap, rate limit, scope-host enforcement, dry-run
   mode, full audit log of every request sent. A probe that bypasses these
   is a bug.
5. **Three safety classes:**
   - `read-only` — only sends benign requests (HEAD/GET with the original
     payload from the finding). Default and always enabled.
   - `probe` — sends test payloads that change query params, headers, or
     bodies but cannot create/modify persistent state. Most validation
     work lives here.
   - `destructive` — could affect application state (POST creates, PUT
     updates, DELETE). **Never enabled by default.** Requires an explicit
     `--allow-destructive` flag at the per-run level *and* an admin-set
     environment toggle.
6. **No automatic re-runs of destructive actions.** Even when allowed, a
   destructive probe runs at most once per finding per session.

## Manifest

Every probe ships with a sibling `<name>.manifest.json` describing what
it does, what it doesn't do, and what arguments it accepts:

```json
{
  "name": "sqli_boolean",
  "version": "1.0",
  "summary": "Boolean-based SQLi confirmation via response-difference analysis.",
  "validates": ["A03:2021-Injection", "CWE-89"],
  "safety_class": "probe",
  "request_budget_typical": 4,
  "request_budget_max": 20,
  "args": {
    "--url": "Target URL with the parameter to test (required)",
    "--param": "Name of the parameter to inject into (required)",
    "--method": "HTTP method (default GET)",
    "--cookie": "Cookie header value (optional)",
    "--time-based": "Fall back to time-based detection if no boolean diff observed",
    "--threshold": "Response-size delta required to consider a diff significant (default 50 bytes)"
  }
}
```

## Probe contract

### Input (stdin JSON, when `--stdin` is passed)

```json
{
  "finding_id": 123,
  "url": "https://example.com/path?id=1",
  "method": "GET",
  "param": "id",
  "cookie": "session=abc123",
  "headers": {"X-Custom": "v"},
  "user_agent": "Mozilla/5.0 ...",
  "proxy": "http://127.0.0.1:8080",
  "scope_hosts": ["example.com"],
  "max_requests": 20,
  "max_rps": 1.0,
  "dry_run": false,
  "extra": { /* probe-specific config */ }
}
```

### Output (stdout JSON, always)

```json
{
  "ok": true,
  "validated": true,
  "confidence": 0.85,
  "summary": "Boolean-based SQLi confirmed in `id` param.",
  "evidence": {
    "true_payload":  "1 AND 1=1",
    "false_payload": "1 AND 1=2",
    "true_status":   200,
    "false_status":  200,
    "true_size":     4523,
    "false_size":    2104,
    "delta_bytes":   2419
  },
  "remediation": "Use parameterised queries (PDO/mysqli prepared statements).",
  "severity_uplift": "high",
  "audit_log": [
    {"req": "GET /path?id=1+AND+1%3D1", "status": 200, "size": 4523},
    {"req": "GET /path?id=1+AND+1%3D2", "status": 200, "size": 2104}
  ],
  "safety": {"requests_used": 4, "stopped_for": null}
}
```

`validated` is `true` only when the probe is confident the issue is real.
`false` means "tested and found nothing" (i.e., the scanner was wrong —
mark the finding as `false_positive`). Anything else uses
`"validated": null` and `"summary"` to explain (`"inconclusive"`,
`"target unreachable"`, etc.).

### Exit codes

- `0` — probe ran to completion (regardless of validation outcome)
- `1` — safety violation (out of scope, budget exceeded, refused)
- `2` — runtime error / target unreachable / unrecoverable

## Adding a new probe

1. Create `probes/<name>.py` extending `lib.probe.Probe`.
2. Create `probes/<name>.manifest.json` with the schema above.
3. Use `lib.http.SafeClient(...)` for every outbound request — never raw
   `requests` calls. The wrapper enforces the budget, rate limit, scope,
   and audit log automatically.
4. Test it standalone with `python probes/<name>.py --url ... --param ...`
   before wiring it into the orchestrator.
