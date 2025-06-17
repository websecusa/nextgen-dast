# Parameter discovery — design plan

**Status:** Not implemented. Phase-1 ffuf integration (content discovery)
shipped 2026-04-27 in commit `ba2c961`. This document describes the
follow-up that adds *parameter-name discovery* and feeds discovered
params into the existing high-fidelity probes.

**Author:** Tim Rice <tim.j.rice@hackrange.com>
**Target version:** Defer the version bump until implementation lands —
2.1.1 stays 2.1.1 until then.

---

## Why this matters

The current `sqli_boolean` and `xss_reflect` probes accept `--param
<name>` and require the orchestrator to *already know* the parameter
name. Today that name comes from one of three places:

1. The user types the URL with a query string already on it
   (`/products?id=1`).
2. sqlmap or wapiti found it during their own crawl.
3. The orchestrator's authentication-flow capture observed it in a
   form post.

Plenty of real-world bugs hide in parameters that none of those three
sources surface — debug toggles, internal feature flags, legacy fields
the form no longer renders. ffuf's parameter-fuzzing mode finds those
by brute force; if we then feed each `(url, param_name)` pair into
sqli_boolean and xss_reflect, we get high-fidelity validation of bugs
no other scanner in the stack can find.

This is a meaningful differentiator for the AI consolidation phase too:
"hidden parameter X on URL Y is vulnerable to SQLi" is a much higher-
quality finding than "URL Y is on the attack surface."

---

## Scope

**In scope (phase 2):**

- New ffuf phase: discover parameter *names* on each interesting URL
  surfaced by the phase-1 content-discovery pass.
- Persist discovered `(url, param_name)` pairs to the scan directory
  in a stable JSON shape.
- Iterate `sqli_boolean` and `xss_reflect` over each pair; emit one
  enhanced_testing finding per probe verdict.
- Hard request-budget caps so a 5K-path × 6.5K-param matrix cannot
  run away on a slow target.

**Explicitly out of scope (deferred):**

- Header-name fuzzing (`X-FUZZ: x`).
- POST-body field discovery (different wordlist, different request
  shape, different baseline-detection problem).
- Cookie-name fuzzing.
- WebSocket / GraphQL parameter discovery.

These are real attack surfaces but each is its own probe, with its own
edge cases. Ship the GET-query-string case first.

---

## Architectural shape

Three orchestrator phases run in order:

```
ffuf-content     -> /data/scans/<id>/ffuf/report.json
ffuf-params      -> /data/scans/<id>/ffuf-params/discovered.json
probe-targeted   -> /data/scans/<id>/verdicts/<probe>__<url-hash>.json
```

### Phase 2a: parameter discovery

For each URL in the content-discovery results that:

- returned 200 (skip 301/302/401/403 — different baseline behavior, see
  open questions below),
- is not a static-file extension (`.css`, `.js`, `.png`, `.svg`,
  `.woff*`, `.ico`, `.map`, `.pdf`),
- is on the same host as the target,

run:

```
ffuf -u 'https://target/path?FUZZ=hackrange-probe' \
     -w /opt/wordlists/burp-parameter-names.txt \
     -of json \
     -o /data/scans/<id>/ffuf-params/<url-hash>.json \
     -mc all \
     -fs <baseline_size> \
     -ac \
     -t 20 -rate 40 -timeout 10 -maxtime 60 \
     -x <proxy_url>
```

Two filtering primitives matter here and BOTH need to be on:

- `-fs <baseline_size>`: drop responses whose body length matches the
  unmodified URL's response length (`?FUZZ=x` should change the body
  if the param matters; if it doesn't, the param is being ignored).
- `-ac`: auto-calibrate against random-string baselines so a server
  that returns a stable 200 page for *any* unknown param doesn't
  generate 6.5K false positives.

After ffuf completes, write a consolidated file:

```json
// /data/scans/<id>/ffuf-params/discovered.json
{
  "scanned_at": "2026-04-27T14:00:00Z",
  "results": [
    {"url": "https://target/products", "param": "id"},
    {"url": "https://target/products", "param": "debug"},
    {"url": "https://target/account", "param": "uid"}
  ]
}
```

### Phase 2b: probe-targeted iteration

The orchestrator reads `discovered.json` and, for each
`(url, param)` pair, invokes:

```
python /app/toolkit/probes/sqli_boolean.py \
    --url <url> --param <param> --cookie <session> \
    --stdin <orchestrator-context-json> \
  > /data/scans/<id>/verdicts/sqli_boolean__<url-hash>__<param>.json
```

…and the same for `xss_reflect`. Probes already accept `--param` and
emit `verdicts/<probe>.json`-shaped output, so this is iteration plus
a unique output filename per pair.

### Findings

`findings.parse_enhanced_testing()` already walks `verdicts/` and emits
one finding per verdict file. The unique filename pattern keeps each
`(probe, url, param)` triple as a distinct finding without changes
to the parser.

---

## Wordlist

- Source: SecLists `Discovery/Web-Content/burp-parameter-names.txt`
  (~6.5K entries, MIT-licensed).
- Vendored at `toolkit/wordlists/burp-parameter-names.txt` (matches
  the convention established in `web-content.txt` for offline builds).
- Refresh notes go in the existing `toolkit/wordlists/SOURCES.md`.

---

## Request budget

This is the hardest part of the design. Naive
`paths × params = 4750 × 6500 = ~30M requests` is unacceptable.

### Caps

- Phase 2a only fuzzes paths that returned 200 in phase 1. Realistic
  target: 5–50 paths per scan, not 4750.
- `-maxtime 60` per ffuf invocation: hard ceiling of one minute of
  fuzzing per URL.
- Global cap on phase 2b: max 200 `(url, param)` pairs to probe. If
  ffuf finds more, sample by precedence (admin-shaped paths first,
  then anything containing `id|user|file|path|cmd` in the param name,
  then everything else). Reject the rest and log the count.
- Per-probe budgets are already enforced inside each probe
  (`request_budget_max` in the manifest) — no orchestrator change
  needed for this layer.

### Observed worst-case

Approximate worst case for a typical target on the `premium` profile:

```
phase 2a:   30 URLs × 60s ffuf  = 30 min, ~6.5K req/URL = 195K req
phase 2b:   200 (url,param) × 20 req/probe × 2 probes  = 8K req
```

Total adds ~30–45 minutes to a `premium` scan. Acceptable for the
`premium` tier; do NOT add to `thorough`.

---

## Open questions (resolve before implementing)

1. **Authentication context propagation.** sqli_boolean/xss_reflect
   already take `--cookie`. ffuf parameter discovery should run with
   the same authenticated cookie so we discover post-login parameters.
   The orchestrator's auth-flow capture already produces a session
   cookie for the existing probe pass — confirm the cookie value is
   threaded through phase 2a, not just phase 2b.

2. **301/302/401/403 paths.** A redirect on a known param can mean
   "param caused a different code path." A 401 on a known param can
   mean "param triggered an auth check." Both are interesting. But
   they break the `-fs <baseline_size>` filter because the body is
   short and stable. Decision needed: skip these (cheap, miss bugs),
   or run a different filtering strategy (e.g., `-fc` filter on the
   exact baseline status code, accept all *other* status codes).
   Recommendation: skip in v1, revisit if real findings come from
   redirects in production scans.

3. **Param-name interaction with reflected-XSS context.** xss_reflect
   today injects a unique nonce and looks for it in the response. With
   parameter discovery, we may find params whose value is reflected
   into a JavaScript context, an HTML attribute, or a JSON response
   body. The probe's existing `--length` arg already handles nonce
   length but does not differentiate context. Decision: ship phase 2
   without context-aware reflection, accept that some XSS will be
   missed for now, and revisit context-aware reflection as a
   `xss_reflect` probe v1.1.

4. **Rate-limit interaction with WAF/CDN.** ffuf at 40 req/s through
   a typical CDN-fronted target will trip rate-limiting. Phase 2a
   currently inherits the phase-1 rate. Decision needed before going
   live: lower phase 2a to 10 req/s, or add a 429-detection backoff
   to the ffuf invocation (which ffuf supports via `-sa`).

---

## Test plan

Before merging:

- Unit tests for the orchestrator's "interesting URL" filter (the
  static-extension and same-host rules).
- Unit tests for the per-pair verdict-filename generator (must be
  stable across re-runs so two scans of the same target produce
  comparable diffs).
- Integration test against a known-vulnerable target (Juice Shop has
  several hidden parameters) — verify at least one
  `(url, param_name)` is discovered and at least one downstream probe
  fires a verdict against it.
- Time-budget regression test: phase 2 against Juice Shop must
  complete in under 45 minutes on the reference container host.

---

## Rollout

1. Implement phase 2a (parameter discovery) behind a feature flag in
   `plan_for_profile`. Off by default. Verify on Juice Shop.
2. Implement phase 2b (probe iteration). Off by default.
3. Enable both for `premium` only after the time-budget regression
   test passes three times in a row.
4. Document in README and the toolkit page.

Estimated work: 1–2 days for someone familiar with the orchestrator.

---

## Non-goals

- This plan does not propose adding feroxbuster or any second
  content-discovery tool. ffuf in `-w params -u 'url?FUZZ=x'` mode
  covers parameter discovery; feroxbuster does not, so adding it
  would be unrelated scope.
- This plan does not propose moving parameter discovery into a
  separate container or microservice. It runs in-process with the
  existing orchestrator, in the same Python module.
