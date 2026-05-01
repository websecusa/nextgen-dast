# enhanced_testing

_Author: Tim Rice <tim.j.rice@hackrange.com>_

Proactive, high-fidelity DAST probes that run as part of the **`premium`**
assessment profile, after the traditional scanner pass (wapiti, nuclei,
nikto, testssl, sqlmap, dalfox) finishes. Each probe targets a specific
class of weakness those tools systematically miss because they require
**semantic** understanding of the response, not just pattern matching.

This is distinct from `toolkit/` — that directory holds *validation*
probes which run on demand to challenge an existing finding. The probes
here run *unprompted* and produce findings of their own.

## Layout

```
enhanced_testing/
├── lib/__init__.py            # re-export Probe / Verdict / SafeClient from toolkit/lib
├── probes/                    # one Python file per probe; each ships with a manifest
│   └── info_directory_listing.py
├── tests/
│   ├── probe_stack.yml        # Juice Shop (positive control) + clean nginx (negative)
│   ├── conftest.py            # pytest helpers: stack fixtures + run_probe()
│   ├── fixtures/clean-site/   # the negative-control site nginx serves
│   └── test_<probe>.py        # one test file per probe (positive + negative + smoke)
├── README.md                  # this file
└── TODO.md                    # ordered list of probes to write next
```

## Adding a probe

1. Pick a probe candidate from `TODO.md` (top-of-list = most-serious).
2. Copy `probes/info_directory_listing.py` as a skeleton — it shows the
   import-path setup, the `Probe`/`Verdict` shape, and the read-only
   safety contract every probe must respect.
3. Write the probe's logic in the `run()` method. Constraints:
   - **`safety_class = "read-only"`** — no payloads that change state.
     Premium scans only run probes with this class.
   - **Bounded** — declare a `request_budget_max`; the framework caps
     you at that count.
   - **Deterministic** — return `validated=True` only when the
     evidence is unambiguous. Confidence < 0.85 → `inconclusive`.
   - **Scope-locked** — `SafeClient` already refuses requests outside
     the orchestrator's `--scope`; never bypass.
4. Add a test in `tests/` mirroring `test_info_directory_listing.py`:
   - one `test_<name>_validates_juice_shop` — must return `validated=True`
   - one `test_<name>_quiet_on_clean_ref` — must return `validated=False`
   - one `test_<name>_smoke_no_stack` — runs without docker, asserts
     the probe handles unreachable targets gracefully
5. Run the test stack and the test suite (see below). Both real tests
   must pass before merging the probe.

## Running the test stack

```bash
cd enhanced_testing/tests
docker compose -f probe_stack.yml up -d

# wait ~20–30 s for Juice Shop to start
docker compose -f probe_stack.yml ps         # both containers running
curl -sI http://127.0.0.1:3010/ftp/          # smoke check Juice Shop
curl -sI http://127.0.0.1:3011/              # smoke check clean nginx

# run all probe tests
python3 -m pytest enhanced_testing/tests/ -v

# tear down when done
docker compose -f probe_stack.yml down
```

Tests skip with a helpful message if the stack isn't up, so a developer
can `pytest enhanced_testing/` without docker and still get the
structural smoke tests.

## How the premium profile invokes probes

The orchestrator (`scripts/orchestrator.py`) runs the existing six tools
through `plan_for_profile("thorough")`, then in the new `premium`
profile it invokes each probe under `enhanced_testing/probes/` against
the assessment target, scoped to the assessment's FQDN. Each probe's
verdict becomes a finding row tagged `source_tool='enhanced_testing'`
with `source_scan_id` set to the probe name. Findings flow through the
existing enrichment + report pipeline unchanged.

## Why this exists

Pattern scanners (nuclei, nikto) and fuzzers (wapiti, sqlmap, dalfox)
cover three classes of bug well: pattern signatures, single-shot
fuzzing, and protocol facts. They miss everything that needs semantic
understanding — IDOR/BOLA, mass assignment, JWT internals, GraphQL
field-level authz, business logic, modern-framework specifics, etc.
Each probe here closes one of those gaps with deterministic logic
locked into the image — zero per-scan LLM cost, runs in milliseconds,
ships baked into `dockerregistry.fairtprm.com/nextgen-dast`.
