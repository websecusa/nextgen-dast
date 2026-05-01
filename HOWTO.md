# nextgen-dast 2.1.1 — How To

_Author: Tim Rice <tim.j.rice@hackrange.com>_

This is the operator's playbook. Every section maps a real-world task
("scan a SAML-protected app", "run a recurring weekly scan",
"investigate a false positive") to the exact steps to do it. The
companion `FEATURES.md` is the inventory; `README.md` covers
fresh-machine install.

If a workflow is not covered here, check `FEATURES.md` for what exists
or `README.md → Troubleshooting`.

---

## Contents

1. [First-time install + login](#1-first-time-install--login)
2. [Run an unauthenticated scan](#2-run-an-unauthenticated-scan)
3. [Run an authenticated scan (form login)](#3-run-an-authenticated-scan-form-login)
4. [Capture an SSO session with the proxy](#4-capture-an-sso-session-with-the-proxy)
5. [Reading and triaging findings](#5-reading-and-triaging-findings)
6. [Validating a finding (Test, Validate, Challenge)](#6-validating-a-finding-test-validate-challenge)
7. [Bulk Challenge — clearing false positives](#7-bulk-challenge--clearing-false-positives)
8. [SCA workflow — JS libraries / CVEs](#8-sca-workflow--js-libraries--cves)
9. [Generate and customise the PDF report](#9-generate-and-customise-the-pdf-report)
10. [REST API + Postman](#10-rest-api--postman)
11. [Cron-driven schedules](#11-cron-driven-schedules)
12. [Branding the deployment](#12-branding-the-deployment)
13. [Multi-user + permission model](#13-multi-user--permission-model)
14. [Database backup + restore](#14-database-backup--restore)
15. [Upgrading the image (Day-2)](#15-upgrading-the-image-day-2)
16. [Resetting an environment](#16-resetting-an-environment)


---

## 1. First-time install + login

> Detailed walk-through is in `README.md` (TL;DR + fast path). Quick
> recap so this guide is self-contained.

```bash
sudo mkdir -p /data/pentest
sudo chown "$USER":"$USER" /data/pentest
git clone https://git.hackrange.com/trice/nextgen-dast.git /data/pentest
cd /data/pentest
sudo ./setup.sh
```

`setup.sh` will:

1. Install Docker Engine + Compose plugin if missing.
2. Pull `dockerregistry.fairtprm.com/nextgen-dast:2.1.1` (public).
3. Generate a random `.env_<hex>` env file with strong secrets.
4. Bring up MariaDB and wait for healthy.
5. Apply schema, seed an `admin` user with a randomly generated
   password.
6. Print the path of the secrets file containing that admin password.

**Find the admin password**:

```bash
ls /data/pentest/data/.sensitive_secrets_info_*
cat /data/pentest/data/.sensitive_secrets_info_<hex>
```

**First login**: hit your reverse-proxy URL (or
`http://127.0.0.1:8888/login` if running on the host directly), log in
as `admin` with that password, then immediately open `/me/password`
and rotate it.


---

## 2. Run an unauthenticated scan

For public targets that don't require login.

1. Click **New scan** in the header (or browse to `/assess`).
2. Fill the form:
   * **FQDN** — the target hostname (`example.com`) or `host:port`
     (`example.com:8443`). HTTPS is assumed.
   * **Application ID** — optional. Free text used to correlate the
     scan with an external ticket.
   * **Profile** — `standard` for ~10 min coverage, `thorough` for
     deeper wapiti / ffuf, `premium` for sqlmap + dalfox +
     enhanced_testing.
   * Leave the credentials fields blank for unauthenticated runs.
3. **Start scan**.
4. The page redirects to `/assessment/<id>` with a status badge that
   updates live (`current_step` polling).
5. When the scan finishes, the auto-validate pass runs read-only
   probes against every finding; obvious false positives flip
   automatically to `false_positive`.

**To kill a scan**: `/scan/<scan_id>` → **Kill scan**. The orchestrator
will terminate the running scanner subprocess. The assessment row will
flip to `error` with `error_text` describing the abort.


---

## 3. Run an authenticated scan (form login)

For targets behind a standard HTML login form (no SSO).

1. New scan as above.
2. In the **Authentication** section:
   * **Login URL** — full URL of the login form, e.g.
     `https://example.com/login`.
   * **Username** + **Password** — the test account's credentials.
     Values are stored encrypted at rest in the assessments row.
3. **Start scan**.
4. `auth.form_login_cookie()` fingerprint-detects the login form,
   submits the credentials, and grabs the resulting session cookie.
5. The session cookie is shared across every scanner for the
   duration of the scan, so wapiti, nuclei, dalfox, etc. all run
   *as the logged-in user*.
6. If the login fails, the assessment row gets an `auth.login_error`
   field describing why (HTTP status, missing form field, redirect
   loop, etc.). Fix and re-launch.

**Tips**:

* If the target uses HTTP Basic auth instead of a form, leave
  **Login URL** blank and put `user:pass` in the password field; the
  scanners will inherit it as a Basic auth header.
* Mixed-mode targets (form login + per-API Bearer token) need the
  capture-then-replay path — see §4.


---

## 4. Capture an SSO session with the proxy

For SAML / Okta / Azure AD / WS-Fed targets that cannot be driven
headlessly. The pattern is **capture-then-replay**: a real human
completes the IdP challenge in a real browser through the bundled
proxy; the proxy snapshots the post-auth flow; downstream scans
inherit the captured cookies.

There are two modes — reverse and forward. Reverse-proxy mode is the
default for SAML and is the shape covered in detail in `README.md`.
This section documents the steps from the analyst's seat once the
deployment is configured.

### 4.1 Reverse-proxy mode (recommended for SAML)

1. Open `/proxy`. Confirm the proxy is **Stopped**. Configure:
   * **Listen port** (default 9999).
   * **Upstream URL** (the real target the proxy will forward to).
   * **Captured-cookie host** (usually the same as upstream's host).
2. Click **Start**.
3. In a real browser (Firefox, Chrome) navigate to the proxy URL
   (e.g. `https://test.fairtprm.com:9999/`). Complete the IdP login.
4. The flows table at `/flows` will fill up. Wait until you see the
   post-redirect application page.
5. Click **Save profile** to convert the captured cookies into a
   reusable `auth_profile`.
6. New scan → set the **Auth profile** dropdown to the new profile,
   leave Login URL / Username blank.
7. Run the scan. Scanners replay the captured cookies on every
   request.

### 4.2 Forward-proxy mode

For ad-hoc capture during a manual walkthrough (e.g. capturing a
single API call to feed into a probe).

1. Configure the proxy port at `/proxy`.
2. Set your browser's HTTP / HTTPS proxy to the host:port shown.
3. Trust the mitmproxy CA cert in the browser (one-time).
4. Browse the target. Each request appears in `/flows`.
5. Open the flow, copy the curl, send to scan, send to challenge,
   or save as a new auth_profile.

### 4.3 Common pitfalls

* The proxy's CA must be trusted by the browser, otherwise TLS
  intercept fails on any HTTPS upstream.
* SAML responses can be > 32 KB — the upstream listener is sized for
  this but a too-tight nginx in front would clip it.
* Some IdPs bind cookies to the original hostname. Reverse-proxy mode
  rewrites `Set-Cookie` Domain attributes; if it doesn't, captured
  cookies won't replay. Inspect `Set-Cookie` in the captured flow.

`README.md` has the full reverse-proxy nginx config and the SAML
pitfall list — refer to it when configuring a new SSO target.


---

## 5. Reading and triaging findings

Once a scan finishes, browse to `/assessment/<id>`.

### 5.1 Layout

* **KPI strip** — live risk score, total findings, per-severity dots,
  triage tiles (false-positive / resolved / archived).
* **Three-column workspace** — list, detail, aside.

### 5.2 Filtering

* **Status tabs** — Open / Closed / All.
* **Severity dropdown** — Critical / High / Medium / Low / Info, plus
  pseudo-severities below the divider:
  * **False positives** — overrides the status tab; lists every
    `status='false_positive'` row.
  * **Resolved** — `status='fixed'`.
  * **Archive** — `status='accepted_risk'`.
* **Sort** — by severity / newest / source tool.
* **Search** — free-text title substring.
* **Hide info-severity** toggle — persists per-assessment, affects
  the page AND the next PDF.

### 5.3 Triaging a row

Click a row to load its detail in the centre column. From the aside
panel:

* **Mark as false positive** — rare; usually do this only after running
  the Validate / Challenge button below.
* **Resolve** — finding has been fixed in the target.
* **Archive (accept risk)** — analyst has explicitly accepted the
  risk.
* **Reopen** — undoes any of the above.

### 5.4 Bulk triage

1. Tick the checkboxes in the list. The header checkbox toggles every
   visible row (respects current filters).
2. Use the bulk-action bar at the bottom:
   * **Resolve** — set every selected row to `status='fixed'`.
   * **Archive** — `status='accepted_risk'`.
   * **Delete** — removes the rows entirely (use sparingly).


---

## 6. Validating a finding (Test, Validate, Challenge)

Three buttons appear on the finding panel and on the standalone
`/finding/<id>` page. Pick by what you want to do:

### 6.1 Test — replay the live request

* Re-issues the captured request against the target and shows the
  *current* response.
* Useful when you want to confirm a finding is still reproducible
  without invoking the toolkit.
* Read-only by definition — only sends what was originally captured.
* TLS-aware variants for `testssl` and cert-shape findings (skips the
  HTTP layer, runs a TLS handshake only).

### 6.2 Validate — read-only probe

* Runs the matched **read-only** toolkit probe (e.g.
  `htaccess_bypass`, `info_disclosure`, `sca_finding_validate`).
* Verdict: `validated` / `not validated` / `inconclusive`.
* Result is written to `validation_evidence` and shown as a chip on
  the finding row.
* Probe is killed if it overruns its `request_budget_max`.

### 6.3 Challenge — full toolkit, including mutating probes

* Same UI as Validate, but also covers mutating probes (`xss_reflect`,
  `sqli_boolean`, `csrf_validation`).
* Shows the real `safety_class` (e.g. "mutating: payloads injected").
* Requires the analyst to confirm before firing because the probe
  will issue payload requests.
* Verdict + evidence are written back to the finding.

### 6.4 What flips a finding to false_positive automatically?

The probe's verdict must satisfy *all*:

* `ok = true` (no probe error)
* `validated = false` (the original finding could not be reproduced)
* `confidence >= 0.8` (probe is confident)

Verdicts below 0.8 confidence are written as `inconclusive` —
visible to the analyst but the row is not auto-suppressed.


---

## 7. Bulk Challenge — clearing false positives

The auto-validate pass at end of scan handles read-only probes
automatically. Two paths are still useful:

### 7.1 Re-run on an older assessment

If the assessment was run before the auto-validate feature shipped, or
new probes have been added since:

1. Open `/assessment/<id>`.
2. Click **Challenge all findings** (admin-only, hidden during
   `running` / `queued` / `deleting`).
3. Confirm the prompt — note that mutating probes WILL fire.
4. Watch the status badge — it shows `challenge_all: running probe N/M`.
5. Tail the log if you want detail:

```bash
docker exec nextgen-dast tail -f /data/logs/challenge_all_<aid>.log
```

### 7.2 Trigger via API / CLI

```bash
curl -X POST -b "session=…" \
     https://your-deployment/assessment/29/challenge_all
```

Or directly inside the container:

```bash
docker exec nextgen-dast python -m scripts.challenge_runner 29
```

For a safe-only sweep (skips mutating probes — same shape as the
post-scan auto-pass):

```bash
docker exec nextgen-dast python -m scripts.challenge_runner --safe-only 29
```


---

## 8. SCA workflow — JS libraries / CVEs

### 8.1 What it scans

* Crawls the target's JavaScript surface (assessment-known paths +
  ffuf discoveries).
* `retire.js` content-fingerprint match against every JS asset.
* `osv-scanner` against any SBOM-like manifest discovered.
* Caches `(content_hash, component, version, CVE)` tuples for reuse.

### 8.2 What you'll see

* `Library detected (content fingerprint): <name> <version>` —
  info-severity, one per match. A bundled file (e.g. `core.min.js`)
  can match more than one library, so expect multiple rows per file.
* Per-CVE rows with the advisory's severity, title format
  `<component> <version>: <CVE description>`.

### 8.3 Validating SCA findings

`sca_finding_validate` runs automatically as part of auto-validate.
It:

1. Fetches the cited file once.
2. Reads the banner comment (`/*! jQuery v3.7.1 */` style — preserved
   through minification because build tools mark it as a legal
   comment).
3. Compares to `vulnerable_range` / `fixed_version`.
4. Auto-flips to `false_positive` if `confidence >= 0.8`.

Manual run: open the finding, click **Validate**, read the verdict.

### 8.4 SCA admin

* `/admin/sca` — signature DB age / source / asset count.
* `/admin/sca/update` — manual signature DB refresh (button) or via
  the equivalent CLI `docker exec`.
* `/admin/sca/vuln` — manually annotate or override a CVE record (use
  case: vendor patched a CVE in a backport before the fixed-version
  field was updated upstream).
* `/admin/sca/config` — TTL, crawl depth, asset cap, retire.js
  overlay path.

### 8.5 Why am I seeing duplicate jQuery findings?

Bundled / minified files often contain multiple jQuery code shapes
(jQuery + jQuery Migrate + plugins). retire.js fingerprints by
substring match against its signature DB and emits one match per
match — which is *correct* per signature but wrong as a
vulnerability claim. `sca_finding_validate` is the antidote: it
reads the actual banner version of the file and refutes the older
matches.


---

## 9. Generate and customise the PDF report

### 9.1 Generate

* Open `/assessment/<id>` → header → **Generate PDF** (or
  **Regenerate PDF** if one already exists).
* The PDF appears in the KPI strip with a Download link plus byte
  size. Filename is `<fqdn>_<YYYY-MM-DD>.pdf`.

### 9.2 What's included

* Cover page with the deployment branding (logo, color, classification
  footer, link color).
* Executive summary (LLM-written if Tier-1+ consolidation ran).
* Per-finding sections grouped by severity, ordered by risk-rank.
* Reproduce-&-verify steps when the original capture is present.
* Captured passwords masked in the rendered PDF.
* Triaged findings (FP / fixed / accepted_risk) excluded by default.
* Info-severity rows excluded if **Hide info-severity** is on for
  this assessment.

### 9.3 Re-generate after triage

The PDF is a snapshot of the moment it was rendered. After triage
(marking false positives, resolving findings) re-generate the PDF so
the report and the live state agree.

### 9.4 Customising the look

* `/admin/branding/pdf` — logo, primary color, link color,
  classification footer, footer text.
* `pdf_link_color` — explicit override for hyperlink color in the PDF.
  Default is a print-readable navy. Setting this avoids the gotcha
  where the brand primary is unreadable on print.

### 9.5 Delete a stale PDF

* `/assessment/<id>` → KPI strip → click the report → header →
  **Delete report**. Or post to `/assessment/<id>/report/<filename>/delete`.


---

## 10. REST API + Postman

The full reference is at `/docs` (interactive Swagger UI bundled
in-image — no outbound CDN). This section is task-oriented.

### 10.1 Get a token

* Login as an admin user.
* Browse to `/admin/api-tokens` → **Create token** → copy the value
  (it's only displayed once — store it in your secret manager).
* Tokens have a `scope` (`read` or `write`) and can be enabled /
  disabled / deleted.

### 10.2 Kick off a scan

```bash
curl -X POST https://your-deployment/api/v1/scans \
     -H "X-API-Token: <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "fqdn": "example.com",
       "profile": "thorough",
       "application_id": "TICKET-123"
     }'
```

Response includes `id` (assessment id) and a `status_url` to poll.

### 10.3 List findings

```bash
curl -H "X-API-Token: <token>" \
     "https://your-deployment/api/v1/scans/29/results?include_info=false&include_accepted_risk=false"
```

### 10.4 Stream a PDF

```bash
curl -H "X-API-Token: <token>" \
     "https://your-deployment/api/v1/scans/29/report" \
     -o report.pdf
```

### 10.5 Postman collection

```bash
curl -H "X-API-Token: <token>" \
     https://your-deployment/api/v1/postman.json -o ngd.postman.json
```

Import that file into Postman; the collection auto-injects an
`apiToken` variable so you can swap tokens once and have every
request inherit it.

### 10.6 Sample `curl`

A worked example with real values lives at
`/data/pentest/sample_scan_api.txt` for reference (don't run it
against a target you're not authorized to scan).


---

## 11. Cron-driven schedules

For weekly / daily / hourly scans on the same target.

### 11.1 Create

* Open `/schedules` → **New schedule**, or `POST /api/v1/schedules`.
* Fields:
  * **FQDN** + **Profile** + **Application ID** — same as a one-shot
    scan.
  * **Authentication** — login URL + creds OR an `auth_profile_id`
    captured via the proxy (§4).
  * **Cron expression** — standard 5-field cron, evaluated in UTC.
  * **Start after** — defer the first run until a wall-clock time.
  * **Keep only latest** — when on, the schedule deletes prior
    assessments for the same target+profile after a successful run
    so the queue doesn't pile up duplicates.

### 11.2 Manage

* `/schedules` — list with last run / next run / status / toggle.
* `/schedule/<id>` — edit form.
* **Pause** / **Run now** / **Delete** buttons on each row.

### 11.3 Cron tips

* Schedules use `croniter` server-side; the next run is computed and
  shown back in the UI so there's no client-side parsing to debug.
* Stagger cron rules across the hour to avoid scanner thrash on a
  large fleet (e.g. weekly @ Mon 02:00 vs weekly @ Mon 02:15).
* Long-running scans (premium profile) can overlap their next firing.
  The scheduler enforces a "one in flight per schedule" rule — a
  fired schedule that finds the previous run still in progress logs a
  skip.


---

## 12. Branding the deployment

`/admin/branding` is the entry; sub-pages cover web and PDF
separately.

### 12.1 Web branding (`/admin/branding/web`)

* **Logo** — PNG / SVG, ≤1 MB. Surfaced in the sidebar (clamped to a
  reasonable max width) and on the login page.
* **Primary color** — accent / button color.
* **Company name** — sidebar header text under the logo.

### 12.2 PDF branding (`/admin/branding/pdf`)

* **PDF logo** — separate from the web logo so you can ship a
  print-optimised version (high resolution, transparent BG).
* **Primary color** — accent for headings.
* **Link color** — explicit `pdf_link_color` so links are
  print-readable even when the brand primary isn't.
* **Classification footer** — free text that prints on every page
  (e.g. "CONFIDENTIAL — for internal use").

### 12.3 Logo upload

Form-upload via the page. Server-side: image is validated, dimensions
recorded, file stored under `/data/branding/`. Cache-busting CSS
header is bumped automatically so an updated logo appears without a
shift-reload.

### 12.4 Removing the logo

Click **Delete logo** on the relevant page. The default text-only
sidebar is reinstated.


---

## 13. Multi-user + permission model

### 13.1 Roles

* **admin** — full read/write, schema admin, branding, API tokens, DB
  ops, user management.
* **viewer** — read-only access to assessments, findings, reports,
  trend charts. Cannot kick off scans, change settings, or triage.

### 13.2 Add a user

1. `/admin/users` → **Add user**.
2. Username + initial password + role.
3. The new user logs in, opens `/me/password`, rotates the password.

### 13.3 Disable / re-enable / delete

Each user row has buttons:

* **Disable** — preserves history but blocks login.
* **Enable** — un-disable.
* **Reset password** — admin issues a new password (shown once).
* **Delete** — removes the user row entirely.

### 13.4 Audit log

State-changing actions are recorded in the `audit` table (actor,
target, action, timestamp, source IP). The web UI doesn't yet
surface this; query directly:

```bash
docker exec pentest-mariadb mariadb -upentest -p"$DB_PASS" pentest \
  -e "SELECT actor, action, target, created_at FROM audit ORDER BY id DESC LIMIT 50"
```


---

## 14. Database backup + restore

### 14.1 Take a backup

* `/admin/database` → **Create backup**.
* Server runs `mariadb-dump` with `--max-allowed-packet=1G` matched to
  the running server's setting, gzips the result, stores it under
  `/data/backups/`.
* Returns a row in the backups list (filename, size, timestamp).

### 14.2 Download

* Click the filename in the list — authenticated download.
* Or out-of-band:

```bash
ls /data/pentest/data/backups/
# scp to your secret store
```

### 14.3 Restore

* `/admin/database` → **Restore from file**.
* Upload a `.sql` or `.sql.gz`.
* The server validates the file header, then runs the restore inside
  a transaction. Cross-major-version files are rejected.
* Existing data is overwritten — take a backup before restoring.

### 14.4 Delete an old backup

Click **Delete** on the row. The file is unlinked from disk.

### 14.5 Off-host strategy

The web UI handles "I broke something five minutes ago and want to
roll back" cases. For disaster recovery (host loss), schedule an
external job that copies the latest backup off-box (rsync / S3
sync) — `/data/pentest/data/backups/` is your source.


---

## 15. Upgrading the image (Day-2)

Image upgrades are designed to be **pull + restart**, no source-tree
manipulation required.

```bash
cd /data/pentest
./pentest.sh pull          # pulls dockerregistry.fairtprm.com/nextgen-dast:2.1.1
./pentest.sh up -d         # recreates the container with the new image
```

What this does NOT do:

* It will not bump the version. The 2.1.1 tag is the rolling release;
  every image-content change is published under the same tag.
* It will not migrate `./data` — bind-mounted, owned by the host, never
  touched by the upgrade.
* It will not modify `.env_<hex>` or the secrets file.

What you should expect:

* Any in-flight scan in the `nextgen-dast` container is killed (the
  orchestrator runs as a subprocess inside it).
* `assessments.status='running'` rows are reaped on startup by the
  zombie-assessment sweeper and flipped to `error` with a clear
  reason.
* Schema changes self-heal on first start (auto-add missing columns
  for branding / schedules etc.).

If the upgrade fails:

```bash
./pentest.sh logs nextgen-dast | tail -200
```

Common issues and their fixes are in `README.md → Troubleshooting`.


---

## 16. Resetting an environment

Three reset modes, ascending in destructiveness:

### 16.1 `./pentest.sh reset`

Re-seeds the admin password (writes a new one to the secrets file)
and re-runs the row-level seed migrations. Existing assessments and
findings are preserved.

```bash
cd /data/pentest
./pentest.sh reset
cat data/.sensitive_secrets_info_*
```

### 16.2 `./pentest.sh reset-full`

`TRUNCATE`s every table first, then runs `reset`. **Wipes all
assessments, findings, scans, users, branding, schedules, API
tokens.** Keeps the DB itself, the env file, and the on-disk scan
artefacts.

### 16.3 Nuclear — full re-bootstrap

```bash
./pentest.sh down
sudo rm -rf data/mariadb data/scans data/logs data/reports
rm -f .env_*
./setup.sh        # generates a brand new env file + secrets
```

After 16.3 the deployment is indistinguishable from a fresh install.
Use only when you're starting over.


---

_Last updated: 2025-10-30. Companion files: `FEATURES.md` (inventory),
`CHANGELOG.md` (release history), `README.md` (install)._
