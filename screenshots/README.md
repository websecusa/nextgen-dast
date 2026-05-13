# nextgen-dast — UI Screenshots

These screenshots are sample renderings of every operator-facing page in
the nextgen-dast 2.1.1 web UI. They are captured against the public test
deployment at <https://fairtprm.com/test/> and refreshed by running
`capture.py` from this directory.

The images are intended for documentation, onboarding, and release notes.
They are not part of the runtime image.

## Sections

The capture is grouped into five sections so the gallery can be skimmed
top-to-bottom as a tour of the product.

| Range | What it covers |
| --- | --- |
| **01–24** | Top-level pages reachable without route parameters (login, dashboard, proxy, flows, scan, auth, assess, assessments, schedules, llm, user-agents, security/MFA, admin/*, theme). |
| **25–33** | Detail pages that need a row id — assessment, finding, scan, flow, AI prompt — plus SCA log/config and the `/admin/branding` index. The script discovers ids at run time by scraping the listing pages. |
| **40–41** | TOTP (two-factor) walkthrough: the per-user `/security` page in its "not enrolled" and "mid-enrolment, scan this QR" states. |
| **50–51** | SAML 2.0 SSO configuration walkthrough: `/admin/sso` in default (Generic) labelling and again with the "Use Okta" radio toggled on, which relabels every IdP field client-side. |
| **60–63** | Theme walkthrough: the `/theme` page in dark, then in light, plus the dashboard and assessments list rendered in light mode for visual contrast. |

## Privacy / safety notes

`capture.py` is hardened against leaking real authentication material or
account names into the checked-in artifacts:

- **TOTP secret on `41_totp_enrollment_qr.png` is redacted.** The QR
  code and manual-entry secret are blacked out before the image is
  written to disk. The enrolment is also abandoned (verify is never
  submitted), so the database is never touched.
- **Username column on `14_admin_users.png` is redacted.** Each row's
  operator name is overlaid with a `USER` label so the table layout
  is still visible but the names don't leave the deployment.
- **Theme flip is reversible.** The script flips the operator's account
  from dark to light to capture the light-mode pages, then restores
  it to dark in a `try/finally` so a mid-run crash still leaves the
  account on its original theme.
- **No SAML/SSO state is changed.** The Okta toggle on
  `51_admin_sso_okta_relabeled.png` is a pure client-side relabel —
  the form is never submitted.

## Highlighted walkthroughs

### Two-factor (TOTP)

| Step | Image | What it shows |
| --- | --- | --- |
| 1 | `40_totp_not_enrolled.png` | Account-security landing page; single CTA "Set up an authenticator app". |
| 2 | `41_totp_enrollment_qr.png` | After clicking the CTA: server-rendered QR + manual-entry secret + 6-digit confirmation field. (QR + secret redacted in this gallery.) |

### SAML 2.0 SSO (Generic + Okta)

| Step | Image | What it shows |
| --- | --- | --- |
| 1 | `15_admin_sso.png` / `50_admin_sso_generic.png` | Full SSO config form with vendor-neutral labels. Master switches (Enable / Force), IdP details (Entity ID, SSO URL, SLO URL, X.509 certificate), and auto-derived SP details to paste into the IdP. |
| 2 | `51_admin_sso_okta_relabeled.png` | Same form with the "Use Okta" radio selected — every IdP field label and placeholder is swapped client-side to match Okta's "View SAML setup instructions" panel, so an Okta operator can copy-paste without translating field names. |

### Theme switching

| Step | Image | What it shows |
| --- | --- | --- |
| 1 | `24_theme.png` / `60_theme_dark.png` | Theme preference page with **Dark** selected (the default). |
| 2 | `61_theme_light.png` | Same page after switching to **Light**. |
| 3 | `62_dashboard_light.png` | Dashboard rendered with the light theme applied. |
| 4 | `63_assessments_light.png` | Assessments list under the light theme. |

## How they were captured

`capture.py` drives a headless Chromium via Playwright. It:

1. Opens `/login` and screenshots the unauthenticated form.
2. Signs in with the credentials supplied via `DAST_USER` / `DAST_PASS`.
3. Walks every top-level GET route that does not require a row id and
   takes a full-page PNG of each.
4. Scrapes the assessment, scan, flow, and AI-prompt listing pages to
   discover one id of each kind, then captures the corresponding
   detail pages.
5. Drives the `/security`, `/admin/sso`, and `/theme` pages to capture
   the focused walkthroughs above. Sensitive regions are redacted via
   PIL after the screenshot is taken — see `_redact_boxes()` and
   `_redact_totp_secret()` in `capture.py`.

## Refreshing the screenshots

```bash
python3 -m venv /tmp/pw_venv
/tmp/pw_venv/bin/pip install playwright Pillow
/tmp/pw_venv/bin/python -m playwright install chromium

DAST_BASE_URL=https://fairtprm.com/test \
DAST_USER=admin \
DAST_PASS='REDACTED' \
DAST_OUT=/data/pentest/src/screenshots \
/tmp/pw_venv/bin/python capture.py
```

## Full inventory

### Top-level pages (01–24)

| File | Page | What it shows |
| --- | --- | --- |
| `01_login.png` | `/login` | Sign-in form (HackRange branding) |
| `02_dashboard.png` | `/` | Welcome dashboard with risk trend, finding-age widgets, recent assessments |
| `03_proxy.png` | `/proxy` | Capture proxy controls — start/stop, certificate, scope filters |
| `04_flows.png` | `/flows` | Captured HTTP flows from the proxy |
| `05_scan_new.png` | `/scan` | Launch a single-target scan — scanner picker and options |
| `06_auth_profiles.png` | `/auth` | Saved authentication profiles (capture-then-replay) |
| `07_assess_new.png` | `/assess` | Launch a full assessment (multi-scan workflow) |
| `08_assessments.png` | `/assessments` | Assessment history with status, profile, and findings counts |
| `09_schedules.png` | `/schedules` | Scheduled scans (cron-style recurring assessments) |
| `10_llm_endpoints.png` | `/llm` | LLM endpoints, default budget, exploit-chain backfill |
| `11_user_agents.png` | `/user-agents` | Custom User-Agent strings used by scans |
| `12_security_mfa.png` | `/security` | TOTP enrolment / disable for the current user |
| `13_admin_overview.png` | `/admin` | Admin landing page |
| `14_admin_users.png` | `/admin/users` | User CRUD — roles, spend caps, password reset, audit-log pointer (usernames redacted) |
| `15_admin_sso.png` | `/admin/sso` | SAML SSO configuration |
| `16_admin_api_tokens.png` | `/admin/api-tokens` | Personal-access tokens for the REST API |
| `17_admin_branding_web.png` | `/admin/branding/web` | Web header / login logos |
| `18_admin_branding_pdf.png` | `/admin/branding/pdf` | PDF report header / footer branding |
| `19_admin_toolkit.png` | `/admin/toolkit` | Scanner toolkit registry (per-scanner enable / version pin) |
| `20_admin_database.png` | `/admin/database` | Database backups |
| `21_admin_sca.png` | `/admin/sca` | SCA / dependency-vulnerability feed status |
| `22_admin_ai_prompts.png` | `/admin/ai-prompts` | AI prompt library (versioned, restorable) |
| `23_admin_ai_prompts_new.png` | `/admin/ai-prompts/new` | New AI prompt editor |
| `24_theme.png` | `/theme` | Per-user theme preference (dark / light) |

### Detail pages (25–33)

| File | Page | What it shows |
| --- | --- | --- |
| `25_assessment_detail.png` | `/assessment/{id}` | Assessment detail — findings table, scan list, AI deep-dive panel |
| `26_finding_detail.png` | `/finding/{id}` | Finding detail — evidence, AI analysis, remediation, challenge / FP buttons |
| `27_scan_detail.png` | `/scan/{id}` | Scan detail — output stream, files, kill button |
| `28_flow_detail.png` | `/flow/{id}` | Captured flow detail — request, response, "scan this flow" CTA |
| `29_admin_ai_prompt_detail.png` | `/admin/ai-prompts/{id}` | AI prompt editor with version history |
| `30_assessment_llm_debug.png` | `/assessment/{id}/llm-debug` | LLM debug log for an assessment |
| `31_admin_sca_log.png` | `/admin/sca/log` | SCA feed update log |
| `32_admin_sca_config.png` | `/admin/sca/config` | SCA feed configuration |
| `33_admin_branding_index.png` | `/admin/branding` | Branding section index (web / PDF entry points) |

### TOTP walkthrough (40–41)

| File | Page | What it shows |
| --- | --- | --- |
| `40_totp_not_enrolled.png` | `/security` | Landing page when no TOTP is enrolled |
| `41_totp_enrollment_qr.png` | `/security` (post-enroll) | QR + manual-entry secret + 6-digit confirmation field (QR + secret redacted) |

### SAML walkthrough (50–51)

| File | Page | What it shows |
| --- | --- | --- |
| `50_admin_sso_generic.png` | `/admin/sso` | SSO config form with Generic SAML 2.0 labels |
| `51_admin_sso_okta_relabeled.png` | `/admin/sso` | Same form with "Use Okta" toggled — IdP field labels swap to Okta nomenclature |

### Theme walkthrough (60–63)

| File | Page | What it shows |
| --- | --- | --- |
| `60_theme_dark.png` | `/theme` | Theme preference with Dark selected |
| `61_theme_light.png` | `/theme` | Theme preference with Light selected |
| `62_dashboard_light.png` | `/` | Dashboard rendered in light mode |
| `63_assessments_light.png` | `/assessments` | Assessments list in light mode |
