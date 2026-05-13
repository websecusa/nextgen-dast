# nextgen-dast — UI Screenshots

These screenshots are sample renderings of every operator-facing page in
the nextgen-dast 2.1.1 web UI. They are captured against the public test
deployment at <https://fairtprm.com/test/> and refreshed by running
`capture.py` from this directory.

The images are intended for documentation, onboarding, and release notes.
They are not part of the runtime image.

## How they were captured

`capture.py` drives a headless Chromium via Playwright. It:

1. Opens the `/login` page and screenshots the unauthenticated form.
2. Signs in with the credentials supplied via `DAST_USER` / `DAST_PASS`
   (defaults are the standard demo values).
3. Walks every top-level GET route that does not require a row id, and
   writes a full-page PNG named `NN_<page>.png`.

Routes that need a parameter (`/scan/{id}`, `/flow/{id}`,
`/assessment/{id}`, `/schedule/{id}`, `/finding/{id}`, etc.) are
intentionally skipped because there is no deterministic id on a fresh
deployment.

## Refreshing the screenshots

```bash
python3 -m venv /tmp/pw_venv
/tmp/pw_venv/bin/pip install playwright
/tmp/pw_venv/bin/python -m playwright install chromium

DAST_BASE_URL=https://fairtprm.com/test \
DAST_USER=admin \
DAST_PASS='REDACTED' \
DAST_OUT=/data/pentest/src/screenshots \
/tmp/pw_venv/bin/python capture.py
```

## Inventory

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
| `14_admin_users.png` | `/admin/users` | User CRUD — roles, spend caps, password reset, audit-log pointer |
| `15_admin_sso.png` | `/admin/sso` | SAML SSO configuration |
| `16_admin_api_tokens.png` | `/admin/api-tokens` | Personal-access tokens for the REST API |
| `17_admin_branding_web.png` | `/admin/branding/web` | Web header / login logos |
| `18_admin_branding_pdf.png` | `/admin/branding/pdf` | PDF report header / footer branding |
| `19_admin_toolkit.png` | `/admin/toolkit` | Scanner toolkit registry (per-scanner enable / version pin) |
| `20_admin_database.png` | `/admin/database` | Database backups |
| `21_admin_sca.png` | `/admin/sca` | SCA / dependency-vulnerability feed status |
| `22_admin_ai_prompts.png` | `/admin/ai-prompts` | AI prompt library (versioned, restorable) |
| `23_admin_ai_prompts_new.png` | `/admin/ai-prompts/new` | New AI prompt editor |
