#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
#
# Drives a headless Chromium against a deployed nextgen-dast instance and
# captures full-page screenshots of every operator-facing page reachable
# without route parameters. Output is written to OUT_DIR as flat PNGs that
# can be checked into the repository under src/screenshots.

import asyncio
import os
import sys
from pathlib import Path

from playwright.async_api import async_playwright

# Base URL of the test deployment. The application is mounted under /test/
# (the SCRIPT_NAME prefix used in production), so every route below is
# requested at BASE_URL + path.
BASE_URL = os.environ.get("DAST_BASE_URL", "https://fairtprm.com/test")
USERNAME = os.environ.get("DAST_USER", "admin")
PASSWORD = os.environ.get("DAST_PASS", "TGIuuuu99!!!!")
OUT_DIR = Path(os.environ.get("DAST_OUT", "/tmp/dast_screenshots"))

# Pages to capture. Each entry is (output filename, URL path appended to
# BASE_URL, optional human-friendly description used only in logging).
# Routes that need a row-id are skipped here because there is no
# deterministic ID we can reach on a fresh deployment.
PAGES = [
    ("01_login.png",                "/login",                 "Sign-in page"),
    ("02_dashboard.png",            "/",                      "Dashboard / home"),
    ("03_proxy.png",                "/proxy",                 "Capture proxy controls"),
    ("04_flows.png",                "/flows",                 "Captured HTTP flows"),
    ("05_scan_new.png",             "/scan",                  "Launch a new scan"),
    ("06_auth_profiles.png",        "/auth",                  "Auth capture profiles"),
    ("07_assess_new.png",           "/assess",                "Launch a new assessment"),
    ("08_assessments.png",          "/assessments",           "Assessment history"),
    ("09_schedules.png",            "/schedules",             "Scheduled scans"),
    ("10_llm_endpoints.png",        "/llm",                   "LLM endpoints + budget"),
    ("11_user_agents.png",          "/user-agents",           "Custom User-Agent strings"),
    ("12_security_mfa.png",         "/security",              "TOTP enrolment"),
    ("13_admin_overview.png",       "/admin",                 "Admin landing page"),
    ("14_admin_users.png",          "/admin/users",           "User management"),
    ("15_admin_sso.png",            "/admin/sso",             "SSO / SAML configuration"),
    ("16_admin_api_tokens.png",     "/admin/api-tokens",      "API tokens"),
    ("17_admin_branding_web.png",   "/admin/branding/web",    "Web branding"),
    ("18_admin_branding_pdf.png",   "/admin/branding/pdf",    "PDF branding"),
    ("19_admin_toolkit.png",        "/admin/toolkit",         "Scanner toolkit registry"),
    ("20_admin_database.png",       "/admin/database",        "Database backups"),
    ("21_admin_sca.png",            "/admin/sca",             "SCA / dependency feeds"),
    ("22_admin_ai_prompts.png",     "/admin/ai-prompts",      "AI prompt library"),
    ("23_admin_ai_prompts_new.png", "/admin/ai-prompts/new",  "New AI prompt editor"),
]


async def capture_login(page):
    """Capture the unauthenticated sign-in screen, then sign in."""
    await page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    shot = OUT_DIR / "01_login.png"
    await page.screenshot(path=str(shot), full_page=True)
    print(f"  saved {shot.name}")

    # The login form posts to /test/login with a `next` field. Filling the
    # visible inputs and submitting is more robust than crafting the POST
    # ourselves because it follows whatever redirect the server prescribes.
    await page.fill('input[name="username"]', USERNAME)
    await page.fill('input[name="password"]', PASSWORD)
    await page.click('button[type="submit"]')
    # Successful login redirects to "/" inside the /test prefix.
    await page.wait_for_url(f"{BASE_URL}/", timeout=15000)


async def capture_authenticated(page, filename, path, desc):
    """Navigate to `path` and take a full-page screenshot."""
    url = f"{BASE_URL}{path}"
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
    except Exception as exc:
        # Fall back to load if networkidle never settles (long-poll panels
        # on the dashboard occasionally keep the network busy).
        print(f"  warn networkidle failed for {path}: {exc}; retrying")
        await page.goto(url, wait_until="load", timeout=20000)
    # Brief settle so any client-side rendering finishes painting.
    await page.wait_for_timeout(750)
    shot = OUT_DIR / filename
    await page.screenshot(path=str(shot), full_page=True)
    print(f"  saved {shot.name}  <- {desc}")


async def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Use a desktop viewport that matches what an operator would see.
        ctx = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        print(f"capturing {BASE_URL} -> {OUT_DIR}")
        await capture_login(page)

        for filename, path, desc in PAGES[1:]:
            try:
                await capture_authenticated(page, filename, path, desc)
            except Exception as exc:
                print(f"  ERROR capturing {path}: {exc}", file=sys.stderr)

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
