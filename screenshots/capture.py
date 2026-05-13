#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
#
# Drives a headless Chromium against a deployed nextgen-dast instance and
# captures full-page screenshots covering every operator-facing page in
# the 2.1.1 web UI. Output is written to OUT_DIR as flat PNGs that can be
# checked into the repository under src/screenshots.
#
# The captured set is grouped into five sections:
#
#   01-24  Top-level pages reachable without route parameters, including
#          the per-user theme preference page.
#   25-33  Detail pages that need a row id (assessment, finding, scan,
#          flow, AI prompt) plus the SCA log/config pages and the
#          /admin/branding index. IDs are discovered at run time by
#          scraping the corresponding listing page so the script keeps
#          working as the data set rotates.
#   40-41  TOTP (two-factor) walkthrough -- the per-user /security page
#          in its "not enrolled" and "mid-enrolment, scan this QR"
#          states. The verify step is intentionally NOT submitted, so
#          the database is never touched and the operator account stays
#          on whatever MFA setting it had before.
#   50-51  SAML 2.0 SSO configuration walkthrough -- /admin/sso in its
#          default "Generic SAML 2.0" mode and again with the "Use Okta"
#          radio toggled, which relabels the IdP fields client-side to
#          match Okta's own nomenclature. The form is never submitted.
#   60-63  Theme walkthrough -- the /theme page in dark, then in light,
#          and the dashboard + assessments pages rendered in light mode
#          so the contrast against the default dark gallery is obvious.
#          The script flips the operator's theme inside a try/finally so
#          a crash mid-run still restores the original choice.

import asyncio
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image, ImageDraw, ImageFont
from playwright.async_api import Page, async_playwright

# Base URL of the test deployment. The application is mounted under /test/
# (the SCRIPT_NAME prefix used in production), so every route below is
# requested at BASE_URL + path.
BASE_URL = os.environ.get("DAST_BASE_URL", "https://fairtprm.com/test")
USERNAME = os.environ.get("DAST_USER", "admin")
PASSWORD = os.environ.get("DAST_PASS", "TGIuuuu99!!!!")
OUT_DIR  = Path(os.environ.get("DAST_OUT", "/tmp/dast_screenshots"))

VIEWPORT = {"width": 1440, "height": 900}

# --- Section 01-24: parameter-free pages ---------------------------------
# Each entry: (output filename, URL path, short description for log/README).
TOP_LEVEL_PAGES = [
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
    ("12_security_mfa.png",         "/security",              "Account security / TOTP landing"),
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
    ("24_theme.png",                "/theme",                 "Theme preference (per user)"),
]

# Static parameter-free admin pages added in the section-25-33 block.
EXTRA_STATIC_PAGES = [
    ("31_admin_sca_log.png",        "/admin/sca/log",         "SCA feed update log"),
    ("32_admin_sca_config.png",     "/admin/sca/config",      "SCA feed configuration"),
    ("33_admin_branding_index.png", "/admin/branding",        "Branding section index"),
]


async def login(page: Page) -> None:
    """Capture the unauthenticated sign-in screen, then sign in."""
    await page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    await page.screenshot(path=str(OUT_DIR / "01_login.png"), full_page=True)
    print("  saved 01_login.png  <- Sign-in page")

    # Filling the visible inputs and submitting is more robust than
    # crafting the POST ourselves because it follows whatever redirect
    # the server prescribes (including the '/' inside the /test prefix).
    await page.fill('input[name="username"]', USERNAME)
    await page.fill('input[name="password"]', PASSWORD)
    await page.click('button[type="submit"]')
    await page.wait_for_url(f"{BASE_URL}/", timeout=15000)


async def shoot(page: Page, filename: str, path: str, desc: str) -> None:
    """Navigate to `path` and take a full-page screenshot. Pages that
    surface real account names trigger an automatic redaction pass --
    see the path-specific branches at the end of this function."""
    url = f"{BASE_URL}{path}"
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
    except Exception as exc:
        # Long-poll panels on the dashboard occasionally keep the network
        # busy past the timeout; fall back to plain "load".
        print(f"  warn networkidle failed for {path}: {exc}; retrying with load")
        await page.goto(url, wait_until="load", timeout=20000)
    # Brief settle so any client-side rendering finishes painting.
    await page.wait_for_timeout(750)

    # Pages that surface real account names get an automatic
    # redaction pass keyed off the URL path. The bounding boxes are
    # measured against the live DOM (via Playwright locators) BEFORE
    # the screenshot is taken, so layout changes survive without any
    # pixel-level retuning.
    redact_boxes: list[tuple[int, int, int, int]] = []
    if path == "/admin/users":
        # Each row's first <td> wraps the operator name in a <code>
        # tag; blacking out those cells (and not the header) preserves
        # the table layout while removing the actual usernames.
        cells = page.locator("table tbody tr td:first-child code")
        for i in range(await cells.count()):
            box = await cells.nth(i).bounding_box()
            if box:
                redact_boxes.append((
                    int(box["x"]) - 4, int(box["y"]) - 2,
                    int(box["x"] + box["width"])  + 4,
                    int(box["y"] + box["height"]) + 2,
                ))

    out = OUT_DIR / filename
    await page.screenshot(path=str(out), full_page=True)
    if redact_boxes:
        _redact_boxes(out, redact_boxes, label="USER")
    print(f"  saved {filename}  <- {desc}")


# --- Section 25-30: parameterized detail pages ---------------------------

async def first_match(page: Page, list_path: str, link_re: str):
    """Visit `list_path`, return the first href matching `link_re`, or
    None if no row was found. The regex must include exactly one
    capturing group whose content is returned."""
    await page.goto(f"{BASE_URL}{list_path}", wait_until="networkidle", timeout=20000)
    html = await page.content()
    m = re.search(link_re, html)
    return m.group(1) if m else None


async def shoot_detail_pages(page: Page) -> None:
    """Discover one id of each kind by scraping the listing pages, then
    capture a full-page screenshot of the corresponding detail page.
    Skips silently if no row exists for that kind (e.g. no schedules
    configured)."""

    # Assessment + LLM-debug + finding all hang off the same id.
    aid = await first_match(page, "/assessments",
                            r'href="[^"]*/assessment/(\d+)(?:\?|"|/)')
    if aid:
        await shoot(page, "25_assessment_detail.png",
                    f"/assessment/{aid}",
                    f"Assessment detail (id {aid}) -- findings, scans, AI deep-dives")
        await shoot(page, "30_assessment_llm_debug.png",
                    f"/assessment/{aid}/llm-debug",
                    f"LLM debug log for assessment {aid}")

        # Finding ids only show up on an assessment-detail page.
        fid = await first_match(page, f"/assessment/{aid}",
                                r'href="[^"]*/finding/(\d+)"')
        if fid:
            await shoot(page, "26_finding_detail.png",
                        f"/finding/{fid}",
                        f"Finding detail (id {fid}) -- evidence, AI analysis, challenge")

    # Scan ids are slug-shaped (timestamp-hex), not numeric.
    sid = await first_match(page, "/scan",
                            r'href="[^"]*/scan/([0-9a-f-]{20,})(?:"|\?)')
    if sid:
        await shoot(page, "27_scan_detail.png",
                    f"/scan/{sid}",
                    f"Scan detail (id {sid}) -- output, files, kill button")

    # Flow ids are also slug-shaped and only present once the proxy has
    # captured at least one request.
    fl = await first_match(page, "/flows",
                           r'href="[^"]*/flow/([0-9a-zA-Z_-]{10,})(?:"|#)')
    if fl:
        await shoot(page, "28_flow_detail.png",
                    f"/flow/{fl}",
                    f"Flow detail (id {fl}) -- request, response, scan-this-flow CTA")

    # AI-prompt detail page; ids are sequential integers seeded with the
    # default prompt library at install time.
    pid = await first_match(page, "/admin/ai-prompts",
                            r'href="[^"]*/admin/ai-prompts/(\d+)"')
    if pid:
        await shoot(page, "29_admin_ai_prompt_detail.png",
                    f"/admin/ai-prompts/{pid}",
                    f"AI prompt detail (id {pid}) -- editor, version history")

    for fn, path, desc in EXTRA_STATIC_PAGES:
        await shoot(page, fn, path, desc)


# --- Section 40-41: TOTP walkthrough -------------------------------------

# Pixel coordinates of the QR code and the manual-entry secret on the
# captured /security mid-enrolment screenshot, measured against the
# 1440x900 capture viewport. Both regions are blacked out before the
# image is written to disk -- see _redact_totp_secret().
_TOTP_QR_BOX     = (288,  170, 520, 432)
_TOTP_SECRET_BOX = (538,  208, 870, 240)


def _load_label_font(size: int):
    """Load a bold sans font for redaction labels. Falls back to PIL's
    bitmap default if DejaVu isn't installed (rare on the deploy hosts
    we ship to, but worth handling for portability)."""
    try:
        return ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
    except OSError:
        return ImageFont.load_default()


def _redact_boxes(path: Path,
                  boxes: list[tuple[int, int, int, int]],
                  label: str) -> None:
    """Paint solid rectangles over each (x0, y0, x1, y1) box on the
    image at `path`, then write a centred label inside each one. Solid
    black survives re-encoding cleanly and reads as deliberate
    redaction (rather than the visual ambiguity of a blur)."""
    with Image.open(path) as im:
        rgb = im.convert("RGB")
        draw = ImageDraw.Draw(rgb)
        font = _load_label_font(14)
        for x0, y0, x1, y1 in boxes:
            draw.rectangle((x0, y0, x1, y1), fill=(20, 20, 20))
            # Centre the label inside the box. textbbox returns the
            # actual rendered extent so single- and double-digit ids
            # both look balanced.
            bb = draw.textbbox((0, 0), label, font=font)
            tw, th = bb[2] - bb[0], bb[3] - bb[1]
            cx = x0 + ((x1 - x0) - tw) // 2
            cy = y0 + ((y1 - y0) - th) // 2
            draw.text((cx, cy), label, fill=(230, 80, 80), font=font)
        rgb.save(path, format="PNG")


def _redact_totp_secret(path: Path) -> None:
    """Paint over the QR + manual-entry secret on a TOTP enrolment
    screenshot. The capture viewport is fixed at 1440x900, so a single
    set of hard-coded boxes is correct for every run; if the layout
    ever changes the boxes need to move with it."""
    with Image.open(path) as im:
        rgb = im.convert("RGB")
        draw = ImageDraw.Draw(rgb)
        draw.rectangle(_TOTP_QR_BOX,     fill=(20, 20, 20))
        draw.rectangle(_TOTP_SECRET_BOX, fill=(20, 20, 20))
        font = _load_label_font(18)
        draw.text((_TOTP_QR_BOX[0] + 40, _TOTP_QR_BOX[1] + 110),
                  "QR REDACTED",   fill=(230, 80, 80), font=font)
        draw.text((_TOTP_SECRET_BOX[0] + 90, _TOTP_SECRET_BOX[1] + 6),
                  "SECRET REDACTED", fill=(230, 80, 80), font=font)
        rgb.save(path, format="PNG")


async def shoot_totp_walkthrough(page: Page) -> None:
    """Capture the /security page in its "not enrolled" state and again
    after POSTing /security/enroll, which renders the QR code and the
    manual-entry secret. The verify step is NOT submitted -- per
    app/templates/security.html the database is untouched until the
    operator confirms the 6-digit code, so abandoning the flow leaves
    no trace."""

    await shoot(page, "40_totp_not_enrolled.png", "/security",
                "TOTP -- account-security landing, not enrolled")

    # The "Set up an authenticator app" button POSTs to /security/enroll
    # with a CSRF token. Driving the form through Playwright lets us
    # reuse the page's CSRF cookie + hidden field instead of harvesting
    # them by hand.
    try:
        await page.click('form[action$="/security/enroll"] button[type="submit"]')
        await page.wait_for_load_state("networkidle", timeout=10000)
        await page.wait_for_timeout(500)
        # Confirm the QR/secret block actually rendered before saving.
        if await page.locator("text=Scan this QR").count() == 0:
            print("  warn: /security/enroll did not return a QR page; skipping 41")
            return
        out = OUT_DIR / "41_totp_enrollment_qr.png"
        await page.screenshot(path=str(out), full_page=True)
        # The QR code and the manual-entry secret are real OTP material
        # for the operator account that was used to drive this capture
        # run. They were never persisted to the database (the verify
        # form was deliberately left unsubmitted), but a checked-in
        # screenshot is permanent, so paint over both regions before
        # writing the image to OUT_DIR. Layout is deterministic at the
        # 1440x900 viewport, so fixed coordinates are safe.
        _redact_totp_secret(out)
        print("  saved 41_totp_enrollment_qr.png  <- TOTP -- mid-enrolment QR + manual secret (redacted)")
    except Exception as exc:
        print(f"  warn: TOTP enrolment screenshot failed: {exc}", file=sys.stderr)


# --- Section 50-51: SAML walkthrough -------------------------------------

async def shoot_saml_walkthrough(page: Page) -> None:
    """Capture /admin/sso in its default "Generic SAML 2.0" labelling,
    then click the "Use Okta" radio (pure client-side relabel, no
    POST) and capture again so the documentation shows both the
    vendor-neutral form and the Okta-shaped variant side by side."""

    await shoot(page, "50_admin_sso_generic.png", "/admin/sso",
                "SSO config -- Generic SAML 2.0 labels")

    try:
        await page.goto(f"{BASE_URL}/admin/sso", wait_until="networkidle")
        # Toggle the "Use Okta" radio. The page's inline JS swaps the
        # IdP-field labels and placeholders into Okta's nomenclature
        # without touching the server.
        await page.click('input[name="idp_label"][value="okta"]')
        await page.wait_for_timeout(500)
        out = OUT_DIR / "51_admin_sso_okta_relabeled.png"
        await page.screenshot(path=str(out), full_page=True)
        print("  saved 51_admin_sso_okta_relabeled.png  <- SSO config -- Okta-relabeled fields")
    except Exception as exc:
        print(f"  warn: SAML Okta-toggle screenshot failed: {exc}", file=sys.stderr)


# --- Section 60-63: theme walkthrough ------------------------------------

async def _set_theme(page: Page, choice: str) -> None:
    """POST to /theme with the chosen value. Reuses Playwright's logged-in
    context so the session cookie + CSRF token come along automatically."""
    await page.goto(f"{BASE_URL}/theme", wait_until="networkidle")
    # Pick the radio matching the requested theme, then submit.
    await page.click(f'input[name="theme"][value="{choice}"]')
    await page.click('form[action$="/theme"] button[type="submit"]')
    await page.wait_for_load_state("networkidle", timeout=10000)


async def shoot_theme_walkthrough(page: Page) -> None:
    """Capture the theme preference page in dark, then flip the user to
    light and capture three pages so the visual difference is obvious.
    The flip is wrapped in try/finally so a mid-run crash still leaves
    the operator account on its original (dark) theme."""

    # The whole capture run starts on dark, so this first shot reflects
    # the default.
    await shoot(page, "60_theme_dark.png", "/theme",
                "Theme preference -- dark selected")

    try:
        await _set_theme(page, "light")
        await shoot(page, "61_theme_light.png", "/theme",
                    "Theme preference -- light selected")
        await shoot(page, "62_dashboard_light.png", "/",
                    "Dashboard rendered in light mode")
        await shoot(page, "63_assessments_light.png", "/assessments",
                    "Assessments list in light mode")
    finally:
        # Restore the operator's account to dark regardless of how the
        # block above exited. Otherwise a failed run would leave the
        # admin user permanently on light mode.
        try:
            await _set_theme(page, "dark")
        except Exception as exc:
            print(f"  WARNING: failed to restore theme to dark: {exc}",
                  file=sys.stderr)


# --- Driver --------------------------------------------------------------

async def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(
            viewport=VIEWPORT,
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        host = urlparse(BASE_URL).netloc
        print(f"capturing {BASE_URL} (host {host}) -> {OUT_DIR}")

        # 01-24: top-level pages.
        await login(page)
        for fn, path, desc in TOP_LEVEL_PAGES[1:]:  # 01_login already done
            try:
                await shoot(page, fn, path, desc)
            except Exception as exc:
                print(f"  ERROR capturing {path}: {exc}", file=sys.stderr)

        # 25-33: detail pages discovered from listings.
        await shoot_detail_pages(page)

        # 40-41: TOTP walkthrough.
        await shoot_totp_walkthrough(page)

        # 50-51: SAML walkthrough.
        await shoot_saml_walkthrough(page)

        # 60-63: theme walkthrough (dark, flip to light, restore to dark).
        await shoot_theme_walkthrough(page)

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
