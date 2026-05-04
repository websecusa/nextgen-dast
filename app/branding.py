# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Branding settings — single-row table, plus on-disk logos.

All file-system writes go through here so safety checks are centralized.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import db

LOGO_DIR = Path("/data/branding")
# Logo "kinds" -- four web/pdf slots. The web nav has a light-mode
# slot AND a dark-mode slot so an operator can ship a logo tuned
# for each sidebar; base.html selects the right one based on the
# viewer's theme. PDF cover / footer keep their own slots. Old
# `header` / `footer` names stay in the allowlist for back-compat
# with previously-uploaded files.
ALLOWED_KINDS = ("web_header", "web_header_dark",
                 "pdf_header", "pdf_footer",
                 "header", "footer")

# Dark-mode (default) palette. When web_mode='dark', the web UI uses these
# regardless of any web_* color values that may be set. Switch web_mode to
# 'custom' to take per-color overrides.
DARK_DEFAULTS = {
    "primary":  "#5fb3d7",
    "accent":   "#7bc47f",
    "font":     "-apple-system, system-ui, 'Segoe UI', sans-serif",
    "sev_critical": "#ff8a8a",   # bright red, readable on dark
    "sev_high":     "#e67373",
    "sev_medium":   "#e0c46c",
    "sev_low":      "#5fb3d7",
    "sev_info":     "#8a96a3",
}

# PDF defaults — designed for paper (white background, dark text).
PDF_DEFAULTS = {
    "primary":      "#5fb3d7",
    "accent":       "#7bc47f",
    "classif":      "#bb3333",
    "font":         "'Liberation Sans', 'DejaVu Sans', sans-serif",
    "sev_critical": "#6b1f1f",
    "sev_high":     "#c0392b",
    "sev_medium":   "#d4a017",
    "sev_low":      "#3a89ad",
    "sev_info":     "#5d6770",
    # Foreground color for the cover page (which sits on `primary_color`).
    # Default white pairs well with most accent backgrounds; admins can override
    # when their primary_color is light and white text becomes invisible.
    "cover_text":   "#ffffff",
    # Headings (h1/h2/h3) and the rules under h2. Picked independently of the
    # cover background — a near-white primary_color (legitimate brand choice)
    # would otherwise render headings invisible on white pages.
    "header":       "#1a3a5c",
    # Body / paragraph text. Also drives the inline severity labels in finding
    # sections — the severity itself is signaled by border-left and badge
    # color, so the *text* should read like any other paragraph.
    "body":         "#1f2630",
    # Hyperlink color. Default is Wikipedia's #0645ad — a print-friendly
    # blue that stays readable on a black-and-white printout. Decoupled
    # from primary_color because brand primary often doubles as the
    # cover-page background and may legitimately be set to a pale tone
    # under which link text disappears.
    "link":         "#0645ad",
}
# Magic bytes → (extension, content-type)
MAGIC = {
    b"\x89PNG\r\n\x1a\n": ("png", "image/png"),
    b"\xff\xd8\xff": ("jpg", "image/jpeg"),
}
MAX_LOGO_BYTES = 2 * 1024 * 1024   # 2 MB
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _ensure_dir() -> None:
    LOGO_DIR.mkdir(parents=True, exist_ok=True)


def get() -> dict:
    """Return the single branding row. The row is seeded by schema.sql, but
    if it's somehow missing we synthesise sensible defaults."""
    row = db.query_one("SELECT * FROM branding WHERE id = 1")
    if not row:
        db.execute("INSERT IGNORE INTO branding (id) VALUES (1)")
        row = db.query_one("SELECT * FROM branding WHERE id = 1")
    return row or {}


def get_web() -> dict:
    """Resolved web brand: when web_mode == 'dark', dark defaults win
    regardless of any custom colors set; otherwise the user values are
    used (falling back to defaults for empty cells)."""
    b = get()
    mode = (b.get("web_mode") or "dark").lower()
    # Two header-logo slots: light and dark. Both are surfaced to the
    # template; base.html picks the right one based on the viewer's
    # theme. On a single-logo deployment whichever slot is set wins
    # (see resolve_web_header_logo_kind).
    light_logo = b.get("web_header_logo_filename")
    dark_logo  = b.get("web_header_logo_dark_filename")
    if mode == "dark":
        d = DARK_DEFAULTS
        return {
            "mode": "dark",
            "primary": d["primary"],
            "accent":  d["accent"],
            "font":    d["font"],
            "sev_critical": d["sev_critical"],
            "sev_high":     d["sev_high"],
            "sev_medium":   d["sev_medium"],
            "sev_low":      d["sev_low"],
            "sev_info":     d["sev_info"],
            "header_logo_filename": light_logo,
            "header_logo_dark_filename": dark_logo,
        }
    d = DARK_DEFAULTS
    return {
        "mode": "custom",
        "primary": b.get("web_primary_color") or d["primary"],
        "accent":  b.get("web_accent_color")  or d["accent"],
        "font":    b.get("web_font_family")   or d["font"],
        "sev_critical": b.get("web_sev_critical") or d["sev_critical"],
        "sev_high":     b.get("web_sev_high")     or d["sev_high"],
        "sev_medium":   b.get("web_sev_medium")   or d["sev_medium"],
        "sev_low":      b.get("web_sev_low")      or d["sev_low"],
        "sev_info":     b.get("web_sev_info")     or d["sev_info"],
        "header_logo_filename": light_logo,
        "header_logo_dark_filename": dark_logo,
    }


# --- System-wide default theme -------------------------------------------
# Stored in the generic config k/v table rather than a dedicated column on
# `branding` because it's a single scalar with no companion fields. The
# default is exposed via getter/setter so callers don't have to know which
# table backs it; if we ever move it to a typed column the helpers stay.
_DEFAULT_THEME_KEY = "default_theme"
_VALID_THEMES = ("dark", "light")


def get_default_theme() -> str:
    """Return the operator-configured default UI theme ('dark' or 'light').

    Used as the fallback for visitors who have not made a personal choice
    (login page, brand-new users) and as the seed value for new accounts.
    Returns 'dark' when the DB is unhealthy or the config row is missing,
    so the login page never blanks out on a transient backend hiccup."""
    try:
        if not db.healthy():
            return "dark"
        row = db.query_one(
            "SELECT value FROM config WHERE `key`=%s",
            (_DEFAULT_THEME_KEY,))
    except Exception:
        return "dark"
    if not row:
        return "dark"
    val = (row.get("value") or "").strip().lower()
    return val if val in _VALID_THEMES else "dark"


def set_default_theme(value: str) -> None:
    """Persist the operator-configured default UI theme. Validates against
    the allowed set so a tampered form value cannot smuggle arbitrary text
    into the config row."""
    choice = (value or "").strip().lower()
    if choice not in _VALID_THEMES:
        choice = "dark"
    db.execute(
        "INSERT INTO config (`key`, value) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE value = VALUES(value)",
        (_DEFAULT_THEME_KEY, choice))


def resolve_web_header_logo_kind(theme: str) -> Optional[str]:
    """Pick the right web-logo `kind` for the viewer's current theme,
    falling back to the other slot when only one is uploaded.

    Returns the `kind` string (e.g. "web_header" / "web_header_dark")
    that base.html should use to construct the /branding/logo/<kind>
    URL, or None when no web logo is configured at all (in which
    case the template falls back to the legacy pdf header logo)."""
    b = get()
    light = b.get("web_header_logo_filename")
    dark  = b.get("web_header_logo_dark_filename")
    if (theme or "dark").lower() == "dark":
        if dark:
            return "web_header_dark"
        if light:
            return "web_header"
    else:
        if light:
            return "web_header"
        if dark:
            return "web_header_dark"
    return None


def _hex_to_rgba(h: str, alpha: float) -> str:
    """Convert #rrggbb to a CSS rgba() string. Falls back to white at alpha
    so an unparseable input still produces a usable color."""
    s = (h or "").lstrip("#")
    if len(s) != 6:
        return f"rgba(255,255,255,{alpha})"
    try:
        r, g, b = int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)
    except ValueError:
        return f"rgba(255,255,255,{alpha})"
    return f"rgba({r},{g},{b},{alpha})"


def get_pdf() -> dict:
    """Resolved PDF brand. Independent from the web theme — paper-optimized
    defaults, falling back per-field to PDF_DEFAULTS for any empty cells."""
    b = get()
    d = PDF_DEFAULTS
    cover_text = b.get("pdf_cover_text_color") or d["cover_text"]
    return {
        "primary":             b.get("primary_color")        or d["primary"],
        "accent":              b.get("accent_color")         or d["accent"],
        "classification_color": b.get("classification_color") or d["classif"],
        "font":                b.get("pdf_font_family")      or d["font"],
        "sev_critical":        b.get("pdf_sev_critical")     or d["sev_critical"],
        "sev_high":            b.get("pdf_sev_high")         or d["sev_high"],
        "sev_medium":          b.get("pdf_sev_medium")       or d["sev_medium"],
        "sev_low":             b.get("pdf_sev_low")          or d["sev_low"],
        "sev_info":            b.get("pdf_sev_info")         or d["sev_info"],
        "cover_text":          cover_text,
        "cover_text_rule":     _hex_to_rgba(cover_text, 0.4),
        "header":              b.get("pdf_header_color")     or d["header"],
        "body":                b.get("pdf_body_color")       or d["body"],
        "link":                b.get("pdf_link_color")       or d["link"],
        # PDF logos: the legacy *_logo_filename columns are PDF-side
        "header_logo_filename": b.get("header_logo_filename"),
        "footer_logo_filename": b.get("footer_logo_filename"),
    }


def update(fields: dict) -> None:
    """Update only the columns we recognize. Skips empty colors / etc."""
    allowed = {
        # shared
        "company_name", "tagline", "classification", "header_text",
        "footer_text", "disclaimer", "contact_email",
        # PDF
        "primary_color", "accent_color", "classification_color",
        "pdf_font_family", "pdf_cover_text_color",
        "pdf_header_color", "pdf_body_color", "pdf_link_color",
        "pdf_sev_critical", "pdf_sev_high", "pdf_sev_medium",
        "pdf_sev_low", "pdf_sev_info",
        # web
        "web_mode", "web_primary_color", "web_accent_color", "web_font_family",
        "web_sev_critical", "web_sev_high", "web_sev_medium",
        "web_sev_low", "web_sev_info",
    }
    sets = []
    params = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k.endswith("_color"):
            v = (v or "").strip()
            if v and not COLOR_RE.match(v):
                continue
        sets.append(f"{k} = %s")
        params.append((v or "").strip() or None)
    if not sets:
        return
    params.append(1)
    db.execute(f"UPDATE branding SET {', '.join(sets)} WHERE id = %s", params)


def _detect_image(data: bytes) -> Optional[tuple[str, str]]:
    """Return (ext, content_type) if `data` starts with a recognized magic
    byte sequence, else None. SVG is intentionally not supported here — it
    can carry script payloads and needs sanitisation we don't have yet."""
    for magic, info in MAGIC.items():
        if data.startswith(magic):
            return info
    return None


def save_logo(kind: str, data: bytes) -> dict:
    """Validate and store a logo. Returns {ok, error?, filename?}."""
    if kind not in ALLOWED_KINDS:
        return {"ok": False, "error": f"kind must be one of {ALLOWED_KINDS}"}
    if len(data) > MAX_LOGO_BYTES:
        return {"ok": False,
                "error": f"file too large ({len(data)} > {MAX_LOGO_BYTES})"}
    det = _detect_image(data)
    if not det:
        return {"ok": False,
                "error": "not a recognized image (PNG or JPEG only)"}
    ext, _ctype = det

    _ensure_dir()
    # Predictable filename — old logo of any extension gets overwritten via
    # the UPDATE below + cleanup of stale files for this kind.
    new_name = f"{kind}.{ext}"
    out = LOGO_DIR / new_name
    out.write_bytes(data)
    # Remove stale entries with a different extension for the same kind
    for stale in LOGO_DIR.glob(f"{kind}.*"):
        if stale.name != new_name:
            try:
                stale.unlink()
            except OSError:
                pass
    col = _logo_column_for(kind)
    db.execute(
        f"UPDATE branding SET {col} = %s WHERE id = 1",
        (new_name,),
    )
    return {"ok": True, "filename": new_name}


def _logo_column_for(kind: str) -> str:
    """Map a logo kind to its DB column. Legacy 'header'/'footer' kinds map
    to the original PDF logo columns so old uploads keep working.
    `web_header_dark` is the dark-mode-only slot added in 2026-05-04."""
    return {
        "header":           "header_logo_filename",
        "footer":           "footer_logo_filename",
        "pdf_header":       "header_logo_filename",
        "pdf_footer":       "footer_logo_filename",
        "web_header":       "web_header_logo_filename",
        "web_header_dark":  "web_header_logo_dark_filename",
    }[kind]


def delete_logo(kind: str) -> None:
    if kind not in ALLOWED_KINDS:
        return
    for f in LOGO_DIR.glob(f"{kind}.*"):
        try:
            f.unlink()
        except OSError:
            pass
    col = _logo_column_for(kind)
    db.execute(f"UPDATE branding SET {col} = NULL WHERE id = 1")


def get_logo_path(kind: str) -> Optional[Path]:
    if kind not in ALLOWED_KINDS:
        return None
    col = _logo_column_for(kind)
    row = db.query_one(f"SELECT {col} AS fn FROM branding WHERE id = 1")
    if not row or not row.get("fn"):
        return None
    p = LOGO_DIR / row["fn"]
    return p if p.exists() else None


def get_content_type(filename: str) -> str:
    if filename.endswith(".png"):
        return "image/png"
    if filename.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    return "application/octet-stream"
