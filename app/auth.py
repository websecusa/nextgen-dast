# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication profiles.

Profiles are stored in /data/auth_profiles.json. Each scanner run can attach
one profile so the scan inherits the application session.

Profile types:
  basic   - HTTP basic auth (username + password)
  form    - HTML form-based login (URL + field names + creds)
  cookies - pre-acquired session cookies (typically captured from the proxy
            after an SSO / OAuth / SAML / Okta FastPass / DUO login)
  bearer  - Authorization: Bearer <token>

Why "capture cookies from proxy" exists:
Okta FastPass, DUO push, WebAuthn, and most MFA-protected SSO flows cannot be
driven headlessly. The user logs in once through the intercept proxy in a
real browser — completing whatever MFA challenge their IdP demands — and we
extract the resulting session cookies (and any Authorization header in
subsequent requests) into a profile that the scanners can replay.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DATA = Path("/data")
PROFILES_FILE = DATA / "auth_profiles.json"
FLOWS_DIR = DATA / "flows"

VALID_TYPES = {"basic", "form", "cookies", "bearer"}


def _load() -> dict:
    if PROFILES_FILE.exists():
        try:
            return json.loads(PROFILES_FILE.read_text())
        except Exception:
            pass
    return {}


def _save(d: dict) -> None:
    PROFILES_FILE.write_text(json.dumps(d, indent=2))


def list_profiles() -> list[dict]:
    return sorted(_load().values(), key=lambda p: p.get("name", ""))


def get_profile(name: str) -> Optional[dict]:
    return _load().get(name)


def save_profile(profile: dict) -> dict:
    if not profile.get("name"):
        raise ValueError("name required")
    if profile.get("type") not in VALID_TYPES:
        raise ValueError(f"type must be one of {VALID_TYPES}")
    profile["updated_at"] = datetime.now(timezone.utc).isoformat()
    profile.setdefault("created_at", profile["updated_at"])
    d = _load()
    d[profile["name"]] = profile
    _save(d)
    return profile


def delete_profile(name: str) -> None:
    d = _load()
    if name in d:
        del d[name]
        _save(d)


# ---- capture from proxy flow ------------------------------------------------

_SETCOOKIE = re.compile(r"^Set-Cookie:\s*(.+)$", re.I | re.M)
_AUTH = re.compile(r"^Authorization:\s*(.+)$", re.I | re.M)
_HEADER_LINE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.+)$", re.M)


def _parse_set_cookie(header_value: str) -> dict:
    parts = [p.strip() for p in header_value.split(";")]
    name, _, value = parts[0].partition("=")
    cookie = {"name": name.strip(), "value": value.strip(),
              "path": "/", "domain": "", "secure": False, "httponly": False,
              "samesite": ""}
    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k in ("domain", "path", "samesite", "expires", "max-age"):
                cookie[k] = v
        else:
            a = attr.strip().lower()
            if a == "secure":
                cookie["secure"] = True
            elif a == "httponly":
                cookie["httponly"] = True
    return cookie


def capture_from_flow(flow_id: str, profile_name: str,
                      host_filter: str = "") -> dict:
    """Build a 'cookies' profile from a flow's request & response txt files."""
    req_path = FLOWS_DIR / f"{flow_id}_request.txt"
    resp_path = FLOWS_DIR / f"{flow_id}_response.txt"
    if not req_path.exists() and not resp_path.exists():
        raise FileNotFoundError(f"no captured files for flow {flow_id}")

    cookies: list[dict] = []
    headers: dict[str, str] = {}

    if resp_path.exists():
        head = resp_path.read_text(errors="replace").split("\r\n\r\n", 1)[0]
        for m in _SETCOOKIE.finditer(head):
            cookies.append(_parse_set_cookie(m.group(1)))

    if req_path.exists():
        head = req_path.read_text(errors="replace").split("\r\n\r\n", 1)[0]
        # if the request already had a Cookie header, also remember it
        for m in _HEADER_LINE.finditer(head):
            k, v = m.group(1), m.group(2)
            if k.lower() == "cookie":
                # parse "a=1; b=2" into individual cookies if not already present
                for piece in v.split(";"):
                    n, _, val = piece.strip().partition("=")
                    if n and not any(c["name"] == n for c in cookies):
                        cookies.append({"name": n, "value": val, "path": "/",
                                        "domain": host_filter, "secure": False,
                                        "httponly": False})
            elif k.lower() == "authorization":
                headers["Authorization"] = v

    profile = {
        "name": profile_name,
        "type": "cookies",
        "host_filter": host_filter,
        "cookies": cookies,
        "headers": headers,
        "captured_from_flow": flow_id,
    }
    return save_profile(profile)


# ---- scanner argument generation --------------------------------------------

def _write_mozilla_cookies(cookies: list[dict], dest: Path,
                           default_domain: str = "") -> None:
    lines = ["# Netscape HTTP Cookie File"]
    expires = int(time.time()) + 86400  # 1 day
    for c in cookies:
        domain = c.get("domain") or default_domain or ""
        if not domain:
            continue
        if not domain.startswith("."):
            domain_field = domain
            include_sub = "FALSE"
        else:
            domain_field = domain
            include_sub = "TRUE"
        path = c.get("path") or "/"
        secure = "TRUE" if c.get("secure") else "FALSE"
        lines.append("\t".join([
            domain_field, include_sub, path, secure,
            str(expires), c["name"], c["value"]
        ]))
    dest.write_text("\n".join(lines) + "\n")


def wapiti_args(profile: dict, scan_dir: Path, target: str) -> list[str]:
    """Return the CLI args wapiti needs to honor this auth profile."""
    args: list[str] = []
    t = profile.get("type")
    if t == "basic":
        u = profile.get("basic", {}).get("username", "")
        p = profile.get("basic", {}).get("password", "")
        if u and p:
            args += ["--auth-method", "basic", "--auth-cred", f"{u}%{p}"]
    elif t == "form":
        f = profile.get("form_login", {})
        if f.get("username") and f.get("password") and f.get("login_url"):
            args += ["--form-cred", f"{f['username']}%{f['password']}",
                     "--form-url", f["login_url"]]
    elif t == "cookies":
        cookies = profile.get("cookies") or []
        if cookies:
            host = profile.get("host_filter") or ""
            if not host:
                # derive from target
                m = re.match(r"https?://([^/:]+)", target)
                host = m.group(1) if m else ""
            cookie_path = scan_dir / "auth_cookies.txt"
            _write_mozilla_cookies(cookies, cookie_path, default_domain=host)
            args += ["--cookie", str(cookie_path)]
        for hk, hv in (profile.get("headers") or {}).items():
            args += ["--header", f"{hk}: {hv}"]
    elif t == "bearer":
        token = profile.get("bearer", {}).get("token", "")
        if token:
            args += ["--header", f"Authorization: Bearer {token}"]
    return args


def nikto_args(profile: dict) -> tuple[list[str], Optional[str]]:
    """Return (extra_args, warning) for nikto. nikto's auth support is
    limited — only basic auth is well-supported via the CLI."""
    t = profile.get("type")
    if t == "basic":
        u = profile.get("basic", {}).get("username", "")
        p = profile.get("basic", {}).get("password", "")
        if u and p:
            return ["-id", f"{u}:{p}"], None
        return [], "basic auth profile is missing credentials"
    if t == "cookies":
        # nikto has no clean CLI for cookie injection; we fall back to a
        # User-Agent encoding trick that works for the modern parser via -evasion.
        # Easier: warn the user to use a wrapper. We attempt -useragent with
        # cookie? No — cleanest: emit nothing and warn.
        return [], ("nikto cannot replay cookie sessions from the CLI; "
                    "use wapiti for authenticated scans, or run nikto behind "
                    "the intercept proxy after logging in.")
    if t == "bearer":
        return [], ("nikto cannot inject custom Authorization headers from "
                    "the CLI; use wapiti or scan via the intercept proxy.")
    if t == "form":
        return [], "nikto does not support form-based login; use wapiti."
    return [], None


# ---- Live form login (used by the Challenge / probe-validation flow) -------
#
# The Challenge button on a finding-detail page needs to validate under the
# same authenticated context the original scan ran in. Rather than asking
# the analyst to paste a cookie every time, we re-run the form login here
# using the credentials stored on the assessment. The resulting Set-Cookie
# is returned in memory and handed to the probe via stdin JSON — never via
# argv (visible in `ps`), never written to the filesystem, and the value
# is redacted in any saved evidence.
#
# Field-name discovery: GET the login URL, parse the first <form> that
# contains both a text-style input and a password input, use those input
# names for the POST. This handles ~95% of conventional PHP / Django /
# Rails / Express login pages without a per-app config.
import http.cookiejar
import ssl
import urllib.parse
import urllib.request

# Browser-like UA so badly-coded login pages don't reject the GET.
_LOGIN_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

_RE_FORM   = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_RE_ACTION = re.compile(r'\baction\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_INPUT  = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_RE_NAME   = re.compile(r'\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_TYPE   = re.compile(r'\btype\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_VALUE  = re.compile(r'\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)


def _parse_login_form(html: str, page_url: str) -> Optional[dict]:
    """Find the first <form> on the page that has both a username-ish input
    and a password input. Returns dict with action, user_field, pass_field,
    plus any hidden inputs (CSRF tokens, viewstate, etc.) we should send.
    Returns None if no candidate form is present."""
    for m in _RE_FORM.finditer(html):
        body = m.group(1)
        inputs = []
        for inp in _RE_INPUT.findall(body):
            name_m = _RE_NAME.search(inp)
            type_m = _RE_TYPE.search(inp)
            val_m  = _RE_VALUE.search(inp)
            if not name_m:
                continue
            inputs.append({
                "name": name_m.group(1),
                "type": (type_m.group(1).lower() if type_m else "text"),
                "value": (val_m.group(1) if val_m else ""),
            })
        pass_field = next((i for i in inputs if i["type"] == "password"), None)
        if not pass_field:
            continue
        # Username-ish: text/email/search type, or commonly named field.
        text_field = next(
            (i for i in inputs if i["type"] in ("text", "email", "search")
             or i["name"].lower() in ("username", "user", "login",
                                       "email", "userid")),
            None,
        )
        if not text_field:
            continue
        # action attribute on the form element itself
        form_open = m.group(0)[:m.group(0).find(">") + 1]
        action_m = _RE_ACTION.search(form_open)
        action = action_m.group(1) if action_m else page_url
        # Hidden inputs (CSRF, ViewState, etc.) — preserve their values.
        hidden = {i["name"]: i["value"] for i in inputs
                  if i["type"] == "hidden" and i["name"]
                  and i["name"] not in (text_field["name"], pass_field["name"])}
        return {
            "action": urllib.parse.urljoin(page_url, action),
            "user_field": text_field["name"],
            "pass_field": pass_field["name"],
            "hidden": hidden,
        }
    return None


def form_login_cookie(login_url: str, username: str, password: str,
                      timeout: float = 15.0,
                      verify_tls: bool = False) -> dict:
    """Execute a single form-based login and return the resulting session
    cookie header value (the string you'd put in `Cookie:`).

    Returns a dict:
        {"ok": True, "cookie": "a=1; b=2", "diagnostics": {...}}
        {"ok": False, "error": "...", "diagnostics": {...}}

    The credentials only ever live in this function's frame and the
    POST body. They are never written to disk, logged, or passed via
    argv. Returned `cookie` should be passed to subprocess probes via
    stdin JSON — not argv — and redacted before being persisted."""
    if not (login_url and username and password):
        return {"ok": False, "error": "login_url + username + password required"}

    # Cookie jar tracks Set-Cookie across the redirect chain.
    jar = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(jar),
    )
    diagnostics: dict = {}

    # 1. GET the login page so we can discover field names.
    req = urllib.request.Request(login_url, headers={"User-Agent": _LOGIN_UA})
    try:
        with opener.open(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", "replace")
            diagnostics["login_page_status"] = resp.status
    except Exception as e:
        return {"ok": False, "error": f"GET login page failed: {e}",
                "diagnostics": diagnostics}

    form = _parse_login_form(html, login_url)
    if not form:
        return {"ok": False,
                "error": "no recognisable login form on the login page "
                         "(no <form> with both text and password inputs)",
                "diagnostics": diagnostics}
    diagnostics["form"] = {
        "action": form["action"],
        "user_field": form["user_field"],
        "pass_field": form["pass_field"],
        "hidden_fields": list(form["hidden"].keys()),
    }

    # 2. POST credentials. Hidden fields (CSRF tokens, viewstate) preserved.
    post_data = dict(form["hidden"])
    post_data[form["user_field"]] = username
    post_data[form["pass_field"]] = password
    body = urllib.parse.urlencode(post_data).encode()
    req = urllib.request.Request(
        form["action"], data=body, method="POST",
        headers={
            "User-Agent": _LOGIN_UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": login_url,
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            diagnostics["login_post_status"] = resp.status
            diagnostics["login_post_final_url"] = resp.url
    except urllib.error.HTTPError as e:
        diagnostics["login_post_status"] = e.code
    except Exception as e:
        return {"ok": False, "error": f"POST login failed: {e}",
                "diagnostics": diagnostics}

    # 3. Build the Cookie header from the jar — only cookies for the
    # login URL's host (so we don't leak unrelated third-party cookies).
    parsed = urllib.parse.urlparse(login_url)
    target_host = parsed.hostname or ""
    pieces: list[str] = []
    for c in jar:
        if not c.domain:
            continue
        cd = c.domain.lstrip(".").lower()
        if cd == target_host or target_host.endswith("." + cd):
            pieces.append(f"{c.name}={c.value}")
    if not pieces:
        return {"ok": False,
                "error": ("login completed but no cookies were set for "
                          f"host {target_host!r}. Wrong credentials, "
                          "an MFA prompt, or the login uses tokens "
                          "instead of cookies."),
                "diagnostics": diagnostics}
    diagnostics["cookies_set"] = [c.split("=", 1)[0] for c in pieces]
    return {"ok": True, "cookie": "; ".join(pieces),
            "diagnostics": diagnostics}


def redact_cookie(cookie_header: str) -> str:
    """Replace each cookie's value with `***` while keeping the names. Used
    when persisting validation evidence so secrets never land in the DB."""
    if not cookie_header:
        return ""
    out = []
    for piece in cookie_header.split(";"):
        piece = piece.strip()
        if not piece or "=" not in piece:
            continue
        name, _, _val = piece.partition("=")
        out.append(f"{name.strip()}=***")
    return "; ".join(out)
