# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""User-management module. bcrypt for passwords; three roles.

Role tiers (highest → lowest):
  superadmin — superset of admin. Can also: edit AI Prompts, set the
               system-default Enhanced-AI budget, set per-user max_spend
               caps, and promote/demote between superadmin and admin.
               At least one superadmin must always exist.
  admin      — read/write on assessments and the /admin/* settings area.
               Sees the per-scan Enhanced-AI budget field but cannot
               edit it (form renders the input as disabled).
  readonly   — browse-only. Cannot start scans or mutate anything.

The 'superadmin' tier shipped with the Enhanced-AI-Testing release; the
schema migration in app/migrations.py promotes every existing role='admin'
row to 'superadmin' so no one loses privilege on first boot of the new
image. New users still default to 'readonly' on creation.
"""
from __future__ import annotations

import secrets
import string
from datetime import datetime, timezone
from typing import Optional

import bcrypt

import db

# Tuple is order-significant for some UI dropdowns: highest privilege first.
ROLES = ("superadmin", "admin", "readonly")
# Tiers that use the legacy is_admin=1 column. Both superadmin and admin
# pass the existing is_admin checks (everywhere is_admin is consulted as a
# coarse "can mutate" gate). Superadmin-specific gates use role directly.
_PRIVILEGED_ROLES = ("superadmin", "admin")


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def gen_password(n: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def get_by_username(username: str) -> Optional[dict]:
    return db.query_one("SELECT * FROM users WHERE username = %s LIMIT 1",
                        (username,))


def get_by_id(user_id: int) -> Optional[dict]:
    return db.query_one("SELECT * FROM users WHERE id = %s LIMIT 1",
                        (user_id,))


def list_users() -> list[dict]:
    return db.query(
        "SELECT id, username, role, max_spend_usd, disabled, last_login, "
        "created_at FROM users ORDER BY username")


def count_superadmins() -> int:
    """Return the number of active (non-disabled) superadmin users.
    Used to enforce the last-superadmin lockout protection: demoting or
    deleting the only remaining superadmin is refused so the operator
    cannot accidentally lock themselves out of /admin/ai-prompts and
    the system-default budget controls."""
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM users "
        "WHERE role='superadmin' AND disabled=0")
    return int((row or {}).get("n") or 0)


def authenticate(username: str, password: str) -> Optional[dict]:
    """Returns the user dict on success, None on any failure (wrong password,
    disabled account, missing user). Same return for all failure modes so we
    don't leak which usernames exist."""
    u = get_by_username(username)
    if not u:
        # Constant-time defense: still hash the password so timing is similar.
        bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return None
    if u.get("disabled"):
        return None
    try:
        ok = bcrypt.checkpw(password.encode(), u["password_hash"].encode())
    except (ValueError, TypeError):
        return None
    if not ok:
        return None
    db.execute("UPDATE users SET last_login = %s WHERE id = %s",
               (datetime.now(timezone.utc).replace(tzinfo=None), u["id"]))
    return u


def create(username: str, password: str, role: str = "readonly") -> int:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    return db.execute(
        "INSERT INTO users (username, password_hash, role, is_admin) "
        "VALUES (%s, %s, %s, %s)",
        (username.strip(), _hash(password), role,
         1 if role in _PRIVILEGED_ROLES else 0),
    )


def set_role(user_id: int, role: str) -> None:
    """Change a user's role. Refuses to demote the last active superadmin
    so operators cannot accidentally lock themselves out of the
    superadmin-only screens (AI Prompts editor, system-default budget,
    per-user max_spend). The check counts non-disabled superadmins only;
    disabling a superadmin is treated the same as demotion for this
    invariant (see set_disabled)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    current = get_by_id(user_id)
    if (current and current.get("role") == "superadmin"
            and role != "superadmin"
            and count_superadmins() <= 1
            and not current.get("disabled")):
        raise ValueError(
            "cannot demote the last active superadmin; promote another "
            "user to superadmin first")
    db.execute(
        "UPDATE users SET role = %s, is_admin = %s WHERE id = %s",
        (role, 1 if role in _PRIVILEGED_ROLES else 0, int(user_id)),
    )


def set_max_spend(user_id: int, max_spend_usd: Optional[float]) -> None:
    """Set or clear the per-user Enhanced-AI per-scan budget cap.
    None / NULL = no per-user cap (system default applies). Caller is
    responsible for permission gating — this function does not check
    role; gates live at the HTTP handler in app/server.py."""
    if max_spend_usd is not None:
        try:
            max_spend_usd = round(float(max_spend_usd), 2)
        except (TypeError, ValueError):
            raise ValueError("max_spend_usd must be numeric or NULL")
        if max_spend_usd < 0:
            raise ValueError("max_spend_usd cannot be negative")
    db.execute(
        "UPDATE users SET max_spend_usd = %s WHERE id = %s",
        (max_spend_usd, int(user_id)))


def set_password(user_id: int, password: str) -> None:
    db.execute("UPDATE users SET password_hash = %s WHERE id = %s",
               (_hash(password), int(user_id)))


def set_disabled(user_id: int, disabled: bool) -> None:
    """Disable an account. Refuses to disable the last active superadmin
    (same invariant as set_role's last-superadmin guard)."""
    if disabled:
        u = get_by_id(user_id)
        if (u and u.get("role") == "superadmin"
                and not u.get("disabled")
                and count_superadmins() <= 1):
            raise ValueError(
                "cannot disable the last active superadmin; promote "
                "another user to superadmin first")
    db.execute("UPDATE users SET disabled = %s WHERE id = %s",
               (1 if disabled else 0, int(user_id)))


def set_totp_secret(user_id: int, secret: Optional[str]) -> None:
    """Persist (or clear) a user's TOTP secret. Setting `secret` to a
    non-empty string also stamps totp_enrolled_at; clearing the secret
    (None or empty) clears the timestamp too. Caller is responsible for
    having already verified a code against the secret — this function
    does not validate the secret shape beyond non-empty."""
    if secret:
        db.execute(
            "UPDATE users SET totp_secret = %s, totp_enrolled_at = %s "
            "WHERE id = %s",
            (secret, datetime.now(timezone.utc).replace(tzinfo=None),
             int(user_id)),
        )
    else:
        db.execute(
            "UPDATE users SET totp_secret = NULL, totp_enrolled_at = NULL "
            "WHERE id = %s", (int(user_id),))


def find_or_create_saml_user(name_id: str) -> dict:
    """Look up a local user row whose username matches the SAML NameID,
    or JIT-provision one with role='readonly' and auth_source='saml'.

    JIT-provisioned users carry no password_hash (NULL is rejected by
    bcrypt.checkpw, so authenticate() refuses them automatically). An
    existing admin can promote a SAML-only user from /admin/users like
    any other account; the role floor is 'readonly' so an unexpected
    Okta directory entry can't grant elevated access on first login.

    A name_id collision with a pre-existing local username is treated as
    "this is the same person" — we sign them in. That intentional
    overlap lets an operator pre-create a username that matches the
    Okta email and have SAML take over once the IdP config lands.
    Returns the user dict the session cookie will be derived from."""
    name_id = (name_id or "").strip()
    if not name_id:
        raise ValueError("SAML NameID was empty")
    existing = get_by_username(name_id)
    if existing:
        if existing.get("disabled"):
            raise ValueError("user is disabled")
        db.execute(
            "UPDATE users SET last_login = %s WHERE id = %s",
            (datetime.now(timezone.utc).replace(tzinfo=None),
             existing["id"]),
        )
        return existing
    # Insert a SAML-only row. password_hash carries an explicit empty
    # string (NOT NULL on the column) so the row schema stays valid; the
    # bcrypt check inside authenticate() returns False on any non-hash
    # value, so this account cannot use /login even if force_saml is
    # later turned off.
    db.execute(
        "INSERT INTO users (username, password_hash, role, is_admin, "
        "auth_source, last_login) VALUES (%s, %s, %s, %s, %s, %s)",
        (name_id, "", "readonly", 0, "saml",
         datetime.now(timezone.utc).replace(tzinfo=None)),
    )
    row = get_by_username(name_id)
    if not row:
        raise RuntimeError("SAML JIT provisioning failed: row not found")
    return row


def delete(user_id: int) -> None:
    """Delete a user. Same last-superadmin guard as set_role / set_disabled."""
    u = get_by_id(user_id)
    if (u and u.get("role") == "superadmin"
            and not u.get("disabled")
            and count_superadmins() <= 1):
        raise ValueError(
            "cannot delete the last active superadmin; promote another "
            "user to superadmin first")
    db.execute("DELETE FROM users WHERE id = %s", (int(user_id),))
