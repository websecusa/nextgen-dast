# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Tiny user-management module. bcrypt for passwords, two roles."""
from __future__ import annotations

import secrets
import string
from datetime import datetime, timezone
from typing import Optional

import bcrypt

import db

ROLES = ("admin", "readonly")


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
        "SELECT id, username, role, disabled, last_login, created_at "
        "FROM users ORDER BY username")


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
        (username.strip(), _hash(password), role, 1 if role == "admin" else 0),
    )


def set_role(user_id: int, role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    db.execute(
        "UPDATE users SET role = %s, is_admin = %s WHERE id = %s",
        (role, 1 if role == "admin" else 0, int(user_id)),
    )


def set_password(user_id: int, password: str) -> None:
    db.execute("UPDATE users SET password_hash = %s WHERE id = %s",
               (_hash(password), int(user_id)))


def set_disabled(user_id: int, disabled: bool) -> None:
    db.execute("UPDATE users SET disabled = %s WHERE id = %s",
               (1 if disabled else 0, int(user_id)))


def delete(user_id: int) -> None:
    db.execute("DELETE FROM users WHERE id = %s", (int(user_id),))
