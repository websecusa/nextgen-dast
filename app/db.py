# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Tiny PyMySQL helper. Per-call connections; no pool — overkill at our scale."""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterable, Optional

import pymysql
import pymysql.cursors


def _conn():
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "13306")),
        user=os.environ.get("DB_USER", "pentest"),
        password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "pentest"),
        autocommit=True,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


@contextmanager
def get_db():
    conn = _conn()
    try:
        yield conn
    finally:
        conn.close()


def query(sql: str, params: Optional[Iterable[Any]] = None) -> list[dict]:
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return list(cur.fetchall())


def query_one(sql: str, params: Optional[Iterable[Any]] = None) -> Optional[dict]:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: Optional[Iterable[Any]] = None) -> int:
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.lastrowid


def healthy() -> bool:
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            return True
    except Exception:
        return False
