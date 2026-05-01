#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Reset / bootstrap script.

Generic, app-neutral. Reused across deployments: drives any schema and any
secrets-file path passed in. The app's specifics (admin username, default
config, secrets keys) come from CLI flags or the environment, not hardcoded.

What it does:
  1. Wait for the database (--wait-secs).
  2. Apply --schema (idempotent CREATE IF NOT EXISTS).
  3. If --full: TRUNCATE all tables.
  4. Generate (or accept) a random admin password.
  5. Upsert the admin user.
  6. Seed default config rows (--seed-config-json, optional).
  7. Write --secrets to a chmod-600 file.
  8. Echo the credentials to stdout.

Required env (or CLI flags): DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import sys
import time
from pathlib import Path

import bcrypt
import pymysql


def gen_password(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def connect(host, port, user, password, database):
    return pymysql.connect(
        host=host, port=port, user=user, password=password, database=database,
        autocommit=True, charset="utf8mb4",
    )


def wait_for_db(args, retries=30, interval=1):
    last_err = None
    for _ in range(retries):
        try:
            connect(args.db_host, args.db_port, args.db_user, args.db_password,
                    args.db_name).close()
            return
        except Exception as e:
            last_err = e
            time.sleep(interval)
    raise RuntimeError(f"DB never came up: {last_err}")


def _split_sql(sql: str) -> list[str]:
    """Split a SQL script on top-level semicolons. Ignores semicolons that
    appear inside single-quoted string literals so seed data with semicolons
    in User-Agent / paths / URLs survives intact. No DELIMITER support — we
    don't ship triggers."""
    out: list[str] = []
    buf: list[str] = []
    in_str = False
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if in_str:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(sql[i + 1])
                i += 2
                continue
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    buf.append("'")  # doubled-quote escape
                    i += 2
                    continue
                in_str = False
            i += 1
        else:
            if c == "'":
                in_str = True
                buf.append(c)
                i += 1
                continue
            if c == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    out.append(stmt)
                buf = []
                i += 1
                continue
            buf.append(c)
            i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def apply_schema(conn, schema_path: str) -> None:
    sql = Path(schema_path).read_text()
    cleaned = "\n".join(line for line in sql.splitlines()
                        if not line.strip().startswith("--"))
    with conn.cursor() as cur:
        for stmt in _split_sql(cleaned):
            cur.execute(stmt)


def truncate_all(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        cur.execute("SHOW TABLES")
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            cur.execute(f"TRUNCATE TABLE `{t}`")
        cur.execute("SET FOREIGN_KEY_CHECKS=1")


def upsert_admin(conn, username: str, password: str) -> None:
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) "
            "VALUES (%s, %s, 1) "
            "ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), is_admin = 1",
            (username, pw_hash),
        )


def seed_config(conn, defaults: dict) -> None:
    if not defaults:
        return
    with conn.cursor() as cur:
        for k, v in defaults.items():
            cur.execute(
                "INSERT INTO config (`key`, value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE value = VALUES(value)",
                (k, str(v)),
            )


def write_secrets(path: str, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        try:
            p.chmod(0o600)
        except OSError:
            pass
    lines = [
        "# Sensitive secrets — DO NOT COMMIT, DO NOT SHARE.",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
    ]
    for k, v in data.items():
        lines.append(f"{k}={v}")
    p.write_text("\n".join(lines) + "\n")
    p.chmod(0o600)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--schema", default=os.environ.get("SCHEMA_FILE", "/app/db/schema.sql"))
    ap.add_argument("--secrets", default=os.environ.get("SECRETS_FILE", "/data/.sensitive_secrets_info"))
    ap.add_argument("--admin-username", default=os.environ.get("ADMIN_USERNAME", "admin"))
    ap.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD"),
                    help="Specific password to set (default: generate random)")
    ap.add_argument("--full", action="store_true",
                    help="TRUNCATE every table before seeding (data wipe)")
    ap.add_argument("--app-name", default=os.environ.get("APP_NAME", "nextgen-dast"))
    ap.add_argument("--app-url", default=os.environ.get("APP_URL", ""))
    ap.add_argument("--seed-config-json", default=os.environ.get("SEED_CONFIG_JSON", ""),
                    help="JSON object of config key/value pairs to seed")
    ap.add_argument("--db-host", default=os.environ.get("DB_HOST", "127.0.0.1"))
    ap.add_argument("--db-port", type=int, default=int(os.environ.get("DB_PORT", "13306")))
    ap.add_argument("--db-user", default=os.environ.get("DB_USER", "pentest"))
    ap.add_argument("--db-password", default=os.environ.get("DB_PASSWORD", ""))
    ap.add_argument("--db-name", default=os.environ.get("DB_NAME", "pentest"))
    args = ap.parse_args()

    if not args.db_password:
        print("ERROR: DB_PASSWORD not set", file=sys.stderr)
        return 2

    print(f"[reset] connecting to {args.db_host}:{args.db_port} db={args.db_name}", flush=True)
    wait_for_db(args)
    conn = connect(args.db_host, args.db_port, args.db_user, args.db_password, args.db_name)

    print(f"[reset] applying schema: {args.schema}", flush=True)
    apply_schema(conn, args.schema)

    if args.full:
        print("[reset] FULL: truncating all tables", flush=True)
        truncate_all(conn)

    password = args.admin_password or gen_password()

    print(f"[reset] seeding admin user: {args.admin_username!r}", flush=True)
    upsert_admin(conn, args.admin_username, password)

    if args.seed_config_json:
        try:
            seed = json.loads(args.seed_config_json)
            seed_config(conn, seed)
            print(f"[reset] seeded {len(seed)} config row(s)", flush=True)
        except Exception as e:
            print(f"[reset] WARN: --seed-config-json invalid: {e}", file=sys.stderr)

    secrets_payload = {
        "APP_NAME": args.app_name,
        "APP_URL": args.app_url,
        "ADMIN_USERNAME": args.admin_username,
        "ADMIN_PASSWORD": password,
    }
    write_secrets(args.secrets, secrets_payload)
    print(f"[reset] wrote secrets file: {args.secrets} (chmod 600)", flush=True)

    print()
    print("=" * 64)
    print(f"  {args.app_name} reset complete")
    print(f"  URL:      {args.app_url or '(not set)'}")
    print(f"  Username: {args.admin_username}")
    print(f"  Password: {password}")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
