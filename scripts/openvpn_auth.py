#!/opt/vpn-portal/.venv/bin/python
import os
import sqlite3
import sys
from datetime import datetime, timezone

from werkzeug.security import check_password_hash


DB_PATH = os.environ.get("PORTAL_DB_PATH", "/opt/vpn-portal/data/portal.db")


def parse_iso(value: str | None):
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_active_subscription(row: sqlite3.Row) -> bool:
    if int(row["wg_enabled"] or 0) != 1:
        return False
    expires_at = parse_iso(row["subscription_expires_at"])
    if expires_at and expires_at >= datetime.now(timezone.utc):
        return True
    quota = int(row["traffic_quota_bytes"] or 0)
    used = int(row["traffic_used_bytes"] or 0)
    return quota > 0 and used < quota


def load_credentials(auth_file: str) -> tuple[str, str]:
    with open(auth_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    if len(lines) < 2:
        return "", ""
    username = (lines[0] or "").strip()
    password = lines[1] or ""
    return username, password


def authenticate(username: str, password: str) -> bool:
    if not username or not password:
        return False

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                email,
                username,
                password_hash,
                role,
                subscription_expires_at,
                wg_enabled,
                traffic_quota_bytes,
                traffic_used_bytes
            FROM users
            WHERE (email = ? OR username = ?) AND role = 'user'
            LIMIT 1
            """,
            (username.lower(), username),
        ).fetchone()
        if not row:
            return False
        if not check_password_hash(row["password_hash"], password):
            return False
        return is_active_subscription(row)
    finally:
        conn.close()


def main() -> int:
    if len(sys.argv) < 2:
        return 1
    auth_file = sys.argv[1]
    username, password = load_credentials(auth_file)
    return 0 if authenticate(username, password) else 1


if __name__ == "__main__":
    raise SystemExit(main())
