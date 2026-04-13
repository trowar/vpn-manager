#!/usr/bin/env python3
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone


DB_PATH = os.environ.get("PORTAL_DB_PATH", "/app/data/portal.db")
SETTING_OPENVPN_OPEN = "openvpn_open"
OPENVPN_COMMON_NAME_PREFIX = os.environ.get("OPENVPN_COMMON_NAME_PREFIX", "vpn-user-").strip()


def parse_iso(value: str | None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except Exception:
        return None
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


def parse_user_id_from_common_name(common_name: str) -> int | None:
    value = (common_name or "").strip()
    if not value:
        return None
    pattern = rf"{re.escape(OPENVPN_COMMON_NAME_PREFIX)}(\d+)"
    match = re.fullmatch(pattern, value)
    if not match:
        return None
    try:
        user_id = int(match.group(1))
    except Exception:
        return None
    return user_id if user_id > 0 else None


def parse_common_name_from_subject(subject: str) -> str:
    value = (subject or "").strip()
    if not value:
        return ""
    # Supports formats like '/CN=vpn-user-1/...' or 'CN=vpn-user-1,...'
    match = re.search(r"(?:^|/|,)CN\s*=\s*([^,/]+)", value)
    if not match:
        return ""
    return (match.group(1) or "").strip()


def load_common_name_from_tls_verify(argv: list[str]) -> tuple[str, bool]:
    if len(argv) < 3:
        return "", False
    depth = (argv[1] or "").strip()
    subject = argv[2] or ""
    if depth and depth != "0":
        return "", True
    return parse_common_name_from_subject(subject), True


def authenticate_common_name(common_name: str) -> bool:
    user_id = parse_user_id_from_common_name(common_name)
    if user_id is None:
        print(f"[openvpn-auth] invalid common name: {common_name}", file=sys.stderr, flush=True)
        return False

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        setting_row = conn.execute(
            """
            SELECT setting_value
            FROM app_settings
            WHERE setting_key = ?
            LIMIT 1
            """,
            (SETTING_OPENVPN_OPEN,),
        ).fetchone()
        if setting_row is not None:
            raw_setting = (setting_row["setting_value"] or "").strip().lower()
            if raw_setting in {"0", "false", "off", "no"}:
                print("[openvpn-auth] openvpn disabled by setting", file=sys.stderr, flush=True)
                return False

        row = conn.execute(
            """
            SELECT
                id,
                role,
                wg_enabled,
                subscription_expires_at,
                traffic_quota_bytes,
                traffic_used_bytes,
                openvpn_common_name
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        if not row:
            print(f"[openvpn-auth] user not found for id={user_id}", file=sys.stderr, flush=True)
            return False

        stored_common_name = (row["openvpn_common_name"] or "").strip()
        if stored_common_name and stored_common_name != common_name:
            print(
                f"[openvpn-auth] common name mismatch: expected={stored_common_name} got={common_name}",
                file=sys.stderr,
                flush=True,
            )
            return False

        role = (row["role"] or "").strip().lower()
        if role == "admin":
            return True
        if not is_active_subscription(row):
            print(f"[openvpn-auth] inactive subscription for user id={user_id}", file=sys.stderr, flush=True)
            return False
        return True
    finally:
        conn.close()


def main() -> int:
    common_name, known_mode = load_common_name_from_tls_verify(sys.argv)
    if known_mode:
        if not common_name:
            return 1
        return 0 if authenticate_common_name(common_name) else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
