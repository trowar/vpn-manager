#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

from werkzeug.security import check_password_hash


DB_PATH = os.environ.get("PORTAL_DB_PATH", "/opt/vpn-portal/data/portal.db")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
OPENVPN_STATUS_FILE = os.environ.get("OPENVPN_STATUS_FILE", "/tmp/openvpn-status.log")
SETTING_OPENVPN_OPEN = "openvpn_open"
SESSION_REJECT_MESSAGE = "已有连接未断开，请稍后再试"
WG_ACTIVE_HANDSHAKE_SECONDS_RAW = os.environ.get(
    "VPN_SINGLE_SESSION_WG_HANDSHAKE_SECONDS", "180"
).strip()
try:
    WG_ACTIVE_HANDSHAKE_SECONDS = max(5, int(WG_ACTIVE_HANDSHAKE_SECONDS_RAW or 180))
except ValueError:
    WG_ACTIVE_HANDSHAKE_SECONDS = 180


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


def normalize_identity(value: str | None) -> str:
    return (value or "").strip().lower()


def load_credentials(auth_file: str) -> tuple[str, str]:
    with open(auth_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    if len(lines) < 2:
        return "", ""
    username = (lines[0] or "").strip()
    password = lines[1] or ""
    return username, password


def parse_openvpn_active_identities(status_file: str) -> set[str]:
    if not status_file or not os.path.exists(status_file):
        return set()
    identities: set[str] = set()
    in_client_section = False
    try:
        with open(status_file, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = (raw or "").strip()
                if not line:
                    continue

                # status-version 2/3 csv lines
                if line.startswith("CLIENT_LIST,"):
                    parts = line.split(",")
                    if len(parts) > 1:
                        candidate = normalize_identity(parts[1])
                        if candidate and candidate != "common name":
                            identities.add(candidate)
                    continue

                # status-version 1 section markers
                if line.startswith("Common Name,"):
                    in_client_section = True
                    continue
                if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                    in_client_section = False
                    continue
                if in_client_section and "," in line:
                    candidate = normalize_identity(line.split(",", 1)[0])
                    if candidate and candidate != "common name":
                        identities.add(candidate)
    except Exception:
        return set()
    return identities


def is_wireguard_session_active(public_key: str | None) -> bool:
    key = (public_key or "").strip()
    if not key:
        return False
    try:
        completed = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False

    dump = completed.stdout or ""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    for raw_line in dump.splitlines()[1:]:
        parts = raw_line.split("\t")
        if len(parts) < 7:
            continue
        if parts[0].strip() != key:
            continue
        endpoint = (parts[2] or "").strip() if len(parts) > 2 else ""
        try:
            latest_handshake = int(parts[4])
        except Exception:
            latest_handshake = 0
        if not endpoint or latest_handshake <= 0:
            return False
        if now_ts - latest_handshake <= max(5, WG_ACTIVE_HANDSHAKE_SECONDS):
            return True
        return False
    return False


def has_conflicting_active_session(row: sqlite3.Row) -> bool:
    username = normalize_identity(row["username"])
    email = normalize_identity(row["email"])
    active_identities = parse_openvpn_active_identities(OPENVPN_STATUS_FILE)
    if username and username in active_identities:
        return True
    if email and email in active_identities:
        return True
    if is_wireguard_session_active(row["client_public_key"]):
        return True
    return False


def authenticate(username: str, password: str) -> bool:
    if not username or not password:
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
                return False
        row = conn.execute(
            """
            SELECT
                email,
                username,
                password_hash,
                role,
                client_public_key,
                subscription_expires_at,
                wg_enabled,
                traffic_quota_bytes,
                traffic_used_bytes
            FROM users
            WHERE (email = ? OR username = ?) AND role IN ('user', 'admin')
            LIMIT 1
            """,
            (username.lower(), username),
        ).fetchone()
        if not row:
            return False
        if not check_password_hash(row["password_hash"], password):
            return False
        if (row["role"] or "").strip().lower() == "admin":
            return True
        if not is_active_subscription(row):
            return False
        if has_conflicting_active_session(row):
            print(f"[openvpn-auth] {SESSION_REJECT_MESSAGE}", file=sys.stderr, flush=True)
            return False
        return True
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
