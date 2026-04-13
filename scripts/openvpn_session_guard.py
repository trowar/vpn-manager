#!/usr/bin/env python3
import os
import re
import socket
import sqlite3
import time
from datetime import datetime, timezone


DB_PATH = os.environ.get("PORTAL_DB_PATH", "/app/data/portal.db")
OPENVPN_STATUS_FILE = os.environ.get("OPENVPN_STATUS_FILE", "/tmp/openvpn-status.log")
OPENVPN_MANAGEMENT_HOST = os.environ.get("OPENVPN_MANAGEMENT_HOST", "127.0.0.1")
OPENVPN_MANAGEMENT_PORT_RAW = os.environ.get("OPENVPN_MANAGEMENT_PORT", "7505").strip()
OPENVPN_SESSION_GUARD_INTERVAL_RAW = os.environ.get("OPENVPN_SESSION_GUARD_INTERVAL", "20").strip()
OPENVPN_COMMON_NAME_PREFIX = os.environ.get("OPENVPN_COMMON_NAME_PREFIX", "vpn-user-").strip()
SETTING_OPENVPN_OPEN = "openvpn_open"

try:
    OPENVPN_MANAGEMENT_PORT = max(1, int(OPENVPN_MANAGEMENT_PORT_RAW or "7505"))
except ValueError:
    OPENVPN_MANAGEMENT_PORT = 7505

try:
    OPENVPN_SESSION_GUARD_INTERVAL = max(5, int(OPENVPN_SESSION_GUARD_INTERVAL_RAW or "20"))
except ValueError:
    OPENVPN_SESSION_GUARD_INTERVAL = 20


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


def parse_openvpn_active_identities(raw_text: str) -> list[str]:
    identities: list[str] = []
    seen: set[str] = set()
    in_client_section = False
    for raw_line in (raw_text or "").splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        if line.startswith("CLIENT_LIST,"):
            parts = line.split(",")
            if len(parts) > 1:
                identity = (parts[1] or "").strip()
                if identity and identity not in seen and identity.lower() != "common name":
                    seen.add(identity)
                    identities.append(identity)
            continue
        if line.startswith("Common Name,"):
            in_client_section = True
            continue
        if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
            in_client_section = False
            continue
        if in_client_section and "," in line:
            identity = (line.split(",", 1)[0] or "").strip()
            if identity and identity not in seen and identity.lower() != "common name":
                seen.add(identity)
                identities.append(identity)
    return identities


def parse_user_id_from_common_name(common_name: str | None) -> int | None:
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


def should_allow_identity(conn: sqlite3.Connection, identity: str) -> bool:
    identity_value = (identity or "").strip()
    if not identity_value:
        return False

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

    user_id = parse_user_id_from_common_name(identity_value)
    if user_id is None:
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
        return False
    expected_identity = (row["openvpn_common_name"] or "").strip()
    if expected_identity and expected_identity != identity_value:
        return False
    role = (row["role"] or "").strip().lower()
    if role == "admin":
        return True
    return is_active_subscription(row)


def kill_openvpn_identity(identity: str) -> None:
    with socket.create_connection((OPENVPN_MANAGEMENT_HOST, OPENVPN_MANAGEMENT_PORT), timeout=3) as sock:
        sock.settimeout(3)
        try:
            sock.recv(4096)
        except Exception:
            pass
        command = f"kill {identity}\n".encode("utf-8")
        sock.sendall(command)
        try:
            sock.recv(4096)
        except Exception:
            pass


def enforce_once() -> None:
    if not OPENVPN_STATUS_FILE or not os.path.exists(OPENVPN_STATUS_FILE):
        return
    try:
        raw_text = open(OPENVPN_STATUS_FILE, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return
    identities = parse_openvpn_active_identities(raw_text)
    if not identities:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        for identity in identities:
            if should_allow_identity(conn, identity):
                continue
            try:
                kill_openvpn_identity(identity)
                print(
                    f"[openvpn-guard] disconnected identity={identity} (inactive/expired/unknown)",
                    flush=True,
                )
            except Exception as exc:
                print(
                    f"[openvpn-guard] failed to disconnect identity={identity}: {exc}",
                    flush=True,
                )
    finally:
        conn.close()


def main() -> int:
    print(
        f"[openvpn-guard] started interval={OPENVPN_SESSION_GUARD_INTERVAL}s management={OPENVPN_MANAGEMENT_HOST}:{OPENVPN_MANAGEMENT_PORT}",
        flush=True,
    )
    while True:
        try:
            enforce_once()
        except Exception as exc:
            print(f"[openvpn-guard] loop error: {exc}", flush=True)
        time.sleep(OPENVPN_SESSION_GUARD_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
