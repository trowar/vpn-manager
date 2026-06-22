import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from datetime import datetime, timezone

from flask import Response, current_app, request, session
from werkzeug.security import check_password_hash

from portal_config import (
    DOWNLOAD_ACCESS_IP_LOCK_ENABLED,
    DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS,
    SESSION_LAST_ACTIVITY_KEY,
    SINGLE_WEB_SESSION_ENABLED,
)
from portal_db import get_db


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def row_get(row, key: str, default=None):
    try:
        return row[key]
    except Exception:
        return default


def _host_without_optional_port(raw_host: str | None) -> str:
    host = (raw_host or "").strip()
    if not host:
        return ""
    if host.startswith("[") and "]" in host:
        end = host.find("]")
        if end > 1:
            return host[1:end]
    if host.count(":") == 1:
        host_part, port_part = host.rsplit(":", 1)
        if host_part and port_part.isdigit():
            return host_part
    return host


def get_client_ip() -> str:
    cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf_ip:
        return cf_ip

    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first

    x_real_ip = (request.headers.get("X-Real-IP") or "").strip()
    if x_real_ip:
        return x_real_ip

    return (request.remote_addr or "").strip() or "unknown"


def normalize_public_client_ip(raw_value: str | None) -> str:
    raw = (raw_value or "").strip()
    if not raw:
        return ""
    host = _host_without_optional_port(raw)
    if not host:
        return ""
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback:
            return ""
        return str(ip_obj)
    except Exception:
        return host


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return None
    current_version = int(row_get(user, "session_version", 1) or 1)
    session_version = session.get("session_version")
    if session_version is None or int(session_version) != current_version:
        session.clear()
        return None
    if (
        row_get(user, "role") == "user"
        and (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled"
    ):
        session.clear()
        return None
    return user


def build_download_access_token(user, scope: str) -> str:
    user_id = int(row_get(user, "id", 0) or 0)
    session_version = int(row_get(user, "session_version", 1) or 1)
    now_ts = int(time.time())
    client_ip = normalize_public_client_ip(get_client_ip())
    payload_obj = {
        "uid": user_id,
        "sv": session_version,
        "scp": str(scope or "").strip(),
        "iat": now_ts,
        "exp": now_ts + DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS,
        "cip": client_ip,
        "rnd": secrets.token_urlsafe(18),
    }
    payload = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    secret = str(current_app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
    signature = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def resolve_download_access_user(db, access_token: str, scope: str):
    token = (access_token or "").strip()
    if not token:
        return None

    parts = token.split(".")
    if len(parts) == 2:
        payload_b64, signature = parts
        if payload_b64 and signature:
            secret = str(current_app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
            expected_signature = hmac.new(
                secret, payload_b64.encode("ascii"), hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected_signature, signature):
                try:
                    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
                    payload_raw = base64.urlsafe_b64decode(padded.encode("ascii"))
                    payload_obj = json.loads(payload_raw.decode("utf-8"))
                except Exception:
                    payload_obj = None
                if isinstance(payload_obj, dict):
                    token_scope = str(payload_obj.get("scp", "") or "").strip()
                    user_id = int(payload_obj.get("uid", 0) or 0)
                    session_version = int(payload_obj.get("sv", 0) or 0)
                    expire_ts = int(payload_obj.get("exp", 0) or 0)
                    token_client_ip = normalize_public_client_ip(
                        str(payload_obj.get("cip", "") or "")
                    )
                    request_client_ip = normalize_public_client_ip(get_client_ip())
                    now_ts = int(time.time())
                    if (
                        token_scope == str(scope or "").strip()
                        and user_id > 0
                        and session_version > 0
                        and expire_ts >= now_ts
                    ):
                        if (
                            DOWNLOAD_ACCESS_IP_LOCK_ENABLED
                            and token_client_ip
                            and request_client_ip
                            and token_client_ip != request_client_ip
                        ):
                            return None
                        user = db.execute(
                            "SELECT * FROM users WHERE id = ?",
                            (user_id,),
                        ).fetchone()
                        if not user:
                            return None
                        current_session_version = int(
                            row_get(user, "session_version", 1) or 1
                        )
                        if current_session_version == session_version:
                            return user

    if len(parts) != 3:
        return None
    user_id_raw, session_version_raw, signature = parts
    if (not user_id_raw.isdigit()) or (not session_version_raw.isdigit()) or (not signature):
        return None
    user_id = int(user_id_raw)
    session_version = int(session_version_raw)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None
    current_session_version = int(row_get(user, "session_version", 1) or 1)
    if current_session_version != session_version:
        return None
    payload = f"{user_id}:{session_version}:{scope}"
    secret = str(current_app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
    expected_signature = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return None
    return user


def config_download_error(message: str, status: int = 403) -> Response:
    return Response(
        (message or "download denied") + "\n",
        status=status,
        mimetype="text/plain; charset=utf-8",
    )


def admin_must_change_password(user) -> bool:
    if not user or row_get(user, "role") != "admin":
        return False
    return int(row_get(user, "force_password_change", 0) or 0) == 1


def authenticate_user(identity: str, password: str):
    db = get_db()
    user = db.execute(
        """
        SELECT * FROM users
        WHERE username = ? OR email = ?
        LIMIT 1
        """,
        (identity, identity.lower()),
    ).fetchone()
    if not user:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def login_user_session(user) -> None:
    session.clear()
    session["user_id"] = user["id"]
    session["session_version"] = int(row_get(user, "session_version", 1) or 1)
    session[SESSION_LAST_ACTIVITY_KEY] = int(time.time())


def record_user_login_activity(db, user_id: int, *, rotate_session: bool = False):
    client_ip = normalize_public_client_ip(get_client_ip())
    if rotate_session and SINGLE_WEB_SESSION_ENABLED:
        db.execute(
            """
            UPDATE users
            SET last_login_ip = ?,
                last_login_at = ?,
                session_version = session_version + 1
            WHERE id = ?
            """,
            (client_ip, utcnow_iso(), int(user_id)),
        )
    else:
        db.execute(
            """
            UPDATE users
            SET last_login_ip = ?,
                last_login_at = ?
            WHERE id = ?
            """,
            (client_ip, utcnow_iso(), int(user_id)),
        )
    db.commit()
    return db.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()


def start_user_login_session(db, user):
    refreshed = record_user_login_activity(
        db,
        int(user["id"]),
        rotate_session=True,
    )
    if refreshed:
        login_user_session(refreshed)
        return refreshed
    login_user_session(user)
    return user


def user_api_payload(user) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "subscription_expires_at": user["subscription_expires_at"],
        "vpn_enabled": bool(user["vpn_enabled"]),
    }
