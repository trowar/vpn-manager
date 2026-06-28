from portal_config import *
import base64
import hashlib
import json
import shutil
import shlex
import zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from portal_auth import (
    admin_must_change_password,
    authenticate_user,
    build_download_access_token,
    config_download_error,
    current_user,
    get_client_ip,
    login_user_session,
    normalize_public_client_ip,
    resolve_download_access_user,
    row_get,
    start_user_login_session,
    user_api_payload,
)
from portal_format import (
    add_months,
    default_payment_settings,
    duration_value_to_legacy_months,
    format_admin_local_date_input,
    format_admin_local_input,
    format_order_plan,
    format_plan_display_name,
    format_plan_value,
    format_utc,
    format_usdt,
    generate_plan_name,
    normalize_duration_unit,
    normalize_plan_mode,
    parse_admin_local_date,
    parse_admin_local_datetime,
    parse_iso,
    parse_positive_int,
    parse_usdt_amount,
    parse_usdt_amount_strict,
    plan_duration_unit_label,
    plan_mode_label,
    resolve_duration_value_and_unit,
    resolve_order_plan_snapshot,
    to_non_negative_int,
    utcnow,
    utcnow_iso,
)
from portal_settings import (
    ensure_default_system_settings,
    format_mail_security_label,
    format_sender_display,
    get_app_setting,
    load_named_settings,
    normalize_mail_security,
    parse_bool_setting,
    parse_int_setting,
    upsert_app_setting,
)
from portal_web import (
    absolute_url_for,
    build_download_filename_for_user,
    build_masked_download_link,
    display_label_from_host,
    host_without_optional_port,
    is_non_public_host,
    normalize_domain_host,
    normalize_fqdn,
    safe_name,
)
from portal_vpn_profiles import (
    default_profile_mode_from_policy,
    detect_openvpn_platform,
)
from portal_services.versioning import (
    get_current_app_version,
    load_version_nav_state,
)
from portal_services.admin_user_servers import (
    apply_user_server_switch,
    decorate_admin_subscription_row,
)
from portal_services.admin_servers import (
    load_admin_servers as load_admin_servers_impl,
    load_user_selectable_servers as load_user_selectable_servers_impl,
    normalize_relay_port,
    refresh_missing_server_regions as refresh_missing_server_regions_impl,
    usdt_explorer_link,
)
from portal_services.captcha import (
    create_captcha_svg_response_payload,
    validate_captcha_input as validate_captcha_input_impl,
)
from portal_services.commands import (
    run_command,
    run_local_command_with_output,
)
from portal_services.deploy_logs import (
    append_system_upgrade_log,
    build_structured_deploy_log,
    clip_text,
    mask_secret,
    normalize_deploy_log_text,
    read_system_upgrade_log_text,
    summarize_text,
)
from portal_services.servers import (
    detect_server_region,
    get_server_kcptun_port as _get_server_kcptun_port,
    get_server_shadowsocks_backend_port as _get_server_shadowsocks_backend_port,
    normalize_remote_host,
    normalize_server_port,
    normalize_server_region,
    runtime_uses_kcptun as _runtime_uses_kcptun,
    serialize_runtime_server,
    server_supports_openvpn,
    server_supports_ssh_tunnel,
    server_supports_ss_kcptun,
)
from portal_services.vpn_runtime import (
    build_shadowsocks_sport_filter_expr,
    format_bytes,
    format_bytes_in_gb,
    format_bytes_in_mb,
    handshake_epoch_to_iso,
    parse_kcptun_active_peer_hosts,
    parse_shadowsocks_active_peer_snapshot,
)
from portal_services.vpn_api_client import (
    host_for_http_url,
    request_vpn_api,
)
from portal_services.openvpn_certs import (
    ensure_user_openvpn_client_identity,
)
from portal_services import ss_profiles as ss_profile_service
from portal_services.system_upgrade import (
    load_system_upgrade_state as load_system_upgrade_state_impl,
    load_system_upgrade_state_with_timeout_unlock as load_system_upgrade_state_with_timeout_unlock_impl,
    save_system_upgrade_state as save_system_upgrade_state_impl,
)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET_KEY", "change-this-secret")
_OPENVPN_ROUTE_LINES_CACHE: list[str] | None = None
_OPENVPN_ROUTE_LINES_PROFILE_CACHE: dict[str, list[str]] = {}
SYSTEM_UPGRADE_LOG_TAIL_CHARS = 20000


@app.template_filter("fmt_utc")
def fmt_utc_filter(value: str | None) -> str:
    return format_utc(value)


@app.template_filter("fmt_local_date_input")
def fmt_local_date_input_filter(value: str | None) -> str:
    return format_admin_local_date_input(value)


@app.template_filter("fmt_local_input")
def fmt_local_input_filter(value: str | None) -> str:
    return format_admin_local_date_input(value)


@app.template_filter("fmt_order_plan")
def fmt_order_plan_filter(order: DatabaseRow | dict) -> str:
    return format_order_plan(order)


def get_openvpn_endpoint_host(
    *, user: DatabaseRow | None = None, server_row: DatabaseRow | None = None
) -> str:
    use_server = server_row
    if use_server is None and user is not None:
        try:
            db = get_db()
            use_server = get_persisted_runtime_server_for_account(db, user)
        except Exception:
            use_server = None

    def prefer_configured_host(candidate: str | None) -> str:
        host = host_without_optional_port(candidate)
        if not host:
            return ""
        return host

    if use_server is not None:
        preferred_domain = prefer_configured_host(
            normalize_domain_host(row_get(use_server, "domain", ""))
        )
        if preferred_domain:
            return preferred_domain
        preferred_host = prefer_configured_host(
            normalize_remote_host(row_get(use_server, "host", ""))
        )
        if preferred_host:
            return preferred_host

    preferred_portal_domain = prefer_configured_host(get_portal_domain_setting())
    if preferred_portal_domain:
        return preferred_portal_domain

    preferred_openvpn_host = prefer_configured_host(OPENVPN_ENDPOINT_HOST)
    if preferred_openvpn_host:
        return preferred_openvpn_host

    try:
        preferred_request_host = prefer_configured_host(request.host)
        if preferred_request_host:
            return preferred_request_host
    except Exception:
        pass

    return ""


def get_openvpn_route_lines() -> list[str]:
    global _OPENVPN_ROUTE_LINES_CACHE
    if _OPENVPN_ROUTE_LINES_CACHE is not None:
        return _OPENVPN_ROUTE_LINES_CACHE

    _OPENVPN_ROUTE_LINES_CACHE = get_openvpn_route_lines_for_profile(
        default_profile_mode_from_policy()
    )
    return _OPENVPN_ROUTE_LINES_CACHE


def get_openvpn_route_lines_for_profile(profile_mode: str) -> list[str]:
    mode = (profile_mode or "global").strip().lower() or "global"
    if mode in _OPENVPN_ROUTE_LINES_PROFILE_CACHE:
        return _OPENVPN_ROUTE_LINES_PROFILE_CACHE[mode]

    lines = ["redirect-gateway def1"]
    _OPENVPN_ROUTE_LINES_PROFILE_CACHE[mode] = lines
    return lines


def read_required_text(path: Path, label: str) -> str:
    if not path.exists():
        raise RuntimeError(f"{label} 文件不存在：{path}")
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise RuntimeError(f"{label} 文件为空：{path}")
    return content


def read_first_existing_text(paths: list[Path]) -> str:
    for path in paths:
        try:
            if path.exists():
                content = path.read_text(encoding="utf-8").strip()
                if content:
                    return content
        except Exception:
            continue
    return ""


def get_openvpn_client_materials(
    *, user: DatabaseRow | None = None, server_row: DatabaseRow | None = None
) -> tuple[str, str]:
    api_error: Exception | None = None
    if use_vpn_api(user=user, server_row=server_row):
        try:
            result = vpn_api_request(
                "GET",
                "/openvpn/client-materials",
                user=user,
                server_row=server_row,
            )
            ca_text = (result.get("ca_cert") or "").strip()
            tls_crypt_text = (result.get("tls_crypt_key") or "").strip()
            if ca_text:
                return ca_text, tls_crypt_text
            api_error = RuntimeError("VPN API 未返回 OpenVPN CA 证书。")
        except Exception as exc:
            api_error = exc

    # Fallback to locally mounted/shared cert materials when remote API is
    # temporarily unavailable, so profile downloads remain available.
    ca_text = read_first_existing_text(
        [OPENVPN_CA_CERT_FILE, SHARED_OPENVPN_CA_CERT_FILE]
    )
    tls_crypt_text = read_first_existing_text(
        [OPENVPN_TLS_CRYPT_KEY_FILE, SHARED_OPENVPN_TLS_CRYPT_KEY_FILE]
    )
    if not ca_text:
        if api_error:
            raise RuntimeError(f"OpenVPN 材料获取失败：{api_error}")
        raise RuntimeError(
            f"OpenVPN CA 证书文件不存在或为空：{OPENVPN_CA_CERT_FILE} / {SHARED_OPENVPN_CA_CERT_FILE}"
        )
    if api_error:
        app.logger.warning("OpenVPN client materials fallback to local files: %s", api_error)
    return ca_text, tls_crypt_text


def build_openvpn_client_config(
    username: str,
    *,
    profile_mode: str | None = None,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
) -> str:
    if not is_openvpn_open():
        raise RuntimeError("管理员尚未启用 OpenVPN 支持。")

    ca_text, tls_crypt_text = get_openvpn_client_materials(
        user=user,
        server_row=server_row,
    )
    if user is None:
        raise RuntimeError("OpenVPN 配置生成需要用户上下文。")
    client_cert_text = (row_get(user, "openvpn_client_cert", "") or "").strip()
    client_key_text = (row_get(user, "openvpn_client_key", "") or "").strip()
    if not client_cert_text or not client_key_text:
        raise RuntimeError("用户 OpenVPN 证书不存在，请先重新下载配置生成证书。")

    resolved_server = server_row
    if resolved_server is None and user is not None:
        try:
            db = get_db()
            resolved_server = get_persisted_runtime_server_for_account(db, user)
        except Exception:
            resolved_server = None

    remote_host = ""
    remote_port = OPENVPN_ENDPOINT_PORT
    if resolved_server is not None:
        candidate_host = host_without_optional_port(
            normalize_domain_host(row_get(resolved_server, "domain", ""))
        ) or host_without_optional_port(
            normalize_remote_host(row_get(resolved_server, "host", ""))
        )
        candidate_port = normalize_server_port(
            row_get(resolved_server, "openvpn_port", OPENVPN_ENDPOINT_PORT),
            OPENVPN_ENDPOINT_PORT,
        )
        # 客户端配置优先使用服务器域名，便于后续迁移服务器时只改 DNS。
        if candidate_host:
            remote_host = candidate_host
            remote_port = candidate_port

    if not remote_host:
        remote_host = get_openvpn_endpoint_host(
            user=user,
            server_row=resolved_server or server_row,
        )
        if resolved_server is not None:
            remote_port = normalize_server_port(
                row_get(resolved_server, "openvpn_port", OPENVPN_ENDPOINT_PORT),
                OPENVPN_ENDPOINT_PORT,
            )
    if not remote_host:
        raise RuntimeError("未配置可用 OpenVPN 地址，请先设置服务器 IP 或域名。")
    lines = [
        "client",
        "dev tun",
        f"proto {OPENVPN_PROTO}",
        f"remote {remote_host} {remote_port}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        f"cipher {OPENVPN_CIPHER}",
        f"auth {OPENVPN_AUTH}",
        "verb 3",
    ]
    if OPENVPN_PROTO == "udp":
        lines.append("explicit-exit-notify 1")
    if OPENVPN_CLIENT_DNS:
        lines.append(f"dhcp-option DNS {OPENVPN_CLIENT_DNS}")
    mode = (profile_mode or default_profile_mode_from_policy()).strip().lower()
    lines.extend(get_openvpn_route_lines_for_profile(mode))

    lines.append("<ca>")
    lines.append(ca_text)
    lines.append("</ca>")
    lines.append("<cert>")
    lines.append(client_cert_text)
    lines.append("</cert>")
    lines.append("<key>")
    lines.append(client_key_text)
    lines.append("</key>")
    if tls_crypt_text:
        lines.append("<tls-crypt>")
        lines.append(tls_crypt_text)
        lines.append("</tls-crypt>")

    return "\n".join(lines) + "\n"


def get_registration_cooldown_seconds(
    db: DatabaseConnection, ip_address: str
) -> int:
    row = db.execute(
        """
        SELECT last_register_at
        FROM registration_limits
        WHERE ip_address = ?
        """,
        (ip_address,),
    ).fetchone()
    if not row:
        return 0

    last_register_at = parse_iso(row["last_register_at"])
    if not last_register_at:
        return 0

    next_allowed_at = last_register_at + timedelta(seconds=REGISTER_COOLDOWN_SECONDS)
    remaining = int((next_allowed_at - utcnow()).total_seconds())
    return remaining if remaining > 0 else 0


def mark_registration_success(
    db: DatabaseConnection, ip_address: str, at_iso: str
) -> None:
    db.execute(
        """
        INSERT INTO registration_limits (ip_address, last_register_at)
        VALUES (?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            last_register_at = excluded.last_register_at
        """,
        (ip_address, at_iso),
    )


@app.template_filter("fmt_usdt")
def fmt_usdt_filter(value: str | Decimal | None) -> str:
    return format_usdt(value)


def get_relay_public_host() -> str:
    def prefer_public_host(candidate: str | None) -> str:
        host = host_without_optional_port(candidate)
        if not host or is_non_public_host(host):
            return ""
        return host

    explicit_host = prefer_public_host(VPN_RELAY_PUBLIC_HOST)
    if explicit_host:
        return explicit_host

    portal_domain = prefer_public_host(get_portal_domain_setting())
    if portal_domain:
        return portal_domain

    ovpn_host = prefer_public_host(OPENVPN_ENDPOINT_HOST)
    if ovpn_host:
        return ovpn_host

    try:
        host = host_without_optional_port(request.host)
        if host and not is_non_public_host(host):
            return host
    except Exception:
        pass
    return ""


def allocate_user_ingress_port(
    db: DatabaseConnection,
    *,
    column_name: str,
    start_port: int,
    end_port: int,
    exclude_user_id: int | None = None,
) -> int:
    start = normalize_relay_port(start_port, start_port)
    end = normalize_relay_port(end_port, end_port)
    if end < start:
        raise RuntimeError("VPN relay port range is invalid")
    used_sql = f"SELECT {column_name} FROM users WHERE {column_name} IS NOT NULL"
    params: list[object] = []
    if exclude_user_id is not None:
        used_sql += " AND id <> ?"
        params.append(int(exclude_user_id))
    rows = db.execute(used_sql, params).fetchall()
    used = {int(row[column_name]) for row in rows if row[column_name] is not None}
    for port in range(start, end + 1):
        if port not in used:
            return port
    raise RuntimeError(f"No free relay ports available for {column_name}")


def ensure_user_ingress_ports(
    db: DatabaseConnection,
    user: DatabaseRow,
) -> tuple[int, int]:
    kcptun_port = row_get(user, "kcptun_ingress_port")
    openvpn_port = row_get(user, "openvpn_ingress_port")
    changed = False
    if kcptun_port is None or not str(kcptun_port).strip():
        kcptun_port = allocate_user_ingress_port(
            db,
            column_name="kcptun_ingress_port",
            start_port=KCPTUN_RELAY_PORT_START,
            end_port=KCPTUN_RELAY_PORT_END,
            exclude_user_id=int(user["id"]),
        )
        changed = True
    else:
        kcptun_port = int(kcptun_port)
    if openvpn_port is None or not str(openvpn_port).strip():
        openvpn_port = allocate_user_ingress_port(
            db,
            column_name="openvpn_ingress_port",
            start_port=OPENVPN_RELAY_PORT_START,
            end_port=OPENVPN_RELAY_PORT_END,
            exclude_user_id=int(user["id"]),
        )
        changed = True
    else:
        openvpn_port = int(openvpn_port)
    if changed:
        cursor = db.execute(
            """
            UPDATE users
            SET kcptun_ingress_port = ?,
                openvpn_ingress_port = ?
            WHERE id = ?
            """,
            (kcptun_port, openvpn_port, int(user["id"])),
        )
    return kcptun_port, openvpn_port


def ensure_user_transport_ports(db: DatabaseConnection, user: DatabaseRow) -> DatabaseRow:
    role = (row_get(user, "role", "") or "").strip().lower()
    if role not in {"user", "admin"}:
        return user
    kcptun_port_before = row_get(user, "kcptun_ingress_port")
    ss_port_before = row_get(user, "openvpn_ingress_port")
    kcptun_port_after, ss_port_after = ensure_user_ingress_ports(db, user)
    try:
        kcptun_before = int(kcptun_port_before) if kcptun_port_before is not None else -1
    except Exception:
        kcptun_before = -1
    try:
        ss_before = int(ss_port_before) if ss_port_before is not None else -1
    except Exception:
        ss_before = -1
    changed = (kcptun_before != int(kcptun_port_after)) or (ss_before != int(ss_port_after))
    if changed:
        db.commit()
        refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
        if refreshed is not None:
            return refreshed
    return user


def get_user_shadowsocks_server_port(user: DatabaseRow) -> int:
    raw = row_get(user, "openvpn_ingress_port")
    if raw is None or not str(raw).strip():
        return SHADOWSOCKS_SERVER_PORT
    try:
        port = int(raw)
    except Exception:
        return SHADOWSOCKS_SERVER_PORT
    if port <= 0 or port > 65535:
        return SHADOWSOCKS_SERVER_PORT
    return port


def get_user_kcptun_server_port(user: DatabaseRow) -> int:
    raw = row_get(user, "kcptun_ingress_port")
    if raw is None or not str(raw).strip():
        return KCPTUN_SERVER_PORT
    try:
        port = int(raw)
    except Exception:
        return KCPTUN_SERVER_PORT
    if port <= 0 or port > 65535:
        return KCPTUN_SERVER_PORT
    return port


def derive_shadowsocks_password_for_port(port: int) -> str:
    normalized_port = normalize_server_port(port, SHADOWSOCKS_SERVER_PORT)
    if normalized_port == SHADOWSOCKS_SERVER_PORT:
        return SHADOWSOCKS_PASSWORD
    seed = f"{SHADOWSOCKS_PASSWORD}:{normalized_port}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:32]


def get_openvpn_relay_endpoint(user: DatabaseRow | None) -> tuple[str, int] | None:
    if not VPN_RELAY_ENABLED or not user or row_get(user, "role") != "user":
        return None
    host = get_relay_public_host()
    if not host:
        return None
    port = row_get(user, "openvpn_ingress_port")
    if port is None or not str(port).strip():
        return None
    return host, int(port)


def ensure_shared_vpn_server_materials() -> dict[str, str]:
    # Legacy helper kept for backward compatibility.
    return {}


def load_system_settings(db: DatabaseConnection) -> dict[str, int | bool | str]:
    default_site_title = "新世界发展科技有限公司边缘节点网络管理系统"
    legacy_site_title = "新世界发展科技有限公司边际网络管理系统"
    registration_open_raw = get_app_setting(db, SETTING_REGISTRATION_OPEN, "1")
    order_expire_hours_raw = get_app_setting(db, SETTING_ORDER_EXPIRE_HOURS, "24")
    gift_duration_months_raw = get_app_setting(db, SETTING_GIFT_DURATION_MONTHS, "0")
    gift_traffic_gb_raw = get_app_setting(db, SETTING_GIFT_TRAFFIC_GB, "0")
    telegram_contact = get_app_setting(db, SETTING_TELEGRAM_CONTACT, "")
    site_title = get_app_setting(
        db,
        SETTING_SITE_TITLE,
        default_site_title,
    )
    if (site_title or "").strip() == legacy_site_title:
        site_title = default_site_title
        upsert_app_setting(db, SETTING_SITE_TITLE, default_site_title)
    order_expire_hours = parse_int_setting(order_expire_hours_raw, 24, min_value=1)
    return {
        "registration_open": parse_bool_setting(registration_open_raw, True),
        "order_expire_hours": order_expire_hours,
        "gift_duration_months": parse_int_setting(gift_duration_months_raw, 0, min_value=0),
        "gift_traffic_gb": parse_int_setting(gift_traffic_gb_raw, 0, min_value=0),
        "telegram_contact": (telegram_contact or "").strip(),
        "site_title": (site_title or "").strip() or default_site_title,
        "vpn_open": False,
        "openvpn_open": True,
    }


def load_system_upgrade_state(db: DatabaseConnection) -> dict[str, str]:
    return load_system_upgrade_state_impl(
        db,
        get_setting=get_app_setting,
        status_key=SETTING_SYSTEM_UPGRADE_STATUS,
        summary_key=SETTING_SYSTEM_UPGRADE_SUMMARY,
        started_at_key=SETTING_SYSTEM_UPGRADE_STARTED_AT,
        finished_at_key=SETTING_SYSTEM_UPGRADE_FINISHED_AT,
        current_version=get_current_app_version(BASE_DIR),
    )


def load_system_upgrade_state_with_timeout_unlock(
    db: DatabaseConnection,
) -> dict[str, str]:
    return load_system_upgrade_state_with_timeout_unlock_impl(
        db,
        base_dir=BASE_DIR,
        get_setting=get_app_setting,
        get_current_app_version=get_current_app_version,
        parse_iso=parse_iso,
        utcnow=utcnow,
        utcnow_iso=utcnow_iso,
        append_log=append_system_upgrade_log,
        open_direct_db_connection=open_direct_db_connection,
        running_timeout_seconds=SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS,
        status_key=SETTING_SYSTEM_UPGRADE_STATUS,
        summary_key=SETTING_SYSTEM_UPGRADE_SUMMARY,
        started_at_key=SETTING_SYSTEM_UPGRADE_STARTED_AT,
        finished_at_key=SETTING_SYSTEM_UPGRADE_FINISHED_AT,
    )


def save_system_upgrade_state(
    *,
    status: str,
    summary: str,
    started_at: str = "",
    finished_at: str = "",
) -> None:
    save_system_upgrade_state_impl(
        status=status,
        summary=summary,
        started_at=started_at,
        finished_at=finished_at,
        open_direct_db_connection=open_direct_db_connection,
        utcnow_iso=utcnow_iso,
        status_key=SETTING_SYSTEM_UPGRADE_STATUS,
        summary_key=SETTING_SYSTEM_UPGRADE_SUMMARY,
        started_at_key=SETTING_SYSTEM_UPGRADE_STARTED_AT,
        finished_at_key=SETTING_SYSTEM_UPGRADE_FINISHED_AT,
    )


def detect_origin_default_branch() -> str:
    code, output = run_local_command_with_output(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        cwd=BASE_DIR,
    )
    if code == 0 and output:
        ref = output.strip().split("/")[-1]
        if ref:
            return ref
    return "main"


def resolve_host_web_upgrade_project_dir() -> str:
    raw = (HOST_WEB_UPGRADE_PROJECT_DIR or "").strip()
    if not raw:
        return "/srv/vpn-platform-v1"
    normalized = Path(raw).as_posix().strip()
    if not normalized:
        return "/srv/vpn-platform-v1"
    if normalized == "/":
        return normalized
    return normalized.rstrip("/")


def build_host_web_upgrade_script(current_version: str) -> str:
    branch = shlex.quote(HOST_WEB_UPGRADE_BRANCH or "main")
    project_dir = shlex.quote(resolve_host_web_upgrade_project_dir())
    log_file = shlex.quote(str(SYSTEM_UPGRADE_LOG_FILE))
    quoted_current_version = shlex.quote((current_version or "").strip() or "0")
    quoted_db_backend = shlex.quote(DB_BACKEND)
    quoted_postgres_dsn = shlex.quote(POSTGRES_DSN)
    web_service = shlex.quote(HOST_WEB_UPGRADE_WEB_SERVICE)
    return textwrap.dedent(
        f"""
        #!/usr/bin/env bash
        set -eu
        LOG_FILE={log_file}
        DB_BACKEND={quoted_db_backend}
        POSTGRES_DSN={quoted_postgres_dsn}
        STARTED_AT=\"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
        TARGET_BRANCH={branch}
        CURRENT_VERSION={quoted_current_version}
        PROJECT_DIR={project_dir}
        WEB_SERVICE={web_service}

        log() {{
          mkdir -p \"$(dirname \"$LOG_FILE\")\"
          printf '[%s] %s\\n' \"$(date -u +'%Y-%m-%d %H:%M:%S UTC')\" \"$1\" | tee -a \"$LOG_FILE\"
        }}

        write_state() {{
          if ! command -v python3 >/dev/null 2>&1; then
            return 0
          fi
          python3 - \"$1\" \"$2\" \"$3\" \"$4\" <<'PY'
import os
import sys
from datetime import datetime, timezone

try:
    import psycopg2
except Exception:
    psycopg2 = None

status, summary, started_at, finished_at = sys.argv[1:5]
db_backend = (os.environ.get("DB_BACKEND") or "postgres").strip().lower()
conn = None
try:
    if db_backend != "postgres" or not psycopg2 or not os.environ.get("POSTGRES_DSN"):
        sys.exit(0)
    conn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    upsert_sql = '''
        INSERT INTO app_settings (setting_key, setting_value, updated_at)
        VALUES (%s, %s, %s)
        ON CONFLICT(setting_key) DO UPDATE SET
            setting_value = excluded.setting_value,
            updated_at = excluded.updated_at
    '''
    for key, value in (
        ("system_upgrade_status", status),
        ("system_upgrade_summary", summary[:1000]),
        ("system_upgrade_started_at", started_at),
        ("system_upgrade_finished_at", finished_at),
    ):
        conn.execute(upsert_sql, (key, value, now_iso))
    conn.commit()
except Exception:
    pass
finally:
    if conn is not None:
        conn.close()
PY
        }}

        retry_cmd() {{
          retries=\"$1\"
          delay=\"$2\"
          shift 2
          attempt=1
          while true; do
            \"$@\" && return 0
            code=$?
            if [ \"$attempt\" -ge \"$retries\" ]; then
              return \"$code\"
            fi
            log \"命令失败 (exit=$code), ${{delay}}s 后重试 $attempt/$retries: $*\"
            attempt=$((attempt + 1))
            sleep \"$delay\"
          done
        }}

        success=0
        cleanup() {{
          code=$?
          if [ \"$success\" -ne 1 ]; then
            log \"系统升级失败，退出码: $code\"
            write_state \"failed\" \"系统升级失败，请查看 system-upgrade.log\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
          fi
          exit $code
        }}
        trap cleanup EXIT

        : > \"$LOG_FILE\"
        log \"宿主机升级任务已启动（本地 systemd 模式）\"
        write_state \"running\" \"系统升级进行中\" \"$STARTED_AT\" \"\"
        if [ \"$PROJECT_DIR\" = \"/workspace\" ]; then
          log \"Refusing upgrade: PROJECT_DIR cannot be /workspace.\"
          write_state \"failed\" \"系统升级失败：项目目录配置错误(/workspace)。\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
          exit 1
        fi
        if [ ! -d \"$PROJECT_DIR\" ]; then
          log \"Refusing upgrade: PROJECT_DIR does not exist: $PROJECT_DIR\"
          write_state \"failed\" \"系统升级失败：项目目录不存在。\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
          exit 1
        fi
        if [ ! -f \"$PROJECT_DIR/v1/scripts/install.sh\" ]; then
          log \"Refusing upgrade: install.sh not found under $PROJECT_DIR/v1/scripts/install.sh\"
          write_state \"failed\" \"系统升级失败：缺少安装脚本 v1/scripts/install.sh。\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
          exit 1
        fi
        cd \"$PROJECT_DIR\"
        log \"git fetch origin\"
        git fetch origin
        REMOTE_VERSION=\"$(git show \"origin/$TARGET_BRANCH:VERSION\" 2>/dev/null | head -n 1 | tr -d '\\r' || true)\"
        if [ -n \"$REMOTE_VERSION\" ]; then
          log \"版本检查: 当前=$CURRENT_VERSION, 远端=$REMOTE_VERSION\"
          if python3 - \"$CURRENT_VERSION\" \"$REMOTE_VERSION\" <<'PY'
import re
import sys

current_raw = sys.argv[1]
remote_raw = sys.argv[2]

def parse_parts(raw: str) -> list[int]:
    nums = [int(part) for part in re.findall(r"[0-9]+", (raw or "").strip())]
    return nums or [0]

def compare_parts(a: list[int], b: list[int]) -> int:
    size = max(len(a), len(b))
    for idx in range(size):
        av = a[idx] if idx < len(a) else 0
        bv = b[idx] if idx < len(b) else 0
        if av != bv:
            return 1 if av > bv else -1
    return 0

current_parts = parse_parts(current_raw)
remote_parts = parse_parts(remote_raw)
sys.exit(0 if compare_parts(remote_parts, current_parts) > 0 else 1)
PY
          then
            log \"检测到更高版本，继续执行升级\"
          else
            log \"远端版本未高于当前版本，跳过升级\"
            write_state \"success\" \"远端版本($REMOTE_VERSION) 未高于当前版本($CURRENT_VERSION)，已跳过升级。\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
            success=1
            exit 0
          fi
        else
          log \"未读取到远端 VERSION，继续执行升级\"
        fi
        log \"git checkout $TARGET_BRANCH\"
        git checkout \"$TARGET_BRANCH\"
        log \"git pull --ff-only origin $TARGET_BRANCH\"
        git pull --ff-only origin \"$TARGET_BRANCH\"
        log \"bash v1/scripts/install.sh (upgrade mode)\"
        INSTALL_TMP_LOG=\"$(mktemp)\"
        if ! (
          SKIP_APT_ON_UPGRADE=1 \
          APP_DIR=\"$PROJECT_DIR\" \
          BRANCH=\"$TARGET_BRANCH\" \
          INSTALL_LOCAL_VPN_SERVER=1 \
          UPGRADE_INCLUDE_VPN_SERVER=0 \
          DISABLE_SYSTEMD_RESOLVED=1 \
          bash \"$PROJECT_DIR/v1/scripts/install.sh\"
        ) >\"$INSTALL_TMP_LOG\" 2>&1; then
          while IFS= read -r _line; do
            log \"[install] $_line\"
          done < \"$INSTALL_TMP_LOG\"
          rm -f \"$INSTALL_TMP_LOG\"
          exit 1
        fi
        while IFS= read -r _line; do
          log \"[install] $_line\"
        done < \"$INSTALL_TMP_LOG\"
        rm -f \"$INSTALL_TMP_LOG\"
        if command -v systemctl >/dev/null 2>&1; then
          log \"systemctl restart $WEB_SERVICE\"
          systemctl restart \"$WEB_SERVICE\" || true
        fi
        success=1
        log \"系统升级完成\"
        write_state \"success\" \"系统升级完成，请重新登录。\" \"$STARTED_AT\" \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"
        """
    ).strip()


def dispatch_host_web_upgrade() -> tuple[bool, str]:
    if not HOST_WEB_UPGRADE_PROJECT_DIR:
        return False, "未配置宿主机项目目录，无法升级。"
    project_dir = resolve_host_web_upgrade_project_dir()
    if not project_dir.startswith("/"):
        return False, "宿主机项目目录必须为绝对路径，无法升级。"
    if project_dir == "/workspace":
        return False, "宿主机项目目录不能为 /workspace，请改为真实部署目录后重试。"
    helper_script = build_host_web_upgrade_script(get_current_app_version(BASE_DIR))
    SYSTEM_UPGRADE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, script_path_raw = tempfile.mkstemp(
        prefix="host-upgrade-",
        suffix=".sh",
        dir=str(SYSTEM_UPGRADE_LOG_FILE.parent),
    )
    script_path = Path(script_path_raw)
    with os.fdopen(fd, "w", encoding="utf-8") as file_handle:
        file_handle.write(helper_script + "\n")
    script_path.chmod(0o700)

    has_systemd_run = (
        run_local_command_with_output(
            ["bash", "-lc", "command -v systemd-run >/dev/null 2>&1"],
            cwd=BASE_DIR,
        )[0]
        == 0
    )
    if has_systemd_run:
        unit_name = f"vpn-platform-upgrade-{int(time.time())}"
        args = [
            "systemd-run",
            "--unit",
            unit_name,
            "--collect",
            "--quiet",
            "/bin/bash",
            str(script_path),
        ]
        code, output = run_local_command_with_output(args, cwd=BASE_DIR)
        if code != 0:
            return False, output or "宿主机升级任务派发失败。"
        return True, f"宿主机升级任务已启动（systemd unit: {unit_name}）。"

    try:
        process = subprocess.Popen(
            ["/bin/bash", str(script_path)],
            cwd=project_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        return False, f"宿主机升级任务派发失败：{exc}"
    return True, f"宿主机升级任务已启动（pid: {process.pid}）。"

def schedule_process_restart(delay_seconds: float = 1.5) -> None:
    if not AUTO_RESTART_AFTER_SELF_UPGRADE:
        return

    def _restart() -> None:
        time.sleep(delay_seconds)
        os._exit(0)

    threading.Thread(target=_restart, daemon=True, name="self-upgrade-restart").start()


def run_system_upgrade_task() -> None:
    started_at = utcnow_iso()
    save_system_upgrade_state(
        status="running",
        summary="系统升级进行中",
        started_at=started_at,
        finished_at="",
    )
    SYSTEM_UPGRADE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    SYSTEM_UPGRADE_LOG_FILE.write_text("", encoding="utf-8")
    append_system_upgrade_log(f"当前版本: {get_current_app_version(BASE_DIR)}")

    if not (BASE_DIR / ".git").exists():
        message = "当前运行目录缺少 .git，无法自动升级。"
        append_system_upgrade_log(message)
        save_system_upgrade_state(
            status="failed",
            summary=message,
            started_at=started_at,
            finished_at=utcnow_iso(),
        )
        return

    default_branch = detect_origin_default_branch()
    commands = [
        ["git", "status", "--porcelain"],
        ["git", "fetch", "origin"],
        ["git", "checkout", default_branch],
        ["git", "pull", "--ff-only", "origin", default_branch],
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
    ]
    for args in commands:
        append_system_upgrade_log("$ " + " ".join(args))
        code, output = run_local_command_with_output(args, cwd=BASE_DIR)
        if output:
            append_system_upgrade_log(output)
        if args[:3] == ["git", "status", "--porcelain"]:
            if output.strip():
                message = "当前工作区存在未提交修改，已停止自动升级。"
                append_system_upgrade_log(message)
                save_system_upgrade_state(
                    status="failed",
                    summary=message,
                    started_at=started_at,
                    finished_at=utcnow_iso(),
                )
                return
            continue
        if code != 0:
            message = f"命令执行失败：{' '.join(args)}"
            append_system_upgrade_log(message)
            save_system_upgrade_state(
                status="failed",
                summary=message,
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
            return

    version_after = get_current_app_version(BASE_DIR)
    summary = f"系统升级完成，当前版本 {version_after}。"
    if AUTO_RESTART_AFTER_SELF_UPGRADE:
        summary += " Web 进程将自动重启。"
    else:
        summary += " 请手动重启 Web 服务使代码完全生效。"
    append_system_upgrade_log(summary)
    save_system_upgrade_state(
        status="success",
        summary=summary,
        started_at=started_at,
        finished_at=utcnow_iso(),
    )
    schedule_process_restart()


def launch_system_upgrade_task() -> None:
    thread = threading.Thread(
        target=run_system_upgrade_task,
        daemon=True,
        name="system-upgrade",
    )
    thread.start()


def is_registration_open(db: DatabaseConnection | None = None) -> bool:
    return False


def get_order_expire_hours(db: DatabaseConnection | None = None) -> int:
    use_db = db or get_db()
    return int(load_system_settings(use_db)["order_expire_hours"])


def get_gift_settings(db: DatabaseConnection | None = None) -> tuple[int, int]:
    use_db = db or get_db()
    settings = load_system_settings(use_db)
    return (
        int(settings["gift_duration_months"]),
        int(settings["gift_traffic_gb"]),
    )


def is_vpn_open(db: DatabaseConnection | None = None) -> bool:
    use_db = db or get_db()
    return bool(False and bool(load_system_settings(use_db)["vpn_open"]))


def is_openvpn_open(db: DatabaseConnection | None = None) -> bool:
    use_db = db or get_db()
    return bool(OPENVPN_ENABLED and bool(load_system_settings(use_db)["openvpn_open"]))


def ensure_default_onboarding_settings(db: DatabaseConnection) -> None:
    existing = load_named_settings(db, tuple(ONBOARDING_SETTINGS_DEFAULTS.keys()))
    for key, default_value in ONBOARDING_SETTINGS_DEFAULTS.items():
        if key not in existing or existing.get(key, "") == "":
            if key == ONBOARDING_SETTING_SETUP_COMPLETED:
                # keep explicit boolean semantics
                upsert_app_setting(db, key, existing.get(key, default_value) or default_value)
            else:
                upsert_app_setting(db, key, existing.get(key, default_value) or default_value)


def load_onboarding_settings(db: DatabaseConnection) -> dict[str, str | bool]:
    values = load_named_settings(db, tuple(ONBOARDING_SETTINGS_DEFAULTS.keys()))
    merged = {**ONBOARDING_SETTINGS_DEFAULTS, **values}
    return {
        "portal_domain": merged[ONBOARDING_SETTING_PORTAL_DOMAIN],
        "cloudflare_account": merged[ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT],
        "cloudflare_password": merged[ONBOARDING_SETTING_CLOUDFLARE_PASSWORD],
        "setup_completed": parse_bool_setting(merged[ONBOARDING_SETTING_SETUP_COMPLETED], False),
        "setup_completed_at": merged[ONBOARDING_SETTING_SETUP_COMPLETED_AT],
        "last_server_id": merged[ONBOARDING_SETTING_LAST_SERVER_ID],
    }


def load_onboarding_server_draft(db: DatabaseConnection) -> dict[str, str | int]:
    values = load_named_settings(
        db,
        (
            ONBOARDING_SETTING_DRAFT_SERVER_NAME,
            ONBOARDING_SETTING_DRAFT_SERVER_HOST,
            ONBOARDING_SETTING_DRAFT_SERVER_PORT,
            ONBOARDING_SETTING_DRAFT_SERVER_USERNAME,
            ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD,
            ONBOARDING_SETTING_DRAFT_SERVER_PRIVATE_KEY,
        ),
    )
    merged = {**ONBOARDING_SETTINGS_DEFAULTS, **values}
    return {
        "server_name": (merged[ONBOARDING_SETTING_DRAFT_SERVER_NAME] or "").strip(),
        "server_host": normalize_remote_host(merged[ONBOARDING_SETTING_DRAFT_SERVER_HOST]),
        "server_port": normalize_server_port(
            merged[ONBOARDING_SETTING_DRAFT_SERVER_PORT], 22
        ),
        "server_username": (
            merged[ONBOARDING_SETTING_DRAFT_SERVER_USERNAME] or "root"
        ).strip()
        or "root",
        "server_password": merged[ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD] or "",
        "server_private_key": merged[ONBOARDING_SETTING_DRAFT_SERVER_PRIVATE_KEY] or "",
    }


def save_onboarding_server_draft(
    db: DatabaseConnection,
    *,
    server_name: str,
    server_host: str,
    server_port: int,
    server_username: str,
    server_password: str,
    server_private_key: str = "",
) -> None:
    upsert_app_setting(db, ONBOARDING_SETTING_DRAFT_SERVER_NAME, (server_name or "").strip())
    upsert_app_setting(
        db, ONBOARDING_SETTING_DRAFT_SERVER_HOST, normalize_remote_host(server_host)
    )
    upsert_app_setting(
        db,
        ONBOARDING_SETTING_DRAFT_SERVER_PORT,
        str(normalize_server_port(server_port, 22)),
    )
    upsert_app_setting(
        db,
        ONBOARDING_SETTING_DRAFT_SERVER_USERNAME,
        ((server_username or "").strip() or "root"),
    )
    upsert_app_setting(
        db, ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD, server_password or ""
    )
    upsert_app_setting(
        db,
        ONBOARDING_SETTING_DRAFT_SERVER_PRIVATE_KEY,
        (server_private_key or "").strip(),
    )


def get_admin_onboarding_step_status(db: DatabaseConnection) -> tuple[dict[int, bool], int]:
    settings = load_onboarding_settings(db)
    payment_settings = load_payment_settings(db)
    plan_count = db.execute("SELECT COUNT(*) AS cnt FROM subscription_plans").fetchone()["cnt"]
    cloudflare_active_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM cloudflare_accounts WHERE is_active = 1"
    ).fetchone()["cnt"]
    legacy_cloudflare_ready = bool((settings["cloudflare_account"] or "").strip()) and bool(
        (settings["cloudflare_password"] or "").strip()
    )

    step_status = {
        1: int(plan_count or 0) > 0,
        2: bool((payment_settings["usdt_receive_address"] or "").strip())
        and bool((settings["portal_domain"] or "").strip()),
        3: int(cloudflare_active_count or 0) > 0 or legacy_cloudflare_ready,
        4: bool(settings["setup_completed"]),
    }

    default_step = 4
    for step in (1, 2, 3, 4):
        if not step_status[step]:
            default_step = step
            break
    return step_status, default_step


def next_admin_onboarding_step(db: DatabaseConnection, fallback: int = 4) -> int:
    _, next_step = get_admin_onboarding_step_status(db)
    if next_step < 1 or next_step > 4:
        return fallback
    return next_step


def is_admin_onboarding_completed(db: DatabaseConnection) -> bool:
    raw_value = get_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED, "0")
    return parse_bool_setting(raw_value, False)


def looks_like_email(raw_email: str | None) -> bool:
    value = (raw_email or "").strip()
    return "@" in value and "." in value.rsplit("@", 1)[-1]


def looks_like_internal_username(raw_username: str | None) -> bool:
    value = (raw_username or "").strip()
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value))


def domain_belongs_to_zone(domain_name: str, zone_name: str) -> bool:
    domain = normalize_fqdn(domain_name)
    zone = normalize_fqdn(zone_name)
    if not domain or not zone:
        return False
    return domain == zone or domain.endswith(f".{zone}")


def guess_zone_name_from_domain(domain_name: str) -> str:
    normalized = normalize_fqdn(domain_name)
    if not normalized:
        return ""
    parts = normalized.split(".")
    if len(parts) <= 2:
        return normalized
    return ".".join(parts[-2:])


def get_portal_domain_setting() -> str:
    try:
        db = get_db()
    except Exception:
        return ""
    return normalize_domain_host(
        get_app_setting(db, ONBOARDING_SETTING_PORTAL_DOMAIN, "")
    )


def ensure_default_payment_settings(db: DatabaseConnection) -> None:
    defaults = default_payment_settings()
    rows = db.execute(
        """
        SELECT setting_key, setting_value
        FROM app_settings
        WHERE setting_key IN ({})
        """.format(",".join("?" for _ in PAYMENT_SETTING_KEYS)),
        PAYMENT_SETTING_KEYS,
    ).fetchall()
    existing = {row["setting_key"] for row in rows}
    for key in PAYMENT_SETTING_KEYS:
        if key not in existing:
            upsert_app_setting(db, key, defaults.get(key, ""))


def load_legacy_payment_settings(db: DatabaseConnection) -> dict:
    defaults = default_payment_settings()
    rows = db.execute(
        """
        SELECT setting_key, setting_value
        FROM app_settings
        WHERE setting_key IN ({})
        """.format(",".join("?" for _ in PAYMENT_SETTING_KEYS)),
        PAYMENT_SETTING_KEYS,
    ).fetchall()
    raw_map = {row["setting_key"]: (row["setting_value"] or "").strip() for row in rows}

    network = (raw_map.get("usdt_default_network") or defaults["usdt_default_network"]).upper()
    if network not in USDT_NETWORK_OPTIONS:
        network = defaults["usdt_default_network"]

    address = (raw_map.get("usdt_receive_address") or defaults["usdt_receive_address"]).strip()

    return {
        "usdt_receive_address": address,
        "usdt_default_network": network,
    }


def normalize_payment_method(raw: str | None) -> str:
    method = (raw or "").strip().lower()
    if method in PAYMENT_METHOD_CHOICES:
        return method
    return PAYMENT_METHOD_USDT


def payment_method_label(method_code: str | None) -> str:
    normalized = normalize_payment_method(method_code)
    if normalized == PAYMENT_METHOD_USDT:
        return "USDT"
    return normalized.upper()


def load_payment_methods(db: DatabaseConnection, *, active_only: bool = False) -> list[dict]:
    sql = """
        SELECT
            id,
            method_code,
            method_name,
            network,
            receive_address,
            is_active,
            sort_order,
            created_at,
            updated_at
        FROM payment_methods
    """
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY sort_order ASC, id ASC"
    rows = db.execute(sql).fetchall()

    methods: list[dict] = []
    for row in rows:
        method_code = normalize_payment_method(row["method_code"])
        network = (row["network"] or USDT_DEFAULT_NETWORK).strip().upper()
        if network not in USDT_NETWORK_OPTIONS:
            network = USDT_DEFAULT_NETWORK
        method_name = (row["method_name"] or "").strip()
        if not method_name:
            method_name = f"{payment_method_label(method_code)} {network}"
        methods.append(
            {
                "id": row["id"],
                "method_code": method_code,
                "method_label": payment_method_label(method_code),
                "method_name": method_name,
                "network": network,
                "receive_address": (row["receive_address"] or "").strip(),
                "is_active": 1 if int(row["is_active"] or 0) == 1 else 0,
                "sort_order": to_non_negative_int(row["sort_order"]),
                "display_name": f"{method_name} ({network})",
            }
        )
    return methods


def resolve_default_payment_method(db: DatabaseConnection) -> dict | None:
    active_methods = load_payment_methods(db, active_only=True)
    if active_methods:
        return active_methods[0]
    total_count = db.execute("SELECT COUNT(*) AS cnt FROM payment_methods").fetchone()["cnt"]
    if total_count > 0:
        return None
    return None


def sync_legacy_payment_settings_with_default_method(db: DatabaseConnection) -> None:
    default_method = resolve_default_payment_method(db)
    if not default_method:
        return
    upsert_app_setting(db, "usdt_receive_address", default_method["receive_address"])
    upsert_app_setting(db, "usdt_default_network", default_method["network"])


def ensure_default_payment_methods(db: DatabaseConnection) -> None:
    count = db.execute("SELECT COUNT(*) AS cnt FROM payment_methods").fetchone()["cnt"]
    if count > 0:
        return

    legacy = load_legacy_payment_settings(db)
    now_iso = utcnow_iso()
    method_name = f"USDT {legacy['usdt_default_network']}"
    db.execute(
        """
        INSERT INTO payment_methods (
            method_code, method_name, network, receive_address,
            is_active, sort_order, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, 1, 10, ?, ?)
        RETURNING id
        """,
        (
            PAYMENT_METHOD_USDT,
            method_name,
            legacy["usdt_default_network"],
            legacy["usdt_receive_address"],
            now_iso,
            now_iso,
        ),
    )


def load_payment_settings(db: DatabaseConnection) -> dict:
    legacy = load_legacy_payment_settings(db)
    default_method = resolve_default_payment_method(db)

    if default_method:
        method_code = default_method["method_code"]
        method_name = default_method["method_name"]
        network = default_method["network"]
        address = default_method["receive_address"]
    else:
        method_code = PAYMENT_METHOD_USDT
        method_name = payment_method_label(method_code)
        network = legacy["usdt_default_network"]
        address = legacy["usdt_receive_address"]

    return {
        "payment_method": method_code,
        "payment_method_name": method_name,
        "payment_display_name": f"{payment_method_label(method_code)} ({network})",
        "usdt_receive_address": address,
        "usdt_default_network": network,
    }


def ensure_default_subscription_plans(db: DatabaseConnection) -> None:
    count = db.execute("SELECT COUNT(*) AS cnt FROM subscription_plans").fetchone()["cnt"]
    if count > 0:
        return

    default_rows = [
        (
            "月付 1个月",
            PLAN_MODE_DURATION,
            1,
            1,
            PLAN_DURATION_UNIT_MONTH,
            None,
            format_usdt(parse_usdt_amount(USDT_PRICE_1M, "10")),
            10,
        ),
        (
            "季付 3个月",
            PLAN_MODE_DURATION,
            3,
            3,
            PLAN_DURATION_UNIT_MONTH,
            None,
            format_usdt(parse_usdt_amount(USDT_PRICE_3M, "27")),
            20,
        ),
        (
            "半年 6个月",
            PLAN_MODE_DURATION,
            6,
            6,
            PLAN_DURATION_UNIT_MONTH,
            None,
            format_usdt(parse_usdt_amount(USDT_PRICE_6M, "50")),
            30,
        ),
        (
            "年付 12个月",
            PLAN_MODE_DURATION,
            12,
            12,
            PLAN_DURATION_UNIT_MONTH,
            None,
            format_usdt(parse_usdt_amount(USDT_PRICE_12M, "90")),
            40,
        ),
        (
            "流量包 100GB",
            PLAN_MODE_TRAFFIC,
            None,
            None,
            None,
            100,
            format_usdt(parse_usdt_amount(USDT_PRICE_1M, "10")),
            50,
        ),
    ]
    now_iso = utcnow_iso()
    for name, mode, duration, duration_value, duration_unit, traffic, price, sort_order in default_rows:
        db.execute(
            """
            INSERT INTO subscription_plans (
                plan_name, billing_mode, duration_months, duration_value, duration_unit, traffic_gb,
                price_usdt, is_active, sort_order, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                name,
                mode,
                duration,
                duration_value,
                duration_unit,
                traffic,
                price,
                sort_order,
                now_iso,
                now_iso,
            ),
        )


def load_subscription_plans(db: DatabaseConnection, *, active_only: bool = False) -> list[dict]:
    sql = """
        SELECT
            id,
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit,
            traffic_gb,
            price_usdt,
            is_active,
            sort_order,
            created_at,
            updated_at
        FROM subscription_plans
    """
    params: list[object] = []
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY sort_order ASC, id ASC"
    rows = db.execute(sql, params).fetchall()

    plans: list[dict] = []
    for row in rows:
        mode = normalize_plan_mode(row["billing_mode"])
        duration_months = to_non_negative_int(row["duration_months"])
        duration_value, duration_unit = resolve_duration_value_and_unit(
            duration_months=duration_months,
            duration_value_raw=row_get(row, "duration_value", 0),
            duration_unit_raw=row_get(row, "duration_unit", PLAN_DURATION_UNIT_MONTH),
        )
        traffic_gb = to_non_negative_int(row["traffic_gb"])
        if mode == PLAN_MODE_TRAFFIC:
            duration_months = 0
            duration_value = 0
            duration_unit = PLAN_DURATION_UNIT_MONTH
        else:
            traffic_gb = 0

        plan = {
            "id": row["id"],
            "plan_name": (row["plan_name"] or "").strip(),
            "billing_mode": mode,
            "mode_label": plan_mode_label(mode),
            "duration_months": duration_months,
            "duration_value": duration_value,
            "duration_unit": duration_unit,
            "duration_unit_label": plan_duration_unit_label(duration_unit),
            "traffic_gb": traffic_gb,
            "value_label": format_plan_value(
                mode,
                duration_months,
                traffic_gb,
                duration_value=duration_value,
                duration_unit=duration_unit,
            ),
            "price_usdt": format_usdt(row["price_usdt"]),
            "is_active": 1 if int(row["is_active"] or 0) == 1 else 0,
            "sort_order": to_non_negative_int(row["sort_order"]),
            "display_name": format_plan_display_name(
                row["plan_name"],
                mode,
                duration_months,
                traffic_gb,
                duration_value=duration_value,
                duration_unit=duration_unit,
            ),
        }
        plans.append(plan)
    return plans


def refresh_missing_server_regions(db: DatabaseConnection) -> None:
    refresh_missing_server_regions_impl(
        db,
        row_get=row_get,
        utcnow_iso=utcnow_iso,
    )


def load_admin_servers(db: DatabaseConnection) -> list[dict]:
    return load_admin_servers_impl(
        db,
        row_get=row_get,
        get_server_ipv6_enabled=get_server_ipv6_enabled,
        default_kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
        default_openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
        default_dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
    )


def get_server_by_id(db: DatabaseConnection, server_id: int | None) -> DatabaseRow | None:
    if not server_id:
        return None
    return db.execute(
        """
        SELECT *
        FROM vpn_servers
        WHERE id = ?
        LIMIT 1
        """,
        (int(server_id),),
    ).fetchone()


def is_runtime_server_ready(server_row: DatabaseRow | None) -> bool:
    if not server_row:
        return False
    status = (row_get(server_row, "status", "") or "").strip().lower()
    host = normalize_remote_host(row_get(server_row, "host", ""))
    token = (row_get(server_row, "vpn_api_token", "") or "").strip()
    return status == "online" and bool(host) and bool(token)


def get_persisted_runtime_server_for_account(
    db: DatabaseConnection,
    user: DatabaseRow | None,
) -> DatabaseRow | None:
    if not user:
        return None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role == "user":
        assigned_server_id = row_get(user, "assigned_server_id")
        if assigned_server_id is None or str(assigned_server_id).strip() == "":
            return None
        try:
            return get_server_by_id(db, int(assigned_server_id))
        except Exception:
            return None
    if role == "admin":
        return choose_runtime_server_for_admin(db, user)
    return None


def get_user_allowed_server_ids(db: DatabaseConnection, user: DatabaseRow | None) -> list[int]:
    if not user or (row_get(user, "role", "") or "").strip().lower() != "user":
        return []
    rows = db.execute(
        """
        SELECT server_id
        FROM user_server_permissions
        WHERE user_id = ?
        ORDER BY server_id ASC
        """,
        (int(user["id"]),),
    ).fetchall()
    result: list[int] = []
    for row in rows:
        try:
            result.append(int(row["server_id"]))
        except Exception:
            continue
    if not result:
        assigned_server_id = row_get(user, "assigned_server_id")
        if assigned_server_id is not None and str(assigned_server_id).strip():
            try:
                result.append(int(assigned_server_id))
            except Exception:
                pass
    return result


def load_user_allowed_runtime_servers(
    db: DatabaseConnection,
    user: DatabaseRow | None,
) -> list[DatabaseRow]:
    allowed_ids = get_user_allowed_server_ids(db, user)
    servers: list[DatabaseRow] = []
    seen: set[int] = set()
    for server_id in allowed_ids:
        if server_id in seen:
            continue
        seen.add(server_id)
        server = get_server_by_id(db, server_id)
        if not is_runtime_server_ready(server):
            continue
        if not normalize_domain_host(row_get(server, "domain", "")):
            continue
        servers.append(server)
    if not servers:
        fallback = get_persisted_runtime_server_for_account(db, user)
        if is_runtime_server_ready(fallback) and normalize_domain_host(row_get(fallback, "domain", "")):
            servers.append(fallback)
    return servers


def get_requested_allowed_server(
    db: DatabaseConnection,
    user: DatabaseRow,
) -> DatabaseRow | None:
    server_id_raw = (request.args.get("server_id", "") or "").strip()
    if server_id_raw:
        try:
            requested_id = int(server_id_raw)
        except Exception:
            return None
        if requested_id not in get_user_allowed_server_ids(db, user):
            return None
        return get_server_by_id(db, requested_id)
    return get_persisted_runtime_server_for_account(db, user)


def save_user_server_permissions(
    db: DatabaseConnection,
    user_id: int,
    server_ids: list[int],
) -> None:
    now_iso = utcnow_iso()
    clean_ids: list[int] = []
    for server_id in server_ids:
        try:
            sid = int(server_id)
        except Exception:
            continue
        if sid not in clean_ids:
            clean_ids.append(sid)
    db.execute("DELETE FROM user_server_permissions WHERE user_id = ?", (int(user_id),))
    for sid in clean_ids:
        db.execute(
            """
            INSERT INTO user_server_permissions (user_id, server_id, created_at)
            VALUES (?, ?, ?)
            """,
            (int(user_id), int(sid), now_iso),
        )
    assigned = db.execute(
        "SELECT assigned_server_id FROM users WHERE id = ? LIMIT 1",
        (int(user_id),),
    ).fetchone()
    assigned_id = row_get(assigned, "assigned_server_id") if assigned else None
    if assigned_id is not None and str(assigned_id).strip():
        try:
            if int(assigned_id) not in clean_ids:
                db.execute(
                    "UPDATE users SET assigned_server_id = NULL, preferred_server_id = NULL WHERE id = ?",
                    (int(user_id),),
                )
        except Exception:
            db.execute(
                "UPDATE users SET assigned_server_id = NULL, preferred_server_id = NULL WHERE id = ?",
                (int(user_id),),
            )


def load_user_selectable_servers(
    db: DatabaseConnection,
    user: DatabaseRow,
) -> list[dict]:
    return load_user_selectable_servers_impl(
        db,
        user,
        row_get=row_get,
        normalize_domain_host=normalize_domain_host,
    )


def get_server_kcptun_port(server_row: DatabaseRow | None) -> int:
    return _get_server_kcptun_port(server_row, default_port=KCPTUN_SERVER_PORT)


def get_server_shadowsocks_backend_port(server_row: DatabaseRow | None) -> int:
    return _get_server_shadowsocks_backend_port(
        server_row,
        default_port=SHADOWSOCKS_SERVER_PORT,
    )


def runtime_uses_kcptun(server_row: DatabaseRow | None) -> bool:
    return _runtime_uses_kcptun(server_row, global_kcptun_enabled=KCPTUN_ENABLED)


def pick_best_online_server(db: DatabaseConnection) -> DatabaseRow | None:
    return db.execute(
        """
        SELECT
            s.*,
            COUNT(u.id) AS active_user_count
        FROM vpn_servers s
        LEFT JOIN users u
          ON u.assigned_server_id = s.id
         AND u.role = 'user'
         AND u.vpn_enabled = 1
        WHERE s.status = 'online'
        GROUP BY s.id
        ORDER BY
          active_user_count ASC,
          COALESCE(s.last_allocated_at, '1970-01-01T00:00:00+00:00') ASC,
          s.id ASC
        LIMIT 1
        """
    ).fetchone()


def choose_runtime_server_for_user(
    db: DatabaseConnection,
    user: DatabaseRow,
    *,
    allow_reassign: bool = True,
) -> DatabaseRow | None:
    if not user or row_get(user, "role") != "user":
        return None

    candidate_ids: list[int] = []
    preferred_server_id = row_get(user, "preferred_server_id")
    if preferred_server_id is not None and str(preferred_server_id).strip():
        try:
            candidate_ids.append(int(preferred_server_id))
        except Exception:
            pass

    assigned_server_id = row_get(user, "assigned_server_id")
    if assigned_server_id is not None and str(assigned_server_id).strip():
        try:
            assigned_server_id_int = int(assigned_server_id)
            if assigned_server_id_int not in candidate_ids:
                candidate_ids.append(assigned_server_id_int)
        except Exception:
            assigned_server_id_int = 0
    else:
        assigned_server_id_int = 0

    for candidate_id in candidate_ids:
        candidate = get_server_by_id(db, candidate_id)
        if not is_runtime_server_ready(candidate):
            continue
        if assigned_server_id_int != int(candidate["id"]):
            now_iso = utcnow_iso()
            db.execute(
                """
                UPDATE users
                SET assigned_server_id = ?
                WHERE id = ? AND role = 'user'
                """,
                (int(candidate["id"]), int(user["id"])),
            )
            db.execute(
                """
                UPDATE vpn_servers
                SET last_allocated_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, now_iso, int(candidate["id"])),
            )
        return candidate

    if not allow_reassign:
        return None

    next_server = pick_best_online_server(db)
    if not next_server:
        return None

    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE users
        SET assigned_server_id = ?
        WHERE id = ? AND role = 'user'
        """,
        (int(next_server["id"]), int(user["id"])),
    )
    db.execute(
        """
        UPDATE vpn_servers
        SET last_allocated_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (now_iso, now_iso, int(next_server["id"])),
    )
    return db.execute(
        "SELECT * FROM vpn_servers WHERE id = ? LIMIT 1",
        (int(next_server["id"]),),
    ).fetchone()


def choose_runtime_server_for_admin(
    db: DatabaseConnection,
    admin_user: DatabaseRow | None = None,
) -> DatabaseRow | None:
    candidate_ids: list[int] = []

    assigned_server_id = row_get(admin_user, "assigned_server_id")
    if assigned_server_id is not None and str(assigned_server_id).strip():
        try:
            assigned_id = int(assigned_server_id)
            if assigned_id not in candidate_ids:
                candidate_ids.append(assigned_id)
        except Exception:
            pass

    preferred_server_id_raw = ""
    try:
        settings = load_onboarding_settings(db)
        preferred_server_id_raw = str(settings.get("last_server_id", "") or "").strip()
    except Exception:
        preferred_server_id_raw = ""
    if preferred_server_id_raw.isdigit():
        preferred_id = int(preferred_server_id_raw)
        if preferred_id not in candidate_ids:
            candidate_ids.append(preferred_id)

    for server_id in candidate_ids:
        row = get_server_by_id(db, server_id)
        if not row:
            continue
        status = (row_get(row, "status", "") or "").strip().lower()
        host = normalize_remote_host(row_get(row, "host", ""))
        token = (row_get(row, "vpn_api_token", "") or "").strip()
        if status == "online" and host and token:
            return row

    row = db.execute(
        """
        SELECT *
        FROM vpn_servers
        WHERE status = 'online'
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    if not row:
        return None

    host = normalize_remote_host(row_get(row, "host", ""))
    token = (row_get(row, "vpn_api_token", "") or "").strip()
    if not host or not token:
        return None
    return row


def select_runtime_server_for_account(
    db: DatabaseConnection,
    user: DatabaseRow | None,
    *,
    allow_reassign: bool = True,
) -> DatabaseRow | None:
    if not user:
        return None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role == "user":
        return choose_runtime_server_for_user(db, user, allow_reassign=allow_reassign)
    if role == "admin":
        return choose_runtime_server_for_admin(db, user)
    return None


def user_prefers_managed_nodes(db: DatabaseConnection, user: DatabaseRow | None) -> bool:
    if not user or row_get(user, "role") != "user":
        return False
    if VPN_API_URL:
        return True
    if row_get(user, "assigned_server_id"):
        return True
    row = db.execute("SELECT id FROM vpn_servers LIMIT 1").fetchone()
    return bool(row)


def load_cloudflare_accounts(db: DatabaseConnection, *, active_only: bool = False) -> list[dict]:
    sql = """
        SELECT
            id,
            account_name,
            api_token,
            zone_name,
            zone_id,
            is_active,
            sort_order,
            created_at,
            updated_at
        FROM cloudflare_accounts
    """
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY sort_order ASC, id ASC"
    rows = db.execute(sql).fetchall()
    accounts: list[dict] = []
    for row in rows:
        accounts.append(
            {
                "id": int(row["id"]),
                "account_name": (row["account_name"] or "").strip(),
                "api_token": (row["api_token"] or "").strip(),
                "api_token_masked": mask_secret(row["api_token"] or "", visible=4),
                "zone_name": normalize_fqdn(row["zone_name"]),
                "zone_id": (row["zone_id"] or "").strip(),
                "is_active": 1 if int(row["is_active"] or 0) == 1 else 0,
                "sort_order": to_non_negative_int(row["sort_order"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return accounts


def get_default_cloudflare_account_id(db: DatabaseConnection) -> int | None:
    row = db.execute(
        """
        SELECT id
        FROM cloudflare_accounts
        WHERE is_active = 1
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    if not row:
        return None
    return int(row["id"])


def build_mail_server_config(
    *,
    server_name: str,
    host: str,
    port: int,
    username: str,
    password: str,
    from_email: str,
    from_name: str,
    security: str,
    is_active: int = 0,
    sort_order: int = 100,
    source: str = "db",
    config_id: int | None = None,
    created_at: str = "",
    updated_at: str = "",
) -> dict[str, int | str]:
    normalized_security = normalize_mail_security(security)
    normalized_host = normalize_remote_host(host)
    normalized_from_email = (from_email or "").strip().lower()
    normalized_from_name = (from_name or "").strip()
    normalized_username = (username or "").strip()
    normalized_password = (password or "").strip()
    resolved_name = (server_name or "").strip() or normalized_host
    return {
        "id": int(config_id) if config_id else 0,
        "server_name": resolved_name,
        "host": normalized_host,
        "port": normalize_server_port(port, 587),
        "username": normalized_username,
        "password": normalized_password,
        "password_masked": mask_secret(normalized_password),
        "from_email": normalized_from_email,
        "from_name": normalized_from_name,
        "sender_display": format_sender_display(normalized_from_name, normalized_from_email),
        "security": normalized_security,
        "security_label": format_mail_security_label(normalized_security),
        "is_active": 1 if int(is_active or 0) == 1 else 0,
        "sort_order": to_non_negative_int(sort_order),
        "source": source,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def load_mail_servers(db: DatabaseConnection, *, active_only: bool = False) -> list[dict]:
    sql = """
        SELECT
            id,
            server_name,
            host,
            port,
            username,
            password,
            from_email,
            from_name,
            security,
            is_active,
            sort_order,
            created_at,
            updated_at
        FROM mail_servers
    """
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY is_active DESC, sort_order ASC, id ASC"
    rows = db.execute(sql).fetchall()
    servers: list[dict] = []
    for row in rows:
        servers.append(
            build_mail_server_config(
                config_id=row["id"],
                server_name=row["server_name"] or "",
                host=row["host"] or "",
                port=row["port"] or 587,
                username=row["username"] or "",
                password=row["password"] or "",
                from_email=row["from_email"] or "",
                from_name=row["from_name"] or "",
                security=row["security"] or MAIL_SECURITY_STARTTLS,
                is_active=row["is_active"] or 0,
                sort_order=row["sort_order"] or 0,
                source="db",
                created_at=row["created_at"] or "",
                updated_at=row["updated_at"] or "",
            )
        )
    return servers


def get_mail_server_by_id(
    db: DatabaseConnection,
    mail_server_id: int | None,
) -> DatabaseRow | None:
    if not mail_server_id:
        return None
    return db.execute(
        """
        SELECT *
        FROM mail_servers
        WHERE id = ?
        LIMIT 1
        """,
        (int(mail_server_id),),
    ).fetchone()


def get_active_mail_server_config(
    db: DatabaseConnection | None = None,
) -> dict[str, int | str] | None:
    use_db = db or get_db()
    row = use_db.execute(
        """
        SELECT *
        FROM mail_servers
        WHERE is_active = 1
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    if not row:
        return None
    return build_mail_server_config(
        config_id=row["id"],
        server_name=row["server_name"] or "",
        host=row["host"] or "",
        port=row["port"] or 587,
        username=row["username"] or "",
        password=row["password"] or "",
        from_email=row["from_email"] or "",
        from_name=row["from_name"] or "",
        security=row["security"] or MAIL_SECURITY_STARTTLS,
        is_active=row["is_active"] or 0,
        sort_order=row["sort_order"] or 0,
        source="db",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def load_env_mail_server_config() -> dict[str, int | str] | None:
    smtp_host = normalize_remote_host(os.environ.get("SMTP_HOST", ""))
    smtp_user = (os.environ.get("SMTP_USER") or "").strip()
    smtp_pass = (os.environ.get("SMTP_PASS") or "").strip()
    smtp_from = (os.environ.get("SMTP_FROM") or smtp_user).strip().lower()
    smtp_from_name = (os.environ.get("SMTP_FROM_NAME") or "").strip()
    smtp_port = parse_int_setting(os.environ.get("SMTP_PORT", "587"), 587, min_value=1)
    use_tls = (os.environ.get("SMTP_USE_TLS", "1") or "1").strip().lower() not in {
        "0",
        "false",
        "off",
        "no",
    }
    if not smtp_host or not smtp_from:
        return None
    return build_mail_server_config(
        server_name="环境变量 SMTP_*",
        host=smtp_host,
        port=smtp_port,
        username=smtp_user,
        password=smtp_pass,
        from_email=smtp_from,
        from_name=smtp_from_name,
        security=MAIL_SECURITY_STARTTLS if use_tls else MAIL_SECURITY_SSL,
        is_active=1,
        sort_order=0,
        source="env",
    )


def resolve_runtime_mail_server_config(
    db: DatabaseConnection | None = None,
) -> dict[str, int | str] | None:
    active_config = get_active_mail_server_config(db)
    if active_config:
        return active_config
    return load_env_mail_server_config()


def is_email_verification_available(
    db: DatabaseConnection | None = None,
) -> bool:
    return resolve_runtime_mail_server_config(db) is not None


def set_active_mail_server(
    db: DatabaseConnection,
    mail_server_id: int | None,
) -> None:
    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE mail_servers
        SET is_active = 0,
            updated_at = ?
        WHERE is_active <> 0
        """,
        (now_iso,),
    )
    if mail_server_id:
        db.execute(
            """
            UPDATE mail_servers
            SET is_active = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (now_iso, int(mail_server_id)),
        )


def load_managed_domains(
    db: DatabaseConnection,
    *,
    active_only: bool = False,
    only_unassigned: bool = False,
) -> list[dict]:
    conditions: list[str] = []
    params: list[object] = []
    if active_only:
        conditions.append("d.is_active = 1")
    if only_unassigned:
        conditions.append("d.assigned_server_id IS NULL")

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    rows = db.execute(
        f"""
        SELECT
            d.id,
            d.domain_name,
            d.cloudflare_account_id,
            d.assigned_server_id,
            d.dns_record_id,
            d.is_active,
            d.sort_order,
            d.last_sync_at,
            d.last_sync_message,
            d.created_at,
            d.updated_at,
            a.account_name,
            a.zone_name,
            a.is_active AS account_is_active,
            s.server_name AS assigned_server_name
        FROM managed_domains d
        LEFT JOIN cloudflare_accounts a ON a.id = d.cloudflare_account_id
        LEFT JOIN vpn_servers s ON s.id = d.assigned_server_id
        {where_clause}
        ORDER BY d.sort_order ASC, d.id ASC
        """,
        params,
    ).fetchall()
    domains: list[dict] = []
    for row in rows:
        domains.append(
            {
                "id": int(row["id"]),
                "domain_name": normalize_fqdn(row["domain_name"]),
                "cloudflare_account_id": row["cloudflare_account_id"],
                "account_name": (row["account_name"] or "").strip(),
                "zone_name": normalize_fqdn(row["zone_name"]),
                "account_is_active": 1 if int(row["account_is_active"] or 0) == 1 else 0,
                "assigned_server_id": row["assigned_server_id"],
                "assigned_server_name": (row["assigned_server_name"] or "").strip(),
                "dns_record_id": (row["dns_record_id"] or "").strip(),
                "is_active": 1 if int(row["is_active"] or 0) == 1 else 0,
                "sort_order": to_non_negative_int(row["sort_order"]),
                "last_sync_at": row["last_sync_at"],
                "last_sync_message": summarize_text(row["last_sync_message"] or "", 220),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return domains


def load_available_managed_domains(db: DatabaseConnection) -> list[dict]:
    rows = db.execute(
        """
        SELECT
            d.id,
            d.domain_name,
            d.sort_order
        FROM managed_domains d
        JOIN cloudflare_accounts a ON a.id = d.cloudflare_account_id
        WHERE d.is_active = 1
          AND d.assigned_server_id IS NULL
          AND a.is_active = 1
        ORDER BY d.sort_order ASC, d.id ASC
        """
    ).fetchall()
    return [
        {
            "id": int(row["id"]),
            "domain_name": normalize_fqdn(row["domain_name"]),
            "sort_order": to_non_negative_int(row["sort_order"]),
        }
        for row in rows
    ]


def ensure_managed_domain_entry(
    db: DatabaseConnection,
    domain_name: str,
    *,
    cloudflare_account_id: int | None = None,
    sort_order: int = 100,
) -> int | None:
    normalized_domain = normalize_fqdn(domain_name)
    if not normalized_domain:
        return None

    existing = db.execute(
        """
        SELECT id, cloudflare_account_id
        FROM managed_domains
        WHERE lower(domain_name) = lower(?)
        LIMIT 1
        """,
        (normalized_domain,),
    ).fetchone()
    now_iso = utcnow_iso()
    if existing:
        domain_id = int(existing["id"])
        if cloudflare_account_id and not existing["cloudflare_account_id"]:
            db.execute(
                """
                UPDATE managed_domains
                SET cloudflare_account_id = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (cloudflare_account_id, now_iso, domain_id),
            )
        return domain_id

    cursor = db.execute(
        """
        INSERT INTO managed_domains (
            domain_name,
            cloudflare_account_id,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, 1, ?, ?, ?)
        RETURNING id
        """,
        (
            normalized_domain,
            cloudflare_account_id,
            max(0, int(sort_order or 0)),
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.fetchone()["id"])


def cloudflare_extract_error_message(payload: dict | None) -> str:
    if not isinstance(payload, dict):
        return "未知错误"
    errors = payload.get("errors") or []
    if isinstance(errors, list):
        messages = []
        for item in errors:
            if isinstance(item, dict):
                message = (item.get("message") or "").strip()
                code = item.get("code")
                if message and code:
                    messages.append(f"[{code}] {message}")
                elif message:
                    messages.append(message)
            elif isinstance(item, str):
                text = item.strip()
                if text:
                    messages.append(text)
        if messages:
            return "; ".join(messages)
    message = (payload.get("message") or "").strip()
    if message:
        return message
    return "未知错误"


def cloudflare_api_request(
    api_key_or_token: str,
    method: str,
    path: str,
    *,
    auth_email: str = "",
    query: dict[str, str | int | None] | None = None,
    payload: dict | None = None,
) -> dict:
    credential = (api_key_or_token or "").strip()
    email = (auth_email or "").strip()
    if not credential:
        raise RuntimeError("Cloudflare Global API Key 为空。")

    request_path = (path or "").strip()
    if not request_path.startswith("/"):
        request_path = "/" + request_path
    url = f"{CLOUDFLARE_API_BASE}{request_path}"
    if query:
        safe_query = {
            str(k): str(v)
            for k, v in query.items()
            if v is not None and str(v).strip() != ""
        }
        if safe_query:
            url = f"{url}?{urllib_parse.urlencode(safe_query)}"

    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    req = urllib_request.Request(url=url, data=body, method=(method or "GET").upper())
    if looks_like_email(email):
        # Preferred mode: Global API Key + email.
        req.add_header("X-Auth-Email", email)
        req.add_header("X-Auth-Key", credential)
    else:
        # Backward compatibility for existing API Token data.
        req.add_header("Authorization", f"Bearer {credential}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib_request.urlopen(req, timeout=12) as response:
            response_text = response.read().decode("utf-8", errors="ignore")
    except urllib_error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        parsed: dict | None = None
        try:
            parsed = json.loads(raw) if raw else None
        except Exception:
            parsed = None
        detail = cloudflare_extract_error_message(parsed)
        raise RuntimeError(f"Cloudflare API 错误（HTTP {exc.code}）：{detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"Cloudflare API 请求失败：{exc.reason}") from exc

    if not response_text:
        raise RuntimeError("Cloudflare API 返回空响应。")
    try:
        parsed = json.loads(response_text)
    except Exception as exc:
        raise RuntimeError("Cloudflare API 响应解析失败。") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Cloudflare API 响应格式错误。")
    if not parsed.get("success", False):
        raise RuntimeError(f"Cloudflare API 返回失败：{cloudflare_extract_error_message(parsed)}")
    return parsed


def cloudflare_get_zone_id(api_key_or_token: str, zone_name: str, *, auth_email: str = "") -> str:
    normalized_zone = normalize_fqdn(zone_name)
    if not normalized_zone:
        raise RuntimeError("Zone 域名不能为空。")
    response = cloudflare_api_request(
        api_key_or_token,
        "GET",
        "/zones",
        auth_email=auth_email,
        query={"name": normalized_zone, "status": "active", "per_page": 1},
    )
    result = response.get("result") or []
    if not isinstance(result, list) or not result:
        raise RuntimeError(f"未找到 Zone：{normalized_zone}")
    zone_id = (result[0].get("id") or "").strip()
    if not zone_id:
        raise RuntimeError(f"Zone 查询成功但缺少 ID：{normalized_zone}")
    return zone_id


def cloudflare_list_zones(api_key_or_token: str, *, auth_email: str = "") -> list[dict[str, str]]:
    zones: list[dict[str, str]] = []
    page = 1
    max_pages = 20
    while page <= max_pages:
        response = cloudflare_api_request(
            api_key_or_token,
            "GET",
            "/zones",
            auth_email=auth_email,
            query={"per_page": 50, "page": page},
        )
        result = response.get("result") or []
        if not isinstance(result, list):
            result = []

        for item in result:
            if not isinstance(item, dict):
                continue
            zone_name = normalize_fqdn(item.get("name"))
            zone_id = (item.get("id") or "").strip()
            if not zone_name or not zone_id:
                continue
            zones.append(
                {
                    "zone_name": zone_name,
                    "zone_id": zone_id,
                }
            )

        result_info = response.get("result_info") or {}
        try:
            total_pages = int(result_info.get("total_pages") or 1)
        except Exception:
            total_pages = 1
        if page >= total_pages or not result:
            break
        page += 1

    deduped: dict[str, dict[str, str]] = {}
    for item in zones:
        deduped[item["zone_name"]] = item
    return sorted(deduped.values(), key=lambda x: x["zone_name"])


def resolve_cloudflare_zone_from_token(
    api_key_or_token: str,
    *,
    auth_email: str = "",
    preferred_zone_name: str = "",
) -> tuple[str, str, list[str]]:
    zones = cloudflare_list_zones(api_key_or_token, auth_email=auth_email)
    if not zones:
        raise RuntimeError("该邮箱与 Global API Key 未查询到可管理域名（Zone）。")

    normalized_preferred = normalize_fqdn(preferred_zone_name)
    selected_zone: dict[str, str] | None = None
    if normalized_preferred:
        for item in zones:
            if item["zone_name"] == normalized_preferred:
                selected_zone = item
                break
        if selected_zone is None:
            raise RuntimeError(f"当前凭据无权管理 Zone：{normalized_preferred}")
    if selected_zone is None:
        selected_zone = zones[0]

    names = [item["zone_name"] for item in zones]
    return selected_zone["zone_name"], selected_zone["zone_id"], names


def summarize_zone_names(zone_names: list[str], limit: int = 6) -> str:
    cleaned: list[str] = []
    for value in zone_names or []:
        normalized = normalize_fqdn(value)
        if normalized:
            cleaned.append(normalized)
    if not cleaned:
        return "无"
    if len(cleaned) <= limit:
        return "、".join(cleaned)
    return "、".join(cleaned[:limit]) + f" 等 {len(cleaned)} 个"


def sync_domains_from_cloudflare_account(
    db: DatabaseConnection,
    account_id: int,
) -> dict[str, object]:
    account = db.execute(
        """
        SELECT id, account_name, api_token, zone_name, is_active
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not account:
        raise RuntimeError("Cloudflare 账号不存在。")
    if int(account["is_active"] or 0) != 1:
        raise RuntimeError("Cloudflare 账号已停用，请先启用后再刷新。")

    account_email = (account["account_name"] or "").strip()
    if not looks_like_email(account_email):
        raise RuntimeError("Cloudflare 邮箱格式无效。")

    api_key = (account["api_token"] or "").strip()
    if not api_key:
        raise RuntimeError("Cloudflare Global API Key 为空。")

    zones = cloudflare_list_zones(api_key, auth_email=account_email)
    if not zones:
        raise RuntimeError("该邮箱与 Global API Key 未查询到可管理域名（Zone）。")

    preferred_zone = normalize_fqdn(account["zone_name"] or "")
    selected_zone = zones[0]
    for zone in zones:
        if zone["zone_name"] == preferred_zone:
            selected_zone = zone
            break

    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE cloudflare_accounts
        SET zone_name = ?,
            zone_id = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (selected_zone["zone_name"], selected_zone["zone_id"], now_iso, account_id),
    )

    touched_ids: list[int] = []
    inserted_count = 0
    updated_count = 0
    base_sort = 10
    sync_prefix = "Cloudflare账号刷新同步"
    for idx, zone in enumerate(zones):
        domain_name = normalize_fqdn(zone["zone_name"])
        existing = db.execute(
            """
            SELECT id
            FROM managed_domains
            WHERE lower(domain_name) = lower(?)
            LIMIT 1
            """,
            (domain_name,),
        ).fetchone()
        if existing:
            domain_id = int(existing["id"])
            updated_count += 1
        else:
            cursor = db.execute(
                """
                INSERT INTO managed_domains (
                    domain_name,
                    cloudflare_account_id,
                    assigned_server_id,
                    dns_record_id,
                    is_active,
                    sort_order,
                    last_sync_at,
                    last_sync_message,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, NULL, '', 1, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    domain_name,
                    account_id,
                    base_sort + idx,
                    now_iso,
                    f"{sync_prefix}：自动导入",
                    now_iso,
                    now_iso,
                ),
            )
            domain_id = int(cursor.fetchone()["id"])
            inserted_count += 1

        db.execute(
            """
            UPDATE managed_domains
            SET cloudflare_account_id = ?,
                is_active = 1,
                sort_order = ?,
                last_sync_at = ?,
                last_sync_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                account_id,
                base_sort + idx,
                now_iso,
                f"{sync_prefix}：自动同步",
                now_iso,
                domain_id,
            ),
        )
        touched_ids.append(domain_id)

    disabled_count = 0
    stale_rows = db.execute(
        """
        SELECT id
        FROM managed_domains
        WHERE cloudflare_account_id = ?
          AND assigned_server_id IS NULL
          AND (
            last_sync_message LIKE 'Cloudflare账号刷新同步%'
            OR last_sync_message LIKE '本次刷新未包含该域名%'
          )
        """,
        (account_id,),
    ).fetchall()
    touched_id_set = set(touched_ids)
    for stale in stale_rows:
        stale_id = int(stale["id"])
        if stale_id in touched_id_set:
            continue
        db.execute(
            """
            UPDATE managed_domains
            SET is_active = 0,
                last_sync_at = ?,
                last_sync_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                now_iso,
                "本次刷新未包含该域名，已自动停用。",
                now_iso,
                stale_id,
            ),
        )
        disabled_count += 1

    return {
        "zone_count": len(zones),
        "zone_names": [zone["zone_name"] for zone in zones],
        "inserted_count": inserted_count,
        "updated_count": updated_count,
        "disabled_count": disabled_count,
        "selected_zone_name": selected_zone["zone_name"],
    }


def cloudflare_upsert_a_record(
    api_key_or_token: str,
    zone_id: str,
    domain_name: str,
    ip_v4: str,
    *,
    auth_email: str = "",
) -> str:
    normalized_domain = normalize_fqdn(domain_name)
    if not normalized_domain:
        raise RuntimeError("域名不能为空。")
    normalized_zone_id = (zone_id or "").strip()
    if not normalized_zone_id:
        raise RuntimeError("Zone ID 不能为空。")

    payload = {
        "type": "A",
        "name": normalized_domain,
        "content": ip_v4,
        "ttl": 1,
        "proxied": False,
    }
    existing = cloudflare_api_request(
        api_key_or_token,
        "GET",
        f"/zones/{normalized_zone_id}/dns_records",
        auth_email=auth_email,
        query={"type": "A", "name": normalized_domain, "per_page": 1},
    )
    records = existing.get("result") or []
    if isinstance(records, list) and records:
        record_id = (records[0].get("id") or "").strip()
        if not record_id:
            raise RuntimeError("查询到现有 DNS 记录但记录 ID 为空。")
        cloudflare_api_request(
            api_key_or_token,
            "PUT",
            f"/zones/{normalized_zone_id}/dns_records/{record_id}",
            auth_email=auth_email,
            payload=payload,
        )
        return record_id

    created = cloudflare_api_request(
        api_key_or_token,
        "POST",
        f"/zones/{normalized_zone_id}/dns_records",
        auth_email=auth_email,
        payload=payload,
    )
    created_result = created.get("result") or {}
    record_id = (created_result.get("id") or "").strip()
    if not record_id:
        raise RuntimeError("DNS 记录创建成功但未返回记录 ID。")
    return record_id


def resolve_ipv4_for_dns_record(host: str) -> str:
    normalized_host = normalize_remote_host(host)
    if not normalized_host:
        raise RuntimeError("服务器地址为空，无法解析 A 记录。")
    try:
        parsed = ipaddress.ip_address(normalized_host)
        if parsed.version == 4:
            return str(parsed)
        raise RuntimeError("当前自动分配域名仅支持 IPv4 地址。")
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(normalized_host)
    except Exception as exc:
        raise RuntimeError(f"无法解析服务器地址 {normalized_host} 的 IPv4。") from exc
    try:
        parsed = ipaddress.ip_address(resolved)
        if parsed.version != 4:
            raise RuntimeError("解析结果不是 IPv4 地址。")
    except Exception as exc:
        raise RuntimeError("服务器地址解析结果无效。") from exc
    return str(parsed)


def ensure_auto_domain_for_server(
    db: DatabaseConnection,
    server_id: int,
) -> tuple[str, str]:
    account_row = db.execute(
        """
        SELECT id, account_name, zone_name
        FROM cloudflare_accounts
        WHERE is_active = 1
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    if not account_row:
        return "", "没有可用的 Cloudflare 账号，请先在“付款方式/Cloudflare 账号”中启用账号。"

    zone_name = normalize_fqdn(account_row["zone_name"])
    if not zone_name:
        return "", f"Cloudflare 账号 {account_row['account_name']} 缺少 Zone 域名，无法自动分配。"

    auto_domain = normalize_fqdn(f"srv{int(server_id)}.{zone_name}")
    if not auto_domain:
        return "", "自动生成域名失败，请检查 Cloudflare Zone 配置。"

    ensure_managed_domain_entry(
        db,
        auto_domain,
        cloudflare_account_id=int(account_row["id"]),
        sort_order=100000 + max(0, int(server_id)),
    )
    return auto_domain, f"已自动创建域名 {auto_domain}，准备分配到该服务器。"


def assign_managed_domain_to_server(
    db: DatabaseConnection,
    server_id: int,
    *,
    preferred_domain: str = "",
) -> tuple[bool, str]:
    server = db.execute(
        """
        SELECT id, host, domain
        FROM vpn_servers
        WHERE id = ?
        LIMIT 1
        """,
        (server_id,),
    ).fetchone()
    if not server:
        return False, "服务器不存在。"

    server_ip = resolve_ipv4_for_dns_record(row_get(server, "host", ""))
    normalized_preferred = normalize_fqdn(preferred_domain)
    query_params: list[object] = [server_id]
    where_domain = ""
    if normalized_preferred:
        where_domain = " AND lower(d.domain_name) = lower(?)"
        query_params.append(normalized_preferred)

    def pick_domain_row() -> DatabaseRow | None:
        return db.execute(
            f"""
            SELECT
                d.id,
                d.domain_name,
                d.cloudflare_account_id,
                a.account_name,
                a.api_token,
                a.zone_name,
                a.zone_id
            FROM managed_domains d
            JOIN cloudflare_accounts a ON a.id = d.cloudflare_account_id
            WHERE d.is_active = 1
              AND a.is_active = 1
              AND (d.assigned_server_id IS NULL OR d.assigned_server_id = ?)
              {where_domain}
            ORDER BY CASE WHEN d.assigned_server_id = ? THEN 0 ELSE 1 END, d.sort_order ASC, d.id ASC
            LIMIT 1
            """,
            tuple(query_params + [server_id]),
        ).fetchone()

    domain_row = pick_domain_row()
    auto_domain_notice = ""
    if not domain_row and not normalized_preferred:
        auto_domain, auto_notice = ensure_auto_domain_for_server(db, server_id)
        if not auto_domain:
            return False, auto_notice
        auto_domain_notice = auto_notice
        normalized_preferred = auto_domain
        where_domain = " AND lower(d.domain_name) = lower(?)"
        query_params = [server_id, normalized_preferred]
        domain_row = pick_domain_row()

    if not domain_row:
        if normalized_preferred:
            return False, f"域名 {normalized_preferred} 不可用或未在域名管理中启用。"
        return False, "没有可分配的域名，请先在“域名管理”添加并启用域名。"

    domain_name = normalize_fqdn(domain_row["domain_name"])
    zone_name = normalize_fqdn(domain_row["zone_name"])
    account_email = (domain_row["account_name"] or "").strip()
    if not looks_like_email(account_email):
        return False, "Cloudflare 邮箱格式无效，请在 Cloudflare 账号中填写正确邮箱。"
    api_key = (domain_row["api_token"] or "").strip()
    if not api_key:
        return False, f"Cloudflare 账号 {account_email} 缺少 Global API Key。"
    if not domain_belongs_to_zone(domain_name, zone_name):
        return False, f"域名 {domain_name} 不属于 Zone {zone_name}。"

    zone_id = (domain_row["zone_id"] or "").strip()
    if not zone_id:
        zone_id = cloudflare_get_zone_id(api_key, zone_name, auth_email=account_email)

    dns_record_id = cloudflare_upsert_a_record(
        api_key_or_token=api_key,
        zone_id=zone_id,
        domain_name=domain_name,
        ip_v4=server_ip,
        auth_email=account_email,
    )
    now_iso = utcnow_iso()
    success_message = f"已分配域名 {domain_name} -> {server_ip}"
    if auto_domain_notice:
        success_message = f"{auto_domain_notice}\n{success_message}"

    db.execute(
        """
        UPDATE cloudflare_accounts
        SET zone_id = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (zone_id, now_iso, int(domain_row["cloudflare_account_id"])),
    )
    db.execute(
        """
        UPDATE managed_domains
        SET assigned_server_id = NULL,
            updated_at = ?
        WHERE assigned_server_id = ?
          AND id <> ?
        """,
        (now_iso, server_id, int(domain_row["id"])),
    )
    db.execute(
        """
        UPDATE managed_domains
        SET assigned_server_id = ?,
            dns_record_id = ?,
            last_sync_at = ?,
            last_sync_message = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            server_id,
            dns_record_id,
            now_iso,
            success_message,
            now_iso,
            int(domain_row["id"]),
        ),
    )
    db.execute(
        """
        UPDATE vpn_servers
        SET domain = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (domain_name, now_iso, server_id),
    )
    return True, success_message


def release_server_domain_bindings(db: DatabaseConnection, server_id: int) -> None:
    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE managed_domains
        SET assigned_server_id = NULL,
            last_sync_at = ?,
            last_sync_message = ?,
            updated_at = ?
        WHERE assigned_server_id = ?
        """,
        (
            now_iso,
            "服务器解绑，域名已释放。",
            now_iso,
            server_id,
        ),
    )
    db.execute(
        """
        UPDATE vpn_servers
        SET domain = '',
            updated_at = ?
        WHERE id = ?
        """,
        (now_iso, server_id),
    )


def upsert_primary_cloudflare_account_from_onboarding(
    db: DatabaseConnection,
    *,
    account_name: str,
    api_token: str,
    zone_name: str = "",
) -> int:
    normalized_account_name = (account_name or "").strip()
    api_key = (api_token or "").strip()
    if not normalized_account_name:
        raise RuntimeError("Cloudflare 邮箱不能为空。")
    if not looks_like_email(normalized_account_name):
        raise RuntimeError("Cloudflare 邮箱格式无效。")
    if not api_key:
        raise RuntimeError("Cloudflare Global API Key 不能为空。")

    selected_zone_name, selected_zone_id, _ = resolve_cloudflare_zone_from_token(
        api_key,
        auth_email=normalized_account_name,
        preferred_zone_name=zone_name,
    )

    now_iso = utcnow_iso()
    existing = db.execute(
        """
        SELECT id
        FROM cloudflare_accounts
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    if existing:
        account_id = int(existing["id"])
        db.execute(
            """
            UPDATE cloudflare_accounts
            SET account_name = ?,
                api_token = ?,
                zone_name = ?,
                zone_id = ?,
                is_active = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (
                normalized_account_name,
                api_key,
                selected_zone_name,
                selected_zone_id,
                now_iso,
                account_id,
            ),
        )
        return account_id

    cursor = db.execute(
        """
        INSERT INTO cloudflare_accounts (
            account_name,
            api_token,
            zone_name,
            zone_id,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, 1, 10, ?, ?)
        """,
        (
            normalized_account_name,
            api_key,
            selected_zone_name,
            selected_zone_id,
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.fetchone()["id"])


def load_ssh_private_key(private_key_text: str) -> paramiko.PKey:
    normalized = (private_key_text or "").strip()
    if not normalized:
        raise ValueError("私钥为空。")
    last_error: Exception | None = None
    for key_cls in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
        paramiko.DSSKey,
    ):
        try:
            return key_cls.from_private_key(io.StringIO(normalized))
        except Exception as exc:
            last_error = exc
    raise ValueError(f"私钥格式无效：{last_error}")


def is_ssh_auth_error(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            paramiko.AuthenticationException,
            paramiko.BadAuthenticationType,
            paramiko.PasswordRequiredException,
        ),
    )


def connect_ssh_with_retry(
    client: paramiko.SSHClient,
    *,
    host: str,
    port: int,
    username: str,
    timeout: int,
    password: str | None = None,
    pkey: paramiko.PKey | None = None,
) -> None:
    last_exc: Exception | None = None
    for attempt in range(1, SSH_CONNECT_MAX_RETRIES + 1):
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return
        except Exception as exc:
            last_exc = exc
            if is_ssh_auth_error(exc) or attempt >= SSH_CONNECT_MAX_RETRIES:
                break
            if SSH_CONNECT_RETRY_DELAY_SECONDS > 0:
                time.sleep(SSH_CONNECT_RETRY_DELAY_SECONDS)
    if last_exc:
        raise last_exc
    raise RuntimeError("SSH connection failed")


def open_ssh_client(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    private_key_text: str = "",
    timeout: int = 10,
) -> paramiko.SSHClient:
    auth_errors: list[str] = []
    normalized_private_key = (private_key_text or "").strip()

    def _new_client() -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client

    if normalized_private_key:
        try:
            private_key = load_ssh_private_key(normalized_private_key)
        except Exception as exc:
            auth_errors.append(str(exc))
        else:
            client = _new_client()
            try:
                connect_ssh_with_retry(
                    client,
                    host=host,
                    port=port,
                    username=username,
                    pkey=private_key,
                    timeout=timeout,
                )
                return client
            except Exception as exc:
                client.close()
                auth_errors.append(f"私钥登录失败：{exc}")

    if password:
        client = _new_client()
        try:
            connect_ssh_with_retry(
                client,
                host=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
            )
            return client
        except Exception as exc:
            client.close()
            auth_errors.append(f"密码登录失败：{exc}")

    if not auth_errors:
        raise ValueError("服务器连接信息不完整（需提供密码或私钥）。")
    raise RuntimeError("；".join(auth_errors))


def test_server_connectivity(
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str = "",
) -> tuple[bool, str]:
    safe_host = normalize_remote_host(host)
    safe_port = normalize_server_port(port)
    safe_username = (username or "").strip()
    safe_private_key = (private_key_text or "").strip()
    if not safe_host or not safe_username or (not password and not safe_private_key):
        return False, "服务器连接信息不完整（需填写密码或私钥）。"

    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(
            safe_host,
            safe_port,
            safe_username,
            password,
            private_key_text=safe_private_key,
            timeout=8,
        )
        stdin, stdout, stderr = client.exec_command(
            "hostname && uname -srm", timeout=10
        )
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        if err:
            return False, f"连接成功，但命令执行异常：{summarize_text(err, 120)}"
        return True, f"连接成功：{summarize_text(out, 120)}"
    except Exception as exc:
        return False, f"连接失败：{exc}"
    finally:
        if client:
            client.close()


def run_remote_ssh_command(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str = "",
    command: str,
    timeout: int = 30,
) -> tuple[bool, str]:
    safe_host = normalize_remote_host(host)
    safe_port = normalize_server_port(port)
    safe_username = (username or "").strip()
    safe_private_key = (private_key_text or "").strip()
    if not safe_host or not safe_username or (not password and not safe_private_key):
        return False, "服务器连接信息不完整（需提供密码或私钥）。"

    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(
            safe_host,
            safe_port,
            safe_username,
            password,
            private_key_text=safe_private_key,
            timeout=10,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        merged = "\n".join(
            [item for item in [out, err] if (item or "").strip()]
        ).strip()
        if exit_code != 0:
            detail = summarize_text(merged or f"exit={exit_code}", 320)
            return False, f"远程命令执行失败：{detail}"
        if merged:
            return True, summarize_text(merged, 320)
        return True, "远程命令执行成功。"
    except Exception as exc:
        return False, f"SSH 执行失败：{exc}"
    finally:
        if client:
            client.close()


def run_remote_ssh_script(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str = "",
    script: str,
    timeout: int = 45,
) -> tuple[bool, str]:
    safe_host = normalize_remote_host(host)
    safe_port = normalize_server_port(port)
    safe_username = (username or "").strip()
    safe_private_key = (private_key_text or "").strip()
    if not safe_host or not safe_username or (not password and not safe_private_key):
        return False, "服务器连接信息不完整（需提供密码或私钥）。"

    script_text = (script or "").strip()
    if not script_text:
        return False, "远程脚本为空。"
    script_payload = script_text + "\n"

    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(
            safe_host,
            safe_port,
            safe_username,
            password,
            private_key_text=safe_private_key,
            timeout=10,
        )
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=timeout)
        stdin.write(script_payload)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        exit_code = stdout.channel.recv_exit_status()
        merged = "\n".join(
            [item for item in [out, err] if (item or "").strip()]
        ).strip()
        if exit_code != 0:
            detail = summarize_text(merged or f"exit={exit_code}", 320)
            return False, f"远程脚本执行失败：{detail}"
        if merged:
            return True, summarize_text(merged, 320)
        return True, "远程脚本执行成功。"
    except Exception as exc:
        return False, f"SSH 执行失败：{exc}"
    finally:
        if client:
            client.close()


def get_server_ipv6_enabled(server_row: DatabaseRow) -> bool | None:
    try:
        if (row_get(server_row, "vpn_api_token", "") or "").strip():
            result = vpn_api_request(
                "GET",
                "/system/ipv6",
                server_row=server_row,
                allow_reassign=False,
            )
            if "enabled" in result:
                return bool(result.get("enabled"))
            if "disabled" in result:
                return not bool(result.get("disabled"))
    except Exception:
        pass
    return None


def set_server_ipv6_state(
    *,
    server_row: DatabaseRow | None = None,
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str,
    enable: bool,
) -> tuple[bool, str]:
    target_value = "0" if enable else "1"
    action_text = "开启" if enable else "关闭"
    if server_row is not None and (row_get(server_row, "vpn_api_token", "") or "").strip():
        try:
            result = vpn_api_request(
                "POST",
                "/system/ipv6/control",
                {"action": "enable" if enable else "disable"},
                server_row=server_row,
                allow_reassign=False,
            )
            state_text = "已开启" if result.get("enabled") else "已关闭"
            return True, f"{action_text} IPv6 成功：当前 IPv6 {state_text}。"
        except Exception as exc:
            app.logger.warning("VPN API IPv6 toggle failed, fallback to SSH: %s", exc)

    script = textwrap.dedent(
        f"""
        set -euo pipefail
        mkdir -p /etc/sysctl.d
        cat > /etc/sysctl.d/99-vpnmanager-ipv6.conf <<'EOF'
        net.ipv6.conf.all.disable_ipv6 = {target_value}
        net.ipv6.conf.default.disable_ipv6 = {target_value}
        net.ipv6.conf.lo.disable_ipv6 = {target_value}
        EOF
        sysctl -p /etc/sysctl.d/99-vpnmanager-ipv6.conf >/dev/null
        sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6
        """
    ).strip()
    ok, result = run_remote_ssh_script(
        host=host,
        port=port,
        username=username,
        password=password,
        private_key_text=private_key_text,
        script=script,
        timeout=45,
    )
    if ok:
        return True, f"{action_text} IPv6 成功：{result}"
    return False, f"{action_text} IPv6 失败：{result}"


def test_server_vpn_api_health(host: str, vpn_api_token: str) -> tuple[bool, str]:
    safe_host = normalize_remote_host(host)
    if not safe_host:
        return False, "节点地址为空。"
    host_url = host_for_http_url(safe_host)
    url = f"http://{host_url}:{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}/healthz"
    headers = {"Accept": "application/json"}
    token = (vpn_api_token or "").strip()
    if token:
        headers["X-VPN-Token"] = token
    req = urllib_request.Request(url=url, headers=headers, method="GET")
    try:
        with urllib_request.urlopen(req, timeout=2) as response:
            body = response.read().decode("utf-8", errors="ignore")
        payload = json.loads(body) if body else {}
        if isinstance(payload, dict) and payload.get("ok", False):
            return True, "节点健康检查通过。"
        return False, "节点健康检查返回异常内容。"
    except urllib_error.HTTPError as exc:
        detail = ""
        try:
            raw = exc.read().decode("utf-8", errors="ignore")
            parsed = json.loads(raw) if raw else {}
            detail = str(parsed.get("error") or parsed.get("message") or raw).strip()
        except Exception:
            detail = ""
        if detail:
            return False, f"节点健康检查失败：HTTP {exc.code}，{summarize_text(detail, 140)}"
        return False, f"节点健康检查失败：HTTP {exc.code}"
    except Exception as exc:
        return False, f"节点健康检查失败：{exc}"


def refresh_server_health_status(
    db: DatabaseConnection, *, force: bool = False
) -> dict[str, int]:
    now = utcnow()
    if not force:
        last_refresh = parse_iso(get_app_setting(db, "server_health_last_check_at", ""))
        if last_refresh and (now - last_refresh) < timedelta(seconds=30):
            counts_row = db.execute(
                """
                SELECT
                    COUNT(*) AS total_count,
                    SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online_count
                FROM vpn_servers
                """
            ).fetchone()
            total_count = int(row_get(counts_row, "total_count", 0) or 0)
            online_count = int(row_get(counts_row, "online_count", 0) or 0)
            abnormal_count = max(0, total_count - online_count)
            return {
                "total": total_count,
                "online": online_count,
                "abnormal": abnormal_count,
                "checked": 0,
            }

    rows = db.execute(
        """
        SELECT id, host, vpn_api_token, status, last_test_at, last_test_ok, last_test_message
        FROM vpn_servers
        ORDER BY id DESC
        """
    ).fetchall()
    timeout_delta = timedelta(seconds=NODE_HEARTBEAT_TIMEOUT_SECONDS)
    checked = 0
    for row in rows:
        current_status = (row_get(row, "status", "") or "").strip().lower()
        if current_status in {"deploying", "deploy_failed"}:
            continue

        last_test_at = parse_iso(row_get(row, "last_test_at", ""))
        need_check = force or not last_test_at or (now - last_test_at) >= timeout_delta
        if not need_check:
            continue

        ok, message = test_server_vpn_api_health(
            row_get(row, "host", ""),
            row_get(row, "vpn_api_token", ""),
        )
        checked += 1
        db.execute(
            """
            UPDATE vpn_servers
            SET status = ?,
                last_test_at = ?,
                last_test_ok = ?,
                last_test_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                "online" if ok else "offline",
                now.isoformat(),
                1 if ok else 0,
                summarize_text(message, 220),
                now.isoformat(),
                int(row["id"]),
            ),
        )
    upsert_app_setting(db, "server_health_last_check_at", now.isoformat())

    counts_row = db.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online_count
        FROM vpn_servers
        """
    ).fetchone()
    total_count = int(row_get(counts_row, "total_count", 0) or 0)
    online_count = int(row_get(counts_row, "online_count", 0) or 0)
    abnormal_count = max(0, total_count - online_count)
    return {
        "total": total_count,
        "online": online_count,
        "abnormal": abnormal_count,
        "checked": checked,
    }


def build_vpn_node_deploy_script(
    *,
    vpn_api_token: str,
    kcptun_port: int,
    shadowsocks_port: int,
    dns_port: int,
    openvpn_enabled: bool,
    shadowsocks_enabled: bool,
    kcptun_enabled: bool,
    skip_os_upgrade: bool,
) -> str:
    manual_script_path = BASE_DIR / "scripts" / "manual_deploy_vpn_node.sh"
    manual_script = manual_script_path.read_text(encoding="utf-8")
    bootstrap = textwrap.dedent(
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        export APP_DIR="/srv/vpn-node"
        export REPO_URL="https://github.com/trowar/vpn-manager.git"
        export BRANCH="main"
        export DEPLOY_SKIP_OS_UPGRADE={"1" if skip_os_upgrade else "0"}
        export OPENVPN_ENABLED={"1" if openvpn_enabled else "0"}
        export SHADOWSOCKS_ENABLED={"1" if shadowsocks_enabled else "0"}
        export KCPTUN_ENABLED={"1" if kcptun_enabled else "0"}
        export OPENVPN_ENDPOINT_PORT="{SERVER_DEPLOY_DEFAULT_OPENVPN_PORT}"
        export KCPTUN_SERVER_PORT="{kcptun_port}"
        export SHADOWSOCKS_SERVER_PORT="{shadowsocks_port}"
        export SHADOWSOCKS_PORT_RANGE_START="{OPENVPN_RELAY_PORT_START}"
        export SHADOWSOCKS_PORT_RANGE_END="{OPENVPN_RELAY_PORT_END}"
        export SHADOWSOCKS_METHOD="{SHADOWSOCKS_METHOD}"
        export SHADOWSOCKS_PASSWORD="{SHADOWSOCKS_PASSWORD}"
        export KCPTUN_KEY="{KCPTUN_KEY}"
        export KCPTUN_CRYPT="{KCPTUN_CRYPT}"
        export KCPTUN_MODE="{KCPTUN_MODE}"
        export KCPTUN_MTU="{KCPTUN_MTU}"
        export VPN_API_PUBLIC_PORT="{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}"
        export VPN_API_TOKEN="{vpn_api_token}"
        """
    ).strip()
    return f"{bootstrap}\n\n{manual_script.strip()}\n"


def deploy_vpn_node_server(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str = "",
    kcptun_port: int,
    shadowsocks_port: int,
    dns_port: int,
    openvpn_enabled: bool = True,
    shadowsocks_enabled: bool = False,
    kcptun_enabled: bool = False,
    vpn_api_token: str | None = None,
) -> tuple[bool, str, str, str]:
    safe_token = (vpn_api_token or "").strip()
    if not safe_token:
        safe_token = hashlib.sha256(os.urandom(32)).hexdigest()[:48]

    normalized_host = normalize_remote_host(host)
    normalized_port = normalize_server_port(port, 22)
    normalized_user = (username or "").strip()
    script = build_vpn_node_deploy_script(
        vpn_api_token=safe_token,
        kcptun_port=normalize_server_port(kcptun_port, SERVER_DEPLOY_DEFAULT_KCPTUN_PORT),
        shadowsocks_port=normalize_server_port(
            shadowsocks_port, SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
        ),
        dns_port=normalize_server_port(dns_port, SERVER_DEPLOY_DEFAULT_DNS_PORT),
        openvpn_enabled=openvpn_enabled,
        shadowsocks_enabled=shadowsocks_enabled,
        kcptun_enabled=kcptun_enabled,
        skip_os_upgrade=SERVER_DEPLOY_SKIP_OS_UPGRADE,
    )

    client: paramiko.SSHClient | None = None
    started_at = datetime.now(timezone.utc)
    try:
        client = open_ssh_client(
            normalized_host,
            normalized_port,
            normalized_user,
            password,
            private_key_text=private_key_text,
            timeout=12,
        )
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=900)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        code = stdout.channel.recv_exit_status()
        merged_raw = normalize_deploy_log_text(out + "\n" + err)
        merged_log = summarize_text(merged_raw, 120000)
        merged = summarize_text(merged_raw, 1200)
        if not merged:
            merged = "部署脚本执行完成，但未返回可读日志。"
        structured_log = build_structured_deploy_log(
            host=normalized_host,
            port=normalized_port,
            username=normalized_user,
            started_at=started_at,
            ended_at=datetime.now(timezone.utc),
            script_text=script,
            script_executed=True,
            exit_code=code,
            stdout_text=out,
            stderr_text=err,
        )
        if not merged_log:
            merged_log = structured_log
        else:
            merged_log = f"{structured_log}\n\n[deploy] 汇总\n{merged_log}"
        if code == 0:
            return True, f"部署成功。{merged}", safe_token, merged_log
        return False, f"部署失败（exit={code}）。{merged}", safe_token, merged_log
    except Exception as exc:
        error_text = f"部署异常：{exc}"
        structured_log = build_structured_deploy_log(
            host=normalized_host,
            port=normalized_port,
            username=normalized_user,
            started_at=started_at,
            ended_at=datetime.now(timezone.utc),
            script_text=script,
            script_executed=False,
            exit_code=None,
            stdout_text="",
            stderr_text="",
            error_text=error_text,
        )
        return False, error_text, safe_token, structured_log
    finally:
        if client:
            client.close()


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_CONF_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_QR_DIR.mkdir(parents=True, exist_ok=True)
    SHARED_VPN_MATERIALS_DIR.mkdir(parents=True, exist_ok=True)


def acquire_db_init_lock(timeout_seconds: float = 60.0) -> None:
    deadline = time.time() + timeout_seconds
    while True:
        try:
            DB_INIT_LOCK_DIR.mkdir()
            return
        except FileExistsError:
            try:
                stat = DB_INIT_LOCK_DIR.stat()
                if (time.time() - stat.st_mtime) > 120:
                    for child in DB_INIT_LOCK_DIR.iterdir():
                        try:
                            if child.is_file():
                                child.unlink(missing_ok=True)
                        except Exception:
                            pass
                    DB_INIT_LOCK_DIR.rmdir()
                    continue
            except Exception:
                pass
            if time.time() >= deadline:
                raise RuntimeError("Timed out waiting for database init lock")
            time.sleep(0.2)


def release_db_init_lock() -> None:
    try:
        DB_INIT_LOCK_DIR.rmdir()
    except Exception:
        pass


from portal_db import (
    DB_INTEGRITY_ERRORS,
    begin_immediate,
    get_db,
    get_table_columns,
    open_direct_db_connection,
    register_db_teardown,
)

register_db_teardown(app)


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'approved',
            email_verified INTEGER NOT NULL DEFAULT 1,
            preferred_server_id INTEGER,
            assigned_server_id INTEGER,
            kcptun_ingress_port INTEGER,
            openvpn_ingress_port INTEGER,
            vpn_internal_ip TEXT,
            archived_private_token TEXT,
            archived_public_token TEXT,
            archived_shared_token TEXT,
            openvpn_common_name TEXT,
            openvpn_client_cert TEXT,
            openvpn_client_key TEXT,
            archived_profile_file TEXT,
            archived_qr_file TEXT,
            client_config_token TEXT,
            last_login_ip TEXT,
            last_login_at TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            subscription_expires_at TEXT,
            vpn_enabled INTEGER NOT NULL DEFAULT 0,
            preferred_billing_mode TEXT NOT NULL DEFAULT 'duration',
            traffic_quota_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_last_total_bytes INTEGER NOT NULL DEFAULT 0,
            force_password_change INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            plan_months INTEGER NOT NULL DEFAULT 0,
            plan_id INTEGER,
            plan_name TEXT,
            plan_mode TEXT,
            plan_duration_months INTEGER,
            plan_duration_value INTEGER,
            plan_duration_unit TEXT,
            plan_traffic_gb INTEGER,
            payment_method TEXT NOT NULL DEFAULT 'usdt',
            usdt_network TEXT NOT NULL DEFAULT 'TRC20',
            usdt_amount TEXT NOT NULL DEFAULT '0',
            pay_to_address TEXT,
            tx_hash TEXT,
            tx_submitted_at TEXT,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            paid_at TEXT,
            note TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS vpn_servers (
            id SERIAL PRIMARY KEY,
            server_name TEXT NOT NULL,
            server_region TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ssh_private_key TEXT NOT NULL DEFAULT '',
            domain TEXT,
            vpn_api_token TEXT,
            kcptun_port INTEGER NOT NULL DEFAULT 51820,
            openvpn_port INTEGER NOT NULL DEFAULT 443,
            dns_port INTEGER NOT NULL DEFAULT 53,
            openvpn_enabled INTEGER NOT NULL DEFAULT 1,
            shadowsocks_enabled INTEGER NOT NULL DEFAULT 0,
            kcptun_enabled INTEGER NOT NULL DEFAULT 0,
            ssh_tunnel_enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            last_test_at TEXT,
            last_test_ok INTEGER NOT NULL DEFAULT 0,
            last_test_message TEXT,
            last_deploy_at TEXT,
            last_deploy_ok INTEGER NOT NULL DEFAULT 0,
            last_deploy_message TEXT,
            last_deploy_log TEXT,
            last_allocated_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_server_permissions (
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, server_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS client_online_sessions (
            user_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT NOT NULL,
            server_id INTEGER,
            server_host TEXT,
            profile_type TEXT NOT NULL,
            profile_id TEXT,
            profile_name TEXT,
            endpoint TEXT,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            tx_bytes INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id SERIAL PRIMARY KEY,
            plan_name TEXT NOT NULL,
            billing_mode TEXT NOT NULL,
            duration_months INTEGER,
            duration_value INTEGER,
            duration_unit TEXT,
            traffic_gb INTEGER,
            price_usdt TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_methods (
            id SERIAL PRIMARY KEY,
            method_code TEXT NOT NULL DEFAULT 'usdt',
            method_name TEXT NOT NULL,
            network TEXT NOT NULL DEFAULT 'TRC20',
            receive_address TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS registration_limits (
            ip_address TEXT PRIMARY KEY,
            last_register_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL,
            code TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            ip_address TEXT,
            expire_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_servers (
            id SERIAL PRIMARY KEY,
            server_name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 587,
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            from_email TEXT NOT NULL,
            from_name TEXT NOT NULL DEFAULT '',
            security TEXT NOT NULL DEFAULT 'starttls',
            is_active INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS vpn_servers (
            id SERIAL PRIMARY KEY,
            server_name TEXT NOT NULL,
            server_region TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ssh_private_key TEXT NOT NULL DEFAULT '',
            domain TEXT,
            vpn_api_token TEXT,
            kcptun_port INTEGER NOT NULL DEFAULT 51820,
            openvpn_port INTEGER NOT NULL DEFAULT 443,
            dns_port INTEGER NOT NULL DEFAULT 53,
            openvpn_enabled INTEGER NOT NULL DEFAULT 1,
            shadowsocks_enabled INTEGER NOT NULL DEFAULT 0,
            kcptun_enabled INTEGER NOT NULL DEFAULT 0,
            ssh_tunnel_enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            last_test_at TEXT,
            last_test_ok INTEGER NOT NULL DEFAULT 0,
            last_test_message TEXT,
            last_deploy_at TEXT,
            last_deploy_ok INTEGER NOT NULL DEFAULT 0,
            last_deploy_message TEXT,
            last_deploy_log TEXT,
            last_allocated_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloudflare_accounts (
            id SERIAL PRIMARY KEY,
            account_name TEXT NOT NULL,
            api_token TEXT NOT NULL,
            zone_name TEXT NOT NULL,
            zone_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_domains (
            id SERIAL PRIMARY KEY,
            domain_name TEXT NOT NULL,
            cloudflare_account_id INTEGER,
            assigned_server_id INTEGER,
            dns_record_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            last_sync_at TEXT,
            last_sync_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (cloudflare_account_id) REFERENCES cloudflare_accounts(id) ON DELETE SET NULL,
            FOREIGN KEY (assigned_server_id) REFERENCES vpn_servers(id) ON DELETE SET NULL
        )
        """
    )
    migrate_schema(db)
    ensure_default_payment_settings(db)
    ensure_default_onboarding_settings(db)
    ensure_default_system_settings(db)
    ensure_default_payment_methods(db)
    onboarding_settings = load_onboarding_settings(db)
    default_cf_account_id = None
    legacy_cf_account = str(onboarding_settings.get("cloudflare_account") or "").strip()
    legacy_cf_password = str(onboarding_settings.get("cloudflare_password") or "").strip()
    if legacy_cf_account and legacy_cf_password:
        existing_cf_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM cloudflare_accounts"
        ).fetchone()["cnt"]
        if int(existing_cf_count or 0) == 0 and looks_like_email(legacy_cf_account):
            zone_from_portal = guess_zone_name_from_domain(
                str(onboarding_settings.get("portal_domain") or "")
            ) or normalize_fqdn(str(onboarding_settings.get("portal_domain") or ""))
            try:
                default_cf_account_id = upsert_primary_cloudflare_account_from_onboarding(
                    db,
                    account_name=legacy_cf_account,
                    api_token=legacy_cf_password,
                    zone_name=zone_from_portal,
                )
            except Exception:
                # Do not block application boot for historical/invalid legacy settings.
                default_cf_account_id = None
    if not default_cf_account_id:
        default_cf_account_id = get_default_cloudflare_account_id(db)
    portal_domain = normalize_fqdn(str(onboarding_settings.get("portal_domain") or ""))
    if portal_domain:
        ensure_managed_domain_entry(
            db,
            portal_domain,
            cloudflare_account_id=default_cf_account_id,
            sort_order=10,
        )
    sync_legacy_payment_settings_with_default_method(db)
    ensure_default_runtime_server(db)
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_status_created ON users(status, created_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_expire ON users(subscription_expires_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_assigned_server ON users(assigned_server_id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_server_permissions_server ON user_server_permissions(server_id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_preferred_server ON users(preferred_server_id)"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_kcptun_ingress_port ON users(kcptun_ingress_port) WHERE kcptun_ingress_port IS NOT NULL"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_openvpn_ingress_port ON users(openvpn_ingress_port) WHERE openvpn_ingress_port IS NOT NULL"
    )
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_openvpn_common_name
        ON users(openvpn_common_name)
        WHERE openvpn_common_name IS NOT NULL AND trim(openvpn_common_name) <> ''
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_user_status ON payment_orders(user_id, status)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_status_created ON payment_orders(status, created_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_status_expire ON payment_orders(status, expires_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_tx_hash ON payment_orders(tx_hash)"
    )
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_tx_hash_unique
        ON payment_orders(tx_hash) WHERE tx_hash IS NOT NULL AND tx_hash <> ''
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_subscription_plans_active_sort ON subscription_plans(is_active, sort_order, id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_payment_methods_active_sort ON payment_methods(is_active, sort_order, id)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_vpn_servers_host ON vpn_servers(host)")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_server_permissions (
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, server_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_server_permissions_server ON user_server_permissions(server_id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vpn_servers_region_status ON vpn_servers(server_region, status, id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vpn_servers_status_alloc ON vpn_servers(status, last_allocated_at, id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_cloudflare_accounts_active_sort ON cloudflare_accounts(is_active, sort_order, id)"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_domains_domain_unique ON managed_domains(domain_name)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_managed_domains_active_sort ON managed_domains(is_active, sort_order, id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_managed_domains_assigned_server ON managed_domains(assigned_server_id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_email_verifications_lookup ON email_verifications(email, purpose, status, created_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mail_servers_active_sort ON mail_servers(is_active, sort_order, id)"
    )
    db.commit()


def migrate_schema(db: DatabaseConnection) -> None:
    user_columns = {
        row["name"]: row
        for row in get_table_columns(db, "users")
    }

    def ensure_user_column(column_name: str, definition: str) -> None:
        nonlocal user_columns
        if column_name not in user_columns:
            db.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")
            user_columns = {
                row["name"]: row
                for row in get_table_columns(db, "users")
            }

    def copy_legacy_user_column(old_name: str, new_name: str) -> None:
        if old_name in user_columns and new_name in user_columns:
            db.execute(
                f"""
                UPDATE users
                SET {new_name} = {old_name}
                WHERE {new_name} IS NULL
                  AND {old_name} IS NOT NULL
                """
            )

    if "subscription_expires_at" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TEXT")
    ensure_user_column("vpn_enabled", "INTEGER NOT NULL DEFAULT 0")
    copy_legacy_user_column("w" + "g_enabled", "vpn_enabled")
    if "preferred_billing_mode" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN preferred_billing_mode TEXT NOT NULL DEFAULT 'duration'"
        )
    if "traffic_quota_bytes" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN traffic_quota_bytes INTEGER NOT NULL DEFAULT 0")
    if "traffic_used_bytes" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN traffic_used_bytes INTEGER NOT NULL DEFAULT 0")
    if "traffic_last_total_bytes" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN traffic_last_total_bytes INTEGER NOT NULL DEFAULT 0"
        )
    if "force_password_change" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN force_password_change INTEGER NOT NULL DEFAULT 0"
        )
    if "email_verified" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
    if "preferred_server_id" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN preferred_server_id INTEGER")
    if "assigned_server_id" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN assigned_server_id INTEGER")
    ensure_user_column("kcptun_ingress_port", "INTEGER")
    copy_legacy_user_column("w" + "g_ingress_port", "kcptun_ingress_port")
    if "openvpn_ingress_port" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_ingress_port INTEGER")
    ensure_user_column("vpn_internal_ip", "TEXT")
    copy_legacy_user_column("assigned" + "_ip", "vpn_internal_ip")
    ensure_user_column("archived_private_token", "TEXT")
    copy_legacy_user_column("client" + "_private_key", "archived_private_token")
    ensure_user_column("archived_public_token", "TEXT")
    copy_legacy_user_column("client" + "_public_key", "archived_public_token")
    ensure_user_column("archived_shared_token", "TEXT")
    copy_legacy_user_column("client" + "_psk", "archived_shared_token")
    ensure_user_column("archived_profile_file", "TEXT")
    copy_legacy_user_column("config" + "_path", "archived_profile_file")
    ensure_user_column("archived_qr_file", "TEXT")
    copy_legacy_user_column("qr" + "_path", "archived_qr_file")
    ensure_user_column("client_config_token", "TEXT")
    if "openvpn_common_name" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_common_name TEXT")
    if "openvpn_client_cert" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_client_cert TEXT")
    if "openvpn_client_key" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_client_key TEXT")
    if "last_login_ip" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN last_login_ip TEXT")
    if "last_login_at" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
    if "session_version" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
    db.execute(
        """
        UPDATE users
        SET preferred_billing_mode = ?
        WHERE preferred_billing_mode IS NULL OR trim(preferred_billing_mode) = ''
        """,
        (PLAN_MODE_DURATION,),
    )
    db.execute(
        """
        UPDATE users
        SET preferred_billing_mode = ?
        WHERE lower(trim(preferred_billing_mode)) NOT IN ('duration', 'traffic')
        """,
        (PLAN_MODE_DURATION,),
    )

    order_columns = {
        row["name"]: row
        for row in get_table_columns(db, "payment_orders")
    }
    if "plan_id" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_id INTEGER")
    if "plan_name" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_name TEXT")
    if "plan_mode" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_mode TEXT")
    if "plan_duration_months" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_duration_months INTEGER")
    if "plan_duration_value" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_duration_value INTEGER")
    if "plan_duration_unit" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_duration_unit TEXT")
    if "plan_traffic_gb" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_traffic_gb INTEGER")
    if "payment_method" not in order_columns:
        db.execute(
            "ALTER TABLE payment_orders ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'usdt'"
        )
    if "usdt_network" not in order_columns:
        db.execute(
            "ALTER TABLE payment_orders ADD COLUMN usdt_network TEXT NOT NULL DEFAULT 'TRC20'"
        )
    if "usdt_amount" not in order_columns:
        db.execute(
            "ALTER TABLE payment_orders ADD COLUMN usdt_amount TEXT NOT NULL DEFAULT '0'"
        )
    if "pay_to_address" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN pay_to_address TEXT")
    if "tx_hash" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN tx_hash TEXT")
    if "tx_submitted_at" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN tx_submitted_at TEXT")
    if "expires_at" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN expires_at TEXT")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id SERIAL PRIMARY KEY,
            plan_name TEXT NOT NULL,
            billing_mode TEXT NOT NULL,
            duration_months INTEGER,
            duration_value INTEGER,
            duration_unit TEXT,
            traffic_gb INTEGER,
            price_usdt TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    plan_columns = {
        row["name"]: row
        for row in get_table_columns(db, "subscription_plans")
    }
    if "duration_value" not in plan_columns:
        db.execute("ALTER TABLE subscription_plans ADD COLUMN duration_value INTEGER")
    if "duration_unit" not in plan_columns:
        db.execute("ALTER TABLE subscription_plans ADD COLUMN duration_unit TEXT")
    db.execute(
        """
        UPDATE subscription_plans
        SET duration_unit = ?
        WHERE duration_unit IS NULL OR TRIM(duration_unit) = ''
        """,
        (PLAN_DURATION_UNIT_MONTH,),
    )
    db.execute(
        """
        UPDATE subscription_plans
        SET duration_value = duration_months
        WHERE billing_mode = ? AND (duration_value IS NULL OR duration_value <= 0) AND duration_months > 0
        """,
        (PLAN_MODE_DURATION,),
    )
    db.execute(
        """
        UPDATE payment_orders
        SET plan_duration_unit = ?
        WHERE plan_duration_unit IS NULL OR TRIM(plan_duration_unit) = ''
        """,
        (PLAN_DURATION_UNIT_MONTH,),
    )
    db.execute(
        """
        UPDATE payment_orders
        SET plan_duration_value = COALESCE(NULLIF(plan_duration_months, 0), NULLIF(plan_months, 0))
        WHERE plan_mode = ? AND (plan_duration_value IS NULL OR plan_duration_value <= 0)
        """,
        (PLAN_MODE_DURATION,),
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_methods (
            id SERIAL PRIMARY KEY,
            method_code TEXT NOT NULL DEFAULT 'usdt',
            method_name TEXT NOT NULL,
            network TEXT NOT NULL DEFAULT 'TRC20',
            receive_address TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    payment_method_columns = {
        row["name"]: row
        for row in get_table_columns(db, "payment_methods")
    }
    if "method_code" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN method_code TEXT NOT NULL DEFAULT 'usdt'")
    if "method_name" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN method_name TEXT NOT NULL DEFAULT 'USDT'")
    if "network" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN network TEXT NOT NULL DEFAULT 'TRC20'")
    if "receive_address" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN receive_address TEXT NOT NULL DEFAULT ''")
    if "is_active" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    if "sort_order" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
    if "created_at" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
    if "updated_at" not in payment_method_columns:
        db.execute("ALTER TABLE payment_methods ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL,
            code TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            ip_address TEXT,
            expire_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        )
        """
    )
    email_verification_columns = {
        row["name"]: row
        for row in get_table_columns(db, "email_verifications")
    }
    if "purpose" not in email_verification_columns:
        db.execute(
            "ALTER TABLE email_verifications ADD COLUMN purpose TEXT NOT NULL DEFAULT 'register'"
        )
    if "ip_address" not in email_verification_columns:
        db.execute("ALTER TABLE email_verifications ADD COLUMN ip_address TEXT")
    if "used_at" not in email_verification_columns:
        db.execute("ALTER TABLE email_verifications ADD COLUMN used_at TEXT")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_servers (
            id SERIAL PRIMARY KEY,
            server_name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 587,
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            from_email TEXT NOT NULL,
            from_name TEXT NOT NULL DEFAULT '',
            security TEXT NOT NULL DEFAULT 'starttls',
            is_active INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    mail_server_columns = {
        row["name"]: row
        for row in get_table_columns(db, "mail_servers")
    }
    if "server_name" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN server_name TEXT NOT NULL DEFAULT ''")
    if "host" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN host TEXT NOT NULL DEFAULT ''")
    if "port" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN port INTEGER NOT NULL DEFAULT 587")
    if "username" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN username TEXT NOT NULL DEFAULT ''")
    if "password" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN password TEXT NOT NULL DEFAULT ''")
    if "from_email" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN from_email TEXT NOT NULL DEFAULT ''")
    if "from_name" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN from_name TEXT NOT NULL DEFAULT ''")
    if "security" not in mail_server_columns:
        db.execute(
            "ALTER TABLE mail_servers ADD COLUMN security TEXT NOT NULL DEFAULT 'starttls'"
        )
    if "is_active" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0")
    if "sort_order" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 100")
    if "created_at" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
    if "updated_at" not in mail_server_columns:
        db.execute("ALTER TABLE mail_servers ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS vpn_servers (
            id SERIAL PRIMARY KEY,
            server_name TEXT NOT NULL,
            server_region TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ssh_private_key TEXT NOT NULL DEFAULT '',
            domain TEXT,
            vpn_api_token TEXT,
            kcptun_port INTEGER NOT NULL DEFAULT 51820,
            openvpn_port INTEGER NOT NULL DEFAULT 443,
            dns_port INTEGER NOT NULL DEFAULT 53,
            openvpn_enabled INTEGER NOT NULL DEFAULT 1,
            shadowsocks_enabled INTEGER NOT NULL DEFAULT 0,
            kcptun_enabled INTEGER NOT NULL DEFAULT 0,
            ssh_tunnel_enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            last_test_at TEXT,
            last_test_ok INTEGER NOT NULL DEFAULT 0,
            last_test_message TEXT,
            last_deploy_at TEXT,
            last_deploy_ok INTEGER NOT NULL DEFAULT 0,
            last_deploy_message TEXT,
            last_deploy_log TEXT,
            last_allocated_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    vpn_server_columns = {
        row["name"]: row
        for row in get_table_columns(db, "vpn_servers")
    }
    if "server_name" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN server_name TEXT NOT NULL DEFAULT ''")
    if "server_region" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN server_region TEXT NOT NULL DEFAULT ''")
    if "host" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN host TEXT NOT NULL DEFAULT ''")
    if "port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN port INTEGER NOT NULL DEFAULT 22")
    if "username" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN username TEXT NOT NULL DEFAULT 'root'")
    if "password" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN password TEXT NOT NULL DEFAULT ''")
    if "ssh_private_key" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN ssh_private_key TEXT NOT NULL DEFAULT ''")
    if "domain" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN domain TEXT")
    if "vpn_api_token" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN vpn_api_token TEXT")
    if "kcptun_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN kcptun_port INTEGER NOT NULL DEFAULT 51820")
    if "openvpn_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN openvpn_port INTEGER NOT NULL DEFAULT 443")
    if "dns_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN dns_port INTEGER NOT NULL DEFAULT 53")
    if "openvpn_enabled" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN openvpn_enabled INTEGER NOT NULL DEFAULT 1")
    if "shadowsocks_enabled" not in vpn_server_columns:
        db.execute(
            "ALTER TABLE vpn_servers ADD COLUMN shadowsocks_enabled INTEGER NOT NULL DEFAULT 0"
        )
    if "kcptun_enabled" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN kcptun_enabled INTEGER NOT NULL DEFAULT 0")
    if "ssh_tunnel_enabled" not in vpn_server_columns:
        db.execute(
            "ALTER TABLE vpn_servers ADD COLUMN ssh_tunnel_enabled INTEGER NOT NULL DEFAULT 1"
        )
    if "status" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if "last_test_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_test_at TEXT")
    if "last_test_ok" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_test_ok INTEGER NOT NULL DEFAULT 0")
    if "last_test_message" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_test_message TEXT")
    if "last_deploy_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_deploy_at TEXT")
    if "last_deploy_ok" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_deploy_ok INTEGER NOT NULL DEFAULT 0")
    if "last_deploy_message" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_deploy_message TEXT")
    if "last_deploy_log" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_deploy_log TEXT")
    if "last_allocated_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN last_allocated_at TEXT")
    if "created_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
    if "updated_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloudflare_accounts (
            id SERIAL PRIMARY KEY,
            account_name TEXT NOT NULL,
            api_token TEXT NOT NULL,
            zone_name TEXT NOT NULL,
            zone_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cloudflare_columns = {
        row["name"]: row
        for row in get_table_columns(db, "cloudflare_accounts")
    }
    if "account_name" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN account_name TEXT NOT NULL DEFAULT ''"
        )
    if "api_token" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN api_token TEXT NOT NULL DEFAULT ''"
        )
    if "zone_name" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN zone_name TEXT NOT NULL DEFAULT ''"
        )
    if "zone_id" not in cloudflare_columns:
        db.execute("ALTER TABLE cloudflare_accounts ADD COLUMN zone_id TEXT")
    if "is_active" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
        )
    if "sort_order" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"
        )
    if "created_at" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
        )
    if "updated_at" not in cloudflare_columns:
        db.execute(
            "ALTER TABLE cloudflare_accounts ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''"
        )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_domains (
            id SERIAL PRIMARY KEY,
            domain_name TEXT NOT NULL,
            cloudflare_account_id INTEGER,
            assigned_server_id INTEGER,
            dns_record_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            last_sync_at TEXT,
            last_sync_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (cloudflare_account_id) REFERENCES cloudflare_accounts(id) ON DELETE SET NULL,
            FOREIGN KEY (assigned_server_id) REFERENCES vpn_servers(id) ON DELETE SET NULL
        )
        """
    )
    managed_domain_columns = {
        row["name"]: row
        for row in get_table_columns(db, "managed_domains")
    }
    if "domain_name" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN domain_name TEXT NOT NULL DEFAULT ''")
    if "cloudflare_account_id" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN cloudflare_account_id INTEGER")
    if "assigned_server_id" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN assigned_server_id INTEGER")
    if "dns_record_id" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN dns_record_id TEXT")
    if "is_active" not in managed_domain_columns:
        db.execute(
            "ALTER TABLE managed_domains ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
        )
    if "sort_order" not in managed_domain_columns:
        db.execute(
            "ALTER TABLE managed_domains ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"
        )
    if "last_sync_at" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN last_sync_at TEXT")
    if "last_sync_message" not in managed_domain_columns:
        db.execute("ALTER TABLE managed_domains ADD COLUMN last_sync_message TEXT")
    if "created_at" not in managed_domain_columns:
        db.execute(
            "ALTER TABLE managed_domains ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
        )
    if "updated_at" not in managed_domain_columns:
        db.execute(
            "ALTER TABLE managed_domains ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''"
        )

    # Normalize role values from historical/dirty data so admin user list queries stay stable.
    db.execute(
        """
        UPDATE users
        SET role = CASE
            WHEN role IS NULL OR trim(role) = '' THEN 'user'
            WHEN lower(trim(role)) = 'admin' THEN 'admin'
            WHEN lower(trim(role)) = 'user' THEN 'user'
            ELSE 'user'
        END
        WHERE role IS NULL
           OR trim(role) = ''
           OR lower(trim(role)) NOT IN ('admin', 'user')
           OR role <> lower(trim(role))
        """
    )


def ensure_admin_user() -> None:
    admin_username = os.environ.get("ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
    admin_password = os.environ.get("ADMIN_PASSWORD", DEFAULT_ADMIN_INITIAL_PASSWORD)

    db = get_db()
    existing = db.execute(
        "SELECT id, password_hash, force_password_change FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
    ).fetchone()
    if existing:
        # If admin still uses default initial password, force password reset.
        if (
            check_password_hash(existing["password_hash"], DEFAULT_ADMIN_INITIAL_PASSWORD)
            and int(row_get(existing, "force_password_change", 0) or 0) != 1
        ):
            db.execute(
                "UPDATE users SET force_password_change = 1 WHERE id = ?",
                (existing["id"],),
            )
            db.commit()
        return

    try:
        db.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash,
                role,
                status,
                email_verified,
                created_at,
                approved_at,
                force_password_change,
                session_version
            )
            VALUES (?, ?, ?, 'admin', 'approved', 1, ?, ?, 1, 1)
            """,
            (
                admin_username,
                f"{admin_username}@local",
                generate_password_hash(admin_password),
                utcnow_iso(),
                utcnow_iso(),
            ),
        )
        db.commit()
    except DB_INTEGRITY_ERRORS:
        db.rollback()


@app.context_processor
def inject_user():
    db = get_db()
    payment_settings = load_payment_settings(db)
    system_settings = load_system_settings(db)
    active_user = current_user()
    domain_label = display_label_from_host(request.host, default="Stream")
    version_nav = None
    if active_user and row_get(active_user, "role", "") == "admin":
        force_version_check = session.get("admin_version_checked") != "1"
        version_nav = load_version_nav_state(
            base_dir=BASE_DIR,
            data_dir=DATA_DIR,
            branch=HOST_WEB_UPGRADE_BRANCH or detect_origin_default_branch(),
            force_check=force_version_check,
        )
        session["admin_version_checked"] = "1"
    return {
        "current_user": active_user,
        "usdt_receive_address": payment_settings["usdt_receive_address"],
        "usdt_default_network": payment_settings["usdt_default_network"],
        "usdt_network_options": USDT_NETWORK_OPTIONS,
        "vpn_enabled": bool(False and system_settings["vpn_open"]),
        "openvpn_enabled": bool(OPENVPN_ENABLED and system_settings["openvpn_open"]),
        "shadowsocks_enabled": bool(SHADOWSOCKS_ENABLED),
        "kcptun_enabled": False,
        "registration_open": bool(system_settings["registration_open"]),
        "telegram_contact": str(system_settings["telegram_contact"]),
        "site_title": domain_label,
        "guest_brand_label": domain_label,
        "version_nav": version_nav,
    }


@app.before_request
def enforce_session_idle_timeout():
    endpoint = request.endpoint or ""
    if endpoint == "static":
        return None

    user_id = session.get("user_id")
    if not user_id:
        return None

    now_ts = int(time.time())
    last_activity_raw = session.get(SESSION_LAST_ACTIVITY_KEY)
    last_activity_ts = 0
    if last_activity_raw is not None:
        try:
            last_activity_ts = int(last_activity_raw)
        except Exception:
            last_activity_ts = 0

    if (
        last_activity_ts > 0
        and now_ts - last_activity_ts >= SESSION_IDLE_TIMEOUT_SECONDS
    ):
        session.clear()
        if request.path.startswith("/api/"):
            return {"ok": False, "error": "session_expired"}, 401
        flash("会话超时，请重新登录。", "error")
        return redirect(url_for("login"))

    session[SESSION_LAST_ACTIVITY_KEY] = now_ts
    return None


@app.before_request
def auto_reconcile_subscriptions():
    if request.endpoint == "static":
        return None
    try:
        db = get_db()
        cleanup_verification_records(db)
        expire_pending_orders(db)
        reconcile_expired_subscriptions(db)
        user_id = session.get("user_id")
        if user_id:
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user and user["role"] == "user":
                sync_user_traffic_usage(db, user)
        db.commit()
    except Exception:
        app.logger.exception("Failed to reconcile expired subscriptions")
    return None


@app.before_request
def enforce_admin_password_change():
    endpoint = request.endpoint or ""
    if endpoint == "static":
        return None

    user = current_user()
    if not admin_must_change_password(user):
        return None

    allowed_endpoints = {"logout", "admin_change_password", "static"}
    if endpoint in allowed_endpoints:
        return None

    if request.path.startswith("/api/"):
        return {
            "ok": False,
            "error": "admin_password_change_required",
            "redirect": url_for("admin_change_password"),
        }, 403

    flash("首次登录请先修改管理员密码。", "error")
    return redirect(url_for("admin_change_password"))


@app.before_request
def enforce_admin_onboarding():
    # PRD V1 only mandates default-password forced change for admin.
    # Onboarding wizard should not block admin routes.
    return None


@app.before_request
def block_non_prd_admin_features():
    endpoint = request.endpoint or ""
    if endpoint == "static":
        return None

    blocked_by_name = endpoint in PRD_BLOCKED_ADMIN_ENDPOINTS or "domain" in endpoint
    blocked_by_marker = any(marker in endpoint for marker in PRD_BLOCKED_ADMIN_ENDPOINT_MARKERS)
    if not (blocked_by_name or blocked_by_marker):
        return None

    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if row_get(user, "role") != "admin":
        flash("仅管理员可访问。", "error")
        return redirect(url_for("dashboard"))

    flash("当前版本按 PRD V1 运行，该功能未纳入文档，已禁用。", "error")
    return redirect(url_for("admin_subscriptions"))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            flash("仅管理员可访问。", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped



def use_vpn_api(*, user: DatabaseRow | None = None, server_row: DatabaseRow | None = None) -> bool:
    if server_row is not None:
        host = normalize_remote_host(row_get(server_row, "host", ""))
        token = (row_get(server_row, "vpn_api_token", "") or "").strip()
        return bool(host and token)
    api_url, _, _ = get_runtime_vpn_api_target(user=user)
    return bool(api_url)


def get_runtime_vpn_api_target(
    *,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
    allow_reassign: bool = True,
) -> tuple[str, str, DatabaseRow | None]:
    if server_row is not None:
        host = normalize_remote_host(row_get(server_row, "host", ""))
        token = (row_get(server_row, "vpn_api_token", "") or "").strip()
        if host and token:
            host_url = host_for_http_url(host)
            return f"http://{host_url}:{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}", token, server_row
        return "", "", None

    if VPN_API_URL:
        return VPN_API_URL, VPN_API_TOKEN, None

    try:
        db = get_db()
    except Exception:
        return "", "", None

    if user is not None and row_get(user, "role") == "user":
        selected = choose_runtime_server_for_user(db, user, allow_reassign=allow_reassign)
        if not selected:
            return "", "", None
        host = normalize_remote_host(row_get(selected, "host", ""))
        token = (row_get(selected, "vpn_api_token", "") or "").strip()
        if not host or not token:
            return "", "", None
        host_url = host_for_http_url(host)
        return f"http://{host_url}:{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}", token, selected

    selected = choose_runtime_server_for_admin(db, user)
    if not selected:
        return "", "", None

    status = (row_get(selected, "status", "") or "").strip().lower()
    if status != "online":
        return "", "", None

    host = normalize_remote_host(row_get(selected, "host", ""))
    token = (row_get(selected, "vpn_api_token", "") or "").strip()
    if not host or not token:
        return "", "", None

    host_url = host_for_http_url(host)
    return f"http://{host_url}:{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}", token, selected


def vpn_api_request(
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
    allow_reassign: bool = True,
) -> dict:
    runtime_api_url, runtime_api_token, _ = get_runtime_vpn_api_target(
        user=user,
        server_row=server_row,
        allow_reassign=allow_reassign,
    )
    if not runtime_api_url:
        raise RuntimeError("VPN 服务未配置，请先在后台完成服务器部署。")

    return request_vpn_api(
        method,
        f"{runtime_api_url}{path}",
        token=runtime_api_token,
        path=path,
        payload=payload,
        timeout_seconds=VPN_API_TIMEOUT_SECONDS,
    )


def iter_runtime_vpn_api_targets(db: DatabaseConnection) -> list[DatabaseRow | None]:
    rows = db.execute(
        """
        SELECT *
        FROM vpn_servers
        WHERE status = 'online'
          AND trim(COALESCE(host, '')) <> ''
          AND trim(COALESCE(vpn_api_token, '')) <> ''
        ORDER BY id ASC
        """
    ).fetchall()
    if rows:
        return list(rows)
    if VPN_API_URL:
        return [None]
    return []


def sync_runtime_protocol_state(
    db: DatabaseConnection,
    *,
    vpn_open: bool,
    openvpn_open: bool,
) -> None:
    for target in iter_runtime_vpn_api_targets(db):
        vpn_api_request(
            "POST",
            "/openvpn/control",
            {"action": "up" if vpn_open else "down"},
            server_row=target,
            allow_reassign=False,
        )
        vpn_api_request(
            "POST",
            "/openvpn/control",
            {"action": "start" if openvpn_open else "stop"},
            server_row=target,
            allow_reassign=False,
        )


def get_local_shadowsocks_active_peer_snapshot(
    ports: list[int] | set[int] | tuple[int, ...] | None = None,
) -> tuple[list[str], dict[str, dict[str, int]], dict[str, int], dict[int, dict[str, int]]]:
    use_ports = (
        sorted(
            {
                normalize_server_port(port, SHADOWSOCKS_SERVER_PORT)
                for port in (ports or [])
                if normalize_server_port(port, SHADOWSOCKS_SERVER_PORT) > 0
            }
        )
        if ports
        else [SHADOWSOCKS_SERVER_PORT]
    )
    raw = run_command(
        [
            "ss",
            "-Htni",
            "state",
            "established",
            build_shadowsocks_sport_filter_expr(
                use_ports,
                default_port=SHADOWSOCKS_SERVER_PORT,
                normalize_port=normalize_server_port,
            ),
        ],
        check=False,
    )
    return parse_shadowsocks_active_peer_snapshot(
        raw,
        server_ports=use_ports,
        default_port=SHADOWSOCKS_SERVER_PORT,
        normalize_port=normalize_server_port,
    )


def get_local_shadowsocks_active_peer_hosts() -> list[str]:
    peers, _peer_stats, _aggregate, _port_stats = get_local_shadowsocks_active_peer_snapshot()
    return peers


def get_local_kcptun_active_peer_hosts(window_seconds: int) -> list[str]:
    window = max(30, int(window_seconds or ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS))
    raw = run_command(
        [
            "journalctl",
            "-u",
            "vpnmanager-kcptun.service",
            "--since",
            f"-{window} seconds",
            "--no-pager",
            "-n",
            "800",
        ],
        check=False,
    )
    return parse_kcptun_active_peer_hosts(raw)


def get_runtime_active_peer_hosts(
    *,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
    window_seconds: int = ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
    requested_ports: list[int] | set[int] | tuple[int, ...] | None = None,
) -> tuple[
    list[str],
    str,
    dict[str, dict[str, int]],
    dict[str, int],
    dict[int, dict[str, int]],
]:
    ports = sorted(
        {
            normalize_server_port(port, SHADOWSOCKS_SERVER_PORT)
            for port in (requested_ports or [])
            if normalize_server_port(port, SHADOWSOCKS_SERVER_PORT) > 0
        }
    )
    if not ports:
        ports = [SHADOWSOCKS_SERVER_PORT]
    ports_query = ",".join(str(port) for port in ports)
    use_kcptun = runtime_uses_kcptun(server_row)
    if use_kcptun:
        detect_mode = "kcptun"
    else:
        detect_mode = "shadowsocks"
    if use_vpn_api(user=user, server_row=server_row):
        if use_kcptun:
            path = (
                f"/kcptun/active-peers?window={int(max(30, window_seconds))}&limit=800&ports={ports_query}"
            )
        else:
            path = f"/shadowsocks/active-peers?ports={ports_query}"
        result = vpn_api_request(
            "GET",
            path,
            user=user,
            server_row=server_row,
            allow_reassign=False,
        )
        peers = result.get("peers") if isinstance(result, dict) else []
        peer_stats_raw = result.get("peer_stats") if isinstance(result, dict) else {}
        aggregate_raw = result.get("aggregate") if isinstance(result, dict) else {}
        port_stats_raw = (
            result.get("aggregate_by_port")
            if isinstance(result, dict)
            else {}
        )
        cleaned: list[str] = []
        for item in peers or []:
            host = normalize_public_client_ip(str(item or ""))
            if host:
                cleaned.append(host)
        peer_stats: dict[str, dict[str, int]] = {}
        if isinstance(peer_stats_raw, dict):
            for host_raw, stat_raw in peer_stats_raw.items():
                host = normalize_public_client_ip(str(host_raw or ""))
                if not host:
                    continue
                stat_obj = stat_raw if isinstance(stat_raw, dict) else {}
                rx = to_non_negative_int(stat_obj.get("rx_bytes", 0))
                tx = to_non_negative_int(stat_obj.get("tx_bytes", 0))
                peer_stats[host] = {
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "total_bytes": to_non_negative_int(stat_obj.get("total_bytes", rx + tx)),
                }
        port_stats: dict[int, dict[str, int]] = {}
        if isinstance(port_stats_raw, dict):
            for port_raw, stat_raw in port_stats_raw.items():
                port = normalize_server_port(port_raw, 0)
                if port <= 0:
                    continue
                stat_obj = stat_raw if isinstance(stat_raw, dict) else {}
                rx = to_non_negative_int(stat_obj.get("rx_bytes", 0))
                tx = to_non_negative_int(stat_obj.get("tx_bytes", 0))
                total = to_non_negative_int(stat_obj.get("total_bytes", rx + tx))
                port_stats[int(port)] = {
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "total_bytes": total if total > 0 else (rx + tx),
                }
        aggregate = {
            "rx_bytes": to_non_negative_int(
                (aggregate_raw.get("rx_bytes", 0) if isinstance(aggregate_raw, dict) else 0)
            ),
            "tx_bytes": to_non_negative_int(
                (aggregate_raw.get("tx_bytes", 0) if isinstance(aggregate_raw, dict) else 0)
            ),
            "total_bytes": to_non_negative_int(
                (aggregate_raw.get("total_bytes", 0) if isinstance(aggregate_raw, dict) else 0)
            ),
        }
        if aggregate["total_bytes"] <= 0:
            aggregate["total_bytes"] = aggregate["rx_bytes"] + aggregate["tx_bytes"]
        return sorted(set(cleaned)), detect_mode, peer_stats, aggregate, port_stats
    if use_kcptun:
        peers = get_local_kcptun_active_peer_hosts(window_seconds)
        _ss_peers, _ss_stats, ss_aggregate, ss_port_stats = get_local_shadowsocks_active_peer_snapshot(ports)
        return peers, detect_mode, {}, ss_aggregate, ss_port_stats
    peers, peer_stats, aggregate, port_stats = get_local_shadowsocks_active_peer_snapshot(ports)
    return peers, detect_mode, peer_stats, aggregate, port_stats


def get_user_runtime_transfer_bytes(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    window_seconds: int = ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
) -> tuple[int, int]:
    hydrated_user = prepare_user_for_transport(user)
    runtime_server = server_row or get_runtime_server_for_account(hydrated_user)

    if SHADOWSOCKS_ENABLED:
        try:
            ss_port = get_user_shadowsocks_server_port(hydrated_user)
            _peers, _mode, peer_stats, aggregate_stats, port_stats = get_runtime_active_peer_hosts(
                user=hydrated_user,
                server_row=runtime_server,
                window_seconds=window_seconds,
                requested_ports=[ss_port],
            )
            stats_by_port = port_stats.get(ss_port, {})
            rx_by_port = to_non_negative_int(stats_by_port.get("rx_bytes", 0))
            tx_by_port = to_non_negative_int(stats_by_port.get("tx_bytes", 0))
            if rx_by_port > 0 or tx_by_port > 0:
                return rx_by_port, tx_by_port

            login_ip = normalize_public_client_ip(row_get(hydrated_user, "last_login_ip", ""))
            if login_ip:
                peer_state = peer_stats.get(login_ip, {})
                rx_by_ip = to_non_negative_int(peer_state.get("rx_bytes", 0))
                tx_by_ip = to_non_negative_int(peer_state.get("tx_bytes", 0))
                if rx_by_ip > 0 or tx_by_ip > 0:
                    return rx_by_ip, tx_by_ip

            rx_fallback = to_non_negative_int(aggregate_stats.get("rx_bytes", 0))
            tx_fallback = to_non_negative_int(aggregate_stats.get("tx_bytes", 0))
            if rx_fallback > 0 or tx_fallback > 0:
                return rx_fallback, tx_fallback
        except Exception:
            app.logger.exception("Failed to collect shadowsocks runtime transfer bytes")


    return 0, 0


def get_user_traffic_stats(user: DatabaseRow) -> dict[str, int | str]:
    rx_bytes, tx_bytes = get_user_runtime_transfer_bytes(user)
    total_bytes = rx_bytes + tx_bytes
    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    if quota_bytes > 0 and used_bytes > quota_bytes:
        used_bytes = quota_bytes
    remaining_bytes = max(0, quota_bytes - used_bytes)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    preferred_mode = get_user_preferred_billing_mode(user)
    effective_mode = get_user_effective_billing_mode(user)
    remaining_is_permanent = has_time and effective_mode == PLAN_MODE_DURATION
    if remaining_is_permanent:
        remaining_display = "永久"
    elif quota_bytes > 0:
        remaining_display = format_bytes(remaining_bytes)
    else:
        remaining_display = "-"

    if has_time:
        plan_total_display = "不限"
        plan_used_display = format_bytes(total_bytes)
        plan_remaining_display = "永久"
    elif quota_bytes > 0:
        plan_total_display = format_bytes(quota_bytes)
        plan_used_display = format_bytes(used_bytes)
        plan_remaining_display = format_bytes(remaining_bytes)
    else:
        plan_total_display = "-"
        plan_used_display = format_bytes(total_bytes)
        plan_remaining_display = "-"

    if quota_bytes > 0:
        plan_total_remaining_gb = (
            f"{format_bytes_in_gb(quota_bytes)} / {format_bytes_in_gb(remaining_bytes)}"
        )
    elif has_time:
        plan_total_remaining_gb = "不限 / 永久"
    else:
        plan_total_remaining_gb = "- / -"

    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "total_bytes": total_bytes,
        "rx_human": format_bytes(rx_bytes),
        "tx_human": format_bytes(tx_bytes),
        "total_human": format_bytes(total_bytes),
        "total_gb": format_bytes_in_gb(total_bytes),
        "download_mb": format_bytes_in_mb(tx_bytes),
        "upload_mb": format_bytes_in_mb(rx_bytes),
        "rx_mb": format_bytes_in_mb(rx_bytes),
        "tx_mb": format_bytes_in_mb(tx_bytes),
        "quota_bytes": quota_bytes,
        "used_bytes": used_bytes,
        "remaining_bytes": remaining_bytes,
        "quota_human": format_bytes(quota_bytes),
        "used_human": format_bytes(used_bytes),
        "remaining_human": format_bytes(remaining_bytes),
        "remaining_is_permanent": remaining_is_permanent,
        "remaining_display": remaining_display,
        "plan_total_display": plan_total_display,
        "plan_used_display": plan_used_display,
        "plan_remaining_display": plan_remaining_display,
        "plan_total_remaining_gb": plan_total_remaining_gb,
        "has_active_time": has_time,
        "has_active_traffic": has_traffic,
        "preferred_mode": preferred_mode,
        "preferred_mode_label": plan_mode_label(preferred_mode),
        "effective_mode": effective_mode,
        "effective_mode_label": plan_mode_label(effective_mode),
    }



def get_runtime_server_for_account(user: DatabaseRow | None) -> DatabaseRow | None:
    if not user:
        return None
    try:
        db = get_db()
        return get_persisted_runtime_server_for_account(db, user)
    except Exception:
        return None


def resolve_shadowsocks_endpoint_host(
    *,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
) -> str:
    request_host = ""
    try:
        request_host = request.host
    except Exception:
        request_host = ""
    return ss_profile_service.resolve_shadowsocks_endpoint_host(
        user=user,
        server_row=server_row,
        get_runtime_server_for_account=get_runtime_server_for_account,
        request_host=request_host,
    )


def prepare_user_for_transport(user: DatabaseRow) -> DatabaseRow:
    return ss_profile_service.prepare_user_for_transport(
        user,
        get_db=get_db,
        ensure_user_transport_ports=ensure_user_transport_ports,
    )


def derive_user_shadowsocks_password(user: DatabaseRow) -> str:
    return ss_profile_service.derive_user_shadowsocks_password(
        user,
        get_user_shadowsocks_server_port=get_user_shadowsocks_server_port,
        derive_shadowsocks_password_for_port=derive_shadowsocks_password_for_port,
    )


def build_user_shadowsocks_config(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
) -> str:
    return ss_profile_service.build_user_shadowsocks_config(
        user,
        server_row=server_row,
        prepare_user=prepare_user_for_transport,
        resolve_host=resolve_shadowsocks_endpoint_host,
        get_user_shadowsocks_server_port=get_user_shadowsocks_server_port,
        derive_user_password=derive_user_shadowsocks_password,
    )


def build_user_kcptun_config(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
) -> str:
    return ss_profile_service.build_user_kcptun_config(
        user,
        server_row=server_row,
        prepare_user=prepare_user_for_transport,
        resolve_host=resolve_shadowsocks_endpoint_host,
    )


def build_user_kcptun_clash_profile(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
) -> str:
    return ss_profile_service.build_user_kcptun_clash_profile(
        user,
        server_row=server_row,
        prepare_user=prepare_user_for_transport,
        get_runtime_server_for_account=get_runtime_server_for_account,
        resolve_host=resolve_shadowsocks_endpoint_host,
        get_server_kcptun_port=get_server_kcptun_port,
        derive_shadowsocks_password_for_port=derive_shadowsocks_password_for_port,
    )


def build_user_shadowsocks_clash_profile(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
) -> str:
    return ss_profile_service.build_user_shadowsocks_clash_profile(
        user,
        server_row=server_row,
        prepare_user=prepare_user_for_transport,
        get_runtime_server_for_account=get_runtime_server_for_account,
        resolve_host=resolve_shadowsocks_endpoint_host,
        get_user_shadowsocks_server_port=get_user_shadowsocks_server_port,
        derive_user_password=derive_user_shadowsocks_password,
        derive_shadowsocks_password_for_port=derive_shadowsocks_password_for_port,
        get_server_kcptun_port=get_server_kcptun_port,
    )


def build_user_shadowsocks_uri(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
) -> str:
    return ss_profile_service.build_user_shadowsocks_uri(
        user,
        server_row=server_row,
        prepare_user=prepare_user_for_transport,
        resolve_host=resolve_shadowsocks_endpoint_host,
        get_user_shadowsocks_server_port=get_user_shadowsocks_server_port,
        derive_user_password=derive_user_shadowsocks_password,
    )


def ensure_user_vpn_ready(
    db: DatabaseConnection,
    user: DatabaseRow,
    *,
    force_new_ip: bool = False,
) -> dict[str, str | int]:
    if row_get(user, "role") == "user":
        ensure_user_ingress_ports(db, user)
        user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()

    role = (row_get(user, "role", "") or "").strip().lower()
    target_server = None
    if role in {"user", "admin"}:
        target_server = select_runtime_server_for_account(
            db,
            user,
            allow_reassign=(role == "user"),
        )
        if role == "user" and (not target_server) and user_prefers_managed_nodes(db, user):
            raise RuntimeError("当前没有可用在线节点，请联系管理员检查服务器状态。")

    if OPENVPN_ENABLED:
        ensure_user_openvpn_client_identity(db, user)

    result: dict[str, str | int] = {
        "vpn_enabled": 1,
        "vpn_internal_ip": "",
        "archived_private_token": "",
        "archived_public_token": "",
        "archived_shared_token": "",
        "archived_profile_file": "",
        "archived_qr_file": "",
    }
    if target_server:
        result["assigned_server_id"] = int(target_server["id"])
    return result

def ensure_admin_self_vpn_ready(
    db: DatabaseConnection,
    admin_user: DatabaseRow,
) -> DatabaseRow:
    if row_get(admin_user, "role") != "admin":
        raise ValueError("仅管理员可使用自用 VPN 配置。")

    vpn_data = ensure_user_vpn_ready(db, admin_user)
    assigned_server_id = vpn_data.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(admin_user, "assigned_server_id")
    db.execute(
        """
        UPDATE users
        SET assigned_server_id = ?,
            vpn_enabled = 1,
            subscription_expires_at = NULL,
            traffic_quota_bytes = 0,
            traffic_used_bytes = 0,
            traffic_last_total_bytes = 0
        WHERE id = ? AND role = 'admin'
        """,
        (assigned_server_id, admin_user["id"]),
    )
    db.commit()
    return db.execute("SELECT * FROM users WHERE id = ?", (admin_user["id"],)).fetchone()

def admin_self_vpn_needs_prepare(admin_user: DatabaseRow | None) -> bool:
    if not admin_user or row_get(admin_user, "role") != "admin":
        return True
    if OPENVPN_ENABLED:
        return not all(
            [
                int(row_get(admin_user, "vpn_enabled", 0) or 0) == 1,
                (row_get(admin_user, "openvpn_common_name", "") or "").strip(),
                (row_get(admin_user, "openvpn_client_cert", "") or "").strip(),
                (row_get(admin_user, "openvpn_client_key", "") or "").strip(),
            ]
        )
    return int(row_get(admin_user, "vpn_enabled", 0) or 0) != 1

def enforce_admin_unlimited_entitlement(db: DatabaseConnection, admin_user_id: int) -> None:
    db.execute(
        """
        UPDATE users
        SET subscription_expires_at = NULL,
            traffic_quota_bytes = 0,
            traffic_used_bytes = 0,
            traffic_last_total_bytes = 0,
            vpn_enabled = 1
        WHERE id = ? AND role = 'admin'
        """,
        (int(admin_user_id),),
    )


def ensure_admin_self_vpn_profile(
    db: DatabaseConnection,
    admin_user: DatabaseRow,
    *,
    force_prepare: bool = False,
) -> tuple[DatabaseRow, bool]:
    if row_get(admin_user, "role") != "admin":
        raise ValueError("仅管理员可使用自用 VPN 配置。")

    prepared_now = False
    refreshed = admin_user
    if force_prepare or admin_self_vpn_needs_prepare(admin_user):
        # Admin profile should be generated from an online managed node (or explicit global VPN_API_URL).
        # Without that, avoid falling back to local `runtime` command in web runtime.
        if not (VPN_API_URL or "").strip():
            target_server = select_runtime_server_for_account(
                db,
                admin_user,
                allow_reassign=False,
            )
            if target_server is None:
                raise RuntimeError("没有服务器，请添加服务器后生成配置。")
        refreshed = ensure_admin_self_vpn_ready(db, admin_user)
        prepared_now = True

    enforce_admin_unlimited_entitlement(db, int(refreshed["id"]))
    db.commit()
    latest = db.execute("SELECT * FROM users WHERE id = ?", (refreshed["id"],)).fetchone()
    if not latest:
        raise RuntimeError("管理员账号不存在。")
    return latest, prepared_now


def calculate_new_expiry(current_expire_iso: str | None, months: int) -> str:
    now = utcnow()
    current_expire = parse_iso(current_expire_iso)

    if current_expire and current_expire >= now:
        period_start = current_expire + timedelta(seconds=1)
    else:
        period_start = now

    period_end = add_months(period_start, months) - timedelta(seconds=1)
    return period_end.isoformat()


def calculate_new_expiry_by_duration(
    current_expire_iso: str | None,
    duration_value: int,
    duration_unit: str | None,
) -> str:
    value = max(1, int(duration_value or 0))
    unit = normalize_duration_unit(duration_unit)
    now = utcnow()
    current_expire = parse_iso(current_expire_iso)

    if current_expire and current_expire >= now:
        period_start = current_expire + timedelta(seconds=1)
    else:
        period_start = now

    if unit == PLAN_DURATION_UNIT_DAY:
        period_end = period_start + timedelta(days=value) - timedelta(seconds=1)
    elif unit == PLAN_DURATION_UNIT_YEAR:
        period_end = add_months(period_start, value * 12) - timedelta(seconds=1)
    else:
        period_end = add_months(period_start, value) - timedelta(seconds=1)
    return period_end.isoformat()


def has_active_time_subscription(user: DatabaseRow) -> bool:
    role = (row_get(user, "role", "") or "").strip().lower()
    status = (row_get(user, "status", "approved") or "approved").strip().lower()
    return role in {"user", "admin"} and status != "disabled"


def has_active_traffic_subscription(user: DatabaseRow) -> bool:
    return False


def get_user_preferred_billing_mode(user: DatabaseRow) -> str:
    return normalize_plan_mode(row_get(user, "preferred_billing_mode", PLAN_MODE_DURATION))


def get_user_effective_billing_mode(user: DatabaseRow) -> str:
    preferred_mode = get_user_preferred_billing_mode(user)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    if preferred_mode == PLAN_MODE_TRAFFIC and has_traffic:
        return PLAN_MODE_TRAFFIC
    if preferred_mode == PLAN_MODE_DURATION and has_time:
        return PLAN_MODE_DURATION
    if has_time:
        return PLAN_MODE_DURATION
    if has_traffic:
        return PLAN_MODE_TRAFFIC
    return preferred_mode


def sync_user_traffic_usage(
    db: DatabaseConnection,
    user: DatabaseRow,
    *,
    current_total_bytes: int | None = None,
) -> DatabaseRow:
    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    if quota_bytes <= 0:
        return user

    used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    last_total_bytes = to_non_negative_int(row_get(user, "traffic_last_total_bytes", 0))
    if current_total_bytes is None:
        rx_bytes, tx_bytes = get_user_runtime_transfer_bytes(user)
        current_total_bytes = rx_bytes + tx_bytes
    current_total_bytes = max(0, int(current_total_bytes))
    effective_mode = get_user_effective_billing_mode(user)
    if (
        has_active_time_subscription(user)
        and effective_mode == PLAN_MODE_DURATION
        and current_total_bytes != last_total_bytes
    ):
        db.execute(
            "UPDATE users SET traffic_last_total_bytes = ? WHERE id = ?",
            (current_total_bytes, user["id"]),
        )
        db.commit()
        return db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    traffic_delta = current_total_bytes - last_total_bytes
    if traffic_delta < 0:
        # runtime counter may reset after interface restart; skip negative delta
        traffic_delta = 0
    new_used_bytes = used_bytes + traffic_delta
    if new_used_bytes > quota_bytes:
        new_used_bytes = quota_bytes

    changed = False
    if new_used_bytes != used_bytes or current_total_bytes != last_total_bytes:
        db.execute(
            """
            UPDATE users
            SET traffic_used_bytes = ?,
                traffic_last_total_bytes = ?
            WHERE id = ?
            """,
            (new_used_bytes, current_total_bytes, user["id"]),
        )
        changed = True

    exhausted = quota_bytes > 0 and new_used_bytes >= quota_bytes
    if exhausted and int(row_get(user, "vpn_enabled", 0) or 0) == 1 and not has_active_time_subscription(user):
        db.execute("UPDATE users SET vpn_enabled = 0 WHERE id = ?", (user["id"],))
        changed = True

    if changed:
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return user


def is_subscription_active(user: DatabaseRow) -> bool:
    if int(row_get(user, "vpn_enabled", 0) or 0) != 1:
        return False
    return has_active_time_subscription(user)


def reconcile_expired_subscriptions(db: DatabaseConnection) -> None:
    return None


def get_nested_value(payload: dict, *paths: str):
    for path in paths:
        current = payload
        ok = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                ok = False
                break
        if ok:
            return current
    return None


def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    if not PAYMENT_WEBHOOK_SECRET:
        return False
    if not signature_header:
        return False

    provided = signature_header.strip()
    if "=" in provided:
        prefix, value = provided.split("=", 1)
        if prefix.lower() in ("sha256", "hmac-sha256"):
            provided = value
    provided = provided.strip().lower()
    expected = hmac.new(
        PAYMENT_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest().lower()
    return hmac.compare_digest(provided, expected)


def settle_order_paid(
    db: DatabaseConnection,
    order_id: int,
    *,
    tx_hash: str | None = None,
    paid_at_iso: str | None = None,
    source: str = "admin",
    require_tx_hash: bool = True,
    webhook_amount: Decimal | None = None,
    webhook_network: str | None = None,
):
    begin_immediate(db)
    order = db.execute(
        "SELECT * FROM payment_orders WHERE id = ?",
        (order_id,),
    ).fetchone()
    if not order:
        db.rollback()
        raise ValueError("订单不存在。")
    if order["status"] == "paid":
        db.rollback()
        return {"status": "already_paid"}
    if order["status"] != "pending":
        db.rollback()
        raise ValueError("订单状态不是待确认。")

    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user'",
        (order["user_id"],),
    ).fetchone()
    if not user:
        db.rollback()
        raise ValueError("用户不存在。")

    method = (order["payment_method"] or "usdt").lower()
    final_tx_hash = (tx_hash or order["tx_hash"] or "").strip()
    if method == "usdt":
        if require_tx_hash and not final_tx_hash:
            db.rollback()
            raise ValueError("USDT 订单缺少交易哈希。")
        if webhook_network and order["usdt_network"]:
            if webhook_network.upper() != str(order["usdt_network"]).upper():
                db.rollback()
                raise ValueError("Webhook 网络与订单网络不一致。")
        if webhook_amount is not None:
            required_amount = Decimal(str(order["usdt_amount"] or "0"))
            if webhook_amount < required_amount:
                db.rollback()
                raise ValueError("Webhook 金额小于订单金额。")
        if final_tx_hash:
            duplicate = db.execute(
                """
                SELECT id, status FROM payment_orders
                WHERE tx_hash = ? AND id <> ?
                LIMIT 1
                """,
                (final_tx_hash, order_id),
            ).fetchone()
            if duplicate and duplicate["status"] == "paid":
                db.rollback()
                raise ValueError("该交易哈希已用于其他已支付订单。")

    plan_snapshot = resolve_order_plan_snapshot(order)
    plan_mode = plan_snapshot["plan_mode"]
    plan_duration_value = to_non_negative_int(plan_snapshot.get("duration_value", 0))
    plan_duration_unit = normalize_duration_unit(
        plan_snapshot.get("duration_unit", PLAN_DURATION_UNIT_MONTH)
    )
    plan_traffic_gb = to_non_negative_int(plan_snapshot["traffic_gb"])
    if plan_mode == PLAN_MODE_DURATION and plan_duration_value <= 0:
        db.rollback()
        raise ValueError("时长套餐配置无效。")
    if plan_mode == PLAN_MODE_TRAFFIC and plan_traffic_gb <= 0:
        db.rollback()
        raise ValueError("流量套餐配置无效。")

    current_expire_iso = row_get(user, "subscription_expires_at")
    if plan_mode == PLAN_MODE_DURATION:
        new_expire_at = calculate_new_expiry_by_duration(
            current_expire_iso,
            plan_duration_value,
            plan_duration_unit,
        )
    else:
        new_expire_at = None

    current_quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    current_used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    current_last_total_bytes = to_non_negative_int(
        row_get(user, "traffic_last_total_bytes", 0)
    )
    rx_now, tx_now = get_user_runtime_transfer_bytes(user)
    current_total_bytes = rx_now + tx_now
    delta_bytes = current_total_bytes - current_last_total_bytes
    if delta_bytes > 0 and current_quota_bytes > 0:
        current_used_bytes = min(current_quota_bytes, current_used_bytes + delta_bytes)
    if current_total_bytes > 0 or current_last_total_bytes > 0:
        current_last_total_bytes = current_total_bytes

    added_traffic_bytes = 0
    if plan_mode == PLAN_MODE_DURATION:
        # Time plans are unlimited-traffic mode: clear traffic quota tracking.
        current_quota_bytes = 0
        current_used_bytes = 0
    else:
        added_traffic_bytes = plan_traffic_gb * BYTES_PER_GB
        current_quota_bytes += added_traffic_bytes
    if current_used_bytes > current_quota_bytes:
        current_used_bytes = current_quota_bytes

    remaining_traffic_bytes = max(0, current_quota_bytes - current_used_bytes)
    vpn_data = ensure_user_vpn_ready(db, user)
    assigned_server_id = vpn_data.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(user, "assigned_server_id")
    paid_at_iso = paid_at_iso or utcnow_iso()
    tx_submitted_at = order["tx_submitted_at"] or (paid_at_iso if final_tx_hash else None)
    note_line = f"{source} confirmed at {paid_at_iso}"
    merged_note = note_line if not order["note"] else f"{order['note']}\n{note_line}"

    db.execute(
        """
        UPDATE users
        SET status = 'approved',
            vpn_internal_ip = ?,
            assigned_server_id = ?,
            archived_private_token = ?,
            archived_public_token = ?,
            archived_shared_token = ?,
            archived_profile_file = ?,
            archived_qr_file = ?,
            approved_at = ?,
            subscription_expires_at = ?,
            traffic_quota_bytes = ?,
            traffic_used_bytes = ?,
            traffic_last_total_bytes = ?,
            vpn_enabled = 1
        WHERE id = ?
        """,
        (
            vpn_data["vpn_internal_ip"],
            assigned_server_id,
            vpn_data["archived_private_token"],
            vpn_data["archived_public_token"],
            vpn_data["archived_shared_token"],
            vpn_data["archived_profile_file"],
            vpn_data["archived_qr_file"],
            utcnow_iso(),
            new_expire_at,
            current_quota_bytes,
            current_used_bytes,
            current_last_total_bytes,
            user["id"],
        ),
    )
    db.execute(
        """
        UPDATE payment_orders
        SET status = 'paid',
            paid_at = ?,
            tx_hash = ?,
            tx_submitted_at = ?,
            note = ?
        WHERE id = ?
        """,
        (paid_at_iso, final_tx_hash, tx_submitted_at, merged_note, order_id),
    )
    db.commit()
    if plan_mode == PLAN_MODE_DURATION:
        grant_text = (
            "时长套餐生效（"
            f"{plan_duration_value}{plan_duration_unit_label(plan_duration_unit)}"
            f"），到期时间：{format_utc(new_expire_at)}，流量剩余：永久"
        )
    else:
        grant_text = (
            f"流量套餐生效（有效期永久），新增 {format_bytes(added_traffic_bytes)}，"
            f"剩余 {format_bytes(remaining_traffic_bytes)}"
        )
    return {
        "status": "paid",
        "username": user["username"],
        "expires_at": new_expire_at,
        "grant_text": grant_text,
        "plan_display": plan_snapshot["display_name"],
    }


@app.route("/healthz")
def healthz():
    return {"ok": True}


@app.route("/openvpn/download")
def openvpn_download_page():
    return redirect(url_for("download_openvpn_config"))


@app.route("/openvpn/download/auto")
def openvpn_download_auto():
    return redirect(url_for("openvpn_download_page"))


@app.route("/openvpn/download/<platform>")
def openvpn_download_redirect(platform: str):
    return redirect(url_for("openvpn_download_page"))


def validate_captcha_input(scene: str, value: str) -> bool:
    return validate_captcha_input_impl(
        scene,
        value,
        scenes=CAPTCHA_SCENES,
        default_scene=CAPTCHA_SCENE_DEFAULT,
        utcnow=utcnow,
        parse_iso=parse_iso,
    )


def can_send_email_code(
    db: DatabaseConnection,
    email: str,
    purpose: str,
) -> tuple[bool, str]:
    now = utcnow()
    resend_cutoff = (now - timedelta(seconds=EMAIL_CODE_RESEND_SECONDS)).isoformat()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    latest = db.execute(
        """
        SELECT created_at
        FROM email_verifications
        WHERE email = ? AND purpose = ? AND created_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (email, purpose, resend_cutoff),
    ).fetchone()
    if latest:
        latest_dt = parse_iso(latest["created_at"])
        if latest_dt:
            wait_seconds = max(
                1, EMAIL_CODE_RESEND_SECONDS - int((now - latest_dt).total_seconds())
            )
        else:
            wait_seconds = EMAIL_CODE_RESEND_SECONDS
        return False, f"发送过于频繁，请在 {wait_seconds} 秒后重试。"

    sent_count = db.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM email_verifications
        WHERE email = ? AND created_at >= ?
        """,
        (email, today_start),
    ).fetchone()
    if int(sent_count["cnt"] or 0) >= EMAIL_CODE_DAILY_LIMIT:
        return False, f"该邮箱今日最多可发送 {EMAIL_CODE_DAILY_LIMIT} 次验证码。"
    return True, ""


def create_email_verification_code(
    db: DatabaseConnection,
    *,
    email: str,
    purpose: str,
    code: str,
    ip_address: str,
) -> int:
    created_at = utcnow_iso()
    expire_at = (utcnow() + timedelta(minutes=EMAIL_CODE_TTL_MINUTES)).isoformat()
    cursor = db.execute(
        """
        INSERT INTO email_verifications (
            email, purpose, code, status, ip_address, expire_at, created_at
        )
        VALUES (?, ?, ?, 'pending', ?, ?, ?)
        RETURNING id
        """,
        (email, purpose, code, ip_address, expire_at, created_at),
    )
    return int(cursor.fetchone()["id"])


def consume_email_verification_code(
    db: DatabaseConnection,
    *,
    email: str,
    purpose: str,
    code: str,
) -> bool:
    now_iso = utcnow_iso()
    row = db.execute(
        """
        SELECT id
        FROM email_verifications
        WHERE email = ?
          AND purpose = ?
          AND code = ?
          AND status = 'pending'
          AND expire_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (email, purpose, (code or "").strip(), now_iso),
    ).fetchone()
    if not row:
        return False
    db.execute(
        """
        UPDATE email_verifications
        SET status = 'used', used_at = ?
        WHERE id = ?
        """,
        (now_iso, int(row["id"])),
    )
    return True


def send_email_message(
    mail_server: dict[str, int | str],
    *,
    to_email: str,
    subject: str,
    body: str,
) -> tuple[bool, str]:
    message = EmailMessage()
    message["Subject"] = subject
    from_email = str(mail_server.get("from_email") or "").strip()
    from_name = str(mail_server.get("from_name") or "").strip()
    message["From"] = formataddr((from_name, from_email)) if from_name else from_email
    message["To"] = to_email
    message.set_content(body)

    host = str(mail_server.get("host") or "").strip()
    port = normalize_server_port(mail_server.get("port"), 587)
    username = str(mail_server.get("username") or "").strip()
    password = str(mail_server.get("password") or "")
    security = normalize_mail_security(str(mail_server.get("security") or ""))

    try:
        if security == MAIL_SECURITY_SSL:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                if security == MAIL_SECURITY_STARTTLS:
                    server.starttls()
                    server.ehlo()
                if username and password:
                    server.login(username, password)
                server.send_message(message)
    except Exception as exc:
        app.logger.exception(
            "邮件发送失败。server=%s host=%s to=%s error=%s",
            mail_server.get("server_name") or host,
            host,
            to_email,
            exc,
        )
        return False, "邮件发送失败"
    return True, ""


def send_verification_email(
    email: str,
    purpose_label: str,
    code: str,
    *,
    db: DatabaseConnection | None = None,
) -> tuple[bool, str]:
    mail_server = resolve_runtime_mail_server_config(db)
    if not mail_server:
        app.logger.warning(
            "邮件服务器未配置，无法发送验证码。email=%s purpose=%s",
            email,
            purpose_label,
        )
        return False, "管理员尚未配置邮件服务器，暂时无法发送验证码。"

    ok, _ = send_email_message(
        mail_server,
        to_email=email,
        subject="VPN 门户验证码",
        body="\n".join(
            [
                "您好，",
                "",
                f"本次操作：{purpose_label}",
                f"验证码：{code}",
                f"有效期：{EMAIL_CODE_TTL_MINUTES} 分钟",
                "",
                "如非本人操作，请忽略这封邮件。",
            ]
        ),
    )
    if not ok:
        return False, "验证码邮件发送失败，请稍后重试。"
    return True, "验证码已发送，请检查邮箱。"

    if not smtp_host or not smtp_from:
        app.logger.warning(
            "SMTP 未配置，验证码仅记录日志。email=%s purpose=%s code=%s",
            email,
            purpose_label,
            code,
        )
        return True, f"测试环境验证码：{code}（未配置 SMTP，已记录日志）"

    message = EmailMessage()
    message["Subject"] = "VPN 门户验证码"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(
        "\n".join(
            [
                "您好，",
                "",
                f"本次操作：{purpose_label}",
                f"验证码：{code}",
                f"有效期：{EMAIL_CODE_TTL_MINUTES} 分钟",
                "",
                "如非本人操作，请忽略本邮件。",
            ]
        )
    )
    try:
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(message)
    except Exception as exc:
        app.logger.exception("验证码邮件发送失败：%s", exc)
        return False, "验证码邮件发送失败，请稍后重试。"
    return True, "验证码已发送，请检查邮箱。"


def expire_pending_orders(db: DatabaseConnection) -> int:
    now_iso = utcnow_iso()
    rows = db.execute(
        """
        SELECT id, note
        FROM payment_orders
        WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < ?
        """,
        (now_iso,),
    ).fetchall()
    for row in rows:
        expired_note = f"[系统自动过期] {now_iso}"
        merged_note = expired_note if not row["note"] else f"{row['note']}\n{expired_note}"
        db.execute(
            """
            UPDATE payment_orders
            SET status = 'cancelled',
                note = ?
            WHERE id = ?
            """,
            (merged_note, int(row["id"])),
        )
    return len(rows)


def cleanup_verification_records(db: DatabaseConnection) -> None:
    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE email_verifications
        SET status = 'expired'
        WHERE status = 'pending' AND expire_at < ?
        """,
        (now_iso,),
    )
    cutoff_iso = (utcnow() - timedelta(hours=UNVERIFIED_USER_RETENTION_HOURS)).isoformat()
    db.execute(
        """
        DELETE FROM users
        WHERE role = 'user'
          AND email_verified = 0
          AND created_at < ?
        """,
        (cutoff_iso,),
    )


def persist_user_vpn_state(
    db: DatabaseConnection,
    user: DatabaseRow,
    vpn_data: dict[str, str | int],
) -> DatabaseRow:
    ensure_user_ingress_ports(db, user)
    assigned_server_id = vpn_data.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(user, "assigned_server_id")
    db.execute(
        """
        UPDATE users
        SET assigned_server_id = ?,
            vpn_enabled = ?
        WHERE id = ?
        """,
        (
            assigned_server_id,
            int(vpn_data.get("vpn_enabled", row_get(user, "vpn_enabled", 1)) or 1),
            int(user["id"]),
        ),
    )
    return db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()

def apply_password_change(
    db: DatabaseConnection,
    user: DatabaseRow,
    *,
    new_password: str,
    clear_force_change: bool = False,
    rotate_vpn: bool = True,
) -> None:
    update_fields = [
        "password_hash = ?",
        "session_version = session_version + 1",
    ]
    params: list[object] = [generate_password_hash(new_password)]
    if clear_force_change:
        update_fields.append("force_password_change = 0")
    params.append(int(user["id"]))
    db.execute(
        f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?",
        params,
    )

def grant_new_user_welcome_entitlement(db: DatabaseConnection, user_id: int) -> None:
    duration_months, traffic_gb = get_gift_settings(db)
    if duration_months <= 0 and traffic_gb <= 0:
        return

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return

    subscription_expires_at = row_get(user, "subscription_expires_at")
    if duration_months > 0:
        subscription_expires_at = calculate_new_expiry(subscription_expires_at, duration_months)

    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    if traffic_gb > 0:
        quota_bytes += traffic_gb * BYTES_PER_GB

    if duration_months > 0 or traffic_gb > 0:
        vpn_data = ensure_user_vpn_ready(db, user)
        assigned_server_id = vpn_data.get("assigned_server_id")
        if assigned_server_id is None:
            assigned_server_id = row_get(user, "assigned_server_id")
        db.execute(
            """
            UPDATE users
            SET vpn_internal_ip = ?,
                assigned_server_id = ?,
                archived_private_token = ?,
                archived_public_token = ?,
                archived_shared_token = ?,
                archived_profile_file = ?,
                archived_qr_file = ?,
                approved_at = ?,
                subscription_expires_at = ?,
                traffic_quota_bytes = ?,
                vpn_enabled = 1
            WHERE id = ?
            """,
            (
                vpn_data["vpn_internal_ip"],
                assigned_server_id,
                vpn_data["archived_private_token"],
                vpn_data["archived_public_token"],
                vpn_data["archived_shared_token"],
                vpn_data["archived_profile_file"],
                vpn_data["archived_qr_file"],
                utcnow_iso(),
                subscription_expires_at,
                quota_bytes,
                user_id,
            ),
        )


@app.route("/captcha.svg")
def captcha_svg():
    svg = create_captcha_svg_response_payload(
        request.args.get("scene") or CAPTCHA_SCENE_DEFAULT,
        scenes=CAPTCHA_SCENES,
        default_scene=CAPTCHA_SCENE_DEFAULT,
        ttl_minutes=CAPTCHA_TTL_MINUTES,
        utcnow=utcnow,
    )
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return login()
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    db = get_db()
    registration_open = is_registration_open(db)
    return render_template(
        "index.html",
        registration_open=registration_open,
    )


@app.route("/register/send-code", methods=["POST"])
def register_send_code():
    flash("公司内部模式下账号由管理员创建，不开放自助注册。", "error")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    flash("公司内部模式下账号由管理员创建，请联系管理员获取用户名和密码。", "error")
    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    registration_open = is_registration_open(db)
    if request.method == "GET":
        return redirect(url_for("index"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        captcha = request.form.get("captcha", "")

        if not validate_captcha_input("login", captcha):
            flash("图片验证码错误或已过期。", "error")
            return redirect(url_for("index", login="1"))

        user = authenticate_user(identity, password)
        if not user:
            flash("用户名或密码错误。", "error")
            return redirect(url_for("index", login="1"))
        if (
            row_get(user, "role") == "user"
            and (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled"
        ):
            flash("账号已停用，请联系管理员。", "error")
            return redirect(url_for("index", login="1"))
        user = start_user_login_session(db, user)
        if admin_must_change_password(user):
            flash("首次登录请先修改管理员密码。", "error")
            return redirect(url_for("admin_change_password"))
        return redirect(url_for("dashboard"))
    return render_template("login.html", registration_open=registration_open)


@app.route("/api/login", methods=["POST"])
def api_login():
    db = get_db()
    payload = request.get_json(silent=True) or {}
    identity = str(payload.get("identity", "")).strip()
    password = str(payload.get("password", ""))

    if not identity or not password:
        return {
            "ok": False,
            "error": "必须提供 identity 和 password",
        }, 400

    user = authenticate_user(identity, password)
    if not user:
        return {
            "ok": False,
            "error": "用户名或密码错误",
        }, 401
    user = start_user_login_session(db, user)
    redirect_url = url_for("dashboard")
    require_password_change = admin_must_change_password(user)
    if require_password_change:
        redirect_url = url_for("admin_change_password")
    return {
        "ok": True,
        "message": "登录成功",
        "user": user_api_payload(user),
        "redirect": redirect_url,
        "require_password_change": require_password_change,
    }, 200


@app.route("/password-recover/send-code", methods=["POST"])
def password_recover_send_code():
    flash("公司内部模式下请联系管理员重置密码。", "error")
    return redirect(url_for("login"))


@app.route("/password-recover", methods=["GET", "POST"])
def password_recover():
    flash("公司内部模式下请联系管理员重置密码。", "error")
    return redirect(url_for("login"))



@app.route("/logout")
def logout():
    session.clear()
    flash("已退出登录。", "success")
    return redirect(url_for("login"))



@app.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def admin_change_password():
    user = current_user()
    if not user or user["role"] != "admin":
        flash("仅管理员可访问。", "error")
        return redirect(url_for("dashboard"))

    must_change = admin_must_change_password(user)
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password or not confirm_password:
            flash("请完整填写当前密码和新密码。", "error")
        elif not check_password_hash(user["password_hash"], current_password):
            flash("当前密码不正确。", "error")
        elif len(new_password) < 8:
            flash("新密码长度至少需要 8 位。", "error")
        elif new_password != confirm_password:
            flash("两次输入的新密码不一致。", "error")
        elif check_password_hash(user["password_hash"], new_password):
            flash("新密码不能与当前密码相同。", "error")
        else:
            db = get_db()
            apply_password_change(
                db,
                user,
                new_password=new_password,
                clear_force_change=True,
                rotate_vpn=True,
            )
            db.commit()
            refreshed_user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            login_user_session(refreshed_user)
            flash("密码修改成功。", "success")
            return redirect(url_for("admin_subscriptions"))

    return render_template(
        "admin_change_password.html",
        must_change=must_change,
        admin_page="change_password",
    )


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))
    return redirect(url_for("dashboard_home"))


@app.route("/dashboard/home")
@login_required
def dashboard_home():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    health_overview = refresh_server_health_status(db)
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    traffic_stats = get_user_traffic_stats(user)
    current_plan_display = get_user_current_plan_display(db, user)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    preferred_mode = get_user_preferred_billing_mode(user)
    effective_mode = get_user_effective_billing_mode(user)
    benefit_summary = "内部账号，长期有效" if has_time else "账号已停用"
    subscription_expiry_display = "长期有效" if has_time else "-"
    current_server = serialize_runtime_server(
        get_server_by_id(db, row_get(user, "assigned_server_id"))
    )
    node_alert_text = ""
    if health_overview["total"] > 0 and health_overview["online"] == 0:
        node_alert_text = "当前节点异常，VPN 服务暂不可用，系统正在恢复。"
    elif health_overview["abnormal"] > 0:
        node_alert_text = "当前节点异常，系统正在切换。"

    return render_template(
        "dashboard_home.html",
        user=user,
        active=is_subscription_active(user),
        traffic_stats=traffic_stats,
        current_plan_display=current_plan_display,
        benefit_summary=benefit_summary,
        subscription_expiry_display=subscription_expiry_display,
        current_server=current_server,
        node_alert_text=node_alert_text,
        preferred_billing_mode=preferred_mode,
        effective_billing_mode=effective_mode,
        can_choose_duration=has_time,
        can_choose_traffic=has_traffic,
        dashboard_page="home",
    )


@app.route("/dashboard/billing-mode", methods=["POST"])
@login_required
def dashboard_set_billing_mode():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))
    flash("公司内部账号不需要切换计费方式。", "error")
    return redirect(url_for("dashboard_home"))

    requested_mode = normalize_plan_mode(request.form.get("billing_mode", PLAN_MODE_DURATION))
    db = get_db()
    reconcile_expired_subscriptions(db)
    latest_user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(user["id"]),),
    ).fetchone()
    if not latest_user:
        flash("用户不存在。", "error")
        return redirect(url_for("dashboard_home"))

    latest_user = sync_user_traffic_usage(db, latest_user)
    has_time = has_active_time_subscription(latest_user)
    has_traffic = has_active_traffic_subscription(latest_user)
    if requested_mode == PLAN_MODE_DURATION and not has_time:
        flash("当前没有可用时长权益，无法切换为按时长。", "error")
        return redirect(url_for("dashboard_home"))
    if requested_mode == PLAN_MODE_TRAFFIC and not has_traffic:
        flash("当前没有可用流量权益，无法切换为按流量。", "error")
        return redirect(url_for("dashboard_home"))

    db.execute(
        "UPDATE users SET preferred_billing_mode = ? WHERE id = ? AND role = 'user'",
        (requested_mode, int(latest_user["id"])),
    )
    db.commit()
    flash(f"默认计费方式已切换为：{plan_mode_label(requested_mode)}。", "success")
    return redirect(url_for("dashboard_home"))


@app.route("/dashboard/guide")
@login_required
def dashboard_guide():
    return redirect(url_for("dashboard_config"))


@app.route("/dashboard/plans")
@login_required
def dashboard_plans():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))
    return redirect(url_for("dashboard_orders"))


@app.route("/dashboard/config")
@login_required
def dashboard_config():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    health_overview = refresh_server_health_status(db)
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    available_servers = load_user_selectable_servers(db, user)
    current_server = serialize_runtime_server(
        get_server_by_id(db, row_get(user, "assigned_server_id"))
    )
    preferred_server = serialize_runtime_server(
        get_server_by_id(db, row_get(user, "preferred_server_id"))
    )

    node_alert_text = ""
    if health_overview["total"] > 0 and health_overview["online"] == 0:
        node_alert_text = "当前节点异常，VPN 服务暂不可用，系统正在恢复。"
    elif health_overview["abnormal"] > 0:
        node_alert_text = "当前节点异常，系统正在切换。"

    current_supports_openvpn = bool(
        current_server and current_server.get("openvpn_enabled") and OPENVPN_ENABLED
    )
    current_supports_ss_kcptun = bool(
        current_server
        and current_server.get("shadowsocks_enabled")
        and current_server.get("kcptun_enabled")
    )
    openvpn_download_link = (
        absolute_url_for("download_openvpn_config") if current_supports_openvpn else ""
    )
    ss_access_token = build_download_access_token(user, "download-config-user")
    ss_download_link = (
        build_masked_download_link(ss_access_token, output_format="yaml")
        if current_supports_ss_kcptun
        else ""
    )
    kcptun_download_link = (
        absolute_url_for("download_kcptun_config") if current_supports_ss_kcptun else ""
    )
    ss_qr_link = absolute_url_for("download_qr") if current_supports_ss_kcptun else ""

    return render_template(
        "dashboard_config.html",
        user=user,
        active=is_subscription_active(user),
        available_servers=available_servers,
        current_server=current_server,
        preferred_server=preferred_server,
        node_alert_text=node_alert_text,
        current_supports_openvpn=current_supports_openvpn,
        current_supports_ss_kcptun=current_supports_ss_kcptun,
        openvpn_download_link=openvpn_download_link,
        ss_download_link=ss_download_link,
        kcptun_download_link=kcptun_download_link,
        ss_qr_link=ss_qr_link,
        dashboard_page="config",
    )


@app.route("/dashboard/config/regenerate", methods=["POST"])
@login_required
def dashboard_regenerate_config():
    user = current_user()
    if user["role"] == "admin":
        flash("管理员无需在用户配置页重建配置。", "error")
        return redirect(url_for("admin_subscriptions"))
    flash("当前使用 OpenVPN，配置为按用户动态生成，无需手动重建。", "success")
    return redirect(url_for("dashboard_config"))


@app.route("/dashboard/config/server", methods=["POST"])
@login_required
def dashboard_select_server():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))

    preferred_server_id_raw = (request.form.get("preferred_server_id", "") or "").strip()
    if not preferred_server_id_raw.isdigit():
        flash("璇烽€夋嫨鍙敤鐨勮妭鐐广€?", "error")
        return redirect(url_for("dashboard_config"))

    preferred_server_id = int(preferred_server_id_raw)
    db = get_db()
    reconcile_expired_subscriptions(db)
    latest_user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (user["id"],),
    ).fetchone()
    if not latest_user:
        flash("鐢ㄦ埛涓嶅瓨鍦ㄣ€?", "error")
        return redirect(url_for("dashboard_config"))

    target_server = get_server_by_id(db, preferred_server_id)
    if not is_runtime_server_ready(target_server):
        flash("鎵€閫夎妭鐐瑰綋鍓嶄笉鍙敤锛岃閫夋嫨鍏朵粬鍦ㄧ嚎鏈嶅姟鍣ㄣ€?", "error")
        return redirect(url_for("dashboard_config"))

    db.execute(
        "UPDATE users SET preferred_server_id = ? WHERE id = ? AND role = 'user'",
        (preferred_server_id, int(latest_user["id"])),
    )
    latest_user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(latest_user["id"]),),
    ).fetchone()

    if is_subscription_active(latest_user):
        try:
            vpn_data = ensure_user_vpn_ready(
                db,
                latest_user,
                force_new_ip=is_dynamic_ip_assignment_mode(),
            )
            persist_user_vpn_state(db, latest_user, vpn_data)
            db.commit()
        except Exception as exc:
            db.rollback()
            flash(f"鍒囨崲鏈嶅姟鍣ㄥけ璐ワ細{exc}", "error")
            return redirect(url_for("dashboard_config"))
        flash(
            f"榛樿鏈嶅姟鍣ㄥ凡鍒囨崲鍒?{normalize_server_region(row_get(target_server, 'server_region', '')) or row_get(target_server, 'server_name', '') or row_get(target_server, 'host', '')}锛岃閲嶆柊涓嬭浇閰嶇疆鍚庡啀杩炴帴銆?",
            "success",
        )
        return redirect(url_for("dashboard_config"))

    db.commit()
    flash("榛樿鏈嶅姟鍣ㄥ凡淇濆瓨锛屽緟璁㈤槄鐢熸晥鍚庝細鑷姩浣跨敤璇ヨ妭鐐广€?", "success")
    return redirect(url_for("dashboard_config"))


@app.route("/dashboard/profile", methods=["GET", "POST"])
@login_required
def dashboard_profile():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password or not confirm_password:
            flash("请完整填写当前密码和新密码。", "error")
            return render_template("dashboard_profile.html", dashboard_page="profile")
        if len(new_password) < 8:
            flash("新密码长度至少需要 8 位。", "error")
            return render_template("dashboard_profile.html", dashboard_page="profile")
        if new_password != confirm_password:
            flash("两次输入的新密码不一致。", "error")
            return render_template("dashboard_profile.html", dashboard_page="profile")

        db = get_db()
        try:
            begin_immediate(db)
            latest_user = db.execute(
                "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
                (user["id"],),
            ).fetchone()
            if not latest_user:
                db.rollback()
                session.clear()
                flash("用户不存在，请重新登录。", "error")
                return redirect(url_for("login"))
            if not check_password_hash(latest_user["password_hash"], current_password):
                db.rollback()
                flash("当前密码不正确。", "error")
                return render_template("dashboard_profile.html", dashboard_page="profile")
            if check_password_hash(latest_user["password_hash"], new_password):
                db.rollback()
                flash("新密码不能与当前密码相同。", "error")
                return render_template("dashboard_profile.html", dashboard_page="profile")

            apply_password_change(
                db,
                latest_user,
                new_password=new_password,
                clear_force_change=False,
                rotate_vpn=True,
            )
            db.commit()
            session.clear()
            flash("密码修改成功，请重新登录。", "success")
            return redirect(url_for("login"))
        except Exception:
            db.rollback()
            raise

    return render_template("dashboard_profile.html", dashboard_page="profile")


@app.route("/dashboard/orders")
@login_required
def dashboard_orders():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_subscriptions"))

    flash("公司内部系统不开放用户下单，请联系管理员分配账号。", "error")
    return redirect(url_for("dashboard_home"))


@app.route("/subscription/create-order", methods=["POST"])
@login_required
def create_subscription_order():
    user = current_user()
    if user["role"] != "user":
        return redirect(url_for("dashboard_orders"))
    flash("公司内部系统不开放用户下单，请联系管理员分配账号。", "error")
    return redirect(url_for("dashboard_home"))

    plan_id_raw = request.form.get("plan_id", "0").strip()
    try:
        plan_id = int(plan_id_raw)
    except ValueError:
        plan_id = 0

    if plan_id <= 0:
        flash("套餐选择无效。", "error")
        return redirect(url_for("dashboard_orders"))

    db = get_db()
    payment_settings = load_payment_settings(db)
    payment_method_code = normalize_payment_method(payment_settings.get("payment_method"))
    network = payment_settings["usdt_default_network"]
    receive_address = payment_settings["usdt_receive_address"]
    if payment_method_code != PAYMENT_METHOD_USDT:
        flash("当前付款方式暂不支持自动下单。", "error")
        return redirect(url_for("dashboard_orders"))
    if not receive_address:
        flash("管理员尚未配置 USDT 收款地址。", "error")
        return redirect(url_for("dashboard_orders"))

    pending = db.execute(
        """
        SELECT id FROM payment_orders
        WHERE user_id = ? AND status = 'pending'
        LIMIT 1
        """,
        (user["id"],),
    ).fetchone()
    if pending:
        flash("你已有待处理订单，请先提交 TxHash 并等待确认。", "error")
        return redirect(url_for("dashboard_orders"))

    plan = db.execute(
        """
        SELECT
            id,
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit,
            traffic_gb,
            price_usdt
        FROM subscription_plans
        WHERE id = ? AND is_active = 1
        LIMIT 1
        """,
        (plan_id,),
    ).fetchone()
    if not plan:
        flash("套餐不存在或已停用。", "error")
        return redirect(url_for("dashboard_orders"))

    plan_mode = normalize_plan_mode(plan["billing_mode"])
    duration_months = to_non_negative_int(plan["duration_months"])
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(plan, "duration_value", 0),
        duration_unit_raw=row_get(plan, "duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    traffic_gb = to_non_negative_int(plan["traffic_gb"])
    if plan_mode == PLAN_MODE_DURATION and duration_value <= 0:
        flash("所选时长套餐配置无效，请联系管理员。", "error")
        return redirect(url_for("dashboard_orders"))
    if plan_mode == PLAN_MODE_TRAFFIC and traffic_gb <= 0:
        flash("所选流量套餐配置无效，请联系管理员。", "error")
        return redirect(url_for("dashboard_orders"))

    usdt_amount = parse_usdt_amount(plan["price_usdt"], "1")
    plan_display = format_plan_display_name(
        plan["plan_name"],
        plan_mode,
        duration_months,
        traffic_gb,
        duration_value=duration_value,
        duration_unit=duration_unit,
    )
    legacy_plan_months = duration_value_to_legacy_months(duration_value, duration_unit)
    order_expire_at = (utcnow() + timedelta(hours=get_order_expire_hours(db))).isoformat()
    db.execute(
        """
        INSERT INTO payment_orders (
            user_id, plan_months, plan_id, plan_name, plan_mode,
            plan_duration_months, plan_duration_value, plan_duration_unit, plan_traffic_gb,
            payment_method, usdt_network, usdt_amount, pay_to_address, expires_at, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            user["id"],
            legacy_plan_months,
            plan["id"],
            plan["plan_name"],
            plan_mode,
            legacy_plan_months if plan_mode == PLAN_MODE_DURATION else None,
            duration_value if plan_mode == PLAN_MODE_DURATION else None,
            duration_unit if plan_mode == PLAN_MODE_DURATION else None,
            traffic_gb if plan_mode == PLAN_MODE_TRAFFIC else None,
            payment_method_code,
            network,
            format_usdt(usdt_amount),
            receive_address,
            order_expire_at,
            utcnow_iso(),
        ),
    )
    db.commit()
    flash(
        (
            f"USDT 订单已创建：{plan_display} / {format_usdt(usdt_amount)} USDT。"
            f" 订单将在 {format_utc(order_expire_at)} 自动过期。请完成支付后提交 TxHash。"
        ),
        "success",
    )
    return redirect(url_for("dashboard_orders"))



@app.route("/subscription/orders/<int:order_id>/submit-tx", methods=["POST"])
@login_required
def submit_usdt_tx_hash(order_id: int):
    user = current_user()
    if user["role"] != "user":
        return redirect(url_for("dashboard_orders"))
    flash("公司内部系统不开放订单支付。", "error")
    return redirect(url_for("dashboard_home"))

    tx_hash = request.form.get("tx_hash", "").strip()
    tx_hash = re.sub(r"\s+", "", tx_hash)
    if not re.fullmatch(r"[A-Za-z0-9]{20,128}", tx_hash):
        flash("TxHash 格式不正确。", "error")
        return redirect(url_for("dashboard_orders"))

    db = get_db()
    order = db.execute(
        """
        SELECT id, user_id, status
        FROM payment_orders
        WHERE id = ?
        """,
        (order_id,),
    ).fetchone()
    if not order or order["user_id"] != user["id"]:
        flash("未找到订单。", "error")
        return redirect(url_for("dashboard_orders"))
    if order["status"] != "pending":
        flash("该订单已处理。", "error")
        return redirect(url_for("dashboard_orders"))

    db.execute(
        """
        UPDATE payment_orders
        SET tx_hash = ?, tx_submitted_at = ?
        WHERE id = ?
        """,
        (tx_hash, utcnow_iso(), order_id),
    )
    db.commit()
    flash("TxHash 已提交，等待 Webhook 自动确认或管理员兜底处理。", "success")
    return redirect(url_for("dashboard_orders"))


@app.route("/subscription/orders/<int:order_id>/cancel", methods=["POST"])
@login_required
def cancel_subscription_order(order_id: int):
    user = current_user()
    if user["role"] != "user":
        return redirect(url_for("dashboard_orders"))
    flash("公司内部系统不开放订单支付。", "error")
    return redirect(url_for("dashboard_home"))

    db = get_db()
    order = db.execute(
        """
        SELECT id, user_id, status, note
        FROM payment_orders
        WHERE id = ?
        """,
        (order_id,),
    ).fetchone()
    if not order or order["user_id"] != user["id"]:
        flash("未找到订单。", "error")
        return redirect(url_for("dashboard_orders"))
    if order["status"] != "pending":
        flash("仅待处理订单可取消。", "error")
        return redirect(url_for("dashboard_orders"))

    cancel_note = f"[用户取消] {utcnow_iso()}"
    merged_note = cancel_note if not order["note"] else f"{order['note']}\n{cancel_note}"
    db.execute(
        """
        UPDATE payment_orders
        SET status = 'cancelled',
            note = ?
        WHERE id = ?
        """,
        (merged_note, order_id),
    )
    db.commit()
    flash("订单已取消。", "success")
    return redirect(url_for("dashboard_orders"))



@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return redirect(url_for("admin_subscriptions"))


def load_admin_pending_orders(db: DatabaseConnection):
    return db.execute(
        """
        SELECT
            o.id,
            o.user_id,
            o.plan_months,
            o.plan_name,
            o.plan_mode,
            o.plan_duration_months,
            o.plan_duration_value,
            o.plan_duration_unit,
            o.plan_traffic_gb,
            o.payment_method,
            o.usdt_network,
            o.usdt_amount,
            o.pay_to_address,
            o.tx_hash,
            o.tx_submitted_at,
            o.created_at,
            o.expires_at,
            u.username,
            u.email,
            u.subscription_expires_at
        FROM payment_orders o
        JOIN users u ON u.id = o.user_id
        WHERE o.status = 'pending'
        ORDER BY o.created_at ASC
        """
    ).fetchall()


def load_admin_paid_orders(db: DatabaseConnection):
    return db.execute(
        """
        SELECT
            o.id,
            o.plan_months,
            o.plan_name,
            o.plan_mode,
            o.plan_duration_months,
            o.plan_duration_value,
            o.plan_duration_unit,
            o.plan_traffic_gb,
            o.payment_method,
            o.usdt_network,
            o.usdt_amount,
            o.tx_hash,
            o.created_at,
            o.paid_at,
            u.username,
            u.email
        FROM payment_orders o
        JOIN users u ON u.id = o.user_id
        WHERE o.status = 'paid'
        ORDER BY o.paid_at DESC
        LIMIT 200
        """
    ).fetchall()


def load_admin_subscriptions(db: DatabaseConnection, username_query: str = ""):
    normalized_role_sql = "COALESCE(NULLIF(lower(trim(u.role)), ''), 'user')"
    base_sql = """
        SELECT
            u.id,
            u.role,
            u.status,
            u.username,
            u.email,
            u.vpn_internal_ip,
            u.assigned_server_id,
            u.subscription_expires_at,
            u.vpn_enabled,
            u.traffic_quota_bytes,
            u.traffic_used_bytes,
            s.server_name,
            s.server_region,
            s.host AS server_host,
            s.domain AS server_domain
        FROM users u
        LEFT JOIN vpn_servers s ON s.id = u.assigned_server_id
        WHERE {normalized_role_sql} IN ('user', 'admin')
    """
    params = []
    normalized_query = (username_query or "").strip()
    if normalized_query:
        base_sql += " AND lower(u.username) LIKE lower(?)"
        params.append(f"%{normalized_query}%")
    base_sql += (
        " ORDER BY CASE WHEN "
        + normalized_role_sql
        + " = 'admin' THEN 1 ELSE 0 END, COALESCE(subscription_expires_at, '') DESC, id DESC"
    )
    base_sql = base_sql.format(normalized_role_sql=normalized_role_sql)
    rows = db.execute(base_sql, params).fetchall()
    result: list[dict] = []
    for row in rows:
        quota_bytes = to_non_negative_int(row_get(row, "traffic_quota_bytes", 0))
        used_bytes = to_non_negative_int(row_get(row, "traffic_used_bytes", 0))
        if used_bytes > quota_bytes:
            used_bytes = quota_bytes
        if quota_bytes > 0:
            traffic_plan_usage_display = (
                f"{format_bytes_in_gb(quota_bytes)} / {format_bytes_in_gb(used_bytes)}"
            )
        else:
            traffic_plan_usage_display = "-"
        item = decorate_admin_subscription_row(row, row_get, normalize_server_region)
        item["traffic_plan_usage_display"] = traffic_plan_usage_display
        if (row_get(row, "role", "") or "").strip().lower() == "user":
            item["allowed_server_ids"] = get_user_allowed_server_ids(db, row)
        else:
            item["allowed_server_ids"] = []
        result.append(item)
    return result


def load_expiring_subscriptions(
    db: DatabaseConnection,
    *,
    days: int = 7,
    limit: int = 20,
) -> list[dict]:
    return []


def load_admin_online_users(
    db: DatabaseConnection,
    *,
    online_window_seconds: int = ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
) -> tuple[list[dict], dict]:
    users = db.execute(
        """
        SELECT
            id,
            role,
            status,
            username,
            email,
            assigned_server_id,
            kcptun_ingress_port,
            openvpn_ingress_port,
            subscription_expires_at,
            traffic_used_bytes,
            vpn_enabled,
            last_login_ip
        FROM users
        WHERE role IN ('user', 'admin')
          AND vpn_enabled = 1
        ORDER BY id DESC
        """
    ).fetchall()
    hydrated_users: list[DatabaseRow] = []
    for user in users:
        try:
            hydrated_users.append(ensure_user_transport_ports(db, user))
        except Exception:
            hydrated_users.append(user)
    users = hydrated_users
    servers = db.execute(
        """
        SELECT *
        FROM vpn_servers
        ORDER BY id DESC
        """
    ).fetchall()
    servers_by_id: dict[int, DatabaseRow] = {}
    for server in servers:
        try:
            servers_by_id[int(server["id"])] = server
        except Exception:
            continue

    now_dt = utcnow()
    now_ts = int(now_dt.timestamp())
    active_peer_hosts_by_source: dict[str, set[str]] = {}
    active_peer_stats_by_source: dict[str, dict[str, dict[str, int]]] = {}
    aggregate_stats_by_source: dict[str, dict[str, int]] = {}
    active_port_stats_by_source: dict[str, dict[int, dict[str, int]]] = {}
    active_mode_by_source: dict[str, str] = {}
    requested_ports_by_source: dict[str, set[int]] = {}
    cache_errors: dict[str, str] = {}
    online_users: list[dict] = []
    source_labels: dict[str, str] = {}
    user_source_meta: dict[int, tuple[str, DatabaseRow | None, str]] = {}
    detect_mode = "shadowsocks"
    client_session_rows = db.execute(
        """
        SELECT *
        FROM client_online_sessions
        WHERE last_seen_at IS NOT NULL
        """
    ).fetchall()
    client_sessions_by_user_id: dict[int, DatabaseRow] = {}
    for session_row in client_session_rows:
        try:
            seen_at = parse_iso(row_get(session_row, "last_seen_at", ""))
            if seen_at is None:
                continue
            age_seconds = max(0, int((now_dt - seen_at).total_seconds()))
            if age_seconds <= max(online_window_seconds, 45):
                client_sessions_by_user_id[int(session_row["user_id"])] = session_row
        except Exception:
            continue

    def resolve_user_source(user_row: DatabaseRow) -> tuple[str, DatabaseRow | None, str]:
        server_row = None
        assigned_server_id = row_get(user_row, "assigned_server_id")
        if assigned_server_id is not None and str(assigned_server_id).strip():
            try:
                server_row = servers_by_id.get(int(assigned_server_id))
            except Exception:
                server_row = None
        if server_row is None:
            try:
                server_row = get_persisted_runtime_server_for_account(db, user_row)
            except Exception:
                server_row = None

        if server_row is not None:
            source_key = f"server:{int(server_row['id'])}"
            server_name = (
                (row_get(server_row, "server_name", "") or "").strip()
                or (row_get(server_row, "host", "") or "").strip()
                or f"#{int(server_row['id'])}"
            )
            return source_key, server_row, server_name
        if VPN_API_URL:
            return "global-api", None, "全局 VPN API"
        return "local", None, "本机 VPN"

    def build_online_row(
        user_row: DatabaseRow,
        *,
        server_name: str,
        source_key: str,
        endpoint: str,
        latest_handshake: int,
        rx_bytes: int = 0,
        tx_bytes: int = 0,
    ) -> dict:
        role_value = (row_get(user_row, "role", "") or "").strip().lower()
        username_display = (row_get(user_row, "username", "") or "").strip()
        if role_value == "admin":
            username_display = f"{username_display or '管理员'}（管理员）"
        rx_clean = max(0, int(rx_bytes or 0))
        tx_clean = max(0, int(tx_bytes or 0))
        total_bytes = rx_clean + tx_clean
        source_mode = (active_mode_by_source.get(source_key, detect_mode) or "").strip().lower()
        if source_mode in {"kcptun", "clash", "ss-kcptun"}:
            connection_mode = "SS+KCPTUN"
        elif source_mode == "shadowsocks":
            connection_mode = "Shadowsocks"
        elif source_mode == "openvpn":
            connection_mode = "OpenVPN"
        elif source_mode in {"ssh", "ssh-tunnel"}:
            connection_mode = "SSH Tunnel"
        else:
            connection_mode = "-"
        return {
            "id": int(user_row["id"]),
            "role": role_value or "user",
            "username": username_display,
            "email": (row_get(user_row, "email", "") or "").strip(),
            "server_name": server_name,
            "connection_mode": connection_mode,
            "__source_key": source_key,
            "endpoint": (endpoint or "").strip() or "-",
            "latest_handshake": int(max(0, latest_handshake)),
            "latest_handshake_at": handshake_epoch_to_iso(latest_handshake),
            "handshake_age_seconds": max(0, now_ts - int(max(0, latest_handshake))),
            "rx_bytes": rx_clean,
            "tx_bytes": tx_clean,
            "total_bytes": total_bytes,
            "rx_human": format_bytes(rx_clean),
            "tx_human": format_bytes(tx_clean),
            "total_human": format_bytes(total_bytes),
            "traffic_used_bytes": to_non_negative_int(row_get(user_row, "traffic_used_bytes", 0)),
            "traffic_used_human": format_bytes(
                to_non_negative_int(row_get(user_row, "traffic_used_bytes", 0))
            ),
            "status": (row_get(user_row, "status", "approved") or "approved").strip().lower(),
            "subscription_expires_at": row_get(user_row, "subscription_expires_at", ""),
        }

    for user in users:
        source_key, server_row, server_name = resolve_user_source(user)
        user_source_meta[int(user["id"])] = (source_key, server_row, server_name)
        source_labels[source_key] = server_name
        requested_port = (
            get_server_shadowsocks_backend_port(server_row)
            if runtime_uses_kcptun(server_row)
            else get_user_shadowsocks_server_port(user)
        )
        requested_ports_by_source.setdefault(source_key, set()).add(
            requested_port
        )
    if any(runtime_uses_kcptun(server_row) for _key, server_row, _name in user_source_meta.values()):
        detect_mode = "kcptun"

    for user in users:
        source_key, server_row, _ = user_source_meta[int(user["id"])]
        if source_key in active_peer_hosts_by_source:
            continue
        try:
            peers, source_mode, peer_stats, aggregate_stats, port_stats = get_runtime_active_peer_hosts(
                user=user,
                server_row=server_row,
                window_seconds=online_window_seconds,
                requested_ports=sorted(requested_ports_by_source.get(source_key, set())),
            )
            active_peer_hosts_by_source[source_key] = set(peers)
            active_peer_stats_by_source[source_key] = peer_stats or {}
            active_mode_by_source[source_key] = source_mode or detect_mode
            aggregate_stats_by_source[source_key] = aggregate_stats or {
                "rx_bytes": 0,
                "tx_bytes": 0,
                "total_bytes": 0,
            }
            active_port_stats_by_source[source_key] = port_stats or {}
            detect_mode = source_mode or detect_mode
        except Exception as exc:
            active_peer_hosts_by_source[source_key] = set()
            active_peer_stats_by_source[source_key] = {}
            active_mode_by_source[source_key] = detect_mode
            aggregate_stats_by_source[source_key] = {
                "rx_bytes": 0,
                "tx_bytes": 0,
                "total_bytes": 0,
            }
            active_port_stats_by_source[source_key] = {}
            cache_errors[source_key] = str(exc)

    matched_user_ids: set[int] = set()
    matched_peer_by_source: dict[str, set[str]] = {
        key: set() for key in active_peer_hosts_by_source
    }

    for user in users:
        user_id = int(user["id"])
        session_row = client_sessions_by_user_id.get(user_id)
        if not session_row:
            continue
        source_key, _, fallback_server_name = user_source_meta[user_id]
        server_name = (
            (row_get(session_row, "server_host", "") or "").strip()
            or fallback_server_name
        )
        profile_type = (row_get(session_row, "profile_type", "") or "").strip().lower()
        active_mode_by_source[source_key] = profile_type or active_mode_by_source.get(source_key, detect_mode)
        try:
            latest_handshake = int(parse_iso(row_get(session_row, "last_seen_at", "")).timestamp())
        except Exception:
            latest_handshake = now_ts
        endpoint = (
            normalize_public_client_ip(row_get(session_row, "endpoint", ""))
            or (row_get(session_row, "endpoint", "") or "").strip()
            or "-"
        )
        matched_user_ids.add(user_id)
        if endpoint and endpoint != "-":
            matched_peer_by_source.setdefault(source_key, set()).add(endpoint)
        online_users.append(
            build_online_row(
                user,
                server_name=server_name,
                source_key=source_key,
                endpoint=endpoint,
                latest_handshake=latest_handshake,
                rx_bytes=to_non_negative_int(row_get(session_row, "rx_bytes", 0)),
                tx_bytes=to_non_negative_int(row_get(session_row, "tx_bytes", 0)),
            )
        )

    for user in users:
        user_id = int(user["id"])
        if user_id in matched_user_ids:
            continue
        source_key, _, server_name = user_source_meta[user_id]
        peers = active_peer_hosts_by_source.get(source_key, set())
        if not peers:
            continue
        login_ip = normalize_public_client_ip(row_get(user, "last_login_ip", ""))
        if not login_ip or login_ip not in peers:
            continue
        matched_user_ids.add(user_id)
        matched_peer_by_source.setdefault(source_key, set()).add(login_ip)
        peer_state = active_peer_stats_by_source.get(source_key, {}).get(login_ip, {})
        user_ss_port = get_user_shadowsocks_server_port(user)
        port_state = active_port_stats_by_source.get(source_key, {}).get(user_ss_port, {})
        rx_bytes = to_non_negative_int(peer_state.get("rx_bytes", 0))
        tx_bytes = to_non_negative_int(peer_state.get("tx_bytes", 0))
        if rx_bytes <= 0 and tx_bytes <= 0:
            rx_bytes = to_non_negative_int(port_state.get("rx_bytes", 0))
            tx_bytes = to_non_negative_int(port_state.get("tx_bytes", 0))
        online_users.append(
            build_online_row(
                user,
                server_name=server_name,
                source_key=source_key,
                endpoint=login_ip,
                latest_handshake=now_ts,
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
            )
        )

    for user in users:
        user_id = int(user["id"])
        if user_id in matched_user_ids:
            continue
        source_key, _, server_name = user_source_meta[user_id]
        user_ss_port = get_user_shadowsocks_server_port(user)
        port_state = active_port_stats_by_source.get(source_key, {}).get(user_ss_port, {})
        rx_bytes = to_non_negative_int(port_state.get("rx_bytes", 0))
        tx_bytes = to_non_negative_int(port_state.get("tx_bytes", 0))
        if rx_bytes <= 0 and tx_bytes <= 0:
            continue
        matched_user_ids.add(user_id)
        login_ip = normalize_public_client_ip(row_get(user, "last_login_ip", ""))
        endpoint = login_ip or f"port:{user_ss_port}"
        online_users.append(
            build_online_row(
                user,
                server_name=server_name,
                source_key=source_key,
                endpoint=endpoint,
                latest_handshake=now_ts,
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
            )
        )

    unknown_counter = 0
    for source_key, peers in active_peer_hosts_by_source.items():
        if not peers:
            continue
        unmatched_peers = [p for p in sorted(peers) if p not in matched_peer_by_source.get(source_key, set())]
        if not unmatched_peers:
            continue
        candidate_users = [
            user
            for user in users
            if int(user["id"]) not in matched_user_ids
            and user_source_meta[int(user["id"])][0] == source_key
        ]
        if len(candidate_users) == 1 and len(unmatched_peers) == 1:
            user = candidate_users[0]
            matched_user_ids.add(int(user["id"]))
            guessed_peer_state = (
                active_peer_stats_by_source.get(source_key, {})
                .get(unmatched_peers[0], {})
            )
            guessed_rx = to_non_negative_int(guessed_peer_state.get("rx_bytes", 0))
            guessed_tx = to_non_negative_int(guessed_peer_state.get("tx_bytes", 0))
            if guessed_rx <= 0 and guessed_tx <= 0:
                guessed_port_state = active_port_stats_by_source.get(source_key, {}).get(
                    get_user_shadowsocks_server_port(user),
                    {},
                )
                guessed_rx = to_non_negative_int(guessed_port_state.get("rx_bytes", 0))
                guessed_tx = to_non_negative_int(guessed_port_state.get("tx_bytes", 0))
            online_users.append(
                build_online_row(
                    user,
                    server_name=source_labels.get(source_key, "-"),
                    source_key=source_key,
                    endpoint=unmatched_peers[0],
                    latest_handshake=now_ts,
                    rx_bytes=guessed_rx,
                    tx_bytes=guessed_tx,
                )
            )
            continue
        for peer_host in unmatched_peers:
            unknown_counter += 1
            online_users.append(
                {
                    "id": -100000 - unknown_counter,
                    "role": "unknown",
                    "status": "unknown",
                    "username": "未知来源（无法映射到具体用户）",
                    "email": "-",
                    "vpn_internal_ip": "-",
                    "server_name": source_labels.get(source_key, "-"),
                    "connection_mode": (
                        "SS+KCPTUN"
                        if (active_mode_by_source.get(source_key, detect_mode) == "kcptun")
                        else (
                            "Shadowsocks"
                            if (active_mode_by_source.get(source_key, detect_mode) == "shadowsocks")
                            else "-"
                        )
                    ),
                    "__source_key": source_key,
                    "endpoint": peer_host,
                    "latest_handshake": now_ts,
                    "latest_handshake_at": handshake_epoch_to_iso(now_ts),
                    "handshake_age_seconds": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "total_bytes": 0,
                    "rx_human": "0 B",
                    "tx_human": "0 B",
                    "total_human": "0 B",
                    "traffic_used_bytes": 0,
                    "traffic_used_human": "0 B",
                    "subscription_expires_at": "",
                }
            )

        # kcptun traffic usually appears as loopback shadowsocks sockets.
        # When one mapped user is online on a source, apply aggregate socket bytes to that user row.
        if detect_mode == "kcptun":
            by_source: dict[str, list[dict]] = {}
            for row in online_users:
                key = str(row.get("__source_key", "") or "")
                if not key:
                    continue
                by_source.setdefault(key, []).append(row)
            for source_key, rows in by_source.items():
                aggregate = aggregate_stats_by_source.get(source_key, {})
                agg_rx = to_non_negative_int(aggregate.get("rx_bytes", 0))
                agg_tx = to_non_negative_int(aggregate.get("tx_bytes", 0))
                agg_total = to_non_negative_int(aggregate.get("total_bytes", agg_rx + agg_tx))
                if agg_total <= 0:
                    continue
                mapped_rows = [r for r in rows if str(r.get("role", "")) != "unknown"]
                if len(mapped_rows) != 1:
                    continue
                row = mapped_rows[0]
                current_total = to_non_negative_int(row.get("total_bytes", 0))
                if current_total > 0:
                    continue
                row["rx_bytes"] = agg_rx
                row["tx_bytes"] = agg_tx
                row["total_bytes"] = max(0, agg_rx + agg_tx)
                row["rx_human"] = format_bytes(row["rx_bytes"])
                row["tx_human"] = format_bytes(row["tx_bytes"])
                row["total_human"] = format_bytes(row["total_bytes"])

    online_users.sort(
        key=lambda item: (
            int(item.get("latest_handshake", 0) or 0),
            int(item.get("total_bytes", 0) or 0),
        ),
        reverse=True,
    )
    for item in online_users:
        item.pop("__source_key", None)
    summary = {
        "tracked_users": len(users),
        "online_users": len(online_users),
        "total_download_bytes": sum(int(item["tx_bytes"]) for item in online_users),
        "total_upload_bytes": sum(int(item["rx_bytes"]) for item in online_users),
        "total_traffic_bytes": sum(int(item["total_bytes"]) for item in online_users),
        "source_errors": len(cache_errors),
        "source_errors_text": " | ".join(
            f"{source_labels.get(name, name)}: {message}" for name, message in cache_errors.items()
        ).strip(),
        "detect_mode": detect_mode,
        "unknown_online_sources": sum(
            1 for item in online_users if str(item.get("role", "")) == "unknown"
        ),
    }
    summary["total_download_human"] = format_bytes(summary["total_download_bytes"])
    summary["total_upload_human"] = format_bytes(summary["total_upload_bytes"])
    summary["total_traffic_human"] = format_bytes(summary["total_traffic_bytes"])
    return online_users, summary


def get_user_current_plan_display(db: DatabaseConnection, user: DatabaseRow) -> str:
    if has_active_time_subscription(user):
        return "内部账号（不限时长）"
    return "账号已停用"


def load_first_plan_for_onboarding(db: DatabaseConnection) -> dict:
    plan = db.execute(
        """
        SELECT
            id,
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit,
            traffic_gb,
            price_usdt,
            sort_order
        FROM subscription_plans
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    if not plan:
        return {
            "plan_name": "月付 1个月",
            "billing_mode": PLAN_MODE_DURATION,
            "duration_months": 1,
            "traffic_gb": 0,
            "price_usdt": "10.00",
            "sort_order": 10,
        }
    mode = normalize_plan_mode(plan["billing_mode"])
    duration_months = max(1, to_non_negative_int(plan["duration_months"]) or 1)
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(plan, "duration_value", 0),
        duration_unit_raw=row_get(plan, "duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    duration_months_for_onboarding = duration_value_to_legacy_months(duration_value, duration_unit)
    if duration_months_for_onboarding <= 0:
        duration_months_for_onboarding = duration_months
    return {
        "plan_name": (plan["plan_name"] or "").strip() or "基础套餐",
        "billing_mode": mode,
        "duration_months": duration_months_for_onboarding,
        "traffic_gb": max(1, to_non_negative_int(plan["traffic_gb"]) or 1),
        "price_usdt": format_usdt(plan["price_usdt"]),
        "sort_order": to_non_negative_int(plan["sort_order"]),
    }


def upsert_first_plan_from_onboarding(
    db: DatabaseConnection,
    *,
    plan_name: str,
    billing_mode: str,
    duration_months: int | None,
    traffic_gb: int | None,
    price_usdt: Decimal,
    sort_order: int = 10,
) -> None:
    existing = db.execute(
        """
        SELECT id
        FROM subscription_plans
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    now_iso = utcnow_iso()
    normalized_mode = normalize_plan_mode(billing_mode)

    if existing:
        db.execute(
            """
            UPDATE subscription_plans
            SET plan_name = ?,
                billing_mode = ?,
                duration_months = ?,
                duration_value = ?,
                duration_unit = ?,
                traffic_gb = ?,
                price_usdt = ?,
                is_active = 1,
                sort_order = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                plan_name,
                normalized_mode,
                duration_months if normalized_mode == PLAN_MODE_DURATION else None,
                duration_months if normalized_mode == PLAN_MODE_DURATION else None,
                PLAN_DURATION_UNIT_MONTH if normalized_mode == PLAN_MODE_DURATION else None,
                traffic_gb if normalized_mode == PLAN_MODE_TRAFFIC else None,
                format_usdt(price_usdt),
                sort_order,
                now_iso,
                existing["id"],
            ),
        )
        return

    db.execute(
        """
        INSERT INTO subscription_plans (
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit,
            traffic_gb,
            price_usdt,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            plan_name,
            normalized_mode,
            duration_months if normalized_mode == PLAN_MODE_DURATION else None,
            duration_months if normalized_mode == PLAN_MODE_DURATION else None,
            PLAN_DURATION_UNIT_MONTH if normalized_mode == PLAN_MODE_DURATION else None,
            traffic_gb if normalized_mode == PLAN_MODE_TRAFFIC else None,
            format_usdt(price_usdt),
            sort_order,
            now_iso,
            now_iso,
        ),
    )


def upsert_primary_payment_method_from_onboarding(
    db: DatabaseConnection,
    *,
    network: str,
    receive_address: str,
) -> None:
    existing = db.execute(
        """
        SELECT id
        FROM payment_methods
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """
    ).fetchone()
    now_iso = utcnow_iso()
    method_name = f"USDT {network}"
    if existing:
        db.execute(
            """
            UPDATE payment_methods
            SET method_code = 'usdt',
                method_name = ?,
                network = ?,
                receive_address = ?,
                is_active = 1,
                sort_order = 10,
                updated_at = ?
            WHERE id = ?
            """,
            (method_name, network, receive_address, now_iso, existing["id"]),
        )
    else:
        db.execute(
            """
            INSERT INTO payment_methods (
                method_code, method_name, network, receive_address,
                is_active, sort_order, created_at, updated_at
            )
            VALUES ('usdt', ?, ?, ?, 1, 10, ?, ?)
            """,
            (method_name, network, receive_address, now_iso, now_iso),
        )
    sync_legacy_payment_settings_with_default_method(db)


def create_server_record(
    db: DatabaseConnection,
    *,
    server_name: str,
    server_region: str,
    host: str,
    port: int,
    username: str,
    password: str,
    ssh_private_key: str = "",
    domain: str,
    kcptun_port: int,
    openvpn_port: int,
    dns_port: int,
    vpn_api_token: str,
    openvpn_enabled: bool = True,
    shadowsocks_enabled: bool = False,
    kcptun_enabled: bool = False,
    ssh_tunnel_enabled: bool = True,
    status: str = "pending",
) -> int:
    now_iso = utcnow_iso()
    cursor = db.execute(
        """
        INSERT INTO vpn_servers (
            server_name, server_region, host, port, username, password, ssh_private_key, domain, vpn_api_token,
            kcptun_port, openvpn_port, dns_port, openvpn_enabled, shadowsocks_enabled, kcptun_enabled, ssh_tunnel_enabled, status,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        (
            server_name,
            normalize_server_region(server_region),
            host,
            port,
            username,
            password,
            (ssh_private_key or "").strip(),
            domain,
            vpn_api_token,
            kcptun_port,
            openvpn_port,
            dns_port,
            1 if openvpn_enabled else 0,
            1 if shadowsocks_enabled else 0,
            1 if kcptun_enabled else 0,
            1 if ssh_tunnel_enabled else 0,
            status,
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.fetchone()["id"])


def parse_server_backend_selection(form) -> tuple[bool, bool, bool]:
    return False, False, False


def ensure_default_runtime_server(db: DatabaseConnection) -> None:
    if not OPENVPN_ENABLED:
        return
    host = host_without_optional_port(OPENVPN_ENDPOINT_HOST)
    if not host and VPN_API_URL:
        try:
            parsed = urllib_parse.urlparse(VPN_API_URL)
            host = host_without_optional_port(parsed.hostname or "")
        except Exception:
            host = ""
    if not host:
        return

    default_password = (
        os.environ.get("LOCAL_SERVER_PASSWORD")
        or os.environ.get("PORTAL_DEFAULT_SERVER_PASSWORD")
        or ""
    )
    default_private_key = os.environ.get("LOCAL_SERVER_SSH_PRIVATE_KEY") or ""
    existing = db.execute(
        """
        SELECT id, password, ssh_private_key
        FROM vpn_servers
        WHERE host = ?
        ORDER BY id ASC
        LIMIT 1
        """,
        (host,),
    ).fetchone()
    if existing:
        if (
            (default_password or default_private_key)
            and not (row_get(existing, "password", "") or "").strip()
            and not (row_get(existing, "ssh_private_key", "") or "").strip()
        ):
            db.execute(
                """
                UPDATE vpn_servers
                SET password = ?,
                    ssh_private_key = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    default_password,
                    default_private_key.strip(),
                    utcnow_iso(),
                    int(row_get(existing, "id")),
                ),
            )
        return

    existing_any = db.execute("SELECT id FROM vpn_servers LIMIT 1").fetchone()
    if existing_any:
        return

    now_iso = utcnow_iso()
    db.execute(
        """
        INSERT INTO vpn_servers (
            server_name, server_region, host, port, username, password,
            ssh_private_key, domain, vpn_api_token, kcptun_port, openvpn_port,
            dns_port, status, last_test_at, last_test_ok, last_test_message,
            last_deploy_at, last_deploy_ok, last_deploy_message,
            created_at, updated_at
        )
        VALUES (?, ?, ?, 22, 'root', ?, ?, '', ?, ?, ?, ?, 'online', ?, 1, ?, ?, 1, ?, ?, ?)
        """,
        (
            "本机 OpenVPN 节点",
            "默认",
            host,
            default_password,
            default_private_key.strip(),
            VPN_API_TOKEN,
            SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
            OPENVPN_ENDPOINT_PORT,
            SERVER_DEPLOY_DEFAULT_DNS_PORT,
            now_iso,
            "默认部署自动登记本机节点。",
            now_iso,
            "OpenVPN 已由默认部署启用。",
            now_iso,
            now_iso,
        ),
    )


def update_server_test_result(
    db: DatabaseConnection,
    server_id: int,
    *,
    ok: bool,
    message: str,
) -> None:
    db.execute(
        """
        UPDATE vpn_servers
        SET last_test_at = ?,
            last_test_ok = ?,
            last_test_message = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            utcnow_iso(),
            1 if ok else 0,
            summarize_text(message, 1200),
            utcnow_iso(),
            server_id,
        ),
    )


def update_server_deploy_result(
    db: DatabaseConnection,
    server_id: int,
    *,
    ok: bool,
    message: str,
    status: str,
    vpn_api_token: str | None = None,
    deploy_log: str | None = None,
) -> None:
    normalized_deploy_log = clip_text(normalize_deploy_log_text(deploy_log or ""))
    if not normalized_deploy_log:
        normalized_deploy_log = clip_text(
            normalize_deploy_log_text(message or "部署任务结束，但未生成日志。")
        )
    params: list[object] = [
        status,
        utcnow_iso(),
        1 if ok else 0,
        summarize_text(message, 1200),
        normalized_deploy_log,
        utcnow_iso(),
        server_id,
    ]
    sql = """
        UPDATE vpn_servers
        SET status = ?,
            last_deploy_at = ?,
            last_deploy_ok = ?,
            last_deploy_message = ?,
            last_deploy_log = ?,
            updated_at = ?
    """
    if vpn_api_token:
        sql += ", vpn_api_token = ?"
        params.insert(-1, vpn_api_token)
    sql += " WHERE id = ?"
    db.execute(sql, params)


def mark_server_deploying(
    db: DatabaseConnection,
    server_id: int,
    *,
    message: str = "部署任务已启动，正在后台执行。",
) -> None:
    now_iso = utcnow_iso()
    short_message = summarize_text(message, 1200)
    deploying_log = "\n".join(
        [
            "[deploy] 任务信息",
            f"开始时间: {now_iso}",
            "状态: deploying",
            "脚本是否执行: 等待执行",
            "说明: 后台正在通过 SSH 执行安装脚本，请稍后刷新部署日志。",
        ]
    ).strip()
    db.execute(
        """
        UPDATE vpn_servers
        SET status = 'deploying',
            last_deploy_at = ?,
            last_deploy_ok = 0,
            last_deploy_message = ?,
            last_deploy_log = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            now_iso,
            short_message,
            clip_text(deploying_log),
            now_iso,
            server_id,
        ),
    )


def run_server_deploy_task(server_id: int) -> None:
    with app.app_context():
        db = get_db()
        row = db.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            return
        ok, test_message = test_server_connectivity(
            row["host"],
            normalize_server_port(row["port"], 22),
            row["username"],
            row["password"],
            row_get(row, "ssh_private_key", ""),
        )
        update_server_test_result(db, server_id, ok=ok, message=test_message)
        db.commit()
        if not ok:
            update_server_deploy_result(
                db,
                server_id,
                ok=False,
                message=f"服务器连接测试失败：{test_message}",
                status="deploy_failed",
                vpn_api_token=row_get(row, "vpn_api_token", ""),
                deploy_log=f"[deploy] 连接测试失败\n{test_message}",
            )
            db.commit()
            return
        try:
            deploy_ok, deploy_message, final_token, deploy_log = deploy_vpn_node_server(
                host=row["host"],
                port=normalize_server_port(row["port"], 22),
                username=row["username"],
                password=row["password"],
                private_key_text=row_get(row, "ssh_private_key", ""),
                kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
                shadowsocks_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
                dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
                openvpn_enabled=int(row_get(row, "openvpn_enabled", 1) or 0) == 1,
                shadowsocks_enabled=int(row_get(row, "shadowsocks_enabled", 0) or 0) == 1,
                kcptun_enabled=int(row_get(row, "kcptun_enabled", 0) or 0) == 1,
                vpn_api_token=row_get(row, "vpn_api_token", ""),
            )
        except Exception as exc:
            deploy_ok = False
            deploy_message = f"部署异常：{exc}"
            final_token = row_get(row, "vpn_api_token", "")
            deploy_log = deploy_message

        update_server_deploy_result(
            db,
            server_id,
            ok=deploy_ok,
            message=deploy_message,
            status="online" if deploy_ok else "deploy_failed",
            vpn_api_token=final_token,
            deploy_log=deploy_log,
        )
        db.commit()


def launch_server_deploy_task(server_id: int) -> None:
    thread = threading.Thread(
        target=run_server_deploy_task,
        args=(server_id,),
        daemon=True,
        name=f"server-deploy-{server_id}",
    )
    thread.start()


def redirect_admin_onboarding_modal(step: int | None = None):
    if step is not None and 1 <= step <= 4:
        return redirect(
            url_for("admin_subscriptions", onboarding_open="1", onboarding_step=str(step))
        )
    return redirect(url_for("admin_subscriptions", onboarding_open="1"))


def render_onboarding_deploy_log_page(
    *, success: bool, message: str, log_text: str
):
    return render_template(
        "admin_deploy_log.html",
        deploy_success=success,
        deploy_message=message,
        deploy_log=(log_text or message),
        admin_page="home",
    )


@app.route("/admin/onboarding/step-plan", methods=["POST"])
@login_required
@admin_required
def admin_onboarding_step_plan():
    db = get_db()
    if is_admin_onboarding_completed(db):
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_subscriptions"))

    plan_name = request.form.get("plan_name", "").strip()
    plan_mode = normalize_plan_mode(request.form.get("plan_mode", PLAN_MODE_DURATION))
    plan_price_raw = request.form.get("plan_price_usdt", "").strip()
    plan_duration_raw = request.form.get("plan_duration_months", "").strip()
    plan_traffic_raw = request.form.get("plan_traffic_gb", "").strip()
    if plan_mode == PLAN_MODE_DURATION:
        plan_traffic_raw = ""
    else:
        plan_duration_raw = ""

    if not plan_name:
        flash("请填写套餐名称。", "error")
        return redirect_admin_onboarding_modal(1)
    try:
        plan_price = parse_usdt_amount_strict(plan_price_raw)
    except Exception:
        flash("套餐价格格式无效。", "error")
        return redirect_admin_onboarding_modal(1)

    if plan_mode == PLAN_MODE_DURATION:
        try:
            plan_duration = parse_positive_int(plan_duration_raw)
        except Exception:
            flash("按时长套餐请填写大于 0 的月数。", "error")
            return redirect_admin_onboarding_modal(1)
        plan_traffic = None
    else:
        try:
            plan_traffic = parse_positive_int(plan_traffic_raw)
        except Exception:
            flash("按流量套餐请填写大于 0 的流量（GB）。", "error")
            return redirect_admin_onboarding_modal(1)
        plan_duration = None

    upsert_first_plan_from_onboarding(
        db,
        plan_name=plan_name,
        billing_mode=plan_mode,
        duration_months=plan_duration,
        traffic_gb=plan_traffic,
        price_usdt=plan_price,
        sort_order=10,
    )
    db.commit()
    flash("步骤 1 已保存。", "success")
    return redirect_admin_onboarding_modal(next_admin_onboarding_step(db, fallback=2))


@app.route("/admin/onboarding/step-payment", methods=["POST"])
@login_required
@admin_required
def admin_onboarding_step_payment():
    db = get_db()
    if is_admin_onboarding_completed(db):
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_subscriptions"))

    payment_network = request.form.get("payment_network", "TRC20").strip().upper()
    payment_address = request.form.get("payment_address", "").strip()
    portal_domain = normalize_domain_host(request.form.get("portal_domain", ""))

    if payment_network not in USDT_NETWORK_OPTIONS:
        flash("收款网络无效。", "error")
        return redirect_admin_onboarding_modal(2)
    if not payment_address:
        flash("请填写收款地址。", "error")
        return redirect_admin_onboarding_modal(2)
    if not portal_domain:
        flash("请填写站点域名。", "error")
        return redirect_admin_onboarding_modal(2)

    upsert_primary_payment_method_from_onboarding(
        db,
        network=payment_network,
        receive_address=payment_address,
    )
    upsert_app_setting(db, ONBOARDING_SETTING_PORTAL_DOMAIN, portal_domain)
    ensure_managed_domain_entry(
        db,
        portal_domain,
        cloudflare_account_id=get_default_cloudflare_account_id(db),
        sort_order=10,
    )
    db.commit()
    flash("步骤 2 已保存。", "success")
    return redirect_admin_onboarding_modal(next_admin_onboarding_step(db, fallback=3))


@app.route("/admin/onboarding/step-cloudflare", methods=["POST"])
@login_required
@admin_required
def admin_onboarding_step_cloudflare():
    db = get_db()
    if is_admin_onboarding_completed(db):
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_subscriptions"))

    cloudflare_account = request.form.get("cloudflare_account", "").strip()
    cloudflare_password = request.form.get("cloudflare_password", "").strip()
    cloudflare_zone_name = normalize_fqdn(request.form.get("cloudflare_zone_name", ""))

    if not cloudflare_account or not cloudflare_password:
        flash("请填写 Cloudflare 邮箱和 Global API Key。", "error")
        return redirect_admin_onboarding_modal(3)
    if not looks_like_email(cloudflare_account):
        flash("Cloudflare 邮箱格式无效。", "error")
        return redirect_admin_onboarding_modal(3)

    try:
        account_id = upsert_primary_cloudflare_account_from_onboarding(
            db,
            account_name=cloudflare_account,
            api_token=cloudflare_password,
            zone_name=cloudflare_zone_name,
        )
    except Exception as exc:
        flash(f"Cloudflare 配置失败：{exc}", "error")
        return redirect_admin_onboarding_modal(3)
    upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT, cloudflare_account)
    upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_PASSWORD, cloudflare_password)
    portal_domain = normalize_fqdn(load_onboarding_settings(db).get("portal_domain", ""))
    if portal_domain:
        ensure_managed_domain_entry(
            db,
            portal_domain,
            cloudflare_account_id=account_id,
            sort_order=10,
        )
    db.commit()
    flash("步骤 3 已保存。", "success")
    return redirect_admin_onboarding_modal(next_admin_onboarding_step(db, fallback=4))


@app.route("/admin/onboarding/step-server", methods=["POST"])
@login_required
@admin_required
def admin_onboarding_step_server():
    db = get_db()
    if is_admin_onboarding_completed(db):
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_subscriptions"))

    action = (request.form.get("action", "save_draft") or "").strip().lower()
    show_deploy_log_window = (
        action == "save_and_deploy"
        and (request.form.get("open_deploy_log_window", "") or "").strip() == "1"
    )
    server_host = normalize_remote_host(request.form.get("server_host", ""))
    server_port = normalize_server_port(request.form.get("server_port", "22"), 22)
    server_username = request.form.get("server_username", "").strip()
    server_password = request.form.get("server_password", "")
    server_private_key = request.form.get("server_private_key", "")

    save_onboarding_server_draft(
        db,
        server_name=server_host,
        server_host=server_host,
        server_port=server_port,
        server_username=server_username or "root",
        server_password=server_password,
        server_private_key=server_private_key,
    )

    if action == "save_draft":
        db.commit()
        flash("步骤 4 草稿已保存，可稍后继续。", "success")
        return redirect_admin_onboarding_modal(4)

    if (
        not server_host
        or not server_username
        or (not server_password and not (server_private_key or "").strip())
    ):
        db.commit()
        message = "请填写服务器 IP/域名、账号，并提供密码或私钥。"
        if show_deploy_log_window:
            return render_onboarding_deploy_log_page(
                success=False,
                message=message,
                log_text=message,
            )
        flash(message, "error")
        return redirect_admin_onboarding_modal(4)

    if action == "test_server":
        ok, message = test_server_connectivity(
            server_host,
            server_port,
            server_username,
            server_password,
            server_private_key,
        )
        db.commit()
        flash(message, "success" if ok else "error")
        return redirect_admin_onboarding_modal(4)

    step_status, next_step = get_admin_onboarding_step_status(db)
    if not step_status[1] or not step_status[2] or not step_status[3]:
        db.commit()
        message = "请先完成前 3 个步骤后再部署服务器。"
        if show_deploy_log_window:
            return render_onboarding_deploy_log_page(
                success=False,
                message=message,
                log_text=message,
            )
        flash(message, "error")
        return redirect_admin_onboarding_modal(next_step)

    ok, test_message = test_server_connectivity(
        server_host,
        server_port,
        server_username,
        server_password,
        server_private_key,
    )
    if not ok:
        db.commit()
        message = f"服务器连通测试失败：{test_message}"
        if show_deploy_log_window:
            return render_onboarding_deploy_log_page(
                success=False,
                message=message,
                log_text=message,
            )
        flash(message, "error")
        return redirect_admin_onboarding_modal(4)

    settings = load_onboarding_settings(db)
    portal_domain = normalize_fqdn(str(settings["portal_domain"]))
    server_name = server_host

    deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
    server_id = create_server_record(
        db,
        server_name=server_name,
        server_region="",
        host=server_host,
        port=server_port,
        username=server_username,
        password=server_password,
        ssh_private_key=server_private_key,
        domain="",
        kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
        openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
        dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
        vpn_api_token=deploy_token,
        status="deploying",
    )
    update_server_test_result(
        db,
        server_id,
        ok=True,
        message=test_message,
    )

    deploy_ok, deploy_message, final_token, deploy_log = deploy_vpn_node_server(
        host=server_host,
        port=server_port,
        username=server_username,
        password=server_password,
        private_key_text=server_private_key,
        kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
        shadowsocks_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
        dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
        openvpn_enabled=True,
        shadowsocks_enabled=False,
        kcptun_enabled=False,
        vpn_api_token=deploy_token,
    )
    update_server_deploy_result(
        db,
        server_id,
        ok=deploy_ok,
        message=deploy_message,
        status="online" if deploy_ok else "deploy_failed",
        vpn_api_token=final_token,
        deploy_log=deploy_log,
    )
    domain_ok = False
    domain_message = ""
    if deploy_ok:
        try:
            domain_ok, domain_message = assign_managed_domain_to_server(
                db,
                server_id,
                preferred_domain=portal_domain,
            )
        except Exception as exc:
            domain_message = str(exc)
    if deploy_ok:
        upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED, "1")
        upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED_AT, utcnow_iso())
        upsert_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, str(server_id))
        save_onboarding_server_draft(
            db,
            server_name=server_name,
            server_host=server_host,
            server_port=server_port,
            server_username=server_username,
            server_password="",
            server_private_key="",
        )
        db.commit()
        if show_deploy_log_window:
            final_message = deploy_message
            if domain_message:
                final_message = (
                    f"{deploy_message}\n{domain_message}"
                    if domain_ok
                    else f"{deploy_message}\n域名分配失败：{domain_message}"
                )
            return render_onboarding_deploy_log_page(
                success=True,
                message=final_message,
                log_text=f"{deploy_log}\n\n{final_message}",
            )
        flash("初始化完成，VPN 服务端部署成功。", "success")
        if domain_message:
            flash(domain_message, "success" if domain_ok else "error")
        return redirect(url_for("admin_subscriptions"))

    db.commit()
    if show_deploy_log_window:
        return render_onboarding_deploy_log_page(
            success=False,
            message=deploy_message,
            log_text=deploy_log,
        )
    flash(f"服务器部署失败：{deploy_message}", "error")
    return redirect_admin_onboarding_modal(4)


@app.route("/admin/onboarding", methods=["GET", "POST"])
@login_required
@admin_required
def admin_onboarding():
    return redirect_admin_onboarding_modal()

    db = get_db()
    settings = load_onboarding_settings(db)
    if settings["setup_completed"]:
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_subscriptions"))

    first_plan = load_first_plan_for_onboarding(db)
    payment_settings = load_payment_settings(db)
    save_mode = request.form.get("plan_mode", first_plan["billing_mode"]) if request.method == "POST" else first_plan["billing_mode"]

    if request.method == "POST":
        action = (request.form.get("action", "save_and_deploy") or "").strip().lower()
        if action == "test_server":
            host = request.form.get("server_host", "").strip()
            port = normalize_server_port(request.form.get("server_port", "22"), 22)
            username = request.form.get("server_username", "").strip()
            password = request.form.get("server_password", "")
            ok, message = test_server_connectivity(host, port, username, password)
            flash(message, "success" if ok else "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=save_mode,
                admin_page="onboarding",
            )

        plan_name = request.form.get("plan_name", "").strip()
        plan_mode = normalize_plan_mode(request.form.get("plan_mode", PLAN_MODE_DURATION))
        plan_price_raw = request.form.get("plan_price_usdt", "").strip()
        plan_duration_raw = request.form.get("plan_duration_months", "").strip()
        plan_traffic_raw = request.form.get("plan_traffic_gb", "").strip()
        if plan_mode == PLAN_MODE_DURATION:
            plan_traffic_raw = ""
        else:
            plan_duration_raw = ""

        payment_network = request.form.get("payment_network", "TRC20").strip().upper()
        payment_address = request.form.get("payment_address", "").strip()

        portal_domain = normalize_domain_host(request.form.get("portal_domain", ""))
        cloudflare_account = request.form.get("cloudflare_account", "").strip()
        cloudflare_password = request.form.get("cloudflare_password", "").strip()

        server_host = normalize_remote_host(request.form.get("server_host", ""))
        server_port = normalize_server_port(request.form.get("server_port", "22"), 22)
        server_username = request.form.get("server_username", "").strip()
        server_password = request.form.get("server_password", "")

        if not plan_name:
            flash("请填写第一个套餐名称。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )
        try:
            plan_price = parse_usdt_amount_strict(plan_price_raw)
        except Exception:
            flash("套餐价格格式无效。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )

        if plan_mode == PLAN_MODE_DURATION:
            try:
                plan_duration = parse_positive_int(plan_duration_raw)
            except Exception:
                flash("按时长套餐请填写大于 0 的月数。", "error")
                return render_template(
                    "admin_onboarding.html",
                    settings=settings,
                    first_plan=first_plan,
                    payment_settings=payment_settings,
                    save_mode=plan_mode,
                    admin_page="onboarding",
                )
            plan_traffic = None
        else:
            try:
                plan_traffic = parse_positive_int(plan_traffic_raw)
            except Exception:
                flash("按流量套餐请填写大于 0 的流量（GB）。", "error")
                return render_template(
                    "admin_onboarding.html",
                    settings=settings,
                    first_plan=first_plan,
                    payment_settings=payment_settings,
                    save_mode=plan_mode,
                    admin_page="onboarding",
                )
            plan_duration = None

        if payment_network not in USDT_NETWORK_OPTIONS:
            flash("收款网络无效。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )
        if not payment_address:
            flash("请填写收款地址（用于收款二维码）。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )
        if not portal_domain:
            flash("请填写站点域名。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )
        if not cloudflare_account or not cloudflare_password:
            flash("请填写 Cloudflare 邮箱和 Global API Key。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )

        if not server_host or not server_username or not server_password:
            flash("请填写服务器 IP/域名、账号、密码。", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )

        ok, test_message = test_server_connectivity(
            server_host,
            server_port,
            server_username,
            server_password,
        )
        if not ok:
            flash(f"服务器连通测试失败：{test_message}", "error")
            return render_template(
                "admin_onboarding.html",
                settings=settings,
                first_plan=first_plan,
                payment_settings=payment_settings,
                save_mode=plan_mode,
                admin_page="onboarding",
            )

        upsert_primary_payment_method_from_onboarding(
            db,
            network=payment_network,
            receive_address=payment_address,
        )
        upsert_first_plan_from_onboarding(
            db,
            plan_name=plan_name,
            billing_mode=plan_mode,
            duration_months=plan_duration,
            traffic_gb=plan_traffic,
            price_usdt=plan_price,
            sort_order=10,
        )
        upsert_app_setting(db, ONBOARDING_SETTING_PORTAL_DOMAIN, portal_domain)
        upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT, cloudflare_account)
        upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_PASSWORD, cloudflare_password)

        server_name = server_host
        deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
        server_id = create_server_record(
            db,
            server_name=server_name,
            server_region="",
            host=server_host,
            port=server_port,
            username=server_username,
            password=server_password,
            ssh_private_key="",
            domain="",
            kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
            openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
            dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
            vpn_api_token=deploy_token,
            status="deploying",
        )
        update_server_test_result(
            db,
            server_id,
            ok=True,
            message=test_message,
        )

        deploy_ok, deploy_message, final_token, deploy_log = deploy_vpn_node_server(
            host=server_host,
            port=server_port,
            username=server_username,
            password=server_password,
            kcptun_port=SERVER_DEPLOY_DEFAULT_KCPTUN_PORT,
            shadowsocks_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
            dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
            openvpn_enabled=True,
            shadowsocks_enabled=False,
            kcptun_enabled=False,
            vpn_api_token=deploy_token,
        )
        update_server_deploy_result(
            db,
            server_id,
            ok=deploy_ok,
            message=deploy_message,
            status="online" if deploy_ok else "deploy_failed",
            vpn_api_token=final_token,
            deploy_log=deploy_log,
        )
        if deploy_ok:
            upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED, "1")
            upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED_AT, utcnow_iso())
            upsert_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, str(server_id))
            db.commit()
            flash("初始化完成，VPN 服务端部署成功。", "success")
            return redirect(url_for("admin_subscriptions"))

        db.commit()
        flash(f"初始化信息已保存，但服务端部署失败：{deploy_message}", "error")
        return render_template(
            "admin_onboarding.html",
            settings=load_onboarding_settings(db),
            first_plan=load_first_plan_for_onboarding(db),
            payment_settings=load_payment_settings(db),
            save_mode=plan_mode,
            admin_page="onboarding",
        )

    return render_template(
        "admin_onboarding.html",
        settings=settings,
        first_plan=first_plan,
        payment_settings=payment_settings,
        save_mode=first_plan["billing_mode"],
        admin_page="onboarding",
    )


@app.route("/admin/servers")
@login_required
@admin_required
def admin_servers():
    db = get_db()
    refresh_missing_server_regions(db)
    refresh_server_health_status(db, force=True)
    db.commit()
    servers = load_admin_servers(db)
    return render_template(
        "admin_servers.html",
        servers=servers,
        admin_page="servers",
    )


@app.route("/admin/servers/test", methods=["POST"])
@login_required
@admin_required
def admin_test_server_connection():
    try:
        payload = request.get_json(silent=True) or request.form
        host = normalize_remote_host(payload.get("host", ""))
        port = normalize_server_port(payload.get("port", "22"), 22)
        username = (payload.get("username", "") or "").strip()
        password = payload.get("password", "") or ""
        private_key_text = payload.get("private_key", "") or ""

        ok, message = test_server_connectivity(
            host, port, username, password, private_key_text
        )
        status_code = 200 if ok else 400
        return {"ok": ok, "message": message}, status_code
    except Exception as exc:
        app.logger.exception("server connection test failed: %s", exc)
        return {"ok": False, "message": f"测试请求失败：{exc}"}, 500


@app.route("/admin/servers/create", methods=["GET", "POST"])
@login_required
@admin_required
def admin_create_server():
    if request.method == "GET":
        return redirect(url_for("admin_servers"))
    db = get_db()
    host = normalize_remote_host(request.form.get("host", ""))
    server_region = detect_server_region(host)
    domain = normalize_domain_host(request.form.get("domain", ""))
    port = normalize_server_port(request.form.get("port", "22"), 22)
    username = (request.form.get("username", "") or "").strip()
    password = request.form.get("password", "") or ""
    ssh_private_key = request.form.get("ssh_private_key", "") or ""
    kcptun_port = SERVER_DEPLOY_DEFAULT_KCPTUN_PORT
    openvpn_port = SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
    dns_port = SERVER_DEPLOY_DEFAULT_DNS_PORT
    openvpn_enabled, shadowsocks_enabled, kcptun_enabled = parse_server_backend_selection(
        request.form
    )

    if not host or not username or (not password and not (ssh_private_key or "").strip()):
        flash("请完整填写服务器地址、账号，并提供密码或私钥。", "error")
        return redirect(url_for("admin_servers"))
    if not domain:
        flash("请填写客户端连接域名。", "error")
        return redirect(url_for("admin_servers"))
    server_name = host
    deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
    server_id = create_server_record(
        db,
        server_name=server_name,
        server_region=server_region,
        host=host,
        port=port,
        username=username,
        password=password,
        ssh_private_key=ssh_private_key,
        domain=domain,
        kcptun_port=kcptun_port,
        openvpn_port=openvpn_port,
        dns_port=dns_port,
        openvpn_enabled=openvpn_enabled,
        shadowsocks_enabled=shadowsocks_enabled,
        kcptun_enabled=kcptun_enabled,
        ssh_tunnel_enabled=True,
        vpn_api_token=deploy_token,
        status="deploying",
    )
    mark_server_deploying(db, server_id)
    # 先落库再异步部署，确保部署失败/中断时服务器仍保留在列表中可查看日志。
    db.commit()
    launch_server_deploy_task(server_id)
    flash("服务器已保存，连接测试和部署已转入后台执行。可在列表查看状态并打开部署日志。", "success")
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/test", methods=["POST"])
@login_required
@admin_required
def admin_test_saved_server(server_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,)).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))
    ok, message = test_server_connectivity(
        row["host"],
        normalize_server_port(row["port"], 22),
        row["username"],
        row["password"],
        row_get(row, "ssh_private_key", ""),
    )
    update_server_test_result(db, server_id, ok=ok, message=message)
    db.commit()
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/ipv6/<string:action>", methods=["POST"])
@login_required
@admin_required
def admin_toggle_server_ipv6(server_id: int, action: str):
    normalized_action = (action or "").strip().lower()
    if normalized_action not in {"enable", "disable"}:
        flash("IPv6 操作无效。", "error")
        return redirect(url_for("admin_servers"))

    db = get_db()
    row = db.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,)).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))

    enable = normalized_action == "enable"
    ok, message = set_server_ipv6_state(
        server_row=row,
        host=row_get(row, "host", ""),
        port=normalize_server_port(row_get(row, "port", 22), 22),
        username=row_get(row, "username", ""),
        password=row_get(row, "password", "") or "",
        private_key_text=row_get(row, "ssh_private_key", "") or "",
        enable=enable,
    )
    update_server_test_result(db, server_id, ok=ok, message=message)
    db.commit()
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/deploy-log")
@login_required
@admin_required
def admin_server_deploy_log(server_id: int):
    db = get_db()
    row = db.execute(
        """
        SELECT
            id,
            server_name,
            host,
            status,
            last_test_at,
            last_test_message,
            last_deploy_at,
            last_deploy_message,
            last_deploy_log
        FROM vpn_servers
        WHERE id = ?
        LIMIT 1
        """,
        (server_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "服务器不存在。"}, 404

    deploy_log = normalize_deploy_log_text(row_get(row, "last_deploy_log", ""))
    if not deploy_log:
        deploy_log = normalize_deploy_log_text(row_get(row, "last_deploy_message", ""))
    if not deploy_log:
        status = (row_get(row, "status", "") or "").strip().lower()
        if status == "deploying":
            deploy_log = "部署任务已启动，日志正在生成，请稍后刷新。"
        else:
            deploy_log = "暂无部署日志。"
    return {
        "ok": True,
        "server_id": int(row["id"]),
        "server_name": (row_get(row, "server_name", "") or "").strip()
        or (row_get(row, "host", "") or "").strip(),
        "last_test_at": row_get(row, "last_test_at", "") or "",
        "last_test_message": summarize_text(
            normalize_deploy_log_text(row_get(row, "last_test_message", "") or "") or "-",
            800,
        ),
        "last_deploy_at": row["last_deploy_at"] or "",
        "last_deploy_message": summarize_text(
            normalize_deploy_log_text(row_get(row, "last_deploy_message", "") or "") or "-",
            800,
        ),
        "deploy_log": deploy_log,
    }, 200


@app.route("/admin/servers/<int:server_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_saved_server(server_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,)).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))

    host = normalize_remote_host(request.form.get("host", ""))
    server_region = detect_server_region(host, row_get(row, "server_region", ""))
    domain = normalize_domain_host(request.form.get("domain", ""))
    port = normalize_server_port(request.form.get("port", "22"), 22)
    username = (request.form.get("username", "") or "").strip()
    password_raw = request.form.get("password", "") or ""
    private_key_raw = request.form.get("ssh_private_key", "") or ""
    kcptun_port = SERVER_DEPLOY_DEFAULT_KCPTUN_PORT
    openvpn_port = SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
    dns_port = SERVER_DEPLOY_DEFAULT_DNS_PORT
    openvpn_enabled, shadowsocks_enabled, kcptun_enabled = parse_server_backend_selection(
        request.form
    )

    if not host or not username:
        flash("服务器地址和账号不能为空。", "error")
        return redirect(url_for("admin_servers"))
    if not domain:
        flash("请填写客户端连接域名。", "error")
        return redirect(url_for("admin_servers"))
    server_name = host

    password_to_save = password_raw if password_raw else (row_get(row, "password", "") or "")
    private_key_to_save = (
        private_key_raw.strip()
        if private_key_raw.strip()
        else (row_get(row, "ssh_private_key", "") or "")
    )
    previous_status = (row_get(row, "status", "") or "").strip().lower()
    should_redeploy = (
        previous_status in {"online", "deploying"}
        or int(row_get(row, "last_deploy_ok", 0) or 0) == 1
        or bool((row_get(row, "last_deploy_at", "") or "").strip())
    )
    db.execute(
        """
        UPDATE vpn_servers
        SET server_name = ?,
            server_region = ?,
            host = ?,
            port = ?,
            username = ?,
            password = ?,
            ssh_private_key = ?,
            domain = ?,
            kcptun_port = ?,
            openvpn_port = ?,
            dns_port = ?,
            openvpn_enabled = ?,
            shadowsocks_enabled = ?,
            kcptun_enabled = ?,
            ssh_tunnel_enabled = 1,
            updated_at = ?
        WHERE id = ?
        """,
        (
            server_name,
            server_region,
            host,
            port,
            username,
            password_to_save,
            private_key_to_save,
            domain,
            kcptun_port,
            openvpn_port,
            dns_port,
            1 if openvpn_enabled else 0,
            1 if shadowsocks_enabled else 0,
            1 if kcptun_enabled else 0,
            utcnow_iso(),
            server_id,
        ),
    )

    if should_redeploy:
        mark_server_deploying(db, server_id)
        db.commit()
        launch_server_deploy_task(server_id)
        flash("服务器信息已更新；该服务器已部署过，远端服务变更已自动重新部署。", "success")
    else:
        db.commit()
        flash("服务器信息已保存；该服务器尚未部署，请需要时点击“部署”。", "success")
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_saved_server(server_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, server_name, host FROM vpn_servers WHERE id = ? LIMIT 1",
        (server_id,),
    ).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))

    release_server_domain_bindings(db, server_id)
    db.execute("DELETE FROM vpn_servers WHERE id = ?", (server_id,))
    if (get_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, "") or "").strip() == str(server_id):
        upsert_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, "")
    db.commit()
    server_label = (row_get(row, "host", "") or "").strip() or (
        row_get(row, "server_name", "") or ""
    ).strip()
    flash(
        f"服务器 {server_label} 已从管理列表删除；远端主机和已安装的本地服务会保留，可随时重新部署。",
        "success",
    )
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/deploy", methods=["POST"])
@login_required
@admin_required
def admin_deploy_saved_server(server_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,)).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))
    if (row_get(row, "status", "") or "").strip().lower() == "online":
        flash("服务器已部署完成，如需更新请使用升级。", "error")
        return redirect(url_for("admin_servers"))

    mark_server_deploying(db, server_id)
    db.commit()
    launch_server_deploy_task(server_id)
    flash("部署任务已启动。可在列表查看状态并打开部署日志。", "success")
    return redirect(url_for("admin_servers"))


@app.route("/admin/servers/<int:server_id>/upgrade", methods=["POST"])
@login_required
@admin_required
def admin_upgrade_saved_server(server_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, server_name, host FROM vpn_servers WHERE id = ? LIMIT 1",
        (server_id,),
    ).fetchone()
    if not row:
        flash("服务器不存在。", "error")
        return redirect(url_for("admin_servers"))

    mark_server_deploying(db, server_id)
    db.commit()
    launch_server_deploy_task(server_id)
    server_label = (row_get(row, "server_name", "") or "").strip() or (
        row_get(row, "host", "") or ""
    ).strip()
    flash(
        f"服务器 {server_label} 升级任务已启动，会按当前部署类型重新应用远端服务配置。",
        "success",
    )
    return redirect(url_for("admin_servers"))


@app.route("/admin/system/upgrade", methods=["POST"])
@login_required
@admin_required
def admin_upgrade_system():
    db = get_db()
    state = load_system_upgrade_state_with_timeout_unlock(db)
    if (state.get("status") or "").strip().lower() == "running":
        flash("系统升级任务正在运行中，请稍后刷新查看结果。", "error")
        return redirect(url_for("admin_subscriptions"))

    started_at = utcnow_iso()
    save_system_upgrade_state(
        status="running",
        summary="系统升级任务正在启动，请稍后刷新查看日志。",
        started_at=started_at,
        finished_at="",
    )
    append_system_upgrade_log("系统升级任务已触发，正在派发宿主机升级任务。")
    ok, message = dispatch_host_web_upgrade()
    if not ok:
        append_system_upgrade_log(f"升级任务派发失败：{message}")
        save_system_upgrade_state(
            status="failed",
            summary=f"系统升级任务派发失败：{message}",
            started_at=started_at,
            finished_at=utcnow_iso(),
        )
        flash(f"系统升级任务派发失败：{message}", "error")
        return redirect(url_for("admin_subscriptions"))

    append_system_upgrade_log(message)
    flash("系统升级任务已派发到宿主机，Web 会在新版本构建完成后自动重启。", "success")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/system/upgrade/log")
def admin_system_upgrade_log():
    if not session.get("user_id"):
        return {
            "ok": False,
            "error": "unauthorized",
            "message": "登录状态已失效，请重新登录。",
            "redirect": url_for("login"),
        }, 401
    user = current_user()
    if not user or row_get(user, "role", "") != "admin":
        return {
            "ok": False,
            "error": "forbidden",
            "message": "仅管理员可访问。",
            "redirect": url_for("dashboard"),
        }, 403

    db = get_db()
    state = load_system_upgrade_state_with_timeout_unlock(db)
    log_text = read_system_upgrade_log_text()
    if not log_text:
        status = (state.get("status") or "").strip().lower()
        if status == "running":
            log_text = "系统升级任务进行中，日志正在生成，请稍后刷新。"
        elif status in {"success", "failed"}:
            log_text = "暂无系统升级日志，请确认数据卷映射与权限是否正常。"
        else:
            log_text = "尚未触发系统升级。"
    return {
        "ok": True,
        "status": state.get("status", ""),
        "summary": state.get("summary", ""),
        "started_at": state.get("started_at", ""),
        "finished_at": state.get("finished_at", ""),
        "version": state.get("version", ""),
        "log_text": log_text,
    }, 200

@app.route("/admin/configs")
@login_required
@admin_required
def admin_configs():
    return redirect(url_for("admin_subscriptions"))


def _legacy_admin_configs():
    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账户不存在。", "error")
        return redirect(url_for("admin_subscriptions"))

    admin_vpn_error = ""
    endpoint_display = "-"

    target_server = choose_runtime_server_for_admin(db, admin)
    target_server_serialized = serialize_runtime_server(target_server)
    admin_openvpn_ready = bool(
        target_server_serialized
        and target_server_serialized.get("openvpn_enabled")
        and OPENVPN_ENABLED
        and is_openvpn_open(db)
    )
    admin_ss_kcptun_ready = bool(
        target_server_serialized
        and target_server_serialized.get("shadowsocks_enabled")
        and target_server_serialized.get("kcptun_enabled")
    )
    admin_vpn_ready = bool(admin_openvpn_ready or admin_ss_kcptun_ready)
    if admin_openvpn_ready and admin_ss_kcptun_ready:
        admin_vpn_status_text = "已就绪（OpenVPN + SS+kcptun）"
    elif admin_openvpn_ready:
        admin_vpn_status_text = "已就绪（OpenVPN）"
    elif admin_ss_kcptun_ready:
        admin_vpn_status_text = "已就绪（SS+kcptun）"
    else:
        admin_vpn_status_text = "未启用"
    target_server_name = "-"
    target_server_host = "-"
    if target_server is not None:
        target_server_name = (
            (row_get(target_server, "server_name", "") or "").strip()
            or (row_get(target_server, "host", "") or "").strip()
            or "-"
        )
        target_server_host = (row_get(target_server, "host", "") or "").strip() or "-"
        if admin_openvpn_ready:
            endpoint_display = (
                get_openvpn_endpoint_host(user=admin, server_row=target_server) or "-"
            ).strip() or "-"

    admin_openvpn_download_link = (
        absolute_url_for("admin_download_openvpn_config") if admin_openvpn_ready else ""
    )
    admin_ss_access_token = build_download_access_token(admin, "download-config-admin")
    admin_ss_download_link = (
        build_masked_download_link(admin_ss_access_token, output_format="yaml")
        if admin_ss_kcptun_ready
        else ""
    )
    admin_kcptun_download_link = (
        absolute_url_for("admin_download_kcptun_config") if admin_ss_kcptun_ready else ""
    )
    admin_ss_qr_link = absolute_url_for("admin_download_qr") if admin_ss_kcptun_ready else ""

    db.commit()

    return render_template(
        "admin_configs.html",
        admin_user=admin,
        admin_vpn_ready=admin_vpn_ready,
        admin_openvpn_ready=admin_openvpn_ready,
        admin_ss_kcptun_ready=admin_ss_kcptun_ready,
        admin_vpn_status_text=admin_vpn_status_text,
        admin_vpn_error=admin_vpn_error,
        target_server_name=target_server_name,
        target_server_host=target_server_host,
        endpoint_display=endpoint_display,
        admin_openvpn_download_link=admin_openvpn_download_link,
        admin_ss_download_link=admin_ss_download_link,
        admin_kcptun_download_link=admin_kcptun_download_link,
        admin_ss_qr_link=admin_ss_qr_link,
        admin_page="configs",
    )


@app.route("/admin/configs/server", methods=["POST"])
@login_required
@admin_required
def admin_set_default_server():
    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账户不存在。", "error")
        return redirect(url_for("admin_subscriptions"))

    server_id_raw = (request.form.get("server_id", "") or "").strip()
    redirect_to = (request.form.get("redirect_to", "") or "").strip()
    redirect_target = (
        "admin_subscriptions" if redirect_to == "admin_subscriptions" else "admin_subscriptions"
    )
    if not server_id_raw.isdigit():
        flash("请选择有效的默认节点。", "error")
        return redirect(url_for(redirect_target))

    server_id = int(server_id_raw)
    target_server = get_server_by_id(db, server_id)
    if not is_runtime_server_ready(target_server):
        flash("所选节点不可用，请选择在线节点。", "error")
        return redirect(url_for(redirect_target))

    db.execute(
        """
        UPDATE users
        SET assigned_server_id = ?,
            preferred_server_id = ?
        WHERE id = ? AND role = 'admin'
        """,
        (server_id, server_id, int(admin["id"])),
    )
    upsert_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, str(server_id))
    db.commit()

    region = normalize_server_region(row_get(target_server, "server_region", ""))
    name = (row_get(target_server, "server_name", "") or "").strip() or (
        row_get(target_server, "host", "") or ""
    ).strip()
    label = f"{region} / {name}" if region else name
    flash(f"管理员默认节点已更新为：{label}（OpenVPN 配置已按新节点生效）", "success")
    return redirect(url_for(redirect_target))


@app.route("/admin/settings")
@login_required
@admin_required
def admin_settings():
    db = get_db()
    system_settings = load_system_settings(db)
    return render_template(
        "admin_settings.html",
        system_settings=system_settings,
        admin_page="system_settings",
    )


def parse_mail_server_form(
    form,
    *,
    existing: DatabaseRow | None = None,
) -> tuple[dict[str, int | str] | None, str]:
    server_name = (form.get("server_name", "") or "").strip()
    host = normalize_remote_host(form.get("host", ""))
    port_raw = (form.get("port", "") or "").strip()
    username_input = (form.get("username", "") or "").strip()
    password_input = form.get("password", "") or ""
    from_email = (form.get("from_email", "") or "").strip().lower()
    from_name = (form.get("from_name", "") or "").strip()
    security = normalize_mail_security(form.get("security", MAIL_SECURITY_STARTTLS))
    sort_order_raw = (form.get("sort_order", "") or "").strip()
    is_active = (form.get("is_active", "1") or "1").strip() == "1"

    if not host:
        return None, "SMTP 服务器地址不能为空。"
    port = normalize_server_port(port_raw or 587, 587)
    if not from_email:
        return None, "发件邮箱不能为空。"
    if not looks_like_email(from_email):
        return None, "发件邮箱格式无效。"
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    username = username_input
    password = password_input
    if existing is None:
        if bool(username) != bool(password):
            return None, "如需启用 SMTP 登录认证，请同时填写账号和密码。"
    else:
        existing_username = (existing["username"] or "").strip()
        existing_password = existing["password"] or ""
        if password_input:
            if not username_input:
                return None, "修改 SMTP 密码时必须同时填写账号。"
            username = username_input
            password = password_input
        elif not username_input:
            username = ""
            password = ""
        elif username_input == existing_username:
            username = username_input
            password = existing_password
        else:
            return None, "修改 SMTP 账号时请同时填写新的密码。"

    return (
        build_mail_server_config(
            server_name=server_name or host,
            host=host,
            port=port,
            username=username,
            password=password,
            from_email=from_email,
            from_name=from_name,
            security=security,
            is_active=1 if is_active else 0,
            sort_order=sort_order,
        ),
        "",
    )


@app.route("/admin/mail-servers")
@login_required
@admin_required
def admin_mail_servers():
    db = get_db()
    mail_servers = load_mail_servers(db, active_only=False)
    active_mail_server = next((row for row in mail_servers if row["is_active"] == 1), None)
    env_mail_server = None if active_mail_server else load_env_mail_server_config()
    return render_template(
        "admin_mail_servers.html",
        mail_servers=mail_servers,
        active_mail_server=active_mail_server,
        env_mail_server=env_mail_server,
        mail_security_choices=[
            (choice, MAIL_SECURITY_LABELS[choice]) for choice in MAIL_SECURITY_CHOICES
        ],
        admin_page="mail_servers",
    )


@app.route("/admin/mail-servers/create", methods=["POST"])
@login_required
@admin_required
def admin_create_mail_server():
    db = get_db()
    payload, error_message = parse_mail_server_form(request.form)
    if error_message:
        flash(error_message, "error")
        return redirect(url_for("admin_mail_servers"))

    now_iso = utcnow_iso()
    cursor = db.execute(
        """
        INSERT INTO mail_servers (
            server_name,
            host,
            port,
            username,
            password,
            from_email,
            from_name,
            security,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        (
            payload["server_name"],
            payload["host"],
            payload["port"],
            payload["username"],
            payload["password"],
            payload["from_email"],
            payload["from_name"],
            payload["security"],
            payload["is_active"],
            payload["sort_order"],
            now_iso,
            now_iso,
        ),
    )
    mail_server_id = int(cursor.fetchone()["id"])
    if int(payload["is_active"] or 0) == 1:
        set_active_mail_server(db, mail_server_id)
    db.commit()
    flash(
        f"邮件服务器 {payload['server_name']} 已创建。"
        + (" 已设为当前启用配置。" if int(payload["is_active"] or 0) == 1 else ""),
        "success",
    )
    return redirect(url_for("admin_mail_servers"))


@app.route("/admin/mail-servers/<int:mail_server_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_mail_server(mail_server_id: int):
    db = get_db()
    existing = get_mail_server_by_id(db, mail_server_id)
    if not existing:
        flash("邮件服务器不存在。", "error")
        return redirect(url_for("admin_mail_servers"))

    payload, error_message = parse_mail_server_form(request.form, existing=existing)
    if error_message:
        flash(error_message, "error")
        return redirect(url_for("admin_mail_servers"))

    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE mail_servers
        SET server_name = ?,
            host = ?,
            port = ?,
            username = ?,
            password = ?,
            from_email = ?,
            from_name = ?,
            security = ?,
            is_active = ?,
            sort_order = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            payload["server_name"],
            payload["host"],
            payload["port"],
            payload["username"],
            payload["password"],
            payload["from_email"],
            payload["from_name"],
            payload["security"],
            payload["is_active"],
            payload["sort_order"],
            now_iso,
            mail_server_id,
        ),
    )
    if int(payload["is_active"] or 0) == 1:
        set_active_mail_server(db, mail_server_id)
    db.commit()
    flash(
        f"邮件服务器 {payload['server_name']} 已更新。"
        + (" 当前已启用。" if int(payload["is_active"] or 0) == 1 else ""),
        "success",
    )
    return redirect(url_for("admin_mail_servers"))


@app.route("/admin/mail-servers/<int:mail_server_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_mail_server(mail_server_id: int):
    db = get_db()
    mail_server = get_mail_server_by_id(db, mail_server_id)
    if not mail_server:
        flash("邮件服务器不存在。", "error")
        return redirect(url_for("admin_mail_servers"))

    server_name = (mail_server["server_name"] or "").strip() or (mail_server["host"] or "").strip()
    if int(mail_server["is_active"] or 0) == 1:
        db.execute(
            """
            UPDATE mail_servers
            SET is_active = 0,
                updated_at = ?
            WHERE id = ?
            """,
            (utcnow_iso(), mail_server_id),
        )
        db.commit()
        flash(f"邮件服务器 {server_name} 已停用。", "success")
    else:
        set_active_mail_server(db, mail_server_id)
        db.commit()
        flash(f"邮件服务器 {server_name} 已启用。", "success")
    return redirect(url_for("admin_mail_servers"))


@app.route("/admin/mail-servers/<int:mail_server_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_mail_server(mail_server_id: int):
    db = get_db()
    mail_server = get_mail_server_by_id(db, mail_server_id)
    if not mail_server:
        flash("邮件服务器不存在。", "error")
        return redirect(url_for("admin_mail_servers"))

    server_name = (mail_server["server_name"] or "").strip() or (mail_server["host"] or "").strip()
    db.execute("DELETE FROM mail_servers WHERE id = ?", (mail_server_id,))
    db.commit()
    flash(f"邮件服务器 {server_name} 已删除。", "success")
    return redirect(url_for("admin_mail_servers"))


@app.route("/admin/payment")
@login_required
@admin_required
def admin_payment_settings():
    flash("公司内部模式已取消套餐与收款配置，请在用户管理中创建账号。", "error")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/payment-methods")
@login_required
@admin_required
def admin_payment_methods():
    flash("公司内部模式已取消付款方式配置，请在用户管理中创建账号。", "error")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/cloudflare-accounts")
@login_required
@admin_required
def admin_cloudflare_accounts():
    db = get_db()
    accounts = load_cloudflare_accounts(db, active_only=False)
    return render_template(
        "admin_cloudflare_accounts.html",
        cloudflare_accounts=accounts,
        admin_page="cloudflare_accounts",
    )


@app.route("/admin/cloudflare-accounts/create", methods=["POST"])
@login_required
@admin_required
def admin_create_cloudflare_account():
    db = get_db()
    account_name = request.form.get("account_name", "").strip()
    api_token = request.form.get("api_token", "").strip()
    zone_name = normalize_fqdn(request.form.get("zone_name", ""))
    sort_order_raw = request.form.get("sort_order", "").strip()

    if not account_name:
        flash("Cloudflare 邮箱不能为空。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    if not looks_like_email(account_name):
        flash("Cloudflare 邮箱格式无效。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    if not api_token:
        flash("Global API Key 不能为空。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    try:
        selected_zone_name, selected_zone_id, zone_names = resolve_cloudflare_zone_from_token(
            api_token,
            auth_email=account_name,
            preferred_zone_name=zone_name,
        )
    except Exception as exc:
        flash(f"Cloudflare 域名读取失败：{exc}", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    now_iso = utcnow_iso()
    db.execute(
        """
        INSERT INTO cloudflare_accounts (
            account_name,
            api_token,
            zone_name,
            zone_id,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            account_name,
            api_token,
            selected_zone_name,
            selected_zone_id,
            sort_order,
            now_iso,
            now_iso,
        ),
    )
    db.commit()
    flash(
        f"Cloudflare 账号已添加。已自动识别可管理域名：{summarize_zone_names(zone_names)}；当前使用 {selected_zone_name}（邮箱 {account_name}）。",
        "success",
    )
    return redirect(url_for("admin_cloudflare_accounts"))


@app.route("/admin/cloudflare-accounts/<int:account_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_cloudflare_account(account_id: int):
    db = get_db()
    existing = db.execute(
        """
        SELECT id, api_token, zone_name
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not existing:
        flash("Cloudflare 账号不存在。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    account_name = request.form.get("account_name", "").strip()
    api_token = request.form.get("api_token", "").strip()
    zone_name = normalize_fqdn(request.form.get("zone_name", ""))
    sort_order_raw = request.form.get("sort_order", "").strip()

    if not account_name:
        flash("Cloudflare 邮箱不能为空。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    if not looks_like_email(account_name):
        flash("Cloudflare 邮箱格式无效。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    if not api_token:
        api_token = (existing["api_token"] or "").strip()
    if not api_token:
        flash("Global API Key 不能为空。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    preferred_zone = zone_name or normalize_fqdn(existing["zone_name"] or "")
    try:
        selected_zone_name, selected_zone_id, zone_names = resolve_cloudflare_zone_from_token(
            api_token,
            auth_email=account_name,
            preferred_zone_name=preferred_zone,
        )
    except Exception as exc:
        flash(f"Cloudflare 域名读取失败：{exc}", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    db.execute(
        """
        UPDATE cloudflare_accounts
        SET account_name = ?,
            api_token = ?,
            zone_name = ?,
            zone_id = ?,
            sort_order = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            account_name,
            api_token,
            selected_zone_name,
            selected_zone_id,
            sort_order,
            utcnow_iso(),
            account_id,
        ),
    )
    db.commit()
    flash(
        f"Cloudflare 账号已更新。已自动识别可管理域名：{summarize_zone_names(zone_names)}；当前使用 {selected_zone_name}（邮箱 {account_name}）。",
        "success",
    )
    return redirect(url_for("admin_cloudflare_accounts"))


@app.route("/admin/cloudflare-accounts/<int:account_id>/refresh-domains", methods=["POST"])
@login_required
@admin_required
def admin_refresh_cloudflare_domains(account_id: int):
    db = get_db()
    account = db.execute(
        """
        SELECT id, account_name
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not account:
        flash("Cloudflare 账号不存在。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    try:
        summary = sync_domains_from_cloudflare_account(db, int(account_id))
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"刷新失败：{exc}", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    flash(
        (
            f"账号 {account['account_name']} 域名刷新完成。"
            f"同步 Zone {summary['zone_count']} 个（{summarize_zone_names(summary['zone_names'])}），"
            f"新增 {summary['inserted_count']}、更新 {summary['updated_count']}、停用 {summary['disabled_count']}。"
            f"当前默认 Zone：{summary['selected_zone_name']}。"
        ),
        "success",
    )
    return redirect(url_for("admin_cloudflare_accounts"))


@app.route("/admin/cloudflare-accounts/<int:account_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_cloudflare_account(account_id: int):
    db = get_db()
    account = db.execute(
        """
        SELECT id, account_name, is_active
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not account:
        flash("Cloudflare 账号不存在。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    next_active = 0 if int(account["is_active"] or 0) == 1 else 1
    db.execute(
        """
        UPDATE cloudflare_accounts
        SET is_active = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (next_active, utcnow_iso(), account_id),
    )
    db.commit()
    flash(
        f"Cloudflare 账号 {account['account_name']} 已{'启用' if next_active == 1 else '停用'}。",
        "success",
    )
    return redirect(url_for("admin_cloudflare_accounts"))


@app.route("/admin/cloudflare-accounts/<int:account_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_cloudflare_account(account_id: int):
    db = get_db()
    account = db.execute(
        """
        SELECT id, account_name
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not account:
        flash("Cloudflare 账号不存在。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    bound_domain_count = db.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM managed_domains
        WHERE cloudflare_account_id = ?
        """,
        (account_id,),
    ).fetchone()["cnt"]
    if int(bound_domain_count or 0) > 0:
        flash("该账号下仍有关联域名，请先在域名管理中迁移或删除域名。", "error")
        return redirect(url_for("admin_cloudflare_accounts"))

    db.execute("DELETE FROM cloudflare_accounts WHERE id = ?", (account_id,))
    db.commit()
    flash(f"Cloudflare 账号 {account['account_name']} 已删除。", "success")
    return redirect(url_for("admin_cloudflare_accounts"))


@app.route("/admin/domains")
@login_required
@admin_required
def admin_domains():
    db = get_db()
    domains = load_managed_domains(db, active_only=False)
    accounts = load_cloudflare_accounts(db, active_only=False)
    return render_template(
        "admin_domains.html",
        managed_domains=domains,
        cloudflare_accounts=accounts,
        admin_page="domains",
    )


@app.route("/admin/domains/create", methods=["POST"])
@login_required
@admin_required
def admin_create_domain():
    flash("已禁用手动新增。请在 Cloudflare 账号列表点击“刷新域名”自动同步。", "error")
    return redirect(url_for("admin_domains"))


@app.route("/admin/domains/<int:domain_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_domain(domain_id: int):
    db = get_db()
    domain_row = db.execute(
        """
        SELECT id, assigned_server_id
        FROM managed_domains
        WHERE id = ?
        LIMIT 1
        """,
        (domain_id,),
    ).fetchone()
    if not domain_row:
        flash("域名不存在。", "error")
        return redirect(url_for("admin_domains"))

    domain_name = normalize_fqdn(request.form.get("domain_name", ""))
    account_id_raw = request.form.get("cloudflare_account_id", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()
    if not domain_name:
        flash("域名不能为空。", "error")
        return redirect(url_for("admin_domains"))
    try:
        account_id = int(account_id_raw)
    except Exception:
        account_id = 0
    if account_id <= 0:
        flash("请选择 Cloudflare 账号。", "error")
        return redirect(url_for("admin_domains"))
    account = db.execute(
        """
        SELECT id, is_active
        FROM cloudflare_accounts
        WHERE id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if not account:
        flash("Cloudflare 账号不存在。", "error")
        return redirect(url_for("admin_domains"))
    if int(account["is_active"] or 0) != 1:
        flash("所选 Cloudflare 账号已停用，请先启用后再绑定域名。", "error")
        return redirect(url_for("admin_domains"))
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    conflict = db.execute(
        """
        SELECT id
        FROM managed_domains
        WHERE lower(domain_name) = lower(?)
          AND id <> ?
        LIMIT 1
        """,
        (domain_name, domain_id),
    ).fetchone()
    if conflict:
        flash("域名已存在，请使用其他域名。", "error")
        return redirect(url_for("admin_domains"))

    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE managed_domains
        SET domain_name = ?,
            cloudflare_account_id = ?,
            dns_record_id = '',
            sort_order = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (domain_name, account_id, sort_order, now_iso, domain_id),
    )
    if domain_row["assigned_server_id"]:
        db.execute(
            """
            UPDATE vpn_servers
            SET domain = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (domain_name, now_iso, int(domain_row["assigned_server_id"])),
        )
    db.commit()
    flash("域名已更新。", "success")
    return redirect(url_for("admin_domains"))


@app.route("/admin/domains/<int:domain_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_domain(domain_id: int):
    db = get_db()
    domain_row = db.execute(
        """
        SELECT id, domain_name, is_active
        FROM managed_domains
        WHERE id = ?
        LIMIT 1
        """,
        (domain_id,),
    ).fetchone()
    if not domain_row:
        flash("域名不存在。", "error")
        return redirect(url_for("admin_domains"))

    next_active = 0 if int(domain_row["is_active"] or 0) == 1 else 1
    db.execute(
        """
        UPDATE managed_domains
        SET is_active = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (next_active, utcnow_iso(), domain_id),
    )
    db.commit()
    flash(
        f"域名 {domain_row['domain_name']} 已{'启用' if next_active == 1 else '停用'}。",
        "success",
    )
    return redirect(url_for("admin_domains"))


@app.route("/admin/domains/<int:domain_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_domain(domain_id: int):
    db = get_db()
    domain_row = db.execute(
        """
        SELECT id, domain_name, assigned_server_id
        FROM managed_domains
        WHERE id = ?
        LIMIT 1
        """,
        (domain_id,),
    ).fetchone()
    if not domain_row:
        flash("域名不存在。", "error")
        return redirect(url_for("admin_domains"))

    now_iso = utcnow_iso()
    if domain_row["assigned_server_id"]:
        db.execute(
            """
            UPDATE vpn_servers
            SET domain = '',
                updated_at = ?
            WHERE id = ?
            """,
            (now_iso, int(domain_row["assigned_server_id"])),
        )
    db.execute("DELETE FROM managed_domains WHERE id = ?", (domain_id,))
    db.commit()
    flash(f"域名 {domain_row['domain_name']} 已删除。", "success")
    return redirect(url_for("admin_domains"))


@app.route("/admin/orders/pending")
@login_required
@admin_required
def admin_pending_orders():
    flash("公司内部模式已取消订单支付，请在用户管理中创建账号。", "error")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/orders/paid")
@login_required
@admin_required
def admin_paid_orders():
    flash("公司内部模式已取消订单支付，请在用户管理中创建账号。", "error")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/subscriptions")
@login_required
@admin_required
def admin_subscriptions():
    db = get_db()
    reconcile_expired_subscriptions(db)
    db.execute(
        """
        UPDATE users
        SET vpn_enabled = CASE
                WHEN COALESCE(NULLIF(lower(trim(status)), ''), 'approved') = 'disabled'
                THEN 0 ELSE 1
            END
        WHERE COALESCE(NULLIF(lower(trim(role)), ''), 'user') = 'user'
          AND vpn_enabled <> CASE
                WHEN COALESCE(NULLIF(lower(trim(status)), ''), 'approved') = 'disabled'
                THEN 0 ELSE 1
            END
        """
    )
    db.commit()
    search_username = request.args.get("q", "").strip()
    subscriptions = load_admin_subscriptions(db, search_username)
    expiring_subscriptions = load_expiring_subscriptions(db, days=7, limit=20)
    online_rows, online_summary = load_admin_online_users(db)
    online_by_user_id: dict[int, dict] = {}
    for row in online_rows:
        try:
            online_by_user_id[int(row.get("id"))] = row
        except Exception:
            continue
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    available_servers = load_user_selectable_servers(db, admin) if admin else []
    return render_template(
        "admin_subscriptions.html",
        subscriptions=subscriptions,
        expiring_subscriptions=expiring_subscriptions,
        search_username=search_username,
        online_by_user_id=online_by_user_id,
        online_summary=online_summary,
        available_servers=available_servers,
        admin_ui_tz_name=ADMIN_UI_TZ_NAME,
        admin_page="subscriptions",
    )


@app.route("/admin/online-users")
@login_required
@admin_required
def admin_online_users():
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/online-users/data")
@login_required
@admin_required
def admin_online_users_data():
    db = get_db()
    reconcile_expired_subscriptions(db)
    rows, summary = load_admin_online_users(db)
    now_iso = utcnow_iso()
    now_epoch = int(utcnow().timestamp())
    db.commit()
    return {
        "ok": True,
        "sampled_at": now_iso,
        "sampled_at_epoch": now_epoch,
        "online_window_seconds": ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
        "summary": summary,
        "rows": rows,
    }, 200


def redirect_admin_subscriptions():
    search_username = request.values.get("q", "").strip()
    if search_username:
        return redirect(url_for("admin_subscriptions", q=search_username))
    return redirect(url_for("admin_subscriptions"))


def redirect_admin_order_page(default_page: str = "pending_orders"):
    page = (request.values.get("redirect_to", "") or "").strip().lower()
    if page == "payment":
        return redirect(url_for("admin_payment_settings"))
    if page == "pending_orders":
        return redirect(url_for("admin_pending_orders"))
    if default_page == "payment":
        return redirect(url_for("admin_payment_settings"))
    return redirect(url_for("admin_pending_orders"))


def redirect_admin_payment_method_page(default_page: str = "payment_methods"):
    page = (request.values.get("redirect_to", "") or "").strip().lower()
    if page == "payment":
        return redirect(url_for("admin_payment_settings"))
    if default_page == "payment":
        return redirect(url_for("admin_payment_settings"))
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/settings/system", methods=["POST"])
@login_required
@admin_required
def admin_update_system_settings():
    db = get_db()
    registration_open = False
    order_expire_hours_raw = request.form.get("order_expire_hours", "24").strip() or "24"
    gift_duration_raw = request.form.get("gift_duration_months", "0").strip() or "0"
    gift_traffic_raw = request.form.get("gift_traffic_gb", "0").strip() or "0"
    telegram_contact = request.form.get("telegram_contact", "").strip()

    try:
        order_expire_hours = parse_int_setting(order_expire_hours_raw, 24, min_value=1)
        gift_duration_months = parse_int_setting(gift_duration_raw, 0, min_value=0)
        gift_traffic_gb = parse_int_setting(gift_traffic_raw, 0, min_value=0)
    except Exception:
        flash("系统设置参数无效。", "error")
        return redirect(url_for("admin_subscriptions"))

    if order_expire_hours <= 0:
        flash("订单过期小时数必须大于 0。", "error")
        return redirect(url_for("admin_subscriptions"))

    upsert_app_setting(db, SETTING_REGISTRATION_OPEN, "1" if registration_open else "0")
    upsert_app_setting(db, SETTING_ORDER_EXPIRE_HOURS, str(order_expire_hours))
    upsert_app_setting(db, SETTING_GIFT_DURATION_MONTHS, str(gift_duration_months))
    upsert_app_setting(db, SETTING_GIFT_TRAFFIC_GB, str(gift_traffic_gb))
    upsert_app_setting(db, SETTING_TELEGRAM_CONTACT, telegram_contact[:160])
    upsert_app_setting(db, SETTING_LEGACY_VPN_OPEN, "0")
    upsert_app_setting(db, SETTING_OPENVPN_OPEN, "1")
    db.commit()
    flash("系统设置已更新。", "success")
    redirect_to = (request.form.get("redirect_to", "") or "").strip()
    if redirect_to == "admin_subscriptions":
        return redirect(url_for("admin_subscriptions"))
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/payment", methods=["POST"])
@login_required
@admin_required
def admin_update_payment_settings():
    flash("公司内部模式已取消支付设置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    receive_address = request.form.get("usdt_receive_address", "").strip()
    network = request.form.get("usdt_default_network", "TRC20").strip().upper()

    if network not in USDT_NETWORK_OPTIONS:
        flash("默认 USDT 网络无效。", "error")
        return redirect(url_for("admin_payment_settings"))
    if not receive_address:
        flash("USDT 收款地址不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

    upsert_app_setting(db, "usdt_receive_address", receive_address)
    upsert_app_setting(db, "usdt_default_network", network)
    db.commit()
    flash("基础支付设置已更新。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/payment-methods/create", methods=["POST"])
@login_required
@admin_required
def admin_create_payment_method():
    flash("公司内部模式已取消付款方式配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    method_code = normalize_payment_method(request.form.get("method_code", PAYMENT_METHOD_USDT))
    method_name = request.form.get("method_name", "").strip()
    network = request.form.get("network", "TRC20").strip().upper()
    receive_address = request.form.get("receive_address", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if method_code != PAYMENT_METHOD_USDT:
        flash("当前仅支持 USDT 付款方式。", "error")
        return redirect_admin_payment_method_page()
    if network not in USDT_NETWORK_OPTIONS:
        flash("付款网络无效。", "error")
        return redirect_admin_payment_method_page()
    if not receive_address:
        flash("收款地址不能为空。", "error")
        return redirect_admin_payment_method_page()

    if not method_name:
        method_name = f"{payment_method_label(method_code)} {network}"
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    now_iso = utcnow_iso()
    placeholder = db.execute(
        """
        SELECT id
        FROM payment_methods
        WHERE method_code = ?
          AND network = ?
          AND trim(COALESCE(receive_address, '')) = ''
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """,
        (method_code, network),
    ).fetchone()
    if placeholder:
        db.execute(
            """
            UPDATE payment_methods
            SET method_name = ?,
                receive_address = ?,
                is_active = 1,
                sort_order = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                method_name,
                receive_address,
                sort_order,
                now_iso,
                int(placeholder["id"]),
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO payment_methods (
                method_code, method_name, network, receive_address,
                is_active, sort_order, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                method_code,
                method_name,
                network,
                receive_address,
                sort_order,
                now_iso,
                now_iso,
            ),
        )
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    flash("付款方式已添加。", "success")
    return redirect_admin_payment_method_page()


@app.route("/admin/payment-methods/save", methods=["POST"])
@login_required
@admin_required
def admin_save_payment_method():
    flash("公司内部模式已取消付款方式配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    method_id_raw = (request.form.get("method_id", "") or "").strip()
    method_id: int | None = None
    if method_id_raw:
        try:
            method_id = int(method_id_raw)
        except Exception:
            method_id = None

    method_code = normalize_payment_method(request.form.get("method_code", PAYMENT_METHOD_USDT))
    method_name = request.form.get("method_name", "").strip()
    network = request.form.get("network", "TRC20").strip().upper()
    receive_address = request.form.get("receive_address", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if method_code != PAYMENT_METHOD_USDT:
        flash("当前仅支持 USDT 付款方式。", "error")
        return redirect_admin_payment_method_page()
    if network not in USDT_NETWORK_OPTIONS:
        flash("付款网络无效。", "error")
        return redirect_admin_payment_method_page()
    if not receive_address:
        flash("收款地址不能为空。", "error")
        return redirect_admin_payment_method_page()

    if not method_name:
        method_name = f"{payment_method_label(method_code)} {network}"
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0
    now_iso = utcnow_iso()

    if method_id is not None:
        existing = db.execute(
            """
            SELECT id
            FROM payment_methods
            WHERE id = ?
            LIMIT 1
            """,
            (method_id,),
        ).fetchone()
        if existing:
            db.execute(
                """
                UPDATE payment_methods
                SET method_code = ?,
                    method_name = ?,
                    network = ?,
                    receive_address = ?,
                    sort_order = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    method_code,
                    method_name,
                    network,
                    receive_address,
                    sort_order,
                    now_iso,
                    method_id,
                ),
            )
            sync_legacy_payment_settings_with_default_method(db)
            db.commit()
            flash("付款方式已更新。", "success")
            return redirect_admin_payment_method_page()

    placeholder = db.execute(
        """
        SELECT id
        FROM payment_methods
        WHERE method_code = ?
          AND network = ?
          AND trim(COALESCE(receive_address, '')) = ''
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """,
        (method_code, network),
    ).fetchone()
    if placeholder:
        db.execute(
            """
            UPDATE payment_methods
            SET method_name = ?,
                receive_address = ?,
                is_active = 1,
                sort_order = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                method_name,
                receive_address,
                sort_order,
                now_iso,
                int(placeholder["id"]),
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO payment_methods (
                method_code, method_name, network, receive_address,
                is_active, sort_order, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                method_code,
                method_name,
                network,
                receive_address,
                sort_order,
                now_iso,
                now_iso,
            ),
        )
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    flash("付款方式已保存。", "success")
    return redirect_admin_payment_method_page()


@app.route("/admin/payment-methods/<int:method_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_payment_method(method_id: int):
    flash("公司内部模式已取消付款方式配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    method = db.execute(
        """
        SELECT id, method_name, is_active
        FROM payment_methods
        WHERE id = ?
        LIMIT 1
        """,
        (method_id,),
    ).fetchone()
    if not method:
        flash("付款方式不存在。", "error")
        return redirect_admin_payment_method_page()

    next_active = 0 if int(method["is_active"] or 0) == 1 else 1
    db.execute(
        """
        UPDATE payment_methods
        SET is_active = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (next_active, utcnow_iso(), method_id),
    )
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    if next_active == 1:
        flash(f"付款方式 {method['method_name']} 已启用。", "success")
    else:
        flash(f"付款方式 {method['method_name']} 已停用。", "success")
    return redirect_admin_payment_method_page()


@app.route("/admin/payment-methods/<int:method_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_payment_method(method_id: int):
    flash("公司内部模式已取消付款方式配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    method = db.execute(
        """
        SELECT id
        FROM payment_methods
        WHERE id = ?
        LIMIT 1
        """,
        (method_id,),
    ).fetchone()
    if not method:
        flash("付款方式不存在。", "error")
        return redirect_admin_payment_method_page()

    method_code = normalize_payment_method(request.form.get("method_code", PAYMENT_METHOD_USDT))
    method_name = request.form.get("method_name", "").strip()
    network = request.form.get("network", "TRC20").strip().upper()
    receive_address = request.form.get("receive_address", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if method_code != PAYMENT_METHOD_USDT:
        flash("当前仅支持 USDT 付款方式。", "error")
        return redirect_admin_payment_method_page()
    if network not in USDT_NETWORK_OPTIONS:
        flash("付款网络无效。", "error")
        return redirect_admin_payment_method_page()
    if not receive_address:
        flash("收款地址不能为空。", "error")
        return redirect_admin_payment_method_page()
    if not method_name:
        method_name = f"{payment_method_label(method_code)} {network}"
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    db.execute(
        """
        UPDATE payment_methods
        SET method_code = ?,
            method_name = ?,
            network = ?,
            receive_address = ?,
            sort_order = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            method_code,
            method_name,
            network,
            receive_address,
            sort_order,
            utcnow_iso(),
            method_id,
        ),
    )
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    flash("付款方式已更新。", "success")
    return redirect_admin_payment_method_page()


@app.route("/admin/payment-methods/<int:method_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_payment_method(method_id: int):
    flash("公司内部模式已取消付款方式配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    method = db.execute(
        """
        SELECT id, method_name
        FROM payment_methods
        WHERE id = ?
        LIMIT 1
        """,
        (method_id,),
    ).fetchone()
    if not method:
        flash("付款方式不存在。", "error")
        return redirect_admin_payment_method_page()

    db.execute("DELETE FROM payment_methods WHERE id = ?", (method_id,))
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    flash(f"付款方式 {method['method_name']} 已删除。", "success")
    return redirect_admin_payment_method_page()


@app.route("/admin/plans/create", methods=["POST"])
@login_required
@admin_required
def admin_create_plan():
    flash("公司内部模式已取消套餐配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    plan_name = request.form.get("plan_name", "").strip()
    billing_mode = normalize_plan_mode(request.form.get("billing_mode", "duration"))
    duration_value_raw = request.form.get("duration_value", "").strip()
    duration_unit = normalize_duration_unit(request.form.get("duration_unit", PLAN_DURATION_UNIT_MONTH))
    duration_months_raw = request.form.get("duration_months", "").strip()
    traffic_gb_raw = request.form.get("traffic_gb", "").strip()
    if billing_mode == PLAN_MODE_DURATION:
        traffic_gb_raw = ""
        if not duration_value_raw and duration_months_raw:
            duration_value_raw = duration_months_raw
    else:
        duration_value_raw = ""
        duration_months_raw = ""
    price_raw = request.form.get("price_usdt", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    try:
        price_usdt = parse_usdt_amount_strict(price_raw)
    except Exception:
        flash("价格格式无效，请输入大于 0 的数字。", "error")
        return redirect(url_for("admin_payment_settings"))

    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    duration_months = None
    duration_value = None
    duration_unit_to_save = None
    traffic_gb = None
    if billing_mode == PLAN_MODE_DURATION:
        try:
            duration_value = parse_positive_int(duration_value_raw)
        except Exception:
            flash("时长套餐必须填写大于 0 的时长。", "error")
            return redirect(url_for("admin_payment_settings"))
        duration_unit_to_save = duration_unit
        duration_months = duration_value_to_legacy_months(duration_value, duration_unit_to_save)
        if not plan_name:
            plan_name = generate_plan_name(
                mode=billing_mode,
                duration_value=duration_value,
                duration_unit=duration_unit_to_save,
            )
    else:
        try:
            traffic_gb = parse_positive_int(traffic_gb_raw)
        except Exception:
            flash("流量套餐必须填写大于 0 的流量（GB）。", "error")
            return redirect(url_for("admin_payment_settings"))
        if not plan_name:
            plan_name = generate_plan_name(mode=billing_mode, traffic_gb=traffic_gb)

    if not plan_name:
        flash("套餐名称不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

    now_iso = utcnow_iso()
    db.execute(
        """
        INSERT INTO subscription_plans (
            plan_name, billing_mode, duration_months, duration_value, duration_unit, traffic_gb,
            price_usdt, is_active, sort_order, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit_to_save,
            traffic_gb,
            format_usdt(price_usdt),
            sort_order,
            now_iso,
            now_iso,
        ),
    )
    db.commit()
    flash("套餐已添加。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/plans/<int:plan_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_plan(plan_id: int):
    flash("公司内部模式已取消套餐配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    existing_plan = db.execute(
        """
        SELECT id, plan_name
        FROM subscription_plans
        WHERE id = ?
        LIMIT 1
        """,
        (plan_id,),
    ).fetchone()
    if not existing_plan:
        flash("套餐不存在。", "error")
        return redirect(url_for("admin_payment_settings"))

    plan_name = request.form.get("plan_name", "").strip()
    billing_mode = normalize_plan_mode(request.form.get("billing_mode", "duration"))
    duration_value_raw = request.form.get("duration_value", "").strip()
    duration_unit = normalize_duration_unit(request.form.get("duration_unit", PLAN_DURATION_UNIT_MONTH))
    duration_months_raw = request.form.get("duration_months", "").strip()
    traffic_gb_raw = request.form.get("traffic_gb", "").strip()
    if billing_mode == PLAN_MODE_DURATION:
        traffic_gb_raw = ""
        if not duration_value_raw and duration_months_raw:
            duration_value_raw = duration_months_raw
    else:
        duration_value_raw = ""
        duration_months_raw = ""
    price_raw = request.form.get("price_usdt", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    try:
        price_usdt = parse_usdt_amount_strict(price_raw)
    except Exception:
        flash("价格格式无效，请输入大于 0 的数字。", "error")
        return redirect(url_for("admin_payment_settings"))

    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    duration_months = None
    duration_value = None
    duration_unit_to_save = None
    traffic_gb = None
    if billing_mode == PLAN_MODE_DURATION:
        try:
            duration_value = parse_positive_int(duration_value_raw)
        except Exception:
            flash("时长套餐必须填写大于 0 的时长。", "error")
            return redirect(url_for("admin_payment_settings"))
        duration_unit_to_save = duration_unit
        duration_months = duration_value_to_legacy_months(duration_value, duration_unit_to_save)
        if not plan_name:
            plan_name = generate_plan_name(
                mode=billing_mode,
                duration_value=duration_value,
                duration_unit=duration_unit_to_save,
            )
    else:
        try:
            traffic_gb = parse_positive_int(traffic_gb_raw)
        except Exception:
            flash("流量套餐必须填写大于 0 的流量（GB）。", "error")
            return redirect(url_for("admin_payment_settings"))
        if not plan_name:
            plan_name = generate_plan_name(mode=billing_mode, traffic_gb=traffic_gb)

    if not plan_name:
        plan_name = (existing_plan["plan_name"] or "").strip()
    if not plan_name:
        flash("套餐名称不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

    db.execute(
        """
        UPDATE subscription_plans
        SET plan_name = ?,
            billing_mode = ?,
            duration_months = ?,
            duration_value = ?,
            duration_unit = ?,
            traffic_gb = ?,
            price_usdt = ?,
            sort_order = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            plan_name,
            billing_mode,
            duration_months,
            duration_value,
            duration_unit_to_save,
            traffic_gb,
            format_usdt(price_usdt),
            sort_order,
            utcnow_iso(),
            plan_id,
        ),
    )
    db.commit()
    flash(f"套餐 {existing_plan['plan_name']} 已更新。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/plans/<int:plan_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_plan(plan_id: int):
    flash("公司内部模式已取消套餐配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    plan = db.execute(
        "SELECT id, plan_name, is_active FROM subscription_plans WHERE id = ?",
        (plan_id,),
    ).fetchone()
    if not plan:
        flash("套餐不存在。", "error")
        return redirect(url_for("admin_payment_settings"))

    next_active = 0 if int(plan["is_active"] or 0) == 1 else 1
    db.execute(
        """
        UPDATE subscription_plans
        SET is_active = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (next_active, utcnow_iso(), plan_id),
    )
    db.commit()
    if next_active == 1:
        flash(f"套餐 {plan['plan_name']} 已启用。", "success")
    else:
        flash(f"套餐 {plan['plan_name']} 已停用。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/plans/<int:plan_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_plan(plan_id: int):
    flash("公司内部模式已取消套餐配置。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    plan = db.execute(
        """
        SELECT id, plan_name
        FROM subscription_plans
        WHERE id = ?
        LIMIT 1
        """,
        (plan_id,),
    ).fetchone()
    if not plan:
        flash("套餐不存在。", "error")
        return redirect(url_for("admin_payment_settings"))

    db.execute("DELETE FROM subscription_plans WHERE id = ?", (plan_id,))
    db.commit()
    flash(f"套餐 {plan['plan_name']} 已删除。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/users/create", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    username = (request.form.get("username", "") or "").strip()
    password = (request.form.get("password", "") or "").strip()
    allowed_server_ids_raw = request.form.getlist("allowed_server_ids")

    if not looks_like_internal_username(username):
        flash("用户名格式不正确：请使用 3-32 位字母、数字、下划线、点或短横线。", "error")
        return redirect_admin_subscriptions()
    if len(password) < 8:
        flash("请设置至少 8 位客户端登录密码。", "error")
        return redirect_admin_subscriptions()
    allowed_server_ids = [int(item) for item in allowed_server_ids_raw if str(item).isdigit()]

    db = get_db()
    try:
        now_iso = utcnow_iso()
        begin_immediate(db)
        for allowed_server_id in allowed_server_ids:
            server = get_server_by_id(db, allowed_server_id)
            if not server or not is_runtime_server_ready(server):
                db.rollback()
                flash("请选择在线可用服务器。", "error")
                return redirect_admin_subscriptions()
            if not normalize_domain_host(row_get(server, "domain", "")):
                db.rollback()
                flash("所选服务器未配置客户端连接域名。", "error")
                return redirect_admin_subscriptions()
        cursor = db.execute(
            """
            INSERT INTO users (
                username, email, password_hash, role, status,
                email_verified, preferred_server_id, assigned_server_id,
                created_at, approved_at, subscription_expires_at,
                vpn_enabled, preferred_billing_mode, traffic_quota_bytes,
                traffic_used_bytes, traffic_last_total_bytes,
                force_password_change, session_version, client_config_token
            )
            VALUES (?, ?, ?, 'user', 'approved', 1, ?, ?, ?, ?, NULL, 0, 'duration', 0, 0, 0, 0, 1, ?)
            RETURNING id
            """,
            (
                username,
                username,
                generate_password_hash(password),
                None,
                None,
                now_iso,
                now_iso,
                generate_client_config_token(),
            ),
        )
        user_id = int(cursor.fetchone()["id"])
        if allowed_server_ids:
            save_user_server_permissions(db, user_id, allowed_server_ids)
        db.execute(
            """
            UPDATE users
            SET approved_at = ?,
                vpn_enabled = 1,
                status = 'approved'
            WHERE id = ?
            """,
            (now_iso, user_id),
        )
        db.commit()
        if allowed_server_ids:
            flash(f"内部账号 {username} 已创建并启用。", "success")
        else:
            flash(f"内部账号 {username} 已创建并启用；当前未分配服务器权限。", "success")
    except DB_INTEGRITY_ERRORS:
        db.rollback()
        flash("该用户名已存在。", "error")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"创建用户失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/servers", methods=["POST"])
@login_required
@admin_required
def admin_update_user_server_permissions(user_id: int):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(user_id),),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()
    server_ids = [int(item) for item in request.form.getlist("allowed_server_ids") if str(item).isdigit()]
    if not server_ids:
        flash("请至少选择一台服务器。", "error")
        return redirect_admin_subscriptions()
    save_user_server_permissions(db, int(user_id), server_ids)
    db.commit()
    flash(f"已更新 {user['username']} 的服务器权限。", "success")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/set-expiry", methods=["POST"])
@login_required
@admin_required
def admin_set_user_expiry(user_id: int):
    flash("公司内部模式已取消账号有效期，请使用启用/停用控制账号。", "error")
    return redirect_admin_subscriptions()

    expires_raw = request.form.get("expires_at_local", "").strip()
    if not expires_raw:
        flash("请选择到期时间。", "error")
        return redirect_admin_subscriptions()

    try:
        expires_at_utc = parse_admin_local_date(expires_raw)
    except Exception:
        flash("到期时间格式无效。", "error")
        return redirect_admin_subscriptions()

    expires_iso = expires_at_utc.isoformat()
    db = get_db()
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ? AND role IN ('user', 'admin')
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()

    user = sync_user_traffic_usage(db, user)
    try:
        has_traffic = has_active_traffic_subscription(user)
        if expires_at_utc >= utcnow() or has_traffic:
            vpn_data = ensure_user_vpn_ready(db, user)
            assigned_server_id = vpn_data.get("assigned_server_id")
            if assigned_server_id is None:
                assigned_server_id = row_get(user, "assigned_server_id")
            db.execute(
                """
                UPDATE users
                SET vpn_internal_ip = ?,
                    assigned_server_id = ?,
                    archived_private_token = ?,
                    archived_public_token = ?,
                    archived_shared_token = ?,
                    archived_profile_file = ?,
                    archived_qr_file = ?,
                    approved_at = ?,
                    subscription_expires_at = ?,
                    vpn_enabled = 1
                WHERE id = ?
                """,
                (
                    vpn_data["vpn_internal_ip"],
                    assigned_server_id,
                    vpn_data["archived_private_token"],
                    vpn_data["archived_public_token"],
                    vpn_data["archived_shared_token"],
                    vpn_data["archived_profile_file"],
                    vpn_data["archived_qr_file"],
                    utcnow_iso(),
                    expires_iso,
                    user_id,
                ),
            )
            db.commit()
            flash(
                f"已设置用户 {user['username']} 的到期时间：{format_utc(expires_iso)}，VPN 已启用。",
                "success",
            )
            return redirect_admin_subscriptions()

        if user["archived_public_token"]:
            remove_legacy_peer(user["archived_public_token"], user=user)
        if is_dynamic_ip_assignment_mode():
            db.execute(
                """
                UPDATE users
                SET subscription_expires_at = ?,
                    vpn_enabled = 0,
                    vpn_internal_ip = NULL
                WHERE id = ?
                """,
                (expires_iso, user_id),
            )
        else:
            db.execute(
                """
                UPDATE users
                SET subscription_expires_at = ?,
                    vpn_enabled = 0
                WHERE id = ?
                """,
                (expires_iso, user_id),
            )
        db.commit()
        flash(
            f"已设置用户 {user['username']} 的到期时间：{format_utc(expires_iso)}，VPN 已停用。",
            "success",
        )
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"设置用户期限失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id: int):
    db = get_db()
    user = db.execute(
        """
        SELECT id, username, email, role, assigned_server_id, archived_public_token, archived_profile_file, archived_qr_file
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()
    confirm_username = (request.form.get("confirm_username", "") or "").strip()
    expected_username = ((user["username"] or "").strip())
    if not confirm_username or confirm_username != expected_username:
        flash("删除失败：请输入用户名进行二次确认。", "error")
        return redirect_admin_subscriptions()

    try:
        if user["archived_public_token"]:
            remove_legacy_peer(user["archived_public_token"], user=user)

        archived_profile_file = (user["archived_profile_file"] or "").strip()
        if archived_profile_file:
            Path(archived_profile_file).unlink(missing_ok=True)

        archived_qr_file = (user["archived_qr_file"] or "").strip()
        if archived_qr_file:
            Path(archived_qr_file).unlink(missing_ok=True)

        db.execute("DELETE FROM payment_orders WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM email_verifications WHERE email = ?", (user["email"],))
        db.execute("DELETE FROM users WHERE id = ? AND role = 'user'", (user_id,))
        db.commit()
        flash(f"用户 {user['username']} 已删除。", "success")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"删除用户失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@login_required
@admin_required
def admin_disable_user(user_id: int):
    db = get_db()
    user = db.execute(
        """
        SELECT
            id,
            username,
            role,
            status,
            assigned_server_id,
            archived_public_token,
            vpn_enabled,
            subscription_expires_at,
            preferred_billing_mode,
            traffic_quota_bytes,
            traffic_used_bytes,
            traffic_last_total_bytes
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()

    user = sync_user_traffic_usage(db, user)
    try:
        if user["archived_public_token"]:
            remove_legacy_peer(user["archived_public_token"], user=user)

        if is_dynamic_ip_assignment_mode():
            db.execute(
                """
                UPDATE users
                SET status = 'disabled',
                    vpn_enabled = 0,
                    vpn_internal_ip = NULL
                WHERE id = ? AND role = 'user'
                """,
                (user_id,),
            )
        else:
            db.execute(
                """
                UPDATE users
                SET status = 'disabled',
                    vpn_enabled = 0
                WHERE id = ? AND role = 'user'
                """,
                (user_id,),
            )
        db.commit()

        if (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
            flash(f"用户 {user['username']} 已是停用状态。", "success")
        else:
            flash(f"用户 {user['username']} 已停用。", "success")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"停用用户失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@login_required
@admin_required
def admin_enable_user(user_id: int):
    db = get_db()
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()

    user = sync_user_traffic_usage(db, user)
    try:
        vpn_data = ensure_user_vpn_ready(db, user)
        assigned_server_id = vpn_data.get("assigned_server_id")
        if assigned_server_id is None:
            assigned_server_id = row_get(user, "assigned_server_id")
        db.execute(
            """
            UPDATE users
            SET vpn_internal_ip = ?,
                assigned_server_id = ?,
                archived_private_token = ?,
                archived_public_token = ?,
                archived_shared_token = ?,
                archived_profile_file = ?,
                archived_qr_file = ?,
                approved_at = ?,
                subscription_expires_at = NULL,
                status = 'approved',
                vpn_enabled = 1
            WHERE id = ?
            """,
            (
                vpn_data["vpn_internal_ip"],
                assigned_server_id,
                vpn_data["archived_private_token"],
                vpn_data["archived_public_token"],
                vpn_data["archived_shared_token"],
                vpn_data["archived_profile_file"],
                vpn_data["archived_qr_file"],
                utcnow_iso(),
                user_id,
            ),
        )
        db.commit()
        flash(f"用户 {user['username']} 已启用。", "success")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"启用用户失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/server", methods=["POST"])
@login_required
@admin_required
def admin_set_user_server(user_id: int):
    server_id_raw = (request.form.get("server_id", "") or "").strip()
    if not server_id_raw.isdigit():
        flash("请选择有效的服务器。", "error")
        return redirect_admin_subscriptions()

    db = get_db()
    try:
        begin_immediate(db)
        ok, message = apply_user_server_switch(
            db,
            user_id=user_id,
            server_id=int(server_id_raw),
            row_get=row_get,
            get_server_by_id=get_server_by_id,
            is_runtime_server_ready=is_runtime_server_ready,
            ensure_user_vpn_ready=ensure_user_vpn_ready,
            utcnow_iso=utcnow_iso,
        )
        if not ok:
            db.rollback()
            flash(message, "error")
            return redirect_admin_subscriptions()
        db.commit()
        flash(message, "success")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"切换服务器失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@admin_required
def admin_reset_user_password(user_id: int):
    new_password = (request.form.get("new_password", "") or "").strip()
    if len(new_password) < 8:
        flash("新密码长度至少需要 8 位。", "error")
        return redirect_admin_subscriptions()

    db = get_db()
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()

    try:
        begin_immediate(db)
        latest_user = db.execute(
            "SELECT * FROM users WHERE id = ? AND role IN ('user', 'admin') LIMIT 1",
            (user_id,),
        ).fetchone()
        if not latest_user:
            db.rollback()
            flash("用户不存在。", "error")
            return redirect_admin_subscriptions()
        apply_password_change(
            db,
            latest_user,
            new_password=new_password,
            clear_force_change=False,
            rotate_vpn=True,
        )
        db.commit()
        if row_get(latest_user, "role") == "admin":
            flash(f"已修改管理员 {latest_user['username']} 的密码。", "success")
        else:
            flash(f"已重置用户 {latest_user['username']} 的密码，并断开其旧 VPN 会话。", "success")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"重置用户密码失败：{exc}", "error")
    return redirect_admin_subscriptions()


@app.route("/admin/orders/<int:order_id>/cancel", methods=["POST"])
@login_required
@admin_required
def admin_cancel_pending_order(order_id: int):
    flash("公司内部模式已取消订单支付。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    order = db.execute(
        """
        SELECT id, status, note
        FROM payment_orders
        WHERE id = ?
        LIMIT 1
        """,
        (order_id,),
    ).fetchone()
    if not order:
        flash("未找到订单。", "error")
        return redirect_admin_order_page()
    if (order["status"] or "").strip().lower() != "pending":
        flash("仅待处理订单可取消。", "error")
        return redirect_admin_order_page()

    cancel_note = f"[管理员取消] {utcnow_iso()}"
    merged_note = cancel_note if not order["note"] else f"{order['note']}\n{cancel_note}"
    db.execute(
        """
        UPDATE payment_orders
        SET status = 'cancelled',
            note = ?
        WHERE id = ?
        """,
        (merged_note, order_id),
    )
    db.commit()
    flash(f"订单 {order_id} 已取消。", "success")
    return redirect_admin_order_page()


@app.route("/admin/orders/<int:order_id>/mark-paid", methods=["POST"])
@login_required
@admin_required
def admin_mark_order_paid(order_id: int):
    flash("公司内部模式已取消订单支付。", "error")
    return redirect(url_for("admin_subscriptions"))

    db = get_db()
    try:
        result = settle_order_paid(
            db,
            order_id,
            source="admin",
            require_tx_hash=False,
        )
        if result["status"] == "already_paid":
            flash("该订单已支付。", "success")
        else:
            flash(
                f"订单确认成功。用户 {result['username']}，{result['plan_display']}，{result['grant_text']}。",
                "success",
            )
    except ValueError as exc:
        flash(str(exc), "error")
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"处理订单失败：{exc}", "error")
    return redirect_admin_order_page()



@app.route("/webhook/usdt", methods=["POST"])
def usdt_payment_webhook():
    return {"ok": False, "error": "payment_disabled"}, 404

    raw_body = request.get_data(cache=True) or b""
    signature = request.headers.get("X-Webhook-Signature", "") or request.headers.get(
        "X-Signature", ""
    )
    if not verify_webhook_signature(raw_body, signature):
        return {"ok": False, "error": "签名无效"}, 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return {"ok": False, "error": "无效的请求体"}, 400

    order_id_raw = get_nested_value(
        payload,
        "order_id",
        "merchant_order_id",
        "metadata.order_id",
        "order.id",
    )
    try:
        order_id = int(str(order_id_raw).strip())
    except Exception:
        return {"ok": False, "error": "缺少 order_id"}, 400

    status_raw = str(
        get_nested_value(payload, "status", "payment_status", "event", "type") or ""
    ).strip().lower()
    pending_states = {"pending", "processing", "created", "waiting", "new"}
    if status_raw in pending_states:
        return {"ok": True, "status": "pending"}, 202

    conf_raw = get_nested_value(payload, "confirmations", "payment.confirmations", "data.confirmations")
    confirmations = 0
    if conf_raw is not None:
        try:
            confirmations = int(str(conf_raw).strip())
        except ValueError:
            confirmations = 0
    if confirmations < PAYMENT_MIN_CONFIRMATIONS:
        return {"ok": True, "status": "waiting_confirmations", "confirmations": confirmations}, 202

    currency = str(
        get_nested_value(payload, "currency", "coin", "payment_currency", "data.currency")
        or "USDT"
    ).strip().upper()
    if currency and currency != "USDT":
        return {"ok": False, "error": "币种必须为 USDT"}, 400

    tx_hash = str(
        get_nested_value(
            payload,
            "tx_hash",
            "txid",
            "hash",
            "payment_hash",
            "transaction_hash",
            "data.tx_hash",
        )
        or ""
    ).strip()
    if not tx_hash:
        return {"ok": False, "error": "缺少 tx_hash"}, 400

    network = str(
        get_nested_value(payload, "network", "chain", "usdt_network", "payment.network")
        or ""
    ).strip().upper() or None

    amount_raw = get_nested_value(
        payload,
        "amount",
        "paid_amount",
        "amount_received",
        "payment.amount",
        "data.amount",
    )
    webhook_amount = None
    if amount_raw is not None and str(amount_raw).strip() != "":
        try:
            webhook_amount = Decimal(str(amount_raw)).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError):
            return {"ok": False, "error": "金额格式无效"}, 400

    db = get_db()
    try:
        result = settle_order_paid(
            db,
            order_id,
            tx_hash=tx_hash,
            source="webhook",
            require_tx_hash=True,
            webhook_amount=webhook_amount,
            webhook_network=network,
        )
        if result["status"] == "already_paid":
            return {"ok": True, "status": "already_paid", "order_id": order_id}
        return {
            "ok": True,
            "status": "paid",
            "order_id": order_id,
            "expires_at": result["expires_at"],
            "grant_text": result["grant_text"],
            "plan_display": result["plan_display"],
        }
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}, 400
    except Exception as exc:
        return {"ok": False, "error": f"内部错误：{exc}"}, 500


def generate_client_config_token() -> str:
    return secrets.token_urlsafe(32)


def ensure_user_client_config_token(db: DatabaseConnection, user: DatabaseRow) -> str:
    existing = (row_get(user, "client_config_token", "") or "").strip()
    if existing:
        return existing
    token = generate_client_config_token()
    db.execute(
        "UPDATE users SET client_config_token = ? WHERE id = ?",
        (token, int(user["id"])),
    )
    db.commit()
    return token


def extract_client_config_token() -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (request.args.get("token") or "").strip()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    clean = (value or "").strip()
    return base64.urlsafe_b64decode(clean + "=" * ((4 - len(clean) % 4) % 4))


def _client_auth_message(method: str, path: str, timestamp: str) -> bytes:
    return f"{method.upper()}\n{path}\n{timestamp}".encode("utf-8")


CLIENT_GLOBAL_CRYPTO_KEY_DEFAULT = "company-vpn-global-client-key-v1-20260621"
CLIENT_GLOBAL_CRYPTO_KEY = (
    os.environ.get("COMPANYVPN_CLIENT_GLOBAL_KEY", CLIENT_GLOBAL_CRYPTO_KEY_DEFAULT).strip()
    or CLIENT_GLOBAL_CRYPTO_KEY_DEFAULT
)
CLIENT_LOGIN_WINDOW_SECONDS = 60


def _client_global_key_bytes() -> bytes:
    return hashlib.sha256(CLIENT_GLOBAL_CRYPTO_KEY.encode("utf-8")).digest()


def _client_login_slug_for_window(window_index: int) -> str:
    digest = hmac.new(
        CLIENT_GLOBAL_CRYPTO_KEY.encode("utf-8"),
        f"login:{int(window_index)}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)[:32]


def is_valid_client_login_slug(slug: str) -> bool:
    clean = (slug or "").strip()
    if not clean:
        return False
    now_window = int(utcnow().timestamp()) // CLIENT_LOGIN_WINDOW_SECONDS
    for offset in (-1, 0, 1):
        if hmac.compare_digest(clean, _client_login_slug_for_window(now_window + offset)):
            return True
    return False


def _verify_client_signed_auth(token: str) -> bool:
    clean_token = (token or "").strip()
    timestamp = (request.headers.get("X-CompanyVPN-Auth-Time") or "").strip()
    signature = (request.headers.get("X-CompanyVPN-Auth-Signature") or "").strip()
    if not clean_token or not timestamp or not signature:
        return False
    try:
        auth_time = int(timestamp)
    except ValueError:
        return False
    now = int(utcnow().timestamp())
    if abs(now - auth_time) > 300:
        return False
    expected = hmac.new(
        clean_token.encode("utf-8"),
        _client_auth_message(request.method, request.path, timestamp),
        hashlib.sha256,
    ).digest()
    try:
        supplied = _b64url_decode(signature)
    except Exception:
        return False
    return hmac.compare_digest(expected, supplied)


def encrypt_client_api_payload(payload: dict, token: str) -> dict:
    if (request.headers.get("X-CompanyVPN-Encrypted") or "").strip().lower() != "v1":
        return payload
    key = _client_global_key_bytes()
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "ok": True,
        "encrypted": "v1",
        "nonce": _b64url_encode(nonce),
        "payload": _b64url_encode(ciphertext),
    }


def encrypt_login_api_payload(payload: dict) -> dict:
    key = _client_global_key_bytes()
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "ok": True,
        "encrypted": "login-v1",
        "nonce": _b64url_encode(nonce),
        "payload": _b64url_encode(ciphertext),
    }


def resolve_client_config_user(db: DatabaseConnection, username: str, token: str):
    clean_username = (username or "").strip()
    clean_token = (token or "").strip()
    if not clean_username:
        return None
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE username = ? AND role = 'user'
        LIMIT 1
        """,
        (clean_username,),
    ).fetchone()
    if not user:
        return None
    stored_token = (row_get(user, "client_config_token", "") or "").strip()
    if not stored_token:
        return None
    if clean_token and hmac.compare_digest(stored_token, clean_token):
        return user
    if not clean_token and _verify_client_signed_auth(stored_token):
        return user
    return None


def generate_ssh_cleanup_token(server_id: int, temp_username: str, username: str) -> str:
    payload = {
        "server_id": int(server_id),
        "temp_username": (temp_username or "").strip(),
        "username": (username or "").strip(),
        "exp": int(utcnow().timestamp()) + 3600,
    }
    body = _b64url_encode(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    secret = str(app.config.get("SECRET_KEY") or PORTAL_SECRET_KEY).encode("utf-8")
    signature = _b64url_encode(hmac.new(secret, body.encode("utf-8"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def verify_ssh_cleanup_token(token: str) -> dict | None:
    clean = (token or "").strip()
    if "." not in clean:
        return None
    body, signature = clean.rsplit(".", 1)
    secret = str(app.config.get("SECRET_KEY") or PORTAL_SECRET_KEY).encode("utf-8")
    expected = _b64url_encode(hmac.new(secret, body.encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception:
        return None
    if int(payload.get("exp") or 0) < int(utcnow().timestamp()):
        return None
    temp_username = (payload.get("temp_username") or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,30}", temp_username or ""):
        return None
    return payload


def build_client_bootstrap_payload(user: DatabaseRow, token: str) -> dict:
    username = row_get(user, "username", "")
    profiles = []
    try:
        db = get_db()
        target_servers = load_user_allowed_runtime_servers(db, user)
    except Exception:
        target_servers = []
    if not target_servers:
        target_servers = [None]
    for target_server in target_servers:
        server_info = serialize_runtime_server(target_server)
        server_id = int(row_get(target_server, "id", 0) or 0) if target_server else 0
        server_label = (
            row_get(target_server, "domain", "")
            or row_get(target_server, "host", "")
            or row_get(target_server, "server_name", "")
            or "服务器"
        )
        server_query = {"server_id": server_id} if server_id else {}
        if server_supports_ssh_tunnel(target_server):
            profiles.append(
                {
                    "id": f"server-{server_id}-ssh-tunnel" if server_id else "ssh-tunnel",
                    "name": f"{server_label} / SSH Tunnel",
                    "type": "ssh-tunnel",
                    "update_url": url_for(
                        "client_profile_config",
                        username=username,
                        profile_type="ssh-tunnel",
                        _external=True,
                        **server_query,
                    ),
                    "online_url": url_for(
                        "client_online_heartbeat",
                        username=username,
                        _external=True,
                    ),
                    "update_token": token,
                    "server": server_info,
                }
            )
    server_info = serialize_runtime_server(target_servers[0] if target_servers else None)
    return {
        "schema": "company-vpn-client.v1",
        "name": f"company-user-{username}",
        "account": username,
        "bootstrap_update_url": url_for(
            "client_bootstrap_config",
            username=username,
            _external=True,
        ),
        "update_token": token,
        "server": server_info,
        "profiles": profiles,
    }


def generate_ssh_tunnel_key_pair(username: str) -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")
    comment = safe_name(username or "user")[:24] or "user"
    return private_key, f"{public_key} companyvpn-{comment}"


def build_ssh_tunnel_install_script(temp_username: str, public_key: str) -> str:
    user_q = shlex.quote(temp_username)
    pub_q = shlex.quote(public_key)
    return textwrap.dedent(
	        f"""\
	        set -euo pipefail
	        if command -v flock >/dev/null 2>&1; then
	          exec 9>/run/companyvpn-ssh-user.lock
	          flock -w 45 9
	        fi
	        tunnel_user={user_q}
	        public_key={pub_q}
	        home_dir="/home/${{tunnel_user}}"
        if ! id "${{tunnel_user}}" >/dev/null 2>&1; then
          useradd -m -s /bin/sh "${{tunnel_user}}"
        fi
        install -d -m 700 -o "${{tunnel_user}}" -g "${{tunnel_user}}" "${{home_dir}}/.ssh"
        auth_file="${{home_dir}}/.ssh/authorized_keys"
        touch "${{auth_file}}"
        chmod 600 "${{auth_file}}"
        chown "${{tunnel_user}}:${{tunnel_user}}" "${{auth_file}}"
        key_line="no-pty,no-agent-forwarding,no-X11-forwarding ${{public_key}}"
        if ! grep -qxF "${{key_line}}" "${{auth_file}}"; then
          printf '%s\\n' "${{key_line}}" >> "${{auth_file}}"
        fi
        chown "${{tunnel_user}}:${{tunnel_user}}" "${{auth_file}}"
        if command -v systemd-run >/dev/null 2>&1; then
          unit_name="companyvpn-clean-${{tunnel_user}}"
          systemd-run --quiet --unit="${{unit_name}}" --on-active=1h /usr/sbin/userdel -f -r "${{tunnel_user}}" >/dev/null 2>&1 || true
        else
          nohup sh -c "sleep 3600; /usr/sbin/userdel -f -r {user_q} >/dev/null 2>&1 || true" >/dev/null 2>&1 &
        fi
        printf 'ready:%s\\n' "${{tunnel_user}}"
        """
    ).strip()


def build_ssh_tunnel_cleanup_script(temp_username: str) -> str:
    user_q = shlex.quote(temp_username)
    return textwrap.dedent(
	        f"""\
	        set -euo pipefail
	        if command -v flock >/dev/null 2>&1; then
	          exec 9>/run/companyvpn-ssh-user.lock
	          flock -w 45 9
	        fi
	        tunnel_user={user_q}
	        if id "${{tunnel_user}}" >/dev/null 2>&1; then
          home_dir="$(getent passwd "${{tunnel_user}}" | cut -d: -f6 || true)"
          if [ -n "${{home_dir}}" ]; then
            rm -f "${{home_dir}}/.ssh/authorized_keys" >/dev/null 2>&1 || true
          fi
          passwd -l "${{tunnel_user}}" >/dev/null 2>&1 || true
          usermod -L -s /usr/sbin/nologin "${{tunnel_user}}" >/dev/null 2>&1 || true
          /usr/sbin/userdel -f -r "${{tunnel_user}}" >/dev/null 2>&1 || true
          if id "${{tunnel_user}}" >/dev/null 2>&1; then
            nohup sh -c "sleep 1800; /usr/sbin/userdel -f -r {user_q} >/dev/null 2>&1 || true" >/dev/null 2>&1 &
          fi
        fi
        printf 'cleaned:%s\\n' "${{tunnel_user}}"
        """
    ).strip()


def build_user_ssh_tunnel_config(
    db: DatabaseConnection,
    user: DatabaseRow,
    server_row: DatabaseRow,
) -> str:
    if not server_supports_ssh_tunnel(server_row):
        raise RuntimeError("SSH Tunnel is disabled for this server")
    admin_host = normalize_remote_host(row_get(server_row, "host", ""))
    admin_port = normalize_server_port(row_get(server_row, "port", 22), 22)
    admin_username = (row_get(server_row, "username", "") or "").strip()
    admin_password = row_get(server_row, "password", "") or ""
    admin_private_key = (row_get(server_row, "ssh_private_key", "") or "").strip()
    if not admin_host or not admin_username or (not admin_password and not admin_private_key):
        raise RuntimeError("服务器连接信息不完整，无法创建 SSH Tunnel 临时用户。")

    user_id = int(row_get(user, "id", 0) or 0)
    temp_username = f"cvpn{user_id}{secrets.token_hex(4)}"[:31]
    private_key, public_key = generate_ssh_tunnel_key_pair(row_get(user, "username", ""))
    ok, message = run_remote_ssh_script(
        host=admin_host,
        port=admin_port,
        username=admin_username,
        password=admin_password,
        private_key_text=admin_private_key,
        script=build_ssh_tunnel_install_script(temp_username, public_key),
        timeout=30,
    )
    if not ok:
        raise RuntimeError(message)

    endpoint_host = host_without_optional_port(row_get(server_row, "domain", "")) or admin_host
    server_id = int(row_get(server_row, "id", 0) or 0)
    config_obj = {
        "host": endpoint_host,
        "port": admin_port,
        "username": temp_username,
        "private_key": private_key,
        "local_socks": "127.0.0.1:7890",
        "expires_in_seconds": 3600,
        "cleanup_url": url_for("client_ssh_tunnel_cleanup", _external=True),
        "cleanup_token": generate_ssh_cleanup_token(
            server_id,
            temp_username,
            row_get(user, "username", ""),
        ),
    }
    return json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n"


@app.route("/client-api/login", methods=["POST"])
def client_password_login_legacy_blocked():
    return {"ok": False, "error": "not found"}, 404


@app.route("/client-api/time")
def client_api_time():
    nonce = secrets.token_urlsafe(12)
    now_ts = int(utcnow().timestamp())
    signature = _b64url_encode(
        hmac.new(
            CLIENT_GLOBAL_CRYPTO_KEY.encode("utf-8"),
            f"time:{now_ts}:{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
    )
    return {
        "ok": True,
        "server_time": now_ts,
        "nonce": nonce,
        "signature": signature,
    }


@app.route("/client-api/session/<login_slug>", methods=["POST"])
def client_password_login(login_slug: str):
    if not is_valid_client_login_slug(login_slug):
        return {"ok": False, "error": "not found"}, 404
    payload = request.get_json(silent=True) or request.form
    username = (payload.get("username", "") or "").strip()
    password = (payload.get("password", "") or "").strip()
    if not username or not password:
        return {"ok": False, "error": "username and password required"}, 400

    db = get_db()
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE username = ? AND role = 'user'
        LIMIT 1
        """,
        (username,),
    ).fetchone()
    if not user or not check_password_hash(row_get(user, "password_hash", "") or "", password):
        return {"ok": False, "error": "用户名或密码错误"}, 401
    if (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
        return {"ok": False, "error": "账号已停用"}, 403
    if int(row_get(user, "vpn_enabled", 0) or 0) != 1:
        return {"ok": False, "error": "VPN 未启用"}, 403

    token = ensure_user_client_config_token(db, user)
    client_ip = normalize_public_client_ip(get_client_ip())
    db.execute(
        """
        UPDATE users
        SET last_login_ip = ?,
            last_login_at = ?
        WHERE id = ?
        """,
        (client_ip, utcnow_iso(), int(user["id"])),
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    bootstrap_payload = build_client_bootstrap_payload(user, token)
    return encrypt_login_api_payload(bootstrap_payload)


@app.route("/client-api/bootstrap/<username>")
def client_bootstrap_config(username: str):
    db = get_db()
    user = resolve_client_config_user(db, username, extract_client_config_token())
    if not user:
        return {"ok": False, "error": "invalid token"}, 401
    client_token = (row_get(user, "client_config_token", "") or "").strip()
    if (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
        return encrypt_client_api_payload({"ok": False, "error": "account disabled"}, client_token), 403
    if int(row_get(user, "vpn_enabled", 0) or 0) != 1:
        return encrypt_client_api_payload({"ok": False, "error": "vpn disabled"}, client_token), 403
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    client_token = (row_get(user, "client_config_token", "") or "").strip() if user else client_token
    if not user:
        return encrypt_client_api_payload({"ok": False, "error": "account disabled"}, client_token), 403
    return encrypt_client_api_payload(build_client_bootstrap_payload(user, client_token), client_token)


@app.route("/client-api/online/<username>", methods=["POST"])
def client_online_heartbeat(username: str):
    db = get_db()
    user = resolve_client_config_user(db, username, extract_client_config_token())
    if not user:
        return {"ok": False, "error": "invalid token"}, 401
    if (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
        return {"ok": False, "error": "account disabled"}, 403
    if int(row_get(user, "vpn_enabled", 0) or 0) != 1:
        return {"ok": False, "error": "vpn disabled"}, 403

    payload = request.get_json(silent=True) or request.form
    status = (payload.get("status", "online") or "online").strip().lower()
    user_id = int(user["id"])
    if status in {"offline", "disconnect", "disconnected"}:
        db.execute("DELETE FROM client_online_sessions WHERE user_id = ?", (user_id,))
        db.commit()
        return {"ok": True}

    profile_type = (payload.get("profile_type", "") or "").strip().lower() or "unknown"
    profile_id = (payload.get("profile_id", "") or "").strip()
    profile_name = (payload.get("profile_name", "") or "").strip()
    server_host = (payload.get("server_host", "") or "").strip()
    endpoint = normalize_public_client_ip(get_client_ip()) or (row_get(user, "last_login_ip", "") or "").strip()
    try:
        server_id = int(payload.get("server_id") or 0) or None
    except Exception:
        server_id = None
    rx_bytes = to_non_negative_int(payload.get("rx_bytes", 0))
    tx_bytes = to_non_negative_int(payload.get("tx_bytes", 0))
    now = utcnow_iso()
    db.execute(
        """
        INSERT INTO client_online_sessions (
            user_id, username, server_id, server_host, profile_type, profile_id,
            profile_name, endpoint, rx_bytes, tx_bytes, last_seen_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (user_id) DO UPDATE SET
            username = EXCLUDED.username,
            server_id = EXCLUDED.server_id,
            server_host = EXCLUDED.server_host,
            profile_type = EXCLUDED.profile_type,
            profile_id = EXCLUDED.profile_id,
            profile_name = EXCLUDED.profile_name,
            endpoint = EXCLUDED.endpoint,
            rx_bytes = EXCLUDED.rx_bytes,
            tx_bytes = EXCLUDED.tx_bytes,
            last_seen_at = EXCLUDED.last_seen_at
        """,
        (
            user_id,
            row_get(user, "username", ""),
            server_id,
            server_host,
            profile_type,
            profile_id,
            profile_name,
            endpoint,
            rx_bytes,
            tx_bytes,
            now,
            now,
        ),
    )
    if endpoint:
        db.execute(
            "UPDATE users SET last_login_ip = ?, last_login_at = ? WHERE id = ?",
            (endpoint, now, user_id),
        )
    db.commit()
    return {"ok": True}


@app.route("/admin/users/<int:user_id>/client-bootstrap")
@login_required
@admin_required
def admin_download_client_bootstrap(user_id: int):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(user_id),),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()
    token = ensure_user_client_config_token(db, user)
    payload = build_client_bootstrap_payload(user, token)
    filename = f"company-vpn-{safe_name(user['username'])}.json"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        headers=headers,
        mimetype="application/json; charset=utf-8",
    )


CLIENT_BUILD_LOG_FILE = DATA_DIR / "client-build.log"
CLIENT_BUILD_STATE_FILE = DATA_DIR / "client-build-state.json"
CLIENT_BUILD_LOCK = threading.Lock()


def append_client_build_log(message: str) -> None:
    CLIENT_BUILD_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = (message or "").rstrip()
    with CLIENT_BUILD_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"{timestamp}  {text}\n")


def read_client_build_log() -> str:
    if not CLIENT_BUILD_LOG_FILE.exists():
        return ""
    data = CLIENT_BUILD_LOG_FILE.read_text(encoding="utf-8", errors="replace")
    return data[-60000:]


def save_client_build_state(state: dict) -> None:
    CLIENT_BUILD_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CLIENT_BUILD_STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def read_client_build_state() -> dict:
    if not CLIENT_BUILD_STATE_FILE.exists():
        return {"running": False, "ok": None, "message": "", "started_at": "", "finished_at": ""}
    try:
        state = json.loads(CLIENT_BUILD_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"running": False, "ok": None, "message": "", "started_at": "", "finished_at": ""}
    if not isinstance(state, dict):
        return {"running": False, "ok": None, "message": "", "started_at": "", "finished_at": ""}
    state.setdefault("running", False)
    state.setdefault("ok", None)
    state.setdefault("message", "")
    state.setdefault("started_at", "")
    state.setdefault("finished_at", "")
    return state


def run_logged_process(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    log_callback=None,
) -> tuple[int, str]:
    if log_callback:
        log_callback("$ " + " ".join(shlex.quote(str(part)) for part in cmd))
    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    output_lines: list[str] = []
    if process.stdout:
        for line in process.stdout:
            text = line.rstrip()
            output_lines.append(text)
            if log_callback and text:
                log_callback(text)
    return_code = process.wait()
    if log_callback:
        log_callback(f"命令结束: exit={return_code}")
    return return_code, "\n".join(output_lines[-300:])


def write_client_package_file(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    if path.name.lower().startswith("readme"):
        return
    stored_suffixes = {
        ".msi",
        ".zip",
        ".7z",
        ".gz",
        ".xz",
        ".rar",
    }
    compression = (
        zipfile.ZIP_STORED
        if path.suffix.lower() in stored_suffixes
        else zipfile.ZIP_DEFLATED
    )
    if compression == zipfile.ZIP_DEFLATED:
        archive.write(path, arcname, compress_type=compression, compresslevel=9)
    else:
        archive.write(path, arcname, compress_type=compression)


def ensure_go_toolchain(log_callback=None) -> tuple[bool, str, str]:
    go_bin = shutil.which("go")
    if go_bin:
        if log_callback:
            log_callback(f"Go 工具链已安装: {go_bin}")
        return True, go_bin, "Go 工具链已安装。"

    apt_get = shutil.which("apt-get")
    if not apt_get:
        return False, "", "服务器未安装 Go，且当前系统没有 apt-get，无法自动安装 Go 工具链。"

    logs: list[str] = ["服务器未安装 Go，开始自动安装 Go 工具链..."]
    if log_callback:
        log_callback(logs[-1])
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    for cmd in ([apt_get, "update"], [apt_get, "install", "-y", "golang-go"]):
        return_code, output_tail = run_logged_process(cmd, env=env, log_callback=log_callback)
        logs.append(f"{' '.join(cmd)}: exit={return_code}")
        if output_tail:
            logs.append(output_tail[-3000:])
        if return_code != 0:
            return False, "", "\n".join(logs)

    go_bin = shutil.which("go") or "/usr/bin/go"
    if not Path(go_bin).exists():
        return False, "", "\n".join(logs + ["Go 安装完成后仍未找到 go 命令。"])
    logs.append(f"Go 工具链安装完成: {go_bin}")
    return True, go_bin, "\n".join(logs)


def parse_client_package_version(name: str) -> str:
    raw = Path(name).name
    if raw.startswith("client-") and raw.endswith(".zip"):
        return raw[len("client-") : -len(".zip")]
    return ""


def normalize_client_package_version_for_sort(version: str) -> str:
    name = parse_client_package_version(version)
    if not name:
        name = (version or "").strip()

    parts = name.split("-")

    # New format: YYYY-MMDD-HHMM-SSMM (e.g. 2026-0622-1430-1211)
    if len(parts) == 4:
        year, month_day, hm, ssms = (part.strip() for part in parts)
        if len(year) == 4 and len(month_day) == 4 and len(hm) == 4:
            return f"{year}{month_day}{hm}{ssms.zfill(4)[:4]}"

    # Transitional format: YYYY-MMDD-HHMM-SS-MM
    if len(parts) == 5:
        year, month_day, hm, sec, ms = (part.strip() for part in parts)
        if (
            len(year) == 4
            and len(month_day) == 4
            and len(hm) == 4
            and sec
            and ms
        ):
            return f"{year}{month_day}{hm}{sec.zfill(2)[:2]}{ms.zfill(2)[:2]}"

    # Legacy format: YYYYMMDD-HHMMSS-SS
    if len(parts) == 3:
        date_part = parts[0].strip()
        time_part = parts[1].strip()
        ms_part = parts[2].strip()
        if len(date_part) == 8 and len(time_part) >= 4:
            year = date_part[:4]
            month_day = date_part[4:8]
            hm = time_part[:4]
            sec = time_part[4:6] if len(time_part) >= 6 else "00"
            ms = ms_part.zfill(2)[:2]
            return f"{year}{month_day}{hm}{sec}{ms}"

    return ""


def sort_client_packages_by_version(paths) -> list[Path]:
    def _key(path: Path):
        version = parse_client_package_version(path.name)
        sort_version = normalize_client_package_version_for_sort(version)
        return (1 if sort_version else 0, sort_version, version, path.stat().st_mtime)

    return sorted(list(paths), key=_key, reverse=True)


def build_client_packages_on_server(web_url: str, log_callback=None) -> tuple[bool, str]:
    go_ok, go_bin, go_message = ensure_go_toolchain(log_callback=log_callback)
    if not go_ok:
        return False, go_message
    client_go_dir = BASE_DIR / "client-go"
    if not client_go_dir.exists():
        return False, "服务器缺少 client-go 源码目录。"
    package_root = BASE_DIR / "client" / "package"
    dist_dir = BASE_DIR / "client" / "dist"
    package_root.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)
    amd_dir = package_root / "windows-amd64"
    amd_dir.mkdir(parents=True, exist_ok=True)
    amd_installer_dir = amd_dir / "installers"
    amd_installer_dir.mkdir(parents=True, exist_ok=True)
    for removable_dir in (amd_dir / "cores", amd_installer_dir):
        if removable_dir.exists():
            shutil.rmtree(removable_dir, ignore_errors=True)
            if log_callback:
                log_callback(f"已移除不再需要的客户端组件目录: {removable_dir.relative_to(amd_dir)}")
    amd_installer_dir.mkdir(parents=True, exist_ok=True)
    for wrong_installer in amd_installer_dir.glob("*arm64*.msi"):
        try:
            wrong_installer.unlink()
            if log_callback:
                log_callback(f"已移除 x86_64 包中的 ARM 安装器: {wrong_installer.name}")
        except Exception as exc:
            if log_callback:
                log_callback(f"移除 ARM 安装器失败: {wrong_installer.name} - {exc}")
    for stale_readme in amd_dir.glob("README*"):
        try:
            stale_readme.unlink()
            if log_callback:
                log_callback(f"已移除客户端包 README: {stale_readme.name}")
        except Exception as exc:
            if log_callback:
                log_callback(f"移除客户端包 README 失败: {stale_readme.name} - {exc}")
    clean_url = (web_url or "").strip().rstrip("/")
    if not clean_url:
        return False, "Web 地址为空，无法内置。"

    if log_callback:
        log_callback(f"内置 Web 地址: {clean_url}")
    now = datetime.now()
    build_version = (
        f"{now.strftime('%Y-%m%d-%H%M')}"
        f"-{now.strftime('%S')}{now.microsecond // 10000:02d}"
    )
    if log_callback:
        log_callback(f"客户端版本号: {build_version}")
    key = CLIENT_GLOBAL_CRYPTO_KEY
    ldflags = " ".join(
        [
            "-H windowsgui",
            "-s",
            "-w",
            f"-X main.embeddedDefaultWebURL={shlex.quote(clean_url)}",
            f"-X main.embeddedClientCryptoKey={shlex.quote(key)}",
            f"-X main.embeddedClientVersion={shlex.quote(build_version)}",
        ]
    )
    logs: list[str] = [go_message, f"内置 Web 地址: {clean_url}", f"客户端版本号: {build_version}"]
    env_base = os.environ.copy()
    env_base.setdefault("GOPROXY", "https://goproxy.cn,direct")
    env_base.setdefault("GOSUMDB", "sum.golang.google.cn")
    env_base.setdefault("GOTOOLCHAIN", "auto")
    if log_callback:
        log_callback("开始编译 Windows x86_64 客户端...")
    env = env_base.copy()
    env["GOOS"] = "windows"
    env["GOARCH"] = "amd64"
    out_path = amd_dir / "CompanyVPN.exe"
    cmd = [go_bin, "build", "-trimpath", "-ldflags", ldflags, "-o", str(out_path), "."]
    return_code, output_tail = run_logged_process(
        cmd,
        cwd=client_go_dir,
        env=env,
        log_callback=log_callback,
    )
    logs.append(f"x86_64: exit={return_code}")
    if output_tail:
        logs.append(output_tail[-3000:])
    if return_code != 0:
        return False, "\n".join(logs)
    if log_callback:
        log_callback("Windows x86_64 客户端编译完成。")

    updater_path = amd_dir / "Updater.exe"
    if log_callback:
        log_callback("开始编译 Windows x86_64 更新程序...")
    updater_cmd = [go_bin, "build", "-trimpath", "-ldflags", "-H windowsgui -s -w", "-o", str(updater_path), "./updater"]
    updater_code, updater_output = run_logged_process(
        updater_cmd,
        cwd=client_go_dir,
        env=env,
        log_callback=log_callback,
    )
    logs.append(f"updater-x86_64: exit={updater_code}")
    if updater_output:
        logs.append(updater_output[-3000:])
    if updater_code != 0:
        return False, "\n".join(logs)
    if log_callback:
        log_callback("Windows x86_64 更新程序编译完成。")

    wintun_src = client_go_dir / "assets" / "wintun" / "amd64" / "wintun.dll"
    if not wintun_src.exists():
        return False, "\n".join(logs + ["缺少 assets/wintun/amd64/wintun.dll，无法打包 TUN 全局模式客户端。"])
    shutil.copy2(wintun_src, amd_dir / "wintun.dll")
    if log_callback:
        log_callback("已打包 Windows TUN 驱动: wintun.dll")

    zip_path = dist_dir / f"client-{build_version}.zip"
    if log_callback:
        log_callback(f"开始打包 {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in amd_dir.rglob("*"):
            if path.is_dir():
                continue
            write_client_package_file(archive, path, path.relative_to(amd_dir).as_posix())
    logs.append(f"package: {zip_path.name}")
    if log_callback:
        log_callback(f"打包完成: {zip_path.name}")
        log_callback(f"默认下载包已更新为: {zip_path.name}")
    for old_package in dist_dir.glob("*.zip"):
        if old_package == zip_path:
            continue
        try:
            old_package.unlink()
            if log_callback:
                log_callback(f"已删除旧包: {old_package.name}")
        except Exception as exc:
            if log_callback:
                log_callback(f"删除旧包失败: {old_package.name} - {exc}")
    for legacy_file in list(dist_dir.glob("company-vpn-windows-*.exe")) + list(dist_dir.glob("README-Windows.txt")):
        try:
            legacy_file.unlink()
            if log_callback:
                log_callback(f"已删除旧客户端下载文件: {legacy_file.name}")
        except Exception as exc:
            if log_callback:
                log_callback(f"删除旧客户端下载文件失败: {legacy_file.name} - {exc}")

    platform_build_script = BASE_DIR / "scripts" / "build_platform_clients.sh"
    if platform_build_script.exists():
        if log_callback:
            log_callback("开始编译 macOS / iOS / Android 客户端...")
        platform_env = env_base.copy()
        platform_env.update(
            {
                "COMPANY_VPN_WEB_URL": clean_url,
                "COMPANY_VPN_CLIENT_KEY": key,
                "COMPANY_VPN_CLIENT_VERSION": build_version,
                "COMPANY_VPN_DIST_DIR": str(dist_dir),
                "COMPANY_VPN_PACKAGE_DIR": str(package_root),
            }
        )
        platform_code, platform_output = run_logged_process(
            [str(platform_build_script)],
            cwd=BASE_DIR,
            env=platform_env,
            log_callback=log_callback,
        )
        logs.append(f"platform-clients: exit={platform_code}")
        if platform_output:
            logs.append(platform_output[-3000:])
        if platform_code != 0 and log_callback:
            log_callback("部分平台客户端编译失败，请查看上方日志；Windows 默认包已生成。")
    elif log_callback:
        log_callback("未找到平台客户端构建脚本，跳过 macOS / iOS / Android。")
    return True, "客户端编译完成。"


def run_client_build_background(web_url: str) -> None:
    try:
        append_client_build_log("客户端编译任务启动。")
        ok, message = build_client_packages_on_server(web_url, log_callback=append_client_build_log)
    except Exception as exc:
        ok, message = False, f"客户端编译失败：{exc}"
        append_client_build_log(message)
    finished_at = utcnow_iso()
    append_client_build_log("客户端编译完成。" if ok else "客户端编译失败。")
    save_client_build_state(
        {
            "running": False,
            "ok": bool(ok),
            "message": message,
            "started_at": read_client_build_state().get("started_at", ""),
            "finished_at": finished_at,
        }
    )


@app.route("/admin/client/build", methods=["POST"])
@login_required
@admin_required
def admin_build_client_packages():
    web_url = (request.form.get("web_url", "") or "").strip() or request.url_root.rstrip("/")
    try:
        ok, message = build_client_packages_on_server(web_url)
    except subprocess.TimeoutExpired:
        ok, message = False, "客户端编译超时。"
    except Exception as exc:
        ok, message = False, f"客户端编译失败：{exc}"
    if ok:
        flash("客户端已在服务器编译完成，内置地址：" + web_url.rstrip("/"), "success")
    else:
        flash(message, "error")
    return redirect_admin_subscriptions()


@app.route("/admin/client/build/start", methods=["POST"])
@login_required
@admin_required
def admin_start_client_build_packages():
    web_url = (request.form.get("web_url", "") or "").strip() or request.url_root.rstrip("/")
    with CLIENT_BUILD_LOCK:
        state = read_client_build_state()
        if state.get("running"):
            return {"ok": True, "running": True, "message": "客户端编译任务正在运行。"}
        CLIENT_BUILD_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CLIENT_BUILD_LOG_FILE.write_text("", encoding="utf-8")
        save_client_build_state(
            {
                "running": True,
                "ok": None,
                "message": "客户端编译任务已启动。",
                "started_at": utcnow_iso(),
                "finished_at": "",
            }
        )
        worker = threading.Thread(
            target=run_client_build_background,
            args=(web_url,),
            daemon=True,
        )
        worker.start()
    return {"ok": True, "running": True, "message": "客户端编译任务已启动。"}


@app.route("/admin/client/build/status")
@login_required
@admin_required
def admin_client_build_status():
    state = read_client_build_state()
    return {
        "ok": True,
        "running": bool(state.get("running")),
        "build_ok": state.get("ok"),
        "message": state.get("message", ""),
        "started_at": state.get("started_at", ""),
        "finished_at": state.get("finished_at", ""),
        "log": read_client_build_log(),
    }


@app.route("/client/download")
def public_client_download():
    dist_dir = BASE_DIR / "client" / "dist"
    candidates = sort_client_packages_by_version(dist_dir.glob("client-*.zip"))
    zip_path = candidates[0] if candidates else None
    if not zip_path:
        legacy_candidates = sorted(
            dist_dir.glob("*.zip"),
            key=lambda item: (item.stat().st_mtime, item.name),
            reverse=True,
        )
        zip_path = legacy_candidates[0] if legacy_candidates else None
    if not zip_path or not zip_path.exists():
        return Response("client package not found", status=404, mimetype="text/plain")
    return send_file(
        zip_path,
        as_attachment=True,
        download_name=zip_path.name,
        mimetype="application/zip",
        max_age=0,
    )


@app.route("/client/latest")
def public_client_latest():
    dist_dir = BASE_DIR / "client" / "dist"
    candidates = sort_client_packages_by_version(dist_dir.glob("client-*.zip"))
    zip_path = candidates[0] if candidates else None
    if not zip_path or not zip_path.exists():
        return {"ok": False, "error": "client package not found"}, 404
    filename = zip_path.name
    version = filename
    if version.startswith("client-"):
        version = version[len("client-") :]
    if version.endswith(".zip"):
        version = version[:-4]
    return {
        "ok": True,
        "version": version,
        "filename": filename,
        "download_url": absolute_url_for("public_client_download"),
    }


@app.route("/admin/users/<int:user_id>/client-package")
@login_required
@admin_required
def admin_download_client_package(user_id: int):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(user_id),),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()

    arch = (request.args.get("arch", "") or "").strip().lower()
    if arch in {"arm", "arm64", "windows-arm64"}:
        package_arch = "windows-arm64"
    else:
        package_arch = "windows-amd64"
    package_dir = BASE_DIR / "client" / "package" / package_arch
    if not package_dir.exists():
        flash("客户端完整包不存在，请先构建客户端。", "error")
        return redirect_admin_subscriptions()

    token = ensure_user_client_config_token(db, user)
    bootstrap_payload = build_client_bootstrap_payload(user, token)
    bootstrap_name = f"company-vpn-{safe_name(user['username'])}.json"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            bootstrap_name,
            json.dumps(bootstrap_payload, ensure_ascii=False, indent=2),
        )
        for path in package_dir.rglob("*"):
            if path.is_dir():
                continue
            arcname = path.relative_to(package_dir).as_posix()
            write_client_package_file(archive, path, arcname)

    filename = f"company-vpn-{safe_name(user['username'])}-{package_arch}.zip"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    return Response(
        buffer.getvalue(),
        headers=headers,
        mimetype="application/zip",
    )


@app.route("/client-api/ssh-tunnel/cleanup", methods=["POST"])
def client_ssh_tunnel_cleanup():
    token = ""
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = (request.form.get("token") or "").strip()
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get("token", "")
    payload = verify_ssh_cleanup_token(token)
    if not payload:
        return {"ok": False, "error": "invalid cleanup token"}, 401

    db = get_db()
    server_row = db.execute(
        "SELECT * FROM vpn_servers WHERE id = ? LIMIT 1",
        (int(payload.get("server_id") or 0),),
    ).fetchone()
    if not server_row:
        return {"ok": False, "error": "server not found"}, 404

    admin_host = normalize_remote_host(row_get(server_row, "host", ""))
    admin_port = normalize_server_port(row_get(server_row, "port", 22), 22)
    admin_username = (row_get(server_row, "username", "") or "").strip()
    admin_password = row_get(server_row, "password", "") or ""
    admin_private_key = (row_get(server_row, "ssh_private_key", "") or "").strip()
    if not admin_host or not admin_username or (not admin_password and not admin_private_key):
        return {"ok": False, "error": "server ssh credential missing"}, 500

    ok, message = run_remote_ssh_script(
        host=admin_host,
        port=admin_port,
        username=admin_username,
        password=admin_password,
        private_key_text=admin_private_key,
        script=build_ssh_tunnel_cleanup_script(str(payload.get("temp_username") or "")),
        timeout=60,
    )
    if not ok:
        return {"ok": False, "error": message}, 500
    return {"ok": True, "message": message}


@app.route("/client-api/profiles/<username>/<profile_type>")
def client_profile_config(username: str, profile_type: str):
    db = get_db()
    user = resolve_client_config_user(db, username, extract_client_config_token())
    if not user:
        return {"ok": False, "error": "invalid token"}, 401
    client_token = (row_get(user, "client_config_token", "") or "").strip()
    if (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
        return encrypt_client_api_payload({"ok": False, "error": "account disabled"}, client_token), 403
    if int(row_get(user, "vpn_enabled", 0) or 0) != 1:
        return encrypt_client_api_payload({"ok": False, "error": "vpn disabled"}, client_token), 403

    profile = (profile_type or "").strip().lower()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    client_token = (row_get(user, "client_config_token", "") or "").strip() if user else client_token
    if not user or (row_get(user, "status", "approved") or "approved").strip().lower() == "disabled":
        return encrypt_client_api_payload({"ok": False, "error": "account disabled"}, client_token), 403
    try:
        client_ip = normalize_public_client_ip(get_client_ip())
        if client_ip:
            db.execute(
                "UPDATE users SET last_login_ip = ? WHERE id = ?",
                (client_ip, int(user["id"])),
            )
            db.commit()
            user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    except Exception:
        app.logger.exception("Failed to update client config source ip")

    try:
        if profile in {"openvpn", "ovpn"}:
            return encrypt_client_api_payload({"ok": False, "error": "OpenVPN is no longer supported"}, client_token), 410

        if profile in {"clash", "ss", "ss-kcptun", "shadowsocks", "kcptun"}:
            return encrypt_client_api_payload({"ok": False, "error": "SS/KCPTUN is no longer supported"}, client_token), 410

        if profile in {"ssh", "ssh-tunnel", "tunnel"}:
            target_server = get_requested_allowed_server(db, user)
            if not server_supports_ssh_tunnel(target_server):
                return encrypt_client_api_payload({"ok": False, "error": "SSH Tunnel is disabled for this server"}, client_token), 503
            config_text = build_user_ssh_tunnel_config(db, user, target_server)
            payload = {
                "ok": True,
                "type": "ssh-tunnel",
                "filename": f"ssh-tunnel-{safe_name(user['username'])}.json",
                "config": config_text,
                "server": serialize_runtime_server(target_server),
            }
            return encrypt_client_api_payload(
                payload,
                client_token,
            )
    except Exception as exc:
        return encrypt_client_api_payload({"ok": False, "error": str(exc)}, client_token), 500

    return encrypt_client_api_payload({"ok": False, "error": "unknown profile type"}, client_token), 404


@app.route("/d/<path:access_token>")
def download_via_token(access_token: str):
    token = (access_token or "").strip()
    if not token:
        return config_download_error("invalid or missing access token", status=401)

    output_format = (
        (request.args.get("format", "") or "").strip()
        or (request.args.get("f", "") or "").strip()
        or "yaml"
    ).lower()
    build_raw = output_format in {"json", "raw"}
    db = get_db()

    def response_with_content(
        config_text: str,
        filename: str,
        *,
        mimetype: str | None = None,
    ):
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        }
        response_mimetype = (
            mimetype or ("application/json" if build_raw else "text/yaml; charset=utf-8")
        )
        return Response(config_text, headers=headers, mimetype=response_mimetype)

    admin_ss = resolve_download_access_user(db, token, "download-config-admin")
    if admin_ss is not None:
        if row_get(admin_ss, "role") != "admin":
            return config_download_error("forbidden", status=403)
        admin = db.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'admin'",
            (admin_ss["id"],),
        ).fetchone()
        if not admin:
            return config_download_error("admin not found", status=404)
        target_server = choose_runtime_server_for_admin(db, admin)
        wants_openvpn = output_format in {"ovpn", "openvpn"}
        if wants_openvpn:
            if not OPENVPN_ENABLED or not server_supports_openvpn(target_server):
                return config_download_error("OpenVPN is disabled for this server", status=503)
            admin = ensure_admin_self_vpn_ready(db, admin)
            db.commit()
            config_text = build_openvpn_client_config(
                admin["username"],
                user=admin,
                server_row=target_server,
            )
            filename = f"openvpn-admin-{safe_name(admin['username'])}.ovpn"
            return response_with_content(
                config_text,
                filename,
                mimetype="application/x-openvpn-profile; charset=utf-8",
            )
        if not server_supports_ss_kcptun(target_server):
            return config_download_error("Shadowsocks + kcptun is disabled for this server", status=503)
        config_text = (
            build_user_shadowsocks_config(admin)
            if build_raw
            else build_user_shadowsocks_clash_profile(admin)
        )
        filename = build_download_filename_for_user(admin, build_raw=build_raw)
        return response_with_content(config_text, filename)

    user_ss = resolve_download_access_user(db, token, "download-config-user")
    if user_ss is not None:
        if row_get(user_ss, "role") != "user":
            return config_download_error("forbidden", status=403)
        reconcile_expired_subscriptions(db)
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_ss["id"],)).fetchone()
        if not user:
            return config_download_error("user not found", status=404)
        if not is_subscription_active(user):
            return config_download_error("subscription inactive", status=403)
        target_server = get_persisted_runtime_server_for_account(db, user)
        wants_openvpn = output_format in {"ovpn", "openvpn"}
        if wants_openvpn:
            if not OPENVPN_ENABLED or not server_supports_openvpn(target_server):
                return config_download_error("OpenVPN is disabled for this server", status=503)
            vpn_data = ensure_user_vpn_ready(db, user)
            assigned_server_id = vpn_data.get("assigned_server_id")
            if assigned_server_id is not None:
                db.execute(
                    "UPDATE users SET assigned_server_id = ?, vpn_enabled = 1 WHERE id = ?",
                    (assigned_server_id, int(user["id"])),
                )
            db.commit()
            user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            config_text = build_openvpn_client_config(
                user["username"],
                user=user,
                server_row=get_persisted_runtime_server_for_account(db, user),
            )
            filename = f"openvpn-{safe_name(user['username'])}.ovpn"
            return response_with_content(
                config_text,
                filename,
                mimetype="application/x-openvpn-profile; charset=utf-8",
            )
        target_server = get_persisted_runtime_server_for_account(db, user)
        if not server_supports_ss_kcptun(target_server):
            return config_download_error("Shadowsocks + kcptun is disabled for this server", status=503)
        config_text = (
            build_user_shadowsocks_config(user)
            if build_raw
            else build_user_shadowsocks_clash_profile(user)
        )
        filename = build_download_filename_for_user(user, build_raw=build_raw)
        return response_with_content(config_text, filename)

    admin_kcptun = resolve_download_access_user(db, token, "download-kcptun-admin")
    if admin_kcptun is not None:
        if row_get(admin_kcptun, "role") != "admin":
            return config_download_error("forbidden", status=403)
        admin = db.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'admin'",
            (admin_kcptun["id"],),
        ).fetchone()
        if not admin:
            return config_download_error("admin not found", status=404)
        if not server_supports_ss_kcptun(choose_runtime_server_for_admin(db, admin)):
            return config_download_error("kcptun is disabled for this server", status=503)
        config_text = (
            build_user_kcptun_config(admin)
            if build_raw
            else build_user_kcptun_clash_profile(admin)
        )
        filename = build_download_filename_for_user(admin, build_raw=build_raw)
        return response_with_content(config_text, filename)

    user_kcptun = resolve_download_access_user(db, token, "download-kcptun-user")
    if user_kcptun is not None:
        if row_get(user_kcptun, "role") != "user":
            return config_download_error("forbidden", status=403)
        reconcile_expired_subscriptions(db)
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_kcptun["id"],)).fetchone()
        if not user:
            return config_download_error("user not found", status=404)
        if not is_subscription_active(user):
            return config_download_error("subscription inactive", status=403)
        if not server_supports_ss_kcptun(get_persisted_runtime_server_for_account(db, user)):
            return config_download_error("kcptun is disabled for this server", status=503)
        config_text = (
            build_user_kcptun_config(user)
            if build_raw
            else build_user_kcptun_clash_profile(user)
        )
        filename = build_download_filename_for_user(user, build_raw=build_raw)
        return response_with_content(config_text, filename)

    return config_download_error("invalid or missing access token", status=401)


@app.route("/download/config")
def download_config():
    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
    if output_format in {"ovpn", "openvpn"}:
        return download_openvpn_config()

    db = get_db()
    user = current_user()
    used_access_token = False
    if not user:
        user = resolve_download_access_user(
            db,
            request.args.get("access", ""),
            "download-config-user",
        )
        used_access_token = True
    if not user:
        return config_download_error("invalid or missing access token", status=401)
    if row_get(user, "role") != "user":
        if used_access_token:
            return config_download_error("forbidden", status=403)
        flash("管理员无需下载客户端配置。", "error")
        return redirect(url_for("dashboard"))

    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user:
        return config_download_error("user not found", status=404)
    if not is_subscription_active(user):
        if used_access_token:
            return config_download_error("subscription inactive", status=403)
        flash("订阅未生效或已过期，请先续费。", "error")
        return redirect(url_for("dashboard"))

    if not server_supports_ss_kcptun(get_persisted_runtime_server_for_account(db, user)):
        return config_download_error("Shadowsocks + kcptun is disabled for this server", status=503)

    build_raw = output_format in {"json", "raw"}
    try:
        config_text = (
            build_user_shadowsocks_config(user)
            if build_raw
            else build_user_shadowsocks_clash_profile(user)
        )
    except Exception as exc:
        flash(f"Shadowsocks 配置生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    filename = build_download_filename_for_user(user, build_raw=build_raw)
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/admin/download/config")
def admin_download_config():
    db = get_db()
    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
    if output_format in {"ovpn", "openvpn"}:
        return admin_download_openvpn_config()

    admin = current_user()
    used_access_token = False
    if not admin:
        admin = resolve_download_access_user(
            db,
            request.args.get("access", ""),
            "download-config-admin",
        )
        used_access_token = True
    if not admin:
        return config_download_error("invalid or missing access token", status=401)
    if row_get(admin, "role") != "admin":
        if used_access_token:
            return config_download_error("forbidden", status=403)
        flash("仅管理员可访问。", "error")
        return redirect(url_for("dashboard"))

    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (admin["id"],),
    ).fetchone()
    if not admin:
        return config_download_error("admin not found", status=404)

    if not server_supports_ss_kcptun(choose_runtime_server_for_admin(db, admin)):
        return config_download_error("Shadowsocks + kcptun is disabled for this server", status=503)

    build_raw = output_format in {"json", "raw"}
    try:
        config_text = (
            build_user_shadowsocks_config(admin)
            if build_raw
            else build_user_shadowsocks_clash_profile(admin)
        )
    except Exception as exc:
        flash(f"管理员 Shadowsocks 配置生成失败：{exc}", "error")
        return redirect(url_for("admin_subscriptions"))

    filename = build_download_filename_for_user(admin, build_raw=build_raw)
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/download/kcptun")
def download_kcptun_config():
    db = get_db()
    user = current_user()
    used_access_token = False
    if not user:
        user = resolve_download_access_user(
            db,
            request.args.get("access", ""),
            "download-kcptun-user",
        )
        used_access_token = True
    if not user:
        return config_download_error("invalid or missing access token", status=401)
    if row_get(user, "role") != "user":
        if used_access_token:
            return config_download_error("forbidden", status=403)
        flash("管理员无需下载客户端配置。", "error")
        return redirect(url_for("dashboard"))

    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user:
        return config_download_error("user not found", status=404)
    if not is_subscription_active(user):
        if used_access_token:
            return config_download_error("subscription inactive", status=403)
        flash("订阅未生效或已过期，请先续费。", "error")
        return redirect(url_for("dashboard"))
    if not server_supports_ss_kcptun(get_persisted_runtime_server_for_account(db, user)):
        return config_download_error("kcptun is disabled for this server", status=503)

    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
    build_raw = output_format in {"json", "raw"}
    try:
        config_text = (
            build_user_kcptun_config(user)
            if build_raw
            else build_user_kcptun_clash_profile(user)
        )
    except Exception as exc:
        flash(f"kcptun 配置生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    filename = build_download_filename_for_user(user, build_raw=build_raw)
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/admin/download/kcptun")
def admin_download_kcptun_config():
    db = get_db()
    admin = current_user()
    used_access_token = False
    if not admin:
        admin = resolve_download_access_user(
            db,
            request.args.get("access", ""),
            "download-kcptun-admin",
        )
        used_access_token = True
    if not admin:
        return config_download_error("invalid or missing access token", status=401)
    if row_get(admin, "role") != "admin":
        if used_access_token:
            return config_download_error("forbidden", status=403)
        flash("仅管理员可访问。", "error")
        return redirect(url_for("dashboard"))

    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (admin["id"],),
    ).fetchone()
    if not admin:
        return config_download_error("admin not found", status=404)
    if not server_supports_ss_kcptun(choose_runtime_server_for_admin(db, admin)):
        return config_download_error("kcptun is disabled for this server", status=503)

    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
    build_raw = output_format in {"json", "raw"}
    try:
        config_text = (
            build_user_kcptun_config(admin)
            if build_raw
            else build_user_kcptun_clash_profile(admin)
        )
    except Exception as exc:
        flash(f"管理员 kcptun 配置生成失败：{exc}", "error")
        return redirect(url_for("admin_subscriptions"))

    filename = build_download_filename_for_user(admin, build_raw=build_raw)
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/download/openvpn")
@login_required
def download_openvpn_config():
    if not OPENVPN_ENABLED or not is_openvpn_open():
        flash("OpenVPN 当前未启用。", "error")
        return redirect(url_for("dashboard_config"))

    db = get_db()
    user = current_user()
    if not user or row_get(user, "role") != "user":
        flash("仅普通用户可下载用户配置。", "error")
        return redirect(url_for("dashboard"))

    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user or not is_subscription_active(user):
        flash("账号未启用，请联系管理员。", "error")
        return redirect(url_for("dashboard_config"))

    try:
        vpn_data = ensure_user_vpn_ready(db, user)
        assigned_server_id = vpn_data.get("assigned_server_id")
        if assigned_server_id is not None:
            db.execute(
                "UPDATE users SET assigned_server_id = ?, vpn_enabled = 1 WHERE id = ?",
                (assigned_server_id, int(user["id"])),
            )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        target_server = get_persisted_runtime_server_for_account(db, user)
        if not server_supports_openvpn(target_server):
            flash("当前节点未启用 OpenVPN。", "error")
            return redirect(url_for("dashboard_config"))
        config_text = build_openvpn_client_config(
            user["username"],
            user=user,
            server_row=target_server,
        )
    except Exception as exc:
        flash(f"OpenVPN 配置生成失败：{exc}", "error")
        return redirect(url_for("dashboard_config"))

    filename = f"openvpn-{safe_name(user['username'])}.ovpn"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    return Response(
        config_text,
        headers=headers,
        mimetype="application/x-openvpn-profile; charset=utf-8",
    )


@app.route("/admin/download/openvpn")
@login_required
@admin_required
def admin_download_openvpn_config():
    if not OPENVPN_ENABLED or not is_openvpn_open():
        flash("OpenVPN 当前未启用。", "error")
        return redirect(url_for("admin_subscriptions"))

    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账户不存在。", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        admin = ensure_admin_self_vpn_ready(db, admin)
        db.commit()
        target_server = choose_runtime_server_for_admin(db, admin)
        if not server_supports_openvpn(target_server):
            flash("当前节点未启用 OpenVPN。", "error")
            return redirect(url_for("admin_subscriptions"))
        config_text = build_openvpn_client_config(
            admin["username"],
            user=admin,
            server_row=target_server,
        )
    except Exception as exc:
        flash(f"管理员 OpenVPN 配置生成失败：{exc}", "error")
        return redirect(url_for("admin_subscriptions"))

    filename = f"openvpn-admin-{safe_name(admin['username'])}.ovpn"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    return Response(
        config_text,
        headers=headers,
        mimetype="application/x-openvpn-profile; charset=utf-8",
    )


def render_qr_png(payload: str) -> bytes:
    content = (payload or "").strip()
    if not content:
        raise RuntimeError("二维码内容为空")

    python_qr_error = ""
    if qrcode is not None:
        try:
            qr_obj = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8,
                border=2,
            )
            qr_obj.add_data(content)
            qr_obj.make(fit=True)
            image = qr_obj.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            return buffer.getvalue()
        except Exception as exc:
            python_qr_error = str(exc).strip() or repr(exc)
    else:
        python_qr_error = "python qrcode 模块不可用"

    native_qr_error = ""
    try:
        qr = subprocess.run(
            ["qrencode", "-o", "-", "-t", "PNG"],
            input=content.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        if qr.returncode == 0 and qr.stdout:
            return qr.stdout
        native_qr_error = (
            (qr.stderr or b"").decode("utf-8", errors="ignore").strip() or "未知错误"
        )
    except FileNotFoundError:
        native_qr_error = "系统未安装 qrencode"
    except Exception as exc:
        native_qr_error = str(exc).strip() or repr(exc)

    details = []
    if python_qr_error:
        details.append(f"Python二维码引擎失败：{python_qr_error}")
    if native_qr_error:
        details.append(f"qrencode 回退失败：{native_qr_error}")
    raise RuntimeError("；".join(details) if details else "未知错误")


@app.route("/admin/download/qr")
@login_required
@admin_required
def admin_download_qr():
    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账号不存在。", "error")
        return redirect(url_for("admin_subscriptions"))
    if not server_supports_ss_kcptun(choose_runtime_server_for_admin(db, admin)):
        flash("当前节点未启用 Shadowsocks + kcptun。", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        config_text = build_user_shadowsocks_uri(admin)
    except Exception as exc:
        flash(f"管理员二维码生成失败：{exc}", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        qr_png = render_qr_png(config_text)
    except Exception as exc:
        msg = str(exc).strip() or "未知错误"
        flash(f"管理员二维码生成失败：{msg}", "error")
        return redirect(url_for("admin_subscriptions"))

    filename = f"ss-admin-{safe_name(admin['username'])}.png"
    headers = {"Content-Disposition": f'inline; filename=\"{filename}\"'}
    return Response(qr_png, headers=headers, mimetype="image/png")



@app.route("/download/qr")
@login_required
def download_qr():
    user = current_user()
    if user["role"] != "user":
        flash("管理员无需下载客户端配置。", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not is_subscription_active(user):
        flash("订阅未生效或已过期，请先续费。", "error")
        return redirect(url_for("dashboard"))
    if not server_supports_ss_kcptun(get_persisted_runtime_server_for_account(db, user)):
        flash("当前节点未启用 Shadowsocks + kcptun。", "error")
        return redirect(url_for("dashboard_config"))

    try:
        config_text = build_user_shadowsocks_uri(user)
    except Exception as exc:
        flash(f"二维码生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    try:
        qr_png = render_qr_png(config_text)
    except Exception as exc:
        msg = str(exc).strip() or "未知错误"
        flash(f"二维码生成失败：{msg}", "error")
        return redirect(url_for("dashboard_home"))

    filename = f"ss-{safe_name(user['username'])}.png"
    headers = {"Content-Disposition": f'inline; filename=\"{filename}\"'}
    return Response(qr_png, headers=headers, mimetype="image/png")


@app.route("/subscription/payment-qr")
@login_required
def subscription_payment_qr():
    return {"ok": False, "error": "payment_disabled"}, 404

    user = current_user()
    if not user or user["role"] != "user":
        return {"ok": False, "error": "仅普通用户可获取支付二维码"}, 403

    payment_settings = load_payment_settings(get_db())
    address = (payment_settings.get("usdt_receive_address") or "").strip()
    if not address:
        return {"ok": False, "error": "未配置 USDT 收款地址"}, 404

    try:
        qr_png = render_qr_png(address)
    except Exception as exc:
        msg = str(exc).strip() or "未知错误"
        return {"ok": False, "error": f"生成支付二维码失败：{msg}"}, 500

    return Response(qr_png, mimetype="image/png")



def bootstrap() -> None:
    ensure_directories()
    acquire_db_init_lock()
    try:
        with app.app_context():
            init_db()
            db = get_db()
            ensure_admin_user()
    finally:
        release_db_init_lock()


bootstrap()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
