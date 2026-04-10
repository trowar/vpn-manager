import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import textwrap
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

import paramiko
from flask import (
    Flask,
    Response,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PORTAL_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.environ.get("PORTAL_DB_PATH", DATA_DIR / "portal.db"))
CLIENT_CONF_DIR = Path(
    os.environ.get("PORTAL_CLIENT_CONF_DIR", DATA_DIR / "client-configs")
)
CLIENT_QR_DIR = Path(os.environ.get("PORTAL_CLIENT_QR_DIR", DATA_DIR / "client-qr"))

WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_NETWORK = os.environ.get("WG_NETWORK", "10.7.0.0/24")
WG_SERVER_ADDRESS = os.environ.get("WG_SERVER_ADDRESS", "10.7.0.1")
WG_SERVER_PUBLIC_KEY_FILE = Path(
    os.environ.get("WG_SERVER_PUBLIC_KEY_FILE", "/etc/wireguard/server_public.key")
)
WG_ENDPOINT = os.environ.get("WG_ENDPOINT", "193.134.209.54:51820")
WG_CLIENT_DNS = os.environ.get("WG_CLIENT_DNS", WG_SERVER_ADDRESS)
WG_CLIENT_ALLOWED_IPS = os.environ.get("WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0")
WG_CLIENT_KEEPALIVE = os.environ.get("WG_CLIENT_KEEPALIVE", "25")
WG_IP_ASSIGNMENT_MODE = os.environ.get("WG_IP_ASSIGNMENT_MODE", "static").strip().lower()
WG_ROUTE_POLICY = os.environ.get("WG_ROUTE_POLICY", "full").strip().lower()
WG_NON_CN_ROUTES_FILE = Path(
    os.environ.get("WG_NON_CN_ROUTES_FILE", DATA_DIR / "non_cn_ipv4_routes.txt")
)
WIREGUARD_DOWNLOAD_FALLBACK = "https://www.wireguard.com/install/"
WIREGUARD_DOWNLOAD_LINKS = {
    "windows": "https://download.wireguard.com/windows-client/wireguard-installer.exe",
    "macos": "https://apps.apple.com/app/wireguard/id1451685025?mt=12",
    "android": "https://play.google.com/store/apps/details?id=com.wireguard.android",
    "ios": "https://apps.apple.com/app/wireguard/id1451685025",
    "linux": "https://www.wireguard.com/install/",
    "android_apk": "https://download.wireguard.com/android-client/",
    "official": "https://www.wireguard.com/install/",
}
OPENVPN_ENABLED = os.environ.get("OPENVPN_ENABLED", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
OPENVPN_ENDPOINT_HOST = os.environ.get("OPENVPN_ENDPOINT_HOST", "").strip()
OPENVPN_ENDPOINT_PORT_RAW = os.environ.get("OPENVPN_ENDPOINT_PORT", "1194").strip()
try:
    OPENVPN_ENDPOINT_PORT = int(OPENVPN_ENDPOINT_PORT_RAW)
except ValueError:
    OPENVPN_ENDPOINT_PORT = 1194
if OPENVPN_ENDPOINT_PORT <= 0 or OPENVPN_ENDPOINT_PORT > 65535:
    OPENVPN_ENDPOINT_PORT = 1194
OPENVPN_PROTO = os.environ.get("OPENVPN_PROTO", "udp").strip().lower() or "udp"
OPENVPN_CLIENT_DNS = os.environ.get("OPENVPN_CLIENT_DNS", WG_CLIENT_DNS).strip()
OPENVPN_CIPHER = os.environ.get("OPENVPN_CIPHER", "AES-256-GCM").strip() or "AES-256-GCM"
OPENVPN_AUTH = os.environ.get("OPENVPN_AUTH", "SHA256").strip() or "SHA256"
OPENVPN_CA_CERT_FILE = Path(
    os.environ.get("OPENVPN_CA_CERT_FILE", "/etc/openvpn/server/ca.crt")
)
OPENVPN_TLS_CRYPT_KEY_FILE = Path(
    os.environ.get("OPENVPN_TLS_CRYPT_KEY_FILE", "/etc/openvpn/server/tls-crypt.key")
)
OPENVPN_DOWNLOAD_FALLBACK = "https://openvpn.net/client/"
OPENVPN_DOWNLOAD_LINKS = {
    "windows": "https://openvpn.net/client/client-connect-vpn-for-windows/",
    "macos": "https://openvpn.net/client/client-connect-vpn-for-mac-os/",
    "android": "https://play.google.com/store/apps/details?id=net.openvpn.openvpn",
    "ios": "https://apps.apple.com/app/openvpn-connect-openvpn-app/id590379981",
    "linux": "https://openvpn.net/client/",
    "official": "https://openvpn.net/client/",
}
VPN_API_URL = os.environ.get("VPN_API_URL", "").strip().rstrip("/")
VPN_API_TOKEN = os.environ.get("VPN_API_TOKEN", "").strip()
VPN_API_TIMEOUT_RAW = os.environ.get("VPN_API_TIMEOUT_SECONDS", "8").strip()
try:
    VPN_API_TIMEOUT_SECONDS = max(1, int(VPN_API_TIMEOUT_RAW))
except ValueError:
    VPN_API_TIMEOUT_SECONDS = 8

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
USDT_NETWORK_OPTIONS = ("TRC20", "ERC20", "BEP20", "POLYGON")
USDT_DEFAULT_NETWORK = os.environ.get("USDT_DEFAULT_NETWORK", "TRC20").upper()
USDT_RECEIVE_ADDRESS = os.environ.get("USDT_RECEIVE_ADDRESS", "").strip()
USDT_PRICE_1M = os.environ.get("USDT_PRICE_1M", "10")
USDT_PRICE_3M = os.environ.get("USDT_PRICE_3M", "27")
USDT_PRICE_6M = os.environ.get("USDT_PRICE_6M", "50")
USDT_PRICE_12M = os.environ.get("USDT_PRICE_12M", "90")
PAYMENT_WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "").strip()
PAYMENT_MIN_CONFIRMATIONS_RAW = os.environ.get("PAYMENT_MIN_CONFIRMATIONS", "1").strip()
try:
    PAYMENT_MIN_CONFIRMATIONS = max(0, int(PAYMENT_MIN_CONFIRMATIONS_RAW))
except ValueError:
    PAYMENT_MIN_CONFIRMATIONS = 1
if USDT_DEFAULT_NETWORK not in USDT_NETWORK_OPTIONS:
    USDT_DEFAULT_NETWORK = "TRC20"

PAYMENT_SETTING_KEYS = (
    "usdt_receive_address",
    "usdt_default_network",
)
PLAN_MODE_DURATION = "duration"
PLAN_MODE_TRAFFIC = "traffic"
PLAN_MODES = (PLAN_MODE_DURATION, PLAN_MODE_TRAFFIC)
WG_PROFILE_SMART = "smart"
WG_PROFILE_GLOBAL = "global"
WG_PROFILE_MODES = (WG_PROFILE_SMART, WG_PROFILE_GLOBAL)
PAYMENT_METHOD_USDT = "usdt"
PAYMENT_METHOD_CHOICES = (PAYMENT_METHOD_USDT,)
BYTES_PER_GB = 1024 * 1024 * 1024
REGISTER_COOLDOWN_SECONDS = 5 * 60
ADMIN_UI_TZ = timezone(timedelta(hours=8))
ADMIN_UI_TZ_NAME = "北京时间 (UTC+8)"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_INITIAL_PASSWORD = "admin"
ONBOARDING_SETTING_PORTAL_DOMAIN = "portal_domain"
ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT = "cloudflare_account"
ONBOARDING_SETTING_CLOUDFLARE_PASSWORD = "cloudflare_password"
ONBOARDING_SETTING_SETUP_COMPLETED = "setup_completed"
ONBOARDING_SETTING_SETUP_COMPLETED_AT = "setup_completed_at"
ONBOARDING_SETTING_LAST_SERVER_ID = "setup_last_server_id"
ONBOARDING_SETTING_DRAFT_SERVER_NAME = "setup_draft_server_name"
ONBOARDING_SETTING_DRAFT_SERVER_HOST = "setup_draft_server_host"
ONBOARDING_SETTING_DRAFT_SERVER_PORT = "setup_draft_server_port"
ONBOARDING_SETTING_DRAFT_SERVER_USERNAME = "setup_draft_server_username"
ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD = "setup_draft_server_password"
ONBOARDING_SETTINGS_DEFAULTS = {
    ONBOARDING_SETTING_PORTAL_DOMAIN: "",
    ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT: "",
    ONBOARDING_SETTING_CLOUDFLARE_PASSWORD: "",
    ONBOARDING_SETTING_SETUP_COMPLETED: "0",
    ONBOARDING_SETTING_SETUP_COMPLETED_AT: "",
    ONBOARDING_SETTING_LAST_SERVER_ID: "",
    ONBOARDING_SETTING_DRAFT_SERVER_NAME: "",
    ONBOARDING_SETTING_DRAFT_SERVER_HOST: "",
    ONBOARDING_SETTING_DRAFT_SERVER_PORT: "22",
    ONBOARDING_SETTING_DRAFT_SERVER_USERNAME: "root",
    ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD: "",
}
SERVER_DEPLOY_DEFAULT_WG_PORT = 51820
SERVER_DEPLOY_DEFAULT_OPENVPN_PORT = 1194
SERVER_DEPLOY_DEFAULT_DNS_PORT = 53
SERVER_DEPLOY_DEFAULT_VPN_API_PORT = 8081

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET_KEY", "change-this-secret")
_CLIENT_ALLOWED_IPS_CACHE: str | None = None
_SMART_ALLOWED_IPS_CACHE: str | None = None
_OPENVPN_ROUTE_LINES_CACHE: list[str] | None = None
_OPENVPN_ROUTE_LINES_PROFILE_CACHE: dict[str, list[str]] = {}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def add_months(dt: datetime, months: int) -> datetime:
    total_month = dt.month - 1 + months
    year = dt.year + total_month // 12
    month = total_month % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def format_utc(value: str | None) -> str:
    dt = parse_iso(value)
    if not dt:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_admin_local_input(value: str | None) -> str:
    dt = parse_iso(value)
    if not dt:
        return ""
    return dt.astimezone(ADMIN_UI_TZ).strftime("%Y-%m-%dT%H:%M")


def parse_admin_local_datetime(raw: str) -> datetime:
    value = (raw or "").strip()
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ADMIN_UI_TZ)
    return dt.astimezone(timezone.utc).replace(second=0, microsecond=0)


@app.template_filter("fmt_utc")
def fmt_utc_filter(value: str | None) -> str:
    return format_utc(value)


@app.template_filter("fmt_local_input")
def fmt_local_input_filter(value: str | None) -> str:
    return format_admin_local_input(value)


def parse_usdt_amount(raw: str, fallback: str) -> Decimal:
    value = (raw or "").strip() or fallback
    try:
        amount = Decimal(value)
        if amount <= 0:
            raise InvalidOperation("amount must be positive")
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return Decimal(fallback).quantize(Decimal("0.01"))


def parse_usdt_amount_strict(raw: str) -> Decimal:
    amount = Decimal((raw or "").strip())
    if amount <= 0:
        raise InvalidOperation("amount must be positive")
    return amount.quantize(Decimal("0.01"))


def default_payment_settings() -> dict[str, str]:
    return {
        "usdt_receive_address": USDT_RECEIVE_ADDRESS,
        "usdt_default_network": USDT_DEFAULT_NETWORK,
    }


def normalize_plan_mode(mode: str | None) -> str:
    raw_mode = (mode or "").strip().lower()
    if raw_mode in PLAN_MODES:
        return raw_mode
    if raw_mode in {"time", "month", "months"}:
        return PLAN_MODE_DURATION
    if raw_mode in {"traffic_gb", "gb", "flow", "data"}:
        return PLAN_MODE_TRAFFIC
    return PLAN_MODE_DURATION


def plan_mode_label(mode: str | None) -> str:
    normalized = normalize_plan_mode(mode)
    if normalized == PLAN_MODE_TRAFFIC:
        return "按流量收费"
    return "按时长收费"


def parse_positive_int(raw: str | None) -> int:
    value = int((raw or "").strip())
    if value <= 0:
        raise ValueError("must be positive")
    return value


def to_non_negative_int(raw) -> int:
    try:
        value = int(raw or 0)
    except Exception:
        value = 0
    return value if value >= 0 else 0


def row_get(row, key: str, default=None):
    try:
        return row[key]
    except Exception:
        return default


def format_plan_value(mode: str | None, duration_months: int, traffic_gb: int) -> str:
    normalized = normalize_plan_mode(mode)
    if normalized == PLAN_MODE_TRAFFIC:
        if traffic_gb <= 0:
            return "流量未设置"
        return f"{traffic_gb} GB"
    if duration_months <= 0:
        return "时长未设置"
    return f"{duration_months} 个月"


def format_plan_display_name(
    plan_name: str | None,
    mode: str | None,
    duration_months: int,
    traffic_gb: int,
) -> str:
    name = (plan_name or "").strip()
    mode_prefix = "时长" if normalize_plan_mode(mode) == PLAN_MODE_DURATION else "流量"
    value_text = format_plan_value(mode, duration_months, traffic_gb)
    if name:
        return f"{name}（{mode_prefix} {value_text}）"
    return f"{mode_prefix} {value_text}"


def format_order_plan(order: sqlite3.Row | dict) -> str:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    return format_plan_display_name(plan_name, plan_mode, duration_months, traffic_gb)


def resolve_order_plan_snapshot(order: sqlite3.Row | dict) -> dict:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    if not plan_name:
        plan_name = "流量套餐" if plan_mode == PLAN_MODE_TRAFFIC else "时长套餐"

    return {
        "plan_name": plan_name,
        "plan_mode": plan_mode,
        "duration_months": duration_months,
        "traffic_gb": traffic_gb,
        "display_name": format_plan_display_name(
            plan_name, plan_mode, duration_months, traffic_gb
        ),
    }


@app.template_filter("fmt_order_plan")
def fmt_order_plan_filter(order: sqlite3.Row | dict) -> str:
    return format_order_plan(order)


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


def load_allowed_ips_from_file(path: Path) -> list[str]:
    if not path.exists():
        return []

    routes: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        routes.append(str(network))
    return routes


def get_client_allowed_ips() -> str:
    global _CLIENT_ALLOWED_IPS_CACHE
    if _CLIENT_ALLOWED_IPS_CACHE is not None:
        return _CLIENT_ALLOWED_IPS_CACHE

    # Force global mode to avoid huge split-route configs causing client freeze.
    _CLIENT_ALLOWED_IPS_CACHE = "0.0.0.0/0, ::/0"
    return _CLIENT_ALLOWED_IPS_CACHE


def normalize_wg_profile_mode(raw_mode: str | None) -> str:
    # Smart split profile has been retired due to oversized config issues.
    _ = (raw_mode or "").strip().lower()
    return WG_PROFILE_GLOBAL


def get_smart_allowed_ips() -> str:
    global _SMART_ALLOWED_IPS_CACHE
    if _SMART_ALLOWED_IPS_CACHE is not None:
        return _SMART_ALLOWED_IPS_CACHE

    routes = load_allowed_ips_from_file(WG_NON_CN_ROUTES_FILE)
    if not routes:
        _SMART_ALLOWED_IPS_CACHE = ""
        return _SMART_ALLOWED_IPS_CACHE

    _SMART_ALLOWED_IPS_CACHE = ", ".join(routes)
    return _SMART_ALLOWED_IPS_CACHE


def get_client_allowed_ips_for_profile(profile_mode: str) -> str:
    _ = normalize_wg_profile_mode(profile_mode)
    return "0.0.0.0/0, ::/0"


def default_profile_mode_from_policy() -> str:
    return WG_PROFILE_GLOBAL


def wireguard_profile_filename_suffix(profile_mode: str) -> str:
    mode = normalize_wg_profile_mode(profile_mode)
    return "global" if mode == WG_PROFILE_GLOBAL else "global"


def detect_client_platform(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "android" in ua:
        return "android"
    if any(token in ua for token in ("iphone", "ipad", "ipod", "ios")):
        return "ios"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "windows" in ua:
        return "windows"
    if "linux" in ua:
        return "linux"
    return "official"


def detect_wireguard_platform(user_agent: str) -> str:
    return detect_client_platform(user_agent)


def detect_openvpn_platform(user_agent: str) -> str:
    return detect_client_platform(user_agent)


def get_openvpn_endpoint_host() -> str:
    portal_domain = get_portal_domain_setting()
    if portal_domain:
        if portal_domain.startswith("["):
            idx = portal_domain.find("]")
            if idx > 1:
                return portal_domain[1:idx]
        if portal_domain.count(":") == 1:
            host_part, port_part = portal_domain.rsplit(":", 1)
            if host_part and port_part.isdigit():
                return host_part
        return portal_domain

    if OPENVPN_ENDPOINT_HOST:
        return OPENVPN_ENDPOINT_HOST

    wg_endpoint = (get_wireguard_endpoint_for_clients() or "").strip()
    if not wg_endpoint:
        return "127.0.0.1"
    if wg_endpoint.startswith("["):
        idx = wg_endpoint.find("]")
        if idx > 1:
            return wg_endpoint[1:idx]
    if wg_endpoint.count(":") == 1:
        return wg_endpoint.rsplit(":", 1)[0]
    return wg_endpoint


def get_openvpn_route_lines() -> list[str]:
    global _OPENVPN_ROUTE_LINES_CACHE
    if _OPENVPN_ROUTE_LINES_CACHE is not None:
        return _OPENVPN_ROUTE_LINES_CACHE

    _OPENVPN_ROUTE_LINES_CACHE = get_openvpn_route_lines_for_profile(
        default_profile_mode_from_policy()
    )
    return _OPENVPN_ROUTE_LINES_CACHE


def get_openvpn_route_lines_for_profile(profile_mode: str) -> list[str]:
    mode = normalize_wg_profile_mode(profile_mode)
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


def get_openvpn_client_materials() -> tuple[str, str]:
    if use_vpn_api():
        result = vpn_api_request("GET", "/openvpn/client-materials")
        ca_text = (result.get("ca_cert") or "").strip()
        tls_crypt_text = (result.get("tls_crypt_key") or "").strip()
        if not ca_text:
            raise RuntimeError("VPN API 未返回 OpenVPN CA 证书。")
        return ca_text, tls_crypt_text

    ca_text = read_required_text(OPENVPN_CA_CERT_FILE, "OpenVPN CA 证书")
    tls_crypt_text = ""
    if OPENVPN_TLS_CRYPT_KEY_FILE.exists():
        tls_crypt_text = OPENVPN_TLS_CRYPT_KEY_FILE.read_text(encoding="utf-8").strip()
    return ca_text, tls_crypt_text


def build_openvpn_client_config(
    username: str,
    *,
    profile_mode: str | None = None,
) -> str:
    if not OPENVPN_ENABLED:
        raise RuntimeError("管理员尚未启用 OpenVPN 支持。")

    ca_text, tls_crypt_text = get_openvpn_client_materials()

    remote_host = get_openvpn_endpoint_host()
    lines = [
        "client",
        "dev tun",
        f"proto {OPENVPN_PROTO}",
        f"remote {remote_host} {OPENVPN_ENDPOINT_PORT}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "auth-user-pass",
        "auth-nocache",
        "remote-cert-tls server",
        f"cipher {OPENVPN_CIPHER}",
        f"auth {OPENVPN_AUTH}",
        "verb 3",
        f"setenv PORTAL_USER {safe_name(username)}",
    ]
    if OPENVPN_PROTO == "udp":
        lines.append("explicit-exit-notify 1")
    if OPENVPN_CLIENT_DNS:
        lines.append(f"dhcp-option DNS {OPENVPN_CLIENT_DNS}")
    mode = normalize_wg_profile_mode(profile_mode or default_profile_mode_from_policy())
    lines.extend(get_openvpn_route_lines_for_profile(mode))

    lines.append("<ca>")
    lines.append(ca_text)
    lines.append("</ca>")
    if tls_crypt_text:
        lines.append("<tls-crypt>")
        lines.append(tls_crypt_text)
        lines.append("</tls-crypt>")

    return "\n".join(lines) + "\n"


def get_registration_cooldown_seconds(
    db: sqlite3.Connection, ip_address: str
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
    db: sqlite3.Connection, ip_address: str, at_iso: str
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


def format_usdt(value: str | Decimal | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, str):
        try:
            amount = Decimal(value)
        except (InvalidOperation, ValueError):
            return value
    else:
        amount = value
    amount = amount.quantize(Decimal("0.01"))
    return f"{amount:.2f}"


@app.template_filter("fmt_usdt")
def fmt_usdt_filter(value: str | Decimal | None) -> str:
    return format_usdt(value)


def upsert_app_setting(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute(
        """
        INSERT INTO app_settings (setting_key, setting_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET
            setting_value = excluded.setting_value,
            updated_at = excluded.updated_at
        """,
        (key, value, utcnow_iso()),
    )


def get_app_setting(db: sqlite3.Connection, key: str, default: str = "") -> str:
    row = db.execute(
        """
        SELECT setting_value
        FROM app_settings
        WHERE setting_key = ?
        LIMIT 1
        """,
        (key,),
    ).fetchone()
    if not row:
        return default
    return (row["setting_value"] or "").strip() or default


def load_named_settings(db: sqlite3.Connection, keys: tuple[str, ...]) -> dict[str, str]:
    if not keys:
        return {}
    rows = db.execute(
        """
        SELECT setting_key, setting_value
        FROM app_settings
        WHERE setting_key IN ({})
        """.format(",".join("?" for _ in keys)),
        keys,
    ).fetchall()
    values = {key: "" for key in keys}
    for row in rows:
        values[row["setting_key"]] = (row["setting_value"] or "").strip()
    return values


def parse_bool_setting(raw: str | None, default: bool = False) -> bool:
    value = (raw or "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def ensure_default_onboarding_settings(db: sqlite3.Connection) -> None:
    existing = load_named_settings(db, tuple(ONBOARDING_SETTINGS_DEFAULTS.keys()))
    for key, default_value in ONBOARDING_SETTINGS_DEFAULTS.items():
        if key not in existing or existing.get(key, "") == "":
            if key == ONBOARDING_SETTING_SETUP_COMPLETED:
                # keep explicit boolean semantics
                upsert_app_setting(db, key, existing.get(key, default_value) or default_value)
            else:
                upsert_app_setting(db, key, existing.get(key, default_value) or default_value)


def load_onboarding_settings(db: sqlite3.Connection) -> dict[str, str | bool]:
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


def load_onboarding_server_draft(db: sqlite3.Connection) -> dict[str, str | int]:
    values = load_named_settings(
        db,
        (
            ONBOARDING_SETTING_DRAFT_SERVER_NAME,
            ONBOARDING_SETTING_DRAFT_SERVER_HOST,
            ONBOARDING_SETTING_DRAFT_SERVER_PORT,
            ONBOARDING_SETTING_DRAFT_SERVER_USERNAME,
            ONBOARDING_SETTING_DRAFT_SERVER_PASSWORD,
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
    }


def save_onboarding_server_draft(
    db: sqlite3.Connection,
    *,
    server_name: str,
    server_host: str,
    server_port: int,
    server_username: str,
    server_password: str,
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


def get_admin_onboarding_step_status(db: sqlite3.Connection) -> tuple[dict[int, bool], int]:
    settings = load_onboarding_settings(db)
    payment_settings = load_payment_settings(db)
    plan_count = db.execute("SELECT COUNT(*) AS cnt FROM subscription_plans").fetchone()["cnt"]

    step_status = {
        1: int(plan_count or 0) > 0,
        2: bool((payment_settings["usdt_receive_address"] or "").strip())
        and bool((settings["portal_domain"] or "").strip()),
        3: bool((settings["cloudflare_account"] or "").strip())
        and bool((settings["cloudflare_password"] or "").strip()),
        4: bool(settings["setup_completed"]),
    }

    default_step = 4
    for step in (1, 2, 3, 4):
        if not step_status[step]:
            default_step = step
            break
    return step_status, default_step


def next_admin_onboarding_step(db: sqlite3.Connection, fallback: int = 4) -> int:
    _, next_step = get_admin_onboarding_step_status(db)
    if next_step < 1 or next_step > 4:
        return fallback
    return next_step


def is_admin_onboarding_completed(db: sqlite3.Connection) -> bool:
    raw_value = get_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED, "0")
    return parse_bool_setting(raw_value, False)


def parse_wg_endpoint_port() -> str:
    raw = (WG_ENDPOINT or "").strip()
    if not raw:
        return str(SERVER_DEPLOY_DEFAULT_WG_PORT)
    if raw.startswith("["):
        idx = raw.find("]")
        if idx > 0 and len(raw) > idx + 2 and raw[idx + 1] == ":":
            tail = raw[idx + 2 :]
            if tail.isdigit():
                return tail
    if raw.count(":") == 1:
        _, port = raw.rsplit(":", 1)
        if port.isdigit():
            return port
    return str(SERVER_DEPLOY_DEFAULT_WG_PORT)


def normalize_domain_host(raw_domain: str | None) -> str:
    value = (raw_domain or "").strip()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/", 1)[0].strip()
    return value


def get_portal_domain_setting() -> str:
    try:
        db = get_db()
    except Exception:
        return ""
    return normalize_domain_host(
        get_app_setting(db, ONBOARDING_SETTING_PORTAL_DOMAIN, "")
    )


def get_wireguard_endpoint_for_clients() -> str:
    portal_domain = get_portal_domain_setting()
    if not portal_domain:
        return WG_ENDPOINT

    if portal_domain.startswith("[") and "]" in portal_domain:
        # IPv6 with optional port
        idx = portal_domain.find("]")
        if idx > 0 and len(portal_domain) > idx + 2 and portal_domain[idx + 1] == ":":
            return portal_domain
        return f"{portal_domain}:{parse_wg_endpoint_port()}"

    if portal_domain.count(":") == 1:
        host_part, port_part = portal_domain.rsplit(":", 1)
        if host_part and port_part.isdigit():
            return portal_domain

    return f"{portal_domain}:{parse_wg_endpoint_port()}"


def ensure_default_payment_settings(db: sqlite3.Connection) -> None:
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


def load_legacy_payment_settings(db: sqlite3.Connection) -> dict:
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


def load_payment_methods(db: sqlite3.Connection, *, active_only: bool = False) -> list[dict]:
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


def resolve_default_payment_method(db: sqlite3.Connection) -> dict | None:
    active_methods = load_payment_methods(db, active_only=True)
    if active_methods:
        return active_methods[0]
    total_count = db.execute("SELECT COUNT(*) AS cnt FROM payment_methods").fetchone()["cnt"]
    if total_count > 0:
        return None
    return None


def sync_legacy_payment_settings_with_default_method(db: sqlite3.Connection) -> None:
    default_method = resolve_default_payment_method(db)
    if not default_method:
        return
    upsert_app_setting(db, "usdt_receive_address", default_method["receive_address"])
    upsert_app_setting(db, "usdt_default_network", default_method["network"])


def ensure_default_payment_methods(db: sqlite3.Connection) -> None:
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


def load_payment_settings(db: sqlite3.Connection) -> dict:
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


def ensure_default_subscription_plans(db: sqlite3.Connection) -> None:
    count = db.execute("SELECT COUNT(*) AS cnt FROM subscription_plans").fetchone()["cnt"]
    if count > 0:
        return

    default_rows = [
        ("月付 1个月", PLAN_MODE_DURATION, 1, None, format_usdt(parse_usdt_amount(USDT_PRICE_1M, "10")), 10),
        ("季付 3个月", PLAN_MODE_DURATION, 3, None, format_usdt(parse_usdt_amount(USDT_PRICE_3M, "27")), 20),
        ("半年 6个月", PLAN_MODE_DURATION, 6, None, format_usdt(parse_usdt_amount(USDT_PRICE_6M, "50")), 30),
        ("年付 12个月", PLAN_MODE_DURATION, 12, None, format_usdt(parse_usdt_amount(USDT_PRICE_12M, "90")), 40),
        ("流量包 100GB", PLAN_MODE_TRAFFIC, None, 100, format_usdt(parse_usdt_amount(USDT_PRICE_1M, "10")), 50),
    ]
    now_iso = utcnow_iso()
    for name, mode, duration, traffic, price, sort_order in default_rows:
        db.execute(
            """
            INSERT INTO subscription_plans (
                plan_name, billing_mode, duration_months, traffic_gb,
                price_usdt, is_active, sort_order, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (name, mode, duration, traffic, price, sort_order, now_iso, now_iso),
        )


def load_subscription_plans(db: sqlite3.Connection, *, active_only: bool = False) -> list[dict]:
    sql = """
        SELECT
            id,
            plan_name,
            billing_mode,
            duration_months,
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
        traffic_gb = to_non_negative_int(row["traffic_gb"])
        if mode == PLAN_MODE_TRAFFIC:
            duration_months = 0
        else:
            traffic_gb = 0

        plan = {
            "id": row["id"],
            "plan_name": (row["plan_name"] or "").strip(),
            "billing_mode": mode,
            "mode_label": plan_mode_label(mode),
            "duration_months": duration_months,
            "traffic_gb": traffic_gb,
            "value_label": format_plan_value(mode, duration_months, traffic_gb),
            "price_usdt": format_usdt(row["price_usdt"]),
            "is_active": 1 if int(row["is_active"] or 0) == 1 else 0,
            "sort_order": to_non_negative_int(row["sort_order"]),
            "display_name": format_plan_display_name(
                row["plan_name"], mode, duration_months, traffic_gb
            ),
        }
        plans.append(plan)
    return plans


def usdt_explorer_link(network: str, tx_hash: str) -> str:
    if not tx_hash:
        return ""
    mapping = {
        "TRC20": "https://tronscan.org/#/transaction/{tx}",
        "ERC20": "https://etherscan.io/tx/{tx}",
        "BEP20": "https://bscscan.com/tx/{tx}",
        "POLYGON": "https://polygonscan.com/tx/{tx}",
    }
    tpl = mapping.get((network or "").upper(), mapping["TRC20"])
    return tpl.format(tx=tx_hash)


def normalize_server_port(raw: str | int | None, default: int = 22) -> int:
    try:
        port = int(raw or default)
    except Exception:
        port = default
    if port <= 0 or port > 65535:
        return default
    return port


def normalize_remote_host(raw: str | None) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/", 1)[0].strip()
    return value


def mask_secret(raw: str, visible: int = 2) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * max(0, len(value) - visible) + value[-visible:]


def summarize_text(raw: str, limit: int = 600) -> str:
    text = (raw or "").strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def load_admin_servers(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        """
        SELECT
            id,
            server_name,
            host,
            port,
            username,
            password,
            domain,
            vpn_api_token,
            wg_port,
            openvpn_port,
            dns_port,
            status,
            last_test_at,
            last_test_ok,
            last_test_message,
            last_deploy_at,
            last_deploy_ok,
            last_deploy_message,
            created_at,
            updated_at
        FROM vpn_servers
        ORDER BY id DESC
        """
    ).fetchall()

    servers: list[dict] = []
    for row in rows:
        status = (row["status"] or "").strip() or "pending"
        servers.append(
            {
                "id": row["id"],
                "server_name": (row["server_name"] or "").strip() or (row["host"] or "").strip(),
                "host": (row["host"] or "").strip(),
                "port": normalize_server_port(row["port"], 22),
                "username": (row["username"] or "").strip(),
                "password_masked": mask_secret(row["password"] or ""),
                "domain": (row["domain"] or "").strip(),
                "vpn_api_token_masked": mask_secret(row["vpn_api_token"] or "", visible=4),
                "wg_port": normalize_server_port(row["wg_port"], SERVER_DEPLOY_DEFAULT_WG_PORT),
                "openvpn_port": normalize_server_port(
                    row["openvpn_port"], SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
                ),
                "dns_port": normalize_server_port(row["dns_port"], SERVER_DEPLOY_DEFAULT_DNS_PORT),
                "status": status,
                "last_test_at": row["last_test_at"],
                "last_test_ok": int(row["last_test_ok"] or 0) == 1,
                "last_test_message": summarize_text(row["last_test_message"] or "", 220),
                "last_deploy_at": row["last_deploy_at"],
                "last_deploy_ok": int(row["last_deploy_ok"] or 0) == 1,
                "last_deploy_message": summarize_text(row["last_deploy_message"] or "", 280),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return servers


def open_ssh_client(
    host: str, port: int, username: str, password: str, *, timeout: int = 10
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        auth_timeout=timeout,
        banner_timeout=timeout,
    )
    return client


def test_server_connectivity(
    host: str, port: int, username: str, password: str
) -> tuple[bool, str]:
    safe_host = normalize_remote_host(host)
    safe_port = normalize_server_port(port)
    safe_username = (username or "").strip()
    if not safe_host or not safe_username or not password:
        return False, "服务器连接信息不完整。"

    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(
            safe_host,
            safe_port,
            safe_username,
            password,
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


def build_vpn_node_deploy_script(
    *,
    vpn_api_token: str,
    wg_port: int,
    openvpn_port: int,
    dns_port: int,
) -> str:
    return textwrap.dedent(
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive

        log() {{ echo "[deploy] $1"; }}

        if ! command -v git >/dev/null 2>&1; then
          apt-get update -qq
          apt-get install -y -qq git ca-certificates curl >/dev/null
        fi

        if ! command -v docker >/dev/null 2>&1; then
          apt-get update -qq
          apt-get install -y -qq docker.io >/dev/null
        fi

        if ! docker compose version >/dev/null 2>&1; then
          apt-get update -qq
          apt-get install -y -qq docker-compose-plugin >/dev/null || \
          apt-get install -y -qq docker-compose-v2 >/dev/null || \
          apt-get install -y -qq docker-compose >/dev/null
        fi

        if ! command -v wg >/dev/null 2>&1; then
          apt-get update -qq
          apt-get install -y -qq wireguard-tools >/dev/null
        fi

        systemctl enable --now docker >/dev/null 2>&1 || true

        if [ ! -d /opt/vpn-node/.git ]; then
          rm -rf /opt/vpn-node
          git clone --depth 1 https://github.com/trowar/vpn-manager.git /opt/vpn-node >/dev/null 2>&1
        else
          git -C /opt/vpn-node fetch --depth 1 origin main >/dev/null 2>&1
          git -C /opt/vpn-node checkout -f main >/dev/null 2>&1 || \
          git -C /opt/vpn-node checkout -B main origin/main >/dev/null 2>&1
          git -C /opt/vpn-node reset --hard origin/main >/dev/null 2>&1
        fi

        cd /opt/vpn-node
        mkdir -p docker/vpn/wireguard docker/vpn/openvpn

        if [ ! -f docker/vpn/wireguard/server_private.key ]; then
          wg genkey > docker/vpn/wireguard/server_private.key
          chmod 600 docker/vpn/wireguard/server_private.key
        fi

        if [ ! -f docker/vpn/wireguard/server_public.key ]; then
          wg pubkey < docker/vpn/wireguard/server_private.key > docker/vpn/wireguard/server_public.key
          chmod 600 docker/vpn/wireguard/server_public.key
        fi

        if [ ! -f docker/vpn/wireguard/wg0.conf ]; then
          UPLINK_IF=$(ip -o route show default 2>/dev/null | awk 'NR==1 {{print $5}}')
          if [ -z "$UPLINK_IF" ]; then
            UPLINK_IF=eth0
          fi
          WG_PRIV=$(cat docker/vpn/wireguard/server_private.key)
          cat > docker/vpn/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.7.0.1/24
ListenPort = {wg_port}
PrivateKey = $WG_PRIV
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $UPLINK_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $UPLINK_IF -j MASQUERADE
EOF
          chmod 600 docker/vpn/wireguard/wg0.conf
        fi

        if [ ! -f docker/vpn/openvpn/server.conf ] && [ -f docker/vpn/openvpn/server.conf.example ]; then
          cp docker/vpn/openvpn/server.conf.example docker/vpn/openvpn/server.conf
        fi

        cat > .env <<EOF
VPN_API_TOKEN={vpn_api_token}
WG_INTERFACE=wg0
WG_PUBLIC_PORT={wg_port}
OPENVPN_PUBLIC_PORT={openvpn_port}
DNS_PUBLIC_PORT={dns_port}
VPN_API_PUBLIC_PORT={SERVER_DEPLOY_DEFAULT_VPN_API_PORT}
VPN_ENABLE_WIREGUARD=1
VPN_ENABLE_DNSMASQ=1
VPN_ENABLE_OPENVPN=0
EOF

        docker compose -f docker-compose.vpn-node.yml --env-file .env up -d --build vpnmanager-server >/dev/null
        docker compose -f docker-compose.vpn-node.yml --env-file .env ps
        log "completed"
        """
    ).strip() + "\n"


def deploy_vpn_node_server(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    wg_port: int,
    openvpn_port: int,
    dns_port: int,
    vpn_api_token: str | None = None,
) -> tuple[bool, str, str]:
    safe_token = (vpn_api_token or "").strip()
    if not safe_token:
        safe_token = hashlib.sha256(os.urandom(32)).hexdigest()[:48]

    script = build_vpn_node_deploy_script(
        vpn_api_token=safe_token,
        wg_port=normalize_server_port(wg_port, SERVER_DEPLOY_DEFAULT_WG_PORT),
        openvpn_port=normalize_server_port(
            openvpn_port, SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
        ),
        dns_port=normalize_server_port(dns_port, SERVER_DEPLOY_DEFAULT_DNS_PORT),
    )

    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(
            normalize_remote_host(host),
            normalize_server_port(port, 22),
            (username or "").strip(),
            password,
            timeout=12,
        )
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=2400)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        code = stdout.channel.recv_exit_status()
        merged = summarize_text((out + "\n" + err).strip(), 1200)
        if code == 0:
            return True, f"部署成功。{merged}", safe_token
        return False, f"部署失败（exit={code}）。{merged}", safe_token
    except Exception as exc:
        return False, f"部署异常：{exc}", safe_token
    finally:
        if client:
            client.close()


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_CONF_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_QR_DIR.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'approved',
            assigned_ip TEXT,
            client_private_key TEXT,
            client_public_key TEXT,
            client_psk TEXT,
            config_path TEXT,
            qr_path TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            subscription_expires_at TEXT,
            wg_enabled INTEGER NOT NULL DEFAULT 0,
            traffic_quota_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_last_total_bytes INTEGER NOT NULL DEFAULT 0,
            force_password_change INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_months INTEGER NOT NULL DEFAULT 0,
            plan_id INTEGER,
            plan_name TEXT,
            plan_mode TEXT,
            plan_duration_months INTEGER,
            plan_traffic_gb INTEGER,
            payment_method TEXT NOT NULL DEFAULT 'usdt',
            usdt_network TEXT NOT NULL DEFAULT 'TRC20',
            usdt_amount TEXT NOT NULL DEFAULT '0',
            pay_to_address TEXT,
            tx_hash TEXT,
            tx_submitted_at TEXT,
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
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_name TEXT NOT NULL,
            billing_mode TEXT NOT NULL,
            duration_months INTEGER,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        CREATE TABLE IF NOT EXISTS vpn_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            domain TEXT,
            vpn_api_token TEXT,
            wg_port INTEGER NOT NULL DEFAULT 51820,
            openvpn_port INTEGER NOT NULL DEFAULT 1194,
            dns_port INTEGER NOT NULL DEFAULT 53,
            status TEXT NOT NULL DEFAULT 'pending',
            last_test_at TEXT,
            last_test_ok INTEGER NOT NULL DEFAULT 0,
            last_test_message TEXT,
            last_deploy_at TEXT,
            last_deploy_ok INTEGER NOT NULL DEFAULT 0,
            last_deploy_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    migrate_schema(db)
    ensure_default_payment_settings(db)
    ensure_default_onboarding_settings(db)
    ensure_default_payment_methods(db)
    sync_legacy_payment_settings_with_default_method(db)
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_status_created ON users(status, created_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_users_expire ON users(subscription_expires_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_user_status ON payment_orders(user_id, status)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_status_created ON payment_orders(status, created_at)"
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
    db.commit()


def migrate_schema(db: sqlite3.Connection) -> None:
    user_columns = {
        row["name"]: row
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    if "subscription_expires_at" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TEXT")
    if "wg_enabled" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN wg_enabled INTEGER NOT NULL DEFAULT 0")
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

    order_columns = {
        row["name"]: row
        for row in db.execute("PRAGMA table_info(payment_orders)").fetchall()
    }
    if "plan_id" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_id INTEGER")
    if "plan_name" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_name TEXT")
    if "plan_mode" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_mode TEXT")
    if "plan_duration_months" not in order_columns:
        db.execute("ALTER TABLE payment_orders ADD COLUMN plan_duration_months INTEGER")
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

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_name TEXT NOT NULL,
            billing_mode TEXT NOT NULL,
            duration_months INTEGER,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(payment_methods)").fetchall()
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
        CREATE TABLE IF NOT EXISTS vpn_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            domain TEXT,
            vpn_api_token TEXT,
            wg_port INTEGER NOT NULL DEFAULT 51820,
            openvpn_port INTEGER NOT NULL DEFAULT 1194,
            dns_port INTEGER NOT NULL DEFAULT 53,
            status TEXT NOT NULL DEFAULT 'pending',
            last_test_at TEXT,
            last_test_ok INTEGER NOT NULL DEFAULT 0,
            last_test_message TEXT,
            last_deploy_at TEXT,
            last_deploy_ok INTEGER NOT NULL DEFAULT 0,
            last_deploy_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    vpn_server_columns = {
        row["name"]: row
        for row in db.execute("PRAGMA table_info(vpn_servers)").fetchall()
    }
    if "server_name" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN server_name TEXT NOT NULL DEFAULT ''")
    if "host" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN host TEXT NOT NULL DEFAULT ''")
    if "port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN port INTEGER NOT NULL DEFAULT 22")
    if "username" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN username TEXT NOT NULL DEFAULT 'root'")
    if "password" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN password TEXT NOT NULL DEFAULT ''")
    if "domain" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN domain TEXT")
    if "vpn_api_token" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN vpn_api_token TEXT")
    if "wg_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN wg_port INTEGER NOT NULL DEFAULT 51820")
    if "openvpn_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN openvpn_port INTEGER NOT NULL DEFAULT 1194")
    if "dns_port" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN dns_port INTEGER NOT NULL DEFAULT 53")
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
    if "created_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
    if "updated_at" not in vpn_server_columns:
        db.execute("ALTER TABLE vpn_servers ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")


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
                created_at,
                approved_at,
                force_password_change
            )
            VALUES (?, ?, ?, 'admin', 'approved', ?, ?, 1)
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
    except sqlite3.IntegrityError:
        db.rollback()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


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


def user_api_payload(user) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "subscription_expires_at": user["subscription_expires_at"],
        "wg_enabled": bool(user["wg_enabled"]),
    }


@app.context_processor
def inject_user():
    db = get_db()
    payment_settings = load_payment_settings(db)
    onboarding_settings = load_onboarding_settings(db)
    return {
        "current_user": current_user(),
        "usdt_receive_address": payment_settings["usdt_receive_address"],
        "usdt_default_network": payment_settings["usdt_default_network"],
        "usdt_network_options": USDT_NETWORK_OPTIONS,
        "openvpn_enabled": OPENVPN_ENABLED,
        "admin_setup_completed": onboarding_settings["setup_completed"],
    }


@app.before_request
def auto_reconcile_subscriptions():
    if request.endpoint == "static":
        return None
    try:
        db = get_db()
        reconcile_expired_subscriptions(db)
        user_id = session.get("user_id")
        if user_id:
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user and user["role"] == "user":
                sync_user_traffic_usage(db, user)
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
    endpoint = request.endpoint or ""
    if endpoint == "static":
        return None

    user = current_user()
    if not user or row_get(user, "role") != "admin":
        return None
    if admin_must_change_password(user):
        return None
    if is_admin_onboarding_completed(get_db()):
        return None

    allowed_endpoints = {
        "logout",
        "admin_home",
        "admin_change_password",
        "admin_onboarding",
        "admin_onboarding_step_plan",
        "admin_onboarding_step_payment",
        "admin_onboarding_step_cloudflare",
        "admin_onboarding_step_server",
        "admin_test_server_connection",
        "static",
    }
    if endpoint in allowed_endpoints:
        return None

    if request.path.startswith("/api/"):
        return {
            "ok": False,
            "error": "admin_onboarding_required",
            "redirect": url_for("admin_home", onboarding_open="1"),
        }, 403

    flash("首次登录请先完成初始化向导。", "error")
    return redirect(url_for("admin_home", onboarding_open="1"))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
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



def run_command(args, input_text=None, check=True) -> str:
    completed = subprocess.run(
        args,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 and check:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"命令执行失败：{' '.join(args)}；{stderr}")
    return completed.stdout.strip()


def use_vpn_api() -> bool:
    api_url, _ = get_runtime_vpn_api_target()
    return bool(api_url)


def host_for_http_url(raw_host: str) -> str:
    host = (raw_host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def get_runtime_vpn_api_target() -> tuple[str, str]:
    if VPN_API_URL:
        return VPN_API_URL, VPN_API_TOKEN

    try:
        db = get_db()
    except Exception:
        return "", ""

    try:
        settings = load_onboarding_settings(db)
        preferred_server_id_raw = str(settings.get("last_server_id", "") or "").strip()
    except Exception:
        preferred_server_id_raw = ""

    row = None
    if preferred_server_id_raw.isdigit():
        row = db.execute(
            """
            SELECT host, vpn_api_token, status
            FROM vpn_servers
            WHERE id = ?
            LIMIT 1
            """,
            (int(preferred_server_id_raw),),
        ).fetchone()

    if not row:
        row = db.execute(
            """
            SELECT host, vpn_api_token, status
            FROM vpn_servers
            WHERE status = 'online'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    if not row:
        return "", ""

    status = (row_get(row, "status", "") or "").strip().lower()
    if status != "online":
        return "", ""

    host = normalize_remote_host(row_get(row, "host", ""))
    token = (row_get(row, "vpn_api_token", "") or "").strip()
    if not host or not token:
        return "", ""

    host_url = host_for_http_url(host)
    return f"http://{host_url}:{SERVER_DEPLOY_DEFAULT_VPN_API_PORT}", token


def vpn_api_request(method: str, path: str, payload: dict | None = None) -> dict:
    runtime_api_url, runtime_api_token = get_runtime_vpn_api_target()
    if not runtime_api_url:
        raise RuntimeError("VPN 服务未配置，请先在后台完成服务器部署。")

    url = f"{runtime_api_url}{path}"
    headers = {"Accept": "application/json"}
    if runtime_api_token:
        headers["X-VPN-Token"] = runtime_api_token

    body_bytes = None
    if payload is not None:
        body_bytes = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib_request.Request(url=url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=VPN_API_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except urllib_error.HTTPError as exc:
        detail = ""
        try:
            detail_raw = exc.read().decode("utf-8", errors="ignore")
            detail_obj = json.loads(detail_raw) if detail_raw else {}
            detail = str(detail_obj.get("error") or detail_obj.get("message") or detail_raw).strip()
        except Exception:
            detail = ""
        if not detail:
            detail = f"HTTP {exc.code}"
        raise RuntimeError(f"VPN API 请求失败：{method} {path}；{detail}")
    except urllib_error.URLError as exc:
        raise RuntimeError(f"VPN API 不可达：{exc.reason}")

    try:
        obj = json.loads(raw or "{}")
    except json.JSONDecodeError:
        raise RuntimeError(f"VPN API 返回非法 JSON：{method} {path}")
    if not isinstance(obj, dict):
        raise RuntimeError(f"VPN API 返回格式错误：{method} {path}")
    if obj.get("ok") is False:
        raise RuntimeError(str(obj.get("error") or f"VPN API 错误：{method} {path}"))
    return obj


def get_wireguard_dump_text() -> str:
    if use_vpn_api():
        result = vpn_api_request("GET", "/wireguard/dump")
        return str(result.get("dump") or "")
    return run_command(["wg", "show", WG_INTERFACE, "dump"], check=False)


def get_wireguard_server_public_key() -> str:
    if use_vpn_api():
        result = vpn_api_request("GET", "/wireguard/server-public-key")
        key = (result.get("public_key") or "").strip()
        if not key:
            raise RuntimeError("VPN API 未返回服务端公钥。")
        return key
    if not WG_SERVER_PUBLIC_KEY_FILE.exists():
        raise RuntimeError(f"未找到服务端公钥文件：{WG_SERVER_PUBLIC_KEY_FILE}")
    return WG_SERVER_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()


def wireguard_generate_keys() -> tuple[str, str, str]:
    if use_vpn_api():
        result = vpn_api_request("POST", "/wireguard/generate-keys")
        private_key = (result.get("private_key") or "").strip()
        public_key = (result.get("public_key") or "").strip()
        psk = (result.get("preshared_key") or "").strip()
        if not private_key or not public_key or not psk:
            raise RuntimeError("VPN API 生成密钥失败：返回数据不完整。")
        return private_key, public_key, psk

    private_key = run_command(["wg", "genkey"])
    public_key = run_command(["wg", "pubkey"], input_text=f"{private_key}\n")
    psk = run_command(["wg", "genpsk"])
    return private_key, public_key, psk


def format_bytes(num_bytes: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(max(0, int(num_bytes)))
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return "0 B"


def get_wireguard_transfer_bytes(public_key: str | None) -> tuple[int, int]:
    if not public_key:
        return 0, 0
    dump = get_wireguard_dump_text()
    if not dump:
        return 0, 0

    for line in dump.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        if parts[0].strip() != public_key:
            continue
        try:
            rx = int(parts[5])
        except Exception:
            rx = 0
        try:
            tx = int(parts[6])
        except Exception:
            tx = 0
        return max(0, rx), max(0, tx)
    return 0, 0


def get_user_traffic_stats(user: sqlite3.Row) -> dict[str, int | str]:
    rx_bytes, tx_bytes = get_wireguard_transfer_bytes(user["client_public_key"])
    total_bytes = rx_bytes + tx_bytes
    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    if quota_bytes > 0 and used_bytes > quota_bytes:
        used_bytes = quota_bytes
    remaining_bytes = max(0, quota_bytes - used_bytes)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    remaining_is_permanent = has_time
    if remaining_is_permanent:
        remaining_display = "永久"
    elif quota_bytes > 0:
        remaining_display = format_bytes(remaining_bytes)
    else:
        remaining_display = "-"
    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "total_bytes": total_bytes,
        "rx_human": format_bytes(rx_bytes),
        "tx_human": format_bytes(tx_bytes),
        "total_human": format_bytes(total_bytes),
        "quota_bytes": quota_bytes,
        "used_bytes": used_bytes,
        "remaining_bytes": remaining_bytes,
        "quota_human": format_bytes(quota_bytes),
        "used_human": format_bytes(used_bytes),
        "remaining_human": format_bytes(remaining_bytes),
        "remaining_is_permanent": remaining_is_permanent,
        "remaining_display": remaining_display,
        "has_active_time": has_time,
        "has_active_traffic": has_traffic,
    }



def safe_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw)


def is_dynamic_ip_assignment_mode() -> bool:
    return WG_IP_ASSIGNMENT_MODE in {"dynamic", "lease", "pool", "dhcp"}


def next_available_ip(
    db: sqlite3.Connection,
    *,
    exclude_user_id: int | None = None,
    avoid_ip: str | None = None,
) -> str:
    network = ipaddress.ip_network(WG_NETWORK, strict=False)
    server_ip = ipaddress.ip_address(WG_SERVER_ADDRESS)

    where_parts = ["role = 'user'", "assigned_ip IS NOT NULL"]
    params: list[object] = []
    if is_dynamic_ip_assignment_mode():
        where_parts.append("wg_enabled = 1")
    if exclude_user_id is not None:
        where_parts.append("id <> ?")
        params.append(exclude_user_id)

    used_rows = db.execute(
        f"""
        SELECT assigned_ip FROM users
        WHERE {' AND '.join(where_parts)}
        """,
        params,
    ).fetchall()

    used_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for row in used_rows:
        try:
            used_ips.add(ipaddress.ip_address(row["assigned_ip"]))
        except Exception:
            continue
    used_ips.add(server_ip)

    avoid_ip_obj = None
    if avoid_ip:
        try:
            avoid_ip_obj = ipaddress.ip_address(avoid_ip)
        except Exception:
            avoid_ip_obj = None

    if avoid_ip_obj:
        for host in network.hosts():
            if host in used_ips or host == avoid_ip_obj:
                continue
            return str(host)

    for host in network.hosts():
        if host in used_ips:
            continue
        return str(host)
    raise RuntimeError("当前网段内没有可分配的 VPN IP。")



def build_client_config(
    client_private_key: str,
    client_psk: str,
    client_ip: str,
    *,
    allowed_ips: str | None = None,
) -> str:
    server_public_key = get_wireguard_server_public_key()
    resolved_allowed_ips = (allowed_ips or get_client_allowed_ips()).strip()
    if not resolved_allowed_ips:
        raise RuntimeError("WireGuard AllowedIPs 为空，无法生成配置。")
    return "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {client_private_key}",
            f"Address = {client_ip}/24",
            f"DNS = {WG_CLIENT_DNS}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"PresharedKey = {client_psk}",
            f"AllowedIPs = {resolved_allowed_ips}",
            f"Endpoint = {get_wireguard_endpoint_for_clients()}",
            f"PersistentKeepalive = {WG_CLIENT_KEEPALIVE}",
            "",
        ]
    )



def write_client_artifacts(
    username: str,
    user_id: int,
    client_private_key: str,
    client_psk: str,
    client_ip: str,
    config_path: str | None = None,
    qr_path: str | None = None,
) -> dict[str, str | None]:
    filename_prefix = f"{safe_name(username)}_{user_id}"
    conf_path = Path(config_path) if config_path else CLIENT_CONF_DIR / f"{filename_prefix}.conf"
    qr_image_path = Path(qr_path) if qr_path else CLIENT_QR_DIR / f"{filename_prefix}.png"

    config_text = build_client_config(client_private_key, client_psk, client_ip)

    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(config_text, encoding="utf-8")
    os.chmod(conf_path, 0o600)

    # 配置二维码功能已停用，仅提供 .conf 下载导入。
    qr_image_path.unlink(missing_ok=True)

    return {
        "config_path": str(conf_path),
        "qr_path": None,
    }


def build_user_wireguard_config(
    user: sqlite3.Row,
    *,
    profile_mode: str,
) -> tuple[str, str]:
    normalized_mode = normalize_wg_profile_mode(profile_mode)
    assigned_ip = (row_get(user, "assigned_ip", "") or "").strip()
    client_private_key = (row_get(user, "client_private_key", "") or "").strip()
    client_psk = (row_get(user, "client_psk", "") or "").strip()

    if not assigned_ip:
        raise RuntimeError("当前用户暂无可用 VPN 地址，请稍后重试或联系管理员。")
    if not client_private_key or not client_psk:
        raise RuntimeError("用户密钥尚未就绪，请联系管理员。")

    allowed_ips = get_client_allowed_ips_for_profile(normalized_mode)
    config_text = build_client_config(
        client_private_key,
        client_psk,
        assigned_ip,
        allowed_ips=allowed_ips,
    )
    return config_text, normalized_mode


def set_wireguard_peer(peer_public_key: str, peer_psk: str, client_ip: str) -> None:
    if use_vpn_api():
        vpn_api_request(
            "POST",
            "/wireguard/set-peer",
            {
                "interface": WG_INTERFACE,
                "peer_public_key": peer_public_key,
                "peer_psk": peer_psk,
                "client_ip": client_ip,
            },
        )
        return

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_psk:
        tmp_psk.write(peer_psk)
        tmp_psk.flush()
        tmp_psk_path = tmp_psk.name

    try:
        run_command(
            [
                "wg",
                "set",
                WG_INTERFACE,
                "peer",
                peer_public_key,
                "preshared-key",
                tmp_psk_path,
                "allowed-ips",
                f"{client_ip}/32",
            ]
        )
        run_command(["wg-quick", "save", WG_INTERFACE])
    finally:
        Path(tmp_psk_path).unlink(missing_ok=True)


def remove_wireguard_peer(peer_public_key: str) -> None:
    if use_vpn_api():
        vpn_api_request(
            "POST",
            "/wireguard/remove-peer",
            {"interface": WG_INTERFACE, "peer_public_key": peer_public_key},
        )
        return

    run_command(
        ["wg", "set", WG_INTERFACE, "peer", peer_public_key, "remove"],
        check=False,
    )
    run_command(["wg-quick", "save", WG_INTERFACE], check=False)


def generate_wireguard_bundle(username: str, user_id: int, client_ip: str):
    client_private_key, client_public_key, client_psk = wireguard_generate_keys()

    artifacts = write_client_artifacts(
        username=username,
        user_id=user_id,
        client_private_key=client_private_key,
        client_psk=client_psk,
        client_ip=client_ip,
    )
    set_wireguard_peer(client_public_key, client_psk, client_ip)

    return {
        "assigned_ip": client_ip,
        "client_private_key": client_private_key,
        "client_public_key": client_public_key,
        "client_psk": client_psk,
        "config_path": artifacts["config_path"],
        "qr_path": artifacts["qr_path"],
    }


def ensure_user_vpn_ready(db: sqlite3.Connection, user: sqlite3.Row) -> dict[str, str | int]:
    has_crypto_keys = all(
        [
            user["client_private_key"],
            user["client_public_key"],
            user["client_psk"],
        ]
    )

    if not has_crypto_keys:
        assigned_ip = next_available_ip(db, exclude_user_id=user["id"])
        bundle = generate_wireguard_bundle(user["username"], user["id"], assigned_ip)
        bundle["wg_enabled"] = 1
        return bundle

    assigned_ip = user["assigned_ip"]
    if not assigned_ip or is_dynamic_ip_assignment_mode():
        assigned_ip = next_available_ip(
            db,
            exclude_user_id=user["id"],
            avoid_ip=user["assigned_ip"] if is_dynamic_ip_assignment_mode() else None,
        )

    artifacts = write_client_artifacts(
        username=user["username"],
        user_id=user["id"],
        client_private_key=user["client_private_key"],
        client_psk=user["client_psk"],
        client_ip=assigned_ip,
        config_path=user["config_path"],
        qr_path=user["qr_path"],
    )
    set_wireguard_peer(user["client_public_key"], user["client_psk"], assigned_ip)

    return {
        "assigned_ip": assigned_ip,
        "client_private_key": user["client_private_key"],
        "client_public_key": user["client_public_key"],
        "client_psk": user["client_psk"],
        "config_path": artifacts["config_path"],
        "qr_path": artifacts["qr_path"],
        "wg_enabled": 1,
    }


def calculate_new_expiry(current_expire_iso: str | None, months: int) -> str:
    now = utcnow()
    current_expire = parse_iso(current_expire_iso)

    if current_expire and current_expire >= now:
        period_start = current_expire + timedelta(seconds=1)
    else:
        period_start = now

    period_end = add_months(period_start, months) - timedelta(seconds=1)
    return period_end.isoformat()


def has_active_time_subscription(user: sqlite3.Row) -> bool:
    expires_at = parse_iso(row_get(user, "subscription_expires_at"))
    return bool(expires_at and expires_at >= utcnow())


def has_active_traffic_subscription(user: sqlite3.Row) -> bool:
    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    return quota_bytes > 0 and used_bytes < quota_bytes


def sync_user_traffic_usage(
    db: sqlite3.Connection,
    user: sqlite3.Row,
    *,
    current_total_bytes: int | None = None,
) -> sqlite3.Row:
    quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    if quota_bytes <= 0:
        return user

    used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    last_total_bytes = to_non_negative_int(row_get(user, "traffic_last_total_bytes", 0))
    if current_total_bytes is None:
        rx_bytes, tx_bytes = get_wireguard_transfer_bytes(row_get(user, "client_public_key"))
        current_total_bytes = rx_bytes + tx_bytes
    current_total_bytes = max(0, int(current_total_bytes))

    traffic_delta = current_total_bytes - last_total_bytes
    if traffic_delta < 0:
        # wg counter may reset after interface restart; skip negative delta
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
    if exhausted and int(row_get(user, "wg_enabled", 0) or 0) == 1 and not has_active_time_subscription(user):
        if row_get(user, "client_public_key"):
            remove_wireguard_peer(user["client_public_key"])
        if is_dynamic_ip_assignment_mode():
            db.execute(
                "UPDATE users SET wg_enabled = 0, assigned_ip = NULL WHERE id = ?",
                (user["id"],),
            )
        else:
            db.execute("UPDATE users SET wg_enabled = 0 WHERE id = ?", (user["id"],))
        changed = True

    if changed:
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return user


def is_subscription_active(user: sqlite3.Row) -> bool:
    if int(row_get(user, "wg_enabled", 0) or 0) != 1:
        return False
    return has_active_time_subscription(user) or has_active_traffic_subscription(user)


def reconcile_expired_subscriptions(db: sqlite3.Connection) -> None:
    now = utcnow()
    rows = db.execute(
        """
        SELECT
            id,
            client_public_key,
            subscription_expires_at,
            wg_enabled,
            traffic_quota_bytes,
            traffic_used_bytes
        FROM users
        WHERE role = 'user' AND wg_enabled = 1 AND subscription_expires_at IS NOT NULL
        """
    ).fetchall()

    changed = 0
    for row in rows:
        expires_at = parse_iso(row["subscription_expires_at"])
        if not expires_at or expires_at >= now:
            continue
        if has_active_traffic_subscription(row):
            continue
        if row["client_public_key"]:
            remove_wireguard_peer(row["client_public_key"])
        if is_dynamic_ip_assignment_mode():
            db.execute(
                "UPDATE users SET wg_enabled = 0, assigned_ip = NULL WHERE id = ?",
                (row["id"],),
            )
        else:
            db.execute("UPDATE users SET wg_enabled = 0 WHERE id = ?", (row["id"],))
        changed += 1

    if changed:
        db.commit()


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
    db: sqlite3.Connection,
    order_id: int,
    *,
    tx_hash: str | None = None,
    paid_at_iso: str | None = None,
    source: str = "admin",
    require_tx_hash: bool = True,
    webhook_amount: Decimal | None = None,
    webhook_network: str | None = None,
):
    db.execute("BEGIN IMMEDIATE")
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
    plan_duration_months = to_non_negative_int(plan_snapshot["duration_months"])
    plan_traffic_gb = to_non_negative_int(plan_snapshot["traffic_gb"])
    if plan_mode == PLAN_MODE_DURATION and plan_duration_months <= 0:
        db.rollback()
        raise ValueError("时长套餐配置无效。")
    if plan_mode == PLAN_MODE_TRAFFIC and plan_traffic_gb <= 0:
        db.rollback()
        raise ValueError("流量套餐配置无效。")

    current_expire_iso = row_get(user, "subscription_expires_at")
    if plan_mode == PLAN_MODE_DURATION:
        new_expire_at = calculate_new_expiry(current_expire_iso, plan_duration_months)
    else:
        new_expire_at = None

    current_quota_bytes = to_non_negative_int(row_get(user, "traffic_quota_bytes", 0))
    current_used_bytes = to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
    current_last_total_bytes = to_non_negative_int(
        row_get(user, "traffic_last_total_bytes", 0)
    )
    if row_get(user, "client_public_key"):
        rx_now, tx_now = get_wireguard_transfer_bytes(user["client_public_key"])
        current_total_bytes = rx_now + tx_now
        delta_bytes = current_total_bytes - current_last_total_bytes
        if delta_bytes > 0 and current_quota_bytes > 0:
            current_used_bytes = min(current_quota_bytes, current_used_bytes + delta_bytes)
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
    paid_at_iso = paid_at_iso or utcnow_iso()
    tx_submitted_at = order["tx_submitted_at"] or (paid_at_iso if final_tx_hash else None)
    note_line = f"{source} confirmed at {paid_at_iso}"
    merged_note = note_line if not order["note"] else f"{order['note']}\n{note_line}"

    db.execute(
        """
        UPDATE users
        SET status = 'approved',
            assigned_ip = ?,
            client_private_key = ?,
            client_public_key = ?,
            client_psk = ?,
            config_path = ?,
            qr_path = ?,
            approved_at = ?,
            subscription_expires_at = ?,
            traffic_quota_bytes = ?,
            traffic_used_bytes = ?,
            traffic_last_total_bytes = ?,
            wg_enabled = 1
        WHERE id = ?
        """,
        (
            vpn_data["assigned_ip"],
            vpn_data["client_private_key"],
            vpn_data["client_public_key"],
            vpn_data["client_psk"],
            vpn_data["config_path"],
            vpn_data["qr_path"],
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
        grant_text = f"时长套餐生效，到期时间：{format_utc(new_expire_at)}，流量剩余：永久"
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


@app.route("/wireguard/download")
def wireguard_download_page():
    user = current_user()
    dashboard_page = "guide" if user and user["role"] == "user" else None
    return render_template(
        "wireguard_download.html",
        dashboard_page=dashboard_page,
        wireguard_download_links=WIREGUARD_DOWNLOAD_LINKS,
    )


@app.route("/wireguard/download/auto")
def wireguard_download_auto():
    platform = detect_wireguard_platform(request.headers.get("User-Agent", ""))
    return redirect(url_for("wireguard_download_redirect", platform=platform))


@app.route("/wireguard/download/<platform>")
def wireguard_download_redirect(platform: str):
    key = (platform or "").strip().lower()
    target_url = WIREGUARD_DOWNLOAD_LINKS.get(key, WIREGUARD_DOWNLOAD_FALLBACK)
    return redirect(target_url, code=302)


@app.route("/openvpn/download")
def openvpn_download_page():
    user = current_user()
    dashboard_page = "guide" if user and user["role"] == "user" else None
    return render_template(
        "openvpn_download.html",
        dashboard_page=dashboard_page,
        openvpn_download_links=OPENVPN_DOWNLOAD_LINKS,
    )


@app.route("/openvpn/download/auto")
def openvpn_download_auto():
    platform = detect_openvpn_platform(request.headers.get("User-Agent", ""))
    return redirect(url_for("openvpn_download_redirect", platform=platform))


@app.route("/openvpn/download/<platform>")
def openvpn_download_redirect(platform: str):
    key = (platform or "").strip().lower()
    target_url = OPENVPN_DOWNLOAD_LINKS.get(key, OPENVPN_DOWNLOAD_FALLBACK)
    return redirect(target_url, code=302)


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    db = get_db()
    landing_plans = load_subscription_plans(db, active_only=True)
    return render_template(
        "index.html",
        landing_plans=landing_plans,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    client_ip = get_client_ip()
    db = get_db()
    cooldown_seconds = get_registration_cooldown_seconds(db, client_ip)
    register_limit_minutes = REGISTER_COOLDOWN_SECONDS // 60

    def render_register():
        return render_template(
            "register.html",
            cooldown_seconds=cooldown_seconds,
            client_ip=client_ip,
            register_limit_seconds=REGISTER_COOLDOWN_SECONDS,
            register_limit_minutes=register_limit_minutes,
        )

    if request.method == "POST":
        if cooldown_seconds > 0:
            flash(
                f"该 IP 注册过于频繁，请在 {cooldown_seconds} 秒后重试。",
                "error",
            )
            return render_register()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if "@" not in email or len(email) < 5:
            flash("邮箱格式不正确。", "error")
            return render_register()
        if len(password) < 8:
            flash("密码长度至少需要 8 位。", "error")
            return render_register()

        username = email
        try:
            now_iso = utcnow_iso()
            db.execute("BEGIN IMMEDIATE")
            cooldown_seconds = get_registration_cooldown_seconds(db, client_ip)
            if cooldown_seconds > 0:
                db.rollback()
                flash(
                    f"该 IP 注册过于频繁，请在 {cooldown_seconds} 秒后重试。",
                    "error",
                )
                return render_register()
            db.execute(
                """
                INSERT INTO users (username, email, password_hash, role, status, created_at, approved_at)
                VALUES (?, ?, ?, 'user', 'approved', ?, ?)
                """,
                (username, email, generate_password_hash(password), now_iso, now_iso),
            )
            mark_registration_success(db, client_ip, now_iso)
            db.commit()
            flash("注册成功，请登录后创建订阅订单。", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            db.rollback()
            flash("该邮箱已注册。", "error")
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            raise
    return render_register()



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(identity, password)
        if not user:
            flash("用户名/邮箱或密码错误。", "error")
            return render_template("login.html")

        login_user_session(user)
        if admin_must_change_password(user):
            flash("首次登录请先修改管理员密码。", "error")
            return redirect(url_for("admin_change_password"))
        flash("登录成功。", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
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
            "error": "用户名/邮箱或密码错误",
        }, 401

    login_user_session(user)
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
            db.execute(
                """
                UPDATE users
                SET password_hash = ?,
                    force_password_change = 0
                WHERE id = ?
                """,
                (generate_password_hash(new_password), user["id"]),
            )
            db.commit()
            flash("密码修改成功，请继续完成初始化向导。", "success")
            return redirect(url_for("admin_home", onboarding_open="1"))

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
        return redirect(url_for("admin_home"))
    return redirect(url_for("dashboard_home"))


@app.route("/dashboard/home")
@login_required
def dashboard_home():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    traffic_stats = get_user_traffic_stats(user)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    if has_traffic and not has_time:
        subscription_expiry_display = "永久"
    else:
        subscription_expiry_display = format_utc(user["subscription_expires_at"])
    if is_dynamic_ip_assignment_mode():
        assigned_ip_display = "DHCP 动态分配"
    else:
        assigned_ip_display = user["assigned_ip"] or "暂未分配"

    return render_template(
        "dashboard_home.html",
        user=user,
        active=is_subscription_active(user),
        traffic_stats=traffic_stats,
        subscription_expiry_display=subscription_expiry_display,
        assigned_ip_display=assigned_ip_display,
        dashboard_page="home",
    )


@app.route("/dashboard/guide")
@login_required
def dashboard_guide():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))
    return render_template(
        "dashboard_guide.html",
        dashboard_page="guide",
    )


@app.route("/dashboard/orders")
@login_required
def dashboard_orders():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    available_plans = load_subscription_plans(db, active_only=True)

    pending_orders = db.execute(
        """
        SELECT id, plan_months, plan_name, plan_mode, plan_duration_months, plan_traffic_gb, status, created_at,
               payment_method, usdt_network, usdt_amount, pay_to_address, tx_hash, tx_submitted_at
        FROM payment_orders
        WHERE user_id = ? AND status = 'pending'
        ORDER BY created_at DESC
        """,
        (user["id"],),
    ).fetchall()
    paid_orders = db.execute(
        """
        SELECT id, plan_months, plan_name, plan_mode, plan_duration_months, plan_traffic_gb, status, created_at, paid_at,
               payment_method, usdt_network, usdt_amount, pay_to_address, tx_hash, tx_submitted_at
        FROM payment_orders
        WHERE user_id = ? AND status = 'paid'
        ORDER BY paid_at DESC
        LIMIT 20
        """,
        (user["id"],),
    ).fetchall()

    return render_template(
        "dashboard_orders.html",
        user=user,
        available_plans=available_plans,
        pending_orders=pending_orders,
        paid_orders=paid_orders,
        usdt_explorer_link=usdt_explorer_link,
        dashboard_page="orders",
    )


@app.route("/subscription/create-order", methods=["POST"])
@login_required
def create_subscription_order():
    user = current_user()
    if user["role"] != "user":
        return redirect(url_for("dashboard_orders"))

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
        SELECT id, plan_name, billing_mode, duration_months, traffic_gb, price_usdt
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
    traffic_gb = to_non_negative_int(plan["traffic_gb"])
    if plan_mode == PLAN_MODE_DURATION and duration_months <= 0:
        flash("所选时长套餐配置无效，请联系管理员。", "error")
        return redirect(url_for("dashboard_orders"))
    if plan_mode == PLAN_MODE_TRAFFIC and traffic_gb <= 0:
        flash("所选流量套餐配置无效，请联系管理员。", "error")
        return redirect(url_for("dashboard_orders"))

    usdt_amount = parse_usdt_amount(plan["price_usdt"], "1")
    plan_display = format_plan_display_name(
        plan["plan_name"], plan_mode, duration_months, traffic_gb
    )
    db.execute(
        """
        INSERT INTO payment_orders (
            user_id, plan_months, plan_id, plan_name, plan_mode, plan_duration_months, plan_traffic_gb,
            payment_method, usdt_network, usdt_amount, pay_to_address, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            user["id"],
            duration_months,
            plan["id"],
            plan["plan_name"],
            plan_mode,
            duration_months if plan_mode == PLAN_MODE_DURATION else None,
            traffic_gb if plan_mode == PLAN_MODE_TRAFFIC else None,
            payment_method_code,
            network,
            format_usdt(usdt_amount),
            receive_address,
            utcnow_iso(),
        ),
    )
    db.commit()
    flash(
        f"USDT 订单已创建：{plan_display} / {format_usdt(usdt_amount)} USDT。请完成支付后提交 TxHash。",
        "success",
    )
    return redirect(url_for("dashboard_orders"))



@app.route("/subscription/orders/<int:order_id>/submit-tx", methods=["POST"])
@login_required
def submit_usdt_tx_hash(order_id: int):
    user = current_user()
    if user["role"] != "user":
        return redirect(url_for("dashboard_orders"))

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
    return redirect(url_for("admin_home"))


def load_admin_pending_orders(db: sqlite3.Connection):
    return db.execute(
        """
        SELECT
            o.id,
            o.user_id,
            o.plan_months,
            o.plan_name,
            o.plan_mode,
            o.plan_duration_months,
            o.plan_traffic_gb,
            o.payment_method,
            o.usdt_network,
            o.usdt_amount,
            o.pay_to_address,
            o.tx_hash,
            o.tx_submitted_at,
            o.created_at,
            u.username,
            u.email,
            u.subscription_expires_at
        FROM payment_orders o
        JOIN users u ON u.id = o.user_id
        WHERE o.status = 'pending'
        ORDER BY o.created_at ASC
        """
    ).fetchall()


def load_admin_paid_orders(db: sqlite3.Connection):
    return db.execute(
        """
        SELECT
            o.id,
            o.plan_months,
            o.plan_name,
            o.plan_mode,
            o.plan_duration_months,
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


def load_admin_subscriptions(db: sqlite3.Connection, email_query: str = ""):
    base_sql = """
        SELECT
            id,
            username,
            email,
            assigned_ip,
            subscription_expires_at,
            wg_enabled
        FROM users
        WHERE role = 'user'
    """
    params = []
    normalized_query = (email_query or "").strip()
    if normalized_query:
        base_sql += " AND email LIKE ? COLLATE NOCASE"
        params.append(f"%{normalized_query}%")
    base_sql += " ORDER BY subscription_expires_at DESC, id DESC"
    return db.execute(base_sql, params).fetchall()


def load_first_plan_for_onboarding(db: sqlite3.Connection) -> dict:
    plan = db.execute(
        """
        SELECT id, plan_name, billing_mode, duration_months, traffic_gb, price_usdt, sort_order
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
    return {
        "plan_name": (plan["plan_name"] or "").strip() or "基础套餐",
        "billing_mode": mode,
        "duration_months": max(1, to_non_negative_int(plan["duration_months"]) or 1),
        "traffic_gb": max(1, to_non_negative_int(plan["traffic_gb"]) or 1),
        "price_usdt": format_usdt(plan["price_usdt"]),
        "sort_order": to_non_negative_int(plan["sort_order"]),
    }


def upsert_first_plan_from_onboarding(
    db: sqlite3.Connection,
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
            traffic_gb,
            price_usdt,
            is_active,
            sort_order,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            plan_name,
            normalized_mode,
            duration_months if normalized_mode == PLAN_MODE_DURATION else None,
            traffic_gb if normalized_mode == PLAN_MODE_TRAFFIC else None,
            format_usdt(price_usdt),
            sort_order,
            now_iso,
            now_iso,
        ),
    )


def upsert_primary_payment_method_from_onboarding(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
    *,
    server_name: str,
    host: str,
    port: int,
    username: str,
    password: str,
    domain: str,
    wg_port: int,
    openvpn_port: int,
    dns_port: int,
    vpn_api_token: str,
    status: str = "pending",
) -> int:
    now_iso = utcnow_iso()
    cursor = db.execute(
        """
        INSERT INTO vpn_servers (
            server_name, host, port, username, password, domain, vpn_api_token,
            wg_port, openvpn_port, dns_port, status,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            server_name,
            host,
            port,
            username,
            password,
            domain,
            vpn_api_token,
            wg_port,
            openvpn_port,
            dns_port,
            status,
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.lastrowid)


def update_server_test_result(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
    server_id: int,
    *,
    ok: bool,
    message: str,
    status: str,
    vpn_api_token: str | None = None,
) -> None:
    params: list[object] = [
        status,
        utcnow_iso(),
        1 if ok else 0,
        summarize_text(message, 1200),
        utcnow_iso(),
        server_id,
    ]
    sql = """
        UPDATE vpn_servers
        SET status = ?,
            last_deploy_at = ?,
            last_deploy_ok = ?,
            last_deploy_message = ?,
            updated_at = ?
    """
    if vpn_api_token:
        sql += ", vpn_api_token = ?"
        params.insert(-1, vpn_api_token)
    sql += " WHERE id = ?"
    db.execute(sql, params)


def redirect_admin_onboarding_modal(step: int | None = None):
    if step is not None and 1 <= step <= 4:
        return redirect(
            url_for("admin_home", onboarding_open="1", onboarding_step=str(step))
        )
    return redirect(url_for("admin_home", onboarding_open="1"))


@app.route("/admin/onboarding/step-plan", methods=["POST"])
@login_required
@admin_required
def admin_onboarding_step_plan():
    db = get_db()
    if is_admin_onboarding_completed(db):
        flash("初始化已完成。", "success")
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

    cloudflare_account = request.form.get("cloudflare_account", "").strip()
    cloudflare_password = request.form.get("cloudflare_password", "").strip()
    if not cloudflare_account or not cloudflare_password:
        flash("请填写 Cloudflare 账号和密码。", "error")
        return redirect_admin_onboarding_modal(3)

    upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_ACCOUNT, cloudflare_account)
    upsert_app_setting(db, ONBOARDING_SETTING_CLOUDFLARE_PASSWORD, cloudflare_password)
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
        return redirect(url_for("admin_home"))

    action = (request.form.get("action", "save_draft") or "").strip().lower()
    server_name = request.form.get("server_name", "").strip()
    server_host = normalize_remote_host(request.form.get("server_host", ""))
    server_port = normalize_server_port(request.form.get("server_port", "22"), 22)
    server_username = request.form.get("server_username", "").strip()
    server_password = request.form.get("server_password", "")

    save_onboarding_server_draft(
        db,
        server_name=server_name,
        server_host=server_host,
        server_port=server_port,
        server_username=server_username or "root",
        server_password=server_password,
    )

    if action == "save_draft":
        db.commit()
        flash("步骤 4 草稿已保存，可稍后继续。", "success")
        return redirect_admin_onboarding_modal(4)

    if not server_host or not server_username or not server_password:
        db.commit()
        flash("请填写服务器 IP/域名、账号、密码。", "error")
        return redirect_admin_onboarding_modal(4)

    if action == "test_server":
        ok, message = test_server_connectivity(
            server_host,
            server_port,
            server_username,
            server_password,
        )
        db.commit()
        flash(message, "success" if ok else "error")
        return redirect_admin_onboarding_modal(4)

    step_status, next_step = get_admin_onboarding_step_status(db)
    if not step_status[1] or not step_status[2] or not step_status[3]:
        db.commit()
        flash("请先完成前 3 个步骤后再部署服务器。", "error")
        return redirect_admin_onboarding_modal(next_step)

    ok, test_message = test_server_connectivity(
        server_host,
        server_port,
        server_username,
        server_password,
    )
    if not ok:
        db.commit()
        flash(f"服务器连通测试失败：{test_message}", "error")
        return redirect_admin_onboarding_modal(4)

    settings = load_onboarding_settings(db)
    portal_domain = normalize_domain_host(str(settings["portal_domain"]))
    if not server_name:
        server_name = server_host

    deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
    server_id = create_server_record(
        db,
        server_name=server_name,
        host=server_host,
        port=server_port,
        username=server_username,
        password=server_password,
        domain=portal_domain,
        wg_port=SERVER_DEPLOY_DEFAULT_WG_PORT,
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

    deploy_ok, deploy_message, final_token = deploy_vpn_node_server(
        host=server_host,
        port=server_port,
        username=server_username,
        password=server_password,
        wg_port=SERVER_DEPLOY_DEFAULT_WG_PORT,
        openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
        dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
        vpn_api_token=deploy_token,
    )
    update_server_deploy_result(
        db,
        server_id,
        ok=deploy_ok,
        message=deploy_message,
        status="online" if deploy_ok else "deploy_failed",
        vpn_api_token=final_token,
    )
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
        )
        db.commit()
        flash("初始化完成，VPN 服务端部署成功。", "success")
        return redirect(url_for("admin_home"))

    db.commit()
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
        return redirect(url_for("admin_home"))

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

        server_name = request.form.get("server_name", "").strip()
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
            flash("请填写 Cloudflare 账号和密码。", "error")
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

        if not server_name:
            server_name = server_host
        deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
        server_id = create_server_record(
            db,
            server_name=server_name,
            host=server_host,
            port=server_port,
            username=server_username,
            password=server_password,
            domain=portal_domain,
            wg_port=SERVER_DEPLOY_DEFAULT_WG_PORT,
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

        deploy_ok, deploy_message, final_token = deploy_vpn_node_server(
            host=server_host,
            port=server_port,
            username=server_username,
            password=server_password,
            wg_port=SERVER_DEPLOY_DEFAULT_WG_PORT,
            openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
            dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
            vpn_api_token=deploy_token,
        )
        update_server_deploy_result(
            db,
            server_id,
            ok=deploy_ok,
            message=deploy_message,
            status="online" if deploy_ok else "deploy_failed",
            vpn_api_token=final_token,
        )
        if deploy_ok:
            upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED, "1")
            upsert_app_setting(db, ONBOARDING_SETTING_SETUP_COMPLETED_AT, utcnow_iso())
            upsert_app_setting(db, ONBOARDING_SETTING_LAST_SERVER_ID, str(server_id))
            db.commit()
            flash("初始化完成，VPN 服务端部署成功。", "success")
            return redirect(url_for("admin_home"))

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
    servers = load_admin_servers(db)
    onboarding_settings = load_onboarding_settings(db)
    return render_template(
        "admin_servers.html",
        servers=servers,
        onboarding_settings=onboarding_settings,
        admin_page="servers",
    )


@app.route("/admin/servers/test", methods=["POST"])
@login_required
@admin_required
def admin_test_server_connection():
    payload = request.get_json(silent=True) or request.form
    host = normalize_remote_host(payload.get("host", ""))
    port = normalize_server_port(payload.get("port", "22"), 22)
    username = (payload.get("username", "") or "").strip()
    password = payload.get("password", "") or ""

    ok, message = test_server_connectivity(host, port, username, password)
    status_code = 200 if ok else 400
    return {"ok": ok, "message": message}, status_code


@app.route("/admin/servers/create", methods=["POST"])
@login_required
@admin_required
def admin_create_server():
    db = get_db()
    server_name = request.form.get("server_name", "").strip()
    host = normalize_remote_host(request.form.get("host", ""))
    port = normalize_server_port(request.form.get("port", "22"), 22)
    username = (request.form.get("username", "") or "").strip()
    password = request.form.get("password", "") or ""
    domain = normalize_domain_host(request.form.get("domain", "")) or get_portal_domain_setting()
    wg_port = normalize_server_port(
        request.form.get("wg_port", str(SERVER_DEPLOY_DEFAULT_WG_PORT)),
        SERVER_DEPLOY_DEFAULT_WG_PORT,
    )
    openvpn_port = normalize_server_port(
        request.form.get("openvpn_port", str(SERVER_DEPLOY_DEFAULT_OPENVPN_PORT)),
        SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
    )
    dns_port = normalize_server_port(
        request.form.get("dns_port", str(SERVER_DEPLOY_DEFAULT_DNS_PORT)),
        SERVER_DEPLOY_DEFAULT_DNS_PORT,
    )

    if not host or not username or not password:
        flash("请完整填写服务器地址、账号和密码。", "error")
        return redirect(url_for("admin_servers"))

    ok, test_message = test_server_connectivity(host, port, username, password)
    if not ok:
        flash(f"服务器连接测试失败：{test_message}", "error")
        return redirect(url_for("admin_servers"))

    if not server_name:
        server_name = host
    deploy_token = hashlib.sha256(os.urandom(24)).hexdigest()[:48]
    server_id = create_server_record(
        db,
        server_name=server_name,
        host=host,
        port=port,
        username=username,
        password=password,
        domain=domain,
        wg_port=wg_port,
        openvpn_port=openvpn_port,
        dns_port=dns_port,
        vpn_api_token=deploy_token,
        status="deploying",
    )
    update_server_test_result(db, server_id, ok=True, message=test_message)

    deploy_ok, deploy_message, final_token = deploy_vpn_node_server(
        host=host,
        port=port,
        username=username,
        password=password,
        wg_port=wg_port,
        openvpn_port=openvpn_port,
        dns_port=dns_port,
        vpn_api_token=deploy_token,
    )
    update_server_deploy_result(
        db,
        server_id,
        ok=deploy_ok,
        message=deploy_message,
        status="online" if deploy_ok else "deploy_failed",
        vpn_api_token=final_token,
    )
    db.commit()

    if deploy_ok:
        flash("服务器已保存并完成 VPN 服务部署。", "success")
    else:
        flash(f"服务器已保存，但部署失败：{deploy_message}", "error")
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
    )
    update_server_test_result(db, server_id, ok=ok, message=message)
    db.commit()
    flash(message, "success" if ok else "error")
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

    deploy_ok, deploy_message, final_token = deploy_vpn_node_server(
        host=row["host"],
        port=normalize_server_port(row["port"], 22),
        username=row["username"],
        password=row["password"],
        wg_port=normalize_server_port(row_get(row, "wg_port"), SERVER_DEPLOY_DEFAULT_WG_PORT),
        openvpn_port=normalize_server_port(
            row_get(row, "openvpn_port"), SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
        ),
        dns_port=normalize_server_port(row_get(row, "dns_port"), SERVER_DEPLOY_DEFAULT_DNS_PORT),
        vpn_api_token=row_get(row, "vpn_api_token", ""),
    )
    update_server_deploy_result(
        db,
        server_id,
        ok=deploy_ok,
        message=deploy_message,
        status="online" if deploy_ok else "deploy_failed",
        vpn_api_token=final_token,
    )
    db.commit()
    flash(deploy_message, "success" if deploy_ok else "error")
    return redirect(url_for("admin_servers"))


@app.route("/admin/home")
@login_required
@admin_required
def admin_home():
    db = get_db()
    reconcile_expired_subscriptions(db)

    onboarding_settings = load_onboarding_settings(db)
    onboarding_step_status, onboarding_default_step = get_admin_onboarding_step_status(db)
    onboarding_current_step = onboarding_default_step
    requested_step_raw = (request.args.get("onboarding_step", "") or "").strip()
    if requested_step_raw.isdigit():
        candidate_step = int(requested_step_raw)
        if 1 <= candidate_step <= 4:
            onboarding_current_step = candidate_step
    onboarding_force_open = (
        (request.args.get("onboarding_open", "") or "").strip() == "1"
        or "onboarding_step" in request.args
    )
    first_plan = load_first_plan_for_onboarding(db)
    payment_settings = load_payment_settings(db)
    onboarding_server_draft = load_onboarding_server_draft(db)

    pending_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM payment_orders WHERE status = 'pending'"
    ).fetchone()["cnt"]
    paid_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM payment_orders WHERE status = 'paid'"
    ).fetchone()["cnt"]
    active_subscriptions = db.execute(
        "SELECT COUNT(*) AS cnt FROM users WHERE role='user' AND wg_enabled = 1"
    ).fetchone()["cnt"]
    total_users = db.execute(
        "SELECT COUNT(*) AS cnt FROM users WHERE role='user'"
    ).fetchone()["cnt"]

    return render_template(
        "admin_home.html",
        pending_count=pending_count,
        paid_count=paid_count,
        active_subscriptions=active_subscriptions,
        total_users=total_users,
        webhook_enabled=bool(PAYMENT_WEBHOOK_SECRET),
        webhook_min_confirmations=PAYMENT_MIN_CONFIRMATIONS,
        onboarding_settings=onboarding_settings,
        onboarding_step_status=onboarding_step_status,
        onboarding_default_step=onboarding_default_step,
        onboarding_current_step=onboarding_current_step,
        onboarding_force_open=onboarding_force_open,
        first_plan=first_plan,
        payment_settings=payment_settings,
        onboarding_server_draft=onboarding_server_draft,
        admin_page="home",
    )


@app.route("/admin/payment")
@login_required
@admin_required
def admin_payment_settings():
    db = get_db()
    plans = load_subscription_plans(db, active_only=False)
    return render_template(
        "admin_payment.html",
        plans=plans,
        admin_page="payment",
    )


@app.route("/admin/payment-methods")
@login_required
@admin_required
def admin_payment_methods():
    db = get_db()
    payment_methods = load_payment_methods(db, active_only=False)
    return render_template(
        "admin_payment_methods.html",
        payment_methods=payment_methods,
        admin_page="payment_methods",
    )


@app.route("/admin/orders/pending")
@login_required
@admin_required
def admin_pending_orders():
    db = get_db()
    reconcile_expired_subscriptions(db)
    pending_orders = load_admin_pending_orders(db)
    return render_template(
        "admin_pending_orders.html",
        pending_orders=pending_orders,
        usdt_explorer_link=usdt_explorer_link,
        admin_page="pending_orders",
    )


@app.route("/admin/orders/paid")
@login_required
@admin_required
def admin_paid_orders():
    db = get_db()
    paid_orders = load_admin_paid_orders(db)
    return render_template(
        "admin_paid_orders.html",
        paid_orders=paid_orders,
        usdt_explorer_link=usdt_explorer_link,
        admin_page="paid_orders",
    )


@app.route("/admin/subscriptions")
@login_required
@admin_required
def admin_subscriptions():
    db = get_db()
    reconcile_expired_subscriptions(db)
    search_email = request.args.get("q", "").strip()
    subscriptions = load_admin_subscriptions(db, search_email)
    return render_template(
        "admin_subscriptions.html",
        subscriptions=subscriptions,
        search_email=search_email,
        admin_ui_tz_name=ADMIN_UI_TZ_NAME,
        admin_page="subscriptions",
    )


def redirect_admin_subscriptions():
    search_email = request.values.get("q", "").strip()
    if search_email:
        return redirect(url_for("admin_subscriptions", q=search_email))
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/settings/payment", methods=["POST"])
@login_required
@admin_required
def admin_update_payment_settings():
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
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/payment-methods/create", methods=["POST"])
@login_required
@admin_required
def admin_create_payment_method():
    db = get_db()
    method_code = normalize_payment_method(request.form.get("method_code", PAYMENT_METHOD_USDT))
    method_name = request.form.get("method_name", "").strip()
    network = request.form.get("network", "TRC20").strip().upper()
    receive_address = request.form.get("receive_address", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if method_code != PAYMENT_METHOD_USDT:
        flash("当前仅支持 USDT 付款方式。", "error")
        return redirect(url_for("admin_payment_methods"))
    if network not in USDT_NETWORK_OPTIONS:
        flash("付款网络无效。", "error")
        return redirect(url_for("admin_payment_methods"))
    if not receive_address:
        flash("收款地址不能为空。", "error")
        return redirect(url_for("admin_payment_methods"))

    if not method_name:
        method_name = f"{payment_method_label(method_code)} {network}"
    try:
        sort_order = int(sort_order_raw) if sort_order_raw else 100
    except Exception:
        sort_order = 100
    if sort_order < 0:
        sort_order = 0

    now_iso = utcnow_iso()
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
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/payment-methods/<int:method_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_payment_method(method_id: int):
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
        return redirect(url_for("admin_payment_methods"))

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
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/plans/create", methods=["POST"])
@login_required
@admin_required
def admin_create_plan():
    db = get_db()
    plan_name = request.form.get("plan_name", "").strip()
    billing_mode = normalize_plan_mode(request.form.get("billing_mode", "duration"))
    duration_months_raw = request.form.get("duration_months", "").strip()
    traffic_gb_raw = request.form.get("traffic_gb", "").strip()
    if billing_mode == PLAN_MODE_DURATION:
        traffic_gb_raw = ""
    else:
        duration_months_raw = ""
    price_raw = request.form.get("price_usdt", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if not plan_name:
        flash("套餐名称不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

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
    traffic_gb = None
    if billing_mode == PLAN_MODE_DURATION:
        try:
            duration_months = parse_positive_int(duration_months_raw)
        except Exception:
            flash("时长套餐必须填写大于 0 的时长（月）。", "error")
            return redirect(url_for("admin_payment_settings"))
    else:
        try:
            traffic_gb = parse_positive_int(traffic_gb_raw)
        except Exception:
            flash("流量套餐必须填写大于 0 的流量（GB）。", "error")
            return redirect(url_for("admin_payment_settings"))

    now_iso = utcnow_iso()
    db.execute(
        """
        INSERT INTO subscription_plans (
            plan_name, billing_mode, duration_months, traffic_gb,
            price_usdt, is_active, sort_order, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            plan_name,
            billing_mode,
            duration_months,
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
    duration_months_raw = request.form.get("duration_months", "").strip()
    traffic_gb_raw = request.form.get("traffic_gb", "").strip()
    if billing_mode == PLAN_MODE_DURATION:
        traffic_gb_raw = ""
    else:
        duration_months_raw = ""
    price_raw = request.form.get("price_usdt", "").strip()
    sort_order_raw = request.form.get("sort_order", "").strip()

    if not plan_name:
        flash("套餐名称不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

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
    traffic_gb = None
    if billing_mode == PLAN_MODE_DURATION:
        try:
            duration_months = parse_positive_int(duration_months_raw)
        except Exception:
            flash("时长套餐必须填写大于 0 的时长（月）。", "error")
            return redirect(url_for("admin_payment_settings"))
    else:
        try:
            traffic_gb = parse_positive_int(traffic_gb_raw)
        except Exception:
            flash("流量套餐必须填写大于 0 的流量（GB）。", "error")
            return redirect(url_for("admin_payment_settings"))

    db.execute(
        """
        UPDATE subscription_plans
        SET plan_name = ?,
            billing_mode = ?,
            duration_months = ?,
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


@app.route("/admin/users/<int:user_id>/set-expiry", methods=["POST"])
@login_required
@admin_required
def admin_set_user_expiry(user_id: int):
    expires_raw = request.form.get("expires_at_local", "").strip()
    if not expires_raw:
        flash("请选择到期时间。", "error")
        return redirect_admin_subscriptions()

    try:
        expires_at_utc = parse_admin_local_datetime(expires_raw)
    except Exception:
        flash("到期时间格式无效。", "error")
        return redirect_admin_subscriptions()

    expires_iso = expires_at_utc.isoformat()
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
        if expires_at_utc >= utcnow():
            vpn_data = ensure_user_vpn_ready(db, user)
            db.execute(
                """
                UPDATE users
                SET assigned_ip = ?,
                    client_private_key = ?,
                    client_public_key = ?,
                    client_psk = ?,
                    config_path = ?,
                    qr_path = ?,
                    approved_at = ?,
                    subscription_expires_at = ?,
                    wg_enabled = 1
                WHERE id = ?
                """,
                (
                    vpn_data["assigned_ip"],
                    vpn_data["client_private_key"],
                    vpn_data["client_public_key"],
                    vpn_data["client_psk"],
                    vpn_data["config_path"],
                    vpn_data["qr_path"],
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

        if user["client_public_key"]:
            remove_wireguard_peer(user["client_public_key"])
        if is_dynamic_ip_assignment_mode():
            db.execute(
                """
                UPDATE users
                SET subscription_expires_at = ?,
                    wg_enabled = 0,
                    assigned_ip = NULL
                WHERE id = ?
                """,
                (expires_iso, user_id),
            )
        else:
            db.execute(
                """
                UPDATE users
                SET subscription_expires_at = ?,
                    wg_enabled = 0
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
        SELECT id, username, role, client_public_key, config_path, qr_path
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
        if user["client_public_key"]:
            remove_wireguard_peer(user["client_public_key"])

        config_path = (user["config_path"] or "").strip()
        if config_path:
            Path(config_path).unlink(missing_ok=True)

        qr_path = (user["qr_path"] or "").strip()
        if qr_path:
            Path(qr_path).unlink(missing_ok=True)

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
        SELECT id, username, role, client_public_key, wg_enabled
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
        if user["client_public_key"]:
            remove_wireguard_peer(user["client_public_key"])

        if is_dynamic_ip_assignment_mode():
            db.execute(
                """
                UPDATE users
                SET wg_enabled = 0,
                    assigned_ip = NULL
                WHERE id = ? AND role = 'user'
                """,
                (user_id,),
            )
        else:
            db.execute(
                """
                UPDATE users
                SET wg_enabled = 0
                WHERE id = ? AND role = 'user'
                """,
                (user_id,),
            )
        db.commit()

        if int(user["wg_enabled"] or 0) == 0:
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


@app.route("/admin/orders/<int:order_id>/mark-paid", methods=["POST"])
@login_required
@admin_required
def admin_mark_order_paid(order_id: int):
    db = get_db()
    try:
        result = settle_order_paid(
            db,
            order_id,
            source="admin",
            require_tx_hash=True,
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
    return redirect(url_for("admin_pending_orders"))



@app.route("/webhook/usdt", methods=["POST"])
def usdt_payment_webhook():
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


@app.route("/download/config")
@login_required
def download_config():
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

    requested_mode = request.args.get("mode", WG_PROFILE_GLOBAL)
    try:
        config_text, normalized_mode = build_user_wireguard_config(
            user,
            profile_mode=requested_mode,
        )
    except Exception as exc:
        flash(f"WireGuard 配置生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    filename = f"wg-{safe_name(user['username'])}-{wireguard_profile_filename_suffix(normalized_mode)}.conf"
    headers = {"Content-Disposition": f'attachment; filename=\"{filename}\"'}
    return Response(config_text, headers=headers, mimetype="text/plain")


@app.route("/download/openvpn")
@login_required
def download_openvpn_config():
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

    requested_mode = request.args.get("mode", WG_PROFILE_GLOBAL)
    normalized_mode = normalize_wg_profile_mode(requested_mode)
    try:
        config_text = build_openvpn_client_config(
            user["username"],
            profile_mode=normalized_mode,
        )
    except Exception as exc:
        flash(f"OpenVPN 配置生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    filename = f"ovpn-{safe_name(user['username'])}-{wireguard_profile_filename_suffix(normalized_mode)}.ovpn"
    headers = {"Content-Disposition": f'attachment; filename=\"{filename}\"'}
    return Response(config_text, headers=headers, mimetype="text/plain")



@app.route("/download/qr")
@login_required
def download_qr():
    user = current_user()
    if user["role"] != "user":
        flash("管理员无需下载客户端配置。", "error")
        return redirect(url_for("dashboard"))

    requested_mode = normalize_wg_profile_mode(request.args.get("mode", WG_PROFILE_GLOBAL))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not is_subscription_active(user):
        flash("订阅未生效或已过期，请先续费。", "error")
        return redirect(url_for("dashboard"))

    try:
        config_text, _ = build_user_wireguard_config(
            user,
            profile_mode=requested_mode,
        )
    except Exception as exc:
        flash(f"二维码生成失败：{exc}", "error")
        return redirect(url_for("dashboard_home"))

    qr = subprocess.run(
        ["qrencode", "-o", "-", "-t", "PNG"],
        input=config_text.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if qr.returncode != 0:
        msg = (qr.stderr or b"").decode("utf-8", errors="ignore").strip() or "未知错误"
        flash(f"二维码生成失败：{msg}", "error")
        return redirect(url_for("dashboard_home"))

    filename = f"wg-{safe_name(user['username'])}-global.png"
    headers = {"Content-Disposition": f'inline; filename=\"{filename}\"'}
    return Response(qr.stdout, headers=headers, mimetype="image/png")


@app.route("/subscription/payment-qr")
@login_required
def subscription_payment_qr():
    user = current_user()
    if not user or user["role"] != "user":
        return {"ok": False, "error": "仅普通用户可获取支付二维码"}, 403

    payment_settings = load_payment_settings(get_db())
    address = (payment_settings.get("usdt_receive_address") or "").strip()
    if not address:
        return {"ok": False, "error": "未配置 USDT 收款地址"}, 404

    qr = subprocess.run(
        ["qrencode", "-o", "-", "-t", "PNG"],
        input=address.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if qr.returncode != 0:
        msg = (qr.stderr or "").strip() or "未知错误"
        return {"ok": False, "error": f"生成支付二维码失败：{msg}"}, 500

    return Response(qr.stdout, mimetype="image/png")



def bootstrap() -> None:
    ensure_directories()
    with app.app_context():
        init_db()
        ensure_admin_user()


bootstrap()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
