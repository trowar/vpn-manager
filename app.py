import calendar
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import random
import re
import secrets
import smtplib
import socket
import sqlite3
import string
import subprocess
import sys
import shlex
import contextlib
import tempfile
import textwrap
import time
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps
from pathlib import Path
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import paramiko
import psycopg
try:
    import qrcode
except Exception:  # pragma: no cover - optional dependency fallback
    qrcode = None
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
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
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PORTAL_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.environ.get("PORTAL_DB_PATH", DATA_DIR / "portal.db"))
DB_BACKEND = os.environ.get("PORTAL_DB_BACKEND", "postgres").strip().lower()
if DB_BACKEND != "postgres":
    DB_BACKEND = "postgres"
POSTGRES_DSN = os.environ.get(
    "PORTAL_POSTGRES_DSN",
    "postgresql://vpnportal:vpnportal@postgres:5432/vpnportal",
).strip()
LEGACY_SQLITE_MIGRATION_SOURCE = Path(
    os.environ.get("PORTAL_SQLITE_MIGRATION_SOURCE", str(DB_PATH))
)
SKIP_SQLITE_IMPORT = os.environ.get("PORTAL_SKIP_SQLITE_IMPORT", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
CLIENT_CONF_DIR = Path(
    os.environ.get("PORTAL_CLIENT_CONF_DIR", DATA_DIR / "client-configs")
)
CLIENT_QR_DIR = Path(os.environ.get("PORTAL_CLIENT_QR_DIR", DATA_DIR / "client-qr"))
SHARED_VPN_MATERIALS_DIR = Path(
    os.environ.get("PORTAL_SHARED_VPN_MATERIALS_DIR", DATA_DIR / "shared-vpn-materials")
)
SHARED_WG_PRIVATE_KEY_FILE = SHARED_VPN_MATERIALS_DIR / "wg_server_private.key"
SHARED_WG_PUBLIC_KEY_FILE = SHARED_VPN_MATERIALS_DIR / "wg_server_public.key"
SHARED_OPENVPN_CA_KEY_FILE = SHARED_VPN_MATERIALS_DIR / "openvpn_ca.key"
SHARED_OPENVPN_CA_CERT_FILE = SHARED_VPN_MATERIALS_DIR / "openvpn_ca.crt"
SHARED_OPENVPN_SERVER_KEY_FILE = SHARED_VPN_MATERIALS_DIR / "openvpn_server.key"
SHARED_OPENVPN_SERVER_CERT_FILE = SHARED_VPN_MATERIALS_DIR / "openvpn_server.crt"
SHARED_OPENVPN_TLS_CRYPT_KEY_FILE = SHARED_VPN_MATERIALS_DIR / "openvpn_tls_crypt.key"
SYSTEM_UPGRADE_LOG_FILE = DATA_DIR / "system-upgrade.log"
DB_INIT_LOCK_DIR = DATA_DIR / ".db-init.lock"
SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS_RAW = os.environ.get(
    "PORTAL_SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS",
    "300",
).strip()
try:
    SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS = max(
        300, int(SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS_RAW)
    )
except ValueError:
    SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS = 300
AUTO_RESTART_AFTER_SELF_UPGRADE = (
    os.environ.get(
        "PORTAL_SELF_UPGRADE_AUTO_RESTART",
        "1" if Path("/.dockerenv").exists() else "0",
    )
    .strip()
    .lower()
    in {"1", "true", "yes", "on"}
)
HOST_WEB_UPGRADE_PROJECT_DIR = os.environ.get(
    "PORTAL_SELF_UPGRADE_HOST_PROJECT_DIR",
    "/srv/vpn-platform-v1",
).strip()
HOST_WEB_UPGRADE_BRANCH = os.environ.get(
    "PORTAL_SELF_UPGRADE_PROJECT_BRANCH",
    "main",
).strip() or "main"
HOST_WEB_UPGRADE_HELPER_IMAGE = os.environ.get(
    "PORTAL_SELF_UPGRADE_HELPER_IMAGE",
    "docker:27-cli",
).strip() or "docker:27-cli"
HOST_WEB_UPGRADE_DATA_VOLUME = os.environ.get(
    "PORTAL_SELF_UPGRADE_DATA_VOLUME",
    "vpn-platform-v1_portal_data",
).strip() or "vpn-platform-v1_portal_data"
DOCKER_SOCKET_FILE = Path("/var/run/docker.sock")

WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_NETWORK = os.environ.get("WG_NETWORK", "10.7.0.0/24")
WG_SERVER_ADDRESS = os.environ.get("WG_SERVER_ADDRESS", "10.7.0.1")
WG_SERVER_PUBLIC_KEY_FILE = Path(
    os.environ.get("WG_SERVER_PUBLIC_KEY_FILE", "/etc/wireguard/server_public.key")
)
WG_ENDPOINT = os.environ.get("WG_ENDPOINT", "193.134.209.54:51820")
WG_CLIENT_DNS = os.environ.get("WG_CLIENT_DNS", WG_SERVER_ADDRESS)
WG_CLIENT_ALLOWED_IPS = os.environ.get("WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0")
WG_CLIENT_KEEPALIVE = os.environ.get("WG_CLIENT_KEEPALIVE", "25")
WG_IP_ASSIGNMENT_MODE = os.environ.get("WG_IP_ASSIGNMENT_MODE", "dynamic").strip().lower()
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
OPENVPN_ENABLED = os.environ.get("OPENVPN_ENABLED", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
WIREGUARD_ENABLED = os.environ.get("VPN_ENABLE_WIREGUARD", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
SHADOWSOCKS_ENABLED = os.environ.get("SHADOWSOCKS_ENABLED", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
KCPTUN_ENABLED = os.environ.get("KCPTUN_ENABLED", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
SHADOWSOCKS_METHOD = (
    os.environ.get("SHADOWSOCKS_METHOD", "chacha20-ietf-poly1305").strip()
    or "chacha20-ietf-poly1305"
)
SHADOWSOCKS_PASSWORD = (
    os.environ.get("SHADOWSOCKS_PASSWORD", "").strip()
    or hashlib.sha256(
        (os.environ.get("PORTAL_SECRET_KEY", "change-this-secret") + ":shadowsocks").encode(
            "utf-8"
        )
    ).hexdigest()[:24]
)
SHADOWSOCKS_ENDPOINT_HOST = os.environ.get("SHADOWSOCKS_ENDPOINT_HOST", "").strip()
SHADOWSOCKS_SERVER_PORT_RAW = os.environ.get("SHADOWSOCKS_SERVER_PORT", "8388").strip()
KCPTUN_SERVER_PORT_RAW = os.environ.get("KCPTUN_SERVER_PORT", "29900").strip()
try:
    SHADOWSOCKS_SERVER_PORT = int(SHADOWSOCKS_SERVER_PORT_RAW)
except ValueError:
    SHADOWSOCKS_SERVER_PORT = 8388
if SHADOWSOCKS_SERVER_PORT <= 0 or SHADOWSOCKS_SERVER_PORT > 65535:
    SHADOWSOCKS_SERVER_PORT = 8388
try:
    KCPTUN_SERVER_PORT = int(KCPTUN_SERVER_PORT_RAW)
except ValueError:
    KCPTUN_SERVER_PORT = 29900
if KCPTUN_SERVER_PORT <= 0 or KCPTUN_SERVER_PORT > 65535:
    KCPTUN_SERVER_PORT = 29900
KCPTUN_KEY = (
    os.environ.get("KCPTUN_KEY", "").strip()
    or hashlib.sha256(
        (os.environ.get("PORTAL_SECRET_KEY", "change-this-secret") + ":kcptun").encode("utf-8")
    ).hexdigest()[:24]
)
OPENVPN_ENDPOINT_HOST = os.environ.get("OPENVPN_ENDPOINT_HOST", "").strip()
OPENVPN_ENDPOINT_PORT_RAW = os.environ.get("OPENVPN_ENDPOINT_PORT", "1194").strip()
try:
    OPENVPN_ENDPOINT_PORT = int(OPENVPN_ENDPOINT_PORT_RAW)
except ValueError:
    OPENVPN_ENDPOINT_PORT = 1194
if OPENVPN_ENDPOINT_PORT <= 0 or OPENVPN_ENDPOINT_PORT > 65535:
    OPENVPN_ENDPOINT_PORT = 1194
OPENVPN_PROTO = os.environ.get("OPENVPN_PROTO", "tcp").strip().lower() or "tcp"
OPENVPN_CLIENT_DNS = os.environ.get("OPENVPN_CLIENT_DNS", WG_CLIENT_DNS).strip()
OPENVPN_CIPHER = os.environ.get("OPENVPN_CIPHER", "AES-256-GCM").strip() or "AES-256-GCM"
OPENVPN_AUTH = os.environ.get("OPENVPN_AUTH", "SHA256").strip() or "SHA256"
OPENVPN_CLIENT_CERT_VALID_DAYS_RAW = os.environ.get(
    "OPENVPN_CLIENT_CERT_VALID_DAYS",
    "3650",
).strip()
try:
    OPENVPN_CLIENT_CERT_VALID_DAYS = max(30, int(OPENVPN_CLIENT_CERT_VALID_DAYS_RAW or 3650))
except ValueError:
    OPENVPN_CLIENT_CERT_VALID_DAYS = 3650
OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS_RAW = os.environ.get(
    "OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS",
    "30",
).strip()
try:
    OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS = max(
        1,
        int(OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS_RAW or 30),
    )
except ValueError:
    OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS = 30
OPENVPN_COMMON_NAME_PREFIX = "vpn-user-"
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
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
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
PLAN_DURATION_UNIT_DAY = "day"
PLAN_DURATION_UNIT_MONTH = "month"
PLAN_DURATION_UNIT_YEAR = "year"
PLAN_DURATION_UNITS = (
    PLAN_DURATION_UNIT_DAY,
    PLAN_DURATION_UNIT_MONTH,
    PLAN_DURATION_UNIT_YEAR,
)
WG_PROFILE_SMART = "smart"
WG_PROFILE_GLOBAL = "global"
WG_PROFILE_MODES = (WG_PROFILE_SMART, WG_PROFILE_GLOBAL)
PAYMENT_METHOD_USDT = "usdt"
PAYMENT_METHOD_CHOICES = (PAYMENT_METHOD_USDT,)
BYTES_PER_GB = 1024 * 1024 * 1024
SESSION_IDLE_TIMEOUT_MINUTES_RAW = os.environ.get(
    "PORTAL_SESSION_IDLE_TIMEOUT_MINUTES",
    "30",
).strip()
try:
    SESSION_IDLE_TIMEOUT_MINUTES = max(1, int(SESSION_IDLE_TIMEOUT_MINUTES_RAW))
except ValueError:
    SESSION_IDLE_TIMEOUT_MINUTES = 30
SESSION_IDLE_TIMEOUT_SECONDS = SESSION_IDLE_TIMEOUT_MINUTES * 60
SESSION_LAST_ACTIVITY_KEY = "last_activity_ts"
DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS_RAW = os.environ.get(
    "PORTAL_DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS",
    "2592000",  # 30 days
).strip()
try:
    DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS = max(
        300, int(DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS_RAW)
    )
except ValueError:
    DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS = 2592000
SSH_CONNECT_MAX_RETRIES_RAW = os.environ.get("PORTAL_SSH_CONNECT_MAX_RETRIES", "3").strip()
try:
    SSH_CONNECT_MAX_RETRIES = max(1, int(SSH_CONNECT_MAX_RETRIES_RAW))
except ValueError:
    SSH_CONNECT_MAX_RETRIES = 3
SSH_CONNECT_RETRY_DELAY_SECONDS_RAW = os.environ.get(
    "PORTAL_SSH_CONNECT_RETRY_DELAY_SECONDS", "2"
).strip()
try:
    SSH_CONNECT_RETRY_DELAY_SECONDS = max(0.0, float(SSH_CONNECT_RETRY_DELAY_SECONDS_RAW))
except ValueError:
    SSH_CONNECT_RETRY_DELAY_SECONDS = 2.0
SERVER_DEPLOY_SKIP_OS_UPGRADE = os.environ.get(
    "PORTAL_DEPLOY_SKIP_OS_UPGRADE",
    "1",
).strip().lower() in {"1", "true", "yes", "on"}
REGISTER_COOLDOWN_SECONDS = 5 * 60
EMAIL_CODE_TTL_MINUTES = 10
EMAIL_CODE_RESEND_SECONDS = 60
EMAIL_CODE_DAILY_LIMIT = 10
UNVERIFIED_USER_RETENTION_HOURS = 24
CAPTCHA_TTL_MINUTES = 5
CAPTCHA_SCENE_DEFAULT = "default"
CAPTCHA_SCENES = ("login", "register", "recover")
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F]")
EMAIL_CODE_PURPOSE_REGISTER = "register"
EMAIL_CODE_PURPOSE_RECOVER = "recover"
SETTING_REGISTRATION_OPEN = "registration_open"
SETTING_ORDER_EXPIRE_HOURS = "order_expire_hours"
SETTING_GIFT_DURATION_MONTHS = "gift_duration_months"
SETTING_GIFT_TRAFFIC_GB = "gift_traffic_gb"
SETTING_TELEGRAM_CONTACT = "telegram_contact"
SETTING_SITE_TITLE = "site_title"
SETTING_WIREGUARD_OPEN = "wireguard_open"
SETTING_OPENVPN_OPEN = "openvpn_open"
SETTING_SYSTEM_UPGRADE_STATUS = "system_upgrade_status"
SETTING_SYSTEM_UPGRADE_SUMMARY = "system_upgrade_summary"
SETTING_SYSTEM_UPGRADE_STARTED_AT = "system_upgrade_started_at"
SETTING_SYSTEM_UPGRADE_FINISHED_AT = "system_upgrade_finished_at"
MAIL_SECURITY_STARTTLS = "starttls"
MAIL_SECURITY_SSL = "ssl"
MAIL_SECURITY_NONE = "none"
MAIL_SECURITY_CHOICES = (
    MAIL_SECURITY_STARTTLS,
    MAIL_SECURITY_SSL,
    MAIL_SECURITY_NONE,
)
MAIL_SECURITY_LABELS = {
    MAIL_SECURITY_STARTTLS: "STARTTLS",
    MAIL_SECURITY_SSL: "SSL/TLS",
    MAIL_SECURITY_NONE: "无加密",
}
VPN_RELAY_ENABLED = os.environ.get("PORTAL_ENABLE_UDP_RELAY", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
VPN_RELAY_PUBLIC_HOST = os.environ.get("VPN_RELAY_PUBLIC_HOST", "").strip()
WG_RELAY_PORT_START_RAW = os.environ.get("WG_RELAY_PORT_START", "24000").strip()
WG_RELAY_PORT_END_RAW = os.environ.get("WG_RELAY_PORT_END", "28999").strip()
OPENVPN_RELAY_PORT_START_RAW = os.environ.get("OPENVPN_RELAY_PORT_START", "29000").strip()
OPENVPN_RELAY_PORT_END_RAW = os.environ.get("OPENVPN_RELAY_PORT_END", "33999").strip()
try:
    WG_RELAY_PORT_START = int(WG_RELAY_PORT_START_RAW)
except ValueError:
    WG_RELAY_PORT_START = 24000
try:
    WG_RELAY_PORT_END = int(WG_RELAY_PORT_END_RAW)
except ValueError:
    WG_RELAY_PORT_END = 28999
try:
    OPENVPN_RELAY_PORT_START = int(OPENVPN_RELAY_PORT_START_RAW)
except ValueError:
    OPENVPN_RELAY_PORT_START = 29000
try:
    OPENVPN_RELAY_PORT_END = int(OPENVPN_RELAY_PORT_END_RAW)
except ValueError:
    OPENVPN_RELAY_PORT_END = 33999
NODE_HEARTBEAT_TIMEOUT_SECONDS = 60
ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS_RAW = os.environ.get(
    "ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS", "180"
).strip()
ADMIN_ONLINE_REFRESH_SECONDS_RAW = os.environ.get("ADMIN_ONLINE_REFRESH_SECONDS", "5").strip()
try:
    ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS = max(
        30, int(ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS_RAW)
    )
except ValueError:
    ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS = 180
try:
    ADMIN_ONLINE_REFRESH_SECONDS = max(3, int(ADMIN_ONLINE_REFRESH_SECONDS_RAW))
except ValueError:
    ADMIN_ONLINE_REFRESH_SECONDS = 5
ADMIN_UI_TZ = timezone(timedelta(hours=8))
ADMIN_UI_TZ_NAME = "北京时间"
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
ONBOARDING_SETTING_DRAFT_SERVER_PRIVATE_KEY = "setup_draft_server_private_key"
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
    ONBOARDING_SETTING_DRAFT_SERVER_PRIVATE_KEY: "",
}
SERVER_DEPLOY_DEFAULT_WG_PORT = 29900
SERVER_DEPLOY_DEFAULT_OPENVPN_PORT = 8388
SERVER_DEPLOY_DEFAULT_DNS_PORT = 53
SERVER_DEPLOY_DEFAULT_VPN_API_PORT = 8081
PRD_BLOCKED_ADMIN_ENDPOINT_MARKERS = ("onboarding", "cloudflare", "payment_method")
PRD_BLOCKED_ADMIN_ENDPOINTS = {
    "admin_domains",
    "admin_create_domain",
    "admin_update_domain",
    "admin_toggle_domain",
    "admin_delete_domain",
    "admin_paid_orders",
}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET_KEY", "change-this-secret")
_CLIENT_ALLOWED_IPS_CACHE: str | None = None
_SMART_ALLOWED_IPS_CACHE: str | None = None
_OPENVPN_ROUTE_LINES_CACHE: list[str] | None = None
_OPENVPN_ROUTE_LINES_PROFILE_CACHE: dict[str, list[str]] = {}
SYSTEM_UPGRADE_LOG_TAIL_CHARS = 20000


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
    return dt.astimezone(ADMIN_UI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def format_admin_local_date_input(value: str | None) -> str:
    dt = parse_iso(value)
    if not dt:
        return ""
    return dt.astimezone(ADMIN_UI_TZ).strftime("%Y-%m-%d")


def format_admin_local_input(value: str | None) -> str:
    # Backward-compatible alias for templates still using fmt_local_input.
    return format_admin_local_date_input(value)


def parse_admin_local_date(raw: str) -> datetime:
    value = (raw or "").strip()
    local_dt = datetime.strptime(value, "%Y-%m-%d").replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
        tzinfo=ADMIN_UI_TZ,
    )
    return local_dt.astimezone(timezone.utc)


def parse_admin_local_datetime(raw: str) -> datetime:
    # Backward-compatible alias so older code paths still parse date-only values.
    return parse_admin_local_date(raw)


@app.template_filter("fmt_utc")
def fmt_utc_filter(value: str | None) -> str:
    return format_utc(value)


@app.template_filter("fmt_local_date_input")
def fmt_local_date_input_filter(value: str | None) -> str:
    return format_admin_local_date_input(value)


@app.template_filter("fmt_local_input")
def fmt_local_input_filter(value: str | None) -> str:
    return format_admin_local_date_input(value)


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


def normalize_duration_unit(unit: str | None) -> str:
    raw_unit = (unit or "").strip().lower()
    if raw_unit in PLAN_DURATION_UNITS:
        return raw_unit
    alias_map = {
        "d": PLAN_DURATION_UNIT_DAY,
        "day": PLAN_DURATION_UNIT_DAY,
        "days": PLAN_DURATION_UNIT_DAY,
        "天": PLAN_DURATION_UNIT_DAY,
        "m": PLAN_DURATION_UNIT_MONTH,
        "month": PLAN_DURATION_UNIT_MONTH,
        "months": PLAN_DURATION_UNIT_MONTH,
        "月": PLAN_DURATION_UNIT_MONTH,
        "个月": PLAN_DURATION_UNIT_MONTH,
        "y": PLAN_DURATION_UNIT_YEAR,
        "year": PLAN_DURATION_UNIT_YEAR,
        "years": PLAN_DURATION_UNIT_YEAR,
        "年": PLAN_DURATION_UNIT_YEAR,
    }
    return alias_map.get(raw_unit, PLAN_DURATION_UNIT_MONTH)


def plan_duration_unit_label(unit: str | None) -> str:
    normalized = normalize_duration_unit(unit)
    if normalized == PLAN_DURATION_UNIT_DAY:
        return "天"
    if normalized == PLAN_DURATION_UNIT_YEAR:
        return "年"
    return "个月"


def duration_value_to_legacy_months(value: int, unit: str | None) -> int:
    normalized_unit = normalize_duration_unit(unit)
    normalized_value = max(0, int(value or 0))
    if normalized_unit == PLAN_DURATION_UNIT_YEAR:
        return normalized_value * 12
    if normalized_unit == PLAN_DURATION_UNIT_MONTH:
        return normalized_value
    return 0


def resolve_duration_value_and_unit(
    *,
    duration_months: int,
    duration_value_raw,
    duration_unit_raw,
) -> tuple[int, str]:
    duration_value = to_non_negative_int(duration_value_raw)
    duration_unit = normalize_duration_unit(duration_unit_raw)
    if duration_value <= 0 and duration_months > 0:
        duration_value = duration_months
        duration_unit = PLAN_DURATION_UNIT_MONTH
    return duration_value, duration_unit


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


def format_plan_value(
    mode: str | None,
    duration_months: int,
    traffic_gb: int,
    *,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> str:
    normalized = normalize_plan_mode(mode)
    if normalized == PLAN_MODE_TRAFFIC:
        if traffic_gb <= 0:
            return "流量未设置"
        return f"{traffic_gb} GB"
    resolved_value, resolved_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=duration_value,
        duration_unit_raw=duration_unit,
    )
    if resolved_value <= 0:
        return "时长未设置"
    return f"{resolved_value} {plan_duration_unit_label(resolved_unit)}"


def format_plan_display_name(
    plan_name: str | None,
    mode: str | None,
    duration_months: int,
    traffic_gb: int,
    *,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> str:
    name = (plan_name or "").strip()
    mode_prefix = "时长" if normalize_plan_mode(mode) == PLAN_MODE_DURATION else "流量"
    value_text = format_plan_value(
        mode,
        duration_months,
        traffic_gb,
        duration_value=duration_value,
        duration_unit=duration_unit,
    )
    if name:
        return f"{name}（{mode_prefix} {value_text}）"
    return f"{mode_prefix} {value_text}"


def format_order_plan(order: sqlite3.Row | dict) -> str:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(order, "plan_duration_value", 0),
        duration_unit_raw=row_get(order, "plan_duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if duration_value <= 0:
        duration_value, duration_unit = resolve_duration_value_and_unit(
            duration_months=duration_months,
            duration_value_raw=duration_value,
            duration_unit_raw=duration_unit,
        )
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    return format_plan_display_name(
        plan_name,
        plan_mode,
        duration_months,
        traffic_gb,
        duration_value=duration_value,
        duration_unit=duration_unit,
    )


def resolve_order_plan_snapshot(order: sqlite3.Row | dict) -> dict:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(order, "plan_duration_value", 0),
        duration_unit_raw=row_get(order, "plan_duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if duration_value <= 0:
        duration_value, duration_unit = resolve_duration_value_and_unit(
            duration_months=duration_months,
            duration_value_raw=duration_value,
            duration_unit_raw=duration_unit,
        )
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    if not plan_name:
        plan_name = "流量套餐" if plan_mode == PLAN_MODE_TRAFFIC else "时长套餐"

    return {
        "plan_name": plan_name,
        "plan_mode": plan_mode,
        "duration_months": duration_months,
        "duration_value": duration_value,
        "duration_unit": duration_unit,
        "traffic_gb": traffic_gb,
        "display_name": format_plan_display_name(
            plan_name,
            plan_mode,
            duration_months,
            traffic_gb,
            duration_value=duration_value,
            duration_unit=duration_unit,
        ),
    }


@app.template_filter("fmt_order_plan")
def fmt_order_plan_filter(order: sqlite3.Row | dict) -> str:
    return format_order_plan(order)


def generate_plan_name(
    *,
    mode: str,
    duration_value: int | None = None,
    duration_unit: str | None = None,
    traffic_gb: int | None = None,
) -> str:
    normalized_mode = normalize_plan_mode(mode)
    if normalized_mode == PLAN_MODE_TRAFFIC:
        value = max(1, int(traffic_gb or 1))
        return f"{value}GB 流量包"
    value = max(1, int(duration_value or 1))
    unit_text = plan_duration_unit_label(duration_unit)
    return f"{value}{unit_text} 时长套餐"


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
    _CLIENT_ALLOWED_IPS_CACHE = "0.0.0.0/0"
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
    return "0.0.0.0/0"


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


def get_openvpn_endpoint_host(
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
) -> str:
    use_server = server_row
    if use_server is None and user is not None:
        try:
            db = get_db()
            use_server = get_persisted_runtime_server_for_account(db, user)
        except Exception:
            use_server = None

    def prefer_public_host(candidate: str | None) -> str:
        host = host_without_optional_port(candidate)
        if not host:
            return ""
        if is_non_public_host(host):
            return ""
        return host

    if use_server is not None:
        preferred_host = prefer_public_host(
            normalize_remote_host(row_get(use_server, "host", ""))
        )
        if preferred_host:
            return preferred_host
        preferred_domain = prefer_public_host(
            normalize_domain_host(row_get(use_server, "domain", ""))
        )
        if preferred_domain:
            return preferred_domain

    preferred_portal_domain = prefer_public_host(get_portal_domain_setting())
    if preferred_portal_domain:
        return preferred_portal_domain

    preferred_openvpn_host = prefer_public_host(OPENVPN_ENDPOINT_HOST)
    if preferred_openvpn_host:
        return preferred_openvpn_host

    wg_endpoint = (get_wireguard_endpoint_for_clients(user=user, server_row=server_row) or "").strip()
    preferred_wg_host = prefer_public_host(wg_endpoint)
    if preferred_wg_host:
        return preferred_wg_host

    try:
        preferred_request_host = prefer_public_host(request.host)
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
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
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
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
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
            normalize_remote_host(row_get(resolved_server, "host", ""))
        )
        candidate_port = normalize_server_port(
            row_get(resolved_server, "openvpn_port", OPENVPN_ENDPOINT_PORT),
            OPENVPN_ENDPOINT_PORT,
        )
        # 用户输入了公网服务器地址时，客户端配置优先直连该地址，避免被反向代理/内网地址覆盖。
        if candidate_host and not is_non_public_host(candidate_host):
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
    if not remote_host or is_non_public_host(remote_host):
        raise RuntimeError("未配置可用公网 OpenVPN 地址，请先设置服务器公网 IP 或域名。")
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
    mode = normalize_wg_profile_mode(profile_mode or default_profile_mode_from_policy())
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


def parse_int_setting(raw: str | None, default: int, *, min_value: int = 0) -> int:
    try:
        value = int((raw or "").strip())
    except Exception:
        value = default
    if value < min_value:
        return min_value
    return value


def ensure_default_system_settings(db: sqlite3.Connection) -> None:
    defaults = {
        SETTING_REGISTRATION_OPEN: "1",
        SETTING_ORDER_EXPIRE_HOURS: "24",
        SETTING_GIFT_DURATION_MONTHS: "0",
        SETTING_GIFT_TRAFFIC_GB: "0",
        SETTING_TELEGRAM_CONTACT: "",
        SETTING_SITE_TITLE: "新世界发展科技有限公司边缘节点网络管理系统",
        SETTING_WIREGUARD_OPEN: "0",
        SETTING_OPENVPN_OPEN: "0",
        SETTING_SYSTEM_UPGRADE_STATUS: "idle",
        SETTING_SYSTEM_UPGRADE_SUMMARY: "",
        SETTING_SYSTEM_UPGRADE_STARTED_AT: "",
        SETTING_SYSTEM_UPGRADE_FINISHED_AT: "",
    }
    for key, value in defaults.items():
        current = get_app_setting(db, key, "")
        if current == "":
            upsert_app_setting(db, key, value)


def normalize_mail_security(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in MAIL_SECURITY_CHOICES:
        return value
    return MAIL_SECURITY_STARTTLS


def format_mail_security_label(raw: str | None) -> str:
    return MAIL_SECURITY_LABELS.get(
        normalize_mail_security(raw),
        MAIL_SECURITY_LABELS[MAIL_SECURITY_STARTTLS],
    )


def format_sender_display(from_name: str | None, from_email: str | None) -> str:
    sender_name = (from_name or "").strip()
    sender_email = (from_email or "").strip()
    if sender_name and sender_email:
        return f"{sender_name} <{sender_email}>"
    return sender_email or "-"


def host_without_optional_port(raw_host: str | None) -> str:
    host = normalize_domain_host(raw_host)
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


def absolute_url_for(endpoint: str, **values) -> str:
    try:
        return url_for(endpoint, _external=True, **values)
    except Exception:
        path = url_for(endpoint, **values)
        host = ""
        try:
            host = (request.host_url or "").strip().rstrip("/")
        except Exception:
            host = ""
        if host:
            return f"{host}{path}"
        return path


def is_non_public_host(raw_host: str | None) -> bool:
    host = host_without_optional_port(raw_host).strip().lower().rstrip(".")
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


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

    wg_host = prefer_public_host(WG_ENDPOINT)
    if wg_host:
        return wg_host
    try:
        host = host_without_optional_port(request.host)
        if host and not is_non_public_host(host):
            return host
    except Exception:
        pass
    return ""


def allocate_user_ingress_port(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
    user: sqlite3.Row,
) -> tuple[int, int]:
    wg_port = row_get(user, "wg_ingress_port")
    openvpn_port = row_get(user, "openvpn_ingress_port")
    changed = False
    if wg_port is None or not str(wg_port).strip():
        wg_port = allocate_user_ingress_port(
            db,
            column_name="wg_ingress_port",
            start_port=WG_RELAY_PORT_START,
            end_port=WG_RELAY_PORT_END,
            exclude_user_id=int(user["id"]),
        )
        changed = True
    else:
        wg_port = int(wg_port)
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
        db.execute(
            """
            UPDATE users
            SET wg_ingress_port = ?,
                openvpn_ingress_port = ?
            WHERE id = ?
            """,
            (wg_port, openvpn_port, int(user["id"])),
        )
    return wg_port, openvpn_port


def get_wireguard_relay_endpoint(user: sqlite3.Row | None) -> str:
    if not VPN_RELAY_ENABLED or not user or row_get(user, "role") != "user":
        return ""
    host = get_relay_public_host()
    if not host:
        return ""
    port = row_get(user, "wg_ingress_port")
    if port is None or not str(port).strip():
        return ""
    return f"{host}:{int(port)}"


def get_openvpn_relay_endpoint(user: sqlite3.Row | None) -> tuple[str, int] | None:
    if not VPN_RELAY_ENABLED or not user or row_get(user, "role") != "user":
        return None
    host = get_relay_public_host()
    if not host:
        return None
    port = row_get(user, "openvpn_ingress_port")
    if port is None or not str(port).strip():
        return None
    return host, int(port)


def generate_openvpn_static_key_text() -> str:
    raw = os.urandom(256)
    hex_text = raw.hex()
    lines = [hex_text[i : i + 32] for i in range(0, len(hex_text), 32)]
    return "\n".join(
        [
            "#",
            "# 2048 bit OpenVPN static key",
            "#",
            "-----BEGIN OpenVPN Static key V1-----",
            *lines,
            "-----END OpenVPN Static key V1-----",
            "",
        ]
    )


def ensure_shared_wireguard_materials() -> tuple[str, str]:
    private_key = ""
    public_key = ""
    if SHARED_WG_PRIVATE_KEY_FILE.exists() and SHARED_WG_PUBLIC_KEY_FILE.exists():
        private_key = SHARED_WG_PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()
        public_key = SHARED_WG_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()
        if private_key and public_key:
            return private_key, public_key

    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_key = base64.b64encode(private_bytes).decode("ascii")
    public_key = base64.b64encode(public_bytes).decode("ascii")
    SHARED_WG_PRIVATE_KEY_FILE.write_text(private_key + "\n", encoding="utf-8")
    SHARED_WG_PUBLIC_KEY_FILE.write_text(public_key + "\n", encoding="utf-8")
    return private_key, public_key


def ensure_shared_openvpn_materials() -> dict[str, str]:
    required_files = {
        "ca_key": SHARED_OPENVPN_CA_KEY_FILE,
        "ca_cert": SHARED_OPENVPN_CA_CERT_FILE,
        "server_key": SHARED_OPENVPN_SERVER_KEY_FILE,
        "server_cert": SHARED_OPENVPN_SERVER_CERT_FILE,
        "tls_crypt_key": SHARED_OPENVPN_TLS_CRYPT_KEY_FILE,
    }
    if all(path.exists() and path.read_text(encoding="utf-8").strip() for path in required_files.values()):
        return {
            key: path.read_text(encoding="utf-8").strip()
            for key, path in required_files.items()
        }

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vpn-manager-ca"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vpn-manager-server"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    materials = {
        "ca_key": ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "ca_cert": ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "server_key": server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "tls_crypt_key": generate_openvpn_static_key_text(),
    }
    for key, path in required_files.items():
        path.write_text(materials[key].strip() + "\n", encoding="utf-8")
    return materials


def build_openvpn_common_name(user: sqlite3.Row) -> str:
    user_id = int(row_get(user, "id", 0) or 0)
    if user_id <= 0:
        raise RuntimeError("无法为用户生成 OpenVPN 身份。")
    return f"{OPENVPN_COMMON_NAME_PREFIX}{user_id}"


def parse_openvpn_user_id_from_common_name(common_name: str | None) -> int | None:
    value = (common_name or "").strip()
    if not value:
        return None
    match = re.fullmatch(rf"{re.escape(OPENVPN_COMMON_NAME_PREFIX)}(\d+)", value)
    if not match:
        return None
    try:
        user_id = int(match.group(1))
    except Exception:
        return None
    return user_id if user_id > 0 else None


def certificate_not_valid_before_utc(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    value = cert.not_valid_before
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def certificate_not_valid_after_utc(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    value = cert.not_valid_after
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def should_rotate_openvpn_client_identity(
    *,
    common_name: str,
    cert_text: str,
    key_text: str,
) -> bool:
    cert_raw = (cert_text or "").strip()
    key_raw = (key_text or "").strip()
    if not cert_raw or not key_raw:
        return True
    try:
        cert = x509.load_pem_x509_certificate(cert_raw.encode("utf-8"))
        private_key = serialization.load_pem_private_key(
            key_raw.encode("utf-8"),
            password=None,
        )
    except Exception:
        return True
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return True
    if (subject_cn or "").strip() != common_name:
        return True
    now = utcnow()
    if certificate_not_valid_before_utc(cert) > now + timedelta(minutes=5):
        return True
    renew_before = now + timedelta(days=max(1, OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS))
    if certificate_not_valid_after_utc(cert) <= renew_before:
        return True
    try:
        cert_public_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return True
    return cert_public_bytes != key_public_bytes


def issue_openvpn_client_identity(common_name: str) -> dict[str, str]:
    materials = ensure_shared_openvpn_materials()
    ca_key = serialization.load_pem_private_key(
        materials["ca_key"].encode("utf-8"),
        password=None,
    )
    ca_cert = x509.load_pem_x509_certificate(materials["ca_cert"].encode("utf-8"))
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utcnow()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager-client"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=OPENVPN_CLIENT_CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return {
        "openvpn_common_name": common_name,
        "openvpn_client_cert": cert.public_bytes(serialization.Encoding.PEM)
        .decode("utf-8")
        .strip(),
        "openvpn_client_key": client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip(),
    }


def ensure_user_openvpn_client_identity(
    db: sqlite3.Connection,
    user: sqlite3.Row,
) -> sqlite3.Row:
    common_name = build_openvpn_common_name(user)
    cert_text = (row_get(user, "openvpn_client_cert", "") or "").strip()
    key_text = (row_get(user, "openvpn_client_key", "") or "").strip()
    stored_common_name = (row_get(user, "openvpn_common_name", "") or "").strip()
    needs_rotate = stored_common_name != common_name or should_rotate_openvpn_client_identity(
        common_name=common_name,
        cert_text=cert_text,
        key_text=key_text,
    )
    if needs_rotate:
        bundle = issue_openvpn_client_identity(common_name)
        db.execute(
            """
            UPDATE users
            SET openvpn_common_name = ?,
                openvpn_client_cert = ?,
                openvpn_client_key = ?
            WHERE id = ?
            """,
            (
                bundle["openvpn_common_name"],
                bundle["openvpn_client_cert"],
                bundle["openvpn_client_key"],
                int(user["id"]),
            ),
        )
        refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
        if not refreshed:
            raise RuntimeError("OpenVPN 证书更新后用户不存在。")
        return refreshed
    if not stored_common_name:
        db.execute(
            "UPDATE users SET openvpn_common_name = ? WHERE id = ?",
            (common_name, int(user["id"])),
        )
        refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
        if refreshed:
            return refreshed
    return user


def ensure_shared_vpn_server_materials() -> dict[str, str]:
    wg_private_key, wg_public_key = ensure_shared_wireguard_materials()
    openvpn_materials = ensure_shared_openvpn_materials()
    return {
        "wg_private_key": wg_private_key,
        "wg_public_key": wg_public_key,
        **openvpn_materials,
    }


def load_system_settings(db: sqlite3.Connection) -> dict[str, int | bool | str]:
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
    wireguard_open_raw = get_app_setting(db, SETTING_WIREGUARD_OPEN, "0")
    openvpn_open_raw = get_app_setting(db, SETTING_OPENVPN_OPEN, "0")
    order_expire_hours = parse_int_setting(order_expire_hours_raw, 24, min_value=1)
    return {
        "registration_open": parse_bool_setting(registration_open_raw, True),
        "order_expire_hours": order_expire_hours,
        "gift_duration_months": parse_int_setting(gift_duration_months_raw, 0, min_value=0),
        "gift_traffic_gb": parse_int_setting(gift_traffic_gb_raw, 0, min_value=0),
        "telegram_contact": (telegram_contact or "").strip(),
        "site_title": (site_title or "").strip() or default_site_title,
        "wireguard_open": parse_bool_setting(wireguard_open_raw, False),
        "openvpn_open": parse_bool_setting(openvpn_open_raw, True),
    }


def get_current_app_version() -> str:
    version_file = BASE_DIR / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip() or "unknown"
    return "unknown"


def load_system_upgrade_state(db: sqlite3.Connection) -> dict[str, str]:
    return {
        "status": get_app_setting(db, SETTING_SYSTEM_UPGRADE_STATUS, "idle"),
        "summary": get_app_setting(db, SETTING_SYSTEM_UPGRADE_SUMMARY, ""),
        "started_at": get_app_setting(db, SETTING_SYSTEM_UPGRADE_STARTED_AT, ""),
        "finished_at": get_app_setting(db, SETTING_SYSTEM_UPGRADE_FINISHED_AT, ""),
        "version": get_current_app_version(),
    }


def load_system_upgrade_state_with_timeout_unlock(
    db: sqlite3.Connection,
) -> dict[str, str]:
    state = load_system_upgrade_state(db)
    status = (state.get("status") or "").strip().lower()
    if status != "running":
        return state

    started_at_raw = (state.get("started_at") or "").strip()
    started_at = parse_iso(started_at_raw)
    if not started_at:
        return state

    elapsed_seconds = (utcnow() - started_at).total_seconds()
    if elapsed_seconds < SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS:
        return state

    timeout_minutes = max(1, SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS // 60)
    summary = (
        f"系统升级任务超过 {timeout_minutes} 分钟未完成，已自动解锁。"
        "请重新发起升级。"
    )
    append_system_upgrade_log(
        "系统升级任务状态超时，自动解锁："
        f"started_at={started_at_raw}, timeout={SYSTEM_UPGRADE_RUNNING_TIMEOUT_SECONDS}s"
    )
    save_system_upgrade_state(
        status="failed",
        summary=summary,
        started_at=started_at_raw,
        finished_at=utcnow_iso(),
    )
    return load_system_upgrade_state(db)


def save_system_upgrade_state(
    *,
    status: str,
    summary: str,
    started_at: str = "",
    finished_at: str = "",
) -> None:
    conn = open_direct_db_connection()
    try:
        for key, value in (
            (SETTING_SYSTEM_UPGRADE_STATUS, status),
            (SETTING_SYSTEM_UPGRADE_SUMMARY, summary[:1000]),
            (SETTING_SYSTEM_UPGRADE_STARTED_AT, started_at),
            (SETTING_SYSTEM_UPGRADE_FINISHED_AT, finished_at),
        ):
            conn.execute(
                """
                INSERT INTO app_settings (setting_key, setting_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    updated_at = excluded.updated_at
                """,
                (key, value, utcnow_iso()),
            )
        conn.commit()
    finally:
        conn.close()


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


def resolve_host_web_upgrade_project_name() -> str:
    project_dir = (HOST_WEB_UPGRADE_PROJECT_DIR or "").strip().rstrip("/\\")
    raw_name = Path(project_dir).name if project_dir else ""
    normalized = re.sub(r"[^a-z0-9_-]+", "-", (raw_name or "").lower()).strip("-_")
    if not normalized:
        normalized = "vpn-platform-v1"
    if not normalized[0].isalnum():
        normalized = f"vpn{normalized}"
    return normalized


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
    compose_project_name = shlex.quote(resolve_host_web_upgrade_project_name())
    project_dir = shlex.quote(resolve_host_web_upgrade_project_dir())
    quoted_current_version = shlex.quote((current_version or "").strip() or "0")
    quoted_db_backend = shlex.quote(DB_BACKEND)
    quoted_postgres_dsn = shlex.quote(POSTGRES_DSN)
    return textwrap.dedent(
        f"""
        set -eu
        LOG_FILE=/app/data/system-upgrade.log
        DB_BACKEND={quoted_db_backend}
        POSTGRES_DSN={quoted_postgres_dsn}
        STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
        TARGET_BRANCH={branch}
        CURRENT_VERSION={quoted_current_version}
        COMPOSE_PROJECT_NAME={compose_project_name}
        PROJECT_DIR={project_dir}

        log() {{
          printf '[%s] %s\\n' "$(date -u +'%Y-%m-%d %H:%M:%S UTC')" "$1" | tee -a "$LOG_FILE"
        }}

        write_state() {{
          if ! command -v python3 >/dev/null 2>&1; then
            return 0
          fi
          python3 - "$1" "$2" "$3" "$4" <<'PY'
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
          retries="$1"
          delay="$2"
          shift 2

          attempt=1
          while true; do
            "$@" && return 0
            code=$?
            if [ "$attempt" -ge "$retries" ]; then
              return "$code"
            fi
            log "命令失败 (exit=$code)，${{delay}}s 后重试 $attempt/$retries: $*"
            attempt=$((attempt + 1))
            sleep "$delay"
          done
        }}

        success=0
        cleanup() {{
          code=$?
          if [ "$success" -ne 1 ]; then
            log "系统升级失败，退出码: $code"
            write_state "failed" "系统升级失败，请查看 system-upgrade.log" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
          fi
          exit $code
        }}
        trap cleanup EXIT

        : > "$LOG_FILE"
        log "宿主机升级任务已启动"
        apk add --no-cache git python3 >/dev/null
        apk add --no-cache py3-psycopg2 >/dev/null 2>&1 || true
        write_state "running" "系统升级进行中" "$STARTED_AT" ""
        if [ "$PROJECT_DIR" = "/workspace" ]; then
          log "Refusing upgrade: PROJECT_DIR cannot be /workspace."
          write_state "failed" "系统升级失败：项目目录配置错误(/workspace)." "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
          exit 1
        fi
        if [ ! -d "$PROJECT_DIR" ]; then
          log "Refusing upgrade: PROJECT_DIR does not exist: $PROJECT_DIR"
          write_state "failed" "系统升级失败：项目目录不存在。" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
          exit 1
        fi
        if [ ! -f "$PROJECT_DIR/docker-compose.yml" ] && [ ! -f "$PROJECT_DIR/compose.yml" ] && [ ! -f "$PROJECT_DIR/compose.yaml" ]; then
          log "Refusing upgrade: docker compose file not found under $PROJECT_DIR"
          write_state "failed" "系统升级失败：项目目录缺少 compose 文件。" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
          exit 1
        fi
        cd "$PROJECT_DIR"
        log "git fetch origin"
        git fetch origin
        REMOTE_VERSION="$(git show "origin/$TARGET_BRANCH:VERSION" 2>/dev/null | head -n 1 | tr -d '\\r' || true)"
        if [ -n "$REMOTE_VERSION" ]; then
          log "版本检查: 当前=$CURRENT_VERSION, 远端=$REMOTE_VERSION"
          if python3 - "$CURRENT_VERSION" "$REMOTE_VERSION" <<'PY'
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
            log "检测到更高版本，继续执行升级"
          else
            log "远端版本未高于当前版本，跳过升级"
            write_state "success" "远端版本($REMOTE_VERSION) 未高于当前版本($CURRENT_VERSION)，已跳过升级。" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
            success=1
            exit 0
          fi
        else
          log "未读取到远端 VERSION，继续执行升级"
        fi
        log "git checkout $TARGET_BRANCH"
        git checkout "$TARGET_BRANCH"
        log "git pull --ff-only origin $TARGET_BRANCH"
        git pull --ff-only origin "$TARGET_BRANCH"
        if [ "$DB_BACKEND" = "postgres" ]; then
          log "docker compose --project-directory $PROJECT_DIR --project-name $COMPOSE_PROJECT_NAME up -d postgres"
          retry_cmd 3 8 docker compose --project-directory "$PROJECT_DIR" --project-name "$COMPOSE_PROJECT_NAME" up -d postgres
        fi
        export COMPOSE_BAKE=0
        export DOCKER_BUILDKIT=0
        export COMPOSE_DOCKER_CLI_BUILD=0
        export COMPOSE_HTTP_TIMEOUT=300
        export DOCKER_CLIENT_TIMEOUT=300
        log "docker pull docker.m.daocloud.io/library/python:3.12-slim (best effort)"
        retry_cmd 3 8 docker pull docker.m.daocloud.io/library/python:3.12-slim || log "预拉取基础镜像失败，继续构建"
        log "docker compose --project-directory $PROJECT_DIR --project-name $COMPOSE_PROJECT_NAME build --pull web"
        retry_cmd 3 10 docker compose --project-directory "$PROJECT_DIR" --project-name "$COMPOSE_PROJECT_NAME" build --pull web
        log "docker compose --project-directory $PROJECT_DIR --project-name $COMPOSE_PROJECT_NAME up -d --no-deps web"
        retry_cmd 3 8 docker compose --project-directory "$PROJECT_DIR" --project-name "$COMPOSE_PROJECT_NAME" up -d --no-deps web
        success=1
        log "系统升级完成"
        write_state "success" "系统升级完成，请重新登录。" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
        """
    ).strip()


def dispatch_host_web_upgrade() -> tuple[bool, str]:
    if not DOCKER_SOCKET_FILE.exists():
        return False, "未检测到 Docker Socket，无法派发宿主机升级任务。"
    if not HOST_WEB_UPGRADE_PROJECT_DIR:
        return False, "未配置宿主机项目目录，无法升级。"
    project_dir = resolve_host_web_upgrade_project_dir()
    if not project_dir.startswith("/"):
        return False, "宿主机项目目录必须为绝对路径，无法升级。"
    if project_dir == "/workspace":
        return False, "宿主机项目目录不能为 /workspace，请改为真实部署目录后重试。"
    helper_script = build_host_web_upgrade_script(get_current_app_version())
    args = [
        "docker",
        "run",
        "-d",
        "--rm",
        "-v",
        f"{DOCKER_SOCKET_FILE}:{DOCKER_SOCKET_FILE}",
        "-v",
        f"{project_dir}:{project_dir}",
        "-v",
        f"{HOST_WEB_UPGRADE_DATA_VOLUME}:/app/data",
        "-w",
        project_dir,
        HOST_WEB_UPGRADE_HELPER_IMAGE,
        "sh",
        "-lc",
        helper_script,
    ]
    code, output = run_local_command_with_output(args, cwd=BASE_DIR)
    if code != 0:
        return False, output or "宿主机升级任务派发失败。"
    return True, output.strip() or "宿主机升级任务已派发。"


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
    append_system_upgrade_log(f"当前版本: {get_current_app_version()}")

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

    version_after = get_current_app_version()
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


def is_registration_open(db: sqlite3.Connection | None = None) -> bool:
    use_db = db or get_db()
    return bool(load_system_settings(use_db)["registration_open"])


def get_order_expire_hours(db: sqlite3.Connection | None = None) -> int:
    use_db = db or get_db()
    return int(load_system_settings(use_db)["order_expire_hours"])


def get_gift_settings(db: sqlite3.Connection | None = None) -> tuple[int, int]:
    use_db = db or get_db()
    settings = load_system_settings(use_db)
    return (
        int(settings["gift_duration_months"]),
        int(settings["gift_traffic_gb"]),
    )


def is_wireguard_open(db: sqlite3.Connection | None = None) -> bool:
    use_db = db or get_db()
    return bool(WIREGUARD_ENABLED and bool(load_system_settings(use_db)["wireguard_open"]))


def is_openvpn_open(db: sqlite3.Connection | None = None) -> bool:
    use_db = db or get_db()
    return bool(OPENVPN_ENABLED and bool(load_system_settings(use_db)["openvpn_open"]))


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
    db: sqlite3.Connection,
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


def get_admin_onboarding_step_status(db: sqlite3.Connection) -> tuple[dict[int, bool], int]:
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


def normalize_fqdn(raw_domain: str | None) -> str:
    return normalize_domain_host(raw_domain).strip().strip(".").lower()


def looks_like_email(raw_email: str | None) -> bool:
    value = (raw_email or "").strip()
    return "@" in value and "." in value.rsplit("@", 1)[-1]


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


def get_wireguard_endpoint_for_clients(
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
) -> str:
    use_server = server_row
    if use_server is None and user is not None:
        try:
            db = get_db()
            use_server = get_persisted_runtime_server_for_account(db, user)
        except Exception:
            use_server = None

    if use_server is not None:
        domain = normalize_domain_host(row_get(use_server, "domain", ""))
        host = domain or normalize_remote_host(row_get(use_server, "host", ""))
        if host:
            wg_port = normalize_server_port(
                row_get(use_server, "wg_port", SERVER_DEPLOY_DEFAULT_WG_PORT),
                SERVER_DEPLOY_DEFAULT_WG_PORT,
            )
            if host.startswith("[") and "]" in host:
                idx = host.find("]")
                if idx > 0 and len(host) > idx + 2 and host[idx + 1] == ":":
                    return host
                return f"{host}:{wg_port}"
            if host.count(":") == 1:
                host_part, port_part = host.rsplit(":", 1)
                if host_part and port_part.isdigit():
                    return host
            return f"{host}:{wg_port}"

    wg_endpoint = (WG_ENDPOINT or "").strip()
    if wg_endpoint:
        return wg_endpoint

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


def load_subscription_plans(db: sqlite3.Connection, *, active_only: bool = False) -> list[dict]:
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


def normalize_server_region(raw: str | None) -> str:
    return (raw or "").strip()[:80]


def normalize_relay_port(value, default: int) -> int:
    try:
        port = int(value)
    except Exception:
        port = default
    if port <= 1024 or port > 65535:
        return default
    return port


def append_system_upgrade_log(message: str) -> None:
    SYSTEM_UPGRADE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with SYSTEM_UPGRADE_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message.rstrip()}\n")


def read_system_upgrade_log_text(limit_chars: int = SYSTEM_UPGRADE_LOG_TAIL_CHARS) -> str:
    if not SYSTEM_UPGRADE_LOG_FILE.exists():
        return ""
    try:
        raw = SYSTEM_UPGRADE_LOG_FILE.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    text = normalize_deploy_log_text(raw)
    if limit_chars > 0 and len(text) > limit_chars:
        return "...(log truncated)\n" + text[-limit_chars:]
    return text


def run_local_command_with_output(args: list[str], *, cwd: Path | None = None) -> tuple[int, str]:
    completed = subprocess.run(
        args,
        cwd=str(cwd or BASE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    merged = "\n".join(
        part.strip() for part in [completed.stdout or "", completed.stderr or ""] if part.strip()
    ).strip()
    return completed.returncode, merged


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


def normalize_deploy_log_text(raw: str) -> str:
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    text = ANSI_ESCAPE_RE.sub("", text)
    text = CONTROL_CHAR_RE.sub("", text)
    normalized_lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(normalized_lines).strip()


def build_structured_deploy_log(
    *,
    host: str,
    port: int,
    username: str,
    started_at: datetime,
    ended_at: datetime,
    script_text: str,
    script_executed: bool,
    exit_code: int | None = None,
    stdout_text: str = "",
    stderr_text: str = "",
    error_text: str = "",
) -> str:
    started = started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ended = ended_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    host_display = f"{normalize_remote_host(host)}:{normalize_server_port(port, 22)}"
    user_display = (username or "").strip() or "root"
    script_line_count = max(1, len((script_text or "").splitlines()))
    out_clean = normalize_deploy_log_text(stdout_text)
    err_clean = normalize_deploy_log_text(stderr_text)
    exc_clean = normalize_deploy_log_text(error_text)
    lines: list[str] = [
        "[deploy] 任务信息",
        f"开始时间: {started}",
        f"结束时间: {ended}",
        f"目标主机: {host_display}",
        f"SSH用户: {user_display}",
        "远程命令: bash -s (stdin install script)",
        f"脚本行数: {script_line_count}",
        "脚本步骤: 升级系统并安装依赖 -> 拉取 GitHub 仓库 -> 启动本地 systemd 服务 vpnmanager-server",
        f"脚本是否执行: {'是' if script_executed else '否'}",
        f"退出码: {exit_code if exit_code is not None else '-'}",
        "",
        "[deploy] stdout",
        out_clean if out_clean else "(empty)",
        "",
        "[deploy] stderr",
        err_clean if err_clean else "(empty)",
    ]
    if exc_clean:
        lines.extend(
            [
                "",
                "[deploy] 异常",
                exc_clean,
            ]
        )
    return "\n".join(lines).strip()


def clip_text(raw: str, limit: int = 200000) -> str:
    text = (raw or "").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def load_admin_servers(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        """
        SELECT
            id,
            server_name,
            server_region,
            host,
            port,
            username,
            password,
            ssh_private_key,
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
            last_deploy_log,
            last_allocated_at,
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
                "server_region": normalize_server_region(row["server_region"]),
                "server_region_display": normalize_server_region(row["server_region"]) or "未设置",
                "host": (row["host"] or "").strip(),
                "port": normalize_server_port(row["port"], 22),
                "username": (row["username"] or "").strip(),
                "password_masked": mask_secret(row["password"] or ""),
                "private_key_enabled": bool((row["ssh_private_key"] or "").strip()),
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
                "has_deploy_log": bool((row["last_deploy_log"] or "").strip()),
                "last_allocated_at": row["last_allocated_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return servers


def get_server_by_id(db: sqlite3.Connection, server_id: int | None) -> sqlite3.Row | None:
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


def is_runtime_server_ready(server_row: sqlite3.Row | None) -> bool:
    if not server_row:
        return False
    status = (row_get(server_row, "status", "") or "").strip().lower()
    host = normalize_remote_host(row_get(server_row, "host", ""))
    token = (row_get(server_row, "vpn_api_token", "") or "").strip()
    return status == "online" and bool(host) and bool(token)


def get_persisted_runtime_server_for_account(
    db: sqlite3.Connection,
    user: sqlite3.Row | None,
) -> sqlite3.Row | None:
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


def load_user_selectable_servers(
    db: sqlite3.Connection,
    user: sqlite3.Row,
) -> list[dict]:
    preferred_server_id = row_get(user, "preferred_server_id")
    assigned_server_id = row_get(user, "assigned_server_id")
    rows = db.execute(
        """
        SELECT
            s.id,
            s.server_name,
            s.server_region,
            s.host,
            s.domain,
            s.status,
            s.last_allocated_at,
            COUNT(u.id) AS active_user_count
        FROM vpn_servers s
        LEFT JOIN users u
          ON u.assigned_server_id = s.id
         AND u.role = 'user'
         AND u.wg_enabled = 1
        WHERE s.status = 'online'
        GROUP BY s.id
        ORDER BY
            CASE WHEN TRIM(COALESCE(s.server_region, '')) = '' THEN 1 ELSE 0 END,
            s.server_region ASC,
            s.server_name ASC,
            s.id ASC
        """
    ).fetchall()
    result: list[dict] = []
    for row in rows:
        server_name = (row["server_name"] or "").strip() or (row["host"] or "").strip()
        server_region = normalize_server_region(row["server_region"])
        host = normalize_remote_host(row["host"])
        domain = normalize_domain_host(row["domain"])
        result.append(
            {
                "id": int(row["id"]),
                "server_name": server_name,
                "server_region": server_region,
                "server_region_display": server_region or "未设置地区",
                "host": host,
                "endpoint_host": domain or host,
                "active_user_count": int(row["active_user_count"] or 0),
                "is_preferred": bool(
                    preferred_server_id is not None
                    and str(preferred_server_id).strip()
                    and int(preferred_server_id) == int(row["id"])
                ),
                "is_current": bool(
                    assigned_server_id is not None
                    and str(assigned_server_id).strip()
                    and int(assigned_server_id) == int(row["id"])
                ),
            }
        )
    return result


def serialize_runtime_server(server_row: sqlite3.Row | None) -> dict[str, int | str] | None:
    if not server_row:
        return None
    server_name = (row_get(server_row, "server_name", "") or "").strip() or (
        row_get(server_row, "host", "") or ""
    ).strip()
    server_region = normalize_server_region(row_get(server_row, "server_region", ""))
    host = normalize_remote_host(row_get(server_row, "host", ""))
    domain = normalize_domain_host(row_get(server_row, "domain", ""))
    return {
        "id": int(row_get(server_row, "id", 0) or 0),
        "server_name": server_name,
        "server_region": server_region,
        "server_region_display": server_region or "未设置地区",
        "host": host,
        "endpoint_host": domain or host,
        "display_name": (
            f"{server_region} / {server_name}" if server_region else server_name
        )
        or host,
    }


def pick_best_online_server(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT
            s.*,
            COUNT(u.id) AS active_user_count
        FROM vpn_servers s
        LEFT JOIN users u
          ON u.assigned_server_id = s.id
         AND u.role = 'user'
         AND u.wg_enabled = 1
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
    db: sqlite3.Connection,
    user: sqlite3.Row,
    *,
    allow_reassign: bool = True,
) -> sqlite3.Row | None:
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
    db: sqlite3.Connection,
    admin_user: sqlite3.Row | None = None,
) -> sqlite3.Row | None:
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
    db: sqlite3.Connection,
    user: sqlite3.Row | None,
    *,
    allow_reassign: bool = True,
) -> sqlite3.Row | None:
    if not user:
        return None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role == "user":
        return choose_runtime_server_for_user(db, user, allow_reassign=allow_reassign)
    if role == "admin":
        return choose_runtime_server_for_admin(db, user)
    return None


def user_prefers_managed_nodes(db: sqlite3.Connection, user: sqlite3.Row | None) -> bool:
    if not user or row_get(user, "role") != "user":
        return False
    if VPN_API_URL:
        return True
    if row_get(user, "assigned_server_id"):
        return True
    row = db.execute("SELECT id FROM vpn_servers LIMIT 1").fetchone()
    return bool(row)


def load_cloudflare_accounts(db: sqlite3.Connection, *, active_only: bool = False) -> list[dict]:
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


def get_default_cloudflare_account_id(db: sqlite3.Connection) -> int | None:
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


def load_mail_servers(db: sqlite3.Connection, *, active_only: bool = False) -> list[dict]:
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
    db: sqlite3.Connection,
    mail_server_id: int | None,
) -> sqlite3.Row | None:
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
    db: sqlite3.Connection | None = None,
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
    db: sqlite3.Connection | None = None,
) -> dict[str, int | str] | None:
    active_config = get_active_mail_server_config(db)
    if active_config:
        return active_config
    return load_env_mail_server_config()


def is_email_verification_available(
    db: sqlite3.Connection | None = None,
) -> bool:
    return resolve_runtime_mail_server_config(db) is not None


def set_active_mail_server(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
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


def load_available_managed_domains(db: sqlite3.Connection) -> list[dict]:
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
    db: sqlite3.Connection,
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
        """,
        (
            normalized_domain,
            cloudflare_account_id,
            max(0, int(sort_order or 0)),
            now_iso,
            now_iso,
        ),
    )
    return int(cursor.lastrowid)


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
    db: sqlite3.Connection,
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
            domain_id = int(cursor.lastrowid)
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
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
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

    def pick_domain_row() -> sqlite3.Row | None:
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


def release_server_domain_bindings(db: sqlite3.Connection, server_id: int) -> None:
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
    db: sqlite3.Connection,
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
    return int(cursor.lastrowid)


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


def set_server_ipv6_state(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    private_key_text: str,
    enable: bool,
) -> tuple[bool, str]:
    target_value = "0" if enable else "1"
    action_text = "开启" if enable else "关闭"
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
    db: sqlite3.Connection, *, force: bool = False
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
    wg_port: int,
    openvpn_port: int,
    dns_port: int,
    skip_os_upgrade: bool,
    wg_private_key_b64: str,
    wg_public_key_b64: str,
    openvpn_ca_cert_b64: str,
    openvpn_server_cert_b64: str,
    openvpn_server_key_b64: str,
    openvpn_tls_crypt_key_b64: str,
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
        export KCPTUN_SERVER_PORT="{wg_port}"
        export SHADOWSOCKS_SERVER_PORT="{openvpn_port}"
        export SHADOWSOCKS_METHOD="{SHADOWSOCKS_METHOD}"
        export SHADOWSOCKS_PASSWORD="{SHADOWSOCKS_PASSWORD}"
        export KCPTUN_KEY="{KCPTUN_KEY}"
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
    wg_port: int,
    openvpn_port: int,
    dns_port: int,
    vpn_api_token: str | None = None,
) -> tuple[bool, str, str, str]:
    safe_token = (vpn_api_token or "").strip()
    if not safe_token:
        safe_token = hashlib.sha256(os.urandom(32)).hexdigest()[:48]
    shared_materials = ensure_shared_vpn_server_materials()

    normalized_host = normalize_remote_host(host)
    normalized_port = normalize_server_port(port, 22)
    normalized_user = (username or "").strip()
    script = build_vpn_node_deploy_script(
        vpn_api_token=safe_token,
        wg_port=normalize_server_port(wg_port, SERVER_DEPLOY_DEFAULT_WG_PORT),
        openvpn_port=normalize_server_port(
            openvpn_port, SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
        ),
        dns_port=normalize_server_port(dns_port, SERVER_DEPLOY_DEFAULT_DNS_PORT),
        skip_os_upgrade=SERVER_DEPLOY_SKIP_OS_UPGRADE,
        wg_private_key_b64=base64.b64encode(
            shared_materials["wg_private_key"].encode("utf-8")
        ).decode("ascii"),
        wg_public_key_b64=base64.b64encode(
            shared_materials["wg_public_key"].encode("utf-8")
        ).decode("ascii"),
        openvpn_ca_cert_b64=base64.b64encode(
            shared_materials["ca_cert"].encode("utf-8")
        ).decode("ascii"),
        openvpn_server_cert_b64=base64.b64encode(
            shared_materials["server_cert"].encode("utf-8")
        ).decode("ascii"),
        openvpn_server_key_b64=base64.b64encode(
            shared_materials["server_key"].encode("utf-8")
        ).decode("ascii"),
        openvpn_tls_crypt_key_b64=base64.b64encode(
            shared_materials["tls_crypt_key"].encode("utf-8")
        ).decode("ascii"),
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


def _replace_qmark_placeholders(sql: str) -> str:
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'" and not in_double:
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if ch == "?" and not in_single and not in_double:
            out.append("%s")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _translate_postgres_sql(sql: str, params) -> tuple[str, tuple | list]:
    text = sql.strip()
    upper = text.upper()
    if upper.startswith("PRAGMA TABLE_INFO("):
        match = re.search(r"PRAGMA\s+table_info\(\s*([^)]+?)\s*\)", text, re.IGNORECASE)
        if match:
            table_name = match.group(1).strip().strip("'\"")
            return (
                """
                SELECT column_name AS name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position
                """,
                (table_name,),
            )
    if upper.startswith("PRAGMA"):
        return "SELECT 1", ()
    if upper.startswith("BEGIN IMMEDIATE"):
        return "BEGIN", ()

    normalized = re.sub(
        r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
        "BIGSERIAL PRIMARY KEY",
        sql,
        flags=re.IGNORECASE,
    )
    if re.search(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+users\b", normalized, re.IGNORECASE):
        normalized = re.sub(
            r",\s*FOREIGN KEY\s*\(assigned_server_id\)\s*REFERENCES\s+vpn_servers\s*\(id\)\s*ON DELETE SET NULL\s*",
            "",
            normalized,
            flags=re.IGNORECASE | re.DOTALL,
        )
    normalized = normalized.replace("COLLATE NOCASE", "")
    normalized = re.sub(
        r"SELECT\s+last_insert_rowid\(\)\s+AS\s+lid",
        "SELECT LASTVAL() AS lid",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = _replace_qmark_placeholders(normalized)
    return normalized, params


class PostgresCompatCursor:
    def __init__(self, conn, cursor, *, translated_sql: str):
        self._conn = conn
        self._cursor = cursor
        self._translated_sql = translated_sql
        self._cached_lastrowid = None

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        if self._cached_lastrowid is not None:
            return self._cached_lastrowid
        try:
            cur = self._conn.cursor(row_factory=dict_row)
            cur.execute("SELECT LASTVAL() AS lid")
            row = cur.fetchone() or {}
            self._cached_lastrowid = row.get("lid")
        except Exception:
            self._cached_lastrowid = None
        return self._cached_lastrowid


class PostgresCompatConnection:
    def __init__(self, raw_conn):
        self._raw_conn = raw_conn
        self.backend = "postgres"

    def execute(self, sql: str, params=()):
        translated_sql, translated_params = _translate_postgres_sql(sql, params)
        cur = self._raw_conn.cursor(row_factory=dict_row)
        if translated_params is None:
            translated_params = ()
        cur.execute(translated_sql, translated_params)
        return PostgresCompatCursor(
            self._raw_conn,
            cur,
            translated_sql=translated_sql,
        )

    def commit(self):
        self._raw_conn.commit()

    def rollback(self):
        self._raw_conn.rollback()

    def close(self):
        self._raw_conn.close()


def connect_postgres_db() -> PostgresCompatConnection:
    if not POSTGRES_DSN:
        raise RuntimeError("PORTAL_POSTGRES_DSN is empty")
    raw_conn = psycopg.connect(POSTGRES_DSN, autocommit=False)
    return PostgresCompatConnection(raw_conn)


def open_direct_db_connection():
    return connect_postgres_db()


def begin_immediate(db) -> None:
    db.execute("BEGIN")


DB_INTEGRITY_ERRORS = (psycopg.IntegrityError,)


def get_db():
    if "db" not in g:
        g.db = connect_postgres_db()
    return g.db


@app.teardown_appcontext
def close_db(_exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def migrate_sqlite_to_postgres_if_needed(db) -> None:
    if DB_BACKEND != "postgres":
        return
    if SKIP_SQLITE_IMPORT:
        return
    if get_app_setting(db, "sqlite_migration_done", ""):
        return
    source_path = LEGACY_SQLITE_MIGRATION_SOURCE
    if not source_path.exists() or source_path.stat().st_size <= 0:
        return

    try:
        src = sqlite3.connect(source_path)
        src.row_factory = sqlite3.Row
    except Exception:
        return

    try:
        source_users_exists = (
            src.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone()
            is not None
        )
        if not source_users_exists:
            return
        source_user_count = int(
            (src.execute("SELECT COUNT(*) AS cnt FROM users").fetchone() or {"cnt": 0})[
                "cnt"
            ]
            or 0
        )
        target_user_count = int(
            (db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone() or {"cnt": 0})[
                "cnt"
            ]
            or 0
        )
        if source_user_count <= 0 or target_user_count > 0:
            upsert_app_setting(db, "sqlite_migration_done", utcnow_iso())
            db.commit()
            return

        table_order = (
            "vpn_servers",
            "cloudflare_accounts",
            "users",
            "managed_domains",
            "subscription_plans",
            "payment_methods",
            "payment_orders",
            "email_verifications",
            "mail_servers",
            "registration_limits",
            "app_settings",
        )
        for table in table_order:
            src_exists = src.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if not src_exists:
                continue

            src_cols = [
                row["name"] for row in src.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            dst_cols = [
                row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            shared_cols = [name for name in dst_cols if name in src_cols]
            if not shared_cols:
                continue

            select_sql = f"SELECT {', '.join(shared_cols)} FROM {table}"
            rows = src.execute(select_sql).fetchall()
            if not rows:
                continue
            insert_sql = (
                f"INSERT INTO {table} ({', '.join(shared_cols)}) "
                f"VALUES ({', '.join('?' for _ in shared_cols)}) ON CONFLICT DO NOTHING"
            )
            for row in rows:
                db.execute(insert_sql, tuple(row[col] for col in shared_cols))

            if "id" in shared_cols:
                db.execute(
                    f"""
                    SELECT setval(
                        pg_get_serial_sequence('{table}', 'id'),
                        COALESCE((SELECT MAX(id) FROM {table}), 1),
                        (SELECT COUNT(*) > 0 FROM {table})
                    )
                    """
                )

        upsert_app_setting(db, "sqlite_migration_done", utcnow_iso())
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        with contextlib.suppress(Exception):
            src.close()


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
            email_verified INTEGER NOT NULL DEFAULT 1,
            preferred_server_id INTEGER,
            assigned_server_id INTEGER,
            wg_ingress_port INTEGER,
            openvpn_ingress_port INTEGER,
            assigned_ip TEXT,
            client_private_key TEXT,
            client_public_key TEXT,
            client_psk TEXT,
            openvpn_common_name TEXT,
            openvpn_client_cert TEXT,
            openvpn_client_key TEXT,
            config_path TEXT,
            qr_path TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            subscription_expires_at TEXT,
            wg_enabled INTEGER NOT NULL DEFAULT 0,
            traffic_quota_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
            traffic_last_total_bytes INTEGER NOT NULL DEFAULT 0,
            force_password_change INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (assigned_server_id) REFERENCES vpn_servers(id) ON DELETE SET NULL
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
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            server_region TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ssh_private_key TEXT NOT NULL DEFAULT '',
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    migrate_sqlite_to_postgres_if_needed(db)
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
        "CREATE INDEX IF NOT EXISTS idx_users_preferred_server ON users(preferred_server_id)"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_wg_ingress_port ON users(wg_ingress_port) WHERE wg_ingress_port IS NOT NULL"
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
    if "email_verified" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
    if "preferred_server_id" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN preferred_server_id INTEGER")
    if "assigned_server_id" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN assigned_server_id INTEGER")
    if "wg_ingress_port" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN wg_ingress_port INTEGER")
    if "openvpn_ingress_port" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_ingress_port INTEGER")
    if "openvpn_common_name" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_common_name TEXT")
    if "openvpn_client_cert" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_client_cert TEXT")
    if "openvpn_client_key" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN openvpn_client_key TEXT")
    if "session_version" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(subscription_plans)").fetchall()
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
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(email_verifications)").fetchall()
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(mail_servers)").fetchall()
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            server_region TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ssh_private_key TEXT NOT NULL DEFAULT '',
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
            last_deploy_log TEXT,
            last_allocated_at TEXT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(cloudflare_accounts)").fetchall()
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        for row in db.execute("PRAGMA table_info(managed_domains)").fetchall()
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
    return user


def build_download_access_token(user, scope: str) -> str:
    user_id = int(row_get(user, "id", 0) or 0)
    session_version = int(row_get(user, "session_version", 1) or 1)
    now_ts = int(time.time())
    payload_obj = {
        "uid": user_id,
        "sv": session_version,
        "scp": str(scope or "").strip(),
        "iat": now_ts,
        "exp": now_ts + DOWNLOAD_ACCESS_TOKEN_TTL_SECONDS,
        "rnd": secrets.token_urlsafe(18),
    }
    payload = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    secret = str(app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
    signature = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def resolve_download_access_user(
    db: sqlite3.Connection,
    access_token: str,
    scope: str,
):
    token = (access_token or "").strip()
    if not token:
        return None

    # New opaque token format: base64url(payload_json).hex_hmac
    parts = token.split(".")
    if len(parts) == 2:
        payload_b64, signature = parts
        if payload_b64 and signature:
            secret = str(app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
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
                    now_ts = int(time.time())
                    if (
                        token_scope == str(scope or "").strip()
                        and user_id > 0
                        and session_version > 0
                        and expire_ts >= now_ts
                    ):
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

    # Legacy format compatibility: user_id.session_version.hex_hmac
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
    secret = str(app.config.get("SECRET_KEY", "change-this-secret")).encode("utf-8")
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
    system_settings = load_system_settings(db)
    return {
        "current_user": current_user(),
        "usdt_receive_address": payment_settings["usdt_receive_address"],
        "usdt_default_network": payment_settings["usdt_default_network"],
        "usdt_network_options": USDT_NETWORK_OPTIONS,
        "wireguard_enabled": bool(WIREGUARD_ENABLED and system_settings["wireguard_open"]),
        "openvpn_enabled": bool(OPENVPN_ENABLED and system_settings["openvpn_open"]),
        "shadowsocks_enabled": bool(SHADOWSOCKS_ENABLED),
        "kcptun_enabled": bool(KCPTUN_ENABLED),
        "registration_open": bool(system_settings["registration_open"]),
        "telegram_contact": str(system_settings["telegram_contact"]),
        "site_title": str(system_settings["site_title"]),
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
    return redirect(url_for("admin_home"))


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


def use_vpn_api(*, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None) -> bool:
    if server_row is not None:
        host = normalize_remote_host(row_get(server_row, "host", ""))
        token = (row_get(server_row, "vpn_api_token", "") or "").strip()
        return bool(host and token)
    api_url, _, _ = get_runtime_vpn_api_target(user=user)
    return bool(api_url)


def host_for_http_url(raw_host: str) -> str:
    host = (raw_host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def get_runtime_vpn_api_target(
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
    allow_reassign: bool = True,
) -> tuple[str, str, sqlite3.Row | None]:
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
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
    allow_reassign: bool = True,
) -> dict:
    runtime_api_url, runtime_api_token, _ = get_runtime_vpn_api_target(
        user=user,
        server_row=server_row,
        allow_reassign=allow_reassign,
    )
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


def iter_runtime_vpn_api_targets(db: sqlite3.Connection) -> list[sqlite3.Row | None]:
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
    db: sqlite3.Connection,
    *,
    wireguard_open: bool,
    openvpn_open: bool,
) -> None:
    for target in iter_runtime_vpn_api_targets(db):
        vpn_api_request(
            "POST",
            "/wireguard/control",
            {"action": "up" if wireguard_open else "down"},
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


def get_wireguard_dump_text(
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
) -> str:
    if use_vpn_api(user=user, server_row=server_row):
        result = vpn_api_request(
            "GET",
            "/wireguard/dump",
            user=user,
            server_row=server_row,
        )
        return str(result.get("dump") or "")
    return run_command(["wg", "show", WG_INTERFACE, "dump"], check=False)


def parse_wireguard_dump_peers(dump_text: str) -> dict[str, dict[str, int | str]]:
    peers: dict[str, dict[str, int | str]] = {}
    lines = (dump_text or "").splitlines()
    if not lines:
        return peers

    for line in lines[1:]:
        parts = (line or "").split("\t")
        if len(parts) < 7:
            continue
        public_key = (parts[0] or "").strip()
        if not public_key:
            continue
        endpoint = (parts[2] or "").strip() if len(parts) > 2 else ""
        try:
            latest_handshake = int(parts[4])
        except Exception:
            latest_handshake = 0
        try:
            rx = int(parts[5])
        except Exception:
            rx = 0
        try:
            tx = int(parts[6])
        except Exception:
            tx = 0
        peers[public_key] = {
            "rx": max(0, rx),
            "tx": max(0, tx),
            "latest_handshake": max(0, latest_handshake),
            "endpoint": endpoint,
        }
    return peers


def get_wireguard_server_public_key(
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
) -> str:
    if use_vpn_api(user=user, server_row=server_row):
        result = vpn_api_request(
            "GET",
            "/wireguard/server-public-key",
            user=user,
            server_row=server_row,
        )
        key = (result.get("public_key") or "").strip()
        if not key:
            raise RuntimeError("VPN API 未返回服务端公钥。")
        return key
    if not WG_SERVER_PUBLIC_KEY_FILE.exists():
        raise RuntimeError(f"未找到服务端公钥文件：{WG_SERVER_PUBLIC_KEY_FILE}")
    return WG_SERVER_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()


def wireguard_generate_keys(
    *, user: sqlite3.Row | None = None, server_row: sqlite3.Row | None = None
) -> tuple[str, str, str]:
    if use_vpn_api(user=user, server_row=server_row):
        result = vpn_api_request(
            "POST",
            "/wireguard/generate-keys",
            user=user,
            server_row=server_row,
        )
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


def get_wireguard_peer_state(
    public_key: str | None,
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> dict[str, int | str]:
    if not public_key:
        return {"rx": 0, "tx": 0, "latest_handshake": 0, "endpoint": ""}
    dump = get_wireguard_dump_text(user=user, server_row=server_row)
    if not dump:
        return {"rx": 0, "tx": 0, "latest_handshake": 0, "endpoint": ""}
    peers = parse_wireguard_dump_peers(dump)
    if public_key in peers:
        return peers[public_key]
    return {"rx": 0, "tx": 0, "latest_handshake": 0, "endpoint": ""}


def get_wireguard_transfer_bytes(
    public_key: str | None,
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> tuple[int, int]:
    state = get_wireguard_peer_state(public_key, user=user, server_row=server_row)
    return int(state["rx"]), int(state["tx"])


def get_user_traffic_stats(user: sqlite3.Row) -> dict[str, int | str]:
    rx_bytes, tx_bytes = get_wireguard_transfer_bytes(
        user["client_public_key"],
        user=user,
    )
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

    where_parts = ["role IN ('user', 'admin')", "assigned_ip IS NOT NULL"]
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
    endpoint: str | None = None,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> str:
    server_public_key = get_wireguard_server_public_key(user=user, server_row=server_row)
    resolved_allowed_ips = (allowed_ips or get_client_allowed_ips()).strip()
    if not resolved_allowed_ips:
        raise RuntimeError("WireGuard AllowedIPs 为空，无法生成配置。")
    # Always use direct endpoint from the selected runtime node.
    direct_endpoint = (endpoint or "").strip() or get_wireguard_endpoint_for_clients(
        user=user,
        server_row=server_row,
    )
    resolved_endpoint = direct_endpoint
    if not resolved_endpoint:
        raise RuntimeError("WireGuard Endpoint 为空，无法生成配置。")
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
            f"Endpoint = {resolved_endpoint}",
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
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> dict[str, str | None]:
    filename_prefix = f"{safe_name(username)}_{user_id}"
    conf_path = Path(config_path) if config_path else CLIENT_CONF_DIR / f"{filename_prefix}.conf"
    qr_image_path = Path(qr_path) if qr_path else CLIENT_QR_DIR / f"{filename_prefix}.png"

    config_text = build_client_config(
        client_private_key,
        client_psk,
        client_ip,
        user=user,
        server_row=server_row,
    )

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
    target_server = None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role in {"user", "admin"}:
        try:
            db = get_db()
            target_server = get_persisted_runtime_server_for_account(db, user)
        except Exception:
            target_server = None
    config_text = build_client_config(
        client_private_key,
        client_psk,
        assigned_ip,
        allowed_ips=allowed_ips,
        user=user,
        server_row=target_server,
    )
    return config_text, normalized_mode


def get_runtime_server_for_account(user: sqlite3.Row | None) -> sqlite3.Row | None:
    if not user:
        return None
    try:
        db = get_db()
        return get_persisted_runtime_server_for_account(db, user)
    except Exception:
        return None


def resolve_shadowsocks_endpoint_host(
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> str:
    def pick_host(candidate: str | None) -> str:
        host = host_without_optional_port(candidate)
        return host.strip() if host else ""

    runtime_server = server_row or get_runtime_server_for_account(user)
    if runtime_server is not None:
        host = pick_host(row_get(runtime_server, "domain", ""))
        if host:
            return host
        host = pick_host(row_get(runtime_server, "host", ""))
        if host:
            return host

    for candidate in (
        SHADOWSOCKS_ENDPOINT_HOST,
        OPENVPN_ENDPOINT_HOST,
        WG_ENDPOINT,
    ):
        host = pick_host(candidate)
        if host:
            return host

    try:
        host = pick_host(request.host)
        if host:
            return host
    except Exception:
        pass
    return ""


def derive_user_shadowsocks_password(user: sqlite3.Row) -> str:
    _ = user
    return SHADOWSOCKS_PASSWORD


def build_user_shadowsocks_config(
    user: sqlite3.Row,
    *,
    server_row: sqlite3.Row | None = None,
) -> str:
    host = resolve_shadowsocks_endpoint_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    config_obj = {
        "server": host,
        "server_port": SHADOWSOCKS_SERVER_PORT,
        "password": derive_user_shadowsocks_password(user),
        "method": SHADOWSOCKS_METHOD,
        "mode": "tcp_and_udp",
        "timeout": 300,
    }
    return json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n"


def build_user_kcptun_config(
    user: sqlite3.Row,
    *,
    server_row: sqlite3.Row | None = None,
) -> str:
    host = resolve_shadowsocks_endpoint_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 kcptun 节点地址。")
    config_obj = {
        "remoteaddr": f"{host}:{KCPTUN_SERVER_PORT}",
        "localaddr": "127.0.0.1:12948",
        "key": KCPTUN_KEY,
        "crypt": "aes",
        "mode": "fast3",
        "conn": 1,
        "autoexpire": 0,
        "mtu": 1350,
        "sndwnd": 256,
        "rcvwnd": 512,
        "datashard": 10,
        "parityshard": 3,
        "dscp": 0,
        "nocomp": False,
        "acknodelay": True,
        "nodelay": 1,
        "interval": 20,
        "resend": 2,
        "nc": 1,
        "sockbuf": 4194304,
        "smuxver": 1,
        "smuxbuf": 4194304,
        "streambuf": 2097152,
        "keepalive": 10,
    }
    return json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n"


def build_user_kcptun_clash_profile(
    user: sqlite3.Row,
    *,
    server_row: sqlite3.Row | None = None,
) -> str:
    host = resolve_shadowsocks_endpoint_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 kcptun 节点地址。")
    username = (row_get(user, "username", "") or "").strip() or "vpn-user"
    proxy_name = f"kcptun-{safe_name(username)}"

    def yaml_str(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    return textwrap.dedent(
        f"""\
        mixed-port: 7890
        mode: rule
        proxies:
          - name: {yaml_str(proxy_name)}
            type: ss
            server: {yaml_str(host)}
            port: {KCPTUN_SERVER_PORT}
            cipher: {yaml_str(SHADOWSOCKS_METHOD)}
            password: {yaml_str(derive_user_shadowsocks_password(user))}
            udp: true
            plugin: "kcptun"
            plugin-opts:
              key: {yaml_str(KCPTUN_KEY)}
              crypt: "aes"
              mode: "fast3"
              mtu: 1350
        proxy-groups:
          - name: "PROXY"
            type: select
            proxies:
              - {yaml_str(proxy_name)}
              - "DIRECT"
          - name: "GLOBAL"
            type: select
            proxies:
              - {yaml_str(proxy_name)}
              - "DIRECT"
        rules:
          - MATCH,PROXY
        """
    )


def build_user_shadowsocks_clash_profile(
    user: sqlite3.Row,
    *,
    server_row: sqlite3.Row | None = None,
) -> str:
    host = resolve_shadowsocks_endpoint_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    username = (row_get(user, "username", "") or "").strip() or "vpn-user"
    ss_proxy_name = f"ss-{safe_name(username)}"
    kcptun_proxy_name = f"kcptun-{safe_name(username)}"
    ss_password = derive_user_shadowsocks_password(user)

    def yaml_str(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    if KCPTUN_ENABLED:
        return textwrap.dedent(
            f"""\
            mixed-port: 7890
            mode: rule
            proxies:
              - name: {yaml_str(kcptun_proxy_name)}
                type: ss
                server: {yaml_str(host)}
                port: {KCPTUN_SERVER_PORT}
                cipher: {yaml_str(SHADOWSOCKS_METHOD)}
                password: {yaml_str(ss_password)}
                udp: true
                plugin: "kcptun"
                plugin-opts:
                  key: {yaml_str(KCPTUN_KEY)}
                  crypt: "aes"
                  mode: "fast3"
                  mtu: 1350
              - name: {yaml_str(ss_proxy_name)}
                type: ss
                server: {yaml_str(host)}
                port: {SHADOWSOCKS_SERVER_PORT}
                cipher: {yaml_str(SHADOWSOCKS_METHOD)}
                password: {yaml_str(ss_password)}
                udp: true
            proxy-groups:
              - name: "PROXY"
                type: select
                proxies:
                  - {yaml_str(kcptun_proxy_name)}
                  - {yaml_str(ss_proxy_name)}
                  - "DIRECT"
              - name: "GLOBAL"
                type: select
                proxies:
                  - {yaml_str(kcptun_proxy_name)}
                  - {yaml_str(ss_proxy_name)}
                  - "DIRECT"
            rules:
              - MATCH,PROXY
            """
        )

    return textwrap.dedent(
        f"""\
        mixed-port: 7890
        mode: rule
        proxies:
          - name: {yaml_str(ss_proxy_name)}
            type: ss
            server: {yaml_str(host)}
            port: {SHADOWSOCKS_SERVER_PORT}
            cipher: {yaml_str(SHADOWSOCKS_METHOD)}
            password: {yaml_str(ss_password)}
            udp: true
        proxy-groups:
          - name: "PROXY"
            type: select
            proxies:
              - {yaml_str(ss_proxy_name)}
              - "DIRECT"
          - name: "GLOBAL"
            type: select
            proxies:
              - {yaml_str(ss_proxy_name)}
              - "DIRECT"
        rules:
          - MATCH,PROXY
        """
    )


def build_user_shadowsocks_uri(
    user: sqlite3.Row,
    *,
    server_row: sqlite3.Row | None = None,
) -> str:
    host = resolve_shadowsocks_endpoint_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    user_label = (row_get(user, "email", "") or row_get(user, "username", "") or "vpn-user").strip()
    raw_auth = f"{SHADOWSOCKS_METHOD}:{derive_user_shadowsocks_password(user)}"
    auth = base64.urlsafe_b64encode(raw_auth.encode("utf-8")).decode("ascii").rstrip("=")
    return (
        f"ss://{auth}@{host}:{SHADOWSOCKS_SERVER_PORT}"
        f"#{urllib_parse.quote(user_label, safe='')}"
    )


def set_wireguard_peer(
    peer_public_key: str,
    peer_psk: str,
    client_ip: str,
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> None:
    if use_vpn_api(user=user, server_row=server_row):
        vpn_api_request(
            "POST",
            "/wireguard/set-peer",
            {
                "interface": WG_INTERFACE,
                "peer_public_key": peer_public_key,
                "peer_psk": peer_psk,
                "client_ip": client_ip,
            },
            user=user,
            server_row=server_row,
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


def remove_wireguard_peer(
    peer_public_key: str,
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
) -> None:
    if use_vpn_api(user=user, server_row=server_row):
        vpn_api_request(
            "POST",
            "/wireguard/remove-peer",
            {"interface": WG_INTERFACE, "peer_public_key": peer_public_key},
            user=user,
            server_row=server_row,
        )
        return

    run_command(
        ["wg", "set", WG_INTERFACE, "peer", peer_public_key, "remove"],
        check=False,
    )
    run_command(["wg-quick", "save", WG_INTERFACE], check=False)


def generate_wireguard_bundle(
    username: str,
    user_id: int,
    client_ip: str,
    *,
    user: sqlite3.Row | None = None,
    server_row: sqlite3.Row | None = None,
):
    client_private_key, client_public_key, client_psk = wireguard_generate_keys(
        user=user,
        server_row=server_row,
    )

    artifacts = write_client_artifacts(
        username=username,
        user_id=user_id,
        client_private_key=client_private_key,
        client_psk=client_psk,
        client_ip=client_ip,
        user=user,
        server_row=server_row,
    )
    set_wireguard_peer(
        client_public_key,
        client_psk,
        client_ip,
        user=user,
        server_row=server_row,
    )

    return {
        "assigned_ip": client_ip,
        "client_private_key": client_private_key,
        "client_public_key": client_public_key,
        "client_psk": client_psk,
        "config_path": artifacts["config_path"],
        "qr_path": artifacts["qr_path"],
    }


def ensure_user_vpn_ready(
    db: sqlite3.Connection,
    user: sqlite3.Row,
    *,
    force_new_ip: bool = False,
) -> dict[str, str | int]:
    if row_get(user, "role") == "user":
        ensure_user_ingress_ports(db, user)
        user = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    previous_server = None
    previous_server_id = row_get(user, "assigned_server_id")
    if previous_server_id is not None and str(previous_server_id).strip():
        try:
            previous_server = get_server_by_id(db, int(previous_server_id))
        except Exception:
            previous_server = None

    target_server = None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role in {"user", "admin"}:
        target_server = select_runtime_server_for_account(
            db,
            user,
            allow_reassign=(role == "user"),
        )
        if role == "user" and (not target_server) and user_prefers_managed_nodes(db, user):
            raise RuntimeError("当前没有可用在线节点，请联系管理员检查服务器状态。")

    previous_server_runtime_id = int(previous_server["id"]) if previous_server else 0
    target_server_runtime_id = int(target_server["id"]) if target_server else 0
    server_changed = previous_server_runtime_id != target_server_runtime_id

    has_crypto_keys = all(
        [
            user["client_private_key"],
            user["client_public_key"],
            user["client_psk"],
        ]
    )

    if not has_crypto_keys:
        assigned_ip = next_available_ip(db, exclude_user_id=user["id"])
        bundle = generate_wireguard_bundle(
            user["username"],
            user["id"],
            assigned_ip,
            user=user,
            server_row=target_server,
        )
        bundle["wg_enabled"] = 1
        if target_server:
            bundle["assigned_server_id"] = int(target_server["id"])
        return bundle

    assigned_ip = row_get(user, "assigned_ip")
    if not assigned_ip:
        assigned_ip = next_available_ip(
            db,
            exclude_user_id=user["id"],
        )
    elif force_new_ip:
        assigned_ip = next_available_ip(
            db,
            exclude_user_id=user["id"],
            avoid_ip=row_get(user, "assigned_ip"),
        )

    old_public_key = (row_get(user, "client_public_key", "") or "").strip()
    if old_public_key and server_changed:
        try:
            remove_wireguard_peer(
                old_public_key,
                user=user,
                server_row=previous_server or target_server,
            )
        except Exception as exc:
            app.logger.warning("移除旧节点 WireGuard peer 失败：%s", exc)

    artifacts = write_client_artifacts(
        username=user["username"],
        user_id=user["id"],
        client_private_key=user["client_private_key"],
        client_psk=user["client_psk"],
        client_ip=assigned_ip,
        config_path=user["config_path"],
        qr_path=user["qr_path"],
        user=user,
        server_row=target_server,
    )
    set_wireguard_peer(
        user["client_public_key"],
        user["client_psk"],
        assigned_ip,
        user=user,
        server_row=target_server,
    )

    result = {
        "assigned_ip": assigned_ip,
        "client_private_key": user["client_private_key"],
        "client_public_key": user["client_public_key"],
        "client_psk": user["client_psk"],
        "config_path": artifacts["config_path"],
        "qr_path": artifacts["qr_path"],
        "wg_enabled": 1,
    }
    if target_server:
        result["assigned_server_id"] = int(target_server["id"])
    return result


def ensure_admin_self_vpn_ready(
    db: sqlite3.Connection,
    admin_user: sqlite3.Row,
) -> sqlite3.Row:
    if row_get(admin_user, "role") != "admin":
        raise ValueError("仅管理员可使用自用 VPN 配置。")

    vpn_data = ensure_user_vpn_ready(db, admin_user)
    assigned_server_id = vpn_data.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(admin_user, "assigned_server_id")
    db.execute(
        """
        UPDATE users
        SET assigned_ip = ?,
            assigned_server_id = ?,
            client_private_key = ?,
            client_public_key = ?,
            client_psk = ?,
            config_path = ?,
            qr_path = ?,
            wg_enabled = 1,
            subscription_expires_at = NULL,
            traffic_quota_bytes = 0,
            traffic_used_bytes = 0,
            traffic_last_total_bytes = 0
        WHERE id = ? AND role = 'admin'
        """,
        (
            vpn_data["assigned_ip"],
            assigned_server_id,
            vpn_data["client_private_key"],
            vpn_data["client_public_key"],
            vpn_data["client_psk"],
            vpn_data["config_path"],
            vpn_data["qr_path"],
            admin_user["id"],
        ),
    )
    db.commit()
    return db.execute("SELECT * FROM users WHERE id = ?", (admin_user["id"],)).fetchone()


def admin_self_vpn_needs_prepare(admin_user: sqlite3.Row | None) -> bool:
    if not admin_user or row_get(admin_user, "role") != "admin":
        return True
    return not all(
        [
            int(row_get(admin_user, "wg_enabled", 0) or 0) == 1,
            (row_get(admin_user, "assigned_ip", "") or "").strip(),
            (row_get(admin_user, "client_private_key", "") or "").strip(),
            (row_get(admin_user, "client_public_key", "") or "").strip(),
            (row_get(admin_user, "client_psk", "") or "").strip(),
        ]
    )


def enforce_admin_unlimited_entitlement(db: sqlite3.Connection, admin_user_id: int) -> None:
    db.execute(
        """
        UPDATE users
        SET subscription_expires_at = NULL,
            traffic_quota_bytes = 0,
            traffic_used_bytes = 0,
            traffic_last_total_bytes = 0,
            wg_enabled = 1
        WHERE id = ? AND role = 'admin'
        """,
        (int(admin_user_id),),
    )


def ensure_admin_self_vpn_profile(
    db: sqlite3.Connection,
    admin_user: sqlite3.Row,
    *,
    force_prepare: bool = False,
) -> tuple[sqlite3.Row, bool]:
    if row_get(admin_user, "role") != "admin":
        raise ValueError("仅管理员可使用自用 VPN 配置。")

    prepared_now = False
    refreshed = admin_user
    if force_prepare or admin_self_vpn_needs_prepare(admin_user):
        # Admin profile should be generated from an online managed node (or explicit global VPN_API_URL).
        # Without that, avoid falling back to local `wg` command in web runtime.
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
        rx_bytes, tx_bytes = get_wireguard_transfer_bytes(
            row_get(user, "client_public_key"),
            user=user,
        )
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
            remove_wireguard_peer(user["client_public_key"], user=user)
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
            role,
            assigned_server_id,
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
            remove_wireguard_peer(row["client_public_key"], user=row)
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
    if row_get(user, "client_public_key"):
        rx_now, tx_now = get_wireguard_transfer_bytes(
            user["client_public_key"],
            user=user,
        )
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
            assigned_ip = ?,
            assigned_server_id = ?,
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
            assigned_server_id,
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


@app.route("/wireguard/download")
def wireguard_download_page():
    if not is_wireguard_open():
        flash("WireGuard 当前已关闭。", "error")
        return redirect(url_for("index"))
    user = current_user()
    dashboard_page = "guide" if user and user["role"] == "user" else None
    return render_template(
        "wireguard_download.html",
        dashboard_page=dashboard_page,
        wireguard_download_links=WIREGUARD_DOWNLOAD_LINKS,
    )


@app.route("/wireguard/download/auto")
def wireguard_download_auto():
    if not is_wireguard_open():
        flash("WireGuard 当前已关闭。", "error")
        return redirect(url_for("index"))
    platform = detect_wireguard_platform(request.headers.get("User-Agent", ""))
    return redirect(url_for("wireguard_download_redirect", platform=platform))


@app.route("/wireguard/download/<platform>")
def wireguard_download_redirect(platform: str):
    key = (platform or "").strip().lower()
    target_url = WIREGUARD_DOWNLOAD_LINKS.get(key, WIREGUARD_DOWNLOAD_FALLBACK)
    return redirect(target_url, code=302)


@app.route("/openvpn/download")
def openvpn_download_page():
    if not is_openvpn_open():
        flash("OpenVPN 当前已关闭。", "error")
        return redirect(url_for("index"))
    user = current_user()
    dashboard_page = "guide" if user and user["role"] == "user" else None
    return render_template(
        "openvpn_download.html",
        dashboard_page=dashboard_page,
        openvpn_download_links=OPENVPN_DOWNLOAD_LINKS,
    )


@app.route("/openvpn/download/auto")
def openvpn_download_auto():
    if not is_openvpn_open():
        flash("OpenVPN 当前已关闭。", "error")
        return redirect(url_for("index"))
    platform = detect_openvpn_platform(request.headers.get("User-Agent", ""))
    return redirect(url_for("openvpn_download_redirect", platform=platform))


@app.route("/openvpn/download/<platform>")
def openvpn_download_redirect(platform: str):
    key = (platform or "").strip().lower()
    target_url = OPENVPN_DOWNLOAD_LINKS.get(key, OPENVPN_DOWNLOAD_FALLBACK)
    return redirect(target_url, code=302)


def captcha_session_key(scene: str) -> str:
    safe_scene = (scene or "").strip().lower()
    if safe_scene not in CAPTCHA_SCENES:
        safe_scene = CAPTCHA_SCENE_DEFAULT
    return f"captcha_{safe_scene}"


def generate_captcha_text(length: int = 5) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(chars) for _ in range(length))


def validate_captcha_input(scene: str, value: str) -> bool:
    payload = session.get(captcha_session_key(scene))
    if not payload:
        return False
    expire_at_raw = payload.get("expire_at")
    if not expire_at_raw:
        return False
    try:
        expire_at = parse_iso(expire_at_raw)
    except Exception:
        return False
    if not expire_at or expire_at < utcnow():
        return False
    input_value = (value or "").strip().upper()
    expected = str(payload.get("text") or "").strip().upper()
    if not input_value or input_value != expected:
        return False
    session.pop(captcha_session_key(scene), None)
    return True


def can_send_email_code(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection,
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
        """,
        (email, purpose, code, ip_address, expire_at, created_at),
    )
    return int(cursor.lastrowid)


def consume_email_verification_code(
    db: sqlite3.Connection,
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
    db: sqlite3.Connection | None = None,
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
        subject="VPN 门户邮箱验证码",
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
    message["Subject"] = "VPN 门户邮箱验证码"
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


def expire_pending_orders(db: sqlite3.Connection) -> int:
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


def cleanup_verification_records(db: sqlite3.Connection) -> None:
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


def rotate_user_wireguard_credentials(
    db: sqlite3.Connection,
    user: sqlite3.Row,
    *,
    force_new_ip: bool | None = None,
) -> sqlite3.Row:
    previous_server = None
    previous_server_id = row_get(user, "assigned_server_id")
    if previous_server_id is not None and str(previous_server_id).strip():
        try:
            previous_server = get_server_by_id(db, int(previous_server_id))
        except Exception:
            previous_server = None

    target_server = None
    role = (row_get(user, "role", "") or "").strip().lower()
    if role in {"user", "admin"}:
        target_server = select_runtime_server_for_account(
            db,
            user,
            allow_reassign=(role == "user"),
        )
        if role == "user" and (not target_server) and user_prefers_managed_nodes(db, user):
            raise RuntimeError("当前没有可用在线节点，请联系管理员检查服务器状态。")

    old_public_key = (row_get(user, "client_public_key", "") or "").strip()
    if old_public_key:
        try:
            remove_wireguard_peer(
                old_public_key,
                user=user,
                server_row=previous_server or target_server,
            )
        except Exception as exc:
            app.logger.warning("移除旧 WireGuard peer 失败：%s", exc)

    assigned_ip = row_get(user, "assigned_ip")
    should_rotate_ip = force_new_ip if force_new_ip is not None else is_dynamic_ip_assignment_mode()
    if not assigned_ip:
        assigned_ip = next_available_ip(db, exclude_user_id=int(user["id"]))
    elif should_rotate_ip:
        assigned_ip = next_available_ip(
            db,
            exclude_user_id=int(user["id"]),
            avoid_ip=str(assigned_ip),
        )
    bundle = generate_wireguard_bundle(
        user["username"],
        int(user["id"]),
        str(assigned_ip),
        user=user,
        server_row=target_server,
    )
    assigned_server_id = bundle.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(user, "assigned_server_id")
    db.execute(
        """
        UPDATE users
        SET assigned_ip = ?,
            assigned_server_id = ?,
            client_private_key = ?,
            client_public_key = ?,
            client_psk = ?,
            config_path = ?,
            qr_path = ?,
            wg_enabled = ?
        WHERE id = ?
        """,
        (
            bundle["assigned_ip"],
            assigned_server_id,
            bundle["client_private_key"],
            bundle["client_public_key"],
            bundle["client_psk"],
            bundle["config_path"],
            bundle["qr_path"],
            int(row_get(user, "wg_enabled", 0) or 0),
            int(user["id"]),
        ),
    )
    return db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()


def persist_user_vpn_state(
    db: sqlite3.Connection,
    user: sqlite3.Row,
    vpn_data: dict[str, str | int],
) -> sqlite3.Row:
    wg_ingress_port, openvpn_ingress_port = ensure_user_ingress_ports(db, user)
    assigned_server_id = vpn_data.get("assigned_server_id")
    if assigned_server_id is None:
        assigned_server_id = row_get(user, "assigned_server_id")
    db.execute(
        """
        UPDATE users
        SET assigned_ip = ?,
            assigned_server_id = ?,
            wg_ingress_port = ?,
            openvpn_ingress_port = ?,
            client_private_key = ?,
            client_public_key = ?,
            client_psk = ?,
            config_path = ?,
            qr_path = ?,
            wg_enabled = ?
        WHERE id = ?
        """,
        (
            vpn_data["assigned_ip"],
            assigned_server_id,
            wg_ingress_port,
            openvpn_ingress_port,
            vpn_data["client_private_key"],
            vpn_data["client_public_key"],
            vpn_data["client_psk"],
            vpn_data["config_path"],
            vpn_data["qr_path"],
            int(vpn_data.get("wg_enabled", row_get(user, "wg_enabled", 1)) or 1),
            int(user["id"]),
        ),
    )
    return db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()


def apply_password_change(
    db: sqlite3.Connection,
    user: sqlite3.Row,
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
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
    if rotate_vpn and refreshed and (row_get(refreshed, "client_public_key", "") or "").strip():
        rotate_user_wireguard_credentials(db, refreshed)


def grant_new_user_welcome_entitlement(db: sqlite3.Connection, user_id: int) -> None:
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
            SET assigned_ip = ?,
                assigned_server_id = ?,
                client_private_key = ?,
                client_public_key = ?,
                client_psk = ?,
                config_path = ?,
                qr_path = ?,
                approved_at = ?,
                subscription_expires_at = ?,
                traffic_quota_bytes = ?,
                wg_enabled = 1
            WHERE id = ?
            """,
            (
                vpn_data["assigned_ip"],
                assigned_server_id,
                vpn_data["client_private_key"],
                vpn_data["client_public_key"],
                vpn_data["client_psk"],
                vpn_data["config_path"],
                vpn_data["qr_path"],
                utcnow_iso(),
                subscription_expires_at,
                quota_bytes,
                user_id,
            ),
        )


@app.route("/captcha.svg")
def captcha_svg():
    scene = (request.args.get("scene") or CAPTCHA_SCENE_DEFAULT).strip().lower()
    if scene not in CAPTCHA_SCENES:
        scene = CAPTCHA_SCENE_DEFAULT

    text = generate_captcha_text()
    session[captcha_session_key(scene)] = {
        "text": text,
        "expire_at": (utcnow() + timedelta(minutes=CAPTCHA_TTL_MINUTES)).isoformat(),
    }

    chars: list[str] = []
    for idx, char in enumerate(text):
        x = 14 + idx * 22
        y = 32 + random.randint(-3, 3)
        rotate = random.randint(-16, 16)
        chars.append(
            f'<text x="{x}" y="{y}" transform="rotate({rotate} {x} {y})">{char}</text>'
        )
    lines: list[str] = []
    for _ in range(4):
        x1, y1 = random.randint(0, 124), random.randint(0, 40)
        x2, y2 = random.randint(0, 124), random.randint(0, 40)
        lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#a7b8d8" stroke-width="1" />'
        )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="124" height="40" viewBox="0 0 124 40">'
        '<rect width="124" height="40" rx="6" ry="6" fill="#edf2fb" />'
        + "".join(lines)
        + '<g font-family="Verdana,sans-serif" font-size="23" font-weight="700" fill="#0f2748">'
        + "".join(chars)
        + "</g></svg>"
    )
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    db = get_db()
    landing_plans = load_subscription_plans(db, active_only=True)
    registration_open = is_registration_open(db)
    return render_template(
        "index.html",
        landing_plans=landing_plans,
        registration_open=registration_open,
    )


@app.route("/register/send-code", methods=["POST"])
def register_send_code():
    db = get_db()
    if not is_registration_open(db):
        return "", 404
    if not is_email_verification_available(db):
        flash("当前未配置邮件服务器，注册已自动关闭邮箱验证码。", "error")
        return redirect(url_for("register"))

    email = request.form.get("email", "").strip().lower()
    captcha = request.form.get("captcha", "")
    if not looks_like_email(email):
        flash("邮箱格式不正确。", "error")
        return redirect(url_for("register", email=email))
    if not validate_captcha_input("register", captcha):
        flash("图片验证码错误或已过期。", "error")
        return redirect(url_for("register", email=email))

    existing_user = db.execute("SELECT id FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
    if existing_user:
        flash("该邮箱已注册，请直接登录。", "error")
        return redirect(url_for("register", email=email))

    allowed, message = can_send_email_code(db, email, EMAIL_CODE_PURPOSE_REGISTER)
    if not allowed:
        flash(message, "error")
        return redirect(url_for("register", email=email))

    code = "".join(random.choice(string.digits) for _ in range(6))
    verification_id = 0
    try:
        begin_immediate(db)
        verification_id = create_email_verification_code(
            db,
            email=email,
            purpose=EMAIL_CODE_PURPOSE_REGISTER,
            code=code,
            ip_address=get_client_ip(),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    ok, message = send_verification_email(email, "注册", code, db=db)
    if not ok and verification_id:
        try:
            db.execute("DELETE FROM email_verifications WHERE id = ?", (verification_id,))
            db.commit()
        except Exception:
            db.rollback()
    flash(message, "success" if ok else "error")
    return redirect(url_for("register", email=email))

    ok, message = send_verification_email(email, "注册", code)
    flash(message, "success" if ok else "error")
    return redirect(url_for("register", email=email))


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    if not is_registration_open(db):
        return "", 404

    client_ip = get_client_ip()
    cooldown_seconds = get_registration_cooldown_seconds(db, client_ip)
    register_limit_minutes = REGISTER_COOLDOWN_SECONDS // 60
    email_prefill = request.values.get("email", "").strip().lower()
    email_verification_enabled = is_email_verification_available(db)

    def render_register():
        return render_template(
            "register.html",
            cooldown_seconds=cooldown_seconds,
            client_ip=client_ip,
            register_limit_seconds=REGISTER_COOLDOWN_SECONDS,
            register_limit_minutes=register_limit_minutes,
            email_prefill=email_prefill,
            email_verification_enabled=email_verification_enabled,
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
        confirm_password = request.form.get("confirm_password", "")
        email_code = request.form.get("email_code", "").strip()
        captcha = request.form.get("captcha", "")
        email_prefill = email

        if not validate_captcha_input("register", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_register()
        if not looks_like_email(email):
            flash("邮箱格式不正确。", "error")
            return render_register()
        if len(password) < 8:
            flash("密码长度至少需要 8 位。", "error")
            return render_register()
        if password != confirm_password:
            flash("两次输入密码不一致。", "error")
            return render_register()
        if email_verification_enabled and not re.fullmatch(r"\d{6}", email_code):
            flash("邮箱验证码格式不正确。", "error")
            return render_register()

        username = email
        try:
            now_iso = utcnow_iso()
            begin_immediate(db)
            cooldown_seconds = get_registration_cooldown_seconds(db, client_ip)
            if cooldown_seconds > 0:
                db.rollback()
                flash(
                    f"该 IP 注册过于频繁，请在 {cooldown_seconds} 秒后重试。",
                    "error",
                )
                return render_register()
            if email_verification_enabled:
                if not consume_email_verification_code(
                    db,
                    email=email,
                    purpose=EMAIL_CODE_PURPOSE_REGISTER,
                    code=email_code,
                ):
                    db.rollback()
                    flash("邮箱验证码无效或已过期。", "error")
                    return render_register()
            db.execute(
                """
                INSERT INTO users (
                    username, email, password_hash, role, status,
                    email_verified, created_at, approved_at, session_version
                )
                VALUES (?, ?, ?, 'user', 'approved', 1, ?, ?, 1)
                """,
                (username, email, generate_password_hash(password), now_iso, now_iso),
            )
            user_id = int(db.execute("SELECT last_insert_rowid() AS lid").fetchone()["lid"])
            mark_registration_success(db, client_ip, now_iso)
            grant_new_user_welcome_entitlement(db, user_id)
            db.commit()
            flash("注册成功，请登录后创建订阅订单。", "success")
            return redirect(url_for("login"))
        except DB_INTEGRITY_ERRORS:
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
    registration_open = is_registration_open(get_db())
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        captcha = request.form.get("captcha", "")

        if not validate_captcha_input("login", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_template("login.html", registration_open=registration_open)

        user = authenticate_user(identity, password)
        if not user:
            flash("用户名/邮箱或密码错误。", "error")
            return render_template("login.html", registration_open=registration_open)
        if row_get(user, "role") == "user" and int(row_get(user, "email_verified", 0) or 0) != 1:
            flash("邮箱尚未验证，暂时无法登录。", "error")
            return render_template("login.html", registration_open=registration_open)

        login_user_session(user)
        if admin_must_change_password(user):
            flash("首次登录请先修改管理员密码。", "error")
            return redirect(url_for("admin_change_password"))
        flash("登录成功。", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html", registration_open=registration_open)


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
    if row_get(user, "role") == "user" and int(row_get(user, "email_verified", 0) or 0) != 1:
        return {
            "ok": False,
            "error": "邮箱尚未验证",
        }, 403

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


@app.route("/password-recover/send-code", methods=["POST"])
def password_recover_send_code():
    db = get_db()
    email = request.form.get("email", "").strip().lower()
    captcha = request.form.get("captcha", "")
    if not looks_like_email(email):
        flash("邮箱格式不正确。", "error")
        return redirect(url_for("password_recover", email=email))
    if not validate_captcha_input("recover", captcha):
        flash("图片验证码错误或已过期。", "error")
        return redirect(url_for("password_recover", email=email))

    user = db.execute(
        "SELECT id FROM users WHERE email = ? AND role = 'user' LIMIT 1",
        (email,),
    ).fetchone()
    if not user:
        flash("该邮箱未注册。", "error")
        return redirect(url_for("password_recover", email=email))

    allowed, message = can_send_email_code(db, email, EMAIL_CODE_PURPOSE_RECOVER)
    if not allowed:
        flash(message, "error")
        return redirect(url_for("password_recover", email=email))

    code = "".join(random.choice(string.digits) for _ in range(6))
    verification_id = 0
    try:
        begin_immediate(db)
        verification_id = create_email_verification_code(
            db,
            email=email,
            purpose=EMAIL_CODE_PURPOSE_RECOVER,
            code=code,
            ip_address=get_client_ip(),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    ok, message = send_verification_email(email, "找回密码", code, db=db)
    if not ok and verification_id:
        try:
            db.execute("DELETE FROM email_verifications WHERE id = ?", (verification_id,))
            db.commit()
        except Exception:
            db.rollback()
    flash(message, "success" if ok else "error")
    return redirect(url_for("password_recover", email=email))

    ok, message = send_verification_email(email, "找回密码", code)
    flash(message, "success" if ok else "error")
    return redirect(url_for("password_recover", email=email))


@app.route("/password-recover", methods=["GET", "POST"])
def password_recover():
    email_prefill = request.values.get("email", "").strip().lower()
    if request.method == "POST":
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        email_prefill = email
        email_code = request.form.get("email_code", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        captcha = request.form.get("captcha", "")

        if not validate_captcha_input("recover", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_template("password_recover.html", email_prefill=email_prefill)
        if not looks_like_email(email):
            flash("邮箱格式不正确。", "error")
            return render_template("password_recover.html", email_prefill=email_prefill)
        if len(new_password) < 8:
            flash("新密码长度至少需要 8 位。", "error")
            return render_template("password_recover.html", email_prefill=email_prefill)
        if new_password != confirm_password:
            flash("两次输入的新密码不一致。", "error")
            return render_template("password_recover.html", email_prefill=email_prefill)
        if not re.fullmatch(r"\d{6}", email_code):
            flash("邮箱验证码格式不正确。", "error")
            return render_template("password_recover.html", email_prefill=email_prefill)

        try:
            begin_immediate(db)
            user = db.execute(
                "SELECT * FROM users WHERE email = ? AND role = 'user' LIMIT 1",
                (email,),
            ).fetchone()
            if not user:
                db.rollback()
                flash("该邮箱未注册。", "error")
                return render_template("password_recover.html", email_prefill=email_prefill)
            if not consume_email_verification_code(
                db,
                email=email,
                purpose=EMAIL_CODE_PURPOSE_RECOVER,
                code=email_code,
            ):
                db.rollback()
                flash("邮箱验证码无效或已过期。", "error")
                return render_template("password_recover.html", email_prefill=email_prefill)
            apply_password_change(
                db,
                user,
                new_password=new_password,
                clear_force_change=False,
                rotate_vpn=True,
            )
            db.commit()
            session.clear()
            flash("密码已重置，请使用新密码登录。", "success")
            return redirect(url_for("login"))
        except Exception:
            db.rollback()
            raise

    return render_template("password_recover.html", email_prefill=email_prefill)



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
            return redirect(url_for("admin_home"))

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
    health_overview = refresh_server_health_status(db)
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    traffic_stats = get_user_traffic_stats(user)
    current_plan_display = get_user_current_plan_display(db, user)
    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    if has_time and has_traffic:
        benefit_summary = "时长权益 + 流量权益"
    elif has_time:
        benefit_summary = "时长权益（不限流量）"
    elif has_traffic:
        benefit_summary = "流量权益（有效期永久）"
    else:
        benefit_summary = "暂无生效权益"
    if has_traffic and not has_time:
        subscription_expiry_display = "永久"
    else:
        subscription_expiry_display = format_utc(user["subscription_expires_at"])
    if is_dynamic_ip_assignment_mode():
        assigned_ip_display = "DHCP 动态分配"
    else:
        assigned_ip_display = user["assigned_ip"] or "暂未分配"
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
        assigned_ip_display=assigned_ip_display,
        current_server=current_server,
        node_alert_text=node_alert_text,
        dashboard_page="home",
    )


@app.route("/dashboard/guide")
@login_required
def dashboard_guide():
    return redirect(url_for("dashboard_config"))


@app.route("/dashboard/plans")
@login_required
def dashboard_plans():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))
    db = get_db()
    available_plans = load_subscription_plans(db, active_only=True)
    return render_template(
        "dashboard_plans.html",
        available_plans=available_plans,
        dashboard_page="plans",
    )


@app.route("/dashboard/config")
@login_required
def dashboard_config():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))

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

    ss_access_token = build_download_access_token(user, "download-config-user")
    kcptun_access_token = build_download_access_token(user, "download-kcptun-user")
    ss_download_link = (
        absolute_url_for("download_config", format="yaml", access=ss_access_token)
        if SHADOWSOCKS_ENABLED
        else ""
    )
    kcptun_download_link = (
        absolute_url_for("download_kcptun_config", format="yaml", access=kcptun_access_token)
        if KCPTUN_ENABLED
        else ""
    )
    ss_qr_link = absolute_url_for("download_qr") if SHADOWSOCKS_ENABLED else ""

    return render_template(
        "dashboard_config.html",
        user=user,
        active=is_subscription_active(user),
        available_servers=available_servers,
        current_server=current_server,
        preferred_server=preferred_server,
        node_alert_text=node_alert_text,
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
        flash("管理员请在管理员配置页操作。", "error")
        return redirect(url_for("admin_configs"))
    flash("当前使用 Shadowsocks + kcptun，配置为按用户动态生成，无需手动重建。", "success")
    return redirect(url_for("dashboard_config"))


@app.route("/dashboard/config/server", methods=["POST"])
@login_required
def dashboard_select_server():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    user = sync_user_traffic_usage(db, user)
    available_plans = load_subscription_plans(db, active_only=True)

    pending_orders = db.execute(
        """
        SELECT id, plan_months, plan_name, plan_mode, plan_duration_months, plan_traffic_gb, status, created_at,
               plan_duration_value, plan_duration_unit,
               payment_method, usdt_network, usdt_amount, pay_to_address, tx_hash, tx_submitted_at, expires_at
        FROM payment_orders
        WHERE user_id = ? AND status = 'pending'
        ORDER BY created_at DESC
        """,
        (user["id"],),
    ).fetchall()
    paid_orders = db.execute(
        """
        SELECT id, plan_months, plan_name, plan_mode, plan_duration_months, plan_traffic_gb, status, created_at, paid_at,
               plan_duration_value, plan_duration_unit,
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


def load_admin_paid_orders(db: sqlite3.Connection):
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


def load_admin_subscriptions(db: sqlite3.Connection, email_query: str = ""):
    base_sql = """
        SELECT
            id,
            role,
            username,
            email,
            assigned_ip,
            subscription_expires_at,
            wg_enabled
        FROM users
        WHERE role IN ('user', 'admin')
    """
    params = []
    normalized_query = (email_query or "").strip()
    if normalized_query:
        base_sql += " AND lower(email) LIKE lower(?)"
        params.append(f"%{normalized_query}%")
    base_sql += " ORDER BY subscription_expires_at DESC, id DESC"
    return db.execute(base_sql, params).fetchall()


def load_expiring_subscriptions(
    db: sqlite3.Connection,
    *,
    days: int = 7,
    limit: int = 20,
) -> list[dict]:
    now_dt = utcnow()
    expire_before = now_dt + timedelta(days=max(1, int(days)))
    safe_limit = max(1, int(limit))
    rows = db.execute(
        """
        SELECT
            id,
            username,
            email,
            subscription_expires_at
        FROM users
        WHERE role = 'user'
          AND wg_enabled = 1
          AND subscription_expires_at IS NOT NULL
        ORDER BY subscription_expires_at ASC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()
    result: list[dict] = []
    for row in rows:
        expires_at = parse_iso(row_get(row, "subscription_expires_at", ""))
        if not expires_at:
            continue
        if expires_at < now_dt or expires_at > expire_before:
            continue
        result.append(
            {
                "id": int(row["id"]),
                "username": (row_get(row, "username", "") or "").strip(),
                "email": (row_get(row, "email", "") or "").strip(),
                "subscription_expires_at": row_get(row, "subscription_expires_at", ""),
            }
        )
    return result


def handshake_epoch_to_iso(epoch_seconds: int) -> str:
    try:
        epoch = int(epoch_seconds or 0)
    except Exception:
        epoch = 0
    if epoch <= 0:
        return ""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()
    except Exception:
        return ""


def load_admin_online_users(
    db: sqlite3.Connection,
    *,
    online_window_seconds: int = ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
) -> tuple[list[dict], dict]:
    users = db.execute(
        """
        SELECT
            id,
            role,
            username,
            email,
            assigned_ip,
            assigned_server_id,
            client_public_key,
            subscription_expires_at,
            traffic_used_bytes,
            wg_enabled
        FROM users
        WHERE role IN ('user', 'admin')
          AND wg_enabled = 1
          AND client_public_key IS NOT NULL
          AND trim(client_public_key) <> ''
        ORDER BY id DESC
        """
    ).fetchall()
    servers = db.execute(
        """
        SELECT *
        FROM vpn_servers
        ORDER BY id DESC
        """
    ).fetchall()
    servers_by_id: dict[int, sqlite3.Row] = {}
    for server in servers:
        try:
            servers_by_id[int(server["id"])] = server
        except Exception:
            continue

    now_dt = utcnow()
    now_ts = int(now_dt.timestamp())
    peer_cache: dict[str, dict[str, dict[str, int | str]]] = {}
    cache_errors: dict[str, str] = {}
    online_users: list[dict] = []

    for user in users:
        public_key = (row_get(user, "client_public_key", "") or "").strip()
        if not public_key:
            continue

        server_row = None
        assigned_server_id = row_get(user, "assigned_server_id")
        if assigned_server_id is not None and str(assigned_server_id).strip():
            try:
                server_row = servers_by_id.get(int(assigned_server_id))
            except Exception:
                server_row = None
        if server_row is None:
            try:
                server_row = get_persisted_runtime_server_for_account(db, user)
            except Exception:
                server_row = None

        if server_row is not None:
            source_key = f"server:{int(server_row['id'])}"
            server_name = (
                (row_get(server_row, "server_name", "") or "").strip()
                or (row_get(server_row, "host", "") or "").strip()
                or f"#{int(server_row['id'])}"
            )
        elif VPN_API_URL:
            source_key = "global-api"
            server_name = "全局 VPN API"
        else:
            source_key = "local"
            server_name = "本机 VPN"

        if source_key not in peer_cache:
            try:
                if server_row is not None:
                    if use_vpn_api(server_row=server_row):
                        dump_text = get_wireguard_dump_text(server_row=server_row)
                    else:
                        dump_text = ""
                else:
                    dump_text = get_wireguard_dump_text()
                peer_cache[source_key] = parse_wireguard_dump_peers(dump_text)
            except Exception as exc:
                peer_cache[source_key] = {}
                cache_errors[source_key] = str(exc)

        peer_state = peer_cache[source_key].get(
            public_key,
            {"rx": 0, "tx": 0, "latest_handshake": 0, "endpoint": ""},
        )
        rx_bytes = max(0, int(peer_state.get("rx", 0) or 0))
        tx_bytes = max(0, int(peer_state.get("tx", 0) or 0))
        total_bytes = rx_bytes + tx_bytes
        latest_handshake = max(0, int(peer_state.get("latest_handshake", 0) or 0))
        handshake_age_seconds = (
            now_ts - latest_handshake if latest_handshake > 0 else 10**9
        )
        is_online = latest_handshake > 0 and handshake_age_seconds <= online_window_seconds
        if not is_online:
            continue

        role_value = (row_get(user, "role", "") or "").strip().lower()
        username_display = (row_get(user, "username", "") or "").strip()
        if role_value == "admin":
            username_display = f"{username_display or '管理员'}（管理员）"

        online_users.append(
            {
                "id": int(user["id"]),
                "role": role_value or "user",
                "username": username_display,
                "email": (row_get(user, "email", "") or "").strip(),
                "assigned_ip": (row_get(user, "assigned_ip", "") or "").strip(),
                "server_name": server_name,
                "endpoint": (peer_state.get("endpoint", "") or "").strip(),
                "latest_handshake": latest_handshake,
                "latest_handshake_at": handshake_epoch_to_iso(latest_handshake),
                "handshake_age_seconds": max(0, handshake_age_seconds),
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "total_bytes": total_bytes,
                "rx_human": format_bytes(rx_bytes),
                "tx_human": format_bytes(tx_bytes),
                "total_human": format_bytes(total_bytes),
                "traffic_used_bytes": to_non_negative_int(row_get(user, "traffic_used_bytes", 0)),
                "traffic_used_human": format_bytes(
                    to_non_negative_int(row_get(user, "traffic_used_bytes", 0))
                ),
                "subscription_expires_at": row_get(user, "subscription_expires_at", ""),
            }
        )

    online_users.sort(
        key=lambda item: (
            int(item.get("latest_handshake", 0) or 0),
            int(item.get("total_bytes", 0) or 0),
        ),
        reverse=True,
    )
    summary = {
        "tracked_users": len(users),
        "online_users": len(online_users),
        "total_download_bytes": sum(int(item["rx_bytes"]) for item in online_users),
        "total_upload_bytes": sum(int(item["tx_bytes"]) for item in online_users),
        "total_traffic_bytes": sum(int(item["total_bytes"]) for item in online_users),
        "source_errors": len(cache_errors),
        "source_errors_text": " | ".join(
            f"{name}: {message}" for name, message in cache_errors.items()
        ).strip(),
    }
    summary["total_download_human"] = format_bytes(summary["total_download_bytes"])
    summary["total_upload_human"] = format_bytes(summary["total_upload_bytes"])
    summary["total_traffic_human"] = format_bytes(summary["total_traffic_bytes"])
    return online_users, summary


def get_user_current_plan_display(db: sqlite3.Connection, user: sqlite3.Row) -> str:
    row = db.execute(
        """
        SELECT
            plan_name,
            plan_mode,
            plan_duration_months,
            plan_duration_value,
            plan_duration_unit,
            plan_traffic_gb,
            plan_months
        FROM payment_orders
        WHERE user_id = ? AND status = 'paid'
        ORDER BY COALESCE(paid_at, created_at) DESC, id DESC
        LIMIT 1
        """,
        (int(user["id"]),),
    ).fetchone()
    if row:
        return format_order_plan(row)

    has_time = has_active_time_subscription(user)
    has_traffic = has_active_traffic_subscription(user)
    if has_time and has_traffic:
        return "赠送权益（时长 + 流量）"
    if has_time:
        return "赠送时长权益（不限流量）"
    if has_traffic:
        return "赠送流量权益（有效期永久）"
    return "暂无生效套餐"


def load_first_plan_for_onboarding(db: sqlite3.Connection) -> dict:
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
    server_region: str,
    host: str,
    port: int,
    username: str,
    password: str,
    ssh_private_key: str = "",
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
            server_name, server_region, host, port, username, password, ssh_private_key, domain, vpn_api_token,
            wg_port, openvpn_port, dns_port, status,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    db: sqlite3.Connection,
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
                wg_port=SERVER_DEPLOY_DEFAULT_WG_PORT,
                openvpn_port=SERVER_DEPLOY_DEFAULT_OPENVPN_PORT,
                dns_port=SERVER_DEPLOY_DEFAULT_DNS_PORT,
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
            url_for("admin_home", onboarding_open="1", onboarding_step=str(step))
        )
    return redirect(url_for("admin_home", onboarding_open="1"))


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
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

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

    deploy_ok, deploy_message, final_token, deploy_log = deploy_vpn_node_server(
        host=server_host,
        port=server_port,
        username=server_username,
        password=server_password,
        private_key_text=server_private_key,
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
        return redirect(url_for("admin_home"))

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

        deploy_ok, deploy_message, final_token, deploy_log = deploy_vpn_node_server(
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
            deploy_log=deploy_log,
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
    server_region = normalize_server_region(request.form.get("server_region", ""))
    host = normalize_remote_host(request.form.get("host", ""))
    port = normalize_server_port(request.form.get("port", "22"), 22)
    username = (request.form.get("username", "") or "").strip()
    password = request.form.get("password", "") or ""
    ssh_private_key = request.form.get("ssh_private_key", "") or ""
    wg_port = SERVER_DEPLOY_DEFAULT_WG_PORT
    openvpn_port = SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
    dns_port = SERVER_DEPLOY_DEFAULT_DNS_PORT

    if not host or not username or (not password and not (ssh_private_key or "").strip()):
        flash("请完整填写服务器地址、账号，并提供密码或私钥。", "error")
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
        domain="",
        wg_port=wg_port,
        openvpn_port=openvpn_port,
        dns_port=dns_port,
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

    server_region = normalize_server_region(request.form.get("server_region", ""))
    host = normalize_remote_host(request.form.get("host", ""))
    port = normalize_server_port(request.form.get("port", "22"), 22)
    username = (request.form.get("username", "") or "").strip()
    password_raw = request.form.get("password", "") or ""
    private_key_raw = request.form.get("ssh_private_key", "") or ""
    wg_port = SERVER_DEPLOY_DEFAULT_WG_PORT
    openvpn_port = SERVER_DEPLOY_DEFAULT_OPENVPN_PORT
    dns_port = SERVER_DEPLOY_DEFAULT_DNS_PORT

    if not host or not username:
        flash("服务器地址和账号不能为空。", "error")
        return redirect(url_for("admin_servers"))
    server_name = host

    password_to_save = password_raw if password_raw else (row_get(row, "password", "") or "")
    private_key_to_save = (
        private_key_raw.strip()
        if private_key_raw.strip()
        else (row_get(row, "ssh_private_key", "") or "")
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
            wg_port = ?,
            openvpn_port = ?,
            dns_port = ?,
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
            wg_port,
            openvpn_port,
            dns_port,
            utcnow_iso(),
            server_id,
        ),
    )

    db.commit()
    flash("服务器信息已更新。", "success")
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
        f"服务器 {server_label} 升级任务已启动，会在原主机拉取 GitHub 最新代码并重启 vpnserver 本地服务。",
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
        return redirect(url_for("admin_home"))

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
        return redirect(url_for("admin_home"))

    append_system_upgrade_log(message)
    flash("系统升级任务已派发到宿主机，Web 会在新版本构建完成后自动重启。", "success")
    return redirect(url_for("admin_home"))


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

@app.route("/admin/home")
@login_required
@admin_required
def admin_home():
    db = get_db()
    reconcile_expired_subscriptions(db)
    pending_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM payment_orders WHERE status = 'pending'"
    ).fetchone()["cnt"]
    total_users = db.execute(
        "SELECT COUNT(*) AS cnt FROM users WHERE role='user'"
    ).fetchone()["cnt"]
    server_overview = refresh_server_health_status(db)
    expiring_subscriptions = load_expiring_subscriptions(db, days=7, limit=50)
    _, online_summary = load_admin_online_users(db)
    system_upgrade = load_system_upgrade_state_with_timeout_unlock(db)
    system_upgrade_log = read_system_upgrade_log_text()
    if not system_upgrade_log:
        status = (system_upgrade.get("status") or "").strip().lower()
        if status == "running":
            system_upgrade_log = "系统升级任务进行中，日志正在生成，请稍后刷新。"
        elif status in {"success", "failed"}:
            system_upgrade_log = "暂无系统升级日志，请确认数据卷映射与权限是否正常。"
        else:
            system_upgrade_log = "尚未触发系统升级。"
    db.commit()

    return render_template(
        "admin_home.html",
        pending_count=pending_count,
        total_users=total_users,
        online_user_count=int(online_summary.get("online_users", 0) or 0),
        abnormal_server_count=server_overview["abnormal"],
        expiring_count=len(expiring_subscriptions),
        system_upgrade=system_upgrade,
        system_upgrade_log=system_upgrade_log,
        admin_page="home",
    )


@app.route("/admin/configs")
@login_required
@admin_required
def admin_configs():
    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账户不存在。", "error")
        return redirect(url_for("admin_home"))

    admin_vpn_ready = bool(SHADOWSOCKS_ENABLED)
    admin_vpn_status_text = "已就绪（Shadowsocks + kcptun）" if SHADOWSOCKS_ENABLED else "未启用"
    admin_vpn_error = ""
    endpoint_display = "-"

    target_server = choose_runtime_server_for_admin(db, admin)
    target_server_name = "-"
    target_server_host = "-"
    if target_server is not None:
        target_server_name = (
            (row_get(target_server, "server_name", "") or "").strip()
            or (row_get(target_server, "host", "") or "").strip()
            or "-"
        )
        target_server_host = (row_get(target_server, "host", "") or "").strip() or "-"
        if admin_vpn_ready:
            endpoint_display = (
                resolve_shadowsocks_endpoint_host(user=admin, server_row=target_server) or "-"
            ).strip() or "-"

    available_servers = load_user_selectable_servers(db, admin)
    selected_default_server_id = 0
    assigned_server_id = row_get(admin, "assigned_server_id")
    if assigned_server_id is not None and str(assigned_server_id).strip():
        try:
            selected_default_server_id = int(assigned_server_id)
        except Exception:
            selected_default_server_id = 0
    if selected_default_server_id <= 0 and target_server is not None:
        selected_default_server_id = int(row_get(target_server, "id", 0) or 0)

    admin_ss_access_token = build_download_access_token(admin, "download-config-admin")
    admin_kcptun_access_token = build_download_access_token(admin, "download-kcptun-admin")
    admin_ss_download_link = (
        absolute_url_for("admin_download_config", format="yaml", access=admin_ss_access_token)
        if SHADOWSOCKS_ENABLED
        else ""
    )
    admin_kcptun_download_link = (
        absolute_url_for(
            "admin_download_kcptun_config",
            format="yaml",
            access=admin_kcptun_access_token,
        )
        if KCPTUN_ENABLED
        else ""
    )
    admin_ss_qr_link = absolute_url_for("admin_download_qr") if SHADOWSOCKS_ENABLED else ""

    db.commit()

    return render_template(
        "admin_configs.html",
        admin_user=admin,
        admin_vpn_ready=admin_vpn_ready,
        admin_vpn_status_text=admin_vpn_status_text,
        admin_vpn_error=admin_vpn_error,
        target_server_name=target_server_name,
        target_server_host=target_server_host,
        endpoint_display=endpoint_display,
        available_servers=available_servers,
        selected_default_server_id=selected_default_server_id,
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
        return redirect(url_for("admin_home"))

    server_id_raw = (request.form.get("server_id", "") or "").strip()
    if not server_id_raw.isdigit():
        flash("请选择有效的默认节点。", "error")
        return redirect(url_for("admin_configs"))

    server_id = int(server_id_raw)
    target_server = get_server_by_id(db, server_id)
    if not is_runtime_server_ready(target_server):
        flash("所选节点不可用，请选择在线节点。", "error")
        return redirect(url_for("admin_configs"))

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
    flash(f"管理员默认节点已更新为：{label}（Shadowsocks/kcptun 配置已按新节点生效）", "success")
    return redirect(url_for("admin_configs"))


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
    existing: sqlite3.Row | None = None,
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
    mail_server_id = int(cursor.lastrowid)
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
    db = get_db()
    reconcile_expired_subscriptions(db)
    plans = load_subscription_plans(db, active_only=False)
    pending_orders = load_admin_pending_orders(db)
    return render_template(
        "admin_payment.html",
        plans=plans,
        pending_orders=pending_orders,
        usdt_explorer_link=usdt_explorer_link,
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
    expiring_subscriptions = load_expiring_subscriptions(db, days=7, limit=20)
    return render_template(
        "admin_subscriptions.html",
        subscriptions=subscriptions,
        expiring_subscriptions=expiring_subscriptions,
        search_email=search_email,
        admin_ui_tz_name=ADMIN_UI_TZ_NAME,
        admin_page="subscriptions",
    )


@app.route("/admin/online-users")
@login_required
@admin_required
def admin_online_users():
    db = get_db()
    reconcile_expired_subscriptions(db)
    rows, summary = load_admin_online_users(db)
    db.commit()
    return render_template(
        "admin_online_users.html",
        online_users=rows,
        summary=summary,
        sampled_at=utcnow_iso(),
        sampled_at_epoch=int(utcnow().timestamp()),
        refresh_seconds=ADMIN_ONLINE_REFRESH_SECONDS,
        online_window_seconds=ADMIN_ONLINE_HANDSHAKE_WINDOW_SECONDS,
        admin_page="online_users",
    )


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
    search_email = request.values.get("q", "").strip()
    if search_email:
        return redirect(url_for("admin_subscriptions", q=search_email))
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


@app.route("/admin/settings/system", methods=["POST"])
@login_required
@admin_required
def admin_update_system_settings():
    db = get_db()
    registration_open = request.form.get("registration_open", "1").strip() == "1"
    order_expire_hours_raw = request.form.get("order_expire_hours", "").strip()
    gift_duration_raw = request.form.get("gift_duration_months", "").strip()
    gift_traffic_raw = request.form.get("gift_traffic_gb", "").strip()
    telegram_contact = request.form.get("telegram_contact", "").strip()
    site_title = request.form.get("site_title", "").strip()
    wireguard_open = request.form.get("wireguard_open", "0").strip() == "1"
    openvpn_open = request.form.get("openvpn_open", "1").strip() == "1"

    try:
        order_expire_hours = parse_int_setting(order_expire_hours_raw, 24, min_value=1)
        gift_duration_months = parse_int_setting(gift_duration_raw, 0, min_value=0)
        gift_traffic_gb = parse_int_setting(gift_traffic_raw, 0, min_value=0)
    except Exception:
        flash("系统设置参数无效。", "error")
        return redirect(url_for("admin_settings"))
    if wireguard_open and not WIREGUARD_ENABLED:
        flash("当前环境未启用 WireGuard 服务，无法开启。", "error")
        return redirect(url_for("admin_settings"))
    if openvpn_open and not OPENVPN_ENABLED:
        flash("当前环境未启用 OpenVPN 服务，无法开启。", "error")
        return redirect(url_for("admin_settings"))

    if not site_title:
        flash("站点标题不能为空。", "error")
        return redirect(url_for("admin_settings"))
    if order_expire_hours <= 0:
        flash("订单过期小时数必须大于 0。", "error")
        return redirect(url_for("admin_settings"))

    upsert_app_setting(db, SETTING_REGISTRATION_OPEN, "1" if registration_open else "0")
    upsert_app_setting(db, SETTING_ORDER_EXPIRE_HOURS, str(order_expire_hours))
    upsert_app_setting(db, SETTING_GIFT_DURATION_MONTHS, str(gift_duration_months))
    upsert_app_setting(db, SETTING_GIFT_TRAFFIC_GB, str(gift_traffic_gb))
    upsert_app_setting(db, SETTING_TELEGRAM_CONTACT, telegram_contact[:160])
    upsert_app_setting(db, SETTING_SITE_TITLE, site_title[:120])
    upsert_app_setting(db, SETTING_WIREGUARD_OPEN, "1" if wireguard_open else "0")
    upsert_app_setting(db, SETTING_OPENVPN_OPEN, "1" if openvpn_open else "0")
    if wireguard_open or openvpn_open:
        try:
            sync_runtime_protocol_state(
                db,
                wireguard_open=wireguard_open,
                openvpn_open=openvpn_open,
            )
        except Exception as exc:
            db.rollback()
            flash(f"协议状态同步到 VPN 节点失败：{exc}", "error")
            return redirect(url_for("admin_settings"))
    db.commit()
    flash("系统设置已更新。", "success")
    return redirect(url_for("admin_settings"))


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


@app.route("/admin/payment-methods/<int:method_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_payment_method(method_id: int):
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
        return redirect(url_for("admin_payment_methods"))

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
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/payment-methods/<int:method_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_payment_method(method_id: int):
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
        return redirect(url_for("admin_payment_methods"))

    db.execute("DELETE FROM payment_methods WHERE id = ?", (method_id,))
    sync_legacy_payment_settings_with_default_method(db)
    db.commit()
    flash(f"付款方式 {method['method_name']} 已删除。", "success")
    return redirect(url_for("admin_payment_methods"))


@app.route("/admin/plans/create", methods=["POST"])
@login_required
@admin_required
def admin_create_plan():
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
            assigned_server_id = vpn_data.get("assigned_server_id")
            if assigned_server_id is None:
                assigned_server_id = row_get(user, "assigned_server_id")
            db.execute(
                """
                UPDATE users
                SET assigned_ip = ?,
                    assigned_server_id = ?,
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
                    assigned_server_id,
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
            remove_wireguard_peer(user["client_public_key"], user=user)
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
        SELECT id, username, email, role, assigned_server_id, client_public_key, config_path, qr_path
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not user:
        flash("用户不存在。", "error")
        return redirect_admin_subscriptions()
    confirm_email = (request.form.get("confirm_email", "") or "").strip().lower()
    expected_email = ((user["email"] or "").strip()).lower()
    if not confirm_email or confirm_email != expected_email:
        flash("删除失败：请输入用户邮箱进行二次确认。", "error")
        return redirect_admin_subscriptions()

    try:
        if user["client_public_key"]:
            remove_wireguard_peer(user["client_public_key"], user=user)

        config_path = (user["config_path"] or "").strip()
        if config_path:
            Path(config_path).unlink(missing_ok=True)

        qr_path = (user["qr_path"] or "").strip()
        if qr_path:
            Path(qr_path).unlink(missing_ok=True)

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
        SELECT id, username, role, assigned_server_id, client_public_key, wg_enabled
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
            remove_wireguard_peer(user["client_public_key"], user=user)

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
            "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
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
def download_config():
    if not SHADOWSOCKS_ENABLED:
        return config_download_error("Shadowsocks is disabled", status=503)

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

    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
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

    filename = f"ss-{safe_name(user['username'])}.{'json' if build_raw else 'yaml'}"
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
    if not SHADOWSOCKS_ENABLED:
        return config_download_error("Shadowsocks is disabled", status=503)

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

    output_format = (request.args.get("format", "yaml") or "yaml").strip().lower()
    build_raw = output_format in {"json", "raw"}
    try:
        config_text = (
            build_user_shadowsocks_config(admin)
            if build_raw
            else build_user_shadowsocks_clash_profile(admin)
        )
    except Exception as exc:
        flash(f"管理员 Shadowsocks 配置生成失败：{exc}", "error")
        return redirect(url_for("admin_home"))

    filename = f"ss-admin-{safe_name(admin['username'])}.{'json' if build_raw else 'yaml'}"
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/download/kcptun")
def download_kcptun_config():
    if not KCPTUN_ENABLED:
        return config_download_error("kcptun is disabled", status=503)

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

    filename = f"kcptun-{safe_name(user['username'])}.{'json' if build_raw else 'yaml'}"
    headers = {
        "Content-Disposition": f'attachment; filename=\"{filename}\"',
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    mimetype = "application/json" if build_raw else "text/yaml; charset=utf-8"
    return Response(config_text, headers=headers, mimetype=mimetype)


@app.route("/admin/download/kcptun")
def admin_download_kcptun_config():
    if not KCPTUN_ENABLED:
        return config_download_error("kcptun is disabled", status=503)

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
        return redirect(url_for("admin_home"))

    filename = f"kcptun-admin-{safe_name(admin['username'])}.{'json' if build_raw else 'yaml'}"
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
    flash("系统已切换为 Shadowsocks + kcptun，OpenVPN 下载入口已停用。", "error")
    return redirect(url_for("dashboard_config"))


@app.route("/admin/download/openvpn")
@login_required
@admin_required
def admin_download_openvpn_config():
    flash("系统已切换为 Shadowsocks + kcptun，OpenVPN 下载入口已停用。", "error")
    return redirect(url_for("admin_configs"))


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
    if not SHADOWSOCKS_ENABLED:
        flash("Shadowsocks 当前未启用。", "error")
        return redirect(url_for("admin_home"))

    db = get_db()
    admin = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'admin'",
        (current_user()["id"],),
    ).fetchone()
    if not admin:
        flash("管理员账号不存在。", "error")
        return redirect(url_for("admin_home"))

    try:
        config_text = build_user_shadowsocks_uri(admin)
    except Exception as exc:
        flash(f"管理员二维码生成失败：{exc}", "error")
        return redirect(url_for("admin_home"))

    try:
        qr_png = render_qr_png(config_text)
    except Exception as exc:
        msg = str(exc).strip() or "未知错误"
        flash(f"管理员二维码生成失败：{msg}", "error")
        return redirect(url_for("admin_home"))

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
    if not SHADOWSOCKS_ENABLED:
        flash("Shadowsocks 当前未启用。", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    reconcile_expired_subscriptions(db)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not is_subscription_active(user):
        flash("订阅未生效或已过期，请先续费。", "error")
        return redirect(url_for("dashboard"))

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
