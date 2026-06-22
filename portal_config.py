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
from typing import Any
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
    send_file,
    session,
    url_for,
)
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PORTAL_DATA_DIR", BASE_DIR / "data"))
DB_BACKEND = os.environ.get("PORTAL_DB_BACKEND", "postgres").strip().lower()
if DB_BACKEND != "postgres":
    DB_BACKEND = "postgres"
POSTGRES_DSN = os.environ.get(
    "PORTAL_POSTGRES_DSN",
    "postgresql://vpnportal:vpnportal@postgres:5432/vpnportal",
).strip()
CLIENT_CONF_DIR = Path(
    os.environ.get("PORTAL_CLIENT_CONF_DIR", DATA_DIR / "client-configs")
)
CLIENT_QR_DIR = Path(os.environ.get("PORTAL_CLIENT_QR_DIR", DATA_DIR / "client-qr"))
SHARED_VPN_MATERIALS_DIR = Path(
    os.environ.get("PORTAL_SHARED_VPN_MATERIALS_DIR", DATA_DIR / "shared-vpn-materials")
)
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
        "0",
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
HOST_WEB_UPGRADE_WEB_SERVICE = os.environ.get(
    "PORTAL_SELF_UPGRADE_WEB_SERVICE",
    "vpn-platform-v1-web.service",
).strip() or "vpn-platform-v1-web.service"

DatabaseConnection = Any
DatabaseRow = dict[str, Any]

# OpenVPN is the primary VPN core for the internal company deployment.
OPENVPN_ENABLED = os.environ.get("OPENVPN_ENABLED", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
SHADOWSOCKS_ENABLED = os.environ.get("SHADOWSOCKS_ENABLED", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
KCPTUN_ENABLED = os.environ.get("KCPTUN_ENABLED", "0").strip().lower() in (
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
KCPTUN_CRYPT = os.environ.get("KCPTUN_CRYPT", "aes").strip() or "aes"
KCPTUN_MODE = os.environ.get("KCPTUN_MODE", "fast3").strip() or "fast3"
KCPTUN_MTU_RAW = os.environ.get("KCPTUN_MTU", "1350").strip()
try:
    KCPTUN_MTU = int(KCPTUN_MTU_RAW)
except ValueError:
    KCPTUN_MTU = 1350
if KCPTUN_MTU <= 500 or KCPTUN_MTU > 1500:
    KCPTUN_MTU = 1350
KCPTUN_DATASHARD_RAW = os.environ.get("KCPTUN_DATASHARD", "10").strip()
KCPTUN_PARITYSHARD_RAW = os.environ.get("KCPTUN_PARITYSHARD", "10").strip()
try:
    KCPTUN_DATASHARD = int(KCPTUN_DATASHARD_RAW)
except ValueError:
    KCPTUN_DATASHARD = 10
if KCPTUN_DATASHARD <= 0 or KCPTUN_DATASHARD > 64:
    KCPTUN_DATASHARD = 10
try:
    KCPTUN_PARITYSHARD = int(KCPTUN_PARITYSHARD_RAW)
except ValueError:
    KCPTUN_PARITYSHARD = 10
if KCPTUN_PARITYSHARD < 0 or KCPTUN_PARITYSHARD > 64:
    KCPTUN_PARITYSHARD = 10
KCPTUN_NOCOMP = os.environ.get("KCPTUN_NOCOMP", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
OPENVPN_ENDPOINT_HOST = os.environ.get("OPENVPN_ENDPOINT_HOST", "").strip()
OPENVPN_ENDPOINT_PORT_RAW = os.environ.get("OPENVPN_ENDPOINT_PORT", "443").strip()
try:
    OPENVPN_ENDPOINT_PORT = int(OPENVPN_ENDPOINT_PORT_RAW)
except ValueError:
    OPENVPN_ENDPOINT_PORT = 443
if OPENVPN_ENDPOINT_PORT <= 0 or OPENVPN_ENDPOINT_PORT > 65535:
    OPENVPN_ENDPOINT_PORT = 443
OPENVPN_PROTO = os.environ.get("OPENVPN_PROTO", "tcp").strip().lower() or "tcp"
OPENVPN_CLIENT_DNS = os.environ.get("OPENVPN_CLIENT_DNS", "1.1.1.1").strip()
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
SINGLE_WEB_SESSION_ENABLED = (
    os.environ.get("PORTAL_SINGLE_WEB_SESSION", "1").strip().lower()
    in {"1", "true", "yes", "on"}
)
DOWNLOAD_ACCESS_IP_LOCK_ENABLED = (
    os.environ.get("PORTAL_DOWNLOAD_ACCESS_IP_LOCK", "1").strip().lower()
    in {"1", "true", "yes", "on"}
)
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
SHADOWSOCKS_RELAY_PORT_START_RAW = os.environ.get(
    "SHADOWSOCKS_RELAY_PORT_START",
    os.environ.get("OPENVPN_RELAY_PORT_START", "29000"),
).strip()
SHADOWSOCKS_RELAY_PORT_END_RAW = os.environ.get(
    "SHADOWSOCKS_RELAY_PORT_END",
    os.environ.get("OPENVPN_RELAY_PORT_END", "33999"),
).strip()
try:
    SHADOWSOCKS_RELAY_PORT_START = int(SHADOWSOCKS_RELAY_PORT_START_RAW)
except ValueError:
    SHADOWSOCKS_RELAY_PORT_START = 29000
try:
    SHADOWSOCKS_RELAY_PORT_END = int(SHADOWSOCKS_RELAY_PORT_END_RAW)
except ValueError:
    SHADOWSOCKS_RELAY_PORT_END = 33999
# Backward-compatible aliases for old constant names.
OPENVPN_RELAY_PORT_START = SHADOWSOCKS_RELAY_PORT_START
OPENVPN_RELAY_PORT_END = SHADOWSOCKS_RELAY_PORT_END
KCPTUN_RELAY_PORT_START_RAW = os.environ.get("KCPTUN_RELAY_PORT_START", "24000").strip()
KCPTUN_RELAY_PORT_END_RAW = os.environ.get("KCPTUN_RELAY_PORT_END", "28999").strip()
try:
    KCPTUN_RELAY_PORT_START = int(KCPTUN_RELAY_PORT_START_RAW)
except ValueError:
    KCPTUN_RELAY_PORT_START = 24000
try:
    KCPTUN_RELAY_PORT_END = int(KCPTUN_RELAY_PORT_END_RAW)
except ValueError:
    KCPTUN_RELAY_PORT_END = 28999
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
SERVER_DEPLOY_DEFAULT_KCPTUN_PORT = 29900
SERVER_DEPLOY_DEFAULT_SHADOWSOCKS_PORT = 8388
# Backward-compatible alias for legacy references.
SERVER_DEPLOY_DEFAULT_OPENVPN_PORT = 443
SERVER_DEPLOY_DEFAULT_DNS_PORT = 53
SERVER_DEPLOY_DEFAULT_VPN_API_PORT = 8081
PRD_BLOCKED_ADMIN_ENDPOINT_MARKERS = ("onboarding", "cloudflare")
PRD_BLOCKED_ADMIN_ENDPOINTS = {
    "admin_domains",
    "admin_create_domain",
    "admin_update_domain",
    "admin_toggle_domain",
    "admin_delete_domain",
    "admin_paid_orders",
}
