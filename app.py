import calendar
import hashlib
import hmac
import ipaddress
import os
import re
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

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

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
PLAN_OPTIONS = (1, 3, 6, 12)
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
    "usdt_price_1m",
    "usdt_price_3m",
    "usdt_price_6m",
    "usdt_price_12m",
)
REGISTER_COOLDOWN_SECONDS = 5 * 60
ADMIN_UI_TZ = timezone(timedelta(hours=8))
ADMIN_UI_TZ_NAME = "北京时间 (UTC+8)"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET_KEY", "change-this-secret")
_CLIENT_ALLOWED_IPS_CACHE: str | None = None


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


PLAN_PRICES = {
    1: parse_usdt_amount(USDT_PRICE_1M, "10"),
    3: parse_usdt_amount(USDT_PRICE_3M, "27"),
    6: parse_usdt_amount(USDT_PRICE_6M, "50"),
    12: parse_usdt_amount(USDT_PRICE_12M, "90"),
}


def parse_usdt_amount_strict(raw: str) -> Decimal:
    amount = Decimal((raw or "").strip())
    if amount <= 0:
        raise InvalidOperation("amount must be positive")
    return amount.quantize(Decimal("0.01"))


def default_payment_settings() -> dict[str, str]:
    return {
        "usdt_receive_address": USDT_RECEIVE_ADDRESS,
        "usdt_default_network": USDT_DEFAULT_NETWORK,
        "usdt_price_1m": format_usdt(PLAN_PRICES[1]),
        "usdt_price_3m": format_usdt(PLAN_PRICES[3]),
        "usdt_price_6m": format_usdt(PLAN_PRICES[6]),
        "usdt_price_12m": format_usdt(PLAN_PRICES[12]),
    }


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

    smart_modes = {"cn_local", "cn_split", "china-bypass", "overseas-proxy"}
    if WG_ROUTE_POLICY in smart_modes:
        routes = load_allowed_ips_from_file(WG_NON_CN_ROUTES_FILE)
        if routes:
            _CLIENT_ALLOWED_IPS_CACHE = ", ".join(routes)
            return _CLIENT_ALLOWED_IPS_CACHE

    _CLIENT_ALLOWED_IPS_CACHE = WG_CLIENT_ALLOWED_IPS
    return _CLIENT_ALLOWED_IPS_CACHE


def detect_wireguard_platform(user_agent: str) -> str:
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


def load_payment_settings(db: sqlite3.Connection) -> dict:
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

    p1_raw = raw_map.get("usdt_price_1m") or defaults["usdt_price_1m"]
    p3_raw = raw_map.get("usdt_price_3m") or defaults["usdt_price_3m"]
    p6_raw = raw_map.get("usdt_price_6m") or defaults["usdt_price_6m"]
    p12_raw = raw_map.get("usdt_price_12m") or defaults["usdt_price_12m"]

    plan_prices = {
        1: parse_usdt_amount(p1_raw, defaults["usdt_price_1m"]),
        3: parse_usdt_amount(p3_raw, defaults["usdt_price_3m"]),
        6: parse_usdt_amount(p6_raw, defaults["usdt_price_6m"]),
        12: parse_usdt_amount(p12_raw, defaults["usdt_price_12m"]),
    }

    return {
        "usdt_receive_address": address,
        "usdt_default_network": network,
        "plan_prices": plan_prices,
        "price_1m": format_usdt(plan_prices[1]),
        "price_3m": format_usdt(plan_prices[3]),
        "price_6m": format_usdt(plan_prices[6]),
        "price_12m": format_usdt(plan_prices[12]),
    }


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
            wg_enabled INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_months INTEGER NOT NULL,
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
    migrate_schema(db)
    ensure_default_payment_settings(db)
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

    order_columns = {
        row["name"]: row
        for row in db.execute("PRAGMA table_info(payment_orders)").fetchall()
    }
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


def ensure_admin_user() -> None:
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@2026!")

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
    ).fetchone()
    if existing:
        return

    try:
        db.execute(
            """
            INSERT INTO users (username, email, password_hash, role, status, created_at, approved_at)
            VALUES (?, ?, ?, 'admin', 'approved', ?, ?)
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
    return {
        "current_user": current_user(),
        "plan_options": PLAN_OPTIONS,
        "plan_prices": {
            m: format_usdt(p) for m, p in payment_settings["plan_prices"].items()
        },
        "usdt_receive_address": payment_settings["usdt_receive_address"],
        "usdt_default_network": payment_settings["usdt_default_network"],
        "usdt_network_options": USDT_NETWORK_OPTIONS,
    }


@app.before_request
def auto_reconcile_subscriptions():
    if request.endpoint == "static":
        return None
    try:
        reconcile_expired_subscriptions(get_db())
    except Exception:
        app.logger.exception("Failed to reconcile expired subscriptions")
    return None


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
    dump = run_command(["wg", "show", WG_INTERFACE, "dump"], check=False)
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
    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "total_bytes": total_bytes,
        "rx_human": format_bytes(rx_bytes),
        "tx_human": format_bytes(tx_bytes),
        "total_human": format_bytes(total_bytes),
    }



def safe_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw)


def is_dynamic_ip_assignment_mode() -> bool:
    return WG_IP_ASSIGNMENT_MODE in {"dynamic", "lease", "pool"}


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



def build_client_config(client_private_key: str, client_psk: str, client_ip: str) -> str:
    if not WG_SERVER_PUBLIC_KEY_FILE.exists():
        raise RuntimeError(f"未找到服务端公钥文件：{WG_SERVER_PUBLIC_KEY_FILE}")
    server_public_key = WG_SERVER_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()
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
            f"AllowedIPs = {get_client_allowed_ips()}",
            f"Endpoint = {WG_ENDPOINT}",
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


def set_wireguard_peer(peer_public_key: str, peer_psk: str, client_ip: str) -> None:
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
    run_command(
        ["wg", "set", WG_INTERFACE, "peer", peer_public_key, "remove"],
        check=False,
    )
    run_command(["wg-quick", "save", WG_INTERFACE], check=False)


def generate_wireguard_bundle(username: str, user_id: int, client_ip: str):
    client_private_key = run_command(["wg", "genkey"])
    client_public_key = run_command(["wg", "pubkey"], input_text=f"{client_private_key}\n")
    client_psk = run_command(["wg", "genpsk"])

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


def is_subscription_active(user: sqlite3.Row) -> bool:
    expires_at = parse_iso(user["subscription_expires_at"])
    if not expires_at:
        return False
    return user["wg_enabled"] == 1 and expires_at >= utcnow()


def reconcile_expired_subscriptions(db: sqlite3.Connection) -> None:
    now = utcnow()
    rows = db.execute(
        """
        SELECT id, client_public_key, subscription_expires_at, wg_enabled
        FROM users
        WHERE role = 'user' AND wg_enabled = 1 AND subscription_expires_at IS NOT NULL
        """
    ).fetchall()

    changed = 0
    for row in rows:
        expires_at = parse_iso(row["subscription_expires_at"])
        if not expires_at or expires_at >= now:
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

    new_expire_at = calculate_new_expiry(
        user["subscription_expires_at"], int(order["plan_months"])
    )
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
    return {
        "status": "paid",
        "username": user["username"],
        "expires_at": new_expire_at,
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


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


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
    return {
        "ok": True,
        "message": "登录成功",
        "user": user_api_payload(user),
        "redirect": url_for("dashboard"),
    }, 200



@app.route("/logout")
def logout():
    session.clear()
    flash("已退出登录。", "success")
    return redirect(url_for("login"))



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
    traffic_stats = get_user_traffic_stats(user)

    return render_template(
        "dashboard_home.html",
        user=user,
        active=is_subscription_active(user),
        traffic_stats=traffic_stats,
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

    pending_orders = db.execute(
        """
        SELECT id, plan_months, status, created_at,
               payment_method, usdt_network, usdt_amount, pay_to_address, tx_hash, tx_submitted_at
        FROM payment_orders
        WHERE user_id = ? AND status = 'pending'
        ORDER BY created_at DESC
        """,
        (user["id"],),
    ).fetchall()
    paid_orders = db.execute(
        """
        SELECT id, plan_months, status, created_at, paid_at,
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

    months_raw = request.form.get("months", "0").strip()
    try:
        months = int(months_raw)
    except ValueError:
        months = 0

    if months not in PLAN_OPTIONS:
        flash("套餐选择无效。", "error")
        return redirect(url_for("dashboard_orders"))

    db = get_db()
    payment_settings = load_payment_settings(db)
    network = payment_settings["usdt_default_network"]
    receive_address = payment_settings["usdt_receive_address"]
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

    usdt_amount = payment_settings["plan_prices"][months]
    db.execute(
        """
        INSERT INTO payment_orders (
            user_id, plan_months, payment_method, usdt_network, usdt_amount,
            pay_to_address, status, created_at
        )
        VALUES (?, ?, 'usdt', ?, ?, ?, 'pending', ?)
        """,
        (
            user["id"],
            months,
            network,
            format_usdt(usdt_amount),
            receive_address,
            utcnow_iso(),
        ),
    )
    db.commit()
    flash(
        f"USDT 订单已创建：{months} 个月 / {format_usdt(usdt_amount)} USDT。请完成支付后提交 TxHash。",
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


def load_admin_subscriptions(db: sqlite3.Connection):
    return db.execute(
        """
        SELECT
            id,
            username,
            email,
            assigned_ip,
            subscription_expires_at,
            wg_enabled
        FROM users
        WHERE role = 'user'
        ORDER BY subscription_expires_at DESC, id DESC
        """
    ).fetchall()


@app.route("/admin/home")
@login_required
@admin_required
def admin_home():
    db = get_db()
    reconcile_expired_subscriptions(db)

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
        admin_page="home",
    )


@app.route("/admin/payment")
@login_required
@admin_required
def admin_payment_settings():
    db = get_db()
    payment_settings = load_payment_settings(db)
    return render_template(
        "admin_payment.html",
        payment_settings=payment_settings,
        admin_page="payment",
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
    subscriptions = load_admin_subscriptions(db)
    return render_template(
        "admin_subscriptions.html",
        subscriptions=subscriptions,
        admin_ui_tz_name=ADMIN_UI_TZ_NAME,
        admin_page="subscriptions",
    )


@app.route("/admin/settings/payment", methods=["POST"])
@login_required
@admin_required
def admin_update_payment_settings():
    db = get_db()
    receive_address = request.form.get("usdt_receive_address", "").strip()
    network = request.form.get("usdt_default_network", "TRC20").strip().upper()
    p1 = request.form.get("price_1m", "").strip()
    p3 = request.form.get("price_3m", "").strip()
    p6 = request.form.get("price_6m", "").strip()
    p12 = request.form.get("price_12m", "").strip()

    if network not in USDT_NETWORK_OPTIONS:
        flash("默认 USDT 网络无效。", "error")
        return redirect(url_for("admin_payment_settings"))
    if not receive_address:
        flash("USDT 收款地址不能为空。", "error")
        return redirect(url_for("admin_payment_settings"))

    try:
        price_1m = parse_usdt_amount_strict(p1)
        price_3m = parse_usdt_amount_strict(p3)
        price_6m = parse_usdt_amount_strict(p6)
        price_12m = parse_usdt_amount_strict(p12)
    except Exception:
        flash("USDT 价格格式无效，请填写大于 0 的数字，例如 10 或 27.50。", "error")
        return redirect(url_for("admin_payment_settings"))

    upsert_app_setting(db, "usdt_receive_address", receive_address)
    upsert_app_setting(db, "usdt_default_network", network)
    upsert_app_setting(db, "usdt_price_1m", format_usdt(price_1m))
    upsert_app_setting(db, "usdt_price_3m", format_usdt(price_3m))
    upsert_app_setting(db, "usdt_price_6m", format_usdt(price_6m))
    upsert_app_setting(db, "usdt_price_12m", format_usdt(price_12m))
    db.commit()
    flash("支付设置已更新。", "success")
    return redirect(url_for("admin_payment_settings"))


@app.route("/admin/users/<int:user_id>/set-expiry", methods=["POST"])
@login_required
@admin_required
def admin_set_user_expiry(user_id: int):
    expires_raw = request.form.get("expires_at_local", "").strip()
    if not expires_raw:
        flash("请选择到期时间。", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        expires_at_utc = parse_admin_local_datetime(expires_raw)
    except Exception:
        flash("到期时间格式无效。", "error")
        return redirect(url_for("admin_subscriptions"))

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
        return redirect(url_for("admin_subscriptions"))

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
            return redirect(url_for("admin_subscriptions"))

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
    return redirect(url_for("admin_subscriptions"))


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
        return redirect(url_for("admin_subscriptions"))

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
    return redirect(url_for("admin_subscriptions"))


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
        return redirect(url_for("admin_subscriptions"))

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
    return redirect(url_for("admin_subscriptions"))


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
                f"订单确认成功。用户 {result['username']} 到期时间：{format_utc(result['expires_at'])}。",
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

    if not user["config_path"]:
        flash("配置文件尚未生成，请联系管理员。", "error")
        return redirect(url_for("dashboard"))

    path = Path(user["config_path"])
    if not path.exists():
        flash("配置文件不存在，请联系管理员。", "error")
        return redirect(url_for("dashboard"))

    return send_file(
        path,
        as_attachment=True,
        download_name=f"wg-{user['username']}.conf",
        mimetype="text/plain",
    )



@app.route("/download/qr")
@login_required
def download_qr():
    flash("配置二维码下载已关闭，请下载 .conf 配置文件导入 WireGuard 客户端。", "error")
    return redirect(url_for("dashboard_home"))


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
