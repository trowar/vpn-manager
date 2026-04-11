import sqlite3
from datetime import datetime, timezone

from flask import current_app, g
from werkzeug.security import generate_password_hash


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db_schema(db: sqlite3.Connection):
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email_verified INTEGER NOT NULL DEFAULT 0,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            plan_type TEXT NOT NULL,
            duration_months INTEGER,
            traffic_gb INTEGER,
            price_usdt TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            duration_expire_at TEXT,
            traffic_total_mb INTEGER NOT NULL DEFAULT 0,
            traffic_used_mb INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            expire_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            ssh_port INTEGER NOT NULL DEFAULT 22,
            ssh_user TEXT NOT NULL,
            auth_mode TEXT NOT NULL DEFAULT 'password',
            ssh_secret TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            deploy_report TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            heartbeat_at TEXT,
            online_sessions INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'register',
            code TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            ip_address TEXT,
            expire_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )


def _column_exists(db: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_schema_migrations(db: sqlite3.Connection):
    if not _column_exists(db, "users", "session_version"):
        db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")

    if not _column_exists(db, "email_verifications", "purpose"):
        db.execute(
            "ALTER TABLE email_verifications ADD COLUMN purpose TEXT NOT NULL DEFAULT 'register'"
        )
    if not _column_exists(db, "email_verifications", "ip_address"):
        db.execute("ALTER TABLE email_verifications ADD COLUMN ip_address TEXT")
    if not _column_exists(db, "email_verifications", "used_at"):
        db.execute("ALTER TABLE email_verifications ADD COLUMN used_at TEXT")


def ensure_default_settings(db: sqlite3.Connection):
    now = utcnow_iso()
    default_settings = {
        "registration_open": "1",
    }
    for key, value in default_settings.items():
        db.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO NOTHING
            """,
            (key, value, now),
        )


def ensure_default_admin(db: sqlite3.Connection):
    row = db.execute("SELECT id FROM users WHERE email = 'admin' LIMIT 1").fetchone()
    if row:
        return
    now = utcnow_iso()
    db.execute(
        """
        INSERT INTO users (
            email, password_hash, role, email_verified, must_change_password,
            session_version, status, created_at, updated_at
        )
        VALUES (?, ?, 'admin', 1, 1, 1, 'active', ?, ?)
        """,
        ("admin", generate_password_hash("admin"), now, now),
    )


def init_db():
    db = get_db()
    init_db_schema(db)
    ensure_schema_migrations(db)
    ensure_default_settings(db)
    ensure_default_admin(db)
    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Initialized SQLite database.")
