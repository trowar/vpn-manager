import psycopg
from flask import g
from psycopg.rows import dict_row

from portal_config import POSTGRES_DSN


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
    if upper.startswith("BEGIN IMMEDIATE"):
        return "BEGIN", ()
    normalized = sql.replace("COLLATE NOCASE", "")
    normalized = _replace_qmark_placeholders(normalized)
    return normalized, params


class PostgresCompatCursor:
    def __init__(self, conn, cursor, *, translated_sql: str):
        self._conn = conn
        self._cursor = cursor
        self._translated_sql = translated_sql

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


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


def get_table_columns(db, table_name: str) -> list[dict]:
    return db.execute(
        """
        SELECT column_name AS name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = ?
        ORDER BY ordinal_position
        """,
        (table_name,),
    ).fetchall()


DB_INTEGRITY_ERRORS = (psycopg.IntegrityError,)


def get_db():
    if "db" not in g:
        g.db = connect_postgres_db()
    return g.db


def close_db(_exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def register_db_teardown(app) -> None:
    app.teardown_appcontext(close_db)
