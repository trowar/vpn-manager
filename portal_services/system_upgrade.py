from pathlib import Path
from typing import Any, Callable


DatabaseConnection = Any


def load_system_upgrade_state(
    db: DatabaseConnection,
    *,
    get_setting: Callable[[DatabaseConnection, str, str], str],
    status_key: str,
    summary_key: str,
    started_at_key: str,
    finished_at_key: str,
    current_version: str,
) -> dict[str, str]:
    return {
        "status": get_setting(db, status_key, "idle"),
        "summary": get_setting(db, summary_key, ""),
        "started_at": get_setting(db, started_at_key, ""),
        "finished_at": get_setting(db, finished_at_key, ""),
        "version": current_version,
    }


def save_system_upgrade_state(
    *,
    status: str,
    summary: str,
    started_at: str = "",
    finished_at: str = "",
    open_direct_db_connection: Callable[[], DatabaseConnection],
    utcnow_iso: Callable[[], str],
    status_key: str,
    summary_key: str,
    started_at_key: str,
    finished_at_key: str,
) -> None:
    conn = open_direct_db_connection()
    try:
        for key, value in (
            (status_key, status),
            (summary_key, summary[:1000]),
            (started_at_key, started_at),
            (finished_at_key, finished_at),
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


def load_system_upgrade_state_with_timeout_unlock(
    db: DatabaseConnection,
    *,
    base_dir: Path,
    get_setting: Callable[[DatabaseConnection, str, str], str],
    get_current_app_version: Callable[[Path], str],
    parse_iso: Callable[[str], Any],
    utcnow: Callable[[], Any],
    utcnow_iso: Callable[[], str],
    append_log: Callable[[str], None],
    open_direct_db_connection: Callable[[], DatabaseConnection],
    running_timeout_seconds: int,
    status_key: str,
    summary_key: str,
    started_at_key: str,
    finished_at_key: str,
) -> dict[str, str]:
    state = load_system_upgrade_state(
        db,
        get_setting=get_setting,
        status_key=status_key,
        summary_key=summary_key,
        started_at_key=started_at_key,
        finished_at_key=finished_at_key,
        current_version=get_current_app_version(base_dir),
    )
    status = (state.get("status") or "").strip().lower()
    if status != "running":
        return state

    started_at_raw = (state.get("started_at") or "").strip()
    started_at = parse_iso(started_at_raw)
    if not started_at:
        return state

    elapsed_seconds = (utcnow() - started_at).total_seconds()
    if elapsed_seconds < running_timeout_seconds:
        return state

    timeout_minutes = max(1, running_timeout_seconds // 60)
    summary = (
        f"系统升级任务超过 {timeout_minutes} 分钟未完成，已自动解锁。"
        "请重新发起升级。"
    )
    append_log(
        "系统升级任务状态超时，自动解锁："
        f"started_at={started_at_raw}, timeout={running_timeout_seconds}s"
    )
    save_system_upgrade_state(
        status="failed",
        summary=summary,
        started_at=started_at_raw,
        finished_at=utcnow_iso(),
        open_direct_db_connection=open_direct_db_connection,
        utcnow_iso=utcnow_iso,
        status_key=status_key,
        summary_key=summary_key,
        started_at_key=started_at_key,
        finished_at_key=finished_at_key,
    )
    return load_system_upgrade_state(
        db,
        get_setting=get_setting,
        status_key=status_key,
        summary_key=summary_key,
        started_at_key=started_at_key,
        finished_at_key=finished_at_key,
        current_version=get_current_app_version(base_dir),
    )
