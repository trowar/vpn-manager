from typing import Any


def server_endpoint_label(row: Any, row_get) -> str:
    domain = (row_get(row, "server_domain", "") or "").strip()
    host = (row_get(row, "server_host", "") or "").strip()
    return domain or host or "-"


def server_display_label(row: Any, row_get, normalize_server_region) -> str:
    region = normalize_server_region(row_get(row, "server_region", ""))
    name = (row_get(row, "server_name", "") or "").strip() or (
        row_get(row, "server_host", "") or ""
    ).strip()
    endpoint = server_endpoint_label(row, row_get)
    return " / ".join(part for part in [region, name, endpoint] if part and part != "-") or "-"


def decorate_admin_subscription_row(row: Any, row_get, normalize_server_region) -> dict:
    item = dict(row)
    item["assigned_server_endpoint"] = server_endpoint_label(row, row_get)
    item["assigned_server_display"] = server_display_label(
        row,
        row_get,
        normalize_server_region,
    )
    return item


def apply_user_server_switch(
    db,
    *,
    user_id: int,
    server_id: int,
    row_get,
    get_server_by_id,
    is_runtime_server_ready,
    ensure_user_vpn_ready,
    utcnow_iso,
) -> tuple[bool, str]:
    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ? AND role = 'user'
        LIMIT 1
        """,
        (int(user_id),),
    ).fetchone()
    if not user:
        return False, "用户不存在。"

    target_server = get_server_by_id(db, int(server_id))
    if not is_runtime_server_ready(target_server):
        return False, "所选服务器不可用，请选择在线服务器。"

    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE users
        SET preferred_server_id = ?,
            assigned_server_id = ?
        WHERE id = ? AND role = 'user'
        """,
        (int(server_id), int(server_id), int(user_id)),
    )
    db.execute(
        """
        UPDATE vpn_servers
        SET last_allocated_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (now_iso, now_iso, int(server_id)),
    )

    refreshed = db.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'user' LIMIT 1",
        (int(user_id),),
    ).fetchone()
    if refreshed and int(row_get(refreshed, "vpn_enabled", 0) or 0) == 1:
        ensure_user_vpn_ready(db, refreshed)

    region = (row_get(target_server, "server_region", "") or "").strip()
    name = (row_get(target_server, "server_name", "") or "").strip() or (
        row_get(target_server, "host", "") or ""
    ).strip()
    endpoint = (row_get(target_server, "domain", "") or "").strip() or (
        row_get(target_server, "host", "") or ""
    ).strip()
    label = " / ".join(part for part in [region, name, endpoint] if part)
    return True, f"用户 {user['username']} 已切换到服务器：{label or endpoint or name}。"
