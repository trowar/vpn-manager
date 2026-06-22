from typing import Any, Callable

from portal_services.deploy_logs import mask_secret, summarize_text
from portal_services.servers import (
    detect_server_region,
    normalize_remote_host,
    normalize_server_port,
    normalize_server_region,
)


DatabaseConnection = Any
DatabaseRow = dict[str, Any]


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


def refresh_missing_server_regions(
    db: DatabaseConnection,
    *,
    row_get: Callable[[DatabaseRow, str, Any], Any],
    utcnow_iso: Callable[[], str],
) -> None:
    rows = db.execute(
        """
        SELECT id, host, server_region
        FROM vpn_servers
        WHERE TRIM(COALESCE(server_region, '')) = ''
        LIMIT 10
        """
    ).fetchall()
    changed = False
    for row in rows:
        detected = detect_server_region(row_get(row, "host", ""))
        if detected:
            db.execute(
                "UPDATE vpn_servers SET server_region = ?, updated_at = ? WHERE id = ?",
                (detected, utcnow_iso(), int(row["id"])),
            )
            changed = True
    if changed:
        db.commit()


def normalize_relay_port(value, default: int) -> int:
    try:
        port = int(value)
    except Exception:
        port = default
    if port <= 1024 or port > 65535:
        return default
    return port


def load_admin_servers(
    db: DatabaseConnection,
    *,
    row_get: Callable[[DatabaseRow, str, Any], Any],
    get_server_ipv6_enabled: Callable[[DatabaseRow], bool | None],
    default_kcptun_port: int,
    default_openvpn_port: int,
    default_dns_port: int,
) -> list[dict]:
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
            kcptun_port,
            openvpn_port,
            dns_port,
            openvpn_enabled,
            shadowsocks_enabled,
            kcptun_enabled,
            ssh_tunnel_enabled,
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
        ipv6_enabled = get_server_ipv6_enabled(row)
        servers.append(
            {
                "id": row["id"],
                "server_name": (row["server_name"] or "").strip() or (row["host"] or "").strip(),
                "server_region": normalize_server_region(row["server_region"]),
                "server_region_display": normalize_server_region(row["server_region"]) or "未识别",
                "host": (row["host"] or "").strip(),
                "port": normalize_server_port(row["port"], 22),
                "username": (row["username"] or "").strip(),
                "password_masked": mask_secret(row["password"] or ""),
                "private_key_enabled": bool((row["ssh_private_key"] or "").strip()),
                "domain": (row["domain"] or "").strip(),
                "vpn_api_token_masked": mask_secret(row["vpn_api_token"] or "", visible=4),
                "kcptun_port": normalize_server_port(row["kcptun_port"], default_kcptun_port),
                "openvpn_port": normalize_server_port(row["openvpn_port"], default_openvpn_port),
                "dns_port": normalize_server_port(row["dns_port"], default_dns_port),
                "openvpn_enabled": int(row_get(row, "openvpn_enabled", 1) or 0) == 1,
                "shadowsocks_enabled": int(row_get(row, "shadowsocks_enabled", 0) or 0) == 1,
                "kcptun_enabled": int(row_get(row, "kcptun_enabled", 0) or 0) == 1,
                "ssh_tunnel_enabled": int(row_get(row, "ssh_tunnel_enabled", 1) or 0) == 1,
                "status": status,
                "ipv6_enabled": ipv6_enabled,
                "ipv6_status_text": (
                    "已开启" if ipv6_enabled is True else (
                        "已关闭" if ipv6_enabled is False else "未知"
                    )
                ),
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


def load_user_selectable_servers(
    db: DatabaseConnection,
    user: DatabaseRow,
    *,
    row_get: Callable[[DatabaseRow, str, Any], Any],
    normalize_domain_host: Callable[[str], str],
) -> list[dict]:
    preferred_server_id = row_get(user, "preferred_server_id", None)
    assigned_server_id = row_get(user, "assigned_server_id", None)
    rows = db.execute(
        """
        SELECT
            s.id,
            s.server_name,
            s.server_region,
            s.host,
            s.domain,
            s.openvpn_enabled,
            s.shadowsocks_enabled,
            s.kcptun_enabled,
            s.ssh_tunnel_enabled,
            s.status,
            s.last_allocated_at,
            COUNT(u.id) AS active_user_count
        FROM vpn_servers s
        LEFT JOIN users u
          ON u.assigned_server_id = s.id
         AND u.role = 'user'
         AND u.vpn_enabled = 1
        WHERE s.status = 'online'
          AND trim(COALESCE(s.domain, '')) <> ''
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
                "server_region_display": server_region or "未识别",
                "host": host,
                "endpoint_host": domain or host,
                "openvpn_enabled": int(row_get(row, "openvpn_enabled", 1) or 0) == 1,
                "shadowsocks_enabled": int(row_get(row, "shadowsocks_enabled", 0) or 0) == 1,
                "kcptun_enabled": int(row_get(row, "kcptun_enabled", 0) or 0) == 1,
                "ssh_tunnel_enabled": int(row_get(row, "ssh_tunnel_enabled", 1) or 0) == 1,
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
