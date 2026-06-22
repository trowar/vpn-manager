from __future__ import annotations

import re

from portal_auth import row_get
from portal_web import normalize_domain_host
from portal_services.ip_region import detect_region_from_host


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


def detect_server_region(host: str | None, fallback: str = "") -> str:
    detected = normalize_server_region(detect_region_from_host(host))
    return detected or normalize_server_region(fallback)


def serialize_runtime_server(server_row) -> dict[str, int | str] | None:
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
        "server_region_display": server_region or "未识别",
        "host": host,
        "endpoint_host": domain or host,
        "openvpn_enabled": int(row_get(server_row, "openvpn_enabled", 1) or 0) == 1,
        "shadowsocks_enabled": int(row_get(server_row, "shadowsocks_enabled", 0) or 0)
        == 1,
        "kcptun_enabled": int(row_get(server_row, "kcptun_enabled", 0) or 0) == 1,
        "ssh_tunnel_enabled": int(row_get(server_row, "ssh_tunnel_enabled", 1) or 0)
        == 1,
        "display_name": (
            f"{server_region} / {server_name}" if server_region else server_name
        )
        or host,
    }


def server_supports_openvpn(server_row) -> bool:
    return bool(server_row and int(row_get(server_row, "openvpn_enabled", 1) or 0) == 1)


def server_supports_ss_kcptun(server_row) -> bool:
    return bool(
        server_row
        and int(row_get(server_row, "shadowsocks_enabled", 0) or 0) == 1
        and int(row_get(server_row, "kcptun_enabled", 0) or 0) == 1
    )


def server_supports_ssh_tunnel(server_row) -> bool:
    return bool(
        server_row
        and int(row_get(server_row, "ssh_tunnel_enabled", 1) or 0) == 1
        and normalize_remote_host(row_get(server_row, "host", ""))
    )


def get_server_kcptun_port(server_row, *, default_port: int) -> int:
    if server_row is None:
        return default_port
    return normalize_server_port(row_get(server_row, "kcptun_port", default_port), default_port)


def get_server_shadowsocks_backend_port(server_row, *, default_port: int) -> int:
    if server_row is None:
        return default_port
    return normalize_server_port(row_get(server_row, "openvpn_port", default_port), default_port)


def runtime_uses_kcptun(server_row, *, global_kcptun_enabled: bool = False) -> bool:
    if server_row is not None:
        return server_supports_ss_kcptun(server_row)
    return bool(global_kcptun_enabled)
