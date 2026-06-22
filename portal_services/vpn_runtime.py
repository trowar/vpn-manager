from __future__ import annotations

from datetime import datetime, timezone
import re

from portal_auth import normalize_public_client_ip


def parse_endpoint_port(token: str) -> int | None:
    raw = (token or "").strip()
    if not raw:
        return None
    if raw.startswith("[") and "]" in raw:
        right = raw.find("]")
        if right > 0 and len(raw) > right + 2 and raw[right + 1] == ":":
            tail = raw[right + 2 :]
            return int(tail) if tail.isdigit() else None
        return None
    if raw.count(":") == 1:
        _host, tail = raw.rsplit(":", 1)
        return int(tail) if tail.isdigit() else None
    if raw.rfind(":") > 0:
        tail = raw.rsplit(":", 1)[-1]
        return int(tail) if tail.isdigit() else None
    return None


def extract_ss_connection_meta(
    raw_line: str,
    allowed_ports: set[int] | None = None,
) -> tuple[str, int | None]:
    tokens = [token.strip() for token in (raw_line or "").split() if token.strip()]
    if len(tokens) < 2:
        return "", None
    for idx, token in enumerate(tokens):
        local_port = parse_endpoint_port(token)
        if local_port is None:
            continue
        if allowed_ports and local_port not in allowed_ports:
            continue
        if idx + 1 >= len(tokens):
            continue
        return normalize_public_client_ip(tokens[idx + 1]), int(local_port)
    return "", None


def parse_shadowsocks_active_peer_snapshot(
    raw_text: str,
    *,
    server_ports: list[int] | set[int] | tuple[int, ...] | None = None,
    default_port: int,
    normalize_port,
) -> tuple[list[str], dict[str, dict[str, int]], dict[str, int], dict[int, dict[str, int]]]:
    allowed_ports: set[int] | None = None
    if server_ports is not None:
        cleaned_ports = {
            normalize_port(port, default_port)
            for port in server_ports
            if normalize_port(port, default_port) > 0
        }
        if cleaned_ports:
            allowed_ports = cleaned_ports
    peers: set[str] = set()
    peer_stats: dict[str, dict[str, int]] = {}
    port_stats: dict[int, dict[str, int]] = {}
    aggregate_rx = 0
    aggregate_tx = 0
    current_host = ""
    current_port: int | None = None
    for raw_line in (raw_text or "").splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        host, local_port = extract_ss_connection_meta(line, allowed_ports)
        if local_port is not None:
            current_port = int(local_port)
            port_stats.setdefault(
                current_port, {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
            )
        if host:
            current_host = host
            peers.add(host)
            peer_stats.setdefault(host, {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0})

        rx_match = re.search(r"bytes_received[:=](\d+)", line)
        tx_ack_match = re.search(r"bytes_acked[:=](\d+)", line)
        tx_sent_match = re.search(r"bytes_sent[:=](\d+)", line)
        if not (rx_match or tx_ack_match or tx_sent_match):
            continue
        rx_bytes = int(rx_match.group(1)) if rx_match else 0
        tx_bytes = int(tx_ack_match.group(1)) if tx_ack_match else (
            int(tx_sent_match.group(1)) if tx_sent_match else 0
        )
        rx_bytes = max(0, rx_bytes)
        tx_bytes = max(0, tx_bytes)
        aggregate_rx += rx_bytes
        aggregate_tx += tx_bytes
        if current_port is not None:
            stats_by_port = port_stats.setdefault(
                int(current_port), {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
            )
            stats_by_port["rx_bytes"] += rx_bytes
            stats_by_port["tx_bytes"] += tx_bytes
            stats_by_port["total_bytes"] += rx_bytes + tx_bytes
        if current_host:
            stats = peer_stats.setdefault(
                current_host, {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
            )
            stats["rx_bytes"] += rx_bytes
            stats["tx_bytes"] += tx_bytes
            stats["total_bytes"] += rx_bytes + tx_bytes
    aggregate = {
        "rx_bytes": max(0, aggregate_rx),
        "tx_bytes": max(0, aggregate_tx),
        "total_bytes": max(0, aggregate_rx + aggregate_tx),
    }
    return sorted(peers), peer_stats, aggregate, port_stats


def parse_kcptun_active_peer_hosts(raw_text: str) -> list[str]:
    peers: set[str] = set()
    pattern = re.compile(r"(?:remote address:\s*|in:\s*)(\[[^\]]+\]:\d+|[^()\s]+)")
    for raw_line in (raw_text or "").splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        match = pattern.search(line)
        if not match:
            continue
        endpoint = (match.group(1) or "").split("(", 1)[0].strip()
        host = normalize_public_client_ip(endpoint)
        if not host:
            continue
        peers.add(host)
    return sorted(peers)


def build_shadowsocks_sport_filter_expr(
    ports: list[int] | set[int] | tuple[int, ...],
    *,
    default_port: int,
    normalize_port,
) -> str:
    normalized = sorted(
        {
            normalize_port(port, default_port)
            for port in ports
            if normalize_port(port, default_port) > 0
        }
    )
    if not normalized:
        return f"( sport = :{default_port} )"
    if len(normalized) == 1:
        return f"( sport = :{normalized[0]} )"
    joined = " or ".join(f"sport = :{port}" for port in normalized)
    return f"( {joined} )"


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


def format_bytes_in_mb(num_bytes: int) -> str:
    value = float(max(0, int(num_bytes))) / (1024 ** 2)
    return f"{value:.2f} MB"


def format_bytes_in_gb(num_bytes: int) -> str:
    value = float(max(0, int(num_bytes))) / (1024 ** 3)
    return f"{value:.2f} GB"


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
