import os
import re
import subprocess
import tempfile
import ipaddress
from pathlib import Path

from flask import Flask, jsonify, request


WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_CONF_PATH = Path(
    os.environ.get("WG_CONF_PATH", f"/etc/wireguard/{WG_INTERFACE}.conf")
)
WG_SERVER_PUBLIC_KEY_FILE = Path(
    os.environ.get("WG_SERVER_PUBLIC_KEY_FILE", "/srv/vpn-shared/server_public.key")
)
VPN_API_TOKEN = os.environ.get("VPN_API_TOKEN", "").strip()
OPENVPN_SERVER_CONF = Path(
    os.environ.get("OPENVPN_SERVER_CONF", "/etc/openvpn/server/server.conf")
)
OPENVPN_CA_CERT_FILE = Path(
    os.environ.get("OPENVPN_CA_CERT_FILE", "/etc/openvpn/server/ca.crt")
)
OPENVPN_TLS_CRYPT_KEY_FILE = Path(
    os.environ.get("OPENVPN_TLS_CRYPT_KEY_FILE", "/etc/openvpn/server/tls-crypt.key")
)
OPENVPN_STATUS_FILE = Path(
    os.environ.get("OPENVPN_STATUS_FILE", "/tmp/openvpn-status.log")
)
OPENVPN_PID_FILE = Path(
    os.environ.get("OPENVPN_PID_FILE", "/run/openvpn-server.pid")
)
SHADOWSOCKS_SERVER_PORT_RAW = os.environ.get("SHADOWSOCKS_SERVER_PORT", "8388").strip()
KCPTUN_SERVER_PORT_RAW = os.environ.get("KCPTUN_SERVER_PORT", "29900").strip()
KCPTUN_SYSTEMD_UNIT = (
    os.environ.get("KCPTUN_SYSTEMD_UNIT", "vpnmanager-kcptun.service").strip()
    or "vpnmanager-kcptun.service"
)
try:
    SHADOWSOCKS_SERVER_PORT = int(SHADOWSOCKS_SERVER_PORT_RAW)
except Exception:
    SHADOWSOCKS_SERVER_PORT = 8388
if SHADOWSOCKS_SERVER_PORT <= 0 or SHADOWSOCKS_SERVER_PORT > 65535:
    SHADOWSOCKS_SERVER_PORT = 8388
try:
    KCPTUN_SERVER_PORT = int(KCPTUN_SERVER_PORT_RAW)
except Exception:
    KCPTUN_SERVER_PORT = 29900
if KCPTUN_SERVER_PORT <= 0 or KCPTUN_SERVER_PORT > 65535:
    KCPTUN_SERVER_PORT = 29900

app = Flask(__name__)


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
        raise RuntimeError(f"command failed: {' '.join(args)}; {stderr}")
    return completed.stdout.strip()


def unauthorized():
    return jsonify({"ok": False, "error": "unauthorized"}), 401


def is_wireguard_up() -> bool:
    return subprocess.run(
        ["wg", "show", WG_INTERFACE],
        capture_output=True,
        text=True,
        check=False,
    ).returncode == 0


def is_openvpn_running() -> bool:
    if OPENVPN_PID_FILE.exists():
        try:
            pid = int((OPENVPN_PID_FILE.read_text(encoding="utf-8") or "").strip())
        except Exception:
            pid = 0
        if pid > 0:
            try:
                os.kill(pid, 0)
                return True
            except Exception:
                pass
    return False


def endpoint_host(endpoint: str) -> str:
    raw = (endpoint or "").strip()
    if not raw or raw in {"*", "*:*"}:
        return ""
    if raw.startswith("[") and "]" in raw:
        right = raw.find("]")
        if right > 1:
            return raw[1:right]
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if host and port.isdigit():
            return host
    return raw


def is_loopback_host(raw_host: str) -> bool:
    host = (raw_host or "").strip().lower()
    if not host:
        return True
    if host in {"127.0.0.1", "::1", "localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except Exception:
        return False


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
        if allowed_ports and int(local_port) not in allowed_ports:
            continue
        if idx + 1 >= len(tokens):
            continue
        peer = endpoint_host(tokens[idx + 1])
        if not peer or is_loopback_host(peer):
            return "", int(local_port)
        return peer, int(local_port)
    return "", None


def parse_ss_peer_snapshot(
    raw_text: str,
    local_ports: list[int] | set[int] | tuple[int, ...] | None = None,
) -> tuple[list[str], dict[str, dict[str, int]], dict[str, int], dict[int, dict[str, int]]]:
    allowed_ports: set[int] | None = None
    if local_ports is not None:
        cleaned_ports = {
            int(port)
            for port in local_ports
            if isinstance(port, int) and 0 < int(port) <= 65535
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
            by_port = port_stats.setdefault(
                int(current_port), {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
            )
            by_port["rx_bytes"] += rx_bytes
            by_port["tx_bytes"] += tx_bytes
            by_port["total_bytes"] += rx_bytes + tx_bytes
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


def parse_kcptun_peer_hosts(raw_text: str) -> list[str]:
    peers: set[str] = set()
    pattern = re.compile(r"(?:remote address:\s*|in:\s*)(\[[^\]]+\]:\d+|[^()\s]+)")
    for raw_line in (raw_text or "").splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        match = pattern.search(line)
        if not match:
            continue
        candidate = endpoint_host((match.group(1) or "").split("(", 1)[0].strip())
        if not candidate or is_loopback_host(candidate):
            continue
        peers.add(candidate)
    return sorted(peers)


def parse_requested_ss_ports(raw_ports: str | None) -> list[int]:
    parts = [segment.strip() for segment in str(raw_ports or "").split(",")]
    result: list[int] = []
    for item in parts:
        if not item:
            continue
        if item.isdigit():
            port = int(item)
            if 0 < port <= 65535:
                result.append(port)
    unique_sorted = sorted(set(result))
    if unique_sorted:
        return unique_sorted
    return [SHADOWSOCKS_SERVER_PORT]


def build_ss_sport_filter_expr(ports: list[int] | set[int] | tuple[int, ...]) -> str:
    normalized = sorted({int(port) for port in ports if 0 < int(port) <= 65535})
    if not normalized:
        return f"( sport = :{SHADOWSOCKS_SERVER_PORT} )"
    if len(normalized) == 1:
        return f"( sport = :{normalized[0]} )"
    return "( " + " or ".join(f"sport = :{port}" for port in normalized) + " )"


@app.before_request
def require_token():
    if request.path == "/healthz":
        return None
    if not VPN_API_TOKEN:
        return None
    token = (request.headers.get("X-VPN-Token") or "").strip()
    if token != VPN_API_TOKEN:
        return unauthorized()
    return None


@app.route("/healthz")
def healthz():
    return {"ok": True}


@app.route("/wireguard/server-public-key")
def wireguard_server_public_key():
    if WG_SERVER_PUBLIC_KEY_FILE.exists():
        key = WG_SERVER_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()
    else:
        key = run_command(["wg", "show", WG_INTERFACE, "public-key"], check=False).strip()
    if not key:
        return {"ok": False, "error": "wireguard server public key not found"}, 500
    return {"ok": True, "public_key": key}


@app.route("/wireguard/dump")
def wireguard_dump():
    interface = (request.args.get("interface") or WG_INTERFACE).strip() or WG_INTERFACE
    dump = run_command(["wg", "show", interface, "dump"], check=False)
    return {"ok": True, "dump": dump}


@app.route("/shadowsocks/active-peers")
def shadowsocks_active_peers():
    ports = parse_requested_ss_ports(request.args.get("ports"))
    raw = run_command(
        [
            "ss",
            "-Htni",
            "state",
            "established",
            build_ss_sport_filter_expr(ports),
        ],
        check=False,
    )
    peers, peer_stats, aggregate, port_stats = parse_ss_peer_snapshot(raw, ports)
    return {
        "ok": True,
        "mode": "shadowsocks",
        "ports": ports,
        "peers": peers,
        "peer_stats": peer_stats,
        "aggregate": aggregate,
        "aggregate_by_port": {str(port): stat for port, stat in port_stats.items()},
    }


@app.route("/kcptun/active-peers")
def kcptun_active_peers():
    window_raw = (request.args.get("window") or "").strip()
    limit_raw = (request.args.get("limit") or "").strip()
    ports = parse_requested_ss_ports(request.args.get("ports"))
    try:
        window = max(30, min(3600, int(window_raw or "180")))
    except Exception:
        window = 180
    try:
        limit = max(50, min(3000, int(limit_raw or "800")))
    except Exception:
        limit = 800
    log_text = run_command(
        [
            "journalctl",
            "-u",
            KCPTUN_SYSTEMD_UNIT,
            "--since",
            f"-{window} seconds",
            "--no-pager",
            "-n",
            str(limit),
        ],
        check=False,
    )
    peers = parse_kcptun_peer_hosts(log_text)
    ss_raw = run_command(
        [
            "ss",
            "-Htni",
            "state",
            "established",
            build_ss_sport_filter_expr(ports),
        ],
        check=False,
    )
    _ss_peers, _ss_peer_stats, ss_aggregate, ss_port_stats = parse_ss_peer_snapshot(
        ss_raw, ports
    )
    return {
        "ok": True,
        "mode": "kcptun",
        "port": KCPTUN_SERVER_PORT,
        "ports": ports,
        "window_seconds": window,
        "peers": peers,
        "peer_stats": {},
        "aggregate": ss_aggregate,
        "aggregate_by_port": {str(port): stat for port, stat in ss_port_stats.items()},
    }


def parse_openvpn_active_identities(raw_text: str) -> list[str]:
    identities: set[str] = set()
    in_client_section = False
    for raw_line in (raw_text or "").splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        if line.startswith("CLIENT_LIST,"):
            parts = line.split(",")
            if len(parts) > 1:
                candidate = (parts[1] or "").strip().lower()
                if candidate and candidate != "common name":
                    identities.add(candidate)
            continue
        if line.startswith("Common Name,"):
            in_client_section = True
            continue
        if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
            in_client_section = False
            continue
        if in_client_section and "," in line:
            candidate = (line.split(",", 1)[0] or "").strip().lower()
            if candidate and candidate != "common name":
                identities.add(candidate)
    return sorted(identities)


@app.route("/openvpn/active-users")
def openvpn_active_users():
    if not OPENVPN_STATUS_FILE.exists():
        return {"ok": True, "users": []}
    raw_text = OPENVPN_STATUS_FILE.read_text(encoding="utf-8", errors="ignore")
    return {"ok": True, "users": parse_openvpn_active_identities(raw_text)}


@app.route("/openvpn/client-materials")
def openvpn_client_materials():
    if not OPENVPN_CA_CERT_FILE.exists():
        return {"ok": False, "error": f"openvpn ca cert not found: {OPENVPN_CA_CERT_FILE}"}, 404
    ca_cert = OPENVPN_CA_CERT_FILE.read_text(encoding="utf-8").strip()
    if not ca_cert:
        return {"ok": False, "error": f"openvpn ca cert empty: {OPENVPN_CA_CERT_FILE}"}, 500
    tls_crypt_key = ""
    if OPENVPN_TLS_CRYPT_KEY_FILE.exists():
        tls_crypt_key = OPENVPN_TLS_CRYPT_KEY_FILE.read_text(encoding="utf-8").strip()
    return {"ok": True, "ca_cert": ca_cert, "tls_crypt_key": tls_crypt_key}


@app.route("/wireguard/generate-keys", methods=["POST"])
def wireguard_generate_keys():
    private_key = run_command(["wg", "genkey"])
    public_key = run_command(["wg", "pubkey"], input_text=f"{private_key}\n")
    psk = run_command(["wg", "genpsk"])
    return {
        "ok": True,
        "private_key": private_key,
        "public_key": public_key,
        "preshared_key": psk,
    }


@app.route("/wireguard/set-peer", methods=["POST"])
def wireguard_set_peer():
    payload = request.get_json(silent=True) or {}
    interface = (payload.get("interface") or WG_INTERFACE).strip() or WG_INTERFACE
    peer_public_key = (payload.get("peer_public_key") or "").strip()
    peer_psk = (payload.get("peer_psk") or "").strip()
    client_ip = (payload.get("client_ip") or "").strip()

    if not peer_public_key or not peer_psk or not client_ip:
        return {
            "ok": False,
            "error": "missing required fields: peer_public_key/peer_psk/client_ip",
        }, 400

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_psk:
        tmp_psk.write(peer_psk)
        tmp_psk.flush()
        tmp_psk_path = tmp_psk.name

    try:
        run_command(
            [
                "wg",
                "set",
                interface,
                "peer",
                peer_public_key,
                "preshared-key",
                tmp_psk_path,
                "allowed-ips",
                f"{client_ip}/32",
            ]
        )
        run_command(["wg-quick", "save", interface], check=False)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}, 500
    finally:
        Path(tmp_psk_path).unlink(missing_ok=True)

    return {"ok": True}


@app.route("/wireguard/remove-peer", methods=["POST"])
def wireguard_remove_peer():
    payload = request.get_json(silent=True) or {}
    interface = (payload.get("interface") or WG_INTERFACE).strip() or WG_INTERFACE
    peer_public_key = (payload.get("peer_public_key") or "").strip()
    if not peer_public_key:
        return {"ok": False, "error": "missing required field: peer_public_key"}, 400

    run_command(
        ["wg", "set", interface, "peer", peer_public_key, "remove"],
        check=False,
    )
    run_command(["wg-quick", "save", interface], check=False)
    return {"ok": True}


@app.route("/wireguard/control", methods=["POST"])
def wireguard_control():
    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").strip().lower()
    if action not in {"up", "down"}:
        return {"ok": False, "error": "invalid action"}, 400

    if action == "down":
        if not is_wireguard_up():
            return {"ok": True, "message": "wireguard already down"}
        run_command(["wg-quick", "down", WG_INTERFACE], check=False)
        return {"ok": True, "message": "wireguard stopped"}

    if is_wireguard_up():
        return {"ok": True, "message": "wireguard already up"}
    if not WG_CONF_PATH.exists():
        return {"ok": False, "error": "wireguard config not found"}, 404
    run_command(["wg-quick", "up", WG_INTERFACE], check=False)
    return {"ok": True, "message": "wireguard started"}


@app.route("/openvpn/control", methods=["POST"])
def openvpn_control():
    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").strip().lower()
    if action not in {"start", "stop"}:
        return {"ok": False, "error": "invalid action"}, 400

    if action == "stop":
        if is_openvpn_running():
            try:
                pid = int((OPENVPN_PID_FILE.read_text(encoding="utf-8") or "").strip())
            except Exception:
                pid = 0
            if pid > 0:
                try:
                    os.kill(pid, 15)
                except Exception:
                    pass
        OPENVPN_PID_FILE.unlink(missing_ok=True)
        return {"ok": True, "message": "openvpn stopped"}

    if is_openvpn_running():
        return {"ok": True, "message": "openvpn already running"}
    if not OPENVPN_SERVER_CONF.exists():
        return {"ok": False, "error": f"openvpn config not found: {OPENVPN_SERVER_CONF}"}, 404
    run_command(
        [
            "openvpn",
            "--config",
            str(OPENVPN_SERVER_CONF),
            "--daemon",
            "ovpn-server",
            "--writepid",
            str(OPENVPN_PID_FILE),
        ],
        check=False,
    )
    return {"ok": True, "message": "openvpn started"}


@app.errorhandler(Exception)
def handle_uncaught(exc):
    return {"ok": False, "error": str(exc)}, 500
