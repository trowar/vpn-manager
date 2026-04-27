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


def parse_ss_peer_hosts(raw_text: str, local_port: int) -> list[str]:
    peers: set[str] = set()
    suffix = f":{int(local_port)}"
    for raw_line in (raw_text or "").splitlines():
        tokens = [token.strip() for token in raw_line.split() if token.strip()]
        if len(tokens) < 2:
            continue
        for idx, token in enumerate(tokens):
            if not token.endswith(suffix):
                continue
            if idx + 1 >= len(tokens):
                continue
            peer = endpoint_host(tokens[idx + 1])
            if not peer or is_loopback_host(peer):
                continue
            peers.add(peer)
    return sorted(peers)


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
    raw = run_command(
        [
            "ss",
            "-Htn",
            "state",
            "established",
            f"( sport = :{SHADOWSOCKS_SERVER_PORT} )",
        ],
        check=False,
    )
    peers = parse_ss_peer_hosts(raw, SHADOWSOCKS_SERVER_PORT)
    return {
        "ok": True,
        "mode": "shadowsocks",
        "port": SHADOWSOCKS_SERVER_PORT,
        "peers": peers,
    }


@app.route("/kcptun/active-peers")
def kcptun_active_peers():
    window_raw = (request.args.get("window") or "").strip()
    limit_raw = (request.args.get("limit") or "").strip()
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
    return {
        "ok": True,
        "mode": "kcptun",
        "port": KCPTUN_SERVER_PORT,
        "window_seconds": window,
        "peers": peers,
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
