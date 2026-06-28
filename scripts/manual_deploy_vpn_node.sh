#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

APP_DIR="${APP_DIR:-/srv/vpn-node}"
REPO_URL="${REPO_URL:-https://github.com/trowar/vpn-manager.git}"
BRANCH="${BRANCH:-main}"
LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-/srv/vpn-platform-v1}"

SHADOWSOCKS_ENABLED="${SHADOWSOCKS_ENABLED:-0}"
SHADOWSOCKS_SERVER_PORT="${SHADOWSOCKS_SERVER_PORT:-8388}"
SHADOWSOCKS_PORT_RANGE_START="${SHADOWSOCKS_PORT_RANGE_START:-29000}"
SHADOWSOCKS_PORT_RANGE_END="${SHADOWSOCKS_PORT_RANGE_END:-33999}"
SHADOWSOCKS_METHOD="${SHADOWSOCKS_METHOD:-chacha20-ietf-poly1305}"
SHADOWSOCKS_PASSWORD="${SHADOWSOCKS_PASSWORD:-}"
KCPTUN_ENABLED="${KCPTUN_ENABLED:-1}"
KCPTUN_SERVER_PORT="${KCPTUN_SERVER_PORT:-29900}"
KCPTUN_KEY="${KCPTUN_KEY:-}"
KCPTUN_CRYPT="${KCPTUN_CRYPT:-aes}"
KCPTUN_MODE="${KCPTUN_MODE:-fast3}"
KCPTUN_MTU="${KCPTUN_MTU:-1350}"
KCPTUN_DATASHARD="${KCPTUN_DATASHARD:-10}"
KCPTUN_PARITYSHARD="${KCPTUN_PARITYSHARD:-10}"
KCPTUN_NOCOMP="${KCPTUN_NOCOMP:-1}"
KCPTUN_VERSION="${KCPTUN_VERSION:-latest}"
KCPTUN_DOWNLOAD_URL="${KCPTUN_DOWNLOAD_URL:-}"
OPENVPN_ENABLED="${OPENVPN_ENABLED:-1}"
OPENVPN_ENDPOINT_PORT="${OPENVPN_ENDPOINT_PORT:-443}"
OPENVPN_PROTO="${OPENVPN_PROTO:-tcp}"
OPENVPN_CLIENT_DNS="${OPENVPN_CLIENT_DNS:-1.1.1.1}"
OPENVPN_NETWORK="${OPENVPN_NETWORK:-10.8.0.0}"
OPENVPN_NETMASK="${OPENVPN_NETMASK:-255.255.255.0}"
OPENVPN_MATERIALS_DIR="${OPENVPN_MATERIALS_DIR:-/etc/openvpn/server-materials}"
PORTAL_POSTGRES_DSN="${PORTAL_POSTGRES_DSN:-}"

VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT:-8081}"
VPN_API_TOKEN="${VPN_API_TOKEN:-}"
DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE:-0}"
DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED:-1}"

PY_VENV_DIR="${PY_VENV_DIR:-${APP_DIR}/.venv-vpn}"

SHADOWSOCKS_CONF_DIR="/etc/shadowsocks-libev"
SHADOWSOCKS_CONF_FILE="${SHADOWSOCKS_CONF_DIR}/vpnmanager.json"
KCPTUN_CONF_DIR="/etc/kcptun"
KCPTUN_CONF_FILE="${KCPTUN_CONF_DIR}/server.json"
KCPTUN_BIN="/usr/local/bin/kcptun-server"
OPENVPN_SERVER_DIR="/etc/openvpn/server"
OPENVPN_SERVER_CONF="${OPENVPN_SERVER_DIR}/server.conf"
OPENVPN_CA_KEY_FILE="${OPENVPN_MATERIALS_DIR}/openvpn_ca.key"
OPENVPN_CA_CERT_FILE="${OPENVPN_MATERIALS_DIR}/openvpn_ca.crt"
OPENVPN_SERVER_KEY_FILE="${OPENVPN_MATERIALS_DIR}/openvpn_server.key"
OPENVPN_SERVER_CERT_FILE="${OPENVPN_MATERIALS_DIR}/openvpn_server.crt"
OPENVPN_TLS_CRYPT_KEY_FILE="${OPENVPN_MATERIALS_DIR}/openvpn_tls_crypt.key"

SHADOWSOCKS_SERVICE_NAME="vpnmanager-shadowsocks.service"
KCPTUN_SERVICE_NAME="vpnmanager-kcptun.service"
OPENVPN_SERVICE_NAME="openvpn-server@server.service"
OPENVPN_NAT_SERVICE_NAME="vpnmanager-openvpn-nat.service"
VPN_API_SERVICE_NAME="vpnmanager-server.service"

PM=""

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

log() {
  echo "[manual-deploy] $*"
}

warn() {
  echo "[manual-deploy][warn] $*" >&2
}

err() {
  echo "[manual-deploy][error] $*" >&2
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "please run as root"
    exit 1
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

retry_cmd() {
  local retries="$1"
  local delay="$2"
  shift 2
  local attempt=1
  local code=0

  while true; do
    code=0
    "$@" || code=$?
    if [ "$code" -eq 0 ]; then
      return 0
    fi
    if [ "$attempt" -ge "$retries" ]; then
      return "$code"
    fi
    warn "command failed (exit=${code}), retry ${attempt}/${retries} in ${delay}s: $*"
    attempt=$((attempt + 1))
    sleep "$delay"
  done
}

apt_cmd() {
  DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt-get \
    -o DPkg::Lock::Timeout=600 \
    -o Acquire::Retries=3 \
    -o Dpkg::Use-Pty=0 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    "$@"
}

detect_pm() {
  if has_cmd apt-get; then
    PM="apt"
    return 0
  fi
  if has_cmd dnf; then
    PM="dnf"
    return 0
  fi
  if has_cmd yum; then
    PM="yum"
    return 0
  fi
  err "unsupported package manager (apt/dnf/yum required)"
  exit 1
}

pkg_update() {
  if [ "$PM" = "apt" ]; then
    retry_cmd 5 8 apt_cmd update
    return 0
  fi
  if [ "$PM" = "dnf" ]; then
    retry_cmd 4 6 dnf -y -q makecache
    return 0
  fi
  retry_cmd 4 6 yum -y -q makecache
}

pkg_upgrade() {
  if [ "$DEPLOY_SKIP_OS_UPGRADE" = "1" ]; then
    log "skip full OS upgrade (DEPLOY_SKIP_OS_UPGRADE=1)"
    return 0
  fi
  log "upgrading system packages via ${PM}"
  if [ "$PM" = "apt" ]; then
    retry_cmd 5 8 apt_cmd upgrade -y || retry_cmd 5 8 apt_cmd dist-upgrade -y
    return 0
  fi
  if [ "$PM" = "dnf" ]; then
    retry_cmd 4 8 dnf -y -q upgrade --refresh || retry_cmd 4 8 dnf -y -q update
    return 0
  fi
  retry_cmd 4 8 yum -y -q update
}

pkg_install() {
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  if [ "$PM" = "apt" ]; then
    retry_cmd 5 8 apt_cmd install -y --no-install-recommends "$@"
    return 0
  fi
  if [ "$PM" = "dnf" ]; then
    retry_cmd 4 6 dnf -y -q install "$@"
    return 0
  fi
  retry_cmd 4 6 yum -y -q install "$@"
}

install_base_deps() {
  pkg_update
  pkg_upgrade

  local base_packages vpn_packages
  if [ "$PM" = "apt" ]; then
    base_packages="ca-certificates curl git openssl iproute2 iptables net-tools tar unzip python3 python3-venv python3-pip"
  else
    base_packages="ca-certificates curl git openssl iproute iptables net-tools tar unzip python3 python3-pip"
  fi
  vpn_packages=""
  if is_enabled "${OPENVPN_ENABLED}"; then
    vpn_packages="${vpn_packages} openvpn"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}"; then
    vpn_packages="${vpn_packages} shadowsocks-libev"
  fi
  pkg_install ${base_packages} ${vpn_packages}

  if is_enabled "${SHADOWSOCKS_ENABLED}" && ! has_cmd ss-server; then
    err "shadowsocks-libev install failed (ss-server missing)"
    exit 1
  fi
  if ! has_cmd python3; then
    err "python3 install failed"
    exit 1
  fi
  if is_enabled "${OPENVPN_ENABLED}" && ! has_cmd openvpn; then
    err "openvpn install failed"
    exit 1
  fi
}

generate_token() {
  if has_cmd openssl; then
    openssl rand -hex 24
    return
  fi
  python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
}

normalize_port() {
  local raw="$1"
  local fallback="$2"
  if [[ "$raw" =~ ^[0-9]+$ ]] && [ "$raw" -ge 1 ] && [ "$raw" -le 65535 ]; then
    echo "$raw"
    return 0
  fi
  echo "$fallback"
}

setup_repo() {
  mkdir -p "$(dirname "${APP_DIR}")"

  if [ -n "${LOCAL_SOURCE_DIR}" ] \
    && [ -d "${LOCAL_SOURCE_DIR}" ] \
    && [ -f "${LOCAL_SOURCE_DIR}/app.py" ] \
    && [ -f "${LOCAL_SOURCE_DIR}/requirements.txt" ]; then
    log "copying repository from local source ${LOCAL_SOURCE_DIR} to ${APP_DIR}"
    rm -rf "${APP_DIR}"
    mkdir -p "${APP_DIR}"
    tar \
      --exclude='.git' \
      --exclude='.env' \
      --exclude='.env.*' \
      --exclude='.venv' \
      --exclude='.venv-vpn' \
      --exclude='data' \
      --exclude='tmp' \
      --exclude='__pycache__' \
      --exclude='client/dist' \
      --exclude='client/package' \
      --exclude='client-apple/.build' \
      --exclude='client-android/.gradle' \
      --exclude='client-android/app/build' \
      -C "${LOCAL_SOURCE_DIR}" -cf - . | tar -C "${APP_DIR}" -xf -
    return
  fi

  if [ -d "${APP_DIR}/.git" ]; then
    log "updating repository in ${APP_DIR}"
    retry_cmd 1 1 sh -c 'for u in "$1" "$2" "$3" "$4"; do git -C "$5" remote set-url origin "$u" >/dev/null 2>&1 || true; if command -v timeout >/dev/null 2>&1; then GIT_TERMINAL_PROMPT=0 timeout 45s git -c http.connectTimeout=10 -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 -C "$5" fetch --depth 1 origin "$6" && exit 0; else GIT_TERMINAL_PROMPT=0 git -c http.connectTimeout=10 -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 -C "$5" fetch --depth 1 origin "$6" && exit 0; fi; done; exit 128' _ "${REPO_URL}" "https://gitclone.com/github.com/trowar/vpn-manager.git" "https://ghproxy.com/https://github.com/trowar/vpn-manager.git" "https://mirror.ghproxy.com/https://github.com/trowar/vpn-manager.git" "${APP_DIR}" "${BRANCH}"
    retry_cmd 4 8 git -C "${APP_DIR}" checkout -f "${BRANCH}" || retry_cmd 4 8 git -C "${APP_DIR}" checkout -B "${BRANCH}" "origin/${BRANCH}"
    retry_cmd 4 8 git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
    return
  fi

  log "cloning repository to ${APP_DIR}"
  rm -rf "${APP_DIR}"
  retry_cmd 1 1 sh -c 'for u in "$1" "$2" "$3" "$4"; do rm -rf "$5"; if command -v timeout >/dev/null 2>&1; then GIT_TERMINAL_PROMPT=0 timeout 45s git -c http.connectTimeout=10 -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 clone --depth 1 --branch "$6" "$u" "$5" && exit 0; else GIT_TERMINAL_PROMPT=0 git -c http.connectTimeout=10 -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 clone --depth 1 --branch "$6" "$u" "$5" && exit 0; fi; done; exit 128' _ "${REPO_URL}" "https://gitclone.com/github.com/trowar/vpn-manager.git" "https://ghproxy.com/https://github.com/trowar/vpn-manager.git" "https://mirror.ghproxy.com/https://github.com/trowar/vpn-manager.git" "${APP_DIR}" "${BRANCH}"
}

disable_systemd_resolved_if_needed() {
  if [ "${DISABLE_SYSTEMD_RESOLVED}" != "1" ]; then
    log "skip disabling systemd-resolved (DISABLE_SYSTEMD_RESOLVED=${DISABLE_SYSTEMD_RESOLVED})"
    return 0
  fi
  if ! has_cmd systemctl; then
    warn "systemctl not available, cannot disable systemd-resolved"
    return 0
  fi
  if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -Fxq "systemd-resolved.service"; then
    return 0
  fi

  log "disabling systemd-resolved by default to free DNS conflicts"
  systemctl stop systemd-resolved >/dev/null 2>&1 || true
  systemctl disable systemd-resolved >/dev/null 2>&1 || true

  if [ -L /etc/resolv.conf ]; then
    local current_target
    current_target="$(readlink -f /etc/resolv.conf || true)"
    if [ "${current_target}" = "/run/systemd/resolve/stub-resolv.conf" ] || [ "${current_target}" = "/run/systemd/resolve/resolv.conf" ] || [ -z "${current_target}" ]; then
      rm -f /etc/resolv.conf || true
    fi
  fi

  if [ ! -s /etc/resolv.conf ] || grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
    cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options timeout:2 attempts:3
EOF
  fi
}

resolve_kcptun_download_url() {
  local arch="$1"
  local api_url
  if [ "${KCPTUN_VERSION}" = "latest" ]; then
    api_url="https://api.github.com/repos/xtaci/kcptun/releases/latest"
  else
    api_url="https://api.github.com/repos/xtaci/kcptun/releases/tags/${KCPTUN_VERSION}"
  fi

  API_URL="${api_url}" ARCH_VALUE="${arch}" python3 - <<'PY'
import json
import os
import re
import sys
from urllib.request import urlopen

api_url = os.environ.get("API_URL", "")
arch = os.environ.get("ARCH_VALUE", "")
try:
    data = json.loads(urlopen(api_url, timeout=15).read().decode("utf-8", "ignore"))
except Exception:
    sys.exit(1)
assets = data.get("assets") or []
pattern = re.compile(rf"kcptun-linux-{re.escape(arch)}.*\\.tar\\.gz$")
for item in assets:
    url = str(item.get("browser_download_url") or "")
    if pattern.search(url):
        print(url)
        sys.exit(0)
sys.exit(1)
PY
}

download_with_mirrors() {
  local url="$1"
  local target="$2"
  local base
  base="${url#https://}"

  local candidates=(
    "$url"
    "https://ghproxy.com/https://${base}"
    "https://mirror.ghproxy.com/https://${base}"
  )

  local u
  for u in "${candidates[@]}"; do
    if curl -fL --connect-timeout 10 --max-time 180 "$u" -o "$target" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

ensure_kcptun_binary() {
  local arch url tmp_tar tmp_dir
  local system_bin

  system_bin="$(command -v kcptun-server 2>/dev/null || true)"
  if [ -n "${system_bin}" ] && [ -x "${system_bin}" ]; then
    KCPTUN_BIN="${system_bin}"
    log "using system kcptun binary: ${KCPTUN_BIN}"
    return 0
  fi

  if [ "${PM}" = "apt" ]; then
    local candidate
    candidate="$(apt-cache policy kcptun 2>/dev/null | awk '/Candidate:/ {print $2; exit}' || true)"
    if [ -n "${candidate}" ] && [ "${candidate}" != "(none)" ]; then
      log "installing kcptun from apt package (candidate=${candidate})"
      pkg_install kcptun || true
      system_bin="$(command -v kcptun-server 2>/dev/null || true)"
      if [ -n "${system_bin}" ] && [ -x "${system_bin}" ]; then
        KCPTUN_BIN="${system_bin}"
        log "using apt kcptun binary: ${KCPTUN_BIN}"
        return 0
      fi
    fi
  fi

  if [ -x "${KCPTUN_BIN}" ]; then
    log "kcptun binary already exists at ${KCPTUN_BIN}, skip download"
    return 0
  fi

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l|armv7|armhf) arch="arm7" ;;
    *)
      err "unsupported architecture for kcptun: ${arch}"
      exit 1
      ;;
  esac

  url="${KCPTUN_DOWNLOAD_URL}"
  if [ -z "$url" ]; then
    url="$(resolve_kcptun_download_url "$arch" || true)"
  fi
  if [ -z "$url" ]; then
    err "failed to resolve kcptun release URL"
    exit 1
  fi

  tmp_tar="$(mktemp /tmp/kcptun.XXXXXX.tar.gz)"
  tmp_dir="$(mktemp -d /tmp/kcptun.XXXXXX)"

  if ! download_with_mirrors "$url" "$tmp_tar"; then
    rm -f "$tmp_tar"
    rm -rf "$tmp_dir"
    err "failed to download kcptun archive"
    exit 1
  fi

  if ! tar -xzf "$tmp_tar" -C "$tmp_dir"; then
    rm -f "$tmp_tar"
    rm -rf "$tmp_dir"
    err "failed to extract kcptun archive"
    exit 1
  fi

  if [ ! -f "$tmp_dir/server_linux_${arch}" ]; then
    rm -f "$tmp_tar"
    rm -rf "$tmp_dir"
    err "kcptun server binary not found in archive"
    exit 1
  fi

  install -m 0755 "$tmp_dir/server_linux_${arch}" "$KCPTUN_BIN"
  rm -f "$tmp_tar"
  rm -rf "$tmp_dir"
}

write_shadowsocks_config() {
  mkdir -p "$SHADOWSOCKS_CONF_DIR"
  SHADOWSOCKS_SERVER_PORT="$(normalize_port "$SHADOWSOCKS_SERVER_PORT" 8388)"
  SHADOWSOCKS_PORT_RANGE_START="$(normalize_port "$SHADOWSOCKS_PORT_RANGE_START" 29000)"
  SHADOWSOCKS_PORT_RANGE_END="$(normalize_port "$SHADOWSOCKS_PORT_RANGE_END" 33999)"
  if [ "$SHADOWSOCKS_PORT_RANGE_END" -lt "$SHADOWSOCKS_PORT_RANGE_START" ]; then
    SHADOWSOCKS_PORT_RANGE_END="$SHADOWSOCKS_PORT_RANGE_START"
  fi
  python3 - "$SHADOWSOCKS_CONF_FILE" "$SHADOWSOCKS_SERVER_PORT" "$SHADOWSOCKS_PASSWORD" "$SHADOWSOCKS_METHOD" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
server_port = int(sys.argv[2])
base_password = sys.argv[3]
method = sys.argv[4]

payload = {
    "server": "0.0.0.0",
    "server_port": server_port,
    "password": base_password,
    "method": method,
    "mode": "tcp_and_udp",
    "timeout": 300,
    "fast_open": False,
}
out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$SHADOWSOCKS_CONF_FILE"
}

write_kcptun_config() {
  mkdir -p "$KCPTUN_CONF_DIR"
  local kcptun_nocomp_json
  kcptun_nocomp_json="false"
  if is_enabled "${KCPTUN_NOCOMP}"; then
    kcptun_nocomp_json="true"
  fi
  cat > "$KCPTUN_CONF_FILE" <<EOF
{
  "listen": ":${KCPTUN_SERVER_PORT}",
  "target": "127.0.0.1:${SHADOWSOCKS_SERVER_PORT}",
  "key": "${KCPTUN_KEY}",
  "crypt": "${KCPTUN_CRYPT}",
  "mode": "${KCPTUN_MODE}",
  "mtu": ${KCPTUN_MTU},
  "sndwnd": 256,
  "rcvwnd": 512,
  "datashard": ${KCPTUN_DATASHARD},
  "parityshard": ${KCPTUN_PARITYSHARD},
  "dscp": 0,
  "nocomp": ${kcptun_nocomp_json},
  "acknodelay": true,
  "nodelay": 1,
  "interval": 20,
  "resend": 2,
  "nc": 1,
  "sockbuf": 4194304,
  "keepalive": 10
}
EOF
  chmod 600 "$KCPTUN_CONF_FILE"
}

write_openvpn_config() {
  if ! is_enabled "${OPENVPN_ENABLED}"; then
    return 0
  fi

  mkdir -p "$OPENVPN_SERVER_DIR" "$OPENVPN_MATERIALS_DIR" /var/log/openvpn
  OPENVPN_ENDPOINT_PORT="$(normalize_port "$OPENVPN_ENDPOINT_PORT" 443)"
  if [ "${OPENVPN_PROTO}" != "udp" ]; then
    OPENVPN_PROTO="tcp"
  fi

  if [ ! -s "$OPENVPN_CA_KEY_FILE" ] || [ ! -s "$OPENVPN_CA_CERT_FILE" ]; then
    log "generating OpenVPN CA materials"
    openssl genrsa -out "$OPENVPN_CA_KEY_FILE" 2048 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$OPENVPN_CA_KEY_FILE" -sha256 -days 3650 \
      -subj "/CN=vpn-manager-ca/O=vpn-manager" \
      -out "$OPENVPN_CA_CERT_FILE" >/dev/null 2>&1
  fi

  if [ ! -s "$OPENVPN_SERVER_KEY_FILE" ] || [ ! -s "$OPENVPN_SERVER_CERT_FILE" ]; then
    log "generating OpenVPN server certificate"
    local csr_file ext_file
    csr_file="$(mktemp /tmp/openvpn-server.XXXXXX.csr)"
    ext_file="$(mktemp /tmp/openvpn-server.XXXXXX.ext)"
    openssl genrsa -out "$OPENVPN_SERVER_KEY_FILE" 2048 >/dev/null 2>&1
    openssl req -new -key "$OPENVPN_SERVER_KEY_FILE" \
      -subj "/CN=vpn-manager-server/O=vpn-manager" \
      -out "$csr_file" >/dev/null 2>&1
    cat > "$ext_file" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
    openssl x509 -req -in "$csr_file" \
      -CA "$OPENVPN_CA_CERT_FILE" -CAkey "$OPENVPN_CA_KEY_FILE" -CAcreateserial \
      -out "$OPENVPN_SERVER_CERT_FILE" -days 1825 -sha256 -extfile "$ext_file" >/dev/null 2>&1
    rm -f "$csr_file" "$ext_file"
  fi

  if [ ! -s "$OPENVPN_TLS_CRYPT_KEY_FILE" ]; then
    log "generating OpenVPN tls-crypt key"
    openvpn --genkey secret "$OPENVPN_TLS_CRYPT_KEY_FILE" >/dev/null 2>&1
  fi

  install -m 0644 "$OPENVPN_CA_CERT_FILE" "${OPENVPN_SERVER_DIR}/ca.crt"
  install -m 0644 "$OPENVPN_SERVER_CERT_FILE" "${OPENVPN_SERVER_DIR}/server.crt"
  install -m 0600 "$OPENVPN_SERVER_KEY_FILE" "${OPENVPN_SERVER_DIR}/server.key"
  install -m 0600 "$OPENVPN_TLS_CRYPT_KEY_FILE" "${OPENVPN_SERVER_DIR}/ta.key"

  local proto_line
  proto_line="tcp-server"
  if [ "${OPENVPN_PROTO}" = "udp" ]; then
    proto_line="udp"
  fi

  cat > "$OPENVPN_SERVER_CONF" <<EOF
port ${OPENVPN_ENDPOINT_PORT}
proto ${proto_line}
dev tun
topology subnet
server ${OPENVPN_NETWORK} ${OPENVPN_NETMASK}
ifconfig-pool-persist /var/log/openvpn/ipp.txt
ca ${OPENVPN_SERVER_DIR}/ca.crt
cert ${OPENVPN_SERVER_DIR}/server.crt
key ${OPENVPN_SERVER_DIR}/server.key
dh none
tls-crypt ${OPENVPN_SERVER_DIR}/ta.key
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
cipher AES-256-GCM
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${OPENVPN_CLIENT_DNS}"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
log-append /var/log/openvpn/server.log
verb 3
EOF

  if [ -n "${PORTAL_POSTGRES_DSN}" ]; then
    cat > "${OPENVPN_SERVER_DIR}/check-client.py" <<EOF
#!${PY_VENV_DIR}/bin/python
import os
import re
import sys
import psycopg

dsn = ${PORTAL_POSTGRES_DSN@Q}
common_name = (os.environ.get("common_name") or "").strip()
match = re.fullmatch(r"vpn-user-(\\d+)", common_name)
if not match:
    sys.exit(1)

try:
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role, status, vpn_enabled FROM users WHERE id = %s LIMIT 1",
                (int(match.group(1)),),
            )
            row = cur.fetchone()
except Exception:
    sys.exit(1)

if not row:
    sys.exit(1)
role, status, vpn_enabled = row
role = (role or "user").strip().lower()
status = (status or "approved").strip().lower()
if status == "disabled":
    sys.exit(1)
if role == "admin" or int(vpn_enabled or 0) == 1:
    sys.exit(0)
sys.exit(1)
EOF
    chmod 0755 "${OPENVPN_SERVER_DIR}/check-client.py"
    cat >> "$OPENVPN_SERVER_CONF" <<EOF
script-security 2
client-connect ${OPENVPN_SERVER_DIR}/check-client.py
EOF
  fi
}

ensure_python_runtime() {
  mkdir -p "${APP_DIR}" "${APP_DIR}/data"
  if [ ! -d "${PY_VENV_DIR}" ]; then
    python3 -m venv "${PY_VENV_DIR}"
  fi
  "${PY_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${PY_VENV_DIR}/bin/pip" install "Flask==3.0.3" "gunicorn==22.0.0" "werkzeug==3.0.2" "psycopg[binary]>=3.2,<4" >/dev/null
}

write_systemd_units() {
  if is_enabled "${SHADOWSOCKS_ENABLED:-0}"; then
    cat > "/etc/systemd/system/${SHADOWSOCKS_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager Shadowsocks Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -s 0.0.0.0 -p ${SHADOWSOCKS_SERVER_PORT} -c ${SHADOWSOCKS_CONF_FILE} -u
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  else
    rm -f "/etc/systemd/system/${SHADOWSOCKS_SERVICE_NAME}"
  fi

  if is_enabled "${SHADOWSOCKS_ENABLED:-0}" && is_enabled "${KCPTUN_ENABLED}"; then
    cat > "/etc/systemd/system/${KCPTUN_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager kcptun Server
After=network-online.target ${SHADOWSOCKS_SERVICE_NAME}
Wants=network-online.target
Requires=${SHADOWSOCKS_SERVICE_NAME}

[Service]
Type=simple
ExecStart=${KCPTUN_BIN} -c ${KCPTUN_CONF_FILE}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  else
    rm -f "/etc/systemd/system/${KCPTUN_SERVICE_NAME}"
  fi

  if is_enabled "${OPENVPN_ENABLED}"; then
    cat > "/etc/systemd/system/${OPENVPN_NAT_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager OpenVPN NAT
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/iptables -t nat -C POSTROUTING -s ${OPENVPN_NETWORK}/24 -j MASQUERADE 2>/dev/null || /usr/sbin/iptables -t nat -A POSTROUTING -s ${OPENVPN_NETWORK}/24 -j MASQUERADE; /usr/sbin/iptables -C FORWARD -s ${OPENVPN_NETWORK}/24 -j ACCEPT 2>/dev/null || /usr/sbin/iptables -A FORWARD -s ${OPENVPN_NETWORK}/24 -j ACCEPT; /usr/sbin/iptables -C FORWARD -d ${OPENVPN_NETWORK}/24 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || /usr/sbin/iptables -A FORWARD -d ${OPENVPN_NETWORK}/24 -m state --state ESTABLISHED,RELATED -j ACCEPT'
ExecStop=/bin/sh -c '/usr/sbin/iptables -t nat -D POSTROUTING -s ${OPENVPN_NETWORK}/24 -j MASQUERADE 2>/dev/null || true; /usr/sbin/iptables -D FORWARD -s ${OPENVPN_NETWORK}/24 -j ACCEPT 2>/dev/null || true; /usr/sbin/iptables -D FORWARD -d ${OPENVPN_NETWORK}/24 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
  else
    rm -f "/etc/systemd/system/${OPENVPN_NAT_SERVICE_NAME}"
  fi

  local api_after
  api_after="network-online.target"
  if is_enabled "${OPENVPN_ENABLED}"; then
    api_after="${api_after} ${OPENVPN_SERVICE_NAME}"
  elif is_enabled "${SHADOWSOCKS_ENABLED:-0}"; then
    api_after="${api_after} ${SHADOWSOCKS_SERVICE_NAME}"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED:-0}" && is_enabled "${KCPTUN_ENABLED}"; then
    api_after="${api_after} ${KCPTUN_SERVICE_NAME}"
  fi
  cat > "/etc/systemd/system/${VPN_API_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager API Service
After=${api_after}
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/vpn
Environment=PATH=${PY_VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=VPN_API_TOKEN=${VPN_API_TOKEN}
Environment=OPENVPN_SYSTEMD_UNIT=${OPENVPN_SERVICE_NAME}
ExecStart=${PY_VENV_DIR}/bin/gunicorn --workers 1 --bind 0.0.0.0:${VPN_API_PUBLIC_PORT} vpn_api:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

start_services() {
  if ! has_cmd systemctl; then
    err "systemctl is required for local deployment mode"
    exit 1
  fi

  if [ ! -f /etc/sysctl.d/99-vpnmanager-ipv6.conf ]; then
    cat > /etc/sysctl.d/99-vpnmanager-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  fi
  sysctl -p /etc/sysctl.d/99-vpnmanager-ipv6.conf >/dev/null || true

  systemctl daemon-reload
  if is_enabled "${OPENVPN_ENABLED}"; then
    cat > /etc/sysctl.d/99-vpnmanager-openvpn.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null || sysctl -w net.ipv4.ip_forward=1 >/dev/null
    systemctl enable --now "${OPENVPN_NAT_SERVICE_NAME}"
    systemctl enable --now "${OPENVPN_SERVICE_NAME}"
  else
    systemctl disable --now "${OPENVPN_SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl disable --now "${OPENVPN_NAT_SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" ; then
    systemctl enable --now "${SHADOWSOCKS_SERVICE_NAME}"
  else
    systemctl disable --now "${SHADOWSOCKS_SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}"; then
    systemctl enable --now "${KCPTUN_SERVICE_NAME}"
  else
    systemctl disable --now "${KCPTUN_SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  systemctl enable --now "${VPN_API_SERVICE_NAME}"
}

wait_vpn_api_ready() {
  local url
  url="http://127.0.0.1:${VPN_API_PUBLIC_PORT}/healthz"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 2 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

print_summary() {
  log "deployment completed"
  echo
  echo "================ Local Deploy Completed ================"
  echo "APP_DIR: ${APP_DIR}"
  if is_enabled "${OPENVPN_ENABLED}"; then
    echo "OpenVPN: ${OPENVPN_ENDPOINT_PORT}/${OPENVPN_PROTO}"
    echo "OpenVPN service: ${OPENVPN_SERVICE_NAME}"
    echo "OpenVPN NAT service: ${OPENVPN_NAT_SERVICE_NAME}"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}"; then
    echo "Shadowsocks: ${SHADOWSOCKS_SERVER_PORT}/tcp+udp"
    echo "Shadowsocks service: ${SHADOWSOCKS_SERVICE_NAME}"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}"; then
    echo "kcptun: ${KCPTUN_SERVER_PORT}/udp"
    echo "kcptun service: ${KCPTUN_SERVICE_NAME}"
  fi
  echo "VPN API: ${VPN_API_PUBLIC_PORT}/tcp"
  echo "VPN API service: ${VPN_API_SERVICE_NAME}"
  echo "VPN_API_TOKEN: ${VPN_API_TOKEN}"
  echo
  echo "Service status checks:"
  if is_enabled "${OPENVPN_ENABLED}"; then
    systemctl --no-pager --full status "${OPENVPN_SERVICE_NAME}" | sed -n '1,6p' || true
    systemctl --no-pager --full status "${OPENVPN_NAT_SERVICE_NAME}" | sed -n '1,6p' || true
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}"; then
    systemctl --no-pager --full status "${SHADOWSOCKS_SERVICE_NAME}" | sed -n '1,6p' || true
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}"; then
    systemctl --no-pager --full status "${KCPTUN_SERVICE_NAME}" | sed -n '1,6p' || true
  fi
  systemctl --no-pager --full status "${VPN_API_SERVICE_NAME}" | sed -n '1,6p' || true
  echo "======================================================="
}

main() {
  require_root
  detect_pm
  log "package manager detected: ${PM}"

  install_base_deps
  setup_repo
  disable_systemd_resolved_if_needed

  if [ -z "${VPN_API_TOKEN}" ]; then
    VPN_API_TOKEN="$(generate_token)"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && [ -z "${SHADOWSOCKS_PASSWORD}" ]; then
    SHADOWSOCKS_PASSWORD="$(generate_token)"
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}" && [ -z "${KCPTUN_KEY}" ]; then
    KCPTUN_KEY="$(generate_token)"
  fi

  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}"; then
    ensure_kcptun_binary
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}"; then
    write_shadowsocks_config
  fi
  if is_enabled "${SHADOWSOCKS_ENABLED}" && is_enabled "${KCPTUN_ENABLED}"; then
    write_kcptun_config
  fi
  write_openvpn_config
  ensure_python_runtime
  write_systemd_units
  start_services

  if ! wait_vpn_api_ready; then
    err "vpn api health check failed on 127.0.0.1:${VPN_API_PUBLIC_PORT}"
    exit 1
  fi

  print_summary
}

main "$@"
