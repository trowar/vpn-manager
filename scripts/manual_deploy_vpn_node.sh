#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

APP_DIR="${APP_DIR:-/srv/vpn-node}"
REPO_URL="${REPO_URL:-https://github.com/trowar/vpn-manager.git}"
BRANCH="${BRANCH:-main}"

SHADOWSOCKS_SERVER_PORT="${SHADOWSOCKS_SERVER_PORT:-8388}"
SHADOWSOCKS_METHOD="${SHADOWSOCKS_METHOD:-chacha20-ietf-poly1305}"
SHADOWSOCKS_PASSWORD="${SHADOWSOCKS_PASSWORD:-}"
KCPTUN_ENABLED="${KCPTUN_ENABLED:-1}"
KCPTUN_SERVER_PORT="${KCPTUN_SERVER_PORT:-29900}"
KCPTUN_KEY="${KCPTUN_KEY:-}"
KCPTUN_CRYPT="${KCPTUN_CRYPT:-aes}"
KCPTUN_MODE="${KCPTUN_MODE:-fast3}"
KCPTUN_VERSION="${KCPTUN_VERSION:-latest}"

VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT:-8081}"
VPN_API_TOKEN="${VPN_API_TOKEN:-}"
DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE:-0}"
DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED:-1}"

PY_VENV_DIR="${PY_VENV_DIR:-${APP_DIR}/.venv-vpn}"
PORTAL_DB_PATH="${PORTAL_DB_PATH:-}"

SHADOWSOCKS_CONF_DIR="/etc/shadowsocks-libev"
SHADOWSOCKS_CONF_FILE="${SHADOWSOCKS_CONF_DIR}/vpnmanager.json"
KCPTUN_CONF_DIR="/etc/kcptun"
KCPTUN_CONF_FILE="${KCPTUN_CONF_DIR}/server.json"
KCPTUN_BIN="/usr/local/bin/kcptun-server"

SHADOWSOCKS_SERVICE_NAME="vpnmanager-shadowsocks.service"
KCPTUN_SERVICE_NAME="vpnmanager-kcptun.service"
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

  if [ "$PM" = "apt" ]; then
    pkg_install \
      ca-certificates curl git openssl \
      iproute2 iptables net-tools \
      shadowsocks-libev tar unzip \
      python3 python3-venv python3-pip
  else
    pkg_install \
      ca-certificates curl git openssl \
      iproute iptables net-tools \
      shadowsocks-libev tar unzip \
      python3 python3-pip
  fi

  if ! has_cmd ss-server; then
    err "shadowsocks-libev install failed (ss-server missing)"
    exit 1
  fi
  if ! has_cmd python3; then
    err "python3 install failed"
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

setup_repo() {
  mkdir -p "$(dirname "${APP_DIR}")"

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

resolve_portal_db_path() {
  if [ -n "${PORTAL_DB_PATH}" ]; then
    echo "${PORTAL_DB_PATH}"
    return
  fi
  if [ -f /srv/vpn-platform-v1/data/portal.db ]; then
    echo "/srv/vpn-platform-v1/data/portal.db"
    return
  fi
  if [ -f /opt/vpn-platform-v1/data/portal.db ]; then
    echo "/opt/vpn-platform-v1/data/portal.db"
    return
  fi
  echo "${APP_DIR}/data/portal.db"
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

  url="$(resolve_kcptun_download_url "$arch" || true)"
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
  cat > "$SHADOWSOCKS_CONF_FILE" <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${SHADOWSOCKS_SERVER_PORT},
  "password": "${SHADOWSOCKS_PASSWORD}",
  "method": "${SHADOWSOCKS_METHOD}",
  "mode": "tcp_and_udp",
  "timeout": 300,
  "fast_open": false,
  "reuse_port": true,
  "no_delay": true
}
EOF
  chmod 600 "$SHADOWSOCKS_CONF_FILE"
}

write_kcptun_config() {
  mkdir -p "$KCPTUN_CONF_DIR"
  cat > "$KCPTUN_CONF_FILE" <<EOF
{
  "listen": ":${KCPTUN_SERVER_PORT}",
  "target": "127.0.0.1:${SHADOWSOCKS_SERVER_PORT}",
  "key": "${KCPTUN_KEY}",
  "crypt": "${KCPTUN_CRYPT}",
  "mode": "${KCPTUN_MODE}",
  "mtu": 1350,
  "sndwnd": 256,
  "rcvwnd": 512,
  "datashard": 10,
  "parityshard": 3,
  "dscp": 0,
  "nocomp": false,
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

ensure_python_runtime() {
  mkdir -p "${APP_DIR}" "${APP_DIR}/data"
  if [ ! -d "${PY_VENV_DIR}" ]; then
    python3 -m venv "${PY_VENV_DIR}"
  fi
  "${PY_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${PY_VENV_DIR}/bin/pip" install "Flask==3.0.3" "gunicorn==22.0.0" "werkzeug==3.0.2" >/dev/null
}

write_systemd_units() {
  cat > "/etc/systemd/system/${SHADOWSOCKS_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager Shadowsocks Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c ${SHADOWSOCKS_CONF_FILE} -u
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if is_enabled "${KCPTUN_ENABLED}"; then
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

  local api_after
  api_after="network-online.target ${SHADOWSOCKS_SERVICE_NAME}"
  if is_enabled "${KCPTUN_ENABLED}"; then
    api_after="${api_after} ${KCPTUN_SERVICE_NAME}"
  fi
  cat > "/etc/systemd/system/${VPN_API_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager API Service
After=${api_after}
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/docker/vpn
Environment=PATH=${PY_VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=VPN_API_TOKEN=${VPN_API_TOKEN}
Environment=PORTAL_DB_PATH=${PORTAL_DB_PATH}
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

  systemctl daemon-reload
  systemctl enable --now "${SHADOWSOCKS_SERVICE_NAME}"
  if is_enabled "${KCPTUN_ENABLED}"; then
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
  echo "Shadowsocks: ${SHADOWSOCKS_SERVER_PORT}/tcp+udp (${SHADOWSOCKS_METHOD})"
  if is_enabled "${KCPTUN_ENABLED}"; then
    echo "kcptun: ${KCPTUN_SERVER_PORT}/udp"
  else
    echo "kcptun: disabled"
  fi
  echo "VPN API: ${VPN_API_PUBLIC_PORT}/tcp"
  echo "VPN_API_TOKEN: ${VPN_API_TOKEN}"
  echo "SHADOWSOCKS_PASSWORD: ${SHADOWSOCKS_PASSWORD}"
  if is_enabled "${KCPTUN_ENABLED}"; then
    echo "KCPTUN_KEY: ${KCPTUN_KEY}"
  fi
  echo "PORTAL_DB_PATH: ${PORTAL_DB_PATH}"
  echo
  echo "Service status checks:"
  systemctl --no-pager --full status "${SHADOWSOCKS_SERVICE_NAME}" | sed -n '1,6p' || true
  if is_enabled "${KCPTUN_ENABLED}"; then
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
  if [ -z "${SHADOWSOCKS_PASSWORD}" ]; then
    SHADOWSOCKS_PASSWORD="$(generate_token)"
  fi
  if is_enabled "${KCPTUN_ENABLED}" && [ -z "${KCPTUN_KEY}" ]; then
    KCPTUN_KEY="$(generate_token)"
  fi

  PORTAL_DB_PATH="$(resolve_portal_db_path)"

  if is_enabled "${KCPTUN_ENABLED}"; then
    ensure_kcptun_binary
  fi
  write_shadowsocks_config
  if is_enabled "${KCPTUN_ENABLED}"; then
    write_kcptun_config
  fi
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
