#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vpn-platform-v1"
REPO_URL="https://github.com/trowar/vpn-manager.git"
WEB_PUBLIC_PORT="${WEB_PUBLIC_PORT:-8080}"
ENV_FILE=".env"
LEGACY_SERVICE_NAME="vpn-platform-v1"

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-600}"
APT_RETRY_COUNT="${APT_RETRY_COUNT:-5}"
APT_RETRY_DELAY_SECONDS="${APT_RETRY_DELAY_SECONDS:-8}"
INSTALL_SWAP_MB="${INSTALL_SWAP_MB:-2048}"

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

log() {
  echo "[install] $*"
}

warn() {
  echo "[install][warn] $*" >&2
}

err() {
  echo "[install][error] $*" >&2
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_swap_if_needed() {
  if ! has_cmd swapon || ! [ -r /proc/meminfo ]; then
    return 0
  fi
  local mem_kb swap_kb
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  swap_kb="$(awk '/SwapTotal/ {print $2}' /proc/meminfo)"
  if [ -z "${mem_kb}" ]; then
    return 0
  fi
  if [ "${swap_kb:-0}" -gt 0 ]; then
    return 0
  fi
  if [ "${mem_kb}" -ge 1800000 ]; then
    return 0
  fi
  if [ -f /swapfile ]; then
    warn "swapfile already exists, skipping auto swap creation"
    return 0
  fi

  log "Low-memory host detected; creating ${INSTALL_SWAP_MB}MB swapfile to avoid OOM during install"
  if has_cmd fallocate; then
    fallocate -l "${INSTALL_SWAP_MB}M" /swapfile
  else
    dd if=/dev/zero of=/swapfile bs=1M count="${INSTALL_SWAP_MB}" status=none
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  if ! grep -q '^/swapfile ' /etc/fstab 2>/dev/null; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
}

on_error() {
  local exit_code=$?
  err "安装失败，退出码: ${exit_code}"
  err "可查看日志排查: /var/log/cloud-init-output.log 或 docker compose logs"
  exit "$exit_code"
}

trap on_error ERR

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "请使用 root 运行此脚本"
    exit 1
  fi
}

retry_cmd() {
  local retries="$1"
  local delay="$2"
  shift 2

  local attempt=1
  while true; do
    "$@"
    local code=$?
    if [ "$code" -eq 0 ]; then
      return 0
    fi
    if [ "$attempt" -ge "$retries" ]; then
      err "命令失败，已重试 ${attempt} 次 (exit=${code}): $*"
      return "$code"
    fi
    warn "命令失败 (exit=${code})，${delay}s 后重试 ${attempt}/${retries}: $*"
    attempt=$((attempt + 1))
    sleep "$delay"
  done
}

apt_cmd() {
  DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt-get \
    -o DPkg::Lock::Timeout="${APT_LOCK_TIMEOUT_SECONDS}" \
    -o Acquire::Retries=3 \
    -o Dpkg::Use-Pty=0 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    "$@"
}

repair_apt_state() {
  log "Repairing dpkg/apt state"
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd -f install -y || true
}

install_base_deps() {
  if has_cmd apt-get; then
    log "Detected apt environment"
    repair_apt_state
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd update
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y \
      ca-certificates curl gnupg lsb-release git wget openssl
    repair_apt_state
    return
  fi

  if has_cmd yum; then
    log "Detected yum environment"
    retry_cmd 3 5 yum makecache -y
    retry_cmd 3 5 yum install -y \
      ca-certificates curl gnupg2 git wget openssl yum-utils
    return
  fi

  err "Unsupported package manager. Need apt-get or yum."
  exit 1
}

install_docker() {
  if has_cmd docker; then
    log "Docker already installed"
  elif has_cmd apt-get; then
    log "Installing docker via apt"
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y docker.io
    if ! retry_cmd 2 5 apt_cmd install -y docker-compose-plugin; then
      retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y docker-compose
    fi
  elif has_cmd yum; then
    log "Installing docker via yum"
    retry_cmd 3 5 yum install -y docker
    if ! retry_cmd 2 5 yum install -y docker-compose-plugin; then
      retry_cmd 3 5 yum install -y docker-compose
    fi
  else
    err "Cannot install docker: unsupported package manager."
    exit 1
  fi

  if has_cmd systemctl; then
    systemctl daemon-reload || true
    systemctl enable --now docker
  else
    service docker start || true
  fi

  if ! docker compose version >/dev/null 2>&1; then
    log "Docker Compose v2 plugin not found; installing standalone plugin"
    local os arch plugin_dir plugin_url
    os="linux"
    arch="$(uname -m)"
    case "${arch}" in
      x86_64|amd64) arch="x86_64" ;;
      aarch64|arm64) arch="aarch64" ;;
      *)
        warn "Unsupported architecture for auto-install docker compose plugin: ${arch}"
        ;;
    esac
    if [ "${arch}" = "x86_64" ] || [ "${arch}" = "aarch64" ]; then
      plugin_dir="/usr/local/lib/docker/cli-plugins"
      mkdir -p "${plugin_dir}"
      plugin_url="https://github.com/docker/compose/releases/download/v2.39.2/docker-compose-${os}-${arch}"
      retry_cmd 3 5 curl -fsSL "${plugin_url}" -o "${plugin_dir}/docker-compose"
      chmod +x "${plugin_dir}/docker-compose"
    fi
  fi
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
    return
  fi
  if has_cmd docker-compose; then
    docker-compose "$@"
    return
  fi
  err "Docker Compose not found."
  exit 1
}

setup_repo() {
  if [ -d "${APP_DIR}/.git" ]; then
    log "Updating existing repo at ${APP_DIR}"
    git -C "${APP_DIR}" fetch --depth 1 origin main
    git -C "${APP_DIR}" checkout -f main
    git -C "${APP_DIR}" reset --hard origin/main
  else
    log "Cloning repo to ${APP_DIR}"
    rm -rf "${APP_DIR}"
    git clone --depth 1 "${REPO_URL}" "${APP_DIR}"
  fi
}

disable_legacy_service_if_needed() {
  if ! has_cmd systemctl; then
    return
  fi
  if ! systemctl list-unit-files | grep -q "^${LEGACY_SERVICE_NAME}\\.service"; then
    return
  fi

  if systemctl is-active --quiet "${LEGACY_SERVICE_NAME}"; then
    log "Stopping legacy service: ${LEGACY_SERVICE_NAME}"
    systemctl stop "${LEGACY_SERVICE_NAME}" || true
  fi
  if systemctl is-enabled --quiet "${LEGACY_SERVICE_NAME}" 2>/dev/null; then
    log "Disabling legacy service: ${LEGACY_SERVICE_NAME}"
    systemctl disable "${LEGACY_SERVICE_NAME}" || true
  fi
}

generate_secret() {
  if has_cmd openssl; then
    openssl rand -hex 24
    return
  fi
  python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
}

upsert_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "${ENV_FILE}" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
  else
    echo "${key}=${value}" >> "${ENV_FILE}"
  fi
}

prepare_env() {
  cd "${APP_DIR}"
  if [ ! -f "${ENV_FILE}" ]; then
    cp .env.docker.example "${ENV_FILE}"
  fi

  local ip portal_secret api_token
  ip="$(hostname -I | awk '{print $1}')"
  portal_secret="$(generate_secret)"
  api_token="$(generate_secret)"

  upsert_env "PORTAL_SECRET_KEY" "${portal_secret}"
  upsert_env "ADMIN_USERNAME" "admin"
  upsert_env "ADMIN_PASSWORD" "admin"
  upsert_env "WEB_PUBLIC_PORT" "${WEB_PUBLIC_PORT}"
  upsert_env "VPN_API_TOKEN" "${api_token}"
  upsert_env "WG_ENDPOINT" "${ip}:51820"
  upsert_env "OPENVPN_ENDPOINT_HOST" "${ip}"
  upsert_env "PORTAL_ENABLE_UDP_RELAY" "1"
  upsert_env "VPN_RELAY_PUBLIC_HOST" "${ip}"
  upsert_env "WG_RELAY_PORT_START" "24000"
  upsert_env "WG_RELAY_PORT_END" "24031"
  upsert_env "OPENVPN_RELAY_PORT_START" "29000"
  upsert_env "OPENVPN_RELAY_PORT_END" "29031"
}

start_web() {
  cd "${APP_DIR}"
  log "Starting web container"
  docker rm -f vpn-web >/dev/null 2>&1 || true
  compose_cmd down --remove-orphans >/dev/null 2>&1 || true
  compose_cmd build web
  compose_cmd up -d --no-deps web
}

print_summary() {
  local ip
  ip="$(hostname -I | awk '{print $1}')"

  cat <<EOF

================ 安装完成 ================
登录地址: http://${ip}:${WEB_PUBLIC_PORT}
IP: ${ip}
端口: ${WEB_PUBLIC_PORT}
默认账号: admin
默认密码: admin
说明:
1) 已安装 Docker 并启动 web 容器
2) vpnmanager-server 默认不在本机部署
3) 请登录后台“服务器管理”添加服务器后自动部署 VPN 服务端
========================================

EOF

  cd "${APP_DIR}"
  compose_cmd ps
}

main() {
  require_root
  ensure_swap_if_needed
  install_base_deps
  install_docker
  setup_repo
  disable_legacy_service_if_needed
  prepare_env
  start_web
  print_summary
}

main "$@"
