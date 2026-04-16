#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/srv/vpn-platform-v1}"
REPO_URL="${REPO_URL:-https://github.com/trowar/vpn-manager.git}"
BRANCH="${BRANCH:-main}"
WEB_PUBLIC_PORT="${WEB_PUBLIC_PORT:-8080}"
WEB_SERVICE_NAME="${WEB_SERVICE_NAME:-vpn-platform-v1-web.service}"
ENV_FILE=".env"

POSTGRES_DB="${POSTGRES_DB:-vpnportal}"
POSTGRES_USER="${POSTGRES_USER:-vpnportal}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-vpnportal}"

LOCAL_VPN_APP_DIR="${LOCAL_VPN_APP_DIR:-/srv/vpn-node}"
INSTALL_LOCAL_VPN_SERVER="${INSTALL_LOCAL_VPN_SERVER:-1}"
WG_PUBLIC_PORT="${WG_PUBLIC_PORT:-51820}"
OPENVPN_PUBLIC_PORT="${OPENVPN_PUBLIC_PORT:-1194}"
OPENVPN_PROTO="${OPENVPN_PROTO:-udp}"
DNS_PUBLIC_PORT="${DNS_PUBLIC_PORT:-53}"
VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT:-8081}"
DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE:-1}"

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-600}"
APT_RETRY_COUNT="${APT_RETRY_COUNT:-5}"
APT_RETRY_DELAY_SECONDS="${APT_RETRY_DELAY_SECONDS:-8}"

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

INSTALL_API_TOKEN=""

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

first_local_ipv4() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

extract_ipv4() {
  printf '%s' "$1" | tr -d '\r' | tr -d '\n' | awk '
    match($0, /([0-9]{1,3}\.){3}[0-9]{1,3}/) { print substr($0, RSTART, RLENGTH); exit }
  '
}

is_public_ipv4() {
  local ip="$1"
  if [ -z "${ip}" ]; then
    return 1
  fi
  if ! printf '%s' "${ip}" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    return 1
  fi
  case "${ip}" in
    10.*|127.*|0.*|169.254.*|192.168.*|255.255.255.255) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 1 ;;
  esac
  return 0
}

detect_public_ipv4() {
  local candidate=""
  local endpoint
  for endpoint in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://ipv4.icanhazip.com" \
    "https://checkip.amazonaws.com"
  do
    candidate="$(curl -4fsSL --max-time 4 "${endpoint}" 2>/dev/null || true)"
    candidate="$(extract_ipv4 "${candidate}")"
    if is_public_ipv4 "${candidate}"; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_preferred_ip() {
  local local_ip public_ip
  local_ip="$(first_local_ipv4)"
  public_ip="$(detect_public_ipv4 || true)"
  if is_public_ipv4 "${public_ip}"; then
    printf '%s' "${public_ip}"
    return 0
  fi
  printf '%s' "${local_ip}"
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

repair_apt_state() {
  log "Repairing dpkg/apt state"
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd -f install -y || true
}

install_base_deps() {
  if ! has_cmd apt-get; then
    err "当前脚本仅支持 apt 系发行版（Ubuntu/Debian）"
    exit 1
  fi

  repair_apt_state
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd update
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y \
    ca-certificates curl git openssl \
    python3 python3-venv python3-pip \
    postgresql postgresql-contrib
  repair_apt_state
}

setup_repo() {
  mkdir -p "$(dirname "${APP_DIR}")"
  if [ -d "${APP_DIR}/.git" ]; then
    log "Updating existing repo at ${APP_DIR}"
    git -C "${APP_DIR}" fetch --depth 1 origin "${BRANCH}"
    git -C "${APP_DIR}" checkout -f "${BRANCH}"
    git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
  else
    log "Cloning repo to ${APP_DIR}"
    rm -rf "${APP_DIR}"
    git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
  fi
}

ensure_postgres_ready() {
  if has_cmd systemctl; then
    systemctl enable --now postgresql
  fi
  retry_cmd 20 2 bash -lc "pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1"
}

setup_postgres_db() {
  local role_exists db_exists
  role_exists="$(runuser -u postgres -- psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'\" | tr -d '[:space:]' || true)"
  if [ "${role_exists}" != "1" ]; then
    runuser -u postgres -- psql -c "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
  else
    runuser -u postgres -- psql -c "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
  fi

  db_exists="$(runuser -u postgres -- psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'\" | tr -d '[:space:]' || true)"
  if [ "${db_exists}" != "1" ]; then
    runuser -u postgres -- psql -c "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"
  fi
}

upsert_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "${APP_DIR}/${ENV_FILE}" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${APP_DIR}/${ENV_FILE}"
  else
    echo "${key}=${value}" >> "${APP_DIR}/${ENV_FILE}"
  fi
}

prepare_env() {
  local ip portal_secret api_token
  ip="$(resolve_preferred_ip)"
  portal_secret="$(generate_secret)"
  api_token="$(generate_secret)"
  INSTALL_API_TOKEN="${api_token}"

  mkdir -p "${APP_DIR}"
  touch "${APP_DIR}/${ENV_FILE}"

  upsert_env "PORTAL_SECRET_KEY" "${portal_secret}"
  upsert_env "ADMIN_USERNAME" "admin"
  upsert_env "ADMIN_PASSWORD" "admin"
  upsert_env "PORTAL_DB_BACKEND" "postgres"
  upsert_env "PORTAL_POSTGRES_DB" "${POSTGRES_DB}"
  upsert_env "PORTAL_POSTGRES_USER" "${POSTGRES_USER}"
  upsert_env "PORTAL_POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}"
  upsert_env "PORTAL_POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
  upsert_env "PORTAL_SQLITE_MIGRATION_SOURCE" "${APP_DIR}/data/portal.db"

  upsert_env "WEB_PUBLIC_PORT" "${WEB_PUBLIC_PORT}"
  upsert_env "PORTAL_SELF_UPGRADE_HOST_PROJECT_DIR" "/srv/vpn-platform-v1"

  upsert_env "VPN_API_TOKEN" "${api_token}"
  upsert_env "VPN_API_URL" "http://${ip}:${VPN_API_PUBLIC_PORT}"
  upsert_env "WG_ENDPOINT" "${ip}:${WG_PUBLIC_PORT}"
  upsert_env "OPENVPN_ENDPOINT_HOST" "${ip}"
  upsert_env "OPENVPN_ENDPOINT_PORT" "${OPENVPN_PUBLIC_PORT}"
  upsert_env "OPENVPN_PROTO" "${OPENVPN_PROTO}"

  upsert_env "PORTAL_ENABLE_UDP_RELAY" "1"
  upsert_env "VPN_RELAY_PUBLIC_HOST" "${ip}"
  upsert_env "WG_RELAY_PORT_START" "24000"
  upsert_env "WG_RELAY_PORT_END" "24031"
  upsert_env "OPENVPN_RELAY_PORT_START" "29000"
  upsert_env "OPENVPN_RELAY_PORT_END" "29031"
}

install_web_runtime() {
  log "Installing web runtime dependencies (local)"
  python3 -m venv "${APP_DIR}/.venv"
  "${APP_DIR}/.venv/bin/pip" install --upgrade pip
  "${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
}

write_web_systemd_unit() {
  cat > "/etc/systemd/system/${WEB_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Platform Web (Local)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/gunicorn --workers 2 --bind 0.0.0.0:${WEB_PUBLIC_PORT} wsgi:app
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
}

start_web_service() {
  if ! has_cmd systemctl; then
    err "systemctl 不可用，无法启动本地 web 服务"
    exit 1
  fi
  systemctl daemon-reload
  systemctl enable --now "${WEB_SERVICE_NAME}"
}

deploy_local_vpn_server() {
  if [ "${INSTALL_LOCAL_VPN_SERVER}" != "1" ]; then
    log "Skipping local vpn-server deploy (INSTALL_LOCAL_VPN_SERVER=${INSTALL_LOCAL_VPN_SERVER})"
    return 0
  fi

  local script_path
  script_path="${APP_DIR}/scripts/manual_deploy_vpn_node.sh"
  if [ ! -f "${script_path}" ]; then
    err "Local vpn deploy script not found: ${script_path}"
    exit 1
  fi

  log "Deploying local vpn-server on host (systemd mode)"
  APP_DIR="${LOCAL_VPN_APP_DIR}" \
  REPO_URL="${REPO_URL}" \
  BRANCH="${BRANCH}" \
  WG_PUBLIC_PORT="${WG_PUBLIC_PORT}" \
  OPENVPN_PUBLIC_PORT="${OPENVPN_PUBLIC_PORT}" \
  OPENVPN_PROTO="${OPENVPN_PROTO}" \
  DNS_PUBLIC_PORT="${DNS_PUBLIC_PORT}" \
  VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT}" \
  VPN_API_TOKEN="${INSTALL_API_TOKEN}" \
  DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE}" \
  OPENVPN_ENFORCE_DB_AUTH=0 \
  bash "${script_path}"
}

verify_first_install_components() {
  if ! systemctl is-active --quiet postgresql; then
    err "postgresql 服务未启动"
    systemctl --no-pager --full status postgresql || true
    exit 1
  fi

  if ! systemctl is-active --quiet "${WEB_SERVICE_NAME}"; then
    err "web 服务未启动: ${WEB_SERVICE_NAME}"
    systemctl --no-pager --full status "${WEB_SERVICE_NAME}" || true
    exit 1
  fi

  if [ "${INSTALL_LOCAL_VPN_SERVER}" = "1" ]; then
    if ! systemctl is-active --quiet "wg-quick@wg0.service"; then
      err "wg-quick@wg0.service 未启动"
      systemctl --no-pager --full status "wg-quick@wg0.service" || true
      exit 1
    fi
    if ! systemctl is-active --quiet "vpnmanager-openvpn.service"; then
      err "vpnmanager-openvpn.service 未启动"
      systemctl --no-pager --full status "vpnmanager-openvpn.service" || true
      exit 1
    fi
    if ! systemctl is-active --quiet "vpnmanager-server.service"; then
      err "vpnmanager-server.service 未启动"
      systemctl --no-pager --full status "vpnmanager-server.service" || true
      exit 1
    fi
  fi
}

print_summary() {
  local ip local_ip
  ip="$(resolve_preferred_ip)"
  local_ip="$(first_local_ipv4)"

  cat <<EOF

================ 安装完成 ================
登录地址: http://${ip}:${WEB_PUBLIC_PORT}
IP: ${ip}
LAN IP: ${local_ip}
端口: ${WEB_PUBLIC_PORT}
默认账号: admin
默认密码: admin
说明:
1) 已本地部署 web 服务（systemd: ${WEB_SERVICE_NAME}）
2) 已本地部署数据库（systemd: postgresql）
3) 已本地部署 vpn-server（systemd）
4) web 目录: ${APP_DIR}
5) vpn-server 目录: ${LOCAL_VPN_APP_DIR}
========================================

EOF

  echo "[status] postgresql: $(systemctl is-active postgresql 2>/dev/null || true)"
  echo "[status] web: $(systemctl is-active "${WEB_SERVICE_NAME}" 2>/dev/null || true)"
  echo "[status] wg: $(systemctl is-active wg-quick@wg0.service 2>/dev/null || true)"
  echo "[status] openvpn: $(systemctl is-active vpnmanager-openvpn.service 2>/dev/null || true)"
  echo "[status] vpn-api: $(systemctl is-active vpnmanager-server.service 2>/dev/null || true)"
}

main() {
  require_root
  install_base_deps
  setup_repo
  ensure_postgres_ready
  setup_postgres_db
  prepare_env
  install_web_runtime
  write_web_systemd_unit
  start_web_service
  deploy_local_vpn_server
  verify_first_install_components
  print_summary
}

main "$@"
