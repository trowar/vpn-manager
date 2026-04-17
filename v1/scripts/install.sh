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
DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED:-1}"

INSTALL_MODE="${INSTALL_MODE:-auto}" # auto|install|upgrade
SKIP_APT_ON_UPGRADE="${SKIP_APT_ON_UPGRADE:-1}"
UPGRADE_INCLUDE_VPN_SERVER="${UPGRADE_INCLUDE_VPN_SERVER:-0}"
UPGRADE_BACKUP_DB="${UPGRADE_BACKUP_DB:-1}"

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-600}"
APT_RETRY_COUNT="${APT_RETRY_COUNT:-5}"
APT_RETRY_DELAY_SECONDS="${APT_RETRY_DELAY_SECONDS:-8}"

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

SCRIPT_MODE=""
INSTALL_API_TOKEN=""
UPGRADE_DB_BACKUP_FILE=""

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

env_path() {
  echo "${APP_DIR}/${ENV_FILE}"
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Please run this script as root."
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
    if [ "${code}" -eq 0 ]; then
      return 0
    fi
    if [ "${attempt}" -ge "${retries}" ]; then
      err "Command failed after ${attempt} attempts (exit=${code}): $*"
      return "${code}"
    fi
    warn "Command failed (exit=${code}), retrying in ${delay}s (${attempt}/${retries}): $*"
    attempt=$((attempt + 1))
    sleep "${delay}"
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
    err "This script currently supports apt-based distributions only (Ubuntu/Debian)."
    exit 1
  fi

  repair_apt_state
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd update
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y \
    ca-certificates curl git openssl \
    net-tools \
    python3 python3-venv python3-pip \
    postgresql postgresql-contrib
  repair_apt_state
}

ensure_net_tools_installed() {
  if has_cmd netstat; then
    return 0
  fi
  log "net-tools is missing, installing net-tools"
  repair_apt_state
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd update
  retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y --no-install-recommends net-tools
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

cleanup_legacy_docker_stack() {
  if ! has_cmd docker; then
    return 0
  fi

  if ! docker info >/dev/null 2>&1; then
    warn "docker command exists but daemon is unavailable, skip legacy cleanup"
    return 0
  fi

  local had_legacy=0
  log "Checking legacy Docker deployment"

  if has_cmd systemctl; then
    systemctl disable --now vpn-platform-v1.service >/dev/null 2>&1 || true
  fi

  for cname in vpn-web vpn-postgres vpnmanager-server; do
    if docker ps -a --format '{{.Names}}' | grep -Fxq "${cname}"; then
      had_legacy=1
      docker rm -f "${cname}" >/dev/null 2>&1 || true
    fi
  done

  if docker compose version >/dev/null 2>&1; then
    local compose_dir
    for compose_dir in "${APP_DIR}" "/srv/vpn-platform-v1" "/opt/vpn-platform-v1" "/root/vpn-platform-v1"; do
      if [ -f "${compose_dir}/docker-compose.yml" ]; then
        had_legacy=1
        docker compose -f "${compose_dir}/docker-compose.yml" --project-name vpn-platform-v1 down --remove-orphans >/dev/null 2>&1 || true
      fi
    done
  fi

  if [ "${had_legacy}" = "1" ]; then
    log "Legacy Docker stack removed"
  fi
}

read_env_value() {
  local key="$1"
  local file
  file="$(env_path)"
  if [ ! -f "${file}" ]; then
    return 0
  fi
  awk -v k="${key}" -F= '
    $1 == k {
      sub(/^[^=]*=/, "", $0)
      val = $0
    }
    END {
      if (val != "") {
        print val
      }
    }
  ' "${file}"
}

upsert_env() {
  local key="$1"
  local value="$2"
  local file
  file="$(env_path)"
  if grep -q "^${key}=" "${file}" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    echo "${key}=${value}" >> "${file}"
  fi
}

upsert_env_if_missing() {
  local key="$1"
  local value="$2"
  local file
  file="$(env_path)"
  if ! grep -q "^${key}=" "${file}" 2>/dev/null; then
    echo "${key}=${value}" >> "${file}"
  fi
}

looks_like_existing_install() {
  local file
  file="$(env_path)"
  if [ -f "${file}" ]; then
    return 0
  fi
  if [ -d "${APP_DIR}/.git" ] && [ -f "/etc/systemd/system/${WEB_SERVICE_NAME}" ]; then
    return 0
  fi
  return 1
}

resolve_install_mode() {
  case "${INSTALL_MODE}" in
    install|upgrade)
      SCRIPT_MODE="${INSTALL_MODE}"
      ;;
    auto)
      if looks_like_existing_install; then
        SCRIPT_MODE="upgrade"
      else
        SCRIPT_MODE="install"
      fi
      ;;
    *)
      err "Invalid INSTALL_MODE=${INSTALL_MODE}. Allowed: auto|install|upgrade"
      exit 1
      ;;
  esac

  if [ "${SCRIPT_MODE}" = "upgrade" ] && ! looks_like_existing_install; then
    err "INSTALL_MODE=upgrade but no existing installation detected under ${APP_DIR}"
    exit 1
  fi

  log "Running in ${SCRIPT_MODE} mode"
}

load_existing_settings_if_any() {
  local file
  file="$(env_path)"
  if [ ! -f "${file}" ]; then
    return 0
  fi

  local v
  v="$(read_env_value PORTAL_POSTGRES_DB || true)"
  if [ -n "${v}" ]; then POSTGRES_DB="${v}"; fi
  v="$(read_env_value PORTAL_POSTGRES_USER || true)"
  if [ -n "${v}" ]; then POSTGRES_USER="${v}"; fi
  v="$(read_env_value PORTAL_POSTGRES_PASSWORD || true)"
  if [ -n "${v}" ]; then POSTGRES_PASSWORD="${v}"; fi
  v="$(read_env_value WEB_PUBLIC_PORT || true)"
  if [ -n "${v}" ]; then WEB_PUBLIC_PORT="${v}"; fi
}

require_upgrade_env_integrity() {
  local file backend dsn
  file="$(env_path)"
  if [ ! -f "${file}" ]; then
    err "Upgrade mode requires existing ${file}. Refusing to continue to protect data."
    exit 1
  fi

  backend="$(read_env_value PORTAL_DB_BACKEND || true)"
  if [ -z "${backend}" ]; then
    backend="postgres"
  fi
  if [ "${backend}" != "postgres" ]; then
    err "Upgrade mode expects PORTAL_DB_BACKEND=postgres in ${file}, got '${backend}'."
    exit 1
  fi

  dsn="$(read_env_value PORTAL_POSTGRES_DSN || true)"
  if [ -z "${dsn}" ]; then
    err "Upgrade mode requires PORTAL_POSTGRES_DSN in ${file}. Refusing to continue."
    exit 1
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
  role_exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'" | tr -d '[:space:]' || true)"
  if [ "${role_exists}" != "1" ]; then
    runuser -u postgres -- psql -c "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
  else
    runuser -u postgres -- psql -c "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
  fi

  db_exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" | tr -d '[:space:]' || true)"
  if [ "${db_exists}" != "1" ]; then
    runuser -u postgres -- psql -c "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"
  fi
}

ensure_postgres_db_exists_for_upgrade() {
  local db_exists users_exists
  db_exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" | tr -d '[:space:]' || true)"
  if [ "${db_exists}" != "1" ]; then
    err "Upgrade mode: database '${POSTGRES_DB}' does not exist. Refusing to create a new empty database."
    exit 1
  fi

  users_exists="$(runuser -u postgres -- psql -d "${POSTGRES_DB}" -tAc "SELECT to_regclass('public.users') IS NOT NULL" | tr -d '[:space:]' || true)"
  if [ "${users_exists}" != "t" ] && [ "${users_exists}" != "true" ]; then
    err "Upgrade mode: table 'users' not found in '${POSTGRES_DB}'. Refusing migration to protect existing data."
    exit 1
  fi
}

backup_postgres_before_upgrade() {
  if [ "${SCRIPT_MODE}" != "upgrade" ] || [ "${UPGRADE_BACKUP_DB}" != "1" ]; then
    return 0
  fi

  if ! has_cmd pg_dump; then
    err "Upgrade mode requires pg_dump for safety backup, but pg_dump is missing."
    exit 1
  fi

  local backup_dir ts backup_file
  backup_dir="${APP_DIR}/backups"
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_file="${backup_dir}/postgres-${POSTGRES_DB}-${ts}.dump"
  mkdir -p "${backup_dir}"
  chmod 700 "${backup_dir}" 2>/dev/null || true

  log "Upgrade mode: creating database backup at ${backup_file}"
  runuser -u postgres -- pg_dump -Fc --dbname="${POSTGRES_DB}" > "${backup_file}"
  chmod 600 "${backup_file}" 2>/dev/null || true
  UPGRADE_DB_BACKUP_FILE="${backup_file}"
}

prepare_env_install() {
  local ip portal_secret api_token
  ip="$(resolve_preferred_ip)"
  portal_secret="$(generate_secret)"
  api_token="$(generate_secret)"
  INSTALL_API_TOKEN="${api_token}"

  mkdir -p "${APP_DIR}"
  touch "$(env_path)"

  upsert_env "PORTAL_SECRET_KEY" "${portal_secret}"
  upsert_env "ADMIN_USERNAME" "admin"
  upsert_env "ADMIN_PASSWORD" "admin"
  upsert_env "PORTAL_DB_BACKEND" "postgres"
  upsert_env "PORTAL_POSTGRES_DB" "${POSTGRES_DB}"
  upsert_env "PORTAL_POSTGRES_USER" "${POSTGRES_USER}"
  upsert_env "PORTAL_POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}"
  upsert_env "PORTAL_POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
  upsert_env "PORTAL_SQLITE_MIGRATION_SOURCE" "${APP_DIR}/data/portal.db"
  upsert_env "PORTAL_SKIP_SQLITE_IMPORT" "0"

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

prepare_env_upgrade() {
  local ip portal_secret api_token
  ip="$(resolve_preferred_ip)"
  mkdir -p "${APP_DIR}"
  touch "$(env_path)"

  portal_secret="$(read_env_value PORTAL_SECRET_KEY || true)"
  if [ -z "${portal_secret}" ]; then
    portal_secret="$(generate_secret)"
  fi
  api_token="$(read_env_value VPN_API_TOKEN || true)"
  if [ -z "${api_token}" ]; then
    api_token="$(generate_secret)"
  fi
  INSTALL_API_TOKEN="${api_token}"

  upsert_env_if_missing "PORTAL_SECRET_KEY" "${portal_secret}"
  upsert_env_if_missing "ADMIN_USERNAME" "admin"
  upsert_env_if_missing "ADMIN_PASSWORD" "admin"
  upsert_env_if_missing "PORTAL_DB_BACKEND" "postgres"
  upsert_env_if_missing "PORTAL_POSTGRES_DB" "${POSTGRES_DB}"
  upsert_env_if_missing "PORTAL_POSTGRES_USER" "${POSTGRES_USER}"
  upsert_env_if_missing "PORTAL_POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}"
  upsert_env_if_missing "PORTAL_POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
  upsert_env_if_missing "PORTAL_SQLITE_MIGRATION_SOURCE" "${APP_DIR}/data/portal.db"
  upsert_env "PORTAL_SKIP_SQLITE_IMPORT" "1"

  upsert_env_if_missing "WEB_PUBLIC_PORT" "${WEB_PUBLIC_PORT}"
  upsert_env_if_missing "PORTAL_SELF_UPGRADE_HOST_PROJECT_DIR" "/srv/vpn-platform-v1"

  upsert_env_if_missing "VPN_API_TOKEN" "${api_token}"
  upsert_env_if_missing "VPN_API_URL" "http://${ip}:${VPN_API_PUBLIC_PORT}"
  upsert_env_if_missing "WG_ENDPOINT" "${ip}:${WG_PUBLIC_PORT}"
  upsert_env_if_missing "OPENVPN_ENDPOINT_HOST" "${ip}"
  upsert_env_if_missing "OPENVPN_ENDPOINT_PORT" "${OPENVPN_PUBLIC_PORT}"
  upsert_env_if_missing "OPENVPN_PROTO" "${OPENVPN_PROTO}"

  upsert_env_if_missing "PORTAL_ENABLE_UDP_RELAY" "1"
  upsert_env_if_missing "VPN_RELAY_PUBLIC_HOST" "${ip}"
  upsert_env_if_missing "WG_RELAY_PORT_START" "24000"
  upsert_env_if_missing "WG_RELAY_PORT_END" "24031"
  upsert_env_if_missing "OPENVPN_RELAY_PORT_START" "29000"
  upsert_env_if_missing "OPENVPN_RELAY_PORT_END" "29031"
}

install_web_runtime() {
  log "Installing/updating web runtime dependencies"
  python3 -m venv "${APP_DIR}/.venv"
  "${APP_DIR}/.venv/bin/pip" install --upgrade pip
  "${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
}

run_upgrade_schema_migration() {
  if [ "${SCRIPT_MODE}" != "upgrade" ]; then
    return 0
  fi
  log "Upgrade mode: applying schema migration only (no data reset)"
  set -a
  # shellcheck disable=SC1090
  . "$(env_path)"
  set +a
  PORTAL_SKIP_SQLITE_IMPORT=1 "${APP_DIR}/.venv/bin/python" - <<'PY'
import os
import traceback
try:
    os.environ["PORTAL_SKIP_SQLITE_IMPORT"] = "1"
    import app as portal
    with portal.app.app_context():
        db = portal.get_db()
        portal.migrate_schema(db)
        db.commit()
    print("schema migration completed")
except Exception:
    traceback.print_exc()
    raise
PY
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

start_or_restart_web_service() {
  if ! has_cmd systemctl; then
    err "systemctl is required for local deployment mode."
    exit 1
  fi
  systemctl daemon-reload
  if systemctl is-active --quiet "${WEB_SERVICE_NAME}"; then
    systemctl restart "${WEB_SERVICE_NAME}"
  else
    systemctl enable --now "${WEB_SERVICE_NAME}"
  fi
}

deploy_local_vpn_server() {
  if [ "${INSTALL_LOCAL_VPN_SERVER}" != "1" ]; then
    log "Skipping local vpn-server deploy (INSTALL_LOCAL_VPN_SERVER=${INSTALL_LOCAL_VPN_SERVER})"
    return 0
  fi

  if [ "${SCRIPT_MODE}" = "upgrade" ] && [ "${UPGRADE_INCLUDE_VPN_SERVER}" != "1" ]; then
    log "Upgrade mode: skip vpn-server redeploy (set UPGRADE_INCLUDE_VPN_SERVER=1 to enable)"
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
  DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED}" \
  DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE}" \
  OPENVPN_ENFORCE_DB_AUTH=0 \
  bash "${script_path}"
}

verify_components() {
  if ! systemctl is-active --quiet postgresql; then
    err "postgresql service is not active"
    systemctl --no-pager --full status postgresql || true
    exit 1
  fi

  if ! systemctl is-active --quiet "${WEB_SERVICE_NAME}"; then
    err "web service is not active: ${WEB_SERVICE_NAME}"
    systemctl --no-pager --full status "${WEB_SERVICE_NAME}" || true
    exit 1
  fi

  if [ "${INSTALL_LOCAL_VPN_SERVER}" = "1" ] && { [ "${SCRIPT_MODE}" = "install" ] || [ "${UPGRADE_INCLUDE_VPN_SERVER}" = "1" ]; }; then
    if ! systemctl is-active --quiet "wg-quick@wg0.service"; then
      err "wg-quick@wg0.service is not active"
      systemctl --no-pager --full status "wg-quick@wg0.service" || true
      exit 1
    fi
    if ! systemctl is-active --quiet "vpnmanager-openvpn.service"; then
      err "vpnmanager-openvpn.service is not active"
      systemctl --no-pager --full status "vpnmanager-openvpn.service" || true
      exit 1
    fi
    if ! systemctl is-active --quiet "vpnmanager-server.service"; then
      err "vpnmanager-server.service is not active"
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

================ Install Completed ================
Mode: ${SCRIPT_MODE}
Login URL: http://${ip}:${WEB_PUBLIC_PORT}
IP: ${ip}
LAN IP: ${local_ip}
Port: ${WEB_PUBLIC_PORT}
Default username: admin
Default password: admin
Notes:
1) Local web service (systemd): ${WEB_SERVICE_NAME}
2) Local database (systemd): postgresql
3) Local vpn-server path: ${LOCAL_VPN_APP_DIR}
4) Web path: ${APP_DIR}
5) Upgrade mode keeps existing account/secret/token values in ${APP_DIR}/${ENV_FILE}
6) Upgrade DB backup: ${UPGRADE_DB_BACKUP_FILE:-skipped}
===================================================

EOF

  echo "[status] postgresql: $(systemctl is-active postgresql 2>/dev/null || true)"
  echo "[status] web: $(systemctl is-active "${WEB_SERVICE_NAME}" 2>/dev/null || true)"
  echo "[status] wg: $(systemctl is-active wg-quick@wg0.service 2>/dev/null || true)"
  echo "[status] openvpn: $(systemctl is-active vpnmanager-openvpn.service 2>/dev/null || true)"
  echo "[status] vpn-api: $(systemctl is-active vpnmanager-server.service 2>/dev/null || true)"
}

main() {
  require_root
  resolve_install_mode

  if [ "${SCRIPT_MODE}" = "install" ]; then
    install_base_deps
  else
    if [ "${SKIP_APT_ON_UPGRADE}" = "1" ]; then
      log "Upgrade mode: skip apt install/update (SKIP_APT_ON_UPGRADE=1)"
    else
      install_base_deps
    fi
  fi
  ensure_net_tools_installed

  setup_repo
  load_existing_settings_if_any
  cleanup_legacy_docker_stack
  if [ "${SCRIPT_MODE}" = "upgrade" ]; then
    require_upgrade_env_integrity
  fi
  ensure_postgres_ready
  if [ "${SCRIPT_MODE}" = "install" ]; then
    setup_postgres_db
  else
    ensure_postgres_db_exists_for_upgrade
    backup_postgres_before_upgrade
  fi

  if [ "${SCRIPT_MODE}" = "install" ]; then
    prepare_env_install
  else
    prepare_env_upgrade
  fi

  install_web_runtime
  run_upgrade_schema_migration
  write_web_systemd_unit
  start_or_restart_web_service
  deploy_local_vpn_server
  verify_components
  print_summary
}

main "$@"
