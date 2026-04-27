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
SHADOWSOCKS_SERVER_PORT="${SHADOWSOCKS_SERVER_PORT:-8388}"
KCPTUN_SERVER_PORT="${KCPTUN_SERVER_PORT:-29900}"
KCPTUN_ENABLED="${KCPTUN_ENABLED:-}"
SHADOWSOCKS_METHOD="${SHADOWSOCKS_METHOD:-chacha20-ietf-poly1305}"
SHADOWSOCKS_PASSWORD="${SHADOWSOCKS_PASSWORD:-}"
KCPTUN_KEY="${KCPTUN_KEY:-}"
WG_PUBLIC_PORT="${WG_PUBLIC_PORT:-${KCPTUN_SERVER_PORT}}"
OPENVPN_PUBLIC_PORT="${OPENVPN_PUBLIC_PORT:-${SHADOWSOCKS_SERVER_PORT}}"
OPENVPN_PROTO="${OPENVPN_PROTO:-tcp}"
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

sync_env_from_local_vpn_runtime_if_present() {
  local ss_file kcptun_file runtime_lines key value
  ss_file="/etc/shadowsocks-libev/vpnmanager.json"
  kcptun_file="/etc/kcptun/server.json"

  if [ ! -f "$(env_path)" ]; then
    return 0
  fi
  if [ ! -f "${ss_file}" ] && [ ! -f "${kcptun_file}" ]; then
    return 0
  fi

  runtime_lines="$(
    python3 - "${ss_file}" "${kcptun_file}" <<'PY'
import json
import os
import re
import sys

ss_path = sys.argv[1]
kcptun_path = sys.argv[2]

def emit(key, value):
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    print(f"{key}={text}")

if os.path.isfile(ss_path):
    try:
        with open(ss_path, "r", encoding="utf-8") as fh:
            ss = json.load(fh)
        emit("SHADOWSOCKS_PASSWORD", ss.get("password"))
        emit("SHADOWSOCKS_METHOD", ss.get("method"))
        port = ss.get("server_port")
        if isinstance(port, int) and 0 < port < 65536:
            emit("SHADOWSOCKS_SERVER_PORT", port)
    except Exception:
        pass

if os.path.isfile(kcptun_path):
    try:
        with open(kcptun_path, "r", encoding="utf-8") as fh:
            kcptun = json.load(fh)
        emit("KCPTUN_KEY", kcptun.get("key"))
        listen = str(kcptun.get("listen", "")).strip()
        match = re.search(r":([0-9]{1,5})$", listen)
        if match:
            port = int(match.group(1))
            if 0 < port < 65536:
                emit("KCPTUN_SERVER_PORT", port)
        emit("KCPTUN_ENABLED", "1")
    except Exception:
        pass
PY
  )"

  if [ -z "${runtime_lines}" ]; then
    return 0
  fi

  log "Syncing .env with current local vpn runtime config"
  while IFS='=' read -r key value; do
    if [ -z "${key}" ]; then
      continue
    fi
    upsert_env "${key}" "${value}"
    case "${key}" in
      SHADOWSOCKS_PASSWORD) SHADOWSOCKS_PASSWORD="${value}" ;;
      SHADOWSOCKS_METHOD) SHADOWSOCKS_METHOD="${value}" ;;
      SHADOWSOCKS_SERVER_PORT) OPENVPN_PUBLIC_PORT="${value}" ;;
      KCPTUN_KEY) KCPTUN_KEY="${value}" ;;
      KCPTUN_SERVER_PORT) WG_PUBLIC_PORT="${value}" ;;
      KCPTUN_ENABLED) KCPTUN_ENABLED="${value}" ;;
    esac
  done <<< "${runtime_lines}"
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
  local ip portal_secret api_token ss_password kcptun_key kcptun_enabled_final
  ip="$(resolve_preferred_ip)"
  portal_secret="$(generate_secret)"
  api_token="$(generate_secret)"
  ss_password="$(generate_secret)"
  kcptun_key="$(generate_secret)"
  INSTALL_API_TOKEN="${api_token}"
  kcptun_enabled_final="${KCPTUN_ENABLED}"
  if [ -z "${kcptun_enabled_final}" ]; then
    kcptun_enabled_final="1"
  fi

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

  upsert_env "WEB_PUBLIC_PORT" "${WEB_PUBLIC_PORT}"
  upsert_env "PORTAL_SELF_UPGRADE_HOST_PROJECT_DIR" "/srv/vpn-platform-v1"

  upsert_env "VPN_API_TOKEN" "${api_token}"
  upsert_env "VPN_API_URL" "http://${ip}:${VPN_API_PUBLIC_PORT}"
  upsert_env "VPN_ENABLE_WIREGUARD" "0"
  upsert_env "OPENVPN_ENABLED" "0"
  upsert_env "SHADOWSOCKS_ENABLED" "1"
  upsert_env "KCPTUN_ENABLED" "${kcptun_enabled_final}"
  upsert_env "SHADOWSOCKS_ENDPOINT_HOST" "${ip}"
  upsert_env "SHADOWSOCKS_SERVER_PORT" "${OPENVPN_PUBLIC_PORT}"
  upsert_env "SHADOWSOCKS_METHOD" "${SHADOWSOCKS_METHOD}"
  upsert_env "SHADOWSOCKS_PASSWORD" "${ss_password}"
  upsert_env "KCPTUN_SERVER_PORT" "${WG_PUBLIC_PORT}"
  upsert_env "KCPTUN_KEY" "${kcptun_key}"
}

prepare_env_upgrade() {
  local ip portal_secret api_token ss_password kcptun_key kcptun_enabled_final
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
  ss_password="$(read_env_value SHADOWSOCKS_PASSWORD || true)"
  if [ -z "${ss_password}" ]; then
    ss_password="$(generate_secret)"
  fi
  kcptun_key="$(read_env_value KCPTUN_KEY || true)"
  if [ -z "${kcptun_key}" ]; then
    kcptun_key="$(generate_secret)"
  fi
  INSTALL_API_TOKEN="${api_token}"
  kcptun_enabled_final="${KCPTUN_ENABLED}"
  if [ -z "${kcptun_enabled_final}" ]; then
    kcptun_enabled_final="$(read_env_value KCPTUN_ENABLED || true)"
  fi
  if [ -z "${kcptun_enabled_final}" ]; then
    kcptun_enabled_final="1"
  fi

  upsert_env_if_missing "PORTAL_SECRET_KEY" "${portal_secret}"
  upsert_env_if_missing "ADMIN_USERNAME" "admin"
  upsert_env_if_missing "ADMIN_PASSWORD" "admin"
  upsert_env_if_missing "PORTAL_DB_BACKEND" "postgres"
  upsert_env_if_missing "PORTAL_POSTGRES_DB" "${POSTGRES_DB}"
  upsert_env_if_missing "PORTAL_POSTGRES_USER" "${POSTGRES_USER}"
  upsert_env_if_missing "PORTAL_POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}"
  upsert_env_if_missing "PORTAL_POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"

  upsert_env_if_missing "WEB_PUBLIC_PORT" "${WEB_PUBLIC_PORT}"
  upsert_env_if_missing "PORTAL_SELF_UPGRADE_HOST_PROJECT_DIR" "/srv/vpn-platform-v1"

  upsert_env_if_missing "VPN_API_TOKEN" "${api_token}"
  upsert_env_if_missing "VPN_API_URL" "http://${ip}:${VPN_API_PUBLIC_PORT}"
  upsert_env "VPN_ENABLE_WIREGUARD" "0"
  upsert_env "OPENVPN_ENABLED" "0"
  upsert_env "SHADOWSOCKS_ENABLED" "1"
  upsert_env "KCPTUN_ENABLED" "${kcptun_enabled_final}"
  upsert_env "SHADOWSOCKS_ENDPOINT_HOST" "${ip}"
  upsert_env "SHADOWSOCKS_SERVER_PORT" "${OPENVPN_PUBLIC_PORT}"
  upsert_env "SHADOWSOCKS_METHOD" "${SHADOWSOCKS_METHOD}"
  upsert_env "SHADOWSOCKS_PASSWORD" "${ss_password}"
  upsert_env "KCPTUN_SERVER_PORT" "${WG_PUBLIC_PORT}"
  upsert_env "KCPTUN_KEY" "${kcptun_key}"
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
  (
    cd "${APP_DIR}"
    "${APP_DIR}/.venv/bin/python" - <<'PY'
import os
import traceback
try:
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
  )
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
  KCPTUN_SERVER_PORT="${WG_PUBLIC_PORT}" \
  KCPTUN_ENABLED="$(read_env_value KCPTUN_ENABLED || echo "${KCPTUN_ENABLED:-1}")" \
  SHADOWSOCKS_SERVER_PORT="${OPENVPN_PUBLIC_PORT}" \
  SHADOWSOCKS_METHOD="${SHADOWSOCKS_METHOD}" \
  SHADOWSOCKS_PASSWORD="$(read_env_value SHADOWSOCKS_PASSWORD || true)" \
  KCPTUN_KEY="$(read_env_value KCPTUN_KEY || true)" \
  VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT}" \
  VPN_API_TOKEN="${INSTALL_API_TOKEN}" \
  DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED}" \
  DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE}" \
  bash "${script_path}"
}

register_local_vpn_server_record() {
  if [ "${INSTALL_LOCAL_VPN_SERVER}" != "1" ]; then
    return 0
  fi
  if [ ! -f "$(env_path)" ]; then
    return 0
  fi

  local host server_name api_token
  host="$(resolve_preferred_ip)"
  server_name="$(hostname 2>/dev/null || echo "local-vpn-server")"
  api_token="$(read_env_value VPN_API_TOKEN || true)"
  if [ -z "${api_token}" ]; then
    api_token="${INSTALL_API_TOKEN}"
  fi

  set -a
  # shellcheck disable=SC1090
  . "$(env_path)"
  set +a

  (
    cd "${APP_DIR}"
    LOCAL_SERVER_HOST="${host}" \
    LOCAL_SERVER_NAME="${server_name}" \
    LOCAL_SERVER_REGION="Local" \
    LOCAL_VPN_API_TOKEN="${api_token}" \
    LOCAL_WG_PORT="${WG_PUBLIC_PORT}" \
    LOCAL_OPENVPN_PORT="${OPENVPN_PUBLIC_PORT}" \
    LOCAL_DNS_PORT="${DNS_PUBLIC_PORT}" \
    "${APP_DIR}/.venv/bin/python" - <<'PY'
import os

import app as portal

host = (os.environ.get("LOCAL_SERVER_HOST") or "").strip()
server_name = (os.environ.get("LOCAL_SERVER_NAME") or "").strip() or host
server_region = (os.environ.get("LOCAL_SERVER_REGION") or "Local").strip()
vpn_api_token = (os.environ.get("LOCAL_VPN_API_TOKEN") or "").strip()
wg_port = portal.normalize_server_port(os.environ.get("LOCAL_WG_PORT"), portal.SERVER_DEPLOY_DEFAULT_WG_PORT)
openvpn_port = portal.normalize_server_port(os.environ.get("LOCAL_OPENVPN_PORT"), portal.SERVER_DEPLOY_DEFAULT_OPENVPN_PORT)
dns_port = portal.normalize_server_port(os.environ.get("LOCAL_DNS_PORT"), portal.SERVER_DEPLOY_DEFAULT_DNS_PORT)
now_iso = portal.utcnow_iso()
message = "Local vpn-server deployed by install script."

if not host:
    raise RuntimeError("empty local server host")

with portal.app.app_context():
    db = portal.get_db()
    row = db.execute(
        """
        SELECT id
        FROM vpn_servers
        WHERE host = ?
           OR (trim(COALESCE(vpn_api_token, '')) <> '' AND vpn_api_token = ?)
        ORDER BY id ASC
        LIMIT 1
        """,
        (host, vpn_api_token),
    ).fetchone()
    if row:
        server_id = int(row["id"])
        db.execute(
            """
            UPDATE vpn_servers
            SET server_name = ?,
                server_region = ?,
                host = ?,
                port = 22,
                username = COALESCE(NULLIF(username, ''), 'root'),
                domain = COALESCE(domain, ''),
                vpn_api_token = ?,
                wg_port = ?,
                openvpn_port = ?,
                dns_port = ?,
                status = 'online',
                last_test_at = ?,
                last_test_ok = 1,
                last_test_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                server_name,
                server_region,
                host,
                vpn_api_token,
                wg_port,
                openvpn_port,
                dns_port,
                now_iso,
                message,
                now_iso,
                server_id,
            ),
        )
    else:
        server_id = portal.create_server_record(
            db,
            server_name=server_name,
            server_region=server_region,
            host=host,
            port=22,
            username="root",
            password="",
            ssh_private_key="",
            domain="",
            wg_port=wg_port,
            openvpn_port=openvpn_port,
            dns_port=dns_port,
            vpn_api_token=vpn_api_token,
            status="online",
        )
        db.execute(
            """
            UPDATE vpn_servers
            SET last_test_at = ?,
                last_test_ok = 1,
                last_test_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (now_iso, message, now_iso, server_id),
        )
    db.commit()
    print(f"local server record upserted: id={server_id}, host={host}")
PY
  ) || {
    err "Failed to register local vpn-server record in portal database"
    exit 1
  }
}

ensure_openvpn_updown_wrapper_compat() {
  local conf up_script down_script iptables_bin up_line uplink_if
  conf="/etc/openvpn/server/server.conf"
  up_script="/etc/openvpn/server/vpnmanager-up.sh"
  down_script="/etc/openvpn/server/vpnmanager-down.sh"

  if [ ! -f "${conf}" ]; then
    return 0
  fi

  if grep -Eq '^proto[[:space:]]+tcp$' "${conf}" 2>/dev/null; then
    sed -i '/^explicit-exit-notify /d' "${conf}" || true
  fi

  up_line="$(grep -E '^up "' "${conf}" 2>/dev/null | head -n 1 || true)"
  if printf '%s' "${up_line}" | grep -q "vpnmanager-up.sh"; then
    return 0
  fi

  iptables_bin="$(command -v iptables || true)"
  if [ -z "${iptables_bin}" ]; then
    iptables_bin="/sbin/iptables"
  fi

  uplink_if="$(printf '%s' "${up_line}" | sed -n 's/.* -o \([^ ]*\) .*/\1/p' | head -n 1)"
  if [ -z "${uplink_if}" ]; then
    uplink_if="eth0"
  fi

  log "Applying OpenVPN up/down compatibility wrapper (uplink=${uplink_if})"
  cat > "${up_script}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if ! ${iptables_bin} -t nat -C POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE >/dev/null 2>&1; then
  ${iptables_bin} -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE
fi
exit 0
EOF
  chmod 755 "${up_script}"

  cat > "${down_script}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
${iptables_bin} -t nat -D POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE >/dev/null 2>&1 || true
exit 0
EOF
  chmod 755 "${down_script}"

  sed -i 's|^up ".*"|up "/etc/openvpn/server/vpnmanager-up.sh"|' "${conf}"
  sed -i 's|^down ".*"|down "/etc/openvpn/server/vpnmanager-down.sh"|' "${conf}"

  if has_cmd systemctl; then
    systemctl restart vpnmanager-openvpn.service || true
  fi
}

verify_components() {
  local kcptun_enabled_current
  kcptun_enabled_current="$(read_env_value KCPTUN_ENABLED || true)"
  if [ -z "${kcptun_enabled_current}" ]; then
    kcptun_enabled_current="${KCPTUN_ENABLED:-1}"
  fi

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
    if ! systemctl is-active --quiet "vpnmanager-shadowsocks.service"; then
      err "vpnmanager-shadowsocks.service is not active"
      systemctl --no-pager --full status "vpnmanager-shadowsocks.service" || true
      exit 1
    fi
    if [ "${kcptun_enabled_current}" = "1" ]; then
      if ! systemctl is-active --quiet "vpnmanager-kcptun.service"; then
        err "vpnmanager-kcptun.service is not active"
        systemctl --no-pager --full status "vpnmanager-kcptun.service" || true
        exit 1
      fi
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
  echo "[status] shadowsocks: $(systemctl is-active vpnmanager-shadowsocks.service 2>/dev/null || true)"
  echo "[status] kcptun: $(systemctl is-active vpnmanager-kcptun.service 2>/dev/null || true)"
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
  sync_env_from_local_vpn_runtime_if_present

  install_web_runtime
  run_upgrade_schema_migration
  write_web_systemd_unit
  start_or_restart_web_service
  deploy_local_vpn_server
  sync_env_from_local_vpn_runtime_if_present
  start_or_restart_web_service
  register_local_vpn_server_record
  verify_components
  print_summary
}

main "$@"
