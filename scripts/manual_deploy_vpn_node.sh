#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

APP_DIR="${APP_DIR:-/srv/vpn-node}"
REPO_URL="${REPO_URL:-https://github.com/trowar/vpn-manager.git}"
BRANCH="${BRANCH:-main}"

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PUBLIC_PORT="${WG_PUBLIC_PORT:-51820}"
OPENVPN_PUBLIC_PORT="${OPENVPN_PUBLIC_PORT:-1194}"
OPENVPN_PROTO="${OPENVPN_PROTO:-udp}"
DNS_PUBLIC_PORT="${DNS_PUBLIC_PORT:-53}"
VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT:-8081}"
VPN_API_TOKEN="${VPN_API_TOKEN:-}"
OPENVPN_ENFORCE_DB_AUTH="${OPENVPN_ENFORCE_DB_AUTH:-}"
DEPLOY_SKIP_OS_UPGRADE="${DEPLOY_SKIP_OS_UPGRADE:-0}"
DISABLE_SYSTEMD_RESOLVED="${DISABLE_SYSTEMD_RESOLVED:-1}"

WG_PRIVATE_KEY_B64="${WG_PRIVATE_KEY_B64:-}"
WG_PUBLIC_KEY_B64="${WG_PUBLIC_KEY_B64:-}"
OPENVPN_CA_CERT_B64="${OPENVPN_CA_CERT_B64:-}"
OPENVPN_SERVER_CERT_B64="${OPENVPN_SERVER_CERT_B64:-}"
OPENVPN_SERVER_KEY_B64="${OPENVPN_SERVER_KEY_B64:-}"
OPENVPN_TLS_CRYPT_KEY_B64="${OPENVPN_TLS_CRYPT_KEY_B64:-}"

PY_VENV_DIR="${PY_VENV_DIR:-${APP_DIR}/.venv-vpn}"
PORTAL_DB_PATH="${PORTAL_DB_PATH:-}"

WG_CONF_PATH="/etc/wireguard/${WG_INTERFACE}.conf"
OPENVPN_DIR="/etc/openvpn/server"
OPENVPN_SERVER_CONF="${OPENVPN_DIR}/server.conf"
OPENVPN_PID_FILE="/run/openvpn-server.pid"
OPENVPN_STATUS_FILE="/run/openvpn-status.log"
OPENVPN_UP_SCRIPT="${OPENVPN_DIR}/vpnmanager-up.sh"
OPENVPN_DOWN_SCRIPT="${OPENVPN_DIR}/vpnmanager-down.sh"
DNSMASQ_CONF="/etc/dnsmasq.d/vpn.conf"
WG_SERVER_PUBLIC_KEY_FILE="/srv/vpn-shared/server_public.key"

OPENVPN_SERVICE_NAME="vpnmanager-openvpn.service"
OPENVPN_GUARD_SERVICE_NAME="vpnmanager-openvpn-guard.service"
VPN_API_SERVICE_NAME="vpnmanager-server.service"

PM=""

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
      wireguard-tools openvpn dnsmasq \
      python3 python3-venv python3-pip
  else
    pkg_install \
      ca-certificates curl git openssl \
      iproute iptables net-tools \
      wireguard-tools openvpn dnsmasq \
      python3 python3-pip
  fi

  if ! has_cmd wg; then
    err "wireguard-tools install failed"
    exit 1
  fi
  if ! has_cmd openvpn; then
    err "openvpn install failed"
    exit 1
  fi
  if ! has_cmd dnsmasq; then
    err "dnsmasq install failed"
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

detect_uplink_interface() {
  local iface
  iface="$(ip -o route show default 2>/dev/null | awk 'NR==1 {print $5}')"
  if [ -z "${iface}" ]; then
    iface="eth0"
  fi
  printf '%s' "${iface}"
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

  log "disabling systemd-resolved by default to free DNS port 53"
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

ensure_wireguard_files() {
  local work_dir priv_file pub_file wg_priv uplink_if
  work_dir="${APP_DIR}/docker/vpn/wireguard"
  priv_file="${work_dir}/server_private.key"
  pub_file="${work_dir}/server_public.key"

  mkdir -p "${work_dir}" /etc/wireguard "$(dirname "${WG_SERVER_PUBLIC_KEY_FILE}")"

  if [ -n "${WG_PRIVATE_KEY_B64}" ]; then
    echo "${WG_PRIVATE_KEY_B64}" | base64 -d > "${priv_file}"
  elif [ ! -f "${priv_file}" ]; then
    wg genkey > "${priv_file}"
  fi
  chmod 600 "${priv_file}"

  if [ -n "${WG_PUBLIC_KEY_B64}" ]; then
    echo "${WG_PUBLIC_KEY_B64}" | base64 -d > "${pub_file}"
  else
    wg pubkey < "${priv_file}" > "${pub_file}"
  fi
  chmod 600 "${pub_file}"

  wg_priv="$(cat "${priv_file}")"
  uplink_if="$(detect_uplink_interface)"

  cat > "${WG_CONF_PATH}" <<EOF
[Interface]
Address = 10.7.0.1/24
ListenPort = ${WG_PUBLIC_PORT}
PrivateKey = ${wg_priv}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${uplink_if} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${uplink_if} -j MASQUERADE
EOF
  chmod 600 "${WG_CONF_PATH}"
  cp -f "${pub_file}" "${WG_SERVER_PUBLIC_KEY_FILE}"
  chmod 600 "${WG_SERVER_PUBLIC_KEY_FILE}"
}

ensure_openvpn_materials() {
  local ca_crt server_crt server_key tls_key
  ca_crt="${OPENVPN_DIR}/ca.crt"
  server_crt="${OPENVPN_DIR}/server.crt"
  server_key="${OPENVPN_DIR}/server.key"
  tls_key="${OPENVPN_DIR}/tls-crypt.key"

  mkdir -p "${OPENVPN_DIR}"

  if [ -n "${OPENVPN_CA_CERT_B64}" ]; then
    echo "${OPENVPN_CA_CERT_B64}" | base64 -d > "${ca_crt}"
  fi
  if [ -n "${OPENVPN_SERVER_CERT_B64}" ]; then
    echo "${OPENVPN_SERVER_CERT_B64}" | base64 -d > "${server_crt}"
  fi
  if [ -n "${OPENVPN_SERVER_KEY_B64}" ]; then
    echo "${OPENVPN_SERVER_KEY_B64}" | base64 -d > "${server_key}"
  fi
  if [ -n "${OPENVPN_TLS_CRYPT_KEY_B64}" ]; then
    echo "${OPENVPN_TLS_CRYPT_KEY_B64}" | base64 -d > "${tls_key}"
  fi

  if [ ! -f "${ca_crt}" ] || [ ! -f "${server_crt}" ] || [ ! -f "${server_key}" ]; then
    log "generating OpenVPN CA/server certificates"
    openssl genrsa -out "${OPENVPN_DIR}/ca.key" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "${OPENVPN_DIR}/ca.key" -sha256 -days 3650 -subj "/CN=vpnmanager-ca" -out "${ca_crt}" >/dev/null 2>&1
    openssl genrsa -out "${server_key}" 4096 >/dev/null 2>&1
    openssl req -new -key "${server_key}" -subj "/CN=vpnmanager-server" -out "${OPENVPN_DIR}/server.csr" >/dev/null 2>&1
    cat > "${OPENVPN_DIR}/server_ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
    openssl x509 -req -in "${OPENVPN_DIR}/server.csr" -CA "${ca_crt}" -CAkey "${OPENVPN_DIR}/ca.key" -CAcreateserial -out "${server_crt}" -days 1825 -sha256 -extfile "${OPENVPN_DIR}/server_ext.cnf" >/dev/null 2>&1
  fi

  if [ ! -f "${tls_key}" ]; then
    openvpn --genkey secret "${tls_key}" >/dev/null 2>&1 || openvpn --genkey --secret "${tls_key}" >/dev/null 2>&1
  fi

  chmod 600 "${server_key}" "${tls_key}" "${OPENVPN_DIR}/ca.key" 2>/dev/null || true
}

write_openvpn_config() {
  local uplink_if auth_lines iptables_bin
  uplink_if="$(detect_uplink_interface)"
  iptables_bin="$(command -v iptables || true)"
  if [ -z "${iptables_bin}" ]; then
    iptables_bin="/sbin/iptables"
  fi

  auth_lines="script-security 2"
  if [ "${OPENVPN_ENFORCE_DB_AUTH}" = "1" ]; then
    auth_lines="$(cat <<EOF
script-security 3
verify-client-cert require
tls-verify "/usr/bin/python3 ${APP_DIR}/scripts/openvpn_auth.py"
management 127.0.0.1 7505
EOF
)"
  fi

  cat > "${OPENVPN_UP_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if ! ${iptables_bin} -t nat -C POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE >/dev/null 2>&1; then
  ${iptables_bin} -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE
fi
exit 0
EOF
  chmod 755 "${OPENVPN_UP_SCRIPT}"

  cat > "${OPENVPN_DOWN_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
${iptables_bin} -t nat -D POSTROUTING -s 10.8.0.0/24 -o ${uplink_if} -j MASQUERADE >/dev/null 2>&1 || true
exit 0
EOF
  chmod 755 "${OPENVPN_DOWN_SCRIPT}"

  cat > "${OPENVPN_SERVER_CONF}" <<EOF
port ${OPENVPN_PUBLIC_PORT}
proto ${OPENVPN_PROTO}
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ${OPENVPN_DIR}/ipp.txt

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh none
ecdh-curve prime256v1
tls-crypt ${OPENVPN_DIR}/tls-crypt.key

cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
keepalive 10 120
persist-key
persist-tun
explicit-exit-notify 1

user nobody
group nogroup

${auth_lines}

push "redirect-gateway def1"
push "dhcp-option DNS 10.7.0.1"

up "${OPENVPN_UP_SCRIPT}"
down "${OPENVPN_DOWN_SCRIPT}"

status ${OPENVPN_STATUS_FILE}
verb 3
EOF
}

write_dnsmasq_conf() {
  mkdir -p "$(dirname "${DNSMASQ_CONF}")"
  cat > "${DNSMASQ_CONF}" <<EOF
port=${DNS_PUBLIC_PORT}
listen-address=10.7.0.1
bind-interfaces
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=1000
EOF
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
  cat > "/etc/systemd/system/${OPENVPN_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager OpenVPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PORTAL_DB_PATH=${PORTAL_DB_PATH}
Environment=OPENVPN_COMMON_NAME_PREFIX=vpn-user-
ExecStart=/usr/sbin/openvpn --config ${OPENVPN_SERVER_CONF} --writepid ${OPENVPN_PID_FILE} --status ${OPENVPN_STATUS_FILE}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${VPN_API_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager API Service
After=network-online.target ${OPENVPN_SERVICE_NAME} wg-quick@${WG_INTERFACE}.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/docker/vpn
Environment=PATH=${PY_VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_INTERFACE=${WG_INTERFACE}
Environment=WG_CONF_PATH=${WG_CONF_PATH}
Environment=WG_SERVER_PUBLIC_KEY_FILE=${WG_SERVER_PUBLIC_KEY_FILE}
Environment=VPN_API_TOKEN=${VPN_API_TOKEN}
Environment=OPENVPN_SERVER_CONF=${OPENVPN_SERVER_CONF}
Environment=OPENVPN_CA_CERT_FILE=${OPENVPN_DIR}/ca.crt
Environment=OPENVPN_TLS_CRYPT_KEY_FILE=${OPENVPN_DIR}/tls-crypt.key
Environment=OPENVPN_STATUS_FILE=${OPENVPN_STATUS_FILE}
Environment=OPENVPN_PID_FILE=${OPENVPN_PID_FILE}
ExecStart=${PY_VENV_DIR}/bin/gunicorn --workers 1 --bind 0.0.0.0:${VPN_API_PUBLIC_PORT} vpn_api:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${OPENVPN_GUARD_SERVICE_NAME}" <<EOF
[Unit]
Description=VPN Manager OpenVPN Session Guard
After=${OPENVPN_SERVICE_NAME}
Requires=${OPENVPN_SERVICE_NAME}

[Service]
Type=simple
Environment=PORTAL_DB_PATH=${PORTAL_DB_PATH}
Environment=OPENVPN_STATUS_FILE=${OPENVPN_STATUS_FILE}
Environment=OPENVPN_MANAGEMENT_HOST=127.0.0.1
Environment=OPENVPN_MANAGEMENT_PORT=7505
Environment=OPENVPN_COMMON_NAME_PREFIX=vpn-user-
ExecStart=/usr/bin/python3 ${APP_DIR}/scripts/openvpn_session_guard.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

enable_ip_forward() {
  cat > /etc/sysctl.d/99-vpnmanager.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
  sysctl --system >/dev/null 2>&1 || true
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
}

start_services() {
  if ! has_cmd systemctl; then
    err "systemctl is required for local deployment mode"
    exit 1
  fi

  systemctl daemon-reload

  systemctl enable --now "wg-quick@${WG_INTERFACE}.service"
  systemctl enable --now dnsmasq
  systemctl enable --now "${OPENVPN_SERVICE_NAME}"

  if [ "${OPENVPN_ENFORCE_DB_AUTH}" = "1" ]; then
    systemctl enable --now "${OPENVPN_GUARD_SERVICE_NAME}"
  else
    systemctl disable --now "${OPENVPN_GUARD_SERVICE_NAME}" >/dev/null 2>&1 || true
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
  echo "WG: ${WG_PUBLIC_PORT}/udp"
  echo "OpenVPN: ${OPENVPN_PUBLIC_PORT}/${OPENVPN_PROTO}"
  echo "DNS: 10.7.0.1:${DNS_PUBLIC_PORT}"
  echo "VPN API: ${VPN_API_PUBLIC_PORT}/tcp"
  echo "VPN_API_TOKEN: ${VPN_API_TOKEN}"
  echo "PORTAL_DB_PATH: ${PORTAL_DB_PATH}"
  echo "Auth enforcement: ${OPENVPN_ENFORCE_DB_AUTH}"
  echo
  echo "Service status checks:"
  systemctl --no-pager --full status "wg-quick@${WG_INTERFACE}.service" | sed -n '1,6p' || true
  systemctl --no-pager --full status "${OPENVPN_SERVICE_NAME}" | sed -n '1,6p' || true
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

  PORTAL_DB_PATH="$(resolve_portal_db_path)"
  if [ -z "${OPENVPN_ENFORCE_DB_AUTH}" ]; then
    if [ -f "${PORTAL_DB_PATH}" ]; then
      OPENVPN_ENFORCE_DB_AUTH="1"
    else
      OPENVPN_ENFORCE_DB_AUTH="0"
    fi
  fi

  ensure_python_runtime
  ensure_wireguard_files
  ensure_openvpn_materials
  write_openvpn_config
  write_dnsmasq_conf
  enable_ip_forward
  write_systemd_units
  start_services

  if ! wait_vpn_api_ready; then
    err "vpn api health check failed on 127.0.0.1:${VPN_API_PUBLIC_PORT}"
    exit 1
  fi

  print_summary
}

main "$@"
