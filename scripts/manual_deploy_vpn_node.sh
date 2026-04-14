#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export TERM="${TERM:-dumb}"
export NEEDRESTART_MODE=a

APP_DIR="${APP_DIR:-/opt/vpn-node}"
REPO_URL="${REPO_URL:-https://github.com/trowar/vpn-manager.git}"
BRANCH="${BRANCH:-main}"

WG_PUBLIC_PORT="${WG_PUBLIC_PORT:-51820}"
OPENVPN_PUBLIC_PORT="${OPENVPN_PUBLIC_PORT:-1194}"
DNS_PUBLIC_PORT="${DNS_PUBLIC_PORT:-53}"
VPN_API_PUBLIC_PORT="${VPN_API_PUBLIC_PORT:-8081}"
VPN_API_TOKEN="${VPN_API_TOKEN:-}"

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-600}"
APT_RETRY_COUNT="${APT_RETRY_COUNT:-5}"
APT_RETRY_DELAY_SECONDS="${APT_RETRY_DELAY_SECONDS:-8}"

PM=""
ACTUAL_DNS_PORT="${DNS_PUBLIC_PORT}"

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
    err "请使用 root 执行该脚本"
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
  err "未找到支持的包管理器（apt / dnf / yum）"
  exit 1
}

pkg_update() {
  if [ "$PM" = "apt" ]; then
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd update
    return 0
  fi
  if [ "$PM" = "dnf" ]; then
    retry_cmd 4 6 dnf -y -q makecache
    return 0
  fi
  retry_cmd 4 6 yum -y -q makecache
}

pkg_upgrade() {
  log "升级系统组件（${PM}）"
  if [ "$PM" = "apt" ]; then
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd upgrade -y
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
    retry_cmd "${APT_RETRY_COUNT}" "${APT_RETRY_DELAY_SECONDS}" apt_cmd install -y --no-install-recommends "$@"
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
  pkg_install ca-certificates curl git openssl

  if ! has_cmd ip; then
    pkg_install iproute2 || pkg_install iproute || true
  fi
  if ! has_cmd iptables; then
    pkg_install iptables || true
  fi
  if ! has_cmd ss; then
    pkg_install iproute2 || pkg_install iproute || true
  fi
  if ! has_cmd wg; then
    pkg_install wireguard-tools || true
  fi
  if ! has_cmd openvpn; then
    pkg_install openvpn || true
  fi

  if ! has_cmd wg; then
    err "wireguard-tools 安装失败"
    exit 1
  fi
  if ! has_cmd openvpn; then
    err "openvpn 安装失败"
    exit 1
  fi
}

install_compose_standalone() {
  local os arch version bin_url plugin_dir
  os="linux"
  version="${DOCKER_COMPOSE_VERSION:-v2.39.2}"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      warn "unsupported architecture for compose standalone install: ${arch}"
      return 1
      ;;
  esac

  bin_url="https://github.com/docker/compose/releases/download/${version}/docker-compose-${os}-${arch}"
  log "安装 Docker Compose standalone (${version})"
  retry_cmd 3 5 curl -fsSL "${bin_url}" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose

  plugin_dir="/usr/local/lib/docker/cli-plugins"
  mkdir -p "${plugin_dir}"
  cp /usr/local/bin/docker-compose "${plugin_dir}/docker-compose" >/dev/null 2>&1 || true
  chmod +x "${plugin_dir}/docker-compose" >/dev/null 2>&1 || true
  hash -r || true
}

ensure_docker_compose() {
  if docker compose version >/dev/null 2>&1 || has_cmd docker-compose; then
    return 0
  fi

  if [ "$PM" = "apt" ]; then
    pkg_install docker-compose-plugin || pkg_install docker-compose-v2 || pkg_install docker-compose || true
  else
    pkg_install docker-compose-plugin || pkg_install docker-compose || true
  fi

  if docker compose version >/dev/null 2>&1 || has_cmd docker-compose; then
    return 0
  fi

  install_compose_standalone || true
  if docker compose version >/dev/null 2>&1 || has_cmd docker-compose; then
    return 0
  fi

  err "Docker Compose 不可用"
  return 1
}

install_docker() {
  if ! has_cmd docker; then
    log "安装 Docker"
    if [ "$PM" = "apt" ]; then
      pkg_install docker.io || true
    else
      pkg_install docker docker-ce docker-ce-cli containerd.io || pkg_install docker || true
    fi
  fi

  if ! has_cmd docker; then
    log "尝试官方安装脚本安装 Docker"
    curl -fsSL https://get.docker.com | sh
  fi

  if ! has_cmd docker; then
    err "Docker 安装失败"
    exit 1
  fi

  if has_cmd systemctl; then
    systemctl daemon-reload || true
    systemctl enable --now docker || true
  else
    service docker start || true
  fi

  ensure_docker_compose
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
    return
  fi
  docker-compose "$@"
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
  if [ -d "${APP_DIR}/.git" ]; then
    log "更新代码：${APP_DIR}"
    retry_cmd 4 8 git -C "${APP_DIR}" fetch --depth 1 origin "${BRANCH}"
    retry_cmd 4 8 git -C "${APP_DIR}" checkout -f "${BRANCH}"
    retry_cmd 4 8 git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
  else
    log "拉取代码到：${APP_DIR}"
    rm -rf "${APP_DIR}"
    retry_cmd 4 8 git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
  fi
}

ensure_wireguard_files() {
  mkdir -p docker/vpn/wireguard

  if [ ! -f docker/vpn/wireguard/server_private.key ]; then
    wg genkey > docker/vpn/wireguard/server_private.key
    chmod 600 docker/vpn/wireguard/server_private.key
  fi

  if [ ! -f docker/vpn/wireguard/server_public.key ]; then
    wg pubkey < docker/vpn/wireguard/server_private.key > docker/vpn/wireguard/server_public.key
    chmod 600 docker/vpn/wireguard/server_public.key
  fi

  if [ ! -f docker/vpn/wireguard/wg0.conf ]; then
    local uplink_if
    local wg_priv

    uplink_if="$(ip -o route show default 2>/dev/null | awk 'NR==1 {print $5}')"
    if [ -z "${uplink_if}" ]; then
      uplink_if="eth0"
    fi

    wg_priv="$(cat docker/vpn/wireguard/server_private.key)"
    cat > docker/vpn/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.7.0.1/24
ListenPort = 51820
PrivateKey = ${wg_priv}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${uplink_if} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${uplink_if} -j MASQUERADE
EOF
    chmod 600 docker/vpn/wireguard/wg0.conf
  fi
}

ensure_openvpn_files() {
  local ovpn_dir
  ovpn_dir="docker/vpn/openvpn"
  mkdir -p "${ovpn_dir}"

  if [ ! -f "${ovpn_dir}/server.conf" ] && [ -f "${ovpn_dir}/server.conf.example" ]; then
    cp "${ovpn_dir}/server.conf.example" "${ovpn_dir}/server.conf"
  fi

  if [ ! -f "${ovpn_dir}/ca.crt" ] || [ ! -f "${ovpn_dir}/server.crt" ] || [ ! -f "${ovpn_dir}/server.key" ]; then
    log "生成 OpenVPN 证书材料"

    if [ ! -f "${ovpn_dir}/ca.key" ]; then
      openssl genrsa -out "${ovpn_dir}/ca.key" 4096 >/dev/null 2>&1
    fi
    if [ ! -f "${ovpn_dir}/ca.crt" ]; then
      openssl req -x509 -new -nodes -key "${ovpn_dir}/ca.key" -sha256 -days 3650 \
        -subj "/CN=vpnmanager-ca" -out "${ovpn_dir}/ca.crt" >/dev/null 2>&1
    fi
    if [ ! -f "${ovpn_dir}/server.key" ]; then
      openssl genrsa -out "${ovpn_dir}/server.key" 4096 >/dev/null 2>&1
    fi
    if [ ! -f "${ovpn_dir}/server.csr" ]; then
      openssl req -new -key "${ovpn_dir}/server.key" -subj "/CN=vpnmanager-server" \
        -out "${ovpn_dir}/server.csr" >/dev/null 2>&1
    fi

    cat > "${ovpn_dir}/server_ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

    openssl x509 -req -in "${ovpn_dir}/server.csr" -CA "${ovpn_dir}/ca.crt" -CAkey "${ovpn_dir}/ca.key" \
      -CAcreateserial -out "${ovpn_dir}/server.crt" -days 1825 -sha256 \
      -extfile "${ovpn_dir}/server_ext.cnf" >/dev/null 2>&1
    chmod 600 "${ovpn_dir}/ca.key" "${ovpn_dir}/server.key"
  fi

  if [ ! -f "${ovpn_dir}/tls-crypt.key" ]; then
    openvpn --genkey secret "${ovpn_dir}/tls-crypt.key" >/dev/null 2>&1 || \
    openvpn --genkey --secret "${ovpn_dir}/tls-crypt.key" >/dev/null 2>&1
    chmod 600 "${ovpn_dir}/tls-crypt.key"
  fi
}

pick_dns_port_if_needed() {
  ACTUAL_DNS_PORT="${DNS_PUBLIC_PORT}"
  if has_cmd ss; then
    if ss -H -lnut "( sport = :${ACTUAL_DNS_PORT} )" 2>/dev/null | grep -q .; then
      for candidate in 5353 1053 2053 3053; do
        if ss -H -lnut "( sport = :${candidate} )" 2>/dev/null | grep -q .; then
          continue
        fi
        ACTUAL_DNS_PORT="${candidate}"
        warn "DNS 端口 ${DNS_PUBLIC_PORT} 已占用，自动改用 ${ACTUAL_DNS_PORT}"
        break
      done
    fi
  fi
}

write_env_file() {
  if [ -z "${VPN_API_TOKEN}" ]; then
    VPN_API_TOKEN="$(generate_token)"
  fi

  cat > .env <<EOF
VPN_API_TOKEN=${VPN_API_TOKEN}
WG_INTERFACE=wg0
WG_PUBLIC_PORT=${WG_PUBLIC_PORT}
OPENVPN_PUBLIC_PORT=${OPENVPN_PUBLIC_PORT}
DNS_PUBLIC_PORT=${ACTUAL_DNS_PORT}
VPN_API_PUBLIC_PORT=${VPN_API_PUBLIC_PORT}
VPN_ENABLE_WIREGUARD=1
VPN_ENABLE_DNSMASQ=1
VPN_ENABLE_OPENVPN=1
EOF
}

start_vpn_service() {
  export COMPOSE_BAKE=0
  export DOCKER_BUILDKIT=1
  export COMPOSE_HTTP_TIMEOUT=300
  export DOCKER_CLIENT_TIMEOUT=300

  retry_cmd 5 8 docker pull python:3.12-slim >/dev/null 2>&1 || warn "预拉取 python:3.12-slim 失败，继续构建"
  retry_cmd 5 10 compose -f docker-compose.vpn-node.yml --env-file .env build --pull vpnmanager-server
  retry_cmd 5 8 compose -f docker-compose.vpn-node.yml --env-file .env up -d --no-build vpnmanager-server
}

print_summary() {
  log "部署完成"
  echo
  echo "================ 手动部署完成 ================"
  echo "目录: ${APP_DIR}"
  echo "WG 端口: ${WG_PUBLIC_PORT}/udp"
  echo "OpenVPN 端口: ${OPENVPN_PUBLIC_PORT}/udp"
  echo "DNS 端口: ${ACTUAL_DNS_PORT}"
  echo "VPN API 端口: ${VPN_API_PUBLIC_PORT}/tcp"
  echo "VPN_API_TOKEN: ${VPN_API_TOKEN}"
  echo "日志查看: cd ${APP_DIR} && docker compose -f docker-compose.vpn-node.yml --env-file .env logs -f vpnmanager-server"
  echo "=============================================="

  compose -f docker-compose.vpn-node.yml --env-file .env ps
}

main() {
  require_root
  detect_pm
  log "检测到包管理器: ${PM}"
  install_base_deps
  install_docker
  setup_repo

  cd "${APP_DIR}"
  ensure_wireguard_files
  ensure_openvpn_files
  pick_dns_port_if_needed
  write_env_file
  start_vpn_service
  print_summary
}

main "$@"
