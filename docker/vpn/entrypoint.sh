#!/usr/bin/env bash
set -euo pipefail

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONF_PATH="${WG_CONF_PATH:-/etc/wireguard/${WG_INTERFACE}.conf}"
WG_SERVER_PUBLIC_KEY_FILE="${WG_SERVER_PUBLIC_KEY_FILE:-/srv/vpn-shared/server_public.key}"
OPENVPN_SERVER_CONF="${OPENVPN_SERVER_CONF:-/etc/openvpn/server/server.conf}"
DNSMASQ_CONF="${DNSMASQ_CONF:-/etc/dnsmasq.d/vpn.conf}"
VPN_API_PORT="${VPN_API_PORT:-8081}"

VPN_ENABLE_WIREGUARD="${VPN_ENABLE_WIREGUARD:-1}"
VPN_ENABLE_OPENVPN="${VPN_ENABLE_OPENVPN:-1}"
VPN_ENABLE_DNSMASQ="${VPN_ENABLE_DNSMASQ:-1}"
OPENVPN_MANAGEMENT_HOST="${OPENVPN_MANAGEMENT_HOST:-127.0.0.1}"
OPENVPN_MANAGEMENT_PORT="${OPENVPN_MANAGEMENT_PORT:-7505}"

ensure_openvpn_cert_auth_mode() {
  local conf_file="$1"
  local tmp_file
  if [[ ! -f "${conf_file}" ]]; then
    return 0
  fi
  tmp_file="$(mktemp)"
  awk '
    BEGIN { IGNORECASE = 1 }
    /^[[:space:]]*auth-user-pass-verify([[:space:]]|$)/ { next }
    /^[[:space:]]*username-as-common-name([[:space:]]|$)/ { next }
    /^[[:space:]]*verify-client-cert([[:space:]]|$)/ { next }
    /^[[:space:]]*client-cert-not-required([[:space:]]|$)/ { next }
    /^[[:space:]]*tls-verify([[:space:]]|$)/ { next }
    /^[[:space:]]*management([[:space:]]|$)/ { next }
    { print }
  ' "${conf_file}" > "${tmp_file}"
  mv "${tmp_file}" "${conf_file}"
  if ! grep -qiE '^[[:space:]]*script-security([[:space:]]|$)' "${conf_file}"; then
    echo 'script-security 3' >> "${conf_file}"
  fi
  echo 'verify-client-cert require' >> "${conf_file}"
  echo 'tls-verify "/usr/local/bin/python /opt/vpn-service/openvpn_auth.py"' >> "${conf_file}"
  echo "management ${OPENVPN_MANAGEMENT_HOST} ${OPENVPN_MANAGEMENT_PORT}" >> "${conf_file}"
}

echo "[vpn] booting vpn service container..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

if [[ "${VPN_ENABLE_WIREGUARD}" == "1" ]]; then
  if [[ -f "${WG_CONF_PATH}" ]]; then
    if ! wg show "${WG_INTERFACE}" >/dev/null 2>&1; then
      echo "[vpn] bringing up wireguard interface ${WG_INTERFACE}"
      wg-quick up "${WG_INTERFACE}"
    else
      echo "[vpn] wireguard ${WG_INTERFACE} already up"
    fi
  else
    echo "[vpn] warning: missing wireguard config ${WG_CONF_PATH}"
  fi
fi

mkdir -p "$(dirname "${WG_SERVER_PUBLIC_KEY_FILE}")"
if wg show "${WG_INTERFACE}" >/dev/null 2>&1; then
  wg show "${WG_INTERFACE}" public-key > "${WG_SERVER_PUBLIC_KEY_FILE}" || true
fi

if [[ "${VPN_ENABLE_DNSMASQ}" == "1" ]]; then
  if [[ -f "${DNSMASQ_CONF}" ]]; then
    echo "[vpn] starting dnsmasq"
    dnsmasq -k --conf-file="${DNSMASQ_CONF}" &
  else
    echo "[vpn] warning: missing dnsmasq config ${DNSMASQ_CONF}"
  fi
fi

if [[ "${VPN_ENABLE_OPENVPN}" == "1" ]]; then
  if [[ -f "${OPENVPN_SERVER_CONF}" ]]; then
    ensure_openvpn_cert_auth_mode "${OPENVPN_SERVER_CONF}"
    echo "[vpn] starting openvpn server"
    openvpn --config "${OPENVPN_SERVER_CONF}" --daemon ovpn-server --writepid /run/openvpn-server.pid
    echo "[vpn] starting openvpn session guard"
    python /opt/vpn-service/openvpn_session_guard.py &
  else
    echo "[vpn] warning: missing openvpn config ${OPENVPN_SERVER_CONF}"
  fi
fi

echo "[vpn] starting vpn api on 0.0.0.0:${VPN_API_PORT}"
exec gunicorn --workers 1 --bind "0.0.0.0:${VPN_API_PORT}" vpn_api:app
