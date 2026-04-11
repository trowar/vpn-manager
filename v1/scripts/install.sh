#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/vpn-platform-v1"
REPO_URL="https://github.com/trowar/vpn-manager.git"
APP_PORT="${APP_PORT:-8080}"
SERVICE_NAME="vpn-platform-v1"

log() {
  echo "[install] $*"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_deps() {
  if has_cmd apt-get; then
    log "Detected apt environment"
    apt-get update -y
    apt-get install -y git curl wget python3 python3-pip python3-venv
    return
  fi
  if has_cmd yum; then
    log "Detected yum environment"
    yum makecache -y || true
    yum install -y git curl wget python3 python3-pip
    return
  fi
  echo "Unsupported package manager. Need apt-get or yum."
  exit 1
}

setup_app() {
  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
  fi
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR/v1"
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
  flask --app app init-db
}

write_service() {
  cat >/etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=VPN Platform V1 Web
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/v1
Environment=APP_SECRET_KEY=$(openssl rand -hex 24 || echo dev-secret)
ExecStart=${APP_DIR}/v1/.venv/bin/gunicorn --workers 2 --bind 0.0.0.0:${APP_PORT} wsgi:app
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
}

print_summary() {
  local ip
  ip="$(hostname -I | awk '{print $1}')"
  cat <<EOF

================ 安装完成 ================
登录地址: http://${ip}:${APP_PORT}
IP: ${ip}
端口: ${APP_PORT}
默认账号: admin
默认密码: admin
初始化提示: 首次登录后必须修改管理员密码
========================================

EOF
}

main() {
  install_deps
  setup_app
  write_service
  print_summary
}

main "$@"

