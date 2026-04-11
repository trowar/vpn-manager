#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vpn-platform-v1"
REPO_URL="https://github.com/trowar/vpn-manager.git"
APP_PORT="${APP_PORT:-8080}"
SERVICE_NAME="vpn-platform-v1"

export DEBIAN_FRONTEND=noninteractive

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

on_error() {
  local exit_code=$?
  err "安装过程中发生错误，退出码: ${exit_code}"
  err "正在输出诊断信息..."

  if has_cmd systemctl; then
    echo
    echo "===== systemctl status cloud-init ====="
    systemctl status cloud-init --no-pager -l || true
    echo
    echo "===== systemctl status ${SERVICE_NAME} ====="
    systemctl status "${SERVICE_NAME}" --no-pager -l || true
  fi

  if [ -f /var/log/cloud-init.log ]; then
    echo
    echo "===== /var/log/cloud-init.log (last 80 lines) ====="
    tail -n 80 /var/log/cloud-init.log || true
  fi

  if [ -f /var/log/cloud-init-output.log ]; then
    echo
    echo "===== /var/log/cloud-init-output.log (last 80 lines) ====="
    tail -n 80 /var/log/cloud-init-output.log || true
  fi

  echo
  err "可手动执行以下命令继续排查："
  err "  dpkg --configure -a"
  err "  apt --fix-broken install"
  err "  systemctl status cloud-init --no-pager -l"
  exit "$exit_code"
}

trap on_error ERR

retry() {
  local attempts="$1"
  shift
  local n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      return 1
    fi
    warn "命令失败，第 ${n}/${attempts} 次，3 秒后重试: $*"
    sleep 3
    n=$((n + 1))
  done
}

wait_for_apt_lock() {
  if ! has_cmd fuser; then
    return 0
  fi

  local waited=0
  local max_wait=120

  while fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
     || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if [ "$waited" -ge "$max_wait" ]; then
      err "apt/dpkg 锁等待超时，请稍后重试"
      return 1
    fi
    log "检测到 apt/dpkg 锁，占用中，等待中... (${waited}s/${max_wait}s)"
    sleep 3
    waited=$((waited + 3))
  done
}

repair_apt_state() {
  log "尝试修复 dpkg/apt 状态"

  wait_for_apt_lock

  # 修复中断配置
  dpkg --configure -a || true

  # 修复损坏依赖
  apt-get -f install -y -o Dpkg::Options::="--force-confnew" || true

  # 再跑一次配置，尽量收尾
  dpkg --configure -a || true
}

disable_problematic_cloud_init_if_requested() {
  # 可通过环境变量跳过/移除 cloud-init
  # 用法:
  #   REMOVE_CLOUD_INIT=1 bash install.sh
  # 仅在你确认此机器不依赖 cloud-init 时使用
  if [ "${REMOVE_CLOUD_INIT:-0}" = "1" ]; then
    warn "检测到 REMOVE_CLOUD_INIT=1，准备移除 cloud-init"
    apt-get purge -y cloud-init || true
    rm -rf /etc/cloud /var/lib/cloud || true
    dpkg --configure -a || true
    apt-get -f install -y || true
  fi
}

install_deps_apt() {
  log "Detected apt environment"

  wait_for_apt_lock
  repair_apt_state
  disable_problematic_cloud_init_if_requested

  retry 3 apt-get update -y

  retry 3 apt-get install -y \
    --no-install-recommends \
    git curl wget python3 python3-pip python3-venv openssl ca-certificates

  # 再次收尾，避免遗留半配置状态
  dpkg --configure -a || true
  apt-get -f install -y || true
}

install_deps_yum() {
  log "Detected yum environment"
  retry 3 yum makecache -y || true
  retry 3 yum install -y git curl wget python3 python3-pip openssl ca-certificates
}

install_deps() {
  if has_cmd apt-get; then
    install_deps_apt
    return
  fi

  if has_cmd yum; then
    install_deps_yum
    return
  fi

  err "Unsupported package manager. Need apt-get or yum."
  exit 1
}

setup_app() {
  log "准备部署应用到 ${APP_DIR}"

  if [ -d "$APP_DIR" ]; then
    log "发现旧目录，先删除: ${APP_DIR}"
    rm -rf "$APP_DIR"
  fi

  retry 3 git clone --depth 1 "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"

  log "创建 Python 虚拟环境"
  python3 -m venv .venv

  # shellcheck disable=SC1091
  source .venv/bin/activate

  log "升级 pip"
  retry 3 pip install --upgrade pip setuptools wheel

  log "安装 Python 依赖"
  retry 3 pip install -r requirements.txt
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

write_service() {
  local portal_secret
  portal_secret="$(generate_secret)"

  log "写入 systemd 服务: ${SERVICE_NAME}"

  cat >/etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=VPN Platform V1
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment=APP_PORT=${APP_PORT}
Environment=APP_SECRET=${portal_secret}
ExecStart=${APP_DIR}/.venv/bin/gunicorn -b 0.0.0.0:${APP_PORT} app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

print_access_info() {
  local host_ip=""

  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"

  echo
  echo "=========================================="
  echo "安装完成"
  echo "服务名: ${SERVICE_NAME}"
  echo "目录: ${APP_DIR}"
  echo "端口: ${APP_PORT}"
  if [ -n "$host_ip" ]; then
    echo "访问地址: http://${host_ip}:${APP_PORT}"
  else
    echo "访问地址: http://<你的服务器IP>:${APP_PORT}"
  fi
  echo "查看服务状态: systemctl status ${SERVICE_NAME} --no-pager -l"
  echo "查看日志: journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  echo "=========================================="
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请使用 root 运行此脚本"
    exit 1
  fi

  install_deps
  setup_app
  write_service
  print_access_info
}

main "$@"
