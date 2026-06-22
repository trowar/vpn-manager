#!/usr/bin/env bash
set -Eeuo pipefail

log_info() {
  echo "[deploy] $*"
}

REMOTE_HOST="${VPN_MANAGER_REMOTE_HOST:-172.16.188.135}"
REMOTE_PORT="${VPN_MANAGER_REMOTE_PORT:-22}"
REMOTE_USER="${VPN_MANAGER_REMOTE_USER:-root}"
REMOTE_DIR="${VPN_MANAGER_REMOTE_DIR:-/srv/vpn-platform-v1}"
REMOTE_SERVICE="${VPN_MANAGER_REMOTE_SERVICE:-vpn-platform-v1-web.service}"
NO_RESTART="${VPN_MANAGER_NO_RESTART:-${NO_RESTART:-0}}"
SSH_KEY="${VPN_MANAGER_REMOTE_KEY:-}"
DEFAULT_DEPLOY_KEY="${HOME}/.vpnmanager/deploy_rsa"
DRY_RUN="${VPN_MANAGER_DRY_RUN:-${DRY_RUN:-0}}"
SYNC_CLIENT_ARTIFACTS="${VPN_MANAGER_SYNC_CLIENT_ARTIFACTS:-0}"
SSH_OPTIONS=("-o" "StrictHostKeyChecking=accept-new")
AUTO_INSTALL_KEY="${AUTO_INSTALL_KEY:-0}"

if [[ -z "${SSH_KEY}" ]]; then
	if [[ -n "${VPN_MANAGER_REMOTE_KEY_PATH:-}" ]]; then
		SSH_KEY="${VPN_MANAGER_REMOTE_KEY_PATH}"
	else
		SSH_KEY="${DEFAULT_DEPLOY_KEY}"
	fi
fi

if [[ ! -f "${SSH_KEY}" ]]; then
	if command -v ssh-keygen >/dev/null 2>&1; then
		mkdir -p "$(dirname "${SSH_KEY}")"
		log_info "本地未检测到部署私钥，正在生成: ${SSH_KEY}"
		ssh-keygen -q -t ed25519 -N "" -f "${SSH_KEY}" -C "vpnmanager-deploy@${REMOTE_HOST}"
		chmod 600 "${SSH_KEY}"
		log_info "已生成部署密钥。公钥位于：${SSH_KEY}.pub"
		log_info "首次部署需要一次性将公钥加到目标机器 root 用户的 authorized_keys。"
		log_info "你可以直接执行：ssh-copy-id -i ${SSH_KEY}.pub -p ${REMOTE_PORT} ${REMOTE_USER}@${REMOTE_HOST}"
		log_info "或手工执行到服务器："
		log_info "  cat ${SSH_KEY}.pub | cat >> /root/.ssh/authorized_keys"
	else
		log_info "错误: 未找到 ssh-keygen，且未配置 VPN_MANAGER_REMOTE_KEY。"
		exit 1
	fi
fi

if [[ -n "${SSH_KEY}" ]]; then
	SSH_OPTIONS+=("-i" "${SSH_KEY}")
fi

if ! command -v rsync >/dev/null 2>&1; then
  log_info "错误: 未找到 rsync，请先安装 rsync 后再执行。"
  exit 1
fi

RSYNC_CMD=(rsync -avz --delete --omit-dir-times --no-perms --times)
RSYNC_CMD+=(--exclude=".git/")
RSYNC_CMD+=(--exclude=".gitignore")
RSYNC_CMD+=(--exclude=".env")
RSYNC_CMD+=(--exclude=".env.*")
RSYNC_CMD+=(--exclude=".venv/")
RSYNC_CMD+=(--exclude="data/")
RSYNC_CMD+=(--exclude="tmp/")
RSYNC_CMD+=(--exclude="__pycache__/")
RSYNC_CMD+=(--exclude="*.pyc")
RSYNC_CMD+=(--exclude="*.pyo")
RSYNC_CMD+=(--exclude="*.pyd")
RSYNC_CMD+=(--exclude="*.so")
RSYNC_CMD+=(--exclude="*.log")
RSYNC_CMD+=(--exclude="client-go/.tmp*")
RSYNC_CMD+=(--exclude="client-go/*.exe")
RSYNC_CMD+=(--exclude="client-go/*.zip")
RSYNC_CMD+=(--exclude="client/package/")
RSYNC_CMD+=(--exclude="client/dist/")
RSYNC_CMD+=(--exclude=".DS_Store")
RSYNC_CMD+=(--exclude="*.sqlite")
RSYNC_CMD+=(--exclude="*.db")

TARGET="${REMOTE_USER}@${REMOTE_HOST}"
SSH_CMD=(ssh "${SSH_OPTIONS[@]}" -p "${REMOTE_PORT}")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/3] 检查 SSH 可达性..."
if ! "${SSH_CMD[@]}" "${TARGET}" true; then
  log_info "密钥认证失败：将尝试自动写入部署公钥（仅在 AUTO_INSTALL_KEY=1 时执行）..."
  if [[ "${AUTO_INSTALL_KEY}" == "1" ]]; then
    if command -v sshpass >/dev/null 2>&1; then
      if [[ -z "${VPN_MANAGER_REMOTE_PASSWORD:-}" ]]; then
        read -s -p "请输入 ${TARGET} 的登录密码: " VPN_MANAGER_REMOTE_PASSWORD
        echo
      fi
      log_info "尝试使用 sshpass 写入公钥..."
      SSHPASS="${VPN_MANAGER_REMOTE_PASSWORD}" \
      sshpass -e ssh -p "${REMOTE_PORT}" \
        "${REMOTE_USER}@${REMOTE_HOST}" \
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" \
        < "${SSH_KEY}.pub"
      log_info "已尝试写入公钥，重新检查连接..."
      if ! "${SSH_CMD[@]}" "${TARGET}" true; then
        log_info "错误: 仍无法连接 SSH，请检查服务器权限与网络。"
        exit 1
      fi
    else
      log_info "未安装 sshpass，仍然需要你先手工把 ${SSH_KEY}.pub 写入服务器。"
      exit 1
    fi
  else
    log_info "错误: SSH 连接失败，请确认主机、端口和凭据。"
    log_info "可设置 AUTO_INSTALL_KEY=1 并配合 VPN_MANAGER_REMOTE_PASSWORD 自动安装密钥（或先执行 ssh-copy-id）。"
    exit 1
  fi
fi

echo "[2/3] 推送到服务器（无编译）..."
set -x
${RSYNC_CMD[@]} \
  -e "ssh ${SSH_OPTIONS[*]} -p ${REMOTE_PORT}" \
  "${PROJECT_ROOT}/" \
  "${TARGET}:${REMOTE_DIR}/"
set +x

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "[3/3] DRY_RUN=1，仅同步命令完成，不执行重启。"
  exit 0
fi

if [[ "${NO_RESTART}" == "1" ]]; then
  echo "[3/3] 已设置 NO_RESTART=1，不重启服务。"
  exit 0
fi

echo "[3/3] 重启服务（仅控制面服务）..."
if ! "${SSH_CMD[@]}" "${TARGET}" "systemctl restart ${REMOTE_SERVICE}"; then
  log_info "警告: 服务重启失败，请手动检查远端服务。"
  exit 1
fi

log_info "推送完成。"
