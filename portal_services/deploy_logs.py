from datetime import datetime, timezone

from portal_config import (
    ANSI_ESCAPE_RE,
    CONTROL_CHAR_RE,
    SYSTEM_UPGRADE_LOG_FILE,
)
from portal_services.servers import normalize_remote_host, normalize_server_port

SYSTEM_UPGRADE_LOG_TAIL_CHARS = 20000


def append_system_upgrade_log(message: str) -> None:
    SYSTEM_UPGRADE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with SYSTEM_UPGRADE_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message.rstrip()}\n")


def read_system_upgrade_log_text(limit_chars: int = SYSTEM_UPGRADE_LOG_TAIL_CHARS) -> str:
    if not SYSTEM_UPGRADE_LOG_FILE.exists():
        return ""
    try:
        raw = SYSTEM_UPGRADE_LOG_FILE.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    text = normalize_deploy_log_text(raw)
    if limit_chars > 0 and len(text) > limit_chars:
        return "...(log truncated)\n" + text[-limit_chars:]
    return text


def mask_secret(raw: str, visible: int = 2) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * max(0, len(value) - visible) + value[-visible:]


def summarize_text(raw: str, limit: int = 600) -> str:
    text = (raw or "").strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def normalize_deploy_log_text(raw: str) -> str:
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    text = ANSI_ESCAPE_RE.sub("", text)
    text = CONTROL_CHAR_RE.sub("", text)
    normalized_lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(normalized_lines).strip()


def build_structured_deploy_log(
    *,
    host: str,
    port: int,
    username: str,
    started_at: datetime,
    ended_at: datetime,
    script_text: str,
    script_executed: bool,
    exit_code: int | None = None,
    stdout_text: str = "",
    stderr_text: str = "",
    error_text: str = "",
) -> str:
    started = started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ended = ended_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    host_display = f"{normalize_remote_host(host)}:{normalize_server_port(port, 22)}"
    user_display = (username or "").strip() or "root"
    script_line_count = max(1, len((script_text or "").splitlines()))
    out_clean = normalize_deploy_log_text(stdout_text)
    err_clean = normalize_deploy_log_text(stderr_text)
    exc_clean = normalize_deploy_log_text(error_text)
    lines: list[str] = [
        "[deploy] 任务信息",
        f"开始时间: {started}",
        f"结束时间: {ended}",
        f"目标主机: {host_display}",
        f"SSH用户: {user_display}",
        "远程命令: bash -s (stdin install script)",
        f"脚本行数: {script_line_count}",
        "脚本步骤: 升级系统并安装依赖 -> 拉取 GitHub 仓库 -> 启动本地 systemd 服务 vpnmanager-server",
        f"脚本是否执行: {'是' if script_executed else '否'}",
        f"退出码: {exit_code if exit_code is not None else '-'}",
        "",
        "[deploy] stdout",
        out_clean if out_clean else "(empty)",
        "",
        "[deploy] stderr",
        err_clean if err_clean else "(empty)",
    ]
    if exc_clean:
        lines.extend(
            [
                "",
                "[deploy] 异常",
                exc_clean,
            ]
        )
    return "\n".join(lines).strip()


def clip_text(raw: str, limit: int = 200000) -> str:
    text = (raw or "").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]
