#!/usr/bin/env python3
"""
Company VPN client prototype.

The client imports a company-issued bundle, lets the user choose an OpenVPN or
Clash/Mihomo profile, writes the selected profile to a local app directory, and
starts the matching local core process.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib import request as urllib_request


APP_NAME = "CompanyVPN"
SCHEMA = "company-vpn-client.v1"
SUPPORTED_TYPES = {"openvpn", "clash", "mihomo", "ss-kcptun"}
FETCH_TIMEOUT_SECONDS = 15


def app_dir() -> Path:
    override = os.environ.get("COMPANY_VPN_HOME", "").strip()
    if override:
        path = Path(override).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        (path / "profiles").mkdir(parents=True, exist_ok=True)
        return path

    system = platform.system().lower()
    if system == "windows":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif system == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    path = root / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    (path / "profiles").mkdir(parents=True, exist_ok=True)
    return path


def state_path() -> Path:
    return app_dir() / "client-state.json"


def load_state() -> dict[str, Any]:
    path = state_path()
    if not path.exists():
        return {"device_id": str(uuid.uuid4()), "bundles": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("device_id", str(uuid.uuid4()))
    data.setdefault("bundles", [])
    return data


def save_state(state: dict[str, Any]) -> None:
    state_path().write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def safe_name(value: str) -> str:
    cleaned = []
    for char in (value or "").strip():
        if char.isalnum() or char in {"-", "_", "."}:
            cleaned.append(char)
        else:
            cleaned.append("_")
    return "".join(cleaned).strip("._") or "profile"


def detect_profile_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".ovpn":
        return "openvpn"
    if suffix in {".yaml", ".yml"}:
        return "clash"
    raise ValueError("无法识别配置文件类型，请使用 .ovpn、.yaml 或 .json 配置包")


def normalize_profile(raw: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    name = str(raw.get("name") or raw.get("label") or "").strip()
    profile_type = str(raw.get("type") or "").strip().lower()
    if profile_type == "ss":
        profile_type = "clash"
    if profile_type not in SUPPORTED_TYPES:
        raise ValueError(f"不支持的连接方式：{profile_type or '-'}")

    config_text = str(raw.get("config") or "")
    update_url = str(raw.get("update_url") or raw.get("url") or "").strip()
    update_token = str(raw.get("update_token") or raw.get("token") or "").strip()
    headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
    source_path = str(raw.get("path") or raw.get("file") or "").strip()
    if not config_text and source_path:
        config_file = Path(source_path)
        if not config_file.is_absolute():
            config_file = base_dir / config_file
        config_text = config_file.read_text(encoding="utf-8")
        if not name:
            name = config_file.stem
    if not config_text.strip() and not update_url:
        raise ValueError(f"配置 {name or profile_type} 没有内容，也没有更新地址")
    if not name:
        name = profile_type

    profile = {
        "id": safe_name(str(raw.get("id") or name)),
        "name": name,
        "type": profile_type,
        "config": config_text,
        "update_url": update_url,
        "update_token": update_token,
        "headers": {str(key): str(value) for key, value in headers.items()},
        "command": str(raw.get("command") or "").strip(),
        "args": raw.get("args") if isinstance(raw.get("args"), list) else [],
    }
    return profile


def import_bundle(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("配置包格式错误")
        profiles_raw = data.get("profiles")
        if not isinstance(profiles_raw, list) or not profiles_raw:
            raise ValueError("配置包里没有 profiles")
        profiles = [normalize_profile(item, path.parent) for item in profiles_raw]
        bundle_name = str(data.get("name") or data.get("account") or path.stem).strip()
        return {
            "schema": data.get("schema") or SCHEMA,
            "name": bundle_name or path.stem,
            "account": str(data.get("account") or "").strip(),
            "imported_at": int(time.time()),
            "profiles": profiles,
        }

    profile_type = detect_profile_type(path)
    config_text = path.read_text(encoding="utf-8")
    return {
        "schema": SCHEMA,
        "name": path.stem,
        "account": "",
        "imported_at": int(time.time()),
        "profiles": [
            {
                "id": safe_name(path.stem),
                "name": path.stem,
                "type": profile_type,
                "config": config_text,
                "update_url": "",
                "update_token": "",
                "headers": {},
                "command": "",
                "args": [],
            }
        ],
    }


def store_bundle(bundle: dict[str, Any]) -> None:
    state = load_state()
    bundle_id = safe_name(f"{bundle.get('account') or bundle.get('name')}-{bundle.get('imported_at')}")
    bundle["id"] = bundle_id
    bundles = [item for item in state.get("bundles", []) if item.get("id") != bundle_id]
    bundles.append(bundle)
    state["bundles"] = bundles
    save_state(state)


def iter_profiles(state: dict[str, Any]):
    for bundle in state.get("bundles", []):
        for profile in bundle.get("profiles", []):
            yield bundle, profile


def find_profile(profile_name: str | None):
    state = load_state()
    profiles = list(iter_profiles(state))
    if not profiles:
        raise RuntimeError("还没有导入配置")
    if not profile_name:
        return profiles[0]
    needle = profile_name.strip().lower()
    for bundle, profile in profiles:
        candidates = {
            str(profile.get("id") or "").lower(),
            str(profile.get("name") or "").lower(),
            f"{bundle.get('name', '')}/{profile.get('name', '')}".lower(),
        }
        if needle in candidates:
            return bundle, profile
    raise RuntimeError(f"没有找到配置：{profile_name}")


def fetch_remote_config(profile: dict[str, Any]) -> str:
    update_url = str(profile.get("update_url") or "").strip()
    if not update_url:
        return str(profile.get("config") or "")

    headers = {
        "User-Agent": f"{APP_NAME}/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    headers.update(profile.get("headers") or {})
    update_token = str(profile.get("update_token") or "").strip()
    if update_token and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {update_token}"

    req = urllib_request.Request(update_url, headers=headers, method="GET")
    with urllib_request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as response:
        body = response.read()
        content_type = (response.headers.get("Content-Type") or "").lower()

    text = body.decode("utf-8", errors="replace")
    if "application/json" in content_type or text.lstrip().startswith("{"):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            if payload.get("ok") is False:
                raise RuntimeError(str(payload.get("error") or "服务器拒绝更新配置"))
            config = payload.get("config") or payload.get("profile") or payload.get("content")
            if isinstance(config, str) and config.strip():
                return config
    if text.strip():
        return text
    raise RuntimeError("服务器返回了空配置")


def write_runtime_config(bundle: dict[str, Any], profile: dict[str, Any]) -> Path:
    ext = ".ovpn" if profile["type"] == "openvpn" else ".yaml"
    filename = safe_name(f"{bundle.get('id')}-{profile.get('id')}") + ext
    target = app_dir() / "profiles" / filename
    config_text = fetch_remote_config(profile)
    target.write_text(config_text, encoding="utf-8")
    return target


def resolve_command(profile: dict[str, Any]) -> str:
    explicit = str(profile.get("command") or "").strip()
    if explicit:
        return explicit
    profile_type = profile.get("type")
    if profile_type == "openvpn":
        command = shutil.which("openvpn")
        if command:
            return command
        return "openvpn"
    for candidate in ("mihomo", "clash"):
        command = shutil.which(candidate)
        if command:
            return command
    return "mihomo"


def build_command(profile: dict[str, Any], config_file: Path) -> list[str]:
    command = resolve_command(profile)
    profile_type = profile.get("type")
    if profile_type == "openvpn":
        args = [command, "--config", str(config_file)]
    else:
        args = [command, "-f", str(config_file)]
    extra_args = [str(item) for item in profile.get("args", []) if str(item).strip()]
    return args + extra_args


def run_profile(profile_name: str | None = None) -> int:
    bundle, profile = find_profile(profile_name)
    config_file = write_runtime_config(bundle, profile)
    command = build_command(profile, config_file)
    print(f"账号：{bundle.get('account') or '-'}")
    print(f"连接方式：{profile.get('name')} ({profile.get('type')})")
    if profile.get("update_url"):
        print("配置来源：服务器实时更新")
    print(f"配置文件：{config_file}")
    print(f"启动命令：{' '.join(command)}")

    process = subprocess.Popen(command)
    try:
        return process.wait()
    except KeyboardInterrupt:
        print("\n正在断开...")
        process.send_signal(signal.SIGTERM)
        try:
            return process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait()


def print_profiles() -> None:
    state = load_state()
    rows = list(iter_profiles(state))
    if not rows:
        print("还没有导入配置")
        return
    for bundle, profile in rows:
        account = bundle.get("account") or "-"
        print(
            f"{bundle.get('name')}/{profile.get('name')}"
            f"  type={profile.get('type')}  account={account}"
        )


def launch_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as exc:
        print(f"当前系统无法启动图形界面：{exc}", file=sys.stderr)
        return 2

    root = tk.Tk()
    root.title("Company VPN")
    root.geometry("720x440")
    root.minsize(640, 360)

    selected_profile = tk.StringVar()
    status_text = tk.StringVar(value="未连接")
    process_holder: dict[str, subprocess.Popen | None] = {"process": None}

    def profile_options() -> list[tuple[str, str]]:
        state = load_state()
        options: list[tuple[str, str]] = []
        for bundle, profile in iter_profiles(state):
            label = f"{bundle.get('name')}/{profile.get('name')} [{profile.get('type')}]"
            key = f"{bundle.get('name')}/{profile.get('name')}"
            options.append((label, key))
        return options

    def refresh_profiles() -> None:
        options = profile_options()
        combo["values"] = [item[0] for item in options]
        combo.profile_keys = {item[0]: item[1] for item in options}  # type: ignore[attr-defined]
        if options and not selected_profile.get():
            selected_profile.set(options[0][0])

    def log(message: str) -> None:
        log_box.configure(state="normal")
        log_box.insert("end", message.rstrip() + "\n")
        log_box.see("end")
        log_box.configure(state="disabled")

    def import_clicked() -> None:
        path_raw = filedialog.askopenfilename(
            title="选择配置包",
            filetypes=[
                ("VPN config", "*.json *.ovpn *.yaml *.yml"),
                ("All files", "*.*"),
            ],
        )
        if not path_raw:
            return
        try:
            bundle = import_bundle(Path(path_raw))
            store_bundle(bundle)
            refresh_profiles()
            log(f"已导入：{bundle.get('name')}")
        except Exception as exc:
            messagebox.showerror("导入失败", str(exc))

    def selected_key() -> str | None:
        label = selected_profile.get()
        return getattr(combo, "profile_keys", {}).get(label)

    def connect_clicked() -> None:
        if process_holder["process"] and process_holder["process"].poll() is None:
            messagebox.showinfo("提示", "当前已有连接在运行")
            return
        try:
            bundle, profile = find_profile(selected_key())
            config_file = write_runtime_config(bundle, profile)
            command = build_command(profile, config_file)
            process_holder["process"] = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            status_text.set(f"已启动：{profile.get('name')}")
            log(f"启动命令：{' '.join(command)}")

            def pump_output() -> None:
                proc = process_holder["process"]
                if not proc or not proc.stdout:
                    return
                line = proc.stdout.readline()
                if line:
                    log(line)
                    root.after(50, pump_output)
                    return
                code = proc.poll()
                if code is None:
                    root.after(200, pump_output)
                    return
                status_text.set(f"已断开（退出码 {code}）")

            root.after(50, pump_output)
        except Exception as exc:
            messagebox.showerror("连接失败", str(exc))

    def disconnect_clicked() -> None:
        proc = process_holder["process"]
        if not proc or proc.poll() is not None:
            status_text.set("未连接")
            return
        proc.terminate()
        status_text.set("正在断开...")
        log("已发送断开信号")

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)

    top = ttk.Frame(frame)
    top.pack(fill="x")
    ttk.Button(top, text="导入配置", command=import_clicked).pack(side="left")
    ttk.Label(top, textvariable=status_text).pack(side="right")

    ttk.Label(frame, text="连接方式").pack(anchor="w", pady=(18, 6))
    combo = ttk.Combobox(frame, textvariable=selected_profile, state="readonly")
    combo.pack(fill="x")
    combo.profile_keys = {}  # type: ignore[attr-defined]

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=12)
    ttk.Button(buttons, text="连接", command=connect_clicked).pack(side="left")
    ttk.Button(buttons, text="断开", command=disconnect_clicked).pack(side="left", padx=8)

    log_box = tk.Text(frame, height=12, state="disabled")
    log_box.pack(fill="both", expand=True)

    refresh_profiles()
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Company VPN client")
    parser.add_argument("--import", dest="import_path", help="导入配置包或单个配置文件")
    parser.add_argument("--list", action="store_true", help="列出已导入配置")
    parser.add_argument("--connect", metavar="PROFILE", nargs="?", const="", help="连接指定配置")
    parser.add_argument("--gui", action="store_true", help="启动图形界面")
    args = parser.parse_args(argv)

    if args.import_path:
        bundle = import_bundle(Path(args.import_path))
        store_bundle(bundle)
        print(f"已导入：{bundle.get('name')}")
    if args.list:
        print_profiles()
    if args.connect is not None:
        return run_profile(args.connect or None)
    if args.gui or not any((args.import_path, args.list, args.connect is not None)):
        return launch_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
