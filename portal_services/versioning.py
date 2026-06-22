import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any


def get_current_app_version(base_dir: Path) -> str:
    version_file = base_dir / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip() or "unknown"
    return "unknown"


def parse_version_parts(raw: str | None) -> list[int]:
    nums = [int(part) for part in re.findall(r"[0-9]+", (raw or "").strip())]
    return nums or [0]


def compare_version_strings(left: str | None, right: str | None) -> int:
    left_parts = parse_version_parts(left)
    right_parts = parse_version_parts(right)
    size = max(len(left_parts), len(right_parts))
    for idx in range(size):
        left_value = left_parts[idx] if idx < len(left_parts) else 0
        right_value = right_parts[idx] if idx < len(right_parts) else 0
        if left_value != right_value:
            return 1 if left_value > right_value else -1
    return 0


def read_remote_version(
    *,
    base_dir: Path,
    branch: str,
    cached_remote_version: str = "",
) -> str:
    try:
        subprocess.run(
            ["git", "fetch", "--quiet", "origin", branch],
            cwd=str(base_dir),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except Exception:
        pass

    try:
        completed = subprocess.run(
            ["git", "show", f"origin/{branch}:VERSION"],
            cwd=str(base_dir),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if completed.returncode == 0:
            return (completed.stdout or "").strip().splitlines()[0].strip()
    except Exception:
        pass
    return cached_remote_version


def load_version_nav_state(
    *,
    base_dir: Path,
    data_dir: Path,
    branch: str,
    force_check: bool = False,
    ttl_seconds: int = 600,
) -> dict[str, str | bool]:
    current_version = get_current_app_version(base_dir)
    cache_file = data_dir / "version-check-cache.json"
    now_ts = int(time.time())
    cached: dict[str, Any] = {}
    try:
        if cache_file.exists():
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception:
        cached = {}

    checked_at = int(cached.get("checked_at", 0) or 0)
    remote_version = str(cached.get("remote_version", "") or "").strip()
    if force_check or not remote_version or now_ts - checked_at > ttl_seconds:
        remote_version = read_remote_version(
            base_dir=base_dir,
            branch=branch,
            cached_remote_version=remote_version,
        )
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(
                json.dumps(
                    {"checked_at": now_ts, "remote_version": remote_version},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    has_update = bool(
        remote_version
        and current_version != "unknown"
        and compare_version_strings(remote_version, current_version) > 0
    )
    return {
        "current_version": current_version,
        "remote_version": remote_version,
        "has_update": has_update,
        "label": remote_version if has_update else current_version,
    }
