import subprocess
from pathlib import Path


def run_command(args, input_text=None, check=True) -> str:
    completed = subprocess.run(
        args,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 and check:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"命令执行失败：{' '.join(args)}；{stderr}")
    return completed.stdout.strip()


def run_local_command_with_output(
    args: list[str],
    *,
    cwd: Path,
) -> tuple[int, str]:
    completed = subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    merged = "\n".join(
        part.strip() for part in [completed.stdout or "", completed.stderr or ""] if part.strip()
    ).strip()
    return completed.returncode, merged
