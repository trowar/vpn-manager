from __future__ import annotations

import json
from urllib import error as urllib_error
from urllib import request as urllib_request


def host_for_http_url(raw_host: str) -> str:
    host = (raw_host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def request_vpn_api(
    method: str,
    url: str,
    *,
    token: str = "",
    path: str = "",
    payload: dict | None = None,
    timeout_seconds: int = 8,
) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-VPN-Token"] = token

    body_bytes = None
    if payload is not None:
        body_bytes = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib_request.Request(url=url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except urllib_error.HTTPError as exc:
        detail = ""
        try:
            detail_raw = exc.read().decode("utf-8", errors="ignore")
            detail_obj = json.loads(detail_raw) if detail_raw else {}
            detail = str(detail_obj.get("error") or detail_obj.get("message") or detail_raw).strip()
        except Exception:
            detail = ""
        if not detail:
            detail = f"HTTP {exc.code}"
        raise RuntimeError(f"VPN API 请求失败：{method} {path}；{detail}")
    except urllib_error.URLError as exc:
        raise RuntimeError(f"VPN API 不可达：{exc.reason}")

    try:
        obj = json.loads(raw or "{}")
    except json.JSONDecodeError:
        raise RuntimeError(f"VPN API 返回非法 JSON：{method} {path}")
    if not isinstance(obj, dict):
        raise RuntimeError(f"VPN API 返回格式错误：{method} {path}")
    if obj.get("ok") is False:
        raise RuntimeError(str(obj.get("error") or f"VPN API 错误：{method} {path}"))
    return obj
