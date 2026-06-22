import ipaddress
import json
import os
import socket
from urllib import request as urllib_request

from portal_web import host_without_optional_port


def _resolve_public_ip(raw_host: str | None) -> str:
    host = host_without_optional_port(raw_host).strip().rstrip(".")
    if not host:
        return ""
    try:
        ip_obj = ipaddress.ip_address(host)
        return str(ip_obj) if ip_obj.is_global else ""
    except ValueError:
        pass
    try:
        ip_text = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip_text)
        return str(ip_obj) if ip_obj.is_global else ""
    except Exception:
        return ""


def detect_region_from_host(raw_host: str | None, timeout: float = 2.0) -> str:
    enabled = os.environ.get("PORTAL_ENABLE_EXTERNAL_IP_GEO", "0").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return ""
    ip_text = _resolve_public_ip(raw_host)
    if not ip_text:
        return ""
    url = (
        "http://ip-api.com/json/"
        + ip_text
        + "?lang=zh-CN&fields=status,country,regionName,city,query"
    )
    try:
        with urllib_request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception:
        return ""
    if str(payload.get("status", "")).lower() != "success":
        return ""
    parts = [
        str(payload.get("country") or "").strip(),
        str(payload.get("regionName") or "").strip(),
        str(payload.get("city") or "").strip(),
    ]
    seen: set[str] = set()
    clean_parts: list[str] = []
    for part in parts:
        if part and part not in seen:
            seen.add(part)
            clean_parts.append(part)
    return " / ".join(clean_parts)[:80]
