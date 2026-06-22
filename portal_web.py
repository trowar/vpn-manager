import ipaddress
import re
from datetime import datetime
from typing import Any

from flask import request, url_for

from portal_auth import row_get
from portal_config import ADMIN_UI_TZ


def safe_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw)


def normalize_domain_host(raw_domain: str | None) -> str:
    value = (raw_domain or "").strip()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/", 1)[0].strip()
    return value


def normalize_fqdn(raw_domain: str | None) -> str:
    return normalize_domain_host(raw_domain).strip().strip(".").lower()


def host_without_optional_port(raw_host: str | None) -> str:
    host = normalize_domain_host(raw_host)
    if not host:
        return ""
    if host.startswith("[") and "]" in host:
        end = host.find("]")
        if end > 1:
            return host[1:end]
    if host.count(":") == 1:
        host_part, port_part = host.rsplit(":", 1)
        if host_part and port_part.isdigit():
            return host_part
    return host


def display_label_from_host(raw_host: str | None, default: str = "Stream") -> str:
    host = host_without_optional_port(raw_host).strip().strip(".").lower()
    if not host:
        return default
    try:
        ipaddress.ip_address(host)
        compact = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", "", host)
        return compact or default
    except ValueError:
        pass
    labels = [part for part in host.split(".") if part]
    while len(labels) > 2 and labels[0] in {"www", "m", "wap", "web", "app"}:
        labels.pop(0)
    if len(labels) >= 3 and labels[-2] in {"com", "net", "org", "co", "gov", "edu"}:
        candidate = labels[-3]
    elif len(labels) >= 2:
        candidate = labels[-2]
    else:
        candidate = labels[0]
    compact = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", "", candidate)
    return compact or default


def is_non_public_host(raw_host: str | None) -> bool:
    host = host_without_optional_port(raw_host).strip().lower().rstrip(".")
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def absolute_url_for(endpoint: str, **values) -> str:
    try:
        return url_for(endpoint, _external=True, **values)
    except Exception:
        path = url_for(endpoint, **values)
        host = ""
        try:
            host = (request.host_url or "").strip().rstrip("/")
        except Exception:
            host = ""
        if host:
            return f"{host}{path}"
        return path


def build_masked_download_link(
    access_token: str,
    *,
    output_format: str = "yaml",
) -> str:
    token = (access_token or "").strip()
    if not token:
        return ""
    fmt = (output_format or "yaml").strip().lower()
    values: dict[str, str] = {"access_token": token}
    if fmt in {"json", "raw"}:
        values["f"] = fmt
    return absolute_url_for("download_via_token", **values)


def build_download_filename_for_user(user: Any, *, build_raw: bool) -> str:
    username = safe_name((row_get(user, "username", "") or "").strip() or "user")
    stamp = datetime.now(ADMIN_UI_TZ).strftime("%Y%m%d%H%M%S")
    ext = "json" if build_raw else "yaml"
    return f"{username}-{stamp}.{ext}"
