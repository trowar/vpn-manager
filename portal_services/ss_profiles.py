import base64
import json
import textwrap
from typing import Any, Callable
from urllib import parse as urllib_parse

from portal_auth import row_get
from portal_config import (
    KCPTUN_CRYPT,
    KCPTUN_DATASHARD,
    KCPTUN_ENABLED,
    KCPTUN_KEY,
    KCPTUN_MODE,
    KCPTUN_MTU,
    KCPTUN_NOCOMP,
    KCPTUN_PARITYSHARD,
    KCPTUN_SERVER_PORT,
    OPENVPN_ENDPOINT_HOST,
    SHADOWSOCKS_ENDPOINT_HOST,
    SHADOWSOCKS_METHOD,
    SHADOWSOCKS_SERVER_PORT,
)
from portal_services.servers import (
    normalize_server_port,
    server_supports_ss_kcptun,
)
from portal_web import host_without_optional_port, safe_name


DatabaseConnection = Any
DatabaseRow = dict[str, Any]


def resolve_shadowsocks_endpoint_host(
    *,
    user: DatabaseRow | None = None,
    server_row: DatabaseRow | None = None,
    get_runtime_server_for_account: Callable[[DatabaseRow | None], DatabaseRow | None],
    request_host: str = "",
) -> str:
    def pick_host(candidate: str | None) -> str:
        host = host_without_optional_port(candidate)
        return host.strip() if host else ""

    runtime_server = server_row or get_runtime_server_for_account(user)
    if runtime_server is not None:
        host = pick_host(row_get(runtime_server, "domain", ""))
        if host:
            return host
        host = pick_host(row_get(runtime_server, "host", ""))
        if host:
            return host

    for candidate in (
        SHADOWSOCKS_ENDPOINT_HOST,
        OPENVPN_ENDPOINT_HOST,
        OPENVPN_ENDPOINT_HOST,
        request_host,
    ):
        host = pick_host(candidate)
        if host:
            return host
    return ""


def prepare_user_for_transport(
    user: DatabaseRow,
    *,
    get_db: Callable[[], DatabaseConnection],
    ensure_user_transport_ports: Callable[[DatabaseConnection, DatabaseRow], DatabaseRow],
) -> DatabaseRow:
    role = (row_get(user, "role", "") or "").strip().lower()
    if role not in {"user", "admin"}:
        return user
    user_id = row_get(user, "id")
    if user_id is None or not str(user_id).strip():
        return user
    try:
        db = get_db()
    except Exception:
        return user
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
    if refreshed is None:
        return user
    return ensure_user_transport_ports(db, refreshed)


def derive_user_shadowsocks_password(
    user: DatabaseRow,
    *,
    get_user_shadowsocks_server_port: Callable[[DatabaseRow], int],
    derive_shadowsocks_password_for_port: Callable[[int], str],
) -> str:
    return derive_shadowsocks_password_for_port(get_user_shadowsocks_server_port(user))


def build_user_shadowsocks_config(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    prepare_user: Callable[[DatabaseRow], DatabaseRow],
    resolve_host: Callable[..., str],
    get_user_shadowsocks_server_port: Callable[[DatabaseRow], int],
    derive_user_password: Callable[[DatabaseRow], str],
) -> str:
    user = prepare_user(user)
    host = resolve_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    server_port = get_user_shadowsocks_server_port(user)
    config_obj = {
        "server": host,
        "server_port": server_port,
        "password": derive_user_password(user),
        "method": SHADOWSOCKS_METHOD,
        "mode": "tcp_and_udp",
        "timeout": 300,
    }
    return json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n"


def build_user_kcptun_config(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    prepare_user: Callable[[DatabaseRow], DatabaseRow],
    resolve_host: Callable[..., str],
) -> str:
    user = prepare_user(user)
    host = resolve_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 kcptun 节点地址。")
    config_obj = {
        "remoteaddr": f"{host}:{KCPTUN_SERVER_PORT}",
        "localaddr": "127.0.0.1:12948",
        "key": KCPTUN_KEY,
        "crypt": KCPTUN_CRYPT,
        "mode": KCPTUN_MODE,
        "conn": 1,
        "autoexpire": 0,
        "mtu": KCPTUN_MTU,
        "sndwnd": 256,
        "rcvwnd": 512,
        "datashard": KCPTUN_DATASHARD,
        "parityshard": KCPTUN_PARITYSHARD,
        "dscp": 0,
        "nocomp": bool(KCPTUN_NOCOMP),
        "acknodelay": True,
        "nodelay": 1,
        "interval": 20,
        "resend": 2,
        "nc": 1,
        "sockbuf": 4194304,
        "smuxver": 1,
        "smuxbuf": 4194304,
        "streambuf": 2097152,
        "keepalive": 10,
    }
    return json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n"


def _yaml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_user_kcptun_clash_profile(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    prepare_user: Callable[[DatabaseRow], DatabaseRow],
    get_runtime_server_for_account: Callable[[DatabaseRow | None], DatabaseRow | None],
    resolve_host: Callable[..., str],
    get_server_kcptun_port: Callable[[DatabaseRow | None], int],
    derive_shadowsocks_password_for_port: Callable[[int], str],
) -> str:
    user = prepare_user(user)
    runtime_server = server_row or get_runtime_server_for_account(user)
    host = resolve_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 kcptun 节点地址。")
    username = (row_get(user, "username", "") or "").strip() or "vpn-user"
    proxy_name = f"kcptun-{safe_name(username)}"
    kcptun_ss_password = derive_shadowsocks_password_for_port(SHADOWSOCKS_SERVER_PORT)
    kcptun_port = get_server_kcptun_port(runtime_server)

    return textwrap.dedent(
        f"""\
        mixed-port: 7890
        mode: rule
        proxies:
          - name: {_yaml_str(proxy_name)}
            type: ss
            server: {_yaml_str(host)}
            port: {kcptun_port}
            cipher: {_yaml_str(SHADOWSOCKS_METHOD)}
            password: {_yaml_str(kcptun_ss_password)}
            udp: true
            plugin: "kcptun"
            plugin-opts:
              key: {_yaml_str(KCPTUN_KEY)}
              crypt: {_yaml_str(KCPTUN_CRYPT)}
              mode: {_yaml_str(KCPTUN_MODE)}
              mtu: {KCPTUN_MTU}
              datashard: {KCPTUN_DATASHARD}
              parityshard: {KCPTUN_PARITYSHARD}
              nocomp: {str(bool(KCPTUN_NOCOMP)).lower()}
        proxy-groups:
          - name: "PROXY"
            type: select
            proxies:
              - {_yaml_str(proxy_name)}
              - "DIRECT"
          - name: "GLOBAL"
            type: select
            proxies:
              - {_yaml_str(proxy_name)}
              - "DIRECT"
        rules:
          - MATCH,PROXY
        """
    )


def build_user_shadowsocks_clash_profile(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    prepare_user: Callable[[DatabaseRow], DatabaseRow],
    get_runtime_server_for_account: Callable[[DatabaseRow | None], DatabaseRow | None],
    resolve_host: Callable[..., str],
    get_user_shadowsocks_server_port: Callable[[DatabaseRow], int],
    derive_user_password: Callable[[DatabaseRow], str],
    derive_shadowsocks_password_for_port: Callable[[int], str],
    get_server_kcptun_port: Callable[[DatabaseRow | None], int],
) -> str:
    user = prepare_user(user)
    runtime_server = server_row or get_runtime_server_for_account(user)
    host = resolve_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    username = (row_get(user, "username", "") or "").strip() or "vpn-user"
    ss_proxy_name = f"ss-{safe_name(username)}"
    kcptun_proxy_name = f"kcptun-{safe_name(username)}"
    ss_port = get_user_shadowsocks_server_port(user)
    ss_password = derive_user_password(user)
    kcptun_ss_password = derive_shadowsocks_password_for_port(SHADOWSOCKS_SERVER_PORT)
    use_kcptun = server_supports_ss_kcptun(runtime_server) or (
        runtime_server is None and KCPTUN_ENABLED
    )
    kcptun_port = get_server_kcptun_port(runtime_server)

    if use_kcptun:
        return textwrap.dedent(
            f"""\
            mixed-port: 7890
            mode: rule
            proxies:
              - name: {_yaml_str(kcptun_proxy_name)}
                type: ss
                server: {_yaml_str(host)}
                port: {kcptun_port}
                cipher: {_yaml_str(SHADOWSOCKS_METHOD)}
                password: {_yaml_str(kcptun_ss_password)}
                udp: true
                plugin: "kcptun"
                plugin-opts:
                  key: {_yaml_str(KCPTUN_KEY)}
                  crypt: {_yaml_str(KCPTUN_CRYPT)}
                  mode: {_yaml_str(KCPTUN_MODE)}
                  mtu: {KCPTUN_MTU}
                  datashard: {KCPTUN_DATASHARD}
                  parityshard: {KCPTUN_PARITYSHARD}
                  nocomp: {str(bool(KCPTUN_NOCOMP)).lower()}
            proxy-groups:
              - name: "PROXY"
                type: select
                proxies:
                  - {_yaml_str(kcptun_proxy_name)}
                  - "DIRECT"
              - name: "GLOBAL"
                type: select
                proxies:
                  - {_yaml_str(kcptun_proxy_name)}
                  - "DIRECT"
            rules:
              - MATCH,PROXY
            """
        )

    return textwrap.dedent(
        f"""\
        mixed-port: 7890
        mode: rule
        proxies:
          - name: {_yaml_str(ss_proxy_name)}
            type: ss
            server: {_yaml_str(host)}
            port: {ss_port}
            cipher: {_yaml_str(SHADOWSOCKS_METHOD)}
            password: {_yaml_str(ss_password)}
            udp: true
        proxy-groups:
          - name: "PROXY"
            type: select
            proxies:
              - {_yaml_str(ss_proxy_name)}
              - "DIRECT"
          - name: "GLOBAL"
            type: select
            proxies:
              - {_yaml_str(ss_proxy_name)}
              - "DIRECT"
        rules:
          - MATCH,PROXY
        """
    )


def build_user_shadowsocks_uri(
    user: DatabaseRow,
    *,
    server_row: DatabaseRow | None = None,
    prepare_user: Callable[[DatabaseRow], DatabaseRow],
    resolve_host: Callable[..., str],
    get_user_shadowsocks_server_port: Callable[[DatabaseRow], int],
    derive_user_password: Callable[[DatabaseRow], str],
) -> str:
    user = prepare_user(user)
    host = resolve_host(user=user, server_row=server_row)
    if not host:
        raise RuntimeError("未找到可用的 Shadowsocks 节点地址。")
    user_label = (row_get(user, "username", "") or row_get(user, "email", "") or "vpn-user").strip()
    ss_port = get_user_shadowsocks_server_port(user)
    raw_auth = f"{SHADOWSOCKS_METHOD}:{derive_user_password(user)}"
    auth = base64.urlsafe_b64encode(raw_auth.encode("utf-8")).decode("ascii").rstrip("=")
    return (
        f"ss://{auth}@{host}:{ss_port}"
        f"#{urllib_parse.quote(user_label, safe='')}"
    )
