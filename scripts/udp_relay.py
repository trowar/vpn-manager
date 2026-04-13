#!/usr/bin/env python3
import asyncio
import logging
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path


DB_PATH = Path(os.environ.get("PORTAL_DB_PATH", "/app/data/portal.db"))
RELAY_BIND_HOST = os.environ.get("VPN_RELAY_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"
REFRESH_SECONDS = max(1, int(os.environ.get("VPN_RELAY_REFRESH_SECONDS", "3") or "3"))
ENABLE_RELAY = (os.environ.get("PORTAL_ENABLE_UDP_RELAY", "0") or "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
SETTING_WIREGUARD_OPEN = "wireguard_open"
SETTING_OPENVPN_OPEN = "openvpn_open"


@dataclass
class RelayMapping:
    protocol: str
    port: int
    target_host: str
    target_port: int


class UserUdpRelay(asyncio.DatagramProtocol):
    def __init__(self, mapping: RelayMapping):
        self.mapping = mapping
        self.transport: asyncio.DatagramTransport | None = None
        self.active_client: tuple[str, int] | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if self.transport is None:
            return
        target = (self.mapping.target_host, self.mapping.target_port)
        if addr == target:
            if self.active_client is not None:
                self.transport.sendto(data, self.active_client)
            return
        self.active_client = addr
        self.transport.sendto(data, target)

    def update_mapping(self, mapping: RelayMapping):
        self.mapping = mapping


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def parse_bool(raw: str | None, default: bool) -> bool:
    value = (raw or "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def fetch_desired_mappings() -> dict[tuple[str, int], RelayMapping]:
    if not ENABLE_RELAY or not DB_PATH.exists():
        return {}
    conn = get_db()
    try:
        settings_rows = conn.execute(
            """
            SELECT setting_key, setting_value
            FROM app_settings
            WHERE setting_key IN (?, ?)
            """,
            (SETTING_WIREGUARD_OPEN, SETTING_OPENVPN_OPEN),
        ).fetchall()
        settings = {row["setting_key"]: (row["setting_value"] or "").strip() for row in settings_rows}
        wireguard_open = parse_bool(settings.get(SETTING_WIREGUARD_OPEN), False)
        openvpn_open = parse_bool(settings.get(SETTING_OPENVPN_OPEN), True)

        rows = conn.execute(
            """
            SELECT
                u.id,
                u.wg_enabled,
                u.wg_ingress_port,
                u.openvpn_ingress_port,
                s.host,
                s.wg_port,
                s.openvpn_port,
                s.status
            FROM users u
            JOIN vpn_servers s ON s.id = u.assigned_server_id
            WHERE u.role = 'user'
              AND u.wg_enabled = 1
              AND s.status = 'online'
            """
        ).fetchall()
    finally:
        conn.close()

    mappings: dict[tuple[str, int], RelayMapping] = {}
    for row in rows:
        host = (row["host"] or "").strip()
        if not host:
            continue
        if wireguard_open and row["wg_ingress_port"] is not None:
            port = int(row["wg_ingress_port"])
            mappings[("wireguard", port)] = RelayMapping(
                protocol="wireguard",
                port=port,
                target_host=host,
                target_port=int(row["wg_port"] or 51820),
            )
        if openvpn_open and row["openvpn_ingress_port"] is not None:
            port = int(row["openvpn_ingress_port"])
            mappings[("openvpn", port)] = RelayMapping(
                protocol="openvpn",
                port=port,
                target_host=host,
                target_port=int(row["openvpn_port"] or 1194),
            )
    return mappings


async def run_relay():
    loop = asyncio.get_running_loop()
    listeners: dict[tuple[str, int], tuple[asyncio.DatagramTransport, UserUdpRelay]] = {}

    while True:
        desired = fetch_desired_mappings()
        for key in list(listeners.keys()):
            if key not in desired:
                transport, _ = listeners.pop(key)
                transport.close()

        for key, mapping in desired.items():
            if key in listeners:
                listeners[key][1].update_mapping(mapping)
                continue
            protocol = UserUdpRelay(mapping)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                local_addr=(RELAY_BIND_HOST, mapping.port),
            )
            listeners[key] = (transport, protocol)

        await asyncio.sleep(REFRESH_SECONDS)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[udp-relay] %(message)s")
    if not ENABLE_RELAY:
        logging.info("relay disabled")
        return 0
    logging.info("starting relay using db=%s", DB_PATH)
    asyncio.run(run_relay())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
