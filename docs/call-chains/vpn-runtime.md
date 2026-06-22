# VPN Runtime Call Chains

## Runtime Server Selection

1. User or admin requests a profile
2. `get_user_allowed_server_ids()`
3. `load_user_allowed_runtime_servers()`
4. `get_requested_allowed_server()`
5. Check selected server status and supported modes
6. Build a mode-specific config for that server

## OpenVPN Config

1. `client_profile_config()`
2. `build_openvpn_client_config()`
3. `get_openvpn_client_materials()`
4. `ensure_user_openvpn_client_identity()`
5. `get_openvpn_route_lines_for_profile()`
6. Return `.ovpn` text to client

## Shadowsocks And KCPTUN Config

1. `client_profile_config()`
2. `ensure_user_transport_ports()`
3. `prepare_user_for_transport()`
4. `derive_user_shadowsocks_password()`
5. One of:
   - `build_user_shadowsocks_clash_profile()`
   - `build_user_kcptun_clash_profile()`
6. Client starts `mihomo.exe` with generated YAML

## SSH Tunnel Config

1. `client_profile_config()`
2. `build_user_ssh_tunnel_config()`
3. Generate temporary SSH key pair
4. SSH to target server with admin credentials
5. `build_ssh_tunnel_install_script()`
6. Create temporary Linux user
7. Add public key to `authorized_keys`
8. Return private key and endpoint to client
9. Client keeps the private key in memory only
10. Client starts in-memory SSH SOCKS
11. Client starts TUN/tun2socks global runtime without writing tunnel config to disk
12. Cleanup is handled by `/client-api/ssh-tunnel/cleanup`

## Node API

1. Web server calls node API with token
2. `portal_services/vpn_api_client.py`
3. Node service runs `vpn/vpn_api.py`
4. Main endpoints:
   - `/healthz`
   - `/shadowsocks/active-peers`
   - `/kcptun/active-peers`
   - `/openvpn/status`
   - `/openvpn/control`
   - `/system/ipv6`
   - `/system/ipv6/control`

## Online Status

1. Admin opens user list or online users data endpoint
2. Web server queries runtime node API
3. Parse OpenVPN, Shadowsocks, and KCPTUN active peers
4. Match peer data back to user ports or certificates
5. User row shows online, source IP, mode, and traffic
