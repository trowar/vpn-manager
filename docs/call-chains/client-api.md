# Client API Call Chains

## Time Sync

1. Client starts
2. `client-go/main.go`
3. `fetchServerTime()`
4. `GET /client-api/time`
5. `client_api_time()`
6. Server returns Unix timestamp
7. Client calculates clock offset before building the login slug

## Login Slug

1. Client calls `loginSlugForTime(serverTime)`
2. Slug uses the global embedded client key and a one-minute time window
3. Client posts to `/client-api/session/<login_slug>`
4. Server checks `is_valid_client_login_slug()`
5. Wrong path or expired window returns 404 or 403

## Password Login

1. Client login button
2. `loginClicked()`
3. `loginWithPassword(webURL, username, password)`
4. `POST /client-api/session/<login_slug>`
5. `client_password_login()`
6. `authenticate_user()`
7. `ensure_user_client_config_token()`
8. `build_client_bootstrap_payload()`
9. `encrypt_login_api_payload()`
10. Client decrypts and stores bootstrap data

## Bootstrap Refresh

1. Client has username and client token
2. `fetchBootstrap()`
3. `GET /client-api/bootstrap/<username>`
4. `client_bootstrap_config()`
5. `resolve_client_config_user()`
6. `build_client_bootstrap_payload()`
7. `encrypt_client_api_payload()`
8. Client refreshes allowed servers and modes

## Profile Fetch

1. Client chooses server and mode
2. `fetchProfileConfig()`
3. `GET /client-api/profiles/<username>/<profile_type>`
4. `client_profile_config()`
5. `resolve_client_config_user()`
6. Validate user status, server permissions, and mode support
7. Build one profile:
   - OpenVPN: `build_openvpn_client_config()`
   - SS/KCPTUN: `build_user_kcptun_clash_profile()`
   - Shadowsocks: `build_user_shadowsocks_clash_profile()`
   - SSH tunnel: `build_user_ssh_tunnel_config()`
8. Server returns encrypted config payload
9. Client writes profile under local app data

## SSH Cleanup

1. SSH tunnel profile includes cleanup token
2. Client disconnects or exits
3. `POST /client-api/ssh-tunnel/cleanup`
4. `client_ssh_tunnel_cleanup()`
5. `verify_ssh_cleanup_token()`
6. SSH to target server as admin account
7. Remove temporary user and `authorized_keys`

