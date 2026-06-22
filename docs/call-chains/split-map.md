# Split Map

This file lists the next safe targets for reducing `app.py`.

## Already Split

- `portal_config.py`: constants and environment configuration.
- `portal_db.py`: PostgreSQL compatibility wrapper and request DB lifecycle.
- `portal_auth.py`: sessions, login helpers, client IP helpers, download tokens.
- `portal_format.py`: date, amount, and plan formatting helpers.
- `portal_settings.py`: app settings helpers.
- `portal_web.py`: URL, host, and download filename helpers.
- `portal_services/admin_servers.py`: server list decoration.
- `portal_services/admin_user_servers.py`: user/server display helpers.
- `portal_services/captcha.py`: captcha generation and validation.
- `portal_services/openvpn_certs.py`: OpenVPN certificate helpers.
- `portal_services/ss_profiles.py`: Shadowsocks and KCPTUN profile generation.
- `portal_services/vpn_runtime.py`: online peer parsing and traffic formatting.

## Recommended Next Splits

1. `portal_routes/auth.py`
   - `/`
   - `/api/login`
   - `/login`
   - `/logout`
   - captcha routes

2. `portal_routes/admin_servers.py`
   - `/admin/servers`
   - create, update, delete
   - deploy and upgrade routes
   - IPv6 toggle

3. `portal_routes/admin_users.py`
   - `/admin/subscriptions`
   - user create, enable, disable, delete
   - user password reset
   - user server permissions

4. `portal_routes/client_api.py`
   - `/client-api/time`
   - `/client-api/session/<login_slug>`
   - `/client-api/bootstrap/<username>`
   - `/client-api/profiles/<username>/<profile_type>`
   - `/client-api/ssh-tunnel/cleanup`

5. `portal_routes/client_build.py`
   - `/admin/client/build/start`
   - `/admin/client/build/status`
   - `/client/download`
   - `/client/latest`

6. `portal_services/ssh_tunnel.py`
   - temporary key generation
   - install script
   - cleanup script
   - SSH tunnel config payload

7. `portal_services/client_crypto.py`
   - base64url helpers
   - login slug validation
   - client payload encryption
   - signed client request verification

## Split Rule

Move one route group at a time. After each move, run:

```bash
python3 -m py_compile app.py portal_*.py portal_services/*.py vpn/*.py
```

Then smoke-test the affected page or API before moving the next group.

