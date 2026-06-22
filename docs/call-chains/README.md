# Call Chains

This directory records the main runtime call chains for future maintenance.
Keep each topic in a separate file so `app.py` can keep shrinking without losing
the map of how features connect.

## Files

- `web-admin.md`: admin pages, users, servers, deployment, and settings.
- `client-api.md`: Windows client login, bootstrap, profile fetch, and cleanup.
- `client-windows.md`: Windows client UI, connection lifecycle, proxy, update.
- `vpn-runtime.md`: OpenVPN, Shadowsocks/KCPTUN, SSH tunnel, node API.
- `client-build-update.md`: server-side client packaging and public update flow.
- `split-map.md`: recommended next module split targets.

## Entry Points

- Web app entry: `wsgi.py` imports `app` from `app.py`.
- Main Flask object: `app.py`.
- Database access: `portal_db.py`.
- Windows client entry: `client-go/main.go`.
- Windows UI: `client-go/ui_windows.go`.
- Windows updater: `client-go/updater/main.go`.
- VPN node API: `vpn/vpn_api.py`.

