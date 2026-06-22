# Client Build And Update Call Chains

## Admin Starts Build

1. Admin opens user list page
2. Build button posts `/admin/client/build/start`
3. `admin_start_client_build_packages()`
4. Save build state as running
5. Start background thread
6. Browser polls `/admin/client/build/status`
7. Build log is read from `read_client_build_log()`

## Build Package

1. `run_client_build_background(web_url)`
2. `build_client_packages_on_server(web_url)`
3. `ensure_go_toolchain()`
4. Generate version stamp: `YYYYMMDD-HHMMSS-ms`
5. Build Windows x86_64 client:
   - `CompanyVPN.exe`
   - embedded Web URL
   - embedded global client key
   - embedded client version
6. Build `Updater.exe`
7. Copy required runtime files:
   - `wintun.dll` for SSH Tunnel global TUN mode
8. Create `client-<version>.zip`
9. Update latest download pointer
10. Delete old package zip files

## Public Download

1. Browser opens `/client/download`
2. `public_client_download()`
3. Resolve latest package
4. Return latest zip

## Version Check

1. Client startup calls `/client/latest`
2. `public_client_latest()`
3. Return:
   - `version`
   - `filename`
   - `download_url`
4. Client compares with embedded version
5. If newer, user confirms update

## Updater

1. Client launches bundled `Updater.exe`
2. Main client disconnects VPN and exits
3. Updater shows progress window
4. Download zip
5. Extract zip
6. Retry file replacement until old executable lock is released
7. Start new `CompanyVPN.exe`
8. Close updater
