# Windows Client Call Chains

## Startup

1. `client-go/main.go`
2. Load embedded build values:
   - `embeddedDefaultWebURL`
   - `embeddedClientCryptoKey`
   - `embeddedClientVersion`
3. Load saved local state
4. `launchClientUI()`
5. `createControls()`
6. Show login screen unless a profile is already available
7. `checkUpdateOnLaunch()` runs in the background

## Login UI

1. User enters username and password
2. Optional `保存密码`
3. `loginClicked()`
4. `loginWithPassword()`
5. Store bootstrap data
6. Store saved login if selected
7. `refreshProfileCombo()`
8. `showVPNScreen()`

## Profile Selection

1. User clicks `Switch Profile`
2. `switchProfileClicked()`
3. Combo selection changes
4. `updateSelectedProfileText()`
5. Status controls refresh

## Connect

1. User clicks connect button
2. `toggleConnectionClicked()`
3. `startProfileAsync()`
4. Fetch latest profile from Web server
5. Start selected runtime:
   - OpenVPN process
   - Mihomo process for SS/KCPTUN
   - SSH Tunnel: in-memory SSH SOCKS plus bundled TUN child runtime
6. SS/KCPTUN can still enable system proxy; SSH Tunnel uses TUN routes instead
7. Status changes to connected

## SSH Tunnel Global Mode

1. `startSSHTunnelProfileAsync()`
2. `parseSSHTunnelConfigText()`
3. `startMemorySSHTunnel()`
4. Local SOCKS listens on `127.0.0.1:7890`
5. `startVirtualTunnelOverSocks()`
6. Start same executable with `tun2socks-child`
7. Child runs embedded tun2socks engine with Wintun
8. Parent configures TUN IP and split default routes
9. Parent adds direct protection routes for SSH endpoint, Web API host, and DNS servers

## Disconnect

1. User clicks disconnect or window closes
2. `disconnectActiveConnection()`
3. Stop active runtime process
4. Stop virtual TUN runtime and delete routes when SSH Tunnel mode is active
5. Disable system proxy if the SS/KCPTUN branch enabled it
6. SSH tunnel mode also calls cleanup API
7. Status changes to disconnected

## Traffic Display

1. Timer fires every 1.5 seconds
2. `updateStatusControls()`
3. Read runtime process state
4. Read traffic counters from `traffic_windows.go`
5. Update receive and send totals

## Update

1. Startup calls `checkUpdateOnLaunch()`
2. `GET /client/latest`
3. Compare server version with `embeddedClientVersion`
4. User confirms update
5. `disconnectActiveConnection()`
6. Copy bundled `Updater.exe` to temp
7. Launch updater with:
   - package URL
   - target install directory
   - executable name
   - target version
8. Main client exits
9. Updater downloads package, shows progress, replaces files, starts new client
