# vpn-manager锛圖ocker 鏋舵瀯锛?

## 涓€閿畨瑁咃紙apt / yum锛?

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

```bash
curl -fsSL https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

## 鎵嬪姩閮ㄧ讲 VPN 鏈嶅姟绔紙鎺掗殰浼樺厛锛?

濡傛灉 Web 鍚庡彴鈥滄湇鍔″櫒绠＄悊 -> 閮ㄧ讲鈥濆け璐ワ紝鍙互鍏堝湪鐩爣 VPN 鏈嶅姟鍣ㄦ墜鍔ㄦ墽琛岋細

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash
```

鎴栵細

```bash
curl -fsSL https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash
```

鍙€夊弬鏁扮ず渚嬶紙涓嶄紶鍒欎娇鐢ㄩ粯璁ょ鍙ｏ細WG 51820 / OVPN 1194 / DNS 53锛夛細

```bash
VPN_API_TOKEN=your_token WG_PUBLIC_PORT=51820 OPENVPN_PUBLIC_PORT=1194 DNS_PUBLIC_PORT=53 bash /path/manual_deploy_vpn_node.sh
```

寤鸿鎶婃墽琛屾棩蹇椾繚瀛樹笅鏉ワ紝渚夸簬鎺掗殰锛?

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash | tee /root/vpn-node-manual-deploy.log
```

瀹夎瀹屾垚鍚庝細鍚姩 Web 鎺у埗绔湇鍔★紝骞舵墦鍗拌闂湴鍧€涓庨粯璁ょ鐞嗗憳璐﹀彿瀵嗙爜锛坄admin / admin`锛岄娆＄櫥褰曢渶鏀瑰瘑锛夈€?

鏈」鐩凡鎷嗗垎涓轰袱涓富瑕佸鍣ㄦ湇鍔★細

- `web`锛氫腑鏂囩鐞嗗悗鍙?+ 鐢ㄦ埛闂ㄦ埛锛團lask锛?
- `vpn`锛歐ireGuard + OpenVPN + dnsmasq + VPN API锛堝悓涓€涓鍣級

鍏朵腑 DNS 涓?VPN 鏀惧湪鍚屼竴涓?`vpn` 瀹瑰櫒閲岋紝绗﹀悎鈥淲eb 鍗曠嫭瀹瑰櫒銆乂PN 浣滀负鐙珛鏈嶅姟銆丏NS 鍜?VPN 涓€璧烽儴缃测€濈殑闇€姹傘€?

## 绠＄悊鍛橀娆＄櫥褰曞紩瀵?

- 榛樿绠＄悊鍛橈細`admin / admin`
- 绗竴娆＄櫥褰曚細寮哄埗璺宠浆鍒扳€滀慨鏀瑰瘑鐮佲€?
- 淇敼鍚庡啀娆＄櫥褰曚細杩涘叆鈥滃垵濮嬪寲鍚戝鈥?
- 鍒濆鍖栧悜瀵奸渶瑕佷竴娆℃€ч厤缃細
  - 绗竴涓椁愶紙鎸夋椂闀挎垨鎸夋祦閲忥級
  - 榛樿 USDT 鏀舵鍦板潃锛堢敤浜庣敓鎴愭敹娆句簩缁寸爜锛?
  - 绔欑偣鍩熷悕
  - Cloudflare 璐﹀彿涓庡瘑鐮侊紙淇濆瓨鍒扮郴缁熻缃級
  - 绗竴鍙版湇鍔″櫒 SSH 淇℃伅锛圛P/绔彛/璐﹀彿/瀵嗙爜锛?
- 鍚戝浼氬厛娴嬭瘯 SSH 杩為€氾紝鍐嶈嚜鍔ㄩ€氳繃 SSH 杩炴帴鐩爣鏈嶅姟鍣ㄩ儴缃?VPN 鏈嶅姟绔?

## 鏈嶅姟鍣ㄧ鐞?

- 绠＄悊绔柊澧炲乏渚у鑸細`鏈嶅姟鍣ㄧ鐞哷
- 椤甸潰鎸夎灞曠ず鎵€鏈夊凡鎺ュ叆鏈嶅姟鍣紙鍩虹淇℃伅銆佺姸鎬併€佹搷浣滐級
- 鈥滄渶杩戞祴璇?/ 鏈€杩戦儴缃测€濈粺涓€鏀惧埌鈥滈儴缃叉棩蹇椻€濆脊绐楅《閮ㄥ拰鏃ュ織姝ｆ枃灞曠ず
- 鍙充笂瑙掆€滄柊澧炴湇鍔″櫒鈥濆脊绐楁敮鎸侊細
  - 杈撳叆 IP/鍩熷悕銆丼SH 绔彛銆佽处鍙枫€佸瘑鐮?
  - 涓€閿祴璇曡繛閫?
  - 淇濆瓨骞惰嚜鍔ㄩ儴缃?VPN 鏈嶅姟
- 姣忚鏀寔鍐嶆鈥滄祴璇曗€濆拰鈥滈儴缃测€濓紝鐢ㄤ簬杩愮淮閲嶈瘯

## 鏋舵瀯璇存槑

- `web` 涓嶅啀鐩存帴鎵ц鏈湴 `wg` 鍛戒护锛岃€屾槸閫氳繃 `VPN_API_URL` 璋冪敤 `vpn` 瀹瑰櫒鍐?API銆?
- `vpn` 瀹瑰櫒璐熻矗锛?
  - WireGuard 鎺ュ彛鎷夎捣涓?peer 绠＄悊
  - OpenVPN 鏈嶅姟锛堣处鍙峰瘑鐮佽璇侊紝璇诲彇鍚屼竴濂楃敤鎴峰簱锛?
  - dnsmasq DNS 瑙ｆ瀽
- 涓や釜瀹瑰櫒鍏变韩鎸佷箙鍖栧嵎锛?
  - `portal_data`锛氭暟鎹簱涓庣敤鎴烽厤缃?
  - `vpn_shared`锛氭湇鍔＄鍏挜绛夊叡浜枃浠?

## 鐩綍

```text
docker/
  web/
    Dockerfile
  vpn/
    Dockerfile
    entrypoint.sh
    vpn_api.py
    dnsmasq.conf
    wireguard/
      wg0.conf.example
    openvpn/
      server.conf.example
docker-compose.yml
docker-compose.vpn-node.yml
.env.docker.example
```

## 蹇€熷惎鍔?

1. 澶嶅埗鐜鍙橀噺鏂囦欢

```bash
cp .env.docker.example .env
```

2. 鍑嗗 WireGuard 閰嶇疆

```bash
sudo apt update
sudo apt install -y wireguard-tools

wg genkey | tee docker/vpn/wireguard/server_private.key | wg pubkey > docker/vpn/wireguard/server_public.key
cp docker/vpn/wireguard/wg0.conf.example docker/vpn/wireguard/wg0.conf
```

鎶?`docker/vpn/wireguard/wg0.conf` 閲岀殑 `PrivateKey` 鏇挎崲鎴?`server_private.key` 鍐呭锛屽苟鎸夐渶淇敼缃戞/绔彛銆?

3. 鍑嗗 OpenVPN锛堝彲閫夛級

```bash
cp docker/vpn/openvpn/server.conf.example docker/vpn/openvpn/server.conf
```

灏嗕互涓嬫枃浠舵斁鍒?`docker/vpn/openvpn/`锛?

- `ca.crt`
- `server.crt`
- `server.key`
- `tls-crypt.key`

濡傛灉鏆傛椂涓嶅惎鐢?OpenVPN锛屽湪 `.env` 涓缃細

```env
VPN_ENABLE_OPENVPN=0
OPENVPN_ENABLED=0
```

4. 鍚姩鏈嶅姟

```bash
docker compose up -d --build web
```

5. 鏌ョ湅鐘舵€?

```bash
docker compose ps
docker compose --profile vpn-server logs -f vpnmanager-server
docker compose logs -f web
```

## 鍏抽敭鐜鍙橀噺

`.env` 涓噸鐐瑰叧娉細

- `PORTAL_SECRET_KEY`锛歐eb 瀵嗛挜锛屽繀椤讳慨鏀?
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`锛氱鐞嗗憳璐﹀彿锛堥粯璁?`admin / admin`锛岄娆＄櫥褰曚細寮哄埗淇敼瀵嗙爜锛?
- `VPN_API_TOKEN`锛歐eb 涓?VPN API 閫氳浠ょ墝
- `WG_ENDPOINT`锛氱敤鎴蜂笅杞?WireGuard 閰嶇疆閲岀殑鍏綉鍏ュ彛锛堝 `www.network000.com:51820`锛?
- `OPENVPN_ENDPOINT_HOST`锛歄penVPN 瀹㈡埛绔繛鎺ュ煙鍚?IP

寮€鍏抽」锛?

- `VPN_ENABLE_WIREGUARD`锛歚1/0`
- `VPN_ENABLE_DNSMASQ`锛歚1/0`
- `VPN_ENABLE_OPENVPN`锛歚1/0`
- `OPENVPN_ENABLED`锛歐eb 鏄惁灞曠ず OpenVPN 涓嬭浇鍏ュ彛锛坄1/0`锛?

## 绔彛

- Web锛歚${WEB_PUBLIC_PORT}` -> 瀹瑰櫒 `8080`
- WireGuard锛歚${WG_PUBLIC_PORT}/udp` -> 瀹瑰櫒 `51820/udp`
- OpenVPN锛歚${OPENVPN_PUBLIC_PORT}/udp` -> 瀹瑰櫒 `1194/udp`
- DNS锛歚${DNS_PUBLIC_PORT}` -> 瀹瑰櫒 `53/tcp,53/udp`

## 鍩熷悕涓?HTTPS锛?43锛?

褰撳墠 Compose 淇濇寔涓ゅ鍣ㄦ灦鏋勶紝涓嶉澶栧紩鍏?Nginx 瀹瑰櫒銆? 
鐢熶骇鐜寤鸿鍦ㄥ涓绘満鐢?Nginx/Caddy 鍙嶄唬鍒?`web`锛堝 `127.0.0.1:8080`锛夛紝骞堕厤缃細

- `80 -> 443` 鑷姩璺宠浆
- Let鈥檚 Encrypt 鍏嶈垂璇佷功
- 鑷姩缁湡锛坄certbot renew` 瀹氭椂浠诲姟锛?

## OpenVPN 璁よ瘉鏈哄埗

OpenVPN now uses certificate identity (`CN=vpn-user-<id>`) instead of username/password prompts.
The server validates subscription status from `portal.db` during TLS verification, and `openvpn_session_guard.py` disconnects expired users and blocks reconnects until renewal.

## 甯哥敤杩愮淮鍛戒护

```bash
docker compose restart web
docker compose --profile vpn-server restart vpnmanager-server
docker compose logs -f --tail=200 web
docker compose --profile vpn-server logs -f --tail=200 vpnmanager-server
```

## 鎺ㄩ€佸苟鏇存柊 Release

姣忔鎺ㄩ€佸悗鍙娇鐢ㄨ剼鏈嚜鍔ㄦ洿鏂?`latest` release锛堜細寮哄埗绉诲姩 `latest` tag 鍒板綋鍓嶆彁浜わ級锛?

```powershell
$env:GH_TOKEN="<浣犵殑 GitHub Token>"
powershell -ExecutionPolicy Bypass -File .\scripts\push_and_update_release.ps1
```
