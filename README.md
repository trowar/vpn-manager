# vpn-manager（Docker 架构）

本项目已拆分为两个主要容器服务：

- `web`：中文管理后台 + 用户门户（Flask）
- `vpn`：WireGuard + OpenVPN + dnsmasq + VPN API（同一个容器）

其中 DNS 与 VPN 放在同一个 `vpn` 容器里，符合“Web 单独容器、VPN 作为独立服务、DNS 和 VPN 一起部署”的需求。

## 架构说明

- `web` 不再直接执行本地 `wg` 命令，而是通过 `VPN_API_URL` 调用 `vpn` 容器内 API。
- `vpn` 容器负责：
  - WireGuard 接口拉起与 peer 管理
  - OpenVPN 服务（账号密码认证，读取同一套用户库）
  - dnsmasq DNS 解析
- 两个容器共享持久化卷：
  - `portal_data`：数据库与用户配置
  - `vpn_shared`：服务端公钥等共享文件

## 目录

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
.env.docker.example
```

## 快速启动

1. 复制环境变量文件

```bash
cp .env.docker.example .env
```

2. 准备 WireGuard 配置

```bash
sudo apt update
sudo apt install -y wireguard-tools

wg genkey | tee docker/vpn/wireguard/server_private.key | wg pubkey > docker/vpn/wireguard/server_public.key
cp docker/vpn/wireguard/wg0.conf.example docker/vpn/wireguard/wg0.conf
```

把 `docker/vpn/wireguard/wg0.conf` 里的 `PrivateKey` 替换成 `server_private.key` 内容，并按需修改网段/端口。

3. 准备 OpenVPN（可选）

```bash
cp docker/vpn/openvpn/server.conf.example docker/vpn/openvpn/server.conf
```

将以下文件放到 `docker/vpn/openvpn/`：

- `ca.crt`
- `server.crt`
- `server.key`
- `tls-crypt.key`

如果暂时不启用 OpenVPN，在 `.env` 中设置：

```env
VPN_ENABLE_OPENVPN=0
OPENVPN_ENABLED=0
```

4. 启动服务

```bash
docker compose up -d --build
```

5. 查看状态

```bash
docker compose ps
docker compose logs -f vpn
docker compose logs -f web
```

## 关键环境变量

`.env` 中重点关注：

- `PORTAL_SECRET_KEY`：Web 密钥，必须修改
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`：管理员账号（默认 `admin / admin`，首次登录会强制修改密码）
- `VPN_API_TOKEN`：Web 与 VPN API 通讯令牌
- `WG_ENDPOINT`：用户下载 WireGuard 配置里的公网入口（如 `www.network000.com:51820`）
- `OPENVPN_ENDPOINT_HOST`：OpenVPN 客户端连接域名/IP

开关项：

- `VPN_ENABLE_WIREGUARD`：`1/0`
- `VPN_ENABLE_DNSMASQ`：`1/0`
- `VPN_ENABLE_OPENVPN`：`1/0`
- `OPENVPN_ENABLED`：Web 是否展示 OpenVPN 下载入口（`1/0`）

## 端口

- Web：`${WEB_PUBLIC_PORT}` -> 容器 `8080`
- WireGuard：`${WG_PUBLIC_PORT}/udp` -> 容器 `51820/udp`
- OpenVPN：`${OPENVPN_PUBLIC_PORT}/udp` -> 容器 `1194/udp`
- DNS：`${DNS_PUBLIC_PORT}` -> 容器 `53/tcp,53/udp`

## 域名与 HTTPS（443）

当前 Compose 保持两容器架构，不额外引入 Nginx 容器。  
生产环境建议在宿主机用 Nginx/Caddy 反代到 `web`（如 `127.0.0.1:8080`），并配置：

- `80 -> 443` 自动跳转
- Let’s Encrypt 免费证书
- 自动续期（`certbot renew` 定时任务）

## OpenVPN 认证机制

OpenVPN 使用 `scripts/openvpn_auth.py` 校验账号密码，读取 `portal.db` 用户数据。  
用户在前台下载 `.ovpn` 后，可在 OpenVPN Connect 中通过“Upload File”导入配置使用。

## 常用运维命令

```bash
docker compose restart web
docker compose restart vpn
docker compose logs -f --tail=200 web
docker compose logs -f --tail=200 vpn
```
