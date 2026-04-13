# vpn-manager（Docker 架构）

## 一键安装（apt / yum）

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

```bash
curl -fsSL https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

## 手动部署 VPN 服务端（排障优先）

如果 Web 后台“服务器管理 -> 部署”失败，可以先在目标 VPN 服务器手动执行：

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash
```

或：

```bash
curl -fsSL https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash
```

可选参数示例（不传则使用默认端口：WG 51820 / OVPN 1194 / DNS 53）：

```bash
VPN_API_TOKEN=your_token WG_PUBLIC_PORT=51820 OPENVPN_PUBLIC_PORT=1194 DNS_PUBLIC_PORT=53 bash /path/manual_deploy_vpn_node.sh
```

建议把执行日志保存下来，便于排障：

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/scripts/manual_deploy_vpn_node.sh | bash | tee /root/vpn-node-manual-deploy.log
```

安装完成后会启动 Web 控制端服务，并打印访问地址与默认管理员账号密码（`admin / admin`，首次登录需改密）。

本项目已拆分为两个主要容器服务：

- `web`：中文管理后台 + 用户门户（Flask）
- `vpn`：WireGuard + OpenVPN + dnsmasq + VPN API（同一个容器）

其中 DNS 与 VPN 放在同一个 `vpn` 容器里，符合“Web 单独容器、VPN 作为独立服务、DNS 和 VPN 一起部署”的需求。

## 管理员首次登录引导

- 默认管理员：`admin / admin`
- 第一次登录会强制跳转到“修改密码”
- 修改后再次登录会进入“初始化向导”
- 初始化向导需要一次性配置：
  - 第一个套餐（按时长或按流量）
  - 默认 USDT 收款地址（用于生成收款二维码）
  - 站点域名
  - Cloudflare 账号与密码（保存到系统设置）
  - 第一台服务器 SSH 信息（IP/端口/账号/密码）
- 向导会先测试 SSH 连通，再自动通过 SSH 连接目标服务器部署 VPN 服务端

## 服务器管理

- 管理端新增左侧导航：`服务器管理`
- 页面按行展示所有已接入服务器（基础信息、状态、操作）
- “最近测试 / 最近部署”统一放到“部署日志”弹窗顶部和日志正文展示
- 右上角“新增服务器”弹窗支持：
  - 输入 IP/域名、SSH 端口、账号、密码
  - 一键测试连通
  - 保存并自动部署 VPN 服务
- 每行支持再次“测试”和“部署”，用于运维重试

## 架构说明

- `web` 不再直接执行本地 `wg` 命令，而是通过 `VPN_API_URL` 调用 `vpn` 容器内 API。
- `vpn` 容器负责：
  - WireGuard 接口拉起与 peer 管理
  - OpenVPN 服务（证书身份认证，按订阅有效期控制会话）
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
docker-compose.vpn-node.yml
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
docker compose up -d --build web
```

5. 查看状态

```bash
docker compose ps
docker compose --profile vpn-server logs -f vpnmanager-server
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

OpenVPN 已切换为证书身份认证（`CN=vpn-user-<id>`），客户端导入 `.ovpn` 后不需要再输入用户名和密码。  
服务端会在 TLS 校验阶段读取 `portal.db` 验证订阅状态，并由 `scripts/openvpn_session_guard.py` 持续巡检：到期用户会被踢下线并拒绝重连，续期后才可恢复连接。

## 常用运维命令

```bash
docker compose restart web
docker compose --profile vpn-server restart vpnmanager-server
docker compose logs -f --tail=200 web
docker compose --profile vpn-server logs -f --tail=200 vpnmanager-server
```

## 推送并更新 Release

每次推送后可使用脚本自动更新 `latest` release（会强制移动 `latest` tag 到当前提交）：

```powershell
$env:GH_TOKEN="<你的 GitHub Token>"
powershell -ExecutionPolicy Bypass -File .\scripts\push_and_update_release.ps1
```
