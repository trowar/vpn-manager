# vpn-manager（WireGuard + USDT）

这是一个中文 VPN 门户项目，包含：

- 用户注册/登录（邮箱即用户名）
- 订单购买（1/3/6/12 个月）
- USDT 收款（支持 Webhook 自动确认）
- WireGuard 配置下发（`.conf` 文件下载）
- 用户有效期、流量统计、管理员后台管理

## 功能概览

- 用户侧
  - 控制台首页：账号、IP、订阅状态、到期时间、流量统计
  - 使用说明：安装/导入/连接指引
  - 订单管理：创建订单、提交 TxHash、取消订单
- 管理员侧（左侧分页导航）
  - 首页：基础运营概览
  - 支付设置：收款地址、网络、套餐价格
  - 待处理订单：手动确认支付
  - 已支付订单：历史订单查询
  - 用户订阅：设置期限、停用用户、删除用户
- 安全与控制
  - 注册 IP 限速：同一 IP 5 分钟内仅允许成功注册 1 次
  - 订阅到期自动停用 WireGuard peer
  - 支持动态 IP 分配模式（可配置）

## 重要说明

- 当前已关闭“用户配置二维码下载”，统一使用 `.conf` 文件导入客户端。
- USDT 支付二维码仍保留（用于收款地址展示）。

## 环境要求

- Ubuntu 22.04/24.04（推荐）
- Python 3.10+
- WireGuard 工具：`wireguard wireguard-tools`
- 其他依赖：`qrencode`
- Web 服务：`gunicorn` + `nginx`（推荐）

## 快速部署（Ubuntu）

1. 安装系统依赖

```bash
apt update
apt install -y python3 python3-venv python3-pip wireguard wireguard-tools qrencode nginx
```

2. 上传项目并安装 Python 依赖

```bash
mkdir -p /opt/vpn-portal
cd /opt/vpn-portal
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

3. 配置环境变量文件 `/etc/vpn-portal.env`

```bash
PORTAL_SECRET_KEY=请替换为随机字符串
ADMIN_USERNAME=admin
ADMIN_PASSWORD=请替换为强密码

WG_INTERFACE=wg0
WG_NETWORK=10.7.0.0/24
WG_SERVER_ADDRESS=10.7.0.1
WG_SERVER_PUBLIC_KEY_FILE=/etc/wireguard/server_public.key
WG_ENDPOINT=你的公网IP或域名:51820
WG_CLIENT_DNS=10.7.0.1
WG_CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0
WG_CLIENT_KEEPALIVE=25

# static 或 dynamic（推荐 dynamic）
WG_IP_ASSIGNMENT_MODE=dynamic

# full 或 cn_local（cn_local=中国直连，境外走代理）
WG_ROUTE_POLICY=cn_local
WG_NON_CN_ROUTES_FILE=/opt/vpn-portal/data/non_cn_ipv4_routes.txt

PORTAL_DATA_DIR=/opt/vpn-portal/data
PORTAL_DB_PATH=/opt/vpn-portal/data/portal.db
PORTAL_CLIENT_CONF_DIR=/opt/vpn-portal/data/client-configs
PORTAL_CLIENT_QR_DIR=/opt/vpn-portal/data/client-qr

USDT_DEFAULT_NETWORK=TRC20
USDT_RECEIVE_ADDRESS=你的USDT地址
USDT_PRICE_1M=10
USDT_PRICE_3M=27
USDT_PRICE_6M=50
USDT_PRICE_12M=90

PAYMENT_WEBHOOK_SECRET=请替换为强随机密钥
PAYMENT_MIN_CONFIRMATIONS=1
```

4. 创建 systemd 服务 `/etc/systemd/system/vpn-portal.service`

```ini
[Unit]
Description=VPN Portal
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vpn-portal
EnvironmentFile=/etc/vpn-portal.env
ExecStart=/opt/vpn-portal/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8080 wsgi:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
systemctl daemon-reload
systemctl enable vpn-portal
systemctl restart vpn-portal
systemctl status vpn-portal
```

5. 反向代理到 Nginx（443）

- 将 `www.network000.com` 代理到 `127.0.0.1:8080`
- 开启 `80 -> 443` 跳转
- 证书建议使用 `certbot` 自动续期

## Webhook 接口

- 地址：`POST /webhook/usdt`
- 签名头：`X-Webhook-Signature`
- 算法：`HMAC-SHA256(raw_body, PAYMENT_WEBHOOK_SECRET)`（十六进制）

支持字段示例：

- `order_id` 或 `merchant_order_id` 或 `metadata.order_id`
- `tx_hash`
- `amount`（可选）
- `network`（可选）
- `confirmations`（可选）

## 用户端使用流程

1. 用户注册并登录
2. 在“订单管理”选择套餐并创建订单
3. 完成链上转账，提交 TxHash（或由 Webhook 自动确认）
4. 订阅生效后，在“首页”下载 `.conf` 配置
5. 导入 WireGuard 客户端后连接使用

## 管理端操作建议

- 日常：处理“待处理订单”、维护支付参数
- 风险控制：使用“停用用户”可立即断开
- 清理：使用“删除用户”会删除用户及关联订单/配置数据

## 常用运维命令

```bash
systemctl restart vpn-portal
systemctl status vpn-portal
journalctl -u vpn-portal -n 200 --no-pager
```

## 目录结构

```text
vpn-portal/
├─ app.py
├─ wsgi.py
├─ requirements.txt
├─ templates/
└─ static/
```

## 许可证

可按你的业务需求自行添加 License 文件。
