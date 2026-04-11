# VPN Platform V1

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

```bash
curl -fsSL https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

基于 `PRD_vpn_platform_v1.md` 的全新起步版本（Web 控制端 + VPN 节点端分离）。

## 本地开发

```bash
cd v1
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
flask --app app run --host 0.0.0.0 --port 8080
```

默认管理员：

- 账号：`admin`
- 密码：`admin`
- 首次登录后必须修改密码

## 当前范围（起步骨架）

- SQLite 初始化与默认管理员
- 首次登录强制改密
- 左侧导航布局基础框架
- 管理端/用户端占位页面
- 一键安装脚本（apt/yum 双兼容）

