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

## 当前范围（M1 已完成）

- SQLite 初始化与默认管理员
- 首次登录强制改密
- 注册（邮箱即账号）
- 邮箱验证码（10 分钟有效）
- 图片验证码（登录/注册/找回均强制）
- 发送限频（同邮箱 60 秒限发、每天最多 10 次）
- 找回密码（重置后旧会话失效）
- 管理后台开放注册开关
- 一键安装脚本（apt/yum 双兼容）

## 邮件发送配置（可选）

如果配置 SMTP，验证码将通过邮件发送：

```bash
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_USER=your_user
export SMTP_PASS=your_password
export SMTP_FROM=your_from@example.com
export SMTP_USE_TLS=1
```

未配置 SMTP 时，系统会把验证码写入服务日志（测试环境便于调试）。
