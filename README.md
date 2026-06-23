# Company VPN 内部网络接入管理系统

这是一个面向公司内部使用的 VPN/代理接入管理平台。管理员在 Web 后台创建账号、分配可连接服务器，员工使用公司客户端登录后选择线路连接。

## 技术架构

- Web 管理端：Python Flask
- Web 服务运行：Gunicorn + systemd
- 数据库：PostgreSQL
- Windows 客户端：Go 编写的 Windows 原生客户端
- macOS 客户端：SwiftUI 原生客户端
- iOS 客户端：SwiftUI 界面工程，后续接入 Network Extension 和开发者签名
- Android 客户端：Android 原生工程，后续接入 `VpnService`
- 更新器：Go 编写的独立 `Updater.exe`
- 全局接入：Windows TUN 虚拟网卡 + Wintun；macOS/iOS/Android 后续使用系统 VPN 框架
- 连接方式：SSH Tunnel
- 客户端与 Web 通讯：HTTP/HTTPS API + 时间窗口签名 + 加密响应
- 部署同步：rsync + SSH key

## 当前能力

- 管理员后台创建、启用、停用、删除用户
- 管理员可修改普通用户和管理员账号密码
- 用户按权限查看可连接服务器
- 客户端登录后实时从 Web 服务获取可用线路
- 连接时临时生成 SSH Tunnel 凭据，断开后清理
- 客户端使用虚拟网卡实现全局流量接入
- 管理后台可查看用户在线状态、连接服务器、连接模式、源 IP、下载/上传流量
- 客户端支持自动检查版本并调用 Updater 更新
- 管理后台支持编译最新 Windows 客户端包，并自动尝试构建 macOS / iOS / Android 客户端产物

## 支持的客户端

当前正式支持：

- Windows x86_64

可测试运行：

- Windows 11 ARM，通过系统 x64 兼容层运行 x86_64 客户端
- macOS 原生客户端，已接入登录和线路权限获取，VPN 全局接入层待继续接入 Network Extension/TUN
- iOS SwiftUI 客户端工程，等待 Apple Developer 账号、签名和 Network Extension capability
- Android 原生客户端工程，等待 Android SDK/Gradle 环境和 `VpnService` 接入

当前不支持：

- Linux 桌面客户端
- 浏览器插件客户端

## 连接模式

当前主模式：

- SSH Tunnel + 本地 TUN 全局模式

说明：

- 客户端登录 Web 服务后，按用户权限获取可连接服务器。
- 用户点击连接后，服务端为该次连接生成临时 SSH 凭据。
- 客户端在内存中建立 SSH Tunnel，并通过 TUN 虚拟网卡接入全局流量。
- 用户断开连接后，服务端清理临时账号和 `authorized_keys`。

## 安装脚本

一键安装：

```bash
wget -O - https://raw.githubusercontent.com/trowar/vpn-manager/main/v1/scripts/install.sh | bash
```

默认 Web 访问地址：

```text
http://服务器IP:8080
```

## 本地变更同步到服务器

如果只想把本地修改同步到服务器，不执行客户端编译：

```bash
./scripts/push_web_no_build.sh
```

## 编译客户端

后台“编译客户端”会执行：

- Windows x86_64：生成默认更新包 `client-版本.zip`
- macOS：如果服务器是 macOS 且安装 Swift，则生成 `client-macos-版本.zip`
- iOS：在没有 Apple Developer 签名配置前生成 `client-ios-source-版本.zip`
- Android：如果安装 Gradle 和 Android SDK，则生成 `client-android-版本.apk`

本地也可以手动执行平台客户端构建：

```bash
COMPANY_VPN_CLIENT_VERSION=2026-0623-1200-0001 \
COMPANY_VPN_WEB_URL=http://172.16.188.135:8080 \
./scripts/build_platform_clients.sh
```

默认参数：

- 服务器：`root@172.16.188.135`
- 端口：`22`
- 目录：`/srv/vpn-platform-v1`
- 服务：`vpn-platform-v1-web.service`

只同步不重启：

```bash
VPN_MANAGER_NO_RESTART=1 ./scripts/push_web_no_build.sh
```

## 本地部署 key

同步脚本默认使用：

```text
~/.vpnmanager/deploy_rsa
```

首次没有 key 时脚本会自动生成。把公钥加入服务器后，后续即可免密码更新：

```bash
ssh-copy-id -i ~/.vpnmanager/deploy_rsa.pub -p 22 root@172.16.188.135
```

如果密钥路径不同：

```bash
VPN_MANAGER_REMOTE_KEY_PATH=/path/to/deploy_rsa ./scripts/push_web_no_build.sh
```
