# Company VPN Client

这是公司内部 VPN 客户端原型。管理员只分发一个引导配置包，客户端每次连接前都会先到管理服务器获取最新配置，再启动对应本机核心。

## 支持方式

- OpenVPN：配置内容是 `.ovpn`，客户端调用本机 `openvpn --config ...`
- SS/KCPTUN：配置内容是 Clash/Mihomo YAML，客户端调用本机 `mihomo -f ...`，如果找不到 `mihomo` 会尝试 `clash`

## 引导配置包格式

管理员可以分发一个 JSON 文件：

```json
{
  "schema": "company-vpn-client.v1",
  "name": "company-user-zhangsan",
  "account": "zhangsan",
  "profiles": [
    {
      "name": "OpenVPN 主线路",
      "type": "openvpn",
      "update_url": "https://vpn.example.com/client-api/profiles/zhangsan/openvpn",
      "update_token": "由后台生成的用户配置令牌"
    },
    {
      "name": "SS/KCPTUN 备用线路",
      "type": "clash",
      "update_url": "https://vpn.example.com/client-api/profiles/zhangsan/clash",
      "update_token": "由后台生成的用户配置令牌"
    }
  ]
}
```

为了方便本地测试，也可以直接导入单个 `.ovpn`、`.yaml` 或 `.yml` 文件。但正式使用时应使用 `update_url`，这样服务器 IP 变化后老客户端不需要重新分发。

## 运行

图形界面：

```bash
python3 client/company_vpn_client.py
```

命令行导入引导配置：

```bash
python3 client/company_vpn_client.py --import ./sample-client-config.json
```

列出配置：

```bash
python3 client/company_vpn_client.py --list
```

连接默认配置：

```bash
python3 client/company_vpn_client.py --connect
```

连接指定配置：

```bash
python3 client/company_vpn_client.py --connect "company-user-zhangsan/OpenVPN 主线路"
```

## 本机依赖

客户端只做配置管理和进程管理。真正的 VPN 核心需要提前安装：

- OpenVPN 配置需要安装 `openvpn`
- SS/KCPTUN 配置建议安装 `mihomo` 或 `clash`

## 配置更新逻辑

每次点击连接时，客户端都会：

1. 读取本地保存的引导配置。
2. 请求当前连接方式对应的 `update_url`。
3. 将服务器返回的最新 `.ovpn` 或 Clash/Mihomo YAML 写入本地运行目录。
4. 启动 `openvpn`、`mihomo` 或 `clash`。

因此配置里不要写死服务器 IP，应该由管理服务器返回最新域名或最新节点配置。
