# Company VPN iOS Client

这是 iOS 客户端工程骨架，界面布局与 Windows/macOS 客户端保持一致。

后续接入真机 VPN 时需要：

- Apple Developer 账号
- Network Extension capability
- App Group 或 Keychain 权限用于保存账号信息
- 使用 `NEPacketTunnelProvider` 实现全局接入

当前目录先保留 SwiftUI 界面与交互骨架，等开发者账号准备好后再生成正式 Xcode 工程和签名配置。
