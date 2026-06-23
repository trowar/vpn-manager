import Foundation

public struct CompanyVPNConfig {
    public let webURL: String
    public let cryptoKey: String
    public let version: String

    public init(webURL: String, cryptoKey: String, version: String) {
        self.webURL = webURL
        self.cryptoKey = cryptoKey
        self.version = version
    }

    public static func fromEnvironment() -> CompanyVPNConfig {
        let env = ProcessInfo.processInfo.environment
        return CompanyVPNConfig(
            webURL: env["COMPANY_VPN_WEB_URL"] ?? GeneratedCompanyVPNConfig.webURL,
            cryptoKey: env["COMPANY_VPN_CLIENT_KEY"] ?? GeneratedCompanyVPNConfig.cryptoKey,
            version: env["COMPANY_VPN_CLIENT_VERSION"] ?? GeneratedCompanyVPNConfig.version
        )
    }
}

public struct VPNServerRoute: Identifiable, Hashable, Codable {
    public var id: String
    public var displayHost: String
    public var account: String
    public var mode: String

    public init(id: String, displayHost: String, account: String, mode: String = "SSH Tunnel") {
        self.id = id
        self.displayHost = displayHost
        self.account = account
        self.mode = mode
    }
}

public enum VPNConnectionState: Equatable {
    case disconnected
    case connecting(String)
    case connected(String)

    public var title: String {
        switch self {
        case .disconnected:
            return "准备连接"
        case .connecting:
            return "正在连接"
        case .connected:
            return "已连接"
        }
    }

    public var isBusy: Bool {
        if case .connecting = self {
            return true
        }
        return false
    }
}

public struct TrafficSnapshot: Equatable {
    public var rxBytes: UInt64
    public var txBytes: UInt64

    public init(rxBytes: UInt64 = 0, txBytes: UInt64 = 0) {
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }

    public var rxText: String { Self.format(rxBytes) }
    public var txText: String { Self.format(txBytes) }

    private static func format(_ value: UInt64) -> String {
        if value < 1024 {
            return "\(value) B"
        }
        let units = ["KB", "MB", "GB", "TB"]
        var number = Double(value) / 1024.0
        var index = 0
        while number >= 1024.0 && index < units.count - 1 {
            number /= 1024.0
            index += 1
        }
        return String(format: "%.2f %@", number, units[index])
    }
}
