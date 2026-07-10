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
    public var updateURL: String
    public var onlineURL: String
    public var updateToken: String
    public var server: VPNServerInfo

    public init(
        id: String,
        displayHost: String,
        account: String,
        mode: String = "SSH Tunnel",
        updateURL: String = "",
        onlineURL: String = "",
        updateToken: String = "",
        server: VPNServerInfo = VPNServerInfo()
    ) {
        self.id = id
        self.displayHost = displayHost
        self.account = account
        self.mode = mode
        self.updateURL = updateURL
        self.onlineURL = onlineURL
        self.updateToken = updateToken
        self.server = server
    }
}

public struct VPNServerInfo: Hashable, Codable {
    public var id: Int
    public var serverName: String
    public var host: String
    public var endpointHost: String
    public var displayName: String
    public var sshTunnelEnabled: Bool

    public init(
        id: Int = 0,
        serverName: String = "",
        host: String = "",
        endpointHost: String = "",
        displayName: String = "",
        sshTunnelEnabled: Bool = false
    ) {
        self.id = id
        self.serverName = serverName
        self.host = host
        self.endpointHost = endpointHost
        self.displayName = displayName
        self.sshTunnelEnabled = sshTunnelEnabled
    }
}

public struct CompanyVPNBootstrap {
    public var account: String
    public var updateToken: String
    public var routes: [VPNServerRoute]

    public init(account: String, updateToken: String, routes: [VPNServerRoute]) {
        self.account = account
        self.updateToken = updateToken
        self.routes = routes
    }
}

public struct SSHTunnelConfig: Codable {
    public var host: String
    public var port: Int
    public var username: String
    public var privateKey: String
    public var localSocks: String
    public var cleanupURL: String
    public var cleanupToken: String

    enum CodingKeys: String, CodingKey {
        case host
        case port
        case username
        case privateKey = "private_key"
        case localSocks = "local_socks"
        case cleanupURL = "cleanup_url"
        case cleanupToken = "cleanup_token"
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
