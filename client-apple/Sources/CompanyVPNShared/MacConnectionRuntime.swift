import Darwin
import Foundation

public final class MacConnectionRuntime {
    private let route: VPNServerRoute
    private let config: SSHTunnelConfig
    private let api: CompanyVPNAPI
    private var sshProcess: Process?
    private var keyFileURL: URL?
    private var proxyManager: MacSystemProxyManager?

    public init(route: VPNServerRoute, config: SSHTunnelConfig, api: CompanyVPNAPI) {
        self.route = route
        self.config = config
        self.api = api
    }

    deinit {
        stop()
    }

    public func start() async throws {
        let local = parseSocksAddress(config.localSocks)
        try ensurePortAvailable(host: local.host, port: local.port)
        let keyURL = try writePrivateKey(config.privateKey)
        keyFileURL = keyURL

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = [
            "-N",
            "-D", "\(local.host):\(local.port)",
            "-p", "\(config.port)",
            "-i", keyURL.path,
            "-o", "ExitOnForwardFailure=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "\(config.username)@\(config.host)",
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        process.terminationHandler = { _ in
            pipe.fileHandleForReading.readabilityHandler = nil
        }
        pipe.fileHandleForReading.readabilityHandler = { handle in
            _ = handle.availableData
        }
        try process.run()
        sshProcess = process
        try waitForPort(host: local.host, port: local.port, timeout: 8)

        let manager = MacSystemProxyManager(host: local.host, port: local.port)
        try manager.enable()
        proxyManager = manager
    }

    public func stop() {
        proxyManager?.restore()
        proxyManager = nil

        if let process = sshProcess, process.isRunning {
            process.terminate()
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.2) {
                if process.isRunning {
                    process.interrupt()
                }
            }
        }
        sshProcess = nil

        if let keyFileURL {
            try? FileManager.default.removeItem(at: keyFileURL)
            self.keyFileURL = nil
        }
        api.cleanupSSHTunnel(config)
    }

    private func writePrivateKey(_ text: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("companyvpn-\(UUID().uuidString)")
            .appendingPathExtension("key")
        try text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return url
    }

    private func parseSocksAddress(_ raw: String) -> (host: String, port: Int) {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = value.split(separator: ":", maxSplits: 1).map(String.init)
        if parts.count == 2, let port = Int(parts[1]) {
            return (parts[0], port)
        }
        return ("127.0.0.1", 7890)
    }

    private func ensurePortAvailable(host: String, port: Int) throws {
        let socket = try SocketProbe(host: host, port: port)
        try socket.close()
    }

    private func waitForPort(host: String, port: Int, timeout: TimeInterval) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if SocketProbe.canConnect(host: host, port: port, timeout: 0.3) {
                return
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        throw MacConnectionError.localSocksNotReady
    }
}

private final class MacSystemProxyManager {
    private let host: String
    private let port: Int
    private var snapshots: [ProxySnapshot] = []

    init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    func enable() throws {
        let services = try listNetworkServices()
        snapshots = services.compactMap { service in
            try? readSnapshot(service: service)
        }
        for service in services {
            _ = try runNetworkSetup(["-setsocksfirewallproxy", service, host, "\(port)"])
            _ = try runNetworkSetup(["-setsocksfirewallproxystate", service, "on"])
        }
    }

    func restore() {
        for snapshot in snapshots {
            if snapshot.enabled, !snapshot.server.isEmpty, snapshot.port > 0 {
                _ = try? runNetworkSetup(["-setsocksfirewallproxy", snapshot.service, snapshot.server, "\(snapshot.port)"])
                _ = try? runNetworkSetup(["-setsocksfirewallproxystate", snapshot.service, "on"])
            } else {
                _ = try? runNetworkSetup(["-setsocksfirewallproxystate", snapshot.service, "off"])
            }
        }
        snapshots = []
    }

    private func listNetworkServices() throws -> [String] {
        let output = try runNetworkSetup(["-listallnetworkservices"])
        return output
            .split(separator: "\n")
            .dropFirst()
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") }
    }

    private func readSnapshot(service: String) throws -> ProxySnapshot {
        let output = try runNetworkSetup(["-getsocksfirewallproxy", service])
        var enabled = false
        var server = ""
        var port = 0
        for line in output.split(separator: "\n").map(String.init) {
            let lower = line.lowercased()
            if lower.hasPrefix("enabled:") {
                enabled = lower.contains("yes")
            } else if lower.hasPrefix("server:") {
                server = String(line.split(separator: ":", maxSplits: 1).last ?? "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
            } else if lower.hasPrefix("port:") {
                let raw = String(line.split(separator: ":", maxSplits: 1).last ?? "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                port = Int(raw) ?? 0
            }
        }
        return ProxySnapshot(service: service, enabled: enabled, server: server, port: port)
    }

    @discardableResult
    private func runNetworkSetup(_ args: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if process.terminationStatus != 0 {
            throw MacConnectionError.commandFailed(output)
        }
        return output
    }
}

private struct ProxySnapshot {
    let service: String
    let enabled: Bool
    let server: String
    let port: Int
}

private final class SocketProbe {
    private let socketFD: Int32

    init(host: String, port: Int) throws {
        socketFD = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw MacConnectionError.localPortBusy
        }
        var yes: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result != 0 {
            Darwin.close(socketFD)
            throw MacConnectionError.localPortBusy
        }
    }

    func close() throws {
        Darwin.close(socketFD)
    }

    static func canConnect(host: String, port: Int, timeout: TimeInterval) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout.truncatingRemainder(dividingBy: 1)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}

private enum MacConnectionError: LocalizedError {
    case localPortBusy
    case localSocksNotReady
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .localPortBusy:
            return "本地 7890 端口已被占用，请先关闭其它代理软件"
        case .localSocksNotReady:
            return "SSH SOCKS 未启动成功"
        case .commandFailed(let output):
            return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "系统命令执行失败" : output
        }
    }
}
