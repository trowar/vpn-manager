import Combine
import Foundation

@MainActor
public final class CompanyVPNViewModel: ObservableObject {
    @Published public var username: String = ""
    @Published public var password: String = ""
    @Published public var rememberPassword: Bool = false
    @Published public var routes: [VPNServerRoute] = []
    @Published public var connectionState: VPNConnectionState = .disconnected
    @Published public var traffic: TrafficSnapshot = TrafficSnapshot()
    @Published public var message: String = ""

    public let config: CompanyVPNConfig
    private let api: CompanyVPNAPI
    private var runtime: MacConnectionRuntime?
    private var bootstrap: CompanyVPNBootstrap?

    public init(config: CompanyVPNConfig = .fromEnvironment()) {
        self.config = config
        self.api = CompanyVPNAPI(config: config)
    }

    deinit {
        runtime?.stop()
    }

    public func login() async {
        let account = username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !account.isEmpty else {
            message = "请输入账户"
            return
        }
        guard !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = "请输入密码"
            return
        }
        message = "正在登录并获取线路..."
        do {
            let result = try await api.login(username: account, password: password)
            bootstrap = result
            routes = result.routes
            message = "登录成功，可用线路 \(routes.count) 个"
        } catch {
            message = "登录失败: \(error.localizedDescription)"
        }
    }

    public func connect(_ route: VPNServerRoute) async {
        guard !connectionState.isBusy else { return }
        guard normalizeMode(route.mode) == "ssh-tunnel" else {
            message = "当前 mac 直下载版仅支持 SSH Tunnel"
            return
        }
        connectionState = .connecting(route.id)
        message = "正在获取临时配置..."
        do {
            let profileConfig = try await api.fetchSSHTunnelConfig(route: route)
            message = "正在连接 \(route.displayHost)"
            let runtime = MacConnectionRuntime(route: route, config: profileConfig, api: api)
            try await runtime.start()
            self.runtime = runtime
            connectionState = .connected(route.id)
            traffic = TrafficSnapshot(rxBytes: 0, txBytes: 0)
            message = "已连接 \(route.displayHost)"
        } catch {
            runtime?.stop()
            runtime = nil
            connectionState = .disconnected
            message = "连接失败: \(error.localizedDescription)"
        }
    }

    public func disconnect() async {
        guard case .connected = connectionState else { return }
        message = "正在断开连接..."
        runtime?.stop()
        runtime = nil
        connectionState = .disconnected
        traffic = TrafficSnapshot()
        message = "已断开"
    }

    public func buttonTitle(for route: VPNServerRoute) -> String {
        switch connectionState {
        case .disconnected:
            return "连接"
        case .connecting(let id):
            return id == route.id ? "连接中" : "连接"
        case .connected(let id):
            return id == route.id ? "断开" : "连接"
        }
    }

    public func isButtonDisabled(for route: VPNServerRoute) -> Bool {
        switch connectionState {
        case .disconnected:
            return false
        case .connecting:
            return true
        case .connected(let id):
            return id != route.id
        }
    }

    public func isRouteActive(_ route: VPNServerRoute) -> Bool {
        if case .connected(let id) = connectionState {
            return id == route.id
        }
        return false
    }

    private func normalizeMode(_ mode: String) -> String {
        mode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
