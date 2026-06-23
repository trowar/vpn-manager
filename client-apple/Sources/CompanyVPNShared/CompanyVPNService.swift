import Foundation
import CryptoKit

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

    public init(config: CompanyVPNConfig = .fromEnvironment()) {
        self.config = config
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
            routes = try await CompanyVPNAPI(config: config).login(username: account, password: password)
            message = "登录成功，可用线路 \(routes.count) 个"
        } catch {
            message = "登录失败: \(error.localizedDescription)"
        }
    }

    public func connect(_ route: VPNServerRoute) async {
        guard !connectionState.isBusy else { return }
        connectionState = .connecting(route.id)
        message = "正在连接 \(route.displayHost)"
        try? await Task.sleep(nanoseconds: 600_000_000)
        connectionState = .connected(route.id)
        traffic = TrafficSnapshot(rxBytes: 0, txBytes: 0)
        message = "已连接 \(route.displayHost)"
    }

    public func disconnect() async {
        guard case .connected = connectionState else { return }
        message = "正在断开连接..."
        try? await Task.sleep(nanoseconds: 250_000_000)
        connectionState = .disconnected
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
}

private struct CompanyVPNAPI {
    let config: CompanyVPNConfig

    func login(username: String, password: String) async throws -> [VPNServerRoute] {
        let baseURL = normalizedBaseURL(config.webURL)
        let serverTime = try await fetchServerTime(baseURL: baseURL)
        let slug = loginSlug(serverTime: serverTime)
        let url = baseURL.appendingPathComponent("client-api/session/\(slug)")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CompanyVPN/1.0", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode(LoginBody(username: username, password: password))
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateHTTP(response: response, data: data)
        let plain = try decryptLoginResponseIfNeeded(data)
        let payload = try JSONDecoder().decode(BootstrapPayload.self, from: plain)
        return payload.profiles.map { profile in
            let host = profile.server.displayName.nonEmpty
                ?? profile.server.endpointHost.nonEmpty
                ?? profile.server.host.nonEmpty
                ?? profile.name
            return VPNServerRoute(
                id: profile.id,
                displayHost: host,
                account: payload.account.nonEmpty ?? username,
                mode: profile.type
            )
        }
    }

    private func fetchServerTime(baseURL: URL) async throws -> Int64 {
        let url = baseURL.appendingPathComponent("client-api/time")
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CompanyVPN/1.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateHTTP(response: response, data: data)
        let payload = try JSONDecoder().decode(TimePayload.self, from: data)
        guard payload.ok, payload.serverTime > 0, !payload.nonce.isEmpty else {
            throw CompanyVPNAPIError.invalidResponse
        }
        let expected = hmacBase64URL("time:\(payload.serverTime):\(payload.nonce)")
        guard expected == payload.signature else {
            throw CompanyVPNAPIError.invalidSignature
        }
        return payload.serverTime
    }

    private func loginSlug(serverTime: Int64) -> String {
        let window = serverTime / 60
        return String(hmacBase64URL("login:\(window)").prefix(32))
    }

    private func decryptLoginResponseIfNeeded(_ data: Data) throws -> Data {
        guard let envelope = try? JSONDecoder().decode(EncryptedEnvelope.self, from: data),
              envelope.encrypted == "login-v1" else {
            return data
        }
        guard let nonce = Data(base64URLEncoded: envelope.nonce),
              let ciphertext = Data(base64URLEncoded: envelope.payload) else {
            throw CompanyVPNAPIError.invalidResponse
        }
        let combined = nonce + ciphertext
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let key = SymmetricKey(data: SHA256.hash(data: Data(config.cryptoKey.utf8)))
        return try AES.GCM.open(sealedBox, using: key)
    }

    private func validateHTTP(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw CompanyVPNAPIError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let text = String(data: data, encoding: .utf8) ?? ""
            throw CompanyVPNAPIError.http("服务器返回 \(http.statusCode): \(text)")
        }
    }

    private func normalizedBaseURL(_ raw: String) -> URL {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.lowercased().hasPrefix("http://") && !text.lowercased().hasPrefix("https://") {
            text = "http://" + text
        }
        return URL(string: text.trimmingCharacters(in: CharacterSet(charactersIn: "/")))!
    }

    private func hmacBase64URL(_ text: String) -> String {
        let key = SymmetricKey(data: Data(config.cryptoKey.utf8))
        let code = HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: key)
        return Data(code).base64URLEncodedString()
    }
}

private struct LoginBody: Encodable {
    let username: String
    let password: String
}

private struct TimePayload: Decodable {
    let ok: Bool
    let serverTime: Int64
    let nonce: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case ok
        case serverTime = "server_time"
        case nonce
        case signature
    }
}

private struct EncryptedEnvelope: Decodable {
    let encrypted: String
    let nonce: String
    let payload: String
}

private struct BootstrapPayload: Decodable {
    let account: String
    let profiles: [ProfilePayload]
}

private struct ProfilePayload: Decodable {
    let id: String
    let name: String
    let type: String
    let server: ServerPayload
}

private struct ServerPayload: Decodable {
    let host: String
    let endpointHost: String
    let displayName: String

    enum CodingKeys: String, CodingKey {
        case host
        case endpointHost = "endpoint_host"
        case displayName = "display_name"
    }
}

private enum CompanyVPNAPIError: LocalizedError {
    case invalidResponse
    case invalidSignature
    case http(String)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "服务器响应无效"
        case .invalidSignature:
            return "服务器时间签名校验失败"
        case .http(let message):
            return message
        }
    }
}

private extension String {
    var nonEmpty: String? {
        let value = trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}

private extension Data {
    init?(base64URLEncoded text: String) {
        var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padding = value.count % 4
        if padding > 0 {
            value += String(repeating: "=", count: 4 - padding)
        }
        self.init(base64Encoded: value)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
