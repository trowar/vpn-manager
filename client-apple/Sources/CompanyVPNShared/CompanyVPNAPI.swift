import CryptoKit
import Foundation

public struct CompanyVPNAPI {
    public let config: CompanyVPNConfig

    public init(config: CompanyVPNConfig) {
        self.config = config
    }

    public func login(username: String, password: String) async throws -> CompanyVPNBootstrap {
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
        let routes = payload.profiles.map { profile in
            let host = profile.server.displayName.nonEmpty
                ?? profile.server.endpointHost.nonEmpty
                ?? profile.server.host.nonEmpty
                ?? profile.name
            return VPNServerRoute(
                id: profile.id,
                displayHost: host,
                account: payload.account.nonEmpty ?? username,
                mode: profile.type,
                updateURL: profile.updateURL,
                onlineURL: profile.onlineURL,
                updateToken: profile.updateToken.nonEmpty ?? payload.updateToken,
                server: profile.server.toPublic()
            )
        }
        return CompanyVPNBootstrap(
            account: payload.account.nonEmpty ?? username,
            updateToken: payload.updateToken,
            routes: routes
        )
    }

    public func fetchSSHTunnelConfig(route: VPNServerRoute) async throws -> SSHTunnelConfig {
        guard let url = URL(string: route.updateURL), !route.updateToken.isEmpty else {
            throw CompanyVPNAPIError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json,text/plain,*/*", forHTTPHeaderField: "Accept")
        request.setValue("CompanyVPN/1.0", forHTTPHeaderField: "User-Agent")
        signClientRequest(&request, token: route.updateToken)
        let (data, response) = try await URLSession.shared.data(for: request)
        let plain = try decryptClientResponseIfNeeded(data)
        try validateHTTP(response: response, data: plain)
        let responsePayload = try JSONDecoder().decode(ProfileConfigResponse.self, from: plain)
        if !responsePayload.ok {
            throw CompanyVPNAPIError.http(responsePayload.error.nonEmpty ?? "获取配置失败")
        }
        guard let configData = responsePayload.config.data(using: .utf8) else {
            throw CompanyVPNAPIError.invalidResponse
        }
        return try JSONDecoder().decode(SSHTunnelConfig.self, from: configData)
    }

    public func cleanupSSHTunnel(_ tunnel: SSHTunnelConfig) {
        guard let url = URL(string: tunnel.cleanupURL), !tunnel.cleanupToken.isEmpty else {
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("CompanyVPN/1.0", forHTTPHeaderField: "User-Agent")
        request.httpBody = try? JSONEncoder().encode(["cleanup_token": tunnel.cleanupToken])
        URLSession.shared.dataTask(with: request).resume()
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
        let expected = hmacBase64URL("time:\(payload.serverTime):\(payload.nonce)", key: config.cryptoKey)
        guard expected == payload.signature else {
            throw CompanyVPNAPIError.invalidSignature
        }
        return payload.serverTime
    }

    private func loginSlug(serverTime: Int64) -> String {
        let window = serverTime / 60
        return String(hmacBase64URL("login:\(window)", key: config.cryptoKey).prefix(32))
    }

    private func signClientRequest(_ request: inout URLRequest, token: String) {
        guard let url = request.url else { return }
        let timestamp = "\(Int(Date().timeIntervalSince1970))"
        let path = url.path.isEmpty ? "/" : url.path
        let message = "\(request.httpMethod ?? "GET")\n\(path)\n\(timestamp)"
        request.setValue(timestamp, forHTTPHeaderField: "X-CompanyVPN-Auth-Time")
        request.setValue(hmacBase64URL(message, key: token), forHTTPHeaderField: "X-CompanyVPN-Auth-Signature")
        request.setValue("v1", forHTTPHeaderField: "X-CompanyVPN-Encrypted")
    }

    private func decryptLoginResponseIfNeeded(_ data: Data) throws -> Data {
        guard let envelope = try? JSONDecoder().decode(EncryptedEnvelope.self, from: data),
              envelope.encrypted == "login-v1" else {
            return data
        }
        return try decryptEnvelope(envelope)
    }

    private func decryptClientResponseIfNeeded(_ data: Data) throws -> Data {
        guard let envelope = try? JSONDecoder().decode(EncryptedEnvelope.self, from: data),
              envelope.encrypted == "v1" else {
            return data
        }
        return try decryptEnvelope(envelope)
    }

    private func decryptEnvelope(_ envelope: EncryptedEnvelope) throws -> Data {
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
    let updateToken: String
    let profiles: [ProfilePayload]

    enum CodingKeys: String, CodingKey {
        case account
        case updateToken = "update_token"
        case profiles
    }
}

private struct ProfilePayload: Decodable {
    let id: String
    let name: String
    let type: String
    let updateURL: String
    let onlineURL: String
    let updateToken: String
    let server: ServerPayload

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case type
        case updateURL = "update_url"
        case onlineURL = "online_url"
        case updateToken = "update_token"
        case server
    }
}

private struct ServerPayload: Decodable {
    let id: Int
    let serverName: String
    let host: String
    let endpointHost: String
    let displayName: String
    let sshTunnelEnabled: Bool

    enum CodingKeys: String, CodingKey {
        case id
        case serverName = "server_name"
        case host
        case endpointHost = "endpoint_host"
        case displayName = "display_name"
        case sshTunnelEnabled = "ssh_tunnel_enabled"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int.self, forKey: .id) ?? 0
        serverName = try container.decodeIfPresent(String.self, forKey: .serverName) ?? ""
        host = try container.decodeIfPresent(String.self, forKey: .host) ?? ""
        endpointHost = try container.decodeIfPresent(String.self, forKey: .endpointHost) ?? ""
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        sshTunnelEnabled = try container.decodeIfPresent(Bool.self, forKey: .sshTunnelEnabled) ?? false
    }

    func toPublic() -> VPNServerInfo {
        VPNServerInfo(
            id: id,
            serverName: serverName,
            host: host,
            endpointHost: endpointHost,
            displayName: displayName,
            sshTunnelEnabled: sshTunnelEnabled
        )
    }
}

private struct ProfileConfigResponse: Decodable {
    let ok: Bool
    let error: String
    let type: String
    let config: String

    enum CodingKeys: String, CodingKey {
        case ok
        case error
        case type
        case config
        case profile
        case content
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ok = try container.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        error = try container.decodeIfPresent(String.self, forKey: .error) ?? ""
        type = try container.decodeIfPresent(String.self, forKey: .type) ?? ""
        config = (
            try container.decodeIfPresent(String.self, forKey: .config)
            ?? container.decodeIfPresent(String.self, forKey: .profile)
            ?? container.decodeIfPresent(String.self, forKey: .content)
            ?? ""
        )
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

private func hmacBase64URL(_ text: String, key: String) -> String {
    let signingKey = SymmetricKey(data: Data(key.utf8))
    let code = HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: signingKey)
    return Data(code).base64URLEncodedString()
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
