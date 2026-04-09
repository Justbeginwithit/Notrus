import CryptoKit
import Foundation

enum RelayClientError: LocalizedError {
    case badURL
    case requestFailed(String)

    var errorDescription: String? {
        switch self {
        case .badURL:
            return "The relay URL is invalid."
        case .requestFailed(let message):
            return message
        }
    }
}

struct RelayClient {
    var origin: String
    var integrityReport: ClientIntegrityReport? = nil
    var appInstanceId: String? = nil
    var deviceDescriptor: DeviceDescriptor? = nil

    private func url(for path: String) throws -> URL {
        let base = try TransportSecurityPolicy.validatedRelayOrigin(origin)
        return URL(string: path, relativeTo: base)!.absoluteURL
    }

    private func send<T: Decodable>(
        _ path: String,
        method: String = "GET",
        decode type: T.Type
    ) async throws -> T {
        var request = URLRequest(url: try url(for: path))
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = TransportSecurityPolicy.requestTimeout
        applyIntegrityHeaders(to: &request)

        let (data, response) = try await perform(request)
        return try decodeResponse(data: data, response: response, as: type)
    }

    private func send<T: Decodable, Body: Encodable>(
        _ path: String,
        method: String,
        body: Body,
        decode type: T.Type
    ) async throws -> T {
        var request = URLRequest(url: try url(for: path))
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = TransportSecurityPolicy.requestTimeout
        request.httpBody = try JSONEncoder().encode(body)
        applyIntegrityHeaders(to: &request)

        let (data, response) = try await perform(request)
        return try decodeResponse(data: data, response: response, as: type)
    }

    private func perform(_ request: URLRequest, retriedForPow: Bool = false) async throws -> (Data, URLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await TransportSecurityPolicy.session().data(for: request)
        } catch let error as URLError {
            throw RelayClientError.requestFailed(describeTransportError(error))
        } catch {
            throw RelayClientError.requestFailed("Could not connect to the relay at \(origin). \(error.localizedDescription)")
        }
        guard let http = response as? HTTPURLResponse else {
            throw RelayClientError.requestFailed("The relay returned an invalid response.")
        }

        if http.statusCode == 428, !retriedForPow {
            let challengeEnvelope = try JSONDecoder().decode(PowChallengeEnvelope.self, from: data)
            guard let challenge = challengeEnvelope.powChallenge else {
                throw RelayClientError.requestFailed("The relay requested proof-of-work without a usable challenge.")
            }
            var retried = request
            let nonce = try solve(challenge: challenge)
            retried.setValue(challenge.token, forHTTPHeaderField: challenge.tokenField ?? "X-Notrus-Pow-Token")
            retried.setValue(nonce, forHTTPHeaderField: challenge.nonceField ?? "X-Notrus-Pow-Nonce")
            return try await perform(retried, retriedForPow: true)
        }

        return (data, response)
    }

    private func describeTransportError(_ error: URLError) -> String {
        switch error.code {
        case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .dnsLookupFailed, .timedOut, .notConnectedToInternet:
            return "Could not connect to the relay at \(origin). Check that the relay URL is correct and that the tunnel is online."
        case .appTransportSecurityRequiresSecureConnection:
            return "macOS rejected the relay connection because it is not using HTTPS."
        default:
            return "Could not connect to the relay at \(origin). \(error.localizedDescription)"
        }
    }

    private func applyIntegrityHeaders(to request: inout URLRequest) {
        if let appInstanceId, !appInstanceId.isEmpty {
            request.setValue(appInstanceId, forHTTPHeaderField: "X-Notrus-Instance-Id")
        }
        if let deviceDescriptor {
            request.setValue(deviceDescriptor.id, forHTTPHeaderField: "X-Notrus-Device-Id")
        }
        guard let integrityReport, let data = try? JSONEncoder().encode(integrityReport) else {
            return
        }
        request.setValue(data.base64EncodedString(), forHTTPHeaderField: "X-Notrus-Integrity")
    }

    private func decodeResponse<T: Decodable>(data: Data, response: URLResponse, as type: T.Type) throws -> T {
        guard let http = response as? HTTPURLResponse else {
            throw RelayClientError.requestFailed("The relay returned an invalid response.")
        }

        if !(200...299).contains(http.statusCode) {
            if
                let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let error = payload["error"] as? String
            {
                throw RelayClientError.requestFailed(error)
            }

            throw RelayClientError.requestFailed("The relay returned HTTP \(http.statusCode).")
        }

        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch let error as DecodingError {
            throw RelayClientError.requestFailed("The relay returned data the Mac client could not understand. \(describeDecodingError(error))")
        }
    }

    private func encodeQueryValue(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
    }

    private func describeDecodingError(_ error: DecodingError) -> String {
        switch error {
        case .keyNotFound(let key, let context):
            return "Missing field '\(key.stringValue)' near \(codingPath(context.codingPath))."
        case .typeMismatch(_, let context):
            return "Unexpected field type near \(codingPath(context.codingPath))."
        case .valueNotFound(_, let context):
            return "Expected value missing near \(codingPath(context.codingPath))."
        case .dataCorrupted(let context):
            return context.debugDescription
        @unknown default:
            return error.localizedDescription
        }
    }

    private func codingPath(_ codingPath: [CodingKey]) -> String {
        guard !codingPath.isEmpty else {
            return "the top-level relay payload"
        }
        return codingPath.map(\.stringValue).joined(separator: ".")
    }

    private func solve(challenge: PowChallenge) throws -> String {
        let token = challenge.token
        var counter: UInt64 = 0
        while counter < 50_000_000 {
            let candidate = String(counter, radix: 16)
            let digest = SHA256.hash(data: Data("\(token):\(candidate)".utf8))
            if leadingZeroBits(in: digest) >= challenge.difficultyBits {
                return candidate
            }
            counter += 1
        }

        throw RelayClientError.requestFailed("Unable to satisfy the relay proof-of-work challenge in time.")
    }

    private func leadingZeroBits(in digest: SHA256Digest) -> Int {
        var count = 0
        for byte in digest {
            if byte == 0 {
                count += 8
                continue
            }

            for shift in stride(from: 7, through: 0, by: -1) {
                if (byte & (1 << shift)) == 0 {
                    count += 1
                } else {
                    return count
                }
            }
        }

        return count
    }

    func health() async throws -> RelayHealth {
        try await send("/api/health", decode: RelayHealth.self)
    }

    func register(identity: LocalIdentity) async throws -> RelayUser {
        let response: RegisterResponse = try await send(
            "/api/register",
            method: "POST",
            body: RegisterRequest(
                device: deviceDescriptor,
                displayName: identity.displayName,
                encryptionPublicJwk: identity.encryptionPublicJwk,
                fingerprint: identity.fingerprint,
                mlsKeyPackage: identity.standardsMlsKeyPackage,
                prekeyCreatedAt: identity.prekeyCreatedAt,
                prekeyFingerprint: identity.prekeyFingerprint,
                prekeyPublicJwk: identity.prekeyPublicJwk,
                prekeySignature: identity.prekeySignature,
                recoveryFingerprint: identity.recoveryFingerprint,
                recoveryPublicJwk: identity.recoveryPublicJwk,
                signalBundle: identity.standardsSignalBundle,
                signingPublicJwk: identity.signingPublicJwk,
                userId: identity.id,
                username: identity.username
            ),
            decode: RegisterResponse.self
        )
        return response.user
    }

    func resetAccount(_ requestBody: AccountResetRequest) async throws -> RelayUser {
        let response: AccountResetResponse = try await send(
            "/api/account-reset",
            method: "POST",
            body: requestBody,
            decode: AccountResetResponse.self
        )
        return response.user
    }

    func sync(userId: String) async throws -> RelaySyncPayload {
        try await send("/api/sync?userId=\(encodeQueryValue(userId))", decode: RelaySyncPayload.self)
    }

    func searchDirectory(userId: String, query: String) async throws -> DirectorySearchResponse {
        let encodedQuery = encodeQueryValue(query)
        return try await send(
            "/api/directory/search?userId=\(encodeQueryValue(userId))&q=\(encodedQuery)",
            decode: DirectorySearchResponse.self
        )
    }

    func createThread(_ requestBody: ThreadCreateRequest) async throws -> ThreadCreateResponse {
        try await send("/api/threads", method: "POST", body: requestBody, decode: ThreadCreateResponse.self)
    }

    func postMessage(threadId: String, message: OutboundMessage) async throws -> MessagePostResponse {
        try await send(
            "/api/threads/\(threadId)/messages",
            method: "POST",
            body: message,
            decode: MessagePostResponse.self
        )
    }

    func uploadAttachment(threadId: String, attachment: AttachmentUploadRequest) async throws -> AttachmentUploadResponse {
        try await send(
            "/api/threads/\(threadId)/attachments",
            method: "POST",
            body: attachment,
            decode: AttachmentUploadResponse.self
        )
    }

    func fetchAttachment(threadId: String, attachmentId: String, userId: String) async throws -> RelayAttachment {
        try await send(
            "/api/threads/\(threadId)/attachments/\(attachmentId)?userId=\(encodeQueryValue(userId))",
            decode: RelayAttachment.self
        )
    }

    func reportAbuse(_ requestBody: AbuseReportRequest) async throws -> AbuseReportResponse {
        try await send(
            "/api/reports",
            method: "POST",
            body: requestBody,
            decode: AbuseReportResponse.self
        )
    }

    func revokeDevice(
        userId: String,
        signerDeviceId: String,
        targetDeviceId: String,
        createdAt: String,
        signature: String
    ) async throws -> DeviceRevokeResponse {
        try await send(
            "/api/devices/revoke",
            method: "POST",
            body: DeviceRevokeRequest(
                createdAt: createdAt,
                signature: signature,
                signerDeviceId: signerDeviceId,
                targetDeviceId: targetDeviceId,
                userId: userId
            ),
            decode: DeviceRevokeResponse.self
        )
    }
}

private struct PowChallengeEnvelope: Decodable {
    let powChallenge: PowChallenge?
}

private struct PowChallenge: Decodable {
    let difficultyBits: Int
    let expiresAt: String?
    let nonceField: String?
    let scope: String?
    let token: String
    let tokenField: String?
}
