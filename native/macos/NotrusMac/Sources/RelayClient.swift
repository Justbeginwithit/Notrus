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

struct RelayLiveEvent: Decodable {
    let event: String?
    let timestamp: String?
}

struct RelayClient {
    var origin: String
    var integrityReport: ClientIntegrityReport? = nil
    var appInstanceId: String? = nil
    var deviceDescriptor: DeviceDescriptor? = nil
    var sessionToken: String? = nil

    private func url(for path: String) throws -> URL {
        let base = try TransportSecurityPolicy.validatedRelayOrigin(origin)
        return URL(string: path, relativeTo: base)!.absoluteURL
    }

    private func send<T: Decodable>(
        _ path: String,
        method: String = "GET",
        authorizationToken: String? = nil,
        includeBootstrapHeaders: Bool = false,
        decode type: T.Type
    ) async throws -> T {
        var request = URLRequest(url: try url(for: path))
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = TransportSecurityPolicy.requestTimeout
        applyHeaders(
            to: &request,
            authorizationToken: authorizationToken,
            includeBootstrapHeaders: includeBootstrapHeaders
        )

        let (data, response) = try await perform(request)
        return try decodeResponse(data: data, response: response, as: type)
    }

    private func send<T: Decodable, Body: Encodable>(
        _ path: String,
        method: String,
        body: Body,
        authorizationToken: String? = nil,
        includeBootstrapHeaders: Bool = false,
        decode type: T.Type
    ) async throws -> T {
        var request = URLRequest(url: try url(for: path))
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = TransportSecurityPolicy.requestTimeout
        request.httpBody = try JSONEncoder().encode(body)
        applyHeaders(
            to: &request,
            authorizationToken: authorizationToken,
            includeBootstrapHeaders: includeBootstrapHeaders
        )

        let (data, response) = try await perform(request)
        return try decodeResponse(data: data, response: response, as: type)
    }

    private func perform(
        _ request: URLRequest,
        retriedForPow: Bool = false,
        transportAttempt: Int = 0
    ) async throws -> (Data, URLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await TransportSecurityPolicy.session().data(for: request)
        } catch let error as URLError {
            if transportAttempt < 3, isTransientTransportError(error) {
                let delays: [UInt64] = [350_000_000, 900_000_000, 1_800_000_000]
                try? await Task.sleep(nanoseconds: delays[min(transportAttempt, delays.count - 1)])
                return try await perform(
                    request,
                    retriedForPow: retriedForPow,
                    transportAttempt: transportAttempt + 1
                )
            }
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
            return try await perform(
                retried,
                retriedForPow: true,
                transportAttempt: transportAttempt
            )
        }

        return (data, response)
    }

    private func isTransientTransportError(_ error: URLError) -> Bool {
        switch error.code {
        case .secureConnectionFailed, .networkConnectionLost, .timedOut, .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed:
            return true
        default:
            return false
        }
    }

    private func describeTransportError(_ error: URLError) -> String {
        switch error.code {
        case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .dnsLookupFailed, .timedOut, .notConnectedToInternet:
            return "Could not connect to the relay at \(origin). Check that the relay URL is correct and that the tunnel is online."
        case .appTransportSecurityRequiresSecureConnection:
            return "macOS rejected the relay connection because it is not using HTTPS."
        case .secureConnectionFailed:
            return "Could not connect to the relay at \(origin). The TLS handshake failed after retrying; verify the HTTPS tunnel is online and that the relay origin is current."
        default:
            return "Could not connect to the relay at \(origin). \(error.localizedDescription)"
        }
    }

    private func applyHeaders(
        to request: inout URLRequest,
        authorizationToken: String?,
        includeBootstrapHeaders: Bool
    ) {
        if let authorizationToken, !authorizationToken.isEmpty {
            request.setValue("Bearer \(authorizationToken)", forHTTPHeaderField: "Authorization")
        }

        guard includeBootstrapHeaders else {
            return
        }

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

    private func currentSessionToken() throws -> String {
        guard let sessionToken, !sessionToken.isEmpty else {
            throw RelayClientError.requestFailed("The relay session expired. Bootstrap the session again from this Mac.")
        }
        return sessionToken
    }

    func register(identity: LocalIdentity) async throws -> RegisterResponse {
        try await send(
            "/api/bootstrap/register",
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
            includeBootstrapHeaders: true,
            decode: RegisterResponse.self
        )
    }

    func resetAccount(_ requestBody: AccountResetRequest) async throws -> AccountResetResponse {
        try await send(
            "/api/bootstrap/account-reset",
            method: "POST",
            body: requestBody,
            includeBootstrapHeaders: true,
            decode: AccountResetResponse.self
        )
    }

    func sync() async throws -> RelaySyncPayload {
        try await send(
            "/api/sync/state",
            authorizationToken: try currentSessionToken(),
            decode: RelaySyncPayload.self
        )
    }

    func securityDevices() async throws -> RelaySecurityDevicesResponse {
        try await send(
            "/api/security/devices",
            authorizationToken: try currentSessionToken(),
            decode: RelaySecurityDevicesResponse.self
        )
    }

    func transparency() async throws -> RelayTransparencySnapshot {
        try await send(
            "/api/security/transparency",
            authorizationToken: try currentSessionToken(),
            decode: RelayTransparencySnapshot.self
        )
    }

    func searchDirectory(query: String) async throws -> DirectorySearchResponse {
        let encodedQuery = encodeQueryValue(query)
        return try await send(
            "/api/directory/search?q=\(encodedQuery)",
            authorizationToken: try currentSessionToken(),
            decode: DirectorySearchResponse.self
        )
    }

    func createThread(_ requestBody: ThreadCreateRequest) async throws -> ThreadCreateResponse {
        try await send(
            "/api/routing/threads",
            method: "POST",
            body: requestBody,
            authorizationToken: try currentSessionToken(),
            decode: ThreadCreateResponse.self
        )
    }

    func postMessage(mailboxHandle: String, deliveryCapability: String, message: OutboundMessage) async throws -> MessagePostResponse {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/messages",
            method: "POST",
            body: message,
            authorizationToken: deliveryCapability,
            decode: MessagePostResponse.self
        )
    }

    func postMessageEdit(
        mailboxHandle: String,
        deliveryCapability: String,
        targetMessageId: String,
        message: OutboundMessage
    ) async throws -> MessagePostResponse {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/messages/\(targetMessageId)/edit",
            method: "POST",
            body: message,
            authorizationToken: deliveryCapability,
            decode: MessagePostResponse.self
        )
    }

    func deleteMessageForEveryone(
        mailboxHandle: String,
        deliveryCapability: String,
        messageId: String,
        deletedAt: String
    ) async throws -> ReadReceiptResponse {
        struct DeleteRequest: Codable {
            let deletedAt: String
        }
        return try await send(
            "/api/mailboxes/\(mailboxHandle)/messages/\(messageId)/delete",
            method: "POST",
            body: DeleteRequest(deletedAt: deletedAt),
            authorizationToken: deliveryCapability,
            decode: ReadReceiptResponse.self
        )
    }

    func postReadReceipt(
        mailboxHandle: String,
        deliveryCapability: String,
        receipt: ReadReceiptRequest
    ) async throws -> ReadReceiptResponse {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/read-receipts",
            method: "POST",
            body: receipt,
            authorizationToken: deliveryCapability,
            decode: ReadReceiptResponse.self
        )
    }

    func uploadAttachment(
        mailboxHandle: String,
        deliveryCapability: String,
        attachment: AttachmentUploadRequest
    ) async throws -> AttachmentUploadResponse {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/attachments",
            method: "POST",
            body: attachment,
            authorizationToken: deliveryCapability,
            decode: AttachmentUploadResponse.self
        )
    }

    func uploadAttachmentChunk(
        mailboxHandle: String,
        deliveryCapability: String,
        attachmentId: String,
        chunk: AttachmentChunkRecord
    ) async throws -> AttachmentChunkUploadResponse {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/attachments/\(attachmentId)/chunks",
            method: "POST",
            body: chunk,
            authorizationToken: deliveryCapability,
            decode: AttachmentChunkUploadResponse.self
        )
    }

    func fetchAttachment(
        mailboxHandle: String,
        deliveryCapability: String,
        attachmentId: String
    ) async throws -> RelayAttachment {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/attachments/\(attachmentId)",
            authorizationToken: deliveryCapability,
            decode: RelayAttachment.self
        )
    }

    func fetchAttachmentChunk(
        mailboxHandle: String,
        deliveryCapability: String,
        attachmentId: String,
        index: Int
    ) async throws -> AttachmentChunkRecord {
        try await send(
            "/api/mailboxes/\(mailboxHandle)/attachments/\(attachmentId)/chunks/\(index)",
            authorizationToken: deliveryCapability,
            decode: AttachmentChunkRecord.self
        )
    }

    func reportAbuse(_ requestBody: AbuseReportRequest) async throws -> AbuseReportResponse {
        try await send(
            "/api/reports",
            method: "POST",
            body: requestBody,
            authorizationToken: try currentSessionToken(),
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
            authorizationToken: try currentSessionToken(),
            decode: DeviceRevokeResponse.self
        )
    }

    func deleteAccount() async throws -> AccountDeleteResponse {
        try await send(
            "/api/account/delete",
            method: "POST",
            body: EmptyPayload(),
            authorizationToken: try currentSessionToken(),
            decode: AccountDeleteResponse.self
        )
    }

    func liveEvents() throws -> AsyncThrowingStream<RelayLiveEvent, Error> {
        var request = URLRequest(url: try url(for: "/api/events"))
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 0
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        applyHeaders(
            to: &request,
            authorizationToken: try currentSessionToken(),
            includeBootstrapHeaders: false
        )

        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = true
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 0
        let session = URLSession(configuration: configuration)

        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let (bytes, response) = try await session.bytes(for: request)
                    guard let http = response as? HTTPURLResponse else {
                        throw RelayClientError.requestFailed("The relay event stream returned an invalid response.")
                    }
                    guard (200...299).contains(http.statusCode) else {
                        throw RelayClientError.requestFailed("The relay event stream returned HTTP \(http.statusCode).")
                    }

                    var currentEvent: String?
                    var dataLines: [String] = []
                    for try await line in bytes.lines {
                        if Task.isCancelled {
                            break
                        }
                        if line.isEmpty {
                            if currentEvent == "sync", !dataLines.isEmpty {
                                let payload = dataLines.joined(separator: "\n")
                                if let data = payload.data(using: .utf8),
                                   let event = try? JSONDecoder().decode(RelayLiveEvent.self, from: data) {
                                    continuation.yield(event)
                                } else {
                                    continuation.yield(RelayLiveEvent(event: "sync-required", timestamp: nil))
                                }
                            }
                            currentEvent = nil
                            dataLines.removeAll(keepingCapacity: true)
                        } else if line.hasPrefix("event:") {
                            currentEvent = String(line.dropFirst("event:".count)).trimmingCharacters(in: .whitespaces)
                        } else if line.hasPrefix("data:") {
                            dataLines.append(String(line.dropFirst("data:".count)).trimmingCharacters(in: .whitespaces))
                        }
                    }
                    continuation.finish()
                } catch {
                    if Task.isCancelled {
                        continuation.finish()
                    } else {
                        continuation.finish(throwing: error)
                    }
                }
            }

            continuation.onTermination = { _ in
                task.cancel()
                session.invalidateAndCancel()
            }
        }
    }
}

private struct EmptyPayload: Encodable {}

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
