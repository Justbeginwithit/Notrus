import Foundation

enum StandardsCoreBridgeError: LocalizedError {
    case helperFailed(String)
    case helperMissing

    var errorDescription: String? {
        switch self {
        case .helperFailed(let details):
            return "The standards protocol core failed. \(details)"
        case .helperMissing:
            return "The bundled standards protocol core helper is missing from this build."
        }
    }
}

enum StandardsCoreBridge {
    private static let helperTimeout: TimeInterval = 30
    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    static func createIdentity(
        displayName: String,
        threadUserId: String,
        username: String
    ) throws -> StandardsCreateIdentityResponse {
        try run(
            CreateIdentityRequest(
                command: "create-identity",
                displayName: displayName,
                threadUserId: threadUserId,
                username: username
            ),
            as: StandardsCreateIdentityResponse.self
        )
    }

    static func refreshMlsKeyPackage(mlsState: String) throws -> StandardsRefreshMlsKeyPackageResponse {
        try run(
            RefreshMlsKeyPackageRequest(command: "refresh-mls-key-package", mlsState: mlsState),
            as: StandardsRefreshMlsKeyPackageResponse.self
        )
    }

    static func refreshSignalBundle(signalState: String) throws -> StandardsRefreshSignalBundleResponse {
        try run(
            RefreshSignalBundleRequest(command: "refresh-signal-bundle", signalState: signalState),
            as: StandardsRefreshSignalBundleResponse.self
        )
    }

    static func signalEncrypt(
        localSignalState: String,
        localUserId: String,
        plaintext: String,
        remoteBundle: PublicSignalBundle,
        remoteUserId: String
    ) throws -> StandardsSignalEncryptResponse {
        try run(
            SignalEncryptRequest(
                command: "signal-encrypt",
                localSignalState: localSignalState,
                localUserId: localUserId,
                plaintext: plaintext,
                remoteBundle: remoteBundle,
                remoteUserId: remoteUserId
            ),
            as: StandardsSignalEncryptResponse.self
        )
    }

    static func signalDecrypt(
        localSignalState: String,
        localUserId: String,
        messageKind: String,
        remoteUserId: String,
        wireMessage: String
    ) throws -> StandardsSignalDecryptResponse {
        try run(
            SignalDecryptRequest(
                command: "signal-decrypt",
                localSignalState: localSignalState,
                localUserId: localUserId,
                messageKind: messageKind,
                remoteUserId: remoteUserId,
                wireMessage: wireMessage
            ),
            as: StandardsSignalDecryptResponse.self
        )
    }

    static func signalResetPeer(
        localSignalState: String,
        remoteUserId: String
    ) throws -> StandardsSignalResetPeerResponse {
        try run(
            SignalResetPeerRequest(
                command: "signal-reset-peer",
                localSignalState: localSignalState,
                remoteUserId: remoteUserId
            ),
            as: StandardsSignalResetPeerResponse.self
        )
    }

    static func mlsCreateGroup(
        creatorMlsState: String,
        creatorUserId: String,
        participantKeyPackages: [String: PublicMlsKeyPackage],
        participantUserIds: [String],
        threadId: String
    ) throws -> StandardsMlsCreateGroupResponse {
        try run(
            MlsCreateGroupRequest(
                command: "mls-create-group",
                creatorMlsState: creatorMlsState,
                creatorUserId: creatorUserId,
                participantKeyPackages: participantKeyPackages,
                participantUserIds: participantUserIds,
                threadId: threadId
            ),
            as: StandardsMlsCreateGroupResponse.self
        )
    }

    static func mlsJoinGroup(
        localMlsState: String,
        localUserId: String,
        threadBootstrap: RelayMlsBootstrap
    ) throws -> StandardsMlsJoinGroupResponse {
        try run(
            MlsJoinGroupRequest(
                command: "mls-join-group",
                localMlsState: localMlsState,
                localUserId: localUserId,
                threadBootstrap: threadBootstrap
            ),
            as: StandardsMlsJoinGroupResponse.self
        )
    }

    static func mlsEncryptMessage(
        localMlsState: String,
        plaintext: String,
        threadState: String
    ) throws -> StandardsMlsEncryptMessageResponse {
        try run(
            MlsEncryptMessageRequest(
                command: "mls-encrypt-message",
                localMlsState: localMlsState,
                plaintext: plaintext,
                threadState: threadState
            ),
            as: StandardsMlsEncryptMessageResponse.self
        )
    }

    static func mlsProcessMessage(
        localMlsState: String,
        threadState: String,
        wireMessage: String
    ) throws -> StandardsMlsProcessMessageResponse {
        try run(
            MlsProcessMessageRequest(
                command: "mls-process-message",
                localMlsState: localMlsState,
                threadState: threadState,
                wireMessage: wireMessage
            ),
            as: StandardsMlsProcessMessageResponse.self
        )
    }

    private static func run<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type
    ) throws -> Response {
        let process = Process()
        process.executableURL = try helperURL()

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        let payload = try encoder.encode(request)
        inputPipe.fileHandleForWriting.write(payload)
        try inputPipe.fileHandleForWriting.close()

        let exitGroup = DispatchGroup()
        let ioGroup = DispatchGroup()
        var output = Data()
        var error = Data()

        ioGroup.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            output = outputPipe.fileHandleForReading.readDataToEndOfFile()
            ioGroup.leave()
        }

        ioGroup.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            error = errorPipe.fileHandleForReading.readDataToEndOfFile()
            ioGroup.leave()
        }

        exitGroup.enter()
        process.terminationHandler = { _ in
            exitGroup.leave()
        }

        if exitGroup.wait(timeout: .now() + helperTimeout) == .timedOut {
            process.terminationHandler = nil
            if process.isRunning {
                process.terminate()
            }
            _ = ioGroup.wait(timeout: .now() + 1)
            throw StandardsCoreBridgeError.helperFailed("The helper timed out after \(Int(helperTimeout)) seconds.")
        }
        process.terminationHandler = nil
        _ = ioGroup.wait(timeout: .now() + 2)

        guard process.terminationStatus == 0 else {
            let details = String(data: error, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            throw StandardsCoreBridgeError.helperFailed(details?.isEmpty == false ? details! : "The helper exited with status \(process.terminationStatus).")
        }

        return try decoder.decode(responseType, from: output)
    }

    static func helperURL(
        bundleURL: URL = Bundle.main.bundleURL,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> URL {
        let fileManager = FileManager.default
        let sourceRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        if let override = environment["NOTRUS_PROTOCOL_CORE_HELPER"], fileManager.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }

        let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent()
        let candidates: [URL] = [
            bundleURL.appendingPathComponent("Contents/Helpers/notrus-protocol-core"),
            bundleURL.appendingPathComponent("Contents/MacOS/notrus-protocol-core"),
            bundleURL.appendingPathComponent("Contents/Resources/notrus-protocol-core"),
            executableDirectory?.appendingPathComponent("notrus-protocol-core"),
            sourceRoot.appendingPathComponent("native/protocol-core/target/release/notrus-protocol-core"),
            sourceRoot.appendingPathComponent("native/protocol-core/target/debug/notrus-protocol-core")
        ].compactMap { $0 }

        if let candidate = candidates.first(where: { fileManager.isExecutableFile(atPath: $0.path) }) {
            return candidate
        }

        throw StandardsCoreBridgeError.helperMissing
    }
}

private struct CreateIdentityRequest: Encodable {
    let command: String
    let displayName: String
    let threadUserId: String
    let username: String
}

private struct RefreshMlsKeyPackageRequest: Encodable {
    let command: String
    let mlsState: String
}

private struct RefreshSignalBundleRequest: Encodable {
    let command: String
    let signalState: String
}

private struct SignalEncryptRequest: Encodable {
    let command: String
    let localSignalState: String
    let localUserId: String
    let plaintext: String
    let remoteBundle: PublicSignalBundle
    let remoteUserId: String
}

private struct SignalDecryptRequest: Encodable {
    let command: String
    let localSignalState: String
    let localUserId: String
    let messageKind: String
    let remoteUserId: String
    let wireMessage: String
}

private struct SignalResetPeerRequest: Encodable {
    let command: String
    let localSignalState: String
    let remoteUserId: String
}

private struct MlsCreateGroupRequest: Encodable {
    let command: String
    let creatorMlsState: String
    let creatorUserId: String
    let participantKeyPackages: [String: PublicMlsKeyPackage]
    let participantUserIds: [String]
    let threadId: String
}

private struct MlsJoinGroupRequest: Encodable {
    let command: String
    let localMlsState: String
    let localUserId: String
    let threadBootstrap: RelayMlsBootstrap
}

private struct MlsEncryptMessageRequest: Encodable {
    let command: String
    let localMlsState: String
    let plaintext: String
    let threadState: String
}

private struct MlsProcessMessageRequest: Encodable {
    let command: String
    let localMlsState: String
    let threadState: String
    let wireMessage: String
}
