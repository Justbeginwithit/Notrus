import CryptoKit
import Foundation

enum ThreadStateStoreError: LocalizedError, Equatable {
    case corruptState
    case rollbackDetected
    case unsupportedVersion

    var errorDescription: String? {
        switch self {
        case .corruptState:
            return "The native thread-state store could not be decrypted on this Mac."
        case .rollbackDetected:
            return "This Mac detected an older copy of the local session state. Restore a current recovery archive instead of replaying stale state."
        case .unsupportedVersion:
            return "The native thread-state store version is not supported by this build."
        }
    }
}

final class ThreadStateStore {
    private let directory: URL
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let deviceSecretStore: DeviceSecretStore

    init(
        directory: URL? = nil,
        deviceSecretStore: DeviceSecretStore = DeviceSecretStore()
    ) {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let root = directory ?? appSupport.appendingPathComponent("NotrusMac", isDirectory: true)
        self.directory = root
        self.deviceSecretStore = deviceSecretStore
        SensitiveStoragePolicy.prepareDirectory(root)
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    func loadRecords(for identity: LocalIdentity) throws -> [String: ThreadStoreRecord] {
        let url = storeURL(for: identity.id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return [:]
        }

        let envelope = try decoder.decode(ThreadStoreEnvelope.self, from: Data(contentsOf: url))
        switch envelope.version {
        case 1:
            let legacy = try loadLegacyRecords(envelope, for: identity)
            try saveRecords(legacy, for: identity)
            return legacy
        case 2:
            let generation = envelope.generation ?? 0
            let knownGeneration = try deviceSecretStore.generation(for: generationScope(for: identity.id))
            if knownGeneration > generation {
                throw ThreadStateStoreError.rollbackDetected
            }

            let plaintext = try openEnvelope(
                envelope,
                using: try deviceSecretStore.existingDerivedKey(purpose: "thread-state", userId: identity.id),
                aad: Data("notrus-native-thread-state-v2".utf8)
            )
            let records = try decoder.decode([String: ThreadStoreRecord].self, from: plaintext)
            if generation > knownGeneration {
                try deviceSecretStore.storeGeneration(generation, for: generationScope(for: identity.id))
            }
            return records
        default:
            throw ThreadStateStoreError.unsupportedVersion
        }
    }

    func saveRecords(_ records: [String: ThreadStoreRecord], for identity: LocalIdentity) throws {
        let plaintext = try encoder.encode(records)
        let nextGeneration = try deviceSecretStore.generation(for: generationScope(for: identity.id)) + 1
        let sealed = try AES.GCM.seal(
            plaintext,
            using: try deviceSecretStore.derivedKey(purpose: "thread-state", userId: identity.id),
            nonce: AES.GCM.Nonce(data: NotrusCrypto.randomData(count: 12)),
            authenticating: Data("notrus-native-thread-state-v2".utf8)
        )

        guard let combined = sealed.combined else {
            throw ThreadStateStoreError.corruptState
        }

        let envelope = ThreadStoreEnvelope(
            ciphertext: combined.dropFirst(12).base64EncodedString(),
            generation: nextGeneration,
            iv: combined.prefix(12).base64EncodedString(),
            version: 2
        )
        let data = try encoder.encode(envelope)
        let url = storeURL(for: identity.id)
        try data.write(to: url, options: .atomic)
        SensitiveStoragePolicy.prepareFile(url)
        try deviceSecretStore.storeGeneration(nextGeneration, for: generationScope(for: identity.id))
    }

    func deleteRecords(for userId: String) throws {
        let url = storeURL(for: userId)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try deviceSecretStore.storeGeneration(0, for: generationScope(for: userId))
    }

    func resetAll() throws {
        let urls = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        for url in urls where url.lastPathComponent.hasPrefix("thread-state-") {
            try FileManager.default.removeItem(at: url)
        }
    }

    private func storeURL(for userId: String) -> URL {
        directory.appendingPathComponent("thread-state-\(userId).json")
    }

    private func generationScope(for userId: String) -> String {
        "thread-state-generation.\(userId)"
    }

    private func openEnvelope(_ envelope: ThreadStoreEnvelope, using key: SymmetricKey, aad: Data) throws -> Data {
        let ciphertext = try NotrusCrypto.base64Data(envelope.ciphertext)
        let iv = try NotrusCrypto.base64Data(envelope.iv)
        let sealedBox = try AES.GCM.SealedBox(combined: iv + ciphertext)
        return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
    }

    private func loadLegacyRecords(_ envelope: ThreadStoreEnvelope, for identity: LocalIdentity) throws -> [String: ThreadStoreRecord] {
        let plaintext = try openEnvelope(
            envelope,
            using: legacySealKey(for: identity),
            aad: Data("notrus-native-thread-state-v1".utf8)
        )
        return try decoder.decode([String: ThreadStoreRecord].self, from: plaintext)
    }

    private func legacySealKey(for identity: LocalIdentity) -> SymmetricKey {
        let material = Data(
            """
            {"encryption":"\(identity.encryptionRepresentation)","prekey":"\(identity.prekeyRepresentation)","signing":"\(identity.signingRepresentation)","userId":"\(identity.id)"}
            """.utf8
        )
        return SymmetricKey(data: Data(SHA256.hash(data: material)))
    }
}
