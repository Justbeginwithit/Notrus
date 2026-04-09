import CryptoKit
import Foundation

enum SecurityStateStoreError: LocalizedError {
    case corruptState
    case unsupportedVersion

    var errorDescription: String? {
        switch self {
        case .corruptState:
            return "The local contact verification state on this Mac could not be opened."
        case .unsupportedVersion:
            return "The local contact verification state version is not supported by this build."
        }
    }
}

final class SecurityStateStore {
    private let directory: URL
    private let usesLegacyCompatibility: Bool
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let deviceSecretStore: DeviceSecretStore

    init(
        directory: URL? = nil,
        deviceSecretStore: DeviceSecretStore = DeviceSecretStore()
    ) {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let currentRoot = directory ?? appSupport.appendingPathComponent("NotrusMac", isDirectory: true)
        let legacyRoot = directory == nil ? appSupport.appendingPathComponent("AegisMac", isDirectory: true) : currentRoot
        let useLegacy = directory == nil && FileManager.default.fileExists(atPath: legacyRoot.path) && FileManager.default.fileExists(atPath: currentRoot.path) == false
        let root = useLegacy ? legacyRoot : currentRoot
        self.directory = root
        self.usesLegacyCompatibility = useLegacy
        self.deviceSecretStore = deviceSecretStore
        SensitiveStoragePolicy.prepareDirectory(root)
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    func loadState(for identity: LocalIdentity) throws -> ContactSecurityState {
        let url = storeURL(for: identity.id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return ContactSecurityState(version: 1, contacts: [:], events: [])
        }

        let envelope = try decoder.decode(SecurityStateEnvelope.self, from: Data(contentsOf: url))
        guard envelope.version == 1 else {
            throw SecurityStateStoreError.unsupportedVersion
        }

        let sealedBox = try AES.GCM.SealedBox(
            combined: try NotrusCrypto.base64Data(envelope.iv) + NotrusCrypto.base64Data(envelope.ciphertext)
        )
        let plaintext = try AES.GCM.open(
            sealedBox,
            using: try deviceSecretStore.existingDerivedKey(purpose: "contact-security-state", userId: identity.id),
            authenticating: Data((usesLegacyCompatibility ? "aegis-mac-contact-security-state-v1" : "notrus-mac-contact-security-state-v1").utf8)
        )
        return try decoder.decode(ContactSecurityState.self, from: plaintext)
    }

    func saveState(_ state: ContactSecurityState, for identity: LocalIdentity) throws {
        let plaintext = try encoder.encode(state)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: try deviceSecretStore.derivedKey(purpose: "contact-security-state", userId: identity.id),
            nonce: AES.GCM.Nonce(data: NotrusCrypto.randomData(count: 12)),
            authenticating: Data((usesLegacyCompatibility ? "aegis-mac-contact-security-state-v1" : "notrus-mac-contact-security-state-v1").utf8)
        )
        guard let combined = sealed.combined else {
            throw SecurityStateStoreError.corruptState
        }

        let envelope = SecurityStateEnvelope(
            ciphertext: combined.dropFirst(12).base64EncodedString(),
            iv: combined.prefix(12).base64EncodedString(),
            version: 1
        )
        let data = try encoder.encode(envelope)
        let url = storeURL(for: identity.id)
        try data.write(to: url, options: .atomic)
        SensitiveStoragePolicy.prepareFile(url)
    }

    func deleteState(for userId: String) throws {
        let url = storeURL(for: userId)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        try FileManager.default.removeItem(at: url)
    }

    func resetAll() throws {
        let urls = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        for url in urls where url.lastPathComponent.hasPrefix("contact-security-") {
            try FileManager.default.removeItem(at: url)
        }
    }

    private func storeURL(for userId: String) -> URL {
        directory.appendingPathComponent("contact-security-\(userId).json")
    }
}
