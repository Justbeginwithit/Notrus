import CryptoKit
import Foundation

enum IdentityStoreError: LocalizedError {
    case corruptCatalog
    case missingIdentity
    case unavailableIdentity(String)

    var errorDescription: String? {
        switch self {
        case .corruptCatalog:
            return "The local account catalog on this Mac could not be read."
        case .missingIdentity:
            return "No local macOS identity was found on this machine."
        case .unavailableIdentity(let details):
            return "A stored Mac account could not reopen its local key material. \(details)"
        }
    }
}

final class IdentityStore {
    private let directory: URL
    private let catalogURL: URL
    private let legacyIdentityURL: URL
    private let usesLegacyCompatibility: Bool
    private let deviceSecretStore: DeviceSecretStore
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

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
        self.catalogURL = root.appendingPathComponent("accounts.json")
        self.legacyIdentityURL = root.appendingPathComponent("identity.json")
        self.usesLegacyCompatibility = useLegacy
        self.deviceSecretStore = deviceSecretStore
        SensitiveStoragePolicy.prepareDirectory(root)
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    func hasStoredProfiles() -> Bool {
        FileManager.default.fileExists(atPath: catalogURL.path) || FileManager.default.fileExists(atPath: legacyIdentityURL.path)
    }

    func loadCatalog() throws -> IdentityCatalog {
        if FileManager.default.fileExists(atPath: catalogURL.path) {
            let rawData = try Data(contentsOf: catalogURL)
            if let envelope = try? decoder.decode(IdentityCatalogEnvelope.self, from: rawData) {
                let combined = try NotrusCrypto.base64Data(envelope.iv) + NotrusCrypto.base64Data(envelope.ciphertext)
                let sealedBox = try AES.GCM.SealedBox(combined: combined)
                let plaintext = try AES.GCM.open(
                    sealedBox,
                    using: try deviceSecretStore.loadExistingCatalogKey(),
                    authenticating: Data((usesLegacyCompatibility ? "aegis-native-account-catalog-v1" : "notrus-native-account-catalog-v1").utf8)
                )
                return try normalizedCatalog(from: plaintext)
            }
            return try normalizedCatalog(from: rawData)
        }

        if FileManager.default.fileExists(atPath: legacyIdentityURL.path) {
            let legacyIdentity = try decoder.decode(LocalIdentity.self, from: Data(contentsOf: legacyIdentityURL))
            let normalized = try normalize(legacyIdentity)
            let migrated = IdentityCatalog(version: 1, activeIdentityId: normalized.id, identities: [normalized])
            try saveCatalog(migrated)
            try? FileManager.default.removeItem(at: legacyIdentityURL)
            return migrated
        }

        return IdentityCatalog(version: 1, activeIdentityId: nil, identities: [])
    }

    func loadIdentity() throws -> LocalIdentity? {
        let catalog = try loadCatalog()
        if let activeIdentityId = catalog.activeIdentityId {
            return catalog.identities.first(where: { $0.id == activeIdentityId })
        }
        return catalog.identities.first
    }

    func loadIdentities() throws -> [LocalIdentity] {
        try loadCatalog().identities
    }

    func saveIdentity(_ identity: LocalIdentity, makeActive: Bool = true) throws -> IdentityCatalog {
        let normalized = try normalize(identity)
        var identities = try loadIdentities()

        if let existingIndex = identities.firstIndex(where: { $0.id == normalized.id }) {
            identities[existingIndex] = normalized
        } else {
            identities.append(normalized)
        }

        let catalog = IdentityCatalog(
            version: 1,
            activeIdentityId: makeActive ? normalized.id : (try loadCatalog().activeIdentityId ?? normalized.id),
            identities: sortIdentities(identities)
        )
        try saveCatalog(catalog)
        return catalog
    }

    func setActiveIdentity(_ userId: String) throws -> IdentityCatalog {
        let catalog = try loadCatalog()
        guard catalog.identities.contains(where: { $0.id == userId }) else {
            throw IdentityStoreError.missingIdentity
        }

        let updated = IdentityCatalog(
            version: 1,
            activeIdentityId: userId,
            identities: catalog.identities
        )
        try saveCatalog(updated)
        return updated
    }

    func deleteIdentity(userId: String) throws -> IdentityCatalog {
        let catalog = try loadCatalog()
        let remaining = catalog.identities.filter { $0.id != userId }
        let nextActiveId: String?

        if catalog.activeIdentityId == userId {
            nextActiveId = remaining.first?.id
        } else {
            nextActiveId = catalog.activeIdentityId
        }

        let updated = IdentityCatalog(
            version: 1,
            activeIdentityId: nextActiveId,
            identities: remaining
        )
        try saveCatalog(updated)
        return updated
    }

    func resetAll() throws {
        if FileManager.default.fileExists(atPath: catalogURL.path) {
            try FileManager.default.removeItem(at: catalogURL)
        }
        if FileManager.default.fileExists(atPath: legacyIdentityURL.path) {
            try FileManager.default.removeItem(at: legacyIdentityURL)
        }
    }

    private func normalizedCatalog(from data: Data) throws -> IdentityCatalog {
        let decodedCatalog: IdentityCatalog
        if let catalog = try? decoder.decode(IdentityCatalog.self, from: data) {
            decodedCatalog = catalog
        } else if let legacyIdentity = try? decoder.decode(LocalIdentity.self, from: data) {
            decodedCatalog = IdentityCatalog(version: 1, activeIdentityId: legacyIdentity.id, identities: [legacyIdentity])
        } else {
            throw IdentityStoreError.corruptCatalog
        }

        let normalizedIdentities = try sortIdentities(decodedCatalog.identities.map(normalize))
        let activeIdentityId = normalizedIdentities.contains(where: { $0.id == decodedCatalog.activeIdentityId })
            ? decodedCatalog.activeIdentityId
            : normalizedIdentities.first?.id
        let normalizedCatalog = IdentityCatalog(
            version: 1,
            activeIdentityId: activeIdentityId,
            identities: normalizedIdentities
        )

        if normalizedCatalog != decodedCatalog {
            try saveCatalog(normalizedCatalog)
        }

        return normalizedCatalog
    }

    private func normalize(_ identity: LocalIdentity) throws -> LocalIdentity {
        do {
            return try NotrusCrypto.restoreIdentity(identity)
        } catch {
            throw IdentityStoreError.unavailableIdentity(error.localizedDescription)
        }
    }

    private func saveCatalog(_ catalog: IdentityCatalog) throws {
        let plaintext = try encoder.encode(catalog)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: try deviceSecretStore.loadOrCreateCatalogKey(),
            nonce: AES.GCM.Nonce(data: NotrusCrypto.randomData(count: 12)),
            authenticating: Data((usesLegacyCompatibility ? "aegis-native-account-catalog-v1" : "notrus-native-account-catalog-v1").utf8)
        )
        guard let combined = sealed.combined else {
            throw IdentityStoreError.corruptCatalog
        }

        let envelope = IdentityCatalogEnvelope(
            version: 1,
            iv: combined.prefix(12).base64EncodedString(),
            ciphertext: combined.dropFirst(12).base64EncodedString()
        )
        let data = try encoder.encode(envelope)
        try data.write(to: catalogURL, options: .atomic)
        SensitiveStoragePolicy.prepareFile(catalogURL)
    }

    private func sortIdentities(_ identities: [LocalIdentity]) -> [LocalIdentity] {
        identities.sorted { left, right in
            if left.displayName != right.displayName {
                return left.displayName.localizedCaseInsensitiveCompare(right.displayName) == .orderedAscending
            }
            return left.username.localizedCaseInsensitiveCompare(right.username) == .orderedAscending
        }
    }
}
