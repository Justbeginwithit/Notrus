import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum DeviceSecretStoreError: LocalizedError, Equatable {
    case authenticationFailed
    case biometryChanged
    case keychain(OSStatus)
    case locked
    case missingVaultKey
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .authenticationFailed:
            return "Notrus could not unlock the device-protected vault."
        case .biometryChanged:
            return "This Mac's biometric set changed, so the local vault must be re-approved before protected secrets can be used again."
        case .keychain(let status):
            return "The local device-protection key could not be accessed (OSStatus \(status))."
        case .locked:
            return "Unlock the local Notrus vault on this Mac before continuing."
        case .missingVaultKey:
            return "This Mac no longer has the local vault key for the stored Notrus data. Reset the local vault and import a recovery archive, or create a new profile."
        case .userCancelled:
            return "The local unlock request was cancelled."
        }
    }
}

enum DeviceSecretPersistenceMode: Equatable {
    case automatic
    case keychainPreferred
    case fileOnly
}

final class DeviceSecretStore {
    private static let currentService = "com.notrus.mac"
    private static let defaultAccountName = "local-account-catalog-key"
    private static let invalidOwnerEditStatus: OSStatus = -25244
    private static let noKeychainAvailableStatus: OSStatus = -25291

    private struct MetadataEnvelope: Codable {
        let version: Int
        let iv: String
        let ciphertext: String
    }

    private let service: String
    private let account: String
    private let fixedData: Data?
    private let metadataDirectory: URL
    private let fallbackVaultKeyURL: URL
    private let unlockSessionLifetime: TimeInterval
    private let persistenceMode: DeviceSecretPersistenceMode

    private var cachedData: Data?
    private var unlockedUntil: Date?

    static func shouldUseFileFallback(forKeychainStatus status: OSStatus) -> Bool {
        status == errSecMissingEntitlement ||
        status == invalidOwnerEditStatus ||
        status == noKeychainAvailableStatus
    }

    static func shouldTreatMissingKeychainItemAsUnavailable(_ status: OSStatus) -> Bool {
        status == errSecItemNotFound || shouldUseFileFallback(forKeychainStatus: status)
    }

    static func shouldIgnoreKeychainDeleteStatus(_ status: OSStatus) -> Bool {
        status == errSecSuccess || status == errSecItemNotFound || shouldUseFileFallback(forKeychainStatus: status)
    }

    init(
        service: String = DeviceSecretStore.currentService,
        account: String = DeviceSecretStore.defaultAccountName,
        fixedData: Data? = nil,
        metadataDirectory: URL? = nil,
        unlockSessionLifetime: TimeInterval = 300,
        persistenceMode: DeviceSecretPersistenceMode = .automatic
    ) {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let root = metadataDirectory ?? appSupport
            .appendingPathComponent("NotrusMac", isDirectory: true)
            .appendingPathComponent("device-metadata", isDirectory: true)
            .appendingPathComponent(Self.storageNamespace(service: service, account: account), isDirectory: true)

        self.service = service
        self.account = account
        self.fixedData = fixedData
        self.metadataDirectory = root
        self.fallbackVaultKeyURL = root.appendingPathComponent("vault-key.bin")
        self.unlockSessionLifetime = unlockSessionLifetime
        self.persistenceMode = Self.resolvePersistenceMode(persistenceMode)
        SensitiveStoragePolicy.prepareDirectory(root)
    }

    var unlockMethodDescription: String {
        "macOS device authentication"
    }

    func isUnlocked() -> Bool {
        guard fixedData == nil else {
            return true
        }
        guard let unlockedUntil, unlockedUntil > Date(), cachedData != nil else {
            return false
        }
        return true
    }

    func lock() {
        cachedData = nil
        unlockedUntil = nil
    }

    @discardableResult
    func unlock(reason: String) throws -> String {
        _ = try loadOrCreateData(reason: reason, requireUnlocked: false)
        return unlockMethodDescription
    }

    @discardableResult
    func reauthenticate(reason: String) throws -> String {
        lock()
        return try unlock(reason: reason)
    }

    @MainActor
    @discardableResult
    func unlockInteractively(reason: String, allowCreation: Bool = true) async throws -> String {
        guard fixedData == nil else {
            return unlockMethodDescription
        }

        if isUnlocked() {
            return unlockMethodDescription
        }

        try await performInteractiveAuthentication(reason: reason)

        if let loaded = try loadStoredData() {
            cache(loaded)
            return unlockMethodDescription
        }

        guard allowCreation else {
            throw DeviceSecretStoreError.missingVaultKey
        }

        let created = NotrusCrypto.randomData(count: 32)
        try saveData(created)
        cache(created)
        return unlockMethodDescription
    }

    @MainActor
    @discardableResult
    func reauthenticateInteractively(reason: String, allowCreation: Bool = false) async throws -> String {
        lock()
        return try await unlockInteractively(reason: reason, allowCreation: allowCreation)
    }

    func loadOrCreateCatalogKey(reason: String = "Unlock the local Notrus vault on this Mac.") throws -> SymmetricKey {
        SymmetricKey(data: try loadOrCreateData(reason: reason, requireUnlocked: true))
    }

    func loadExistingCatalogKey(reason: String = "Unlock the local Notrus vault on this Mac.") throws -> SymmetricKey {
        SymmetricKey(data: try loadExistingData(reason: reason))
    }

    func derivedKey(
        purpose: String,
        userId: String? = nil,
        reason: String = "Unlock the local Notrus vault on this Mac."
    ) throws -> SymmetricKey {
        let base = try SymmetricKey(data: loadOrCreateData(reason: reason, requireUnlocked: true))
        let scope = userId.map { "\(purpose):\($0)" } ?? purpose
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: base,
            salt: Data("notrus-mac-device-scope".utf8),
            info: Data(scope.utf8),
            outputByteCount: 32
        )
    }

    func existingDerivedKey(
        purpose: String,
        userId: String? = nil,
        reason: String = "Unlock the local Notrus vault on this Mac."
    ) throws -> SymmetricKey {
        let base = try SymmetricKey(data: loadExistingData(reason: reason))
        let scope = userId.map { "\(purpose):\($0)" } ?? purpose
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: base,
            salt: Data("notrus-mac-device-scope".utf8),
            info: Data(scope.utf8),
            outputByteCount: 32
        )
    }

    func appInstanceIdentifier(reason: String = "Unlock the local Notrus vault on this Mac.") throws -> String {
        let base = try loadOrCreateData(reason: reason, requireUnlocked: true)
        let digest = SHA256.hash(data: Data("notrus-mac-app-instance-v1".utf8) + base)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    func unlockedAppInstanceIdentifier() -> String? {
        guard isUnlocked() else {
            return nil
        }
        return try? appInstanceIdentifier(reason: "Reuse the unlocked local Notrus vault session on this Mac.")
    }

    func deviceDescriptor(reason: String = "Unlock the local Notrus vault on this Mac.") throws -> DeviceDescriptor {
        _ = try loadOrCreateData(reason: reason, requireUnlocked: true)
        let privateKey = try loadOrCreateDeviceSigningKey()
        let label = Host.current().localizedName ?? "This Mac"
        return DeviceDescriptor(
            createdAt: try loadOrCreateDeviceCreatedAt(),
            id: try loadOrCreateDeviceIdentifier(),
            label: label,
            platform: "macos",
            publicJwk: try NotrusCrypto.jwk(from: privateKey.publicKey.x963Representation),
            riskLevel: "unknown",
            storageMode: deviceKeyStorageMode(for: privateKey)
        )
    }

    func unlockedDeviceDescriptor() -> DeviceDescriptor? {
        guard isUnlocked() else {
            return nil
        }
        return try? deviceDescriptor(reason: "Reuse the unlocked local Notrus vault session on this Mac.")
    }

    func inventorySnapshot() -> LocalDeviceInventory {
        let appInstanceId = unlockedAppInstanceIdentifier()
        let deviceDescriptor = unlockedDeviceDescriptor()
        return LocalDeviceInventory(
            vaultStorageMode: fallbackVaultKeyExists ? "file-fallback" : "data-protection-keychain",
            vaultKeyPresent: fallbackVaultKeyExists || keychainVaultKeyExists(),
            metadataDirectoryLabel: metadataDirectory.lastPathComponent,
            appInstanceId: appInstanceId,
            deviceId: deviceDescriptor?.id,
            deviceKeyStorageMode: deviceDescriptor?.storageMode,
            profileCount: 0,
            profiles: []
        )
    }

    func signDeviceAction(_ payload: String, reason: String = "Unlock the local Notrus vault on this Mac.") throws -> String {
        _ = try loadOrCreateData(reason: reason, requireUnlocked: true)
        let signature = try loadOrCreateDeviceSigningKey().signature(for: Data(payload.utf8))
        return signature.derRepresentation.base64EncodedString()
    }

    func generation(for scope: String) throws -> Int {
        guard let data = try loadMetadata(for: scope) else {
            return 0
        }
        return Int(String(decoding: data, as: UTF8.self)) ?? 0
    }

    func storeGeneration(_ generation: Int, for scope: String) throws {
        try saveMetadata(Data(String(generation).utf8), for: scope)
    }

    private func loadOrCreateData(reason: String, requireUnlocked: Bool) throws -> Data {
        if let fixedData {
            return fixedData
        }

        if
            let cachedData,
            let unlockedUntil,
            unlockedUntil > Date()
        {
            return cachedData
        }

        if requireUnlocked {
            throw DeviceSecretStoreError.locked
        }

        if let existing = try loadStoredData() {
            cache(existing)
            return existing
        }

        let created = NotrusCrypto.randomData(count: 32)
        try saveData(created)
        cache(created)
        return created
    }

    private func loadExistingData(reason: String) throws -> Data {
        if let fixedData {
            return fixedData
        }

        if
            let cachedData,
            let unlockedUntil,
            unlockedUntil > Date()
        {
            return cachedData
        }

        if let existing = try loadStoredData() {
            cache(existing)
            return existing
        }

        throw DeviceSecretStoreError.missingVaultKey
    }

    private func cache(_ data: Data) {
        cachedData = data
        unlockedUntil = Date().addingTimeInterval(unlockSessionLifetime)
    }

    private func loadStoredData() throws -> Data? {
        if shouldUseFileOnlyVaultStorage {
            return try loadFallbackVaultKey()
        }

        let primary = try loadKeychainData(service: service, account: account)
        if let primary {
            return primary
        }
        return try loadFallbackVaultKey()
    }

    private func mapLoadedData(status: OSStatus, item: CFTypeRef?) throws -> Data? {
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound, errSecParam:
            return nil
        case errSecUserCanceled:
            throw DeviceSecretStoreError.userCancelled
        case errSecAuthFailed:
            throw DeviceSecretStoreError.authenticationFailed
        case errSecInteractionNotAllowed:
            throw DeviceSecretStoreError.locked
        case errSecDecode:
            throw DeviceSecretStoreError.biometryChanged
        default:
            throw DeviceSecretStoreError.keychain(status)
        }
    }

    @MainActor
    private func performInteractiveAuthentication(reason: String) async throws {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedCancelTitle = "Cancel"

        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            if let policyError {
                throw Self.mapAuthenticationError(policyError)
            }
            throw DeviceSecretStoreError.authenticationFailed
        }

        try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    continuation.resume(returning: ())
                } else {
                    continuation.resume(throwing: Self.mapAuthenticationError(error))
                }
            }
        }
    }

    private static func mapAuthenticationError(_ error: Error?) -> DeviceSecretStoreError {
        guard let laError = error as? LAError else {
            return .authenticationFailed
        }

        switch laError.code {
        case .userCancel, .systemCancel, .appCancel:
            return .userCancelled
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout:
            return .authenticationFailed
        case .invalidContext, .notInteractive:
            return .locked
        default:
            return .authenticationFailed
        }
    }

    private func saveData(_ data: Data) throws {
        if shouldUseFileOnlyVaultStorage {
            try saveFallbackVaultKey(data)
            return
        }

        let deleteStatus = SecItemDelete(
            keychainQuery(service: service, account: account) as CFDictionary
        )
        if Self.shouldUseFileFallback(forKeychainStatus: deleteStatus) {
            try saveFallbackVaultKey(data)
            return
        }
        guard Self.shouldIgnoreKeychainDeleteStatus(deleteStatus) else {
            throw DeviceSecretStoreError.keychain(deleteStatus)
        }

        let status = SecItemAdd(
            [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
                kSecUseDataProtectionKeychain: true,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData: data
            ] as CFDictionary,
            nil
        )
        if Self.shouldUseFileFallback(forKeychainStatus: status) {
            try saveFallbackVaultKey(data)
            return
        }
        guard status == errSecSuccess else {
            throw DeviceSecretStoreError.keychain(status)
        }
        try? FileManager.default.removeItem(at: fallbackVaultKeyURL)
    }

    private func loadMetadata(for scope: String) throws -> Data? {
        let url = metadataURL(for: scope)
        if FileManager.default.fileExists(atPath: url.path) {
            do {
                return try openMetadata(at: url, scope: scope)
            } catch DeviceSecretStoreError.missingVaultKey {
                throw DeviceSecretStoreError.missingVaultKey
            } catch DeviceSecretStoreError.locked {
                throw DeviceSecretStoreError.locked
            } catch {
                try? FileManager.default.removeItem(at: url)
                return nil
            }
        }
        return nil
    }

    private func saveMetadata(_ data: Data, for scope: String) throws {
        try writeMetadata(data, to: metadataURL(for: scope), scope: scope)
    }

    private func metadataAccount(for scope: String) -> String {
        "\(account).\(scope)"
    }

    func purgeAllLocalSecrets() throws {
        if fixedData == nil {
            try purgeKeychainItems(forService: service)
        }

        if FileManager.default.fileExists(atPath: metadataDirectory.path) {
            try? FileManager.default.removeItem(at: metadataDirectory)
        }
        SensitiveStoragePolicy.prepareDirectory(metadataDirectory)
        lock()
    }

    private func loadOrCreateDeviceIdentifier() throws -> String {
        if let existing = try loadMetadata(for: "device.id") {
            let identifier = String(decoding: existing, as: UTF8.self)
            if !identifier.isEmpty {
                return identifier
            }
        }

        let identifier = UUID().uuidString.lowercased()
        try saveMetadata(Data(identifier.utf8), for: "device.id")
        return identifier
    }

    private func loadOrCreateDeviceCreatedAt() throws -> String {
        if let existing = try loadMetadata(for: "device.createdAt") {
            let createdAt = String(decoding: existing, as: UTF8.self)
            if !createdAt.isEmpty {
                return createdAt
            }
        }

        let createdAt = ISO8601DateFormatter().string(from: Date())
        try saveMetadata(Data(createdAt.utf8), for: "device.createdAt")
        return createdAt
    }

    private func loadOrCreateDeviceSigningKey() throws -> SigningPrivateKeyHandle {
        if let existing = try loadMetadata(for: "device.signing") {
            return try NotrusCrypto.loadSigningPrivateKey(String(decoding: existing, as: UTF8.self))
        }

        let key: SigningPrivateKeyHandle
        if let secureKey = try? SecureEnclave.P256.Signing.PrivateKey() {
            key = .secureEnclave(secureKey)
        } else {
            key = .software(P256.Signing.PrivateKey())
        }

        let representation: Data
        switch key {
        case .secureEnclave(let secureKey):
            representation = Data(secureKey.dataRepresentation.base64EncodedString().utf8)
        case .software(let softwareKey):
            representation = Data(softwareKey.rawRepresentation.base64EncodedString().utf8)
        }
        try saveMetadata(representation, for: "device.signing")
        return key
    }

    private func deviceKeyStorageMode(for key: SigningPrivateKeyHandle) -> String {
        switch key {
        case .secureEnclave:
            return "secure-enclave-device-key"
        case .software:
            return "keychain-device-key"
        }
    }

    private func supportsBiometricUnlock() -> Bool {
        guard fixedData == nil else {
            return false
        }

        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    private static func storageNamespace(service: String, account: String) -> String {
        let digest = SHA256.hash(data: Data("\(service)|\(account)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func metadataURL(for scope: String) -> URL {
        let digest = SHA256.hash(data: Data(scope.utf8))
        let fileName = digest.map { String(format: "%02x", $0) }.joined() + ".json"
        return metadataDirectory.appendingPathComponent(fileName)
    }

    private func metadataKey(allowCreation: Bool) throws -> SymmetricKey {
        let baseData = try (allowCreation
            ? loadOrCreateData(reason: "Unlock the local Notrus vault on this Mac.", requireUnlocked: true)
            : loadExistingData(reason: "Unlock the local Notrus vault on this Mac."))
        let base = SymmetricKey(data: baseData)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: base,
            salt: Data("notrus-mac-device-metadata".utf8),
            info: Data("\(service)|\(account)".utf8),
            outputByteCount: 32
        )
    }

    private func metadataAAD(for scope: String) -> Data {
        Data("notrus-mac-device-metadata-v1|\(scope)".utf8)
    }

    private func loadFallbackVaultKey() throws -> Data? {
        if FileManager.default.fileExists(atPath: fallbackVaultKeyURL.path) {
            return try Data(contentsOf: fallbackVaultKeyURL)
        }
        return nil
    }

    private func saveFallbackVaultKey(_ data: Data) throws {
        SensitiveStoragePolicy.prepareDirectory(metadataDirectory)
        try data.write(to: fallbackVaultKeyURL, options: .atomic)
        SensitiveStoragePolicy.prepareFile(fallbackVaultKeyURL)
    }

    private func openMetadata(at url: URL, scope: String) throws -> Data {
        let envelope = try JSONDecoder().decode(MetadataEnvelope.self, from: Data(contentsOf: url))
        guard envelope.version == 1 else {
            throw DeviceSecretStoreError.authenticationFailed
        }
        let iv = try NotrusCrypto.base64Data(envelope.iv)
        let ciphertext = try NotrusCrypto.base64Data(envelope.ciphertext)
        let sealedBox = try AES.GCM.SealedBox(combined: iv + ciphertext)
        return try AES.GCM.open(
            sealedBox,
            using: metadataKey(allowCreation: false),
            authenticating: metadataAAD(for: scope)
        )
    }

    private func writeMetadata(_ data: Data, to url: URL, scope: String) throws {
        try FileManager.default.createDirectory(at: metadataDirectory, withIntermediateDirectories: true)
        SensitiveStoragePolicy.prepareDirectory(metadataDirectory)
        let sealed = try AES.GCM.seal(
            data,
            using: metadataKey(allowCreation: true),
            nonce: AES.GCM.Nonce(data: NotrusCrypto.randomData(count: 12)),
            authenticating: metadataAAD(for: scope)
        )
        guard let combined = sealed.combined else {
            throw DeviceSecretStoreError.authenticationFailed
        }
        let envelope = MetadataEnvelope(
            version: 1,
            iv: combined.prefix(12).base64EncodedString(),
            ciphertext: combined.dropFirst(12).base64EncodedString()
        )
        let encoded = try JSONEncoder().encode(envelope)
        try encoded.write(to: url, options: .atomic)
        SensitiveStoragePolicy.prepareFile(url)
    }

    private func loadKeychainData(service: String, account: String) throws -> Data? {
        let query = keychainQuery(
            service: service,
            account: account,
            returnData: true,
            matchLimit: kSecMatchLimitOne
        )

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if Self.shouldTreatMissingKeychainItemAsUnavailable(status) {
            return nil
        }
        return try mapLoadedData(status: status, item: item)
    }

    private func purgeKeychainItems(forService service: String) throws {
        if shouldUseFileOnlyVaultStorage {
            return
        }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if Self.shouldUseFileFallback(forKeychainStatus: status) {
            return
        }
        if status != errSecSuccess && status != errSecItemNotFound {
            throw DeviceSecretStoreError.keychain(status)
        }

        if let items = result as? [[CFString: Any]] {
            for item in items {
                guard let itemAccount = item[kSecAttrAccount] as? String else {
                    continue
                }
                if itemAccount == account || itemAccount.hasPrefix("\(account).") {
                    let deleteStatus = SecItemDelete(
                        keychainQuery(
                            service: service,
                            account: itemAccount
                        ) as CFDictionary
                    )
                    if !Self.shouldIgnoreKeychainDeleteStatus(deleteStatus) {
                        throw DeviceSecretStoreError.keychain(deleteStatus)
                    }
                }
            }
        }
    }

    private var shouldUseFileOnlyVaultStorage: Bool {
        fixedData == nil && persistenceMode == .fileOnly
    }

    private var fallbackVaultKeyExists: Bool {
        FileManager.default.fileExists(atPath: fallbackVaultKeyURL.path)
    }

    private func keychainVaultKeyExists() -> Bool {
        guard !shouldUseFileOnlyVaultStorage else {
            return false
        }
        let query = keychainQuery(
            service: service,
            account: account,
            returnAttributes: true,
            matchLimit: kSecMatchLimitOne
        )
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if Self.shouldUseFileFallback(forKeychainStatus: status) {
            return false
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    private static func resolvePersistenceMode(_ mode: DeviceSecretPersistenceMode) -> DeviceSecretPersistenceMode {
        switch mode {
        case .automatic:
            if ProcessInfo.processInfo.environment["NOTRUS_LOCAL_VAULT_MODE"] == "file" {
                return .fileOnly
            }
            return .keychainPreferred
        case .keychainPreferred, .fileOnly:
            return mode
        }
    }

    private func keychainQuery(
        service: String,
        account: String,
        returnData: Bool = false,
        returnAttributes: Bool = false,
        matchLimit: CFString? = nil
    ) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true
        ]

        if returnData {
            query[kSecReturnData] = true
        }
        if returnAttributes {
            query[kSecReturnAttributes] = true
        }
        if let matchLimit {
            query[kSecMatchLimit] = matchLimit
        }

        return query
    }
}
