import Foundation
import XCTest
@testable import NotrusMac

final class NotrusMacCheckpointTests: XCTestCase {
    private var temporaryDirectory: URL!
    private var relayProcess: Process?

    override func setUpWithError() throws {
        temporaryDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        relayProcess?.terminate()
        relayProcess = nil
        if let temporaryDirectory {
            try? FileManager.default.removeItem(at: temporaryDirectory)
        }
    }

    func testNewIdentitiesUsePortableStorageAndCanBeRestored() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let restored = try NotrusCrypto.restoreIdentity(identity)

        XCTAssertEqual(identity.storageMode, "device-vault-v2")
        XCTAssertEqual(restored.fingerprint, identity.fingerprint)
        XCTAssertEqual(restored.recoveryPublicJwk, identity.recoveryPublicJwk)
        XCTAssertEqual(restored.signingPublicJwk, identity.signingPublicJwk)
        XCTAssertEqual(restored.encryptionPublicJwk, identity.encryptionPublicJwk)
        XCTAssertEqual(restored.prekeyPublicJwk, identity.prekeyPublicJwk)
        XCTAssertFalse(restored.prekeySignature.isEmpty)

        let relayUser = RelayUser(
            id: restored.id,
            username: restored.username,
            displayName: restored.displayName,
            fingerprint: restored.fingerprint,
            prekeyCreatedAt: restored.prekeyCreatedAt,
            prekeyFingerprint: restored.prekeyFingerprint,
            prekeyPublicJwk: restored.prekeyPublicJwk,
            prekeySignature: restored.prekeySignature,
            signingPublicJwk: restored.signingPublicJwk,
            encryptionPublicJwk: restored.encryptionPublicJwk,
            createdAt: restored.createdAt,
            updatedAt: restored.createdAt
        )

        XCTAssertTrue(try NotrusCrypto.verifySignedPrekeyRecord(relayUser))
    }

    func testRecoveryArchiveRoundTripsPortableAccountAndThreadState() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Backup", username: "backup")
        let threadState = ThreadStoreRecord(
            bootstrapState: nil,
            currentState: nil,
            groupTreeState: GroupTreeThreadState(
                currentEpoch: 2,
                epochMessageCount: 4,
                epochSecrets: ["2": Data("secret".utf8).base64EncodedString()],
                memberIds: [identity.id, "peer"],
                pendingCommit: nil,
                protocolField: "group-tree-v3",
                senderStates: [identity.id: GroupSenderState(chainKey: Data("chain".utf8).base64EncodedString(), counter: 4)],
                threadId: "thread-1",
                transcriptHash: "transcript",
                treeHash: "tree"
            ),
            lastProcessedMessageId: "message-1",
            messageCache: ["message-1": CachedMessageState(body: "hi", hidden: false, status: "ok")],
            pendingSentStates: [:],
            processedMessageCount: 1,
            protocolField: "group-tree-v3"
        )
        let archive = PortableAccountArchive(
            version: 1,
            exportedAt: NotrusCrypto.isoNow(),
            identity: identity,
            threadRecords: ["thread-1": threadState]
        )

        let sealed = try NotrusCrypto.sealPortableArchive(archive, passphrase: "correct horse battery staple")
        let opened = try NotrusCrypto.openPortableArchive(sealed, passphrase: "correct horse battery staple")

        XCTAssertEqual(opened.identity, identity)
        XCTAssertEqual(opened.threadRecords, archive.threadRecords)
    }

    func testAccountPortabilityExportArchiveWritesChosenFile() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Export", username: "export")
        let destination = temporaryDirectory.appendingPathComponent("chosen-export.json")

        try AccountPortability.exportArchive(
            identity: identity,
            threadRecords: [:],
            passphrase: "correct horse battery staple",
            to: destination
        )

        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.path))
        let reopened = try AccountPortability.importArchive(
            from: destination,
            passphrase: "correct horse battery staple"
        )
        guard case .portable(let archive) = reopened else {
            return XCTFail("Expected the exported Mac archive to reopen as a portable archive.")
        }
        XCTAssertEqual(archive.identity.id, identity.id)
    }

    func testAccountPortabilityImportsAndroidTransferArchive() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Android", username: "android")
        let transfer = RecoveryTransferArchive(
            version: 1,
            exportedAt: NotrusCrypto.isoNow(),
            sourcePlatform: "android",
            transferMode: "recovery-authorized-reset",
            identity: PortableArchiveIdentitySnapshot(identity: identity)
        )
        let sealed = try NotrusCrypto.sealArchivePayload(
            try JSONEncoder().encode(transfer),
            exportedAt: transfer.exportedAt,
            passphrase: "correct horse battery staple"
        )
        let destination = temporaryDirectory.appendingPathComponent("android-transfer.json")
        try JSONEncoder().encode(sealed).write(to: destination)

        let reopened = try AccountPortability.importArchive(
            from: destination,
            passphrase: "correct horse battery staple"
        )

        guard case .transfer(let archive) = reopened else {
            return XCTFail("Expected the Android recovery archive to reopen as a transfer archive.")
        }
        XCTAssertEqual(archive.sourcePlatform, "android")
        XCTAssertEqual(archive.identity.id, identity.id)
        XCTAssertEqual(archive.identity.username, identity.username)
    }

    func testRecoveryAuthorityCanBeRebuiltFromRecoveryRepresentation() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Recover", username: "recover")

        let rebuilt = try NotrusCrypto.recoveryAuthority(from: identity.recoveryRepresentation)

        XCTAssertEqual(rebuilt.fingerprint, identity.recoveryFingerprint)
        XCTAssertEqual(rebuilt.publicJwk, identity.recoveryPublicJwk)
    }

    func testAccountResetNormalizationMatchesRelaySanitizationRules() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Normalize", username: "normalize")
        let request = AccountResetRequest(
            createdAt: " 2026-04-11T12:00:00Z ",
            device: nil,
            displayName: " Normalize User ",
            encryptionPublicJwk: JWK(crv: " P-256 ", kty: " EC ", x: " \(identity.encryptionPublicJwk.x) ", y: " \(identity.encryptionPublicJwk.y) "),
            fingerprint: " \(identity.fingerprint) ",
            mlsKeyPackage: PublicMlsKeyPackage(ciphersuite: " MLS_128 ", keyPackage: " key-package "),
            prekeyCreatedAt: " \(identity.prekeyCreatedAt) ",
            prekeyFingerprint: " \(identity.prekeyFingerprint) ",
            prekeyPublicJwk: JWK(crv: " P-256 ", kty: " EC ", x: " \(identity.prekeyPublicJwk.x) ", y: " \(identity.prekeyPublicJwk.y) "),
            prekeySignature: " \(identity.prekeySignature) ",
            recoveryFingerprint: " \(identity.recoveryFingerprint) ",
            recoveryPublicJwk: JWK(crv: " P-256 ", kty: " EC ", x: " \(identity.recoveryPublicJwk.x) ", y: " \(identity.recoveryPublicJwk.y) "),
            recoverySignature: " signature ",
            signalBundle: PublicSignalBundle(
                deviceId: 1,
                identityKey: " id-key ",
                kyberPreKeyId: 1,
                kyberPreKeyPublic: " kyber-public ",
                kyberPreKeySignature: " kyber-signature ",
                preKeyId: 1,
                preKeyPublic: " prekey-public ",
                registrationId: 1,
                signedPreKeyId: 1,
                signedPreKeyPublic: " signed-prekey-public ",
                signedPreKeySignature: " signed-prekey-signature "
            ),
            signingPublicJwk: JWK(crv: " P-256 ", kty: " EC ", x: " \(identity.signingPublicJwk.x) ", y: " \(identity.signingPublicJwk.y) "),
            userId: " \(identity.id) ",
            username: " Normalize.User "
        )

        let normalized = NotrusCrypto.normalizedForRelay(request)

        XCTAssertEqual(normalized.createdAt, "2026-04-11T12:00:00Z")
        XCTAssertEqual(normalized.displayName, "Normalize User")
        XCTAssertEqual(normalized.username, "normalize.user")
        XCTAssertEqual(normalized.mlsKeyPackage?.keyPackage, "key-package")
        XCTAssertEqual(normalized.signalBundle?.identityKey, "id-key")
        XCTAssertEqual(normalized.signalBundle?.signedPreKeySignature, "signed-prekey-signature")
        XCTAssertEqual(normalized.recoverySignature, "signature")
        XCTAssertEqual(normalized.encryptionPublicJwk.x, identity.encryptionPublicJwk.x)
    }

    func testUpdatingStandardsDoesNotOverrideNativeFingerprintByDefault() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Native", username: "native")
        let updated = identity.updatingStandards(
            mlsKeyPackage: PublicMlsKeyPackage(ciphersuite: "suite", keyPackage: "package"),
            mlsState: "mls-state",
            signalBundle: PublicSignalBundle(
                deviceId: 1,
                identityKey: "id",
                kyberPreKeyId: 1,
                kyberPreKeyPublic: "kp",
                kyberPreKeySignature: "ks",
                preKeyId: 1,
                preKeyPublic: "pp",
                registrationId: 1,
                signedPreKeyId: 1,
                signedPreKeyPublic: "sp",
                signedPreKeySignature: "ss"
            ),
            signalState: "signal-state"
        )

        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
    }

    func testMacTransferResetIsAcceptedByRelay() async throws {
        let port = 3097
        try startRelay(port: port)

        let original = try NotrusCrypto.createIdentity(displayName: "Android Export", username: "android_export")
        let relay = RelayClient(origin: "http://127.0.0.1:\(port)")
        _ = try await relay.register(identity: original)

        let snapshot = PortableArchiveIdentitySnapshot(identity: original)
        let normalizedRecovery = try NotrusCrypto.recoveryAuthority(from: snapshot.recoveryRepresentation)
        let normalizedSnapshot = PortableArchiveIdentitySnapshot(
            id: snapshot.id,
            username: snapshot.username,
            displayName: snapshot.displayName,
            createdAt: snapshot.createdAt,
            recoveryFingerprint: normalizedRecovery.fingerprint,
            recoveryPublicJwk: normalizedRecovery.publicJwk,
            recoveryRepresentation: snapshot.recoveryRepresentation
        )
        let rebuiltBase = try NotrusCrypto.transferredIdentity(from: normalizedSnapshot)
        let standards = try StandardsCoreBridge.createIdentity(
            displayName: normalizedSnapshot.displayName,
            threadUserId: normalizedSnapshot.id,
            username: normalizedSnapshot.username
        )
        let rebuiltIdentity = rebuiltBase.updatingStandards(
            fingerprint: standards.fingerprint,
            mlsKeyPackage: standards.mlsKeyPackage,
            mlsState: standards.mlsState,
            signalBundle: standards.signalBundle,
            signalState: standards.signalState
        )
        let unsigned = NotrusCrypto.normalizedForRelay(AccountResetRequest(
            createdAt: NotrusCrypto.isoNow(),
            device: nil,
            displayName: rebuiltIdentity.displayName,
            encryptionPublicJwk: rebuiltIdentity.encryptionPublicJwk,
            fingerprint: rebuiltIdentity.fingerprint,
            mlsKeyPackage: rebuiltIdentity.standardsMlsKeyPackage,
            prekeyCreatedAt: rebuiltIdentity.prekeyCreatedAt,
            prekeyFingerprint: rebuiltIdentity.prekeyFingerprint,
            prekeyPublicJwk: rebuiltIdentity.prekeyPublicJwk,
            prekeySignature: rebuiltIdentity.prekeySignature,
            recoveryFingerprint: rebuiltIdentity.recoveryFingerprint,
            recoveryPublicJwk: rebuiltIdentity.recoveryPublicJwk,
            recoverySignature: "",
            signalBundle: rebuiltIdentity.standardsSignalBundle,
            signingPublicJwk: rebuiltIdentity.signingPublicJwk,
            userId: rebuiltIdentity.id,
            username: rebuiltIdentity.username
        ))
        let signed = NotrusCrypto.normalizedForRelay(AccountResetRequest(
            createdAt: unsigned.createdAt,
            device: unsigned.device,
            displayName: unsigned.displayName,
            encryptionPublicJwk: unsigned.encryptionPublicJwk,
            fingerprint: unsigned.fingerprint,
            mlsKeyPackage: unsigned.mlsKeyPackage,
            prekeyCreatedAt: unsigned.prekeyCreatedAt,
            prekeyFingerprint: unsigned.prekeyFingerprint,
            prekeyPublicJwk: unsigned.prekeyPublicJwk,
            prekeySignature: unsigned.prekeySignature,
            recoveryFingerprint: unsigned.recoveryFingerprint,
            recoveryPublicJwk: unsigned.recoveryPublicJwk,
            recoverySignature: try NotrusCrypto.signAccountReset(unsigned, recoveryRepresentation: snapshot.recoveryRepresentation),
            signalBundle: unsigned.signalBundle,
            signingPublicJwk: unsigned.signingPublicJwk,
            userId: unsigned.userId,
            username: unsigned.username
        ))

        let response = try await relay.resetAccount(signed)

        XCTAssertEqual(response.user.id, rebuiltIdentity.id)
        XCTAssertEqual(response.user.username, rebuiltIdentity.username)
    }

    private func startRelay(port: Int) throws {
        let storePath = temporaryDirectory.appendingPathComponent("relay-store.json")
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["node", "server.js"]
        process.currentDirectoryURL = repositoryRoot
        var environment = ProcessInfo.processInfo.environment
        environment["HOST"] = "127.0.0.1"
        environment["NOTRUS_STORE_PATH"] = storePath.path
        environment["PORT"] = "\(port)"
        process.environment = environment
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        relayProcess = process

        let healthURL = URL(string: "http://127.0.0.1:\(port)/api/health")!
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if let data = try? Data(contentsOf: healthURL),
               let payload = try? JSONDecoder().decode(RelayHealth.self, from: data),
               payload.ok
            {
                return
            }
            Thread.sleep(forTimeInterval: 0.2)
        }

        throw XCTSkip("Timed out waiting for test relay on port \(port).")
    }

    func testIdentityStoreMigratesLegacyIdentityAndEncryptsCatalog() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "catalog",
            fixedData: Data(repeating: 7, count: 32)
        )
        let store = IdentityStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)
        let identity = try NotrusCrypto.createIdentity(displayName: "Legacy", username: "legacy")
        let legacyURL = temporaryDirectory.appendingPathComponent("identity.json")
        try JSONEncoder().encode(identity).write(to: legacyURL)

        let catalog = try store.loadCatalog()
        let catalogPath = temporaryDirectory.appendingPathComponent("accounts.json")
        let rawCatalog = try String(contentsOf: catalogPath, encoding: .utf8)

        XCTAssertEqual(catalog.activeIdentityId, identity.id)
        XCTAssertEqual(catalog.identities.count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyURL.path))
        XCTAssertFalse(rawCatalog.contains(identity.username))
        XCTAssertFalse(rawCatalog.contains(identity.fingerprint))
    }

    func testLockedDeviceSecretStoreLeavesOptionalMetadataUnavailable() {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "locked-metadata"
        )

        XCTAssertFalse(deviceSecretStore.isUnlocked())
        XCTAssertNil(deviceSecretStore.unlockedAppInstanceIdentifier())
        XCTAssertNil(deviceSecretStore.unlockedDeviceDescriptor())
    }

    func testFixedDataInteractiveUnlockCompletesWithoutPrompt() async throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "fixed-auth",
            fixedData: Data(repeating: 3, count: 32)
        )

        let method = try await deviceSecretStore.unlockInteractively(
            reason: "Unlock the local Notrus vault on this Mac."
        )

        XCTAssertEqual(method, deviceSecretStore.unlockMethodDescription)
        XCTAssertTrue(deviceSecretStore.isUnlocked())
    }

    func testLegacyOwnerMismatchFallsBackToRecoveryCompatibleHandling() {
        let invalidOwnerEditStatus: OSStatus = -25244
        let noKeychainAvailableStatus: OSStatus = -25291

        XCTAssertTrue(DeviceSecretStore.shouldUseFileFallback(forKeychainStatus: invalidOwnerEditStatus))
        XCTAssertTrue(DeviceSecretStore.shouldTreatMissingKeychainItemAsUnavailable(invalidOwnerEditStatus))
        XCTAssertTrue(DeviceSecretStore.shouldIgnoreKeychainDeleteStatus(invalidOwnerEditStatus))
        XCTAssertTrue(DeviceSecretStore.shouldUseFileFallback(forKeychainStatus: noKeychainAvailableStatus))
        XCTAssertTrue(DeviceSecretStore.shouldTreatMissingKeychainItemAsUnavailable(noKeychainAvailableStatus))
        XCTAssertTrue(DeviceSecretStore.shouldIgnoreKeychainDeleteStatus(noKeychainAvailableStatus))
    }

    func testFileOnlyPersistenceModeCreatesReusableFallbackVaultKey() throws {
        let metadataDirectory = temporaryDirectory.appendingPathComponent("file-only-vault", isDirectory: true)
        let service = "com.notrus.mac.tests.\(UUID().uuidString)"
        let firstStore = DeviceSecretStore(
            service: service,
            account: "file-only",
            metadataDirectory: metadataDirectory,
            persistenceMode: .fileOnly
        )

        _ = try firstStore.unlock(reason: "Create a reusable local vault key.")
        let firstKey = try firstStore.loadExistingCatalogKey()

        let secondStore = DeviceSecretStore(
            service: service,
            account: "file-only",
            metadataDirectory: metadataDirectory,
            persistenceMode: .fileOnly
        )
        let secondKey = try secondStore.loadExistingCatalogKey()

        XCTAssertEqual(
            Data(firstKey.withUnsafeBytes { Array($0) }),
            Data(secondKey.withUnsafeBytes { Array($0) })
        )
    }

    func testTransportPolicyUsesFiniteTimeouts() {
        let session = TransportSecurityPolicy.session()
        XCTAssertEqual(session.configuration.timeoutIntervalForRequest, TransportSecurityPolicy.requestTimeout)
        XCTAssertEqual(session.configuration.timeoutIntervalForResource, TransportSecurityPolicy.resourceTimeout)
        XCTAssertGreaterThan(TransportSecurityPolicy.witnessTimeout, 0)
    }

    func testFileBackedMetadataPersistsAcrossStoreInstances() throws {
        let service = "com.notrus.mac.tests.\(UUID().uuidString)"
        let account = "file-metadata"
        let metadataDirectory = temporaryDirectory.appendingPathComponent("device-metadata", isDirectory: true)
        let fixedData = Data(repeating: 4, count: 32)

        let firstStore = DeviceSecretStore(
            service: service,
            account: account,
            fixedData: fixedData,
            metadataDirectory: metadataDirectory
        )
        let firstDescriptor = try firstStore.deviceDescriptor()
        try firstStore.storeGeneration(7, for: "thread-state-generation.user-1")

        let secondStore = DeviceSecretStore(
            service: service,
            account: account,
            fixedData: fixedData,
            metadataDirectory: metadataDirectory
        )
        let secondDescriptor = try secondStore.deviceDescriptor()

        XCTAssertEqual(secondDescriptor, firstDescriptor)
        XCTAssertEqual(try secondStore.generation(for: "thread-state-generation.user-1"), 7)
    }

    func testPurgeAllLocalSecretsRemovesFileBackedMetadata() throws {
        let service = "com.notrus.mac.tests.\(UUID().uuidString)"
        let account = "purge-metadata"
        let metadataDirectory = temporaryDirectory.appendingPathComponent("purge-device-metadata", isDirectory: true)
        let fixedData = Data(repeating: 5, count: 32)
        let store = DeviceSecretStore(
            service: service,
            account: account,
            fixedData: fixedData,
            metadataDirectory: metadataDirectory
        )

        _ = try store.deviceDescriptor()
        try store.storeGeneration(2, for: "thread-state-generation.user-2")
        XCTAssertFalse((try FileManager.default.contentsOfDirectory(atPath: metadataDirectory.path)).isEmpty)

        try store.purgeAllLocalSecrets()

        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: metadataDirectory.path), [])
    }

    func testMissingExistingVaultKeyThrowsRecoveryError() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "missing-existing"
        )

        XCTAssertThrowsError(try deviceSecretStore.loadExistingCatalogKey()) { error in
            XCTAssertEqual(error as? DeviceSecretStoreError, .missingVaultKey)
        }
    }

    func testIdentityStoreResetAllRemovesCatalogFiles() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "reset-catalog",
            fixedData: Data(repeating: 6, count: 32)
        )
        let store = IdentityStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)
        let identity = try NotrusCrypto.createIdentity(displayName: "Reset", username: "reset")

        _ = try store.saveIdentity(identity, makeActive: true)
        try store.resetAll()

        XCTAssertFalse(FileManager.default.fileExists(atPath: temporaryDirectory.appendingPathComponent("accounts.json").path))
        XCTAssertEqual(try store.loadIdentities(), [])
    }

    func testIdentityStoreReportsMissingVaultKeyForEncryptedCatalog() throws {
        let writeStore = IdentityStore(
            directory: temporaryDirectory,
            deviceSecretStore: DeviceSecretStore(
                service: "com.notrus.mac.tests.\(UUID().uuidString)",
                account: "write-existing",
                fixedData: Data(repeating: 9, count: 32)
            )
        )
        let identity = try NotrusCrypto.createIdentity(displayName: "Existing", username: "existing")
        _ = try writeStore.saveIdentity(identity, makeActive: true)

        let readStore = IdentityStore(
            directory: temporaryDirectory,
            deviceSecretStore: DeviceSecretStore(
                service: "com.notrus.mac.tests.\(UUID().uuidString)",
                account: "read-existing"
            )
        )

        XCTAssertThrowsError(try readStore.loadCatalog()) { error in
            XCTAssertEqual(error as? DeviceSecretStoreError, .missingVaultKey)
        }
    }

    func testPerIdentityStoresResetAllRemoveEncryptedArtifacts() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "reset-state",
            fixedData: Data(repeating: 2, count: 32),
            metadataDirectory: temporaryDirectory.appendingPathComponent("reset-state-metadata", isDirectory: true)
        )
        let identity = try NotrusCrypto.createIdentity(displayName: "State", username: "state")
        let threadStore = ThreadStateStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)
        let securityStore = SecurityStateStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)

        try threadStore.saveRecords(
            ["thread": ThreadStoreRecord(
                bootstrapState: nil,
                currentState: nil,
                groupTreeState: nil,
                lastProcessedMessageId: nil,
                messageCache: [:],
                pendingSentStates: [:],
                processedMessageCount: 0,
                protocolField: "signal-pqxdh-double-ratchet-v1"
            )],
            for: identity
        )
        try securityStore.saveState(
            ContactSecurityState(version: 1, contacts: [:], events: []),
            for: identity
        )

        try threadStore.resetAll()
        try securityStore.resetAll()

        let remaining = try FileManager.default.contentsOfDirectory(atPath: temporaryDirectory.path)
        XCTAssertFalse(remaining.contains(where: { $0.hasPrefix("thread-state-") }))
        XCTAssertFalse(remaining.contains(where: { $0.hasPrefix("contact-security-") }))
    }

    func testIdentityStoreLoadsLegacyProfileMissingPrekeyRepresentation() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "legacy-prekey",
            fixedData: Data(repeating: 8, count: 32)
        )
        let store = IdentityStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)
        let modern = try NotrusCrypto.createIdentity(displayName: "Legacy Prekey", username: "legacyprekey")
        let legacyJson = Data(
            """
            {
              "id":"\(modern.id)",
              "username":"\(modern.username)",
              "displayName":"\(modern.displayName)",
              "createdAt":"\(modern.createdAt)",
              "storageMode":"device-vault-v2",
              "fingerprint":"\(modern.fingerprint)",
              "recoveryFingerprint":"\(modern.recoveryFingerprint)",
              "recoveryPublicJwk":{"crv":"\(modern.recoveryPublicJwk.crv)","kty":"\(modern.recoveryPublicJwk.kty)","x":"\(modern.recoveryPublicJwk.x)","y":"\(modern.recoveryPublicJwk.y)"},
              "recoveryRepresentation":"\(modern.recoveryRepresentation)",
              "signingPublicJwk":{"crv":"\(modern.signingPublicJwk.crv)","kty":"\(modern.signingPublicJwk.kty)","x":"\(modern.signingPublicJwk.x)","y":"\(modern.signingPublicJwk.y)"},
              "signingRepresentation":"\(modern.signingRepresentation)",
              "encryptionPublicJwk":{"crv":"\(modern.encryptionPublicJwk.crv)","kty":"\(modern.encryptionPublicJwk.kty)","x":"\(modern.encryptionPublicJwk.x)","y":"\(modern.encryptionPublicJwk.y)"},
              "encryptionRepresentation":"\(modern.encryptionRepresentation)"
            }
            """.utf8
        )

        try legacyJson.write(to: temporaryDirectory.appendingPathComponent("identity.json"))
        let loaded = try XCTUnwrap(store.loadIdentity())

        XCTAssertEqual(loaded.id, modern.id)
        XCTAssertFalse(loaded.prekeyRepresentation.isEmpty)
        XCTAssertFalse(loaded.prekeySignature.isEmpty)
        XCTAssertFalse(loaded.prekeyCreatedAt.isEmpty)
    }

    func testIdentityStoreSupportsMultipleProfilesAndActiveSwitching() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "switching",
            fixedData: Data(repeating: 9, count: 32)
        )
        let store = IdentityStore(directory: temporaryDirectory, deviceSecretStore: deviceSecretStore)
        let alice = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let bob = try NotrusCrypto.createIdentity(displayName: "Bob", username: "bob")

        _ = try store.saveIdentity(alice, makeActive: true)
        _ = try store.saveIdentity(bob, makeActive: false)
        _ = try store.setActiveIdentity(bob.id)

        let active = try store.loadIdentity()
        let identities = try store.loadIdentities()

        XCTAssertEqual(active?.id, bob.id)
        XCTAssertEqual(Set(identities.map(\.id)), Set([alice.id, bob.id]))
    }

    func testSecurityStateStoreEncryptsContactVerificationData() throws {
        let directory = temporaryDirectory.appendingPathComponent("security-state", isDirectory: true)
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "security-state",
            fixedData: Data(repeating: 4, count: 32)
        )
        let store = SecurityStateStore(directory: directory, deviceSecretStore: deviceSecretStore)
        let identity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let state = ContactSecurityState(
            version: 1,
            contacts: [
                "bob": ContactTrustRecord(
                    userId: "bob",
                    username: "bob",
                    displayName: "Bob",
                    observedFingerprint: "observed-fingerprint",
                    trustedFingerprint: "trusted-fingerprint",
                    observedPrekeyFingerprint: "prekey-a",
                    trustedPrekeyFingerprint: "prekey-a",
                    firstSeenAt: NotrusCrypto.isoNow(),
                    lastSeenAt: NotrusCrypto.isoNow(),
                    lastVerifiedAt: nil,
                    verificationMethod: nil,
                    lastKeyChangeAt: nil,
                    lastPrekeyRotationAt: nil,
                    status: .unverified
                )
            ],
            events: []
        )

        try store.saveState(state, for: identity)
        let fileURL = directory.appendingPathComponent("contact-security-\(identity.id).json")
        let rawFile = try String(contentsOf: fileURL, encoding: .utf8)
        let reopened = try store.loadState(for: identity)

        XCTAssertEqual(reopened, state)
        XCTAssertFalse(rawFile.contains("Bob"))
        XCTAssertFalse(rawFile.contains("observed-fingerprint"))
    }

    func testThreadStateStoreRoundTripsLocalRecords() throws {
        let directory = temporaryDirectory.appendingPathComponent("thread-state", isDirectory: true)
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "thread-state",
            fixedData: Data(repeating: 5, count: 32),
            metadataDirectory: temporaryDirectory.appendingPathComponent("thread-state-metadata", isDirectory: true)
        )
        let store = ThreadStateStore(directory: directory, deviceSecretStore: deviceSecretStore)
        let identity = try NotrusCrypto.createIdentity(displayName: "Threads", username: "threads")
        let record = ThreadStoreRecord(
            bootstrapState: nil,
            currentState: nil,
            groupTreeState: nil,
            lastProcessedMessageId: "m1",
            messageCache: ["m1": CachedMessageState(body: "cached", hidden: false, status: "ok")],
            pendingSentStates: [:],
            processedMessageCount: 1,
            protocolField: "static-room-v1"
        )

        try store.saveRecords(["thread-a": record], for: identity)
        let loaded = try store.loadRecords(for: identity)

        XCTAssertEqual(loaded, ["thread-a": record])
    }

    func testLegacyThreadStoreRecordDecodesWithModernDefaults() throws {
        let legacyJson = Data(
            """
            {
              "thread-a": {
                "groupTreeState": {
                  "epochSecrets": {
                    "1": "\(Data("secret".utf8).base64EncodedString())"
                  },
                  "memberIds": ["alice", "bob"],
                  "senderStates": {},
                  "threadId": "thread-a",
                  "transcriptHash": "legacy-transcript",
                  "treeHash": "legacy-tree"
                },
                "lastProcessedMessageId": "message-1",
                "messageCache": {
                  "message-1": {
                    "body": "hello from legacy"
                  }
                }
              }
            }
            """.utf8
        )

        let decoded = try JSONDecoder().decode([String: ThreadStoreRecord].self, from: legacyJson)
        let record = try XCTUnwrap(decoded["thread-a"])
        let groupState = try XCTUnwrap(record.groupTreeState)
        let cached = try XCTUnwrap(record.messageCache["message-1"])

        XCTAssertEqual(record.lastProcessedMessageId, "message-1")
        XCTAssertEqual(record.processedMessageCount, 1)
        XCTAssertEqual(record.protocolField, "group-tree-v3")
        XCTAssertEqual(groupState.currentEpoch, 1)
        XCTAssertEqual(groupState.epochMessageCount, 0)
        XCTAssertEqual(groupState.protocolField, "group-tree-v3")
        XCTAssertEqual(cached.body, "hello from legacy")
        XCTAssertEqual(cached.status, "ok")
        XCTAssertEqual(cached.attachments, [])
        XCTAssertFalse(cached.hidden)
    }

    func testThreadStateStoreRejectsRollback() throws {
        let directory = temporaryDirectory.appendingPathComponent("thread-state-rollback", isDirectory: true)
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "thread-state-rollback",
            fixedData: Data(repeating: 3, count: 32),
            metadataDirectory: temporaryDirectory.appendingPathComponent("thread-state-rollback-metadata", isDirectory: true)
        )
        let store = ThreadStateStore(directory: directory, deviceSecretStore: deviceSecretStore)
        let identity = try NotrusCrypto.createIdentity(displayName: "Rollback", username: "rollback")

        try store.saveRecords(
            ["thread-a": ThreadStoreRecord(protocolField: "static-room-v1")],
            for: identity
        )
        let originalData = try Data(contentsOf: directory.appendingPathComponent("thread-state-\(identity.id).json"))

        try store.saveRecords(
            ["thread-a": ThreadStoreRecord(messageCache: ["m2": CachedMessageState(body: "later", hidden: false, status: "ok")], processedMessageCount: 1, protocolField: "static-room-v1")],
            for: identity
        )

        try originalData.write(
            to: directory.appendingPathComponent("thread-state-\(identity.id).json"),
            options: .atomic
        )

        XCTAssertThrowsError(try store.loadRecords(for: identity)) { error in
            XCTAssertEqual((error as? ThreadStateStoreError), .rollbackDetected)
        }
    }

    @MainActor
    func testContactVerificationStartsUnverifiedAndFlagsIdentityChanges() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "contact-security",
            fixedData: Data(repeating: 6, count: 32)
        )
        let model = AppModel(
            deviceSecretStore: deviceSecretStore,
            identityStore: IdentityStore(directory: temporaryDirectory.appendingPathComponent("accounts", isDirectory: true), deviceSecretStore: deviceSecretStore),
            securityStateStore: SecurityStateStore(directory: temporaryDirectory.appendingPathComponent("security", isDirectory: true), deviceSecretStore: deviceSecretStore),
            threadStateStore: ThreadStateStore(directory: temporaryDirectory.appendingPathComponent("threads", isDirectory: true), deviceSecretStore: deviceSecretStore)
        )

        let localIdentity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let firstSeen = RelayUser(
            id: "bob-user",
            username: "bob",
            displayName: "Bob",
            fingerprint: "fingerprint-v1",
            mlsKeyPackage: nil,
            prekeyCreatedAt: NotrusCrypto.isoNow(),
            prekeyFingerprint: "prekey-v1",
            prekeyPublicJwk: localIdentity.prekeyPublicJwk,
            prekeySignature: localIdentity.prekeySignature,
            signalBundle: nil,
            signingPublicJwk: localIdentity.signingPublicJwk,
            encryptionPublicJwk: localIdentity.encryptionPublicJwk,
            createdAt: NotrusCrypto.isoNow(),
            updatedAt: nil
        )

        let initialState = model.reconcileContactSecurityState(users: [firstSeen], identity: localIdentity)
        XCTAssertEqual(initialState.contacts[firstSeen.id]?.status, .unverified)
        XCTAssertEqual(initialState.events.first?.kind, "first-seen")
        XCTAssertEqual(initialState.events.first?.requiresAction, true)

        model.contactSecurityState = initialState
        let changedIdentity = RelayUser(
            id: firstSeen.id,
            username: firstSeen.username,
            displayName: firstSeen.displayName,
            fingerprint: "fingerprint-v2",
            mlsKeyPackage: nil,
            prekeyCreatedAt: firstSeen.prekeyCreatedAt,
            prekeyFingerprint: "prekey-v2",
            prekeyPublicJwk: firstSeen.prekeyPublicJwk,
            prekeySignature: firstSeen.prekeySignature,
            signalBundle: nil,
            signingPublicJwk: firstSeen.signingPublicJwk,
            encryptionPublicJwk: firstSeen.encryptionPublicJwk,
            createdAt: firstSeen.createdAt,
            updatedAt: NotrusCrypto.isoNow()
        )

        let changedState = model.reconcileContactSecurityState(users: [changedIdentity], identity: localIdentity)
        XCTAssertEqual(changedState.contacts[firstSeen.id]?.status, .changed)
        XCTAssertTrue(
            changedState.events.contains(where: {
                $0.kind == "identity-key-changed" &&
                $0.userId == firstSeen.id &&
                $0.requiresAction
            })
        )
    }

    @MainActor
    func testAppModelBuildsLocalDeviceInventoryFromStoredProfiles() async throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "device-inventory",
            fixedData: Data(repeating: 4, count: 32)
        )
        let accountsDirectory = temporaryDirectory.appendingPathComponent("accounts", isDirectory: true)
        let securityDirectory = temporaryDirectory.appendingPathComponent("security", isDirectory: true)
        let threadsDirectory = temporaryDirectory.appendingPathComponent("threads", isDirectory: true)
        let identityStore = IdentityStore(directory: accountsDirectory, deviceSecretStore: deviceSecretStore)
        let firstIdentity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let secondIdentity = try NotrusCrypto.createIdentity(displayName: "Bob", username: "bob")
        _ = try identityStore.saveIdentity(firstIdentity, makeActive: true)
        _ = try identityStore.saveIdentity(secondIdentity, makeActive: false)

        let model = AppModel(
            deviceSecretStore: deviceSecretStore,
            identityStore: identityStore,
            securityStateStore: SecurityStateStore(directory: securityDirectory, deviceSecretStore: deviceSecretStore),
            threadStateStore: ThreadStateStore(directory: threadsDirectory, deviceSecretStore: deviceSecretStore)
        )

        await model.bootstrap()

        XCTAssertEqual(model.localDeviceInventory.profileCount, 2)
        XCTAssertEqual(model.localDeviceInventory.profiles.map(\.username), ["alice", "bob"])
        XCTAssertEqual(model.localDeviceInventory.vaultStorageMode, "data-protection-keychain")
        XCTAssertNotNil(model.localDeviceInventory.appInstanceId)
    }

    func testTransportPolicyRejectsRemoteHttp() throws {
        XCTAssertThrowsError(try TransportSecurityPolicy.validatedRelayOrigin("http://192.168.1.20:3000"))
        XCTAssertNoThrow(try TransportSecurityPolicy.validatedRelayOrigin("http://127.0.0.1:3000"))
        XCTAssertNoThrow(try TransportSecurityPolicy.validatedRelayOrigin("https://relay.example.com"))
    }

    func testRotatedIdentityPreservesRecoveryAuthorityAndChangesMessagingKeys() throws {
        let identity = try NotrusCrypto.createIdentity(displayName: "Rotate", username: "rotate")
        let rotated = try NotrusCrypto.rotatedIdentity(from: identity)

        XCTAssertEqual(rotated.id, identity.id)
        XCTAssertEqual(rotated.username, identity.username)
        XCTAssertEqual(rotated.recoveryFingerprint, identity.recoveryFingerprint)
        XCTAssertEqual(rotated.recoveryPublicJwk, identity.recoveryPublicJwk)
        XCTAssertEqual(rotated.recoveryRepresentation, identity.recoveryRepresentation)
        XCTAssertNotEqual(rotated.fingerprint, identity.fingerprint)
        XCTAssertNotEqual(rotated.signingPublicJwk, identity.signingPublicJwk)
        XCTAssertNotEqual(rotated.encryptionPublicJwk, identity.encryptionPublicJwk)
        XCTAssertNotEqual(rotated.prekeyPublicJwk, identity.prekeyPublicJwk)
    }

    func testEncryptedAttachmentRoundTripsWithoutPlaintextOnTheRelayContract() throws {
        let plaintext = Data("super secret attachment bytes".utf8)
        let sealed = try NotrusCrypto.sealAttachment(data: plaintext, senderId: "alice", threadId: "thread-1")
        let relayAttachment = RelayAttachment(
            byteLength: sealed.request.byteLength,
            ciphertext: sealed.request.ciphertext,
            createdAt: sealed.request.createdAt,
            id: sealed.request.id,
            iv: sealed.request.iv,
            senderId: sealed.request.senderId ?? "alice",
            sha256: sealed.request.sha256,
            threadId: sealed.request.threadId ?? "thread-1"
        )

        XCTAssertFalse(sealed.request.ciphertext.contains("super secret"))
        XCTAssertGreaterThan(sealed.request.byteLength, plaintext.count)
        XCTAssertEqual(try NotrusCrypto.openAttachment(relayAttachment, reference: sealed.reference), plaintext)
    }

    func testAttachmentGatewaySanitizesPotentiallyDangerousFileNames() {
        XCTAssertEqual(AttachmentGateway.sanitizedFileName("../taxes 2026.pdf"), ".._taxes_2026.pdf")
        XCTAssertEqual(AttachmentGateway.sanitizedFileName(""), "attachment.bin")
        XCTAssertEqual(AttachmentGateway.sanitizedFileName("photo?.heic"), "photo_.heic")
    }

    func testStandardsCoreBridgePrefersBundledHelperLocation() throws {
        let bundleURL = temporaryDirectory.appendingPathComponent("NotrusMac.app", isDirectory: true)
        let helperURL = bundleURL.appendingPathComponent("Contents/Helpers/notrus-protocol-core")
        try FileManager.default.createDirectory(
            at: helperURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "#!/bin/sh\nexit 0\n".write(to: helperURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o755))],
            ofItemAtPath: helperURL.path
        )

        let resolved = try StandardsCoreBridge.helperURL(bundleURL: bundleURL, environment: [:])
        XCTAssertEqual(resolved.path, helperURL.path)
    }

    @MainActor
    func testResetTransparencyTrustClearsPinnedStateForCurrentRelay() async {
        let pinnedHeadsKey = "NotrusMac.transparencyPins"
        let pinnedSignerKeysKey = "NotrusMac.transparencySignerPins"
        let relayOrigin = "https://ramal-paola-yolky.ngrok-free.dev"
        let encoder = JSONEncoder()

        defer {
            UserDefaults.standard.removeObject(forKey: pinnedHeadsKey)
            UserDefaults.standard.removeObject(forKey: pinnedSignerKeysKey)
        }

        UserDefaults.standard.set(
            try? encoder.encode([relayOrigin: "old-head"]),
            forKey: pinnedHeadsKey
        )
        UserDefaults.standard.set(
            try? encoder.encode([relayOrigin: "old-signer"]),
            forKey: pinnedSignerKeysKey
        )

        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "transparency-reset",
            fixedData: Data(repeating: 8, count: 32)
        )
        let model = AppModel(
            deviceSecretStore: deviceSecretStore,
            identityStore: IdentityStore(directory: temporaryDirectory.appendingPathComponent("accounts", isDirectory: true), deviceSecretStore: deviceSecretStore),
            securityStateStore: SecurityStateStore(directory: temporaryDirectory.appendingPathComponent("security", isDirectory: true), deviceSecretStore: deviceSecretStore),
            threadStateStore: ThreadStateStore(directory: temporaryDirectory.appendingPathComponent("threads", isDirectory: true), deviceSecretStore: deviceSecretStore)
        )
        model.relayOrigin = relayOrigin

        await model.resetTransparencyTrust()

        let decodedHeads = (UserDefaults.standard.data(forKey: pinnedHeadsKey)).flatMap {
            try? JSONDecoder().decode([String: String].self, from: $0)
        } ?? [:]
        let decodedSignerKeys = (UserDefaults.standard.data(forKey: pinnedSignerKeysKey)).flatMap {
            try? JSONDecoder().decode([String: String].self, from: $0)
        } ?? [:]

        XCTAssertNil(decodedHeads[relayOrigin])
        XCTAssertNil(decodedSignerKeys[relayOrigin])
    }

    @MainActor
    func testBlockingContactPersistsAndExcludesTheComposerCandidate() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "blocked-contact",
            fixedData: Data(repeating: 8, count: 32)
        )
        let accountsDirectory = temporaryDirectory.appendingPathComponent("accounts", isDirectory: true)
        let securityDirectory = temporaryDirectory.appendingPathComponent("security", isDirectory: true)
        let threadsDirectory = temporaryDirectory.appendingPathComponent("threads", isDirectory: true)
        let securityStore = SecurityStateStore(directory: securityDirectory, deviceSecretStore: deviceSecretStore)
        let model = AppModel(
            deviceSecretStore: deviceSecretStore,
            identityStore: IdentityStore(directory: accountsDirectory, deviceSecretStore: deviceSecretStore),
            securityStateStore: securityStore,
            threadStateStore: ThreadStateStore(directory: threadsDirectory, deviceSecretStore: deviceSecretStore)
        )

        let localIdentity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        model.currentIdentity = localIdentity
        let remote = RelayUser(
            id: "blocked-user",
            username: "blocked",
            displayName: "Blocked Contact",
            fingerprint: "fingerprint-v1",
            mlsKeyPackage: nil,
            prekeyCreatedAt: NotrusCrypto.isoNow(),
            prekeyFingerprint: "prekey-v1",
            prekeyPublicJwk: localIdentity.prekeyPublicJwk,
            prekeySignature: localIdentity.prekeySignature,
            signalBundle: nil,
            signingPublicJwk: localIdentity.signingPublicJwk,
            encryptionPublicJwk: localIdentity.encryptionPublicJwk,
            createdAt: NotrusCrypto.isoNow(),
            updatedAt: nil
        )

        model.users = [remote]
        model.contactSecurityState = model.reconcileContactSecurityState(users: [remote], identity: localIdentity)
        XCTAssertTrue(model.composeCandidates.contains(where: { $0.id == remote.id }))

        model.blockContact(remote.id)

        XCTAssertTrue(model.isContactBlocked(remote.id))
        XCTAssertFalse(model.composeCandidates.contains(where: { $0.id == remote.id }))

        let persisted = try securityStore.loadState(for: localIdentity)
        XCTAssertNotNil(persisted.contacts[remote.id]?.blockedAt)

        model.unblockContact(remote.id)
        XCTAssertFalse(model.isContactBlocked(remote.id))
        XCTAssertTrue(model.composeCandidates.contains(where: { $0.id == remote.id }))
    }

    @MainActor
    func testDeletedLocalContactStaysHiddenAcrossSyncReconciliation() throws {
        let deviceSecretStore = DeviceSecretStore(
            service: "com.notrus.mac.tests.\(UUID().uuidString)",
            account: "deleted-contact",
            fixedData: Data(repeating: 7, count: 32)
        )
        let model = AppModel(
            deviceSecretStore: deviceSecretStore,
            identityStore: IdentityStore(directory: temporaryDirectory.appendingPathComponent("accounts", isDirectory: true), deviceSecretStore: deviceSecretStore),
            securityStateStore: SecurityStateStore(directory: temporaryDirectory.appendingPathComponent("security", isDirectory: true), deviceSecretStore: deviceSecretStore),
            threadStateStore: ThreadStateStore(directory: temporaryDirectory.appendingPathComponent("threads", isDirectory: true), deviceSecretStore: deviceSecretStore)
        )

        let localIdentity = try NotrusCrypto.createIdentity(displayName: "Alice", username: "alice")
        let remote = RelayUser(
            id: "deleted-user",
            username: "deleted",
            displayName: "Deleted Contact",
            fingerprint: "fingerprint-v1",
            mlsKeyPackage: nil,
            prekeyCreatedAt: NotrusCrypto.isoNow(),
            prekeyFingerprint: "prekey-v1",
            prekeyPublicJwk: localIdentity.prekeyPublicJwk,
            prekeySignature: localIdentity.prekeySignature,
            signalBundle: nil,
            signingPublicJwk: localIdentity.signingPublicJwk,
            encryptionPublicJwk: localIdentity.encryptionPublicJwk,
            createdAt: NotrusCrypto.isoNow(),
            updatedAt: nil
        )

        model.users = [remote]
        model.contactSecurityState = model.reconcileContactSecurityState(users: [remote], identity: localIdentity)
        XCTAssertEqual(model.contacts.map(\.id), [remote.id])
        XCTAssertEqual(model.visibleContactRecords.map(\.userId), [remote.id])

        model.deleteLocalContact(remote.id)
        XCTAssertTrue(model.isContactLocallyDeleted(remote.id))
        XCTAssertEqual(model.contacts, [])
        XCTAssertEqual(model.visibleContactRecords, [])

        let reconciled = model.reconcileContactSecurityState(users: [remote], identity: localIdentity)
        XCTAssertNotNil(reconciled.contacts[remote.id]?.deletedAt)

        model.contactSecurityState = reconciled
        XCTAssertEqual(model.contacts, [])
        XCTAssertEqual(model.visibleContactRecords, [])
    }
}
