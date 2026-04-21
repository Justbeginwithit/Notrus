import CryptoKit
import Foundation
import SwiftUI

private struct PreparedThreadCreation {
    let request: ThreadCreateRequest
    let localThreadRecord: ThreadStoreRecord?
    let protocolName: String
    let threadId: String
    let updatedIdentity: LocalIdentity?
}

private struct StandardsMlsFanoutRecipient: Codable {
    let messageKind: String
    let toUserId: String
    let wireMessage: String
}

private struct StandardsMlsFanoutEnvelope: Codable {
    let format: String
    let senderId: String
    let version: Int
    let recipients: [StandardsMlsFanoutRecipient]
}

private enum PrivacyDelayKind {
    case sync
    case interactive
    case delivery
}

@MainActor
final class AppModel: ObservableObject {
    private static let defaultLocalRelayOrigin = "http://127.0.0.1:3000"
    private static let defaultRemoteRelayOrigin = {
        let configured = ProcessInfo.processInfo.environment["NOTRUS_DEFAULT_RELAY_ORIGIN"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let configured, !configured.isEmpty {
            return configured
        }
        return "https://ramal-paola-yolky.ngrok-free.dev"
    }()
    private static let resettableTransparencyWarnings: Set<String> = [
        "This relay presented a transparency history that does not include the head previously pinned on this Mac.",
        "This relay changed its transparency signing key for the Mac key directory.",
    ]
    private static let mlsFanoutCiphersuite = "MLS-compat-signal-fanout-v1"
    private static let mlsFanoutEnvelopeFormat = "notrus-mls-signal-fanout-v1"
    private static let mlsFanoutGroupPrefix = "fanout-signal:"

    @Published var relayOrigin: String
    @Published var witnessOriginsText: String
    @Published var privacyModeEnabled: Bool
    @Published var contactSecurityState = ContactSecurityState(version: 1, contacts: [:], events: [])
    @Published var localProfiles: [LocalIdentity] = []
    @Published var localDeviceInventory = LocalDeviceInventory.empty
    @Published var localVaultLocked = false
    @Published var currentIdentity: LocalIdentity?
    @Published var currentUser: RelayUser?
    @Published var linkedDeviceEvents: [RelayDeviceEvent] = []
    @Published var linkedDevices: [RelayLinkedDevice] = []
    @Published var users: [RelayUser] = []
    @Published var threads: [ConversationThread] = []
    @Published var selectedThreadID: String?
    @Published var draftText = ""
    @Published var pendingAttachments: [LocalAttachmentDraft] = []
    @Published var composeTitle = ""
    @Published var composeSelection: Set<String> = []
    @Published var directorySearchQuery = ""
    @Published var directorySearchResults: [RelayUser] = []
    @Published var composePresented = false
    @Published var accountCenterPresented = false
    @Published var onboardingDisplayName = ""
    @Published var onboardingUsername = ""
    @Published var isBusy = false
    @Published var blockingBusyMessage: String?
    @Published var statusMessage = "Native macOS client ready."
    @Published var errorMessage: String?
    @Published var relayProtocolPolicy: ProtocolPolicySummary?
    @Published var transparency = TransparencyVerificationResult.empty
    @Published var integrityReport: ClientIntegrityReport?

    private let deviceSecretStore: DeviceSecretStore
    private let identityStore: IdentityStore
    private let securityStateStore: SecurityStateStore
    private let threadStateStore: ThreadStateStore
    private let relayOriginKey = "NotrusMac.relayOrigin"
    private let witnessOriginsKey = "NotrusMac.witnessOrigins"
    private let privacyModeKey = "NotrusMac.privacyModeEnabled"
    private let groupEpochRotationInterval = 12
    private let configuredProtocolPolicy = ProtocolPolicyMode(
        rawValue: ProcessInfo.processInfo.environment["NOTRUS_PROTOCOL_POLICY"] ?? ""
    ) ?? .requireStandards

    private var threadRecords: [String: ThreadStoreRecord] = [:]
    private var transparencyPins: [String: String]
    private var transparencySignerPins: [String: String]
    private var appInstanceId: String?
    private var currentDeviceDescriptor: DeviceDescriptor?
    private var relaySession: RelaySession?
    private var cachedRelayHealth: RelayHealth?
    private var cachedRelayHealthOrigin: String?
    private var bootstrapStarted = false

    init(
        deviceSecretStore: DeviceSecretStore = DeviceSecretStore(),
        identityStore: IdentityStore? = nil,
        securityStateStore: SecurityStateStore? = nil,
        threadStateStore: ThreadStateStore? = nil
    ) {
        self.deviceSecretStore = deviceSecretStore
        self.identityStore = identityStore ?? IdentityStore(deviceSecretStore: deviceSecretStore)
        self.securityStateStore = securityStateStore ?? SecurityStateStore(deviceSecretStore: deviceSecretStore)
        self.threadStateStore = threadStateStore ?? ThreadStateStore(deviceSecretStore: deviceSecretStore)
        self.relayOrigin = Self.bootstrapRelayOrigin(UserDefaults.standard.string(forKey: "NotrusMac.relayOrigin"))
        self.witnessOriginsText = UserDefaults.standard.string(forKey: witnessOriginsKey) ?? ""
        self.privacyModeEnabled = UserDefaults.standard.bool(forKey: privacyModeKey)
        self.transparencyPins = Self.loadPinnedHeads()
        self.transparencySignerPins = Self.loadPinnedSignerKeys()
        refreshLocalDeviceInventory()
    }

    var contacts: [RelayUser] {
        users.filter { $0.id != currentIdentity?.id && !isContactLocallyDeleted($0.id) }
    }

    var visibleContactRecords: [ContactTrustRecord] {
        contactSecurityState.contacts.values
            .filter { $0.deletedAt == nil }
            .sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    var composeCandidates: [RelayUser] {
        let merged = Dictionary(
            uniqueKeysWithValues: (contacts + directorySearchResults)
                .map { ($0.id, $0) }
        )
        let candidates = merged.values
            .filter { !isContactBlocked($0.id) }
            .sorted {
                if ($0.mlsKeyPackage != nil) != ($1.mlsKeyPackage != nil) {
                    return $0.mlsKeyPackage != nil
                }
                return $0.username < $1.username
            }
        let query = directorySearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            return candidates
        }
        return candidates.filter { matchesDirectoryQuery($0, query: query) }
    }

    var hasProfiles: Bool {
        !localProfiles.isEmpty
    }

    var selectedThread: ConversationThread? {
        threads.first(where: { $0.id == selectedThreadID })
    }

    var canSendMessage: Bool {
        (!draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !pendingAttachments.isEmpty) &&
        selectedThread?.supported == true &&
        selectedThreadContainsBlockedContact == false &&
        selectedThreadRequiresReverification == false &&
        (selectedThread.map { !isProtocolBlocked($0.rawThread.protocolField ?? "static-room-v1") } ?? false)
    }

    var activeSecurityEvents: [ContactSecurityEvent] {
        contactSecurityState.events
            .filter { $0.dismissedAt == nil }
            .sorted { $0.createdAt > $1.createdAt }
    }

    var hasPendingSecurityActions: Bool {
        activeSecurityEvents.contains(where: \.requiresAction)
    }

    var selectedThreadRequiresReverification: Bool {
        guard let thread = selectedThread, let identity = currentIdentity else {
            return false
        }
        return thread.participants
            .filter { $0.id != identity.id }
            .contains { contactSecurityState.contacts[$0.id]?.status == .changed }
    }

    var selectedThreadContainsBlockedContact: Bool {
        guard let thread = selectedThread, let identity = currentIdentity else {
            return false
        }
        return thread.participants
            .filter { $0.id != identity.id }
            .contains { isContactBlocked($0.id) }
    }

    var effectiveProtocolPolicy: ProtocolPolicyMode {
        relayProtocolPolicy?.mode ?? configuredProtocolPolicy
    }

    var protocolProgramSummary: ProtocolPolicySummary {
        relayProtocolPolicy ?? NotrusProtocolCatalog.summary(for: configuredProtocolPolicy)
    }

    var composeProtocolPreview: String {
        guard currentIdentity != nil else {
            return "Unavailable"
        }

        let participantCount = composeSelection.count + 1
        if composeSelection.isEmpty {
            return "Choose at least one contact"
        }

        return NotrusProtocolCatalog.spec(for: NotrusProtocolCatalog.chooseProtocol(participantCount: participantCount)).label
    }

    var composeProtocolNote: String {
        let participantCount = composeSelection.count + 1
        if composeSelection.isEmpty {
            return protocolProgramSummary.note
        }

        let protocolName = NotrusProtocolCatalog.chooseProtocol(participantCount: participantCount)
        let spec = NotrusProtocolCatalog.spec(for: protocolName)
        if isProtocolBlocked(protocolName) {
            return "\(spec.label) is blocked by the active standards policy. Notrus still needs a real PQXDH/Double Ratchet 1:1 path and RFC 9420 MLS groups before this mode can create conversations."
        }

        return spec.note
    }

    var composeProtocolBlocked: Bool {
        let participantCount = composeSelection.count + 1
        guard participantCount >= 2 else {
            return false
        }
        return isProtocolBlocked(NotrusProtocolCatalog.chooseProtocol(participantCount: participantCount))
    }

    var composeSelectedContacts: [RelayUser] {
        composeCandidates.filter { composeSelection.contains($0.id) }
    }

    var composeMlsIneligibleContacts: [RelayUser] {
        guard composeSelection.count + 1 >= 3 else {
            return []
        }
        return composeSelectedContacts.filter { $0.mlsKeyPackage == nil }
    }

    var composeSelectionWarning: String? {
        if composeSelection.isEmpty {
            return nil
        }
        if !composeMlsIneligibleContacts.isEmpty {
            let names = composeMlsIneligibleContacts.map(\.displayName).joined(separator: ", ")
            return "Some selected contacts (\(names)) have no native MLS key package, so this Mac will use compatible Signal fanout transport inside the standards group thread."
        }
        return nil
    }

    var canCreateComposedThread: Bool {
        !composeSelection.isEmpty && !composeProtocolBlocked
    }

    var protocolBannerTone: StatusStrip.Tone {
        effectiveProtocolPolicy == .requireStandards ? .warning : .neutral
    }

    func isProtocolBlocked(_ protocolName: String) -> Bool {
        !NotrusProtocolCatalog.allowed(protocolName, under: effectiveProtocolPolicy)
    }

    var witnessOrigins: [String] {
        witnessOriginsText
            .split(whereSeparator: { $0 == "," || $0 == "\n" })
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private var currentRelayClient: RelayClient {
        RelayClient(
            origin: relayOrigin,
            integrityReport: integrityReport,
            appInstanceId: appInstanceId,
            deviceDescriptor: currentDeviceDescriptor,
            sessionToken: relaySession?.token
        )
    }

    private func cacheRelayHealth(_ health: RelayHealth, for origin: String) {
        cachedRelayHealth = health
        cachedRelayHealthOrigin = origin
        relayProtocolPolicy = health.protocolPolicy
    }

    private func clearRelayHealthCache() {
        cachedRelayHealth = nil
        cachedRelayHealthOrigin = nil
        relayProtocolPolicy = nil
    }

    private func relayClientAndHealth(
        forceRefreshHealth: Bool = false,
        allowRemoteFallback: Bool = true
    ) async throws -> (RelayClient, RelayHealth) {
        relayOrigin = try TransportSecurityPolicy.validatedRelayOrigin(relayOrigin).absoluteString
        persistRelayOrigin()
        let primaryClient = currentRelayClient

        if !forceRefreshHealth,
           cachedRelayHealthOrigin == relayOrigin,
           let cachedRelayHealth
        {
            return (primaryClient, cachedRelayHealth)
        }

        do {
            let health = try await primaryClient.health()
            cacheRelayHealth(health, for: relayOrigin)
            return (primaryClient, health)
        } catch {
            guard allowRemoteFallback, Self.isBootstrapLocalRelay(relayOrigin) else {
                throw error
            }

            let fallback = Self.defaultRemoteRelayOrigin
            guard fallback != relayOrigin else {
                throw error
            }

            relayOrigin = fallback
            persistRelayOrigin()
            let fallbackClient = currentRelayClient
            let health = try await fallbackClient.health()
            cacheRelayHealth(health, for: relayOrigin)
            statusMessage = "Switched this Mac to the HTTPS relay."
            return (fallbackClient, health)
        }
    }

    private func sessionIsUsable(_ session: RelaySession?) -> Bool {
        guard let session else {
            return false
        }
        guard let expiry = ISO8601DateFormatter().date(from: session.expiresAt) else {
            return false
        }
        return expiry.timeIntervalSinceNow > 30
    }

    private func bootstrapRelaySession(identity: LocalIdentity) async throws -> RegisterResponse {
        let (client, _) = try await relayClientAndHealth(forceRefreshHealth: true)
        let registration = try await client.register(identity: identity)
        relaySession = registration.session
        currentUser = registration.user
        linkedDevices = (registration.devices ?? []).sorted { $0.updatedAt > $1.updatedAt }
        linkedDeviceEvents = (registration.deviceEvents ?? []).sorted { $0.createdAt > $1.createdAt }
        return registration
    }

    private func mergeRegisteredIdentity(_ identity: LocalIdentity, registered: RelayUser) -> LocalIdentity {
        LocalIdentity(
            id: identity.id,
            username: registered.username.isEmpty ? identity.username : registered.username,
            displayName: registered.displayName.isEmpty ? identity.displayName : registered.displayName,
            createdAt: identity.createdAt,
            storageMode: identity.storageMode,
            fingerprint: identity.fingerprint,
            recoveryFingerprint: identity.recoveryFingerprint,
            recoveryPublicJwk: identity.recoveryPublicJwk,
            recoveryRepresentation: identity.recoveryRepresentation,
            signingPublicJwk: identity.signingPublicJwk,
            signingRepresentation: identity.signingRepresentation,
            encryptionPublicJwk: identity.encryptionPublicJwk,
            encryptionRepresentation: identity.encryptionRepresentation,
            prekeyCreatedAt: identity.prekeyCreatedAt,
            prekeyFingerprint: identity.prekeyFingerprint,
            prekeyPublicJwk: identity.prekeyPublicJwk,
            prekeyRepresentation: identity.prekeyRepresentation,
            prekeySignature: identity.prekeySignature,
            standardsMlsKeyPackage: identity.standardsMlsKeyPackage,
            standardsMlsState: identity.standardsMlsState,
            standardsSignalBundle: identity.standardsSignalBundle,
            standardsSignalState: identity.standardsSignalState
        )
    }

    private func ensureRelaySession(for identity: LocalIdentity) async throws {
        guard !sessionIsUsable(relaySession) else {
            return
        }
        _ = try await bootstrapRelaySession(identity: identity)
    }

    private func refreshUnlockedDeviceSessionMetadata() {
        appInstanceId = deviceSecretStore.unlockedAppInstanceIdentifier()
        currentDeviceDescriptor = deviceSecretStore.unlockedDeviceDescriptor()
        refreshLocalDeviceInventory()
    }

    private func clearUnlockedDeviceSessionMetadata() {
        appInstanceId = nil
        currentDeviceDescriptor = nil
        refreshLocalDeviceInventory()
    }

    private func isUserCancellation(_ error: Error) -> Bool {
        if let portabilityError = error as? AccountPortabilityError {
            return portabilityError == .exportCancelled || portabilityError == .importCancelled
        }

        if let deviceError = error as? DeviceSecretStoreError {
            return deviceError == .userCancelled
        }

        let nsError = error as NSError
        return nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError
    }

    private func reloadLocalProfiles(preferredUserId: String? = nil) throws {
        let catalog = try identityStore.loadCatalog()
        localProfiles = catalog.identities

        let targetUserId = preferredUserId ?? catalog.activeIdentityId
        currentIdentity = catalog.identities.first(where: { $0.id == targetUserId }) ?? catalog.identities.first

        if let identity = currentIdentity {
            threadRecords = try threadStateStore.loadRecords(for: identity)
            contactSecurityState = try securityStateStore.loadState(for: identity)
        } else {
            threadRecords = [:]
            contactSecurityState = ContactSecurityState(version: 1, contacts: [:], events: [])
        }
        refreshLocalDeviceInventory()
    }

    private func persistCurrentIdentity(_ identity: LocalIdentity) throws {
        _ = try identityStore.saveIdentity(identity, makeActive: true)
        currentIdentity = identity
        localProfiles = try identityStore.loadIdentities()
        refreshLocalDeviceInventory()
    }

    private func refreshLocalDeviceInventory() {
        let base = deviceSecretStore.inventorySnapshot()
        localDeviceInventory = LocalDeviceInventory(
            vaultStorageMode: base.vaultStorageMode,
            vaultKeyPresent: base.vaultKeyPresent,
            metadataDirectoryLabel: base.metadataDirectoryLabel,
            appInstanceId: base.appInstanceId,
            deviceId: base.deviceId,
            deviceKeyStorageMode: base.deviceKeyStorageMode,
            profileCount: localProfiles.count,
            profiles: localProfiles
                .map {
                    LocalDeviceInventoryProfile(
                        id: $0.id,
                        username: $0.username,
                        displayName: $0.displayName,
                        createdAt: $0.createdAt,
                        directoryCode: currentUser?.id == $0.id ? currentUser?.directoryCode : nil,
                        fingerprint: $0.fingerprint,
                        storageMode: $0.storageMode
                    )
                }
                .sorted { $0.username.localizedCaseInsensitiveCompare($1.username) == .orderedAscending }
        )
    }

    private func clearRemoteWorkspace(preserveRelaySession: Bool = false) {
        if !preserveRelaySession {
            relaySession = nil
            currentUser = nil
            linkedDeviceEvents = []
            linkedDevices = []
        }
        users = []
        threads = []
        selectedThreadID = nil
        draftText = ""
        transparency = .empty
    }

    func bootstrap() async {
        guard !bootstrapStarted else {
            return
        }
        bootstrapStarted = true
        do {
            relayOrigin = try TransportSecurityPolicy.validatedRelayOrigin(relayOrigin).absoluteString
            persistRelayOrigin()
            integrityReport = await DeviceRiskSignals.capture()

            if identityStore.hasStoredProfiles() && !deviceSecretStore.isUnlocked() {
                clearUnlockedDeviceSessionMetadata()
                localVaultLocked = true
                statusMessage = "Unlock the local Notrus vault on this Mac to reopen encrypted accounts and session state."
                return
            }

            refreshUnlockedDeviceSessionMetadata()
            try reloadLocalProfiles()
            if currentIdentity != nil {
                try await registerAndSync()
            } else {
                localVaultLocked = false
                statusMessage = "Create or import a device-protected Notrus profile to begin."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func beginBlockingBusy(_ message: String) {
        isBusy = true
        blockingBusyMessage = message
        statusMessage = message
        errorMessage = nil
    }

    private func endBlockingBusy() {
        blockingBusyMessage = nil
        isBusy = false
    }

    func unlockLocalVault() async {
        beginBlockingBusy("Unlocking the local Notrus vault on this Mac...")
        defer { endBlockingBusy() }

        do {
            let method = try await deviceSecretStore.unlockInteractively(
                reason: "Unlock Notrus to reopen local identities, ratchet state, and contact verification records.",
                allowCreation: false
            )
            localVaultLocked = false
            integrityReport = await DeviceRiskSignals.capture()
            refreshUnlockedDeviceSessionMetadata()
            try reloadLocalProfiles()
            if currentIdentity != nil {
                try await registerAndSync()
            } else {
                statusMessage = "Unlocked the local vault with \(method). Create or import a profile to continue."
            }
        } catch {
            if let deviceError = error as? DeviceSecretStoreError, deviceError == .userCancelled {
                errorMessage = "macOS cancelled the local sign-in request before the Notrus vault opened. Try unlock again. If this Mac lost the old vault key, reset the local vault and import a recovery archive."
            } else if let deviceError = error as? DeviceSecretStoreError, deviceError == .authenticationFailed {
                errorMessage = "macOS rejected the local sign-in request. If this vault was created under an older biometric-only policy, use Touch ID once or reset the local vault and import a recovery archive."
            } else if let deviceError = error as? DeviceSecretStoreError, deviceError == .missingVaultKey {
                errorMessage = deviceError.localizedDescription
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    func lockLocalVault() {
        deviceSecretStore.lock()
        localVaultLocked = identityStore.hasStoredProfiles()
        currentIdentity = nil
        localProfiles = []
        threadRecords = [:]
        contactSecurityState = ContactSecurityState(version: 1, contacts: [:], events: [])
        clearRemoteWorkspace()
        clearUnlockedDeviceSessionMetadata()
        statusMessage = "Locked the local Notrus vault on this Mac."
    }

    func persistRelayOrigin() {
        if let validated = try? TransportSecurityPolicy.validatedRelayOrigin(relayOrigin) {
            let previous = UserDefaults.standard.string(forKey: relayOriginKey)
            relayOrigin = validated.absoluteString
            UserDefaults.standard.set(relayOrigin, forKey: relayOriginKey)
            if previous != relayOrigin {
                relaySession = nil
                clearRelayHealthCache()
            }
        }
    }

    func persistWitnessOrigins() {
        UserDefaults.standard.set(witnessOriginsText, forKey: witnessOriginsKey)
    }

    func persistPrivacyMode() {
        UserDefaults.standard.set(privacyModeEnabled, forKey: privacyModeKey)
    }

    private func applyPrivacyDelayIfEnabled(_ kind: PrivacyDelayKind) async {
        guard privacyModeEnabled else {
            return
        }
        let delayMilliseconds: UInt64
        switch kind {
        case .sync:
            delayMilliseconds = UInt64.random(in: 250...900)
        case .interactive:
            delayMilliseconds = UInt64.random(in: 120...420)
        case .delivery:
            delayMilliseconds = UInt64.random(in: 150...500)
        }
        try? await Task.sleep(nanoseconds: delayMilliseconds * 1_000_000)
    }

    func createIdentity() async {
        let displayName = onboardingDisplayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let username = onboardingUsername.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        guard !displayName.isEmpty else {
            errorMessage = "Enter a display name."
            return
        }

        guard username.range(of: #"^[a-z0-9._-]{3,24}$"#, options: .regularExpression) != nil else {
            errorMessage = "Username must be 3-24 lowercase characters using letters, numbers, dots, dashes, or underscores."
            return
        }

        beginBlockingBusy("Creating a device-protected macOS identity...")
        defer { endBlockingBusy() }

        do {
            relayOrigin = try TransportSecurityPolicy.validatedRelayOrigin(relayOrigin).absoluteString
            persistRelayOrigin()
            let unlockMethod = try await deviceSecretStore.unlockInteractively(
                reason: "Approve local device protection before creating this macOS Notrus profile.",
                allowCreation: !identityStore.hasStoredProfiles()
            )
            refreshUnlockedDeviceSessionMetadata()
            let identity = try await NativeExecution.run {
                try NotrusCrypto.createIdentity(displayName: displayName, username: username)
            }
            let standards = try await NativeExecution.run {
                try StandardsCoreBridge.createIdentity(
                    displayName: displayName,
                    threadUserId: identity.id,
                    username: username
                )
            }
            let standardsIdentity = identity.updatingStandards(
                mlsKeyPackage: standards.mlsKeyPackage,
                mlsState: standards.mlsState,
                signalBundle: standards.signalBundle,
                signalState: standards.signalState
            )
            _ = try identityStore.saveIdentity(standardsIdentity, makeActive: true)
            try threadStateStore.saveRecords([:], for: standardsIdentity)
            refreshUnlockedDeviceSessionMetadata()
            try reloadLocalProfiles(preferredUserId: standardsIdentity.id)
            clearRemoteWorkspace()
            localVaultLocked = false
            onboardingDisplayName = ""
            onboardingUsername = ""
            try await registerAndSync()
            statusMessage = "Created a device-protected macOS profile with \(unlockMethod)."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func ensureStandardsIdentityMaterial(for identity: LocalIdentity) async throws -> LocalIdentity {
        guard !identity.hasCompleteStandardsState else {
            return identity
        }

        let repaired = try await NativeExecution.run {
            try StandardsCoreBridge.createIdentity(
                displayName: identity.displayName,
                threadUserId: identity.id,
                username: identity.username
            )
        }

        let updated = identity.updatingStandards(
            mlsKeyPackage: repaired.mlsKeyPackage,
            mlsState: repaired.mlsState,
            signalBundle: repaired.signalBundle,
            signalState: repaired.signalState
        )
        try persistCurrentIdentity(updated)
        statusMessage = "Rebuilt missing local standards state for \(updated.displayName) on this Mac."
        return updated
    }

    func registerAndSync() async throws {
        guard var identity = currentIdentity else {
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        identity = try await ensureStandardsIdentityMaterial(for: identity)

        if let mlsState = identity.standardsMlsState {
            let refreshed = try await NativeExecution.run {
                try StandardsCoreBridge.refreshMlsKeyPackage(mlsState: mlsState)
            }
            identity = identity.updatingStandards(
                mlsKeyPackage: refreshed.mlsKeyPackage,
                mlsState: refreshed.mlsState
            )
            try persistCurrentIdentity(identity)
        }

        if let signalState = identity.standardsSignalState {
            let refreshed = try await NativeExecution.run {
                try StandardsCoreBridge.refreshSignalBundle(signalState: signalState)
            }
            identity = identity.updatingStandards(
                signalBundle: refreshed.signalBundle,
                signalState: refreshed.signalState
            )
            try persistCurrentIdentity(identity)
        }

        let registration = try await bootstrapRelaySession(identity: identity)
        currentUser = registration.user
        try await sync()
    }

    func syncNow() async {
        do {
            try await sync()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func resetTransparencyTrust() async {
        let relayKey = relayOrigin.trimmingCharacters(in: .whitespacesAndNewlines)
        transparencyPins.removeValue(forKey: relayKey)
        transparencySignerPins.removeValue(forKey: relayKey)
        Self.persistPinnedHeads(transparencyPins)
        Self.persistPinnedSignerKeys(transparencySignerPins)
        transparency = .empty
        statusMessage = "Cleared pinned transparency trust for this relay on this Mac. Syncing the current relay state again..."
        errorMessage = nil

        do {
            try await sync()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func sync() async throws {
        guard var identity = currentIdentity else {
            return
        }

        try await ensureRelaySession(for: identity)
        let (client, health) = try await relayClientAndHealth()
        relayProtocolPolicy = health.protocolPolicy
        await applyPrivacyDelayIfEnabled(.sync)
        let payload = try await client.sync()
        let transparencySnapshot = try await client.transparency()
        let deviceSnapshot = try await client.securityDevices()
        let directory = payload.users.sorted { $0.username < $1.username }
        let lookup = Dictionary(uniqueKeysWithValues: directory.map { ($0.id, $0) })
        transparency = try await verifyTransparency(
            entryCount: transparencySnapshot.entryCount ?? transparencySnapshot.transparencyEntries?.count ?? 0,
            entries: transparencySnapshot.transparencyEntries ?? [],
            expectedHead: transparencySnapshot.transparencyHead,
            expectedSignature: transparencySnapshot.transparencySignature,
            signer: transparencySnapshot.transparencySigner
        )
        contactSecurityState = reconcileContactSecurityState(users: directory, identity: identity)

        let decryptedThreads = try payload.threads
            .map { thread in
                try materialize(thread: thread, usersById: lookup, identity: &identity)
            }
            .sorted(by: sortConversationThreads)
        let visibleThreads = decryptedThreads.filter { threadRecords[$0.id]?.hiddenAt == nil }

        if identity != currentIdentity {
            try persistCurrentIdentity(identity)
        }
        try persistThreadStore()
        try persistSecurityState()

        users = directory
        currentUser = lookup[identity.id]
        linkedDevices = deviceSnapshot.devices.sorted { $0.updatedAt > $1.updatedAt }
        linkedDeviceEvents = deviceSnapshot.deviceEvents.sorted { $0.createdAt > $1.createdAt }
        threads = visibleThreads

        if selectedThreadID == nil {
            selectedThreadID = visibleThreads.first?.id
        } else if !visibleThreads.contains(where: { $0.id == selectedThreadID }) {
            selectedThreadID = visibleThreads.first?.id
        }

        if !transparency.chainValid {
            statusMessage = "Synced \(directory.count) identities and \(visibleThreads.count) threads. Transparency verification needs attention."
        } else if hasPendingSecurityActions {
            statusMessage = "Synced \(directory.count) identities and \(visibleThreads.count) threads. Contact security review needs attention."
        } else {
            statusMessage = "Synced \(directory.count) identities and \(visibleThreads.count) threads from the relay."
        }
    }

    func presentComposer() {
        composeTitle = ""
        composeSelection = []
        directorySearchQuery = ""
        directorySearchResults = []
        composePresented = true
    }

    func chooseAttachments() async {
        do {
            let imported = try AttachmentGateway.importAttachments()
            let existingIds = Set(pendingAttachments.map(\.id))
            pendingAttachments.append(contentsOf: imported.filter { !existingIds.contains($0.id) })
            statusMessage = "Prepared \(pendingAttachments.count) attachment\(pendingAttachments.count == 1 ? "" : "s") for encrypted send."
        } catch {
            if case AttachmentGatewayError.importCancelled = error {
                return
            }
            if let attachmentError = error as? AttachmentGatewayError, case .importCancelled = attachmentError {
                return
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    func removePendingAttachment(_ attachmentId: String) {
        pendingAttachments.removeAll { $0.id == attachmentId }
    }

    func searchDirectory() async {
        guard let identity = currentIdentity else {
            return
        }

        let query = directorySearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        let localMatches = contacts
            .filter { matchesDirectoryQuery($0, query: query) }

        guard query.count >= 3 else {
            directorySearchResults = localMatches
            if localMatches.isEmpty {
                errorMessage = "Search by username or invite code needs at least 3 characters."
            } else {
                errorMessage = nil
                statusMessage = "Showing local matches for that short search query on this Mac."
            }
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            try await ensureRelaySession(for: identity)
            await applyPrivacyDelayIfEnabled(.interactive)
            let response = try await currentRelayClient.searchDirectory(query: query.lowercased())
            directorySearchResults = mergeDirectoryMatches(localMatches, response.results.filter { $0.id != identity.id })
            let lookupMode = "username or invite code"
            let count = directorySearchResults.count
            statusMessage = "Directory search over \(lookupMode) returned \(count) result\(count == 1 ? "" : "s")."
        } catch {
            if localMatches.isEmpty {
                errorMessage = error.localizedDescription
            } else {
                directorySearchResults = localMatches
                errorMessage = nil
                statusMessage = "Relay lookup failed, so this Mac is showing local matches only."
            }
        }
    }

    func switchIdentity(to userId: String) async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            _ = try identityStore.setActiveIdentity(userId)
            try reloadLocalProfiles(preferredUserId: userId)
            clearRemoteWorkspace()
            try await registerAndSync()
            if let identity = currentIdentity {
                statusMessage = "Switched to \(identity.displayName)'s local Notrus profile."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func revokeLinkedDevice(_ deviceId: String) async {
        guard let identity = currentIdentity else {
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            try await ensureRelaySession(for: identity)
            _ = try await deviceSecretStore.reauthenticateInteractively(
                reason: "Approve the linked-device revocation from this Mac."
            )
            refreshUnlockedDeviceSessionMetadata()
            let currentDevice = try await NativeExecution.run {
                try self.deviceSecretStore.deviceDescriptor(
                    reason: "Reuse the approved local Notrus vault session on this Mac."
                )
            }
            let createdAt = ISO8601DateFormatter().string(from: Date())
            let payload = NotrusCrypto.deviceActionSignaturePayload(
                action: "device-revoke",
                createdAt: createdAt,
                signerDeviceId: currentDevice.id,
                targetDeviceId: deviceId,
                userId: identity.id
            )
            let signature = try await NativeExecution.run {
                try self.deviceSecretStore.signDeviceAction(
                    payload,
                    reason: "Reuse the approved local Notrus vault session on this Mac."
                )
            }
            currentDeviceDescriptor = currentDevice
            let response = try await currentRelayClient.revokeDevice(
                userId: identity.id,
                signerDeviceId: currentDevice.id,
                targetDeviceId: deviceId,
                createdAt: createdAt,
                signature: signature
            )
            linkedDevices = response.devices.sorted { $0.updatedAt > $1.updatedAt }
            linkedDeviceEvents = response.deviceEvents.sorted { $0.createdAt > $1.createdAt }
            statusMessage = "Revoked linked device \(deviceId)."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func prepareCurrentAccountExport(passphrase: String) async -> PreparedRecoveryArchiveExport? {
        guard let identity = currentIdentity else {
            return nil
        }

        guard passphrase.trimmingCharacters(in: .whitespacesAndNewlines).count >= 8 else {
            errorMessage = "Use an export passphrase with at least 8 characters."
            return nil
        }

        do {
            beginBlockingBusy("Preparing the encrypted recovery archive...")
            defer { endBlockingBusy() }

            _ = try await deviceSecretStore.reauthenticateInteractively(
                reason: "Confirm local device authentication before exporting an encrypted recovery archive."
            )
            refreshUnlockedDeviceSessionMetadata()
            let records = threadRecords
            let data = try await NativeExecution.run {
                try AccountPortability.exportArchiveData(
                    identity: identity,
                    threadRecords: records,
                    passphrase: passphrase
                )
            }
            statusMessage = "Choose where to save \(identity.displayName)'s encrypted recovery archive."
            return PreparedRecoveryArchiveExport(
                defaultFileName: "notrus-\(identity.username)-recovery.json",
                displayName: identity.displayName,
                document: RecoveryArchiveDocument(data: data)
            )
        } catch {
            if !isUserCancellation(error) {
                errorMessage = error.localizedDescription
            }
            return nil
        }
    }

    func completePreparedExport(_ prepared: PreparedRecoveryArchiveExport, result: Result<URL, Error>) {
        switch result {
        case .success(let url):
            AccountPortability.revealExportedArchive(at: url)
            statusMessage = "Exported \(prepared.displayName)'s encrypted recovery archive to \(url.lastPathComponent)."
        case .failure(let error):
            if !isUserCancellation(error) {
                errorMessage = error.localizedDescription
            }
        }
    }

    func importAccount(from url: URL, passphrase: String) async {
        guard passphrase.trimmingCharacters(in: .whitespacesAndNewlines).count >= 8 else {
            errorMessage = "Use the recovery archive passphrase to import a profile."
            return
        }

        do {
            beginBlockingBusy("Importing the encrypted recovery archive onto this Mac...")
            defer { endBlockingBusy() }

            let payload = try await NativeExecution.run {
                try AccountPortability.importArchive(from: url, passphrase: passphrase)
            }
            _ = try await deviceSecretStore.reauthenticateInteractively(
                reason: "Confirm local device authentication before importing a recovery archive onto this Mac.",
                allowCreation: !identityStore.hasStoredProfiles()
            )
            refreshUnlockedDeviceSessionMetadata()
            switch payload {
            case .portable(let archive):
                try await importPortableArchive(archive, sourceFileName: url.lastPathComponent)
            case .transfer(let archive):
                try await importTransferArchive(archive, sourceFileName: url.lastPathComponent)
            }
        } catch {
            if !isUserCancellation(error) {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func importPortableArchive(_ archive: PortableAccountArchive, sourceFileName: String) async throws {
        _ = try identityStore.saveIdentity(archive.identity, makeActive: true)
        try threadStateStore.saveRecords(archive.threadRecords, for: archive.identity)
        try reloadLocalProfiles(preferredUserId: archive.identity.id)
        clearRemoteWorkspace()
        try await registerAndSync()
        statusMessage = "Imported \(archive.identity.displayName)'s encrypted recovery archive from \(sourceFileName)."
    }

    private func importTransferArchive(_ archive: RecoveryTransferArchive, sourceFileName: String) async throws {
        let normalizedRecovery = try await NativeExecution.run {
            try NotrusCrypto.recoveryAuthority(from: archive.identity.recoveryRepresentation)
        }
        let normalizedIdentity = PortableArchiveIdentitySnapshot(
            id: archive.identity.id,
            username: archive.identity.username,
            displayName: archive.identity.displayName,
            createdAt: archive.identity.createdAt,
            recoveryFingerprint: normalizedRecovery.fingerprint,
            recoveryPublicJwk: normalizedRecovery.publicJwk,
            recoveryRepresentation: archive.identity.recoveryRepresentation
        )
        let rebuiltBase = try await NativeExecution.run {
            try NotrusCrypto.transferredIdentity(from: normalizedIdentity)
        }
        let standards = try await NativeExecution.run {
            try StandardsCoreBridge.createIdentity(
                displayName: normalizedIdentity.displayName,
                threadUserId: normalizedIdentity.id,
                username: normalizedIdentity.username
            )
        }
        let rebuiltIdentity = rebuiltBase.updatingStandards(
            mlsKeyPackage: standards.mlsKeyPackage,
            mlsState: standards.mlsState,
            signalBundle: standards.signalBundle,
            signalState: standards.signalState
        )
        let currentDevice = try await NativeExecution.run {
            try self.deviceSecretStore.deviceDescriptor(
                reason: "Approve importing this recovery archive onto this Mac and publishing a recovery-authorized account reset."
            )
        }
        currentDeviceDescriptor = currentDevice
        let unsignedRequest = NotrusCrypto.normalizedForRelay(AccountResetRequest(
            createdAt: NotrusCrypto.isoNow(),
            device: currentDevice,
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
        let signedRequest = NotrusCrypto.normalizedForRelay(AccountResetRequest(
            createdAt: unsignedRequest.createdAt,
            device: unsignedRequest.device,
            displayName: unsignedRequest.displayName,
            encryptionPublicJwk: unsignedRequest.encryptionPublicJwk,
            fingerprint: unsignedRequest.fingerprint,
            mlsKeyPackage: unsignedRequest.mlsKeyPackage,
            prekeyCreatedAt: unsignedRequest.prekeyCreatedAt,
            prekeyFingerprint: unsignedRequest.prekeyFingerprint,
            prekeyPublicJwk: unsignedRequest.prekeyPublicJwk,
            prekeySignature: unsignedRequest.prekeySignature,
            recoveryFingerprint: unsignedRequest.recoveryFingerprint,
            recoveryPublicJwk: unsignedRequest.recoveryPublicJwk,
            recoverySignature: try await NativeExecution.run {
                try NotrusCrypto.signAccountReset(unsignedRequest, recoveryRepresentation: archive.identity.recoveryRepresentation)
            },
            signalBundle: unsignedRequest.signalBundle,
            signingPublicJwk: unsignedRequest.signingPublicJwk,
            userId: unsignedRequest.userId,
            username: unsignedRequest.username
        ))
        let response = try await currentRelayClient.resetAccount(signedRequest)
        let mergedIdentity = mergeRegisteredIdentity(rebuiltIdentity, registered: response.user)
        relaySession = response.session
        currentUser = response.user
        linkedDevices = (response.devices ?? []).sorted { $0.updatedAt > $1.updatedAt }
        linkedDeviceEvents = (response.deviceEvents ?? []).sorted { $0.createdAt > $1.createdAt }
        try securityStateStore.deleteState(for: mergedIdentity.id)
        try threadStateStore.saveRecords([:], for: mergedIdentity)
        _ = try identityStore.saveIdentity(mergedIdentity, makeActive: true)
        try reloadLocalProfiles(preferredUserId: mergedIdentity.id)
        clearRemoteWorkspace(preserveRelaySession: true)
        try await sync()
        statusMessage = "Imported \(mergedIdentity.displayName)'s \(archive.sourcePlatform) recovery archive from \(sourceFileName) and published a recovery-authorized account reset."
    }

    func resetLocalVault() async {
        beginBlockingBusy("Resetting the local Notrus vault on this Mac...")
        defer { endBlockingBusy() }

        do {
            try threadStateStore.resetAll()
            try securityStateStore.resetAll()
            try identityStore.resetAll()
            try deviceSecretStore.purgeAllLocalSecrets()
            localProfiles = []
            currentIdentity = nil
            threadRecords = [:]
            contactSecurityState = ContactSecurityState(version: 1, contacts: [:], events: [])
            localVaultLocked = false
            clearRemoteWorkspace()
            clearUnlockedDeviceSessionMetadata()
            statusMessage = "Reset the local Notrus vault on this Mac. You can now create a new profile or import a recovery archive."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func createThread() async {
        guard let identity = currentIdentity else {
            return
        }

        guard transparency.chainValid else {
            errorMessage = "Transparency verification needs attention before this Mac creates a new secure thread."
            return
        }

        let selected = Array(composeSelection).sorted()
        guard !selected.isEmpty else {
            errorMessage = "Choose at least one contact."
            return
        }

        if let blockedContact = selected.first(where: { isContactBlocked($0) }) {
            let name = users.first(where: { $0.id == blockedContact })?.displayName ?? "That contact"
            errorMessage = "\(name) is blocked on this Mac. Unblock the contact in Account Center before starting another conversation."
            return
        }

        if let blockedContact = selected.first(where: { contactSecurityState.contacts[$0]?.status == .changed }) {
            let name = users.first(where: { $0.id == blockedContact })?.displayName ?? "That contact"
            errorMessage = "\(name) presented a changed identity key on the relay. Verify the new safety number before starting another conversation."
            return
        }

        beginBlockingBusy("Creating the secure thread on this Mac...")
        defer { endBlockingBusy() }

        do {
            try restoreDeletedContactsIfPresent(selected)
            try await ensureRelaySession(for: identity)
            let participants = ([identity.id] + selected).sorted()
            let protocolName = NotrusProtocolCatalog.chooseProtocol(participantCount: participants.count)
            let protocolSpec = NotrusProtocolCatalog.spec(for: protocolName)
            let localThreadTitle = composeTitle.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !isProtocolBlocked(protocolName) else {
                throw RelayClientError.requestFailed(
                    "\(protocolSpec.label) is blocked by the active standards policy. Notrus still needs a real PQXDH/Double Ratchet 1:1 path and RFC 9420 MLS groups before this mode can create conversations."
                )
            }
            let participantsById = try await refreshedRoutingUsers(
                selectedUserIds: selected,
                participantsById: Dictionary(uniqueKeysWithValues: composeCandidates.map { ($0.id, $0) })
            )
            let participantHandles = selected.compactMap { participantsById[$0]?.contactHandle }
            if protocolName == "signal-pqxdh-double-ratchet-v1",
               let remoteUserId = selected.first,
               restoreHiddenDirectThreadIfPresent(remoteUserId: remoteUserId)
            {
                composePresented = false
                try await sync()
                if let restoredThreadId = threadRecords.first(where: { $0.value.standardsSignalPeerUserId == remoteUserId && $0.value.hiddenAt == nil })?.key {
                    selectedThreadID = restoredThreadId
                }
                statusMessage = "Restored the local direct conversation on this Mac."
                return
            }
            let prepared = try await NativeExecution.run {
                let threadId = UUID().uuidString.lowercased()
                let createdAt = NotrusCrypto.isoNow()
                switch protocolName {
                case "signal-pqxdh-double-ratchet-v1":
                    guard participants.count == 2 else {
                        throw RelayClientError.requestFailed("Signal direct threads require exactly two participants.")
                    }
                    guard let remoteUser = participants.compactMap({ participantsById[$0] }).first(where: { $0.id != identity.id }) else {
                        throw RelayClientError.requestFailed("Signal direct threads require one remote participant.")
                    }
                    guard identity.standardsSignalState != nil, identity.standardsSignalBundle != nil else {
                        throw RelayClientError.requestFailed("This macOS profile is missing its bundled Signal standards state.")
                    }
                    guard remoteUser.signalBundle != nil else {
                        throw RelayClientError.requestFailed("\(remoteUser.displayName) does not currently advertise a Signal pre-key bundle on the relay.")
                    }

                    return PreparedThreadCreation(
                        request: ThreadCreateRequest(
                            createdAt: createdAt,
                            envelopes: [],
                            groupState: nil,
                            id: threadId,
                            initialRatchetPublicJwk: nil,
                            mlsBootstrap: nil,
                            participantHandles: participantHandles,
                            protocol: protocolName,
                            title: ""
                        ),
                        localThreadRecord: ThreadStoreRecord(
                            bootstrapState: nil,
                            currentState: nil,
                            groupTreeState: nil,
                            lastProcessedMessageId: nil,
                            localTitle: localThreadTitle.isEmpty ? nil : localThreadTitle,
                            messageCache: [:],
                            pendingSentStates: [:],
                            processedMessageCount: 0,
                            protocolField: protocolName,
                            standardsMlsThreadState: nil,
                            standardsSignalPeerUserId: remoteUser.id
                        ),
                        protocolName: protocolName,
                        threadId: threadId,
                        updatedIdentity: nil
                    )
                case "mls-rfc9420-v1":
                    guard participants.count >= 3 else {
                        throw RelayClientError.requestFailed("MLS group threads require at least three participants.")
                    }
                    guard identity.standardsSignalState != nil, identity.standardsSignalBundle != nil else {
                        throw RelayClientError.requestFailed("This macOS profile is missing the local Signal standards state required for group fanout compatibility.")
                    }
                    let remoteParticipants = participants
                        .compactMap { participantsById[$0] }
                        .filter { $0.id != identity.id }
                    if let missingSignal = remoteParticipants.first(where: { $0.signalBundle == nil }) {
                        throw RelayClientError.requestFailed("\(missingSignal.displayName) does not currently advertise a Signal bundle required for compatible group fanout.")
                    }
                    let canUseNativeMls =
                        identity.standardsMlsState != nil &&
                        remoteParticipants.allSatisfy { $0.mlsKeyPackage != nil }
                    if canUseNativeMls {
                        let participantKeyPackages = remoteParticipants.reduce(into: [String: PublicMlsKeyPackage]()) { partial, participant in
                            if let package = participant.mlsKeyPackage {
                                partial[participant.id] = package
                            }
                        }
                        guard let localMlsState = identity.standardsMlsState else {
                            throw RelayClientError.requestFailed("This macOS profile is missing its MLS account state.")
                        }
                        let created = try StandardsCoreBridge.mlsCreateGroup(
                            creatorMlsState: localMlsState,
                            creatorUserId: identity.id,
                            participantKeyPackages: participantKeyPackages,
                            participantUserIds: participants,
                            threadId: threadId
                        )
                        let updatedIdentity = identity.updatingStandards(mlsState: created.creatorMlsState)

                        return PreparedThreadCreation(
                            request: ThreadCreateRequest(
                                createdAt: createdAt,
                                envelopes: [],
                                groupState: nil,
                                id: threadId,
                                initialRatchetPublicJwk: nil,
                                mlsBootstrap: created.threadBootstrap,
                                participantHandles: participantHandles,
                                protocol: protocolName,
                                title: ""
                            ),
                            localThreadRecord: ThreadStoreRecord(
                                bootstrapState: nil,
                                currentState: nil,
                                groupTreeState: nil,
                                lastProcessedMessageId: nil,
                                localTitle: localThreadTitle.isEmpty ? nil : localThreadTitle,
                                messageCache: [:],
                                pendingSentStates: [:],
                                processedMessageCount: 0,
                                protocolField: protocolName,
                                standardsMlsThreadState: created.threadState,
                                standardsSignalPeerUserId: nil
                            ),
                            protocolName: protocolName,
                            threadId: threadId,
                            updatedIdentity: updatedIdentity
                        )
                    }

                    let fanoutBootstrap = RelayMlsBootstrap(
                        ciphersuite: Self.mlsFanoutCiphersuite,
                        groupId: "\(Self.mlsFanoutGroupPrefix)\(threadId)",
                        welcomes: remoteParticipants.map { participant in
                            RelayMlsWelcomeEnvelope(
                                toUserId: participant.id,
                                welcome: Data("fanout:\(threadId):\(participant.id):\(createdAt)".utf8).base64EncodedString()
                            )
                        }
                    )
                    return PreparedThreadCreation(
                        request: ThreadCreateRequest(
                            createdAt: createdAt,
                            envelopes: [],
                            groupState: nil,
                            id: threadId,
                            initialRatchetPublicJwk: nil,
                            mlsBootstrap: fanoutBootstrap,
                            participantHandles: participantHandles,
                            protocol: protocolName,
                            title: ""
                        ),
                        localThreadRecord: ThreadStoreRecord(
                            bootstrapState: nil,
                            currentState: nil,
                            groupTreeState: nil,
                            lastProcessedMessageId: nil,
                            localTitle: localThreadTitle.isEmpty ? nil : localThreadTitle,
                            messageCache: [:],
                            pendingSentStates: [:],
                            processedMessageCount: 0,
                            protocolField: protocolName,
                            standardsMlsThreadState: nil,
                            standardsSignalPeerUserId: nil
                        ),
                        protocolName: protocolName,
                        threadId: threadId,
                        updatedIdentity: nil
                    )
                default:
                    let roomKey = NotrusCrypto.randomRoomKey()
                    let envelopes = try participants.map { participantId in
                        guard let participant = participantsById[participantId] else {
                            throw RelayClientError.requestFailed("A selected participant is missing from the relay directory.")
                        }

                        return try NotrusCrypto.wrapRoomKeyForRecipient(
                            createdAt: createdAt,
                            fromUserId: identity.id,
                            recipientEncryptionPublicJwk: participant.encryptionPublicJwk,
                            roomKey: roomKey,
                            senderEncryptionRepresentation: identity.encryptionRepresentation,
                            senderSigningRepresentation: identity.signingRepresentation,
                            threadId: participants.count == 2 ? threadId : "\(threadId):epoch:1",
                            toUserId: participantId
                        )
                    }

                    var initialRatchetPublicJwk: JWK? = nil
                    var groupState: RelayGroupState? = nil
                    var localThreadRecord: ThreadStoreRecord? = nil

                    if participants.count == 2 {
                        guard let remoteUser = participants.compactMap({ participantsById[$0] }).first(where: { $0.id != identity.id }) else {
                            throw RelayClientError.requestFailed("Pairwise threads require exactly one remote participant.")
                        }
                        guard try NotrusCrypto.verifySignedPrekeyRecord(remoteUser) else {
                            throw NativeProtocolError.invalidPrekey
                        }
                        guard let prekeyPublicJwk = remoteUser.prekeyPublicJwk else {
                            throw NativeProtocolError.invalidPrekey
                        }

                        let creatorState = try NotrusCrypto.createPairwiseCreatorThreadState(
                            creatorId: identity.id,
                            recipientId: remoteUser.id,
                            recipientPrekeyPublicJwk: prekeyPublicJwk,
                            roomKey: roomKey,
                            threadId: threadId
                        )

                        initialRatchetPublicJwk = creatorState.localRatchetPublicJwk
                        localThreadRecord = ThreadStoreRecord(
                            bootstrapState: creatorState,
                            currentState: creatorState,
                            groupTreeState: nil,
                            lastProcessedMessageId: nil,
                            localTitle: localThreadTitle.isEmpty ? nil : localThreadTitle,
                            messageCache: [:],
                            pendingSentStates: [:],
                            processedMessageCount: 0,
                            protocolField: protocolName,
                            standardsMlsThreadState: nil,
                            standardsSignalPeerUserId: nil
                        )
                    } else {
                        let initialState = try NotrusCrypto.createGroupTreeThreadState(
                            participantIds: participants,
                            roomKey: roomKey,
                            threadId: threadId
                        )
                        groupState = RelayGroupState(
                            epoch: initialState.currentEpoch,
                            participantIds: initialState.memberIds,
                            transcriptHash: initialState.transcriptHash ?? "",
                            treeHash: initialState.treeHash ?? ""
                        )
                        localThreadRecord = ThreadStoreRecord(
                            bootstrapState: nil,
                            currentState: nil,
                            groupTreeState: initialState,
                            lastProcessedMessageId: nil,
                            localTitle: localThreadTitle.isEmpty ? nil : localThreadTitle,
                            messageCache: [:],
                            pendingSentStates: [:],
                            processedMessageCount: 0,
                            protocolField: protocolName,
                            standardsMlsThreadState: nil,
                            standardsSignalPeerUserId: nil
                        )
                    }

                    return PreparedThreadCreation(
                        request: ThreadCreateRequest(
                            createdAt: createdAt,
                            envelopes: envelopes,
                            groupState: groupState,
                            id: threadId,
                            initialRatchetPublicJwk: initialRatchetPublicJwk,
                            mlsBootstrap: nil,
                            participantHandles: participantHandles,
                            protocol: protocolName,
                            title: ""
                        ),
                        localThreadRecord: localThreadRecord,
                        protocolName: protocolName,
                        threadId: threadId,
                        updatedIdentity: nil
                    )
                }
            }

            await applyPrivacyDelayIfEnabled(.interactive)
            _ = try await currentRelayClient.createThread(prepared.request)

            composePresented = false
            if let updatedIdentity = prepared.updatedIdentity {
                try persistCurrentIdentity(updatedIdentity)
            }
            if let localThreadRecord = prepared.localThreadRecord {
                threadRecords[prepared.threadId] = localThreadRecord
                try persistThreadStore()
            }
            try await sync()
            selectedThreadID = prepared.threadId
            statusMessage = "Created a native thread using \(NotrusProtocolCatalog.spec(for: prepared.protocolName).label)."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func sendMessage() async {
        guard
            let currentIdentity,
            let thread = selectedThread
        else {
            return
        }

        let text = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty || !pendingAttachments.isEmpty else {
            return
        }

        if selectedThreadRequiresReverification {
            errorMessage = "This conversation has a pending identity-key change. Verify the new safety number before sending."
            return
        }

        if selectedThreadContainsBlockedContact {
            errorMessage = "This conversation includes a blocked contact on this Mac. Unblock the contact before sending."
            return
        }

        if !transparency.chainValid {
            if transparencyWarningsAreResettable {
                await resetTransparencyTrust()
            }
            guard transparency.chainValid else {
                errorMessage = transparencyWarningsAreResettable
                    ? "Transparency verification still needs attention after refreshing this Mac's trust pins."
                    : "Transparency verification needs attention before this Mac sends more ciphertext."
                return
            }
        }

        let protocolName = thread.rawThread.protocolField ?? "static-room-v1"
        let protocolSpec = NotrusProtocolCatalog.spec(for: protocolName)
        guard !isProtocolBlocked(protocolName) else {
            errorMessage = "\(protocolSpec.label) is blocked by the active standards policy. This conversation stays visible for migration work, but sending is disabled until a standards-based replacement exists."
            return
        }

        beginBlockingBusy("Encrypting and sending ciphertext...")
        defer { endBlockingBusy() }

        do {
            await applyPrivacyDelayIfEnabled(.delivery)
            var attachments: [SecureAttachmentReference] = []
            attachments.reserveCapacity(pendingAttachments.count)
            for draft in pendingAttachments {
                let data = try Data(contentsOf: draft.url)
                let sealed = try NotrusCrypto.sealAttachment(
                    data: data,
                    fileName: draft.fileName,
                    mediaType: draft.mediaType,
                    senderId: currentIdentity.id,
                    threadId: thread.id
                )
                let route = try routingState(for: thread)
                _ = try await currentRelayClient.uploadAttachment(
                    mailboxHandle: route.mailboxHandle,
                    deliveryCapability: route.deliveryCapability,
                    attachment: sealed.request.relayTransportForm()
                )
                attachments.append(sealed.reference)
            }

            let payload = MessagePayload(
                attachments: attachments,
                cover: nil,
                epochCommit: nil,
                padding: nil,
                text: text
            )
            if !attachments.isEmpty && !["signal-pqxdh-double-ratchet-v1", "mls-rfc9420-v1"].contains(protocolName) {
                throw RelayClientError.requestFailed("Encrypted attachments currently require the standards-based Signal or MLS production path.")
            }
            switch thread.rawThread.protocolField ?? "static-room-v1" {
            case "signal-pqxdh-double-ratchet-v1":
                try await sendStandardsSignalMessage(thread: thread, identity: currentIdentity, payload: payload)
            case "mls-rfc9420-v1":
                try await sendStandardsMlsMessage(thread: thread, identity: currentIdentity, payload: payload)
            case "pairwise-v2":
                try await sendPairwiseMessage(thread: thread, identity: currentIdentity, payload: payload)
            case "group-tree-v3":
                try await sendGroupTreeMessage(thread: thread, identity: currentIdentity, payload: payload)
            default:
                try await sendStaticMessage(thread: thread, identity: currentIdentity, text: text)
            }
            draftText = ""
            pendingAttachments = []
            try await sync()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteCurrentIdentity() async {
        guard let identity = currentIdentity else {
            return
        }
        await deleteIdentity(identity.id)
    }

    func deleteIdentity(_ userId: String) async {
        guard let identity = localProfiles.first(where: { $0.id == userId }) else {
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            _ = try await deviceSecretStore.reauthenticateInteractively(
                reason: "Confirm local device authentication before deleting this local Notrus profile from this Mac."
            )
            refreshUnlockedDeviceSessionMetadata()
            let deletingCurrentIdentity = currentIdentity?.id == identity.id
            if deletingCurrentIdentity {
                try await ensureRelaySession(for: identity)
                _ = try await currentRelayClient.deleteAccount()
                relaySession = nil
            }
            try threadStateStore.deleteRecords(for: identity.id)
            try securityStateStore.deleteState(for: identity.id)
            _ = try identityStore.deleteIdentity(userId: identity.id)
            try reloadLocalProfiles()
            clearRemoteWorkspace()

            if currentIdentity != nil {
                try await registerAndSync()
                statusMessage = "Removed \(identity.displayName)'s profile and switched to the next account."
            } else {
                statusMessage = deletingCurrentIdentity
                    ? "Deleted the last Notrus profile from this Mac and deactivated its relay account."
                    : "Removed the last local Notrus profile from this Mac."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func rotateCurrentIdentityKeys() async {
        guard let identity = currentIdentity else {
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            _ = try await deviceSecretStore.reauthenticateInteractively(
                reason: "Confirm local device authentication before rotating this account's identity keys and publishing an account reset."
            )
            refreshUnlockedDeviceSessionMetadata()
            let rotatedBase = try await NativeExecution.run {
                try NotrusCrypto.rotatedIdentity(from: identity)
            }
            let standards = try await NativeExecution.run {
                try StandardsCoreBridge.createIdentity(
                    displayName: identity.displayName,
                    threadUserId: identity.id,
                    username: identity.username
                )
            }
            let rotatedIdentity = rotatedBase.updatingStandards(
                mlsKeyPackage: standards.mlsKeyPackage,
                mlsState: standards.mlsState,
                signalBundle: standards.signalBundle,
                signalState: standards.signalState
            )
            let createdAt = NotrusCrypto.isoNow()
            let currentDevice = try await NativeExecution.run {
                try self.deviceSecretStore.deviceDescriptor(
                    reason: "Approve the linked-device signature for this account reset from this Mac."
                )
            }
            currentDeviceDescriptor = currentDevice
            let unsignedRequest = AccountResetRequest(
                createdAt: createdAt,
                device: currentDevice,
                displayName: rotatedIdentity.displayName,
                encryptionPublicJwk: rotatedIdentity.encryptionPublicJwk,
                fingerprint: rotatedIdentity.fingerprint,
                mlsKeyPackage: rotatedIdentity.standardsMlsKeyPackage,
                prekeyCreatedAt: rotatedIdentity.prekeyCreatedAt,
                prekeyFingerprint: rotatedIdentity.prekeyFingerprint,
                prekeyPublicJwk: rotatedIdentity.prekeyPublicJwk,
                prekeySignature: rotatedIdentity.prekeySignature,
                recoveryFingerprint: rotatedIdentity.recoveryFingerprint,
                recoveryPublicJwk: rotatedIdentity.recoveryPublicJwk,
                recoverySignature: "",
                signalBundle: rotatedIdentity.standardsSignalBundle,
                signingPublicJwk: rotatedIdentity.signingPublicJwk,
                userId: rotatedIdentity.id,
                username: rotatedIdentity.username
            )
            let recoverySignature = try await NativeExecution.run {
                try NotrusCrypto.signAccountReset(unsignedRequest, recoveryRepresentation: identity.recoveryRepresentation)
            }
            let signedRequest = AccountResetRequest(
                createdAt: unsignedRequest.createdAt,
                device: unsignedRequest.device,
                displayName: unsignedRequest.displayName,
                encryptionPublicJwk: unsignedRequest.encryptionPublicJwk,
                fingerprint: unsignedRequest.fingerprint,
                mlsKeyPackage: unsignedRequest.mlsKeyPackage,
                prekeyCreatedAt: unsignedRequest.prekeyCreatedAt,
                prekeyFingerprint: unsignedRequest.prekeyFingerprint,
                prekeyPublicJwk: unsignedRequest.prekeyPublicJwk,
                prekeySignature: unsignedRequest.prekeySignature,
                recoveryFingerprint: unsignedRequest.recoveryFingerprint,
                recoveryPublicJwk: unsignedRequest.recoveryPublicJwk,
                recoverySignature: recoverySignature,
                signalBundle: unsignedRequest.signalBundle,
                signingPublicJwk: unsignedRequest.signingPublicJwk,
                userId: unsignedRequest.userId,
                username: unsignedRequest.username
            )

            let response = try await currentRelayClient.resetAccount(signedRequest)
            let mergedIdentity = mergeRegisteredIdentity(rotatedIdentity, registered: response.user)
            relaySession = response.session
            currentUser = response.user
            linkedDevices = (response.devices ?? []).sorted { $0.updatedAt > $1.updatedAt }
            linkedDeviceEvents = (response.deviceEvents ?? []).sorted { $0.createdAt > $1.createdAt }
            threadRecords = [:]
            clearRemoteWorkspace(preserveRelaySession: true)
            try persistCurrentIdentity(mergedIdentity)
            try persistThreadStore()
            try await sync()
            statusMessage = "Rotated this account's identity keys and published a recovery-authorized account reset to the relay."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func verifyContact(_ userId: String) async {
        guard var record = contactSecurityState.contacts[userId] else {
            return
        }

        let now = NotrusCrypto.isoNow()
        let wasChanged = record.status == .changed

        do {
            if
                wasChanged,
                var identity = currentIdentity,
                let signalState = identity.standardsSignalState
            {
                let reset = try await NativeExecution.run {
                    try StandardsCoreBridge.signalResetPeer(localSignalState: signalState, remoteUserId: userId)
                }
                identity = identity.updatingStandards(signalState: reset.localSignalState)
                try persistCurrentIdentity(identity)
                threadRecords = threadRecords.filter { _, value in
                    value.standardsSignalPeerUserId != userId
                }
                try persistThreadStore()
            }

            record.trustedFingerprint = record.observedFingerprint
            record.trustedPrekeyFingerprint = record.observedPrekeyFingerprint
            record.lastVerifiedAt = now
            record.verificationMethod = "out-of-band"
            record.status = .verified
            contactSecurityState.contacts[userId] = record
            contactSecurityState.events = contactSecurityState.events.map { event in
                guard event.userId == userId, event.requiresAction, event.dismissedAt == nil else {
                    return event
                }
                var updated = event
                updated.dismissedAt = now
                return updated
            }

            try persistSecurityState()
            if wasChanged {
                try await sync()
                statusMessage = "Verified \(record.displayName)'s new safety number and cleared stale direct-session state on this Mac. Recreate direct conversations if needed."
            } else {
                statusMessage = "Marked \(record.displayName)'s current safety number as verified on this Mac."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func dismissSecurityEvent(_ eventId: String) {
        let now = NotrusCrypto.isoNow()
        contactSecurityState.events = contactSecurityState.events.map { event in
            guard event.id == eventId else {
                return event
            }
            var updated = event
            updated.dismissedAt = now
            return updated
        }

        do {
            try persistSecurityState()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func contactTrust(for userId: String) -> ContactTrustRecord? {
        contactSecurityState.contacts[userId]
    }

    func isContactLocallyDeleted(_ userId: String) -> Bool {
        contactSecurityState.contacts[userId]?.deletedAt != nil
    }

    func isContactBlocked(_ userId: String) -> Bool {
        contactSecurityState.contacts[userId]?.blockedAt != nil
    }

    func blockContact(_ userId: String) {
        guard var record = contactSecurityState.contacts[userId] else {
            return
        }
        guard record.blockedAt == nil else {
            return
        }

        record.blockedAt = NotrusCrypto.isoNow()
        contactSecurityState.contacts[userId] = record
        do {
            try persistSecurityState()
            statusMessage = "Blocked \(record.displayName) on this Mac. New threads and sends to that contact are now disabled locally."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func unblockContact(_ userId: String) {
        guard var record = contactSecurityState.contacts[userId] else {
            return
        }
        guard record.blockedAt != nil else {
            return
        }

        record.blockedAt = nil
        contactSecurityState.contacts[userId] = record
        do {
            try persistSecurityState()
            statusMessage = "Unblocked \(record.displayName) on this Mac."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteLocalContact(_ userId: String) {
        guard var record = contactSecurityState.contacts[userId] else {
            return
        }

        record.deletedAt = NotrusCrypto.isoNow()
        record.blockedAt = nil
        contactSecurityState.contacts[userId] = record
        contactSecurityState.events.removeAll { $0.userId == userId }
        directorySearchResults.removeAll { $0.id == userId }
        do {
            try persistSecurityState()
            statusMessage = "Deleted \(record.displayName)'s local contact record from this Mac."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteConversationLocally(_ threadId: String) {
        guard var record = threadRecords[threadId] else {
            return
        }

        record.hiddenAt = NotrusCrypto.isoNow()
        threadRecords[threadId] = record
        threads.removeAll { $0.id == threadId }
        if selectedThreadID == threadId {
            selectedThreadID = threads.first?.id
            draftText = ""
            pendingAttachments = []
        }

        do {
            try persistThreadStore()
            statusMessage = "Deleted the local copy of this conversation from this Mac."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func reportContact(_ userId: String, reason: String = "abuse-or-spam") async {
        guard let identity = currentIdentity else {
            return
        }
        guard let record = contactSecurityState.contacts[userId] else {
            return
        }

        let relevantThread = threads.first { thread in
            thread.participants.contains(where: { $0.id == identity.id }) &&
            thread.participants.contains(where: { $0.id == userId })
        }
        let messageIds = Array(relevantThread?.messages.suffix(10).map(\.id) ?? [])

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let response = try await currentRelayClient.reportAbuse(
                AbuseReportRequest(
                    createdAt: NotrusCrypto.isoNow(),
                    messageIds: messageIds,
                    reason: reason,
                    reporterId: identity.id,
                    targetUserId: userId,
                    threadId: relevantThread?.id
                )
            )
            statusMessage = "Submitted a minimal-evidence abuse report for \(record.displayName) as \(response.reportId)."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func safetyNumber(for userId: String) -> String? {
        guard
            let identity = currentIdentity,
            let record = contactSecurityState.contacts[userId]
        else {
            return nil
        }

        let source = [identity.fingerprint, record.observedFingerprint].sorted().joined(separator: ":")
        let digest = SHA256.hash(data: Data(source.utf8))
            .compactMap { String(format: "%02x", $0) }
            .joined()
        return stride(from: 0, to: digest.count, by: 4)
            .map { offset in
                let start = digest.index(digest.startIndex, offsetBy: offset)
                let end = digest.index(start, offsetBy: min(4, digest.distance(from: start, to: digest.endIndex)))
                return String(digest[start..<end])
            }
            .joined(separator: " ")
    }

    func saveAttachment(_ reference: SecureAttachmentReference, in thread: ConversationThread) async {
        guard currentIdentity != nil else {
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let route = try routingState(for: thread)
            let encrypted = try await currentRelayClient.fetchAttachment(
                mailboxHandle: route.mailboxHandle,
                deliveryCapability: route.deliveryCapability,
                attachmentId: reference.id,
            )
            let data = try NotrusCrypto.openAttachment(encrypted, reference: reference)
            try AttachmentGateway.saveAttachment(data: data, reference: reference)
            statusMessage = "Saved decrypted attachment to the location you chose."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func encodeStandardsPayload(_ payload: MessagePayload) throws -> String {
        let envelope = StandardsMessageEnvelope(
            attachments: payload.attachments,
            text: payload.text,
            version: 1
        )
        let data = try JSONEncoder().encode(envelope)
        return String(decoding: data, as: UTF8.self)
    }

    private func decodeStandardsPayload(_ plaintext: String) -> (text: String, attachments: [SecureAttachmentReference]) {
        guard
            let data = plaintext.data(using: .utf8),
            let envelope = try? JSONDecoder().decode(StandardsMessageEnvelope.self, from: data),
            envelope.version == 1
        else {
            return (plaintext, [])
        }
        return (envelope.text, envelope.attachments)
    }

    private func isMlsFanoutCompatibleThread(_ thread: RelayThread) -> Bool {
        if let bootstrap = thread.mlsBootstrap {
            if bootstrap.ciphersuite.caseInsensitiveCompare(Self.mlsFanoutCiphersuite) == .orderedSame {
                return true
            }
            if bootstrap.groupId.lowercased().hasPrefix(Self.mlsFanoutGroupPrefix.lowercased()) {
                return true
            }
        }
        return thread.messages.contains { message in
            guard let wireMessage = message.wireMessage else {
                return false
            }
            return (try? decodeMlsFanoutEnvelope(wireMessage)) != nil
        }
    }

    private func decodeMlsFanoutEnvelope(_ wireMessage: String) throws -> StandardsMlsFanoutEnvelope? {
        guard let data = wireMessage.data(using: .utf8) else {
            return nil
        }
        guard let envelope = try? JSONDecoder().decode(StandardsMlsFanoutEnvelope.self, from: data) else {
            return nil
        }
        guard envelope.format == Self.mlsFanoutEnvelopeFormat, envelope.version == 1 else {
            return nil
        }
        guard !envelope.senderId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RelayClientError.requestFailed("Compatible group envelope is missing its sender id.")
        }
        guard !envelope.recipients.isEmpty else {
            throw RelayClientError.requestFailed("Compatible group envelope has no recipients.")
        }
        if envelope.recipients.contains(where: {
            $0.toUserId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            $0.messageKind.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            $0.wireMessage.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }) {
            throw RelayClientError.requestFailed("Compatible group envelope contains an invalid recipient entry.")
        }
        return envelope
    }

    private func routingState(for thread: ConversationThread) throws -> (mailboxHandle: String, deliveryCapability: String) {
        guard
            let mailboxHandle = thread.rawThread.mailboxHandle,
            let deliveryCapability = thread.rawThread.deliveryCapability,
            !mailboxHandle.isEmpty,
            !deliveryCapability.isEmpty
        else {
            throw RelayClientError.requestFailed("This conversation is missing its current relay routing capability on this Mac. Sync once, then try again.")
        }
        return (mailboxHandle, deliveryCapability)
    }

    private func sendStaticMessage(thread: ConversationThread, identity: LocalIdentity, text: String) async throws {
        let roomKey = try roomKeyForThread(thread.rawThread, identity: identity)
        let outbound = try NotrusCrypto.sealMessage(
            text: text,
            roomKey: roomKey,
            senderId: identity.id,
            senderSigningRepresentation: identity.signingRepresentation,
            threadId: thread.id
        )
        let route = try routingState(for: thread)
        _ = try await currentRelayClient.postMessage(
            mailboxHandle: route.mailboxHandle,
            deliveryCapability: route.deliveryCapability,
            message: outbound.relayTransportForm()
        )
        statusMessage = "Sent signed ciphertext from the native macOS client."
    }

    private func sendStandardsSignalMessage(
        thread: ConversationThread,
        identity: LocalIdentity,
        payload: MessagePayload
    ) async throws {
        guard let signalState = identity.standardsSignalState else {
            throw RelayClientError.requestFailed("This macOS profile is missing its Signal standards state.")
        }

        let usersById = Dictionary(uniqueKeysWithValues: users.map { ($0.id, $0) })
        guard var record = threadRecords[thread.id] else {
            throw RelayClientError.requestFailed("This direct thread is missing local Signal session metadata on this Mac.")
        }

        let remoteUserId =
            record.standardsSignalPeerUserId ??
            thread.participants.first(where: { $0.id != identity.id })?.id
        guard let remoteUserId else {
            throw RelayClientError.requestFailed("This direct thread is missing its remote participant.")
        }

        record.standardsSignalPeerUserId = remoteUserId
        guard let remoteUser = usersById[remoteUserId], let remoteBundle = remoteUser.signalBundle else {
            throw RelayClientError.requestFailed("The remote participant is not currently advertising a Signal pre-key bundle on the relay.")
        }

        let plaintext = try encodeStandardsPayload(payload)

        let encrypted = try await NativeExecution.run {
            try StandardsCoreBridge.signalEncrypt(
                localSignalState: signalState,
                localUserId: identity.id,
                plaintext: plaintext,
                remoteBundle: remoteBundle,
                remoteUserId: remoteUserId
            )
        }

        let updatedIdentity = identity.updatingStandards(signalState: encrypted.localSignalState)
        let outbound = OutboundMessage(
            createdAt: NotrusCrypto.isoNow(),
            id: UUID().uuidString.lowercased(),
            messageKind: encrypted.messageKind,
            protocolField: "signal-pqxdh-double-ratchet-v1",
            senderId: identity.id,
            threadId: thread.id,
            wireMessage: encrypted.wireMessage
        )

        record.messageCache[outbound.id] = CachedMessageState(
            attachments: payload.attachments,
            body: payload.text,
            hidden: payload.cover == true,
            status: "ok"
        )
        threadRecords[thread.id] = record
        try persistThreadStore()
        try persistCurrentIdentity(updatedIdentity)

        do {
            let route = try routingState(for: thread)
            _ = try await currentRelayClient.postMessage(
                mailboxHandle: route.mailboxHandle,
                deliveryCapability: route.deliveryCapability,
                message: outbound.relayTransportForm()
            )
            statusMessage = "Sent ciphertext over PQXDH + Double Ratchet."
        } catch {
            record.messageCache.removeValue(forKey: outbound.id)
            threadRecords[thread.id] = record
            try persistThreadStore()
            throw error
        }
    }

    private func sendStandardsMlsMessage(
        thread: ConversationThread,
        identity: LocalIdentity,
        payload: MessagePayload
    ) async throws {
        guard var record = threadRecords[thread.id] else {
            throw RelayClientError.requestFailed("This MLS thread is missing local thread state on this Mac.")
        }
        let plaintext = try encodeStandardsPayload(payload)
        let useFanoutCompatibility = isMlsFanoutCompatibleThread(thread.rawThread)
        let updatedIdentity: LocalIdentity
        let outboundWireMessage: String

        if useFanoutCompatibility {
            guard var signalState = identity.standardsSignalState else {
                throw RelayClientError.requestFailed("This macOS profile is missing the local Signal standards state required for group fanout.")
            }
            let recipients = try thread.participants
                .filter { $0.id != identity.id }
                .sorted { $0.id < $1.id }
                .map { recipient -> StandardsMlsFanoutRecipient in
                    guard let bundle = recipient.signalBundle else {
                        throw RelayClientError.requestFailed("\(recipient.displayName) is missing a Signal bundle required for group fanout.")
                    }
                    let encrypted = try StandardsCoreBridge.signalEncrypt(
                        localSignalState: signalState,
                        localUserId: identity.id,
                        plaintext: plaintext,
                        remoteBundle: bundle,
                        remoteUserId: recipient.id
                    )
                    signalState = encrypted.localSignalState
                    return StandardsMlsFanoutRecipient(
                        messageKind: encrypted.messageKind,
                        toUserId: recipient.id,
                        wireMessage: encrypted.wireMessage
                    )
                }
            let envelope = StandardsMlsFanoutEnvelope(
                format: Self.mlsFanoutEnvelopeFormat,
                senderId: identity.id,
                version: 1,
                recipients: recipients
            )
            let encodedEnvelope = try JSONEncoder().encode(envelope)
            guard let wireMessage = String(data: encodedEnvelope, encoding: .utf8) else {
                throw RelayClientError.requestFailed("Unable to encode the compatibility group envelope.")
            }
            outboundWireMessage = wireMessage
            updatedIdentity = identity.updatingStandards(signalState: signalState)
        } else {
            guard let mlsState = identity.standardsMlsState else {
                throw RelayClientError.requestFailed("This macOS profile is missing its MLS account state.")
            }
            guard let threadState = record.standardsMlsThreadState else {
                throw RelayClientError.requestFailed("This MLS thread is missing its local native group state on this Mac.")
            }
            let encrypted = try await NativeExecution.run {
                try StandardsCoreBridge.mlsEncryptMessage(
                    localMlsState: mlsState,
                    plaintext: plaintext,
                    threadState: threadState
                )
            }
            updatedIdentity = identity.updatingStandards(mlsState: encrypted.localMlsState)
            record.standardsMlsThreadState = encrypted.threadState
            outboundWireMessage = encrypted.wireMessage
        }

        let outbound = OutboundMessage(
            createdAt: NotrusCrypto.isoNow(),
            id: UUID().uuidString.lowercased(),
            messageKind: "mls-application",
            protocolField: "mls-rfc9420-v1",
            senderId: identity.id,
            threadId: thread.id,
            wireMessage: outboundWireMessage
        )

        record.messageCache[outbound.id] = CachedMessageState(
            attachments: payload.attachments,
            body: payload.text,
            hidden: payload.cover == true,
            status: "ok"
        )
        threadRecords[thread.id] = record
        try persistThreadStore()
        try persistCurrentIdentity(updatedIdentity)

        do {
            let route = try routingState(for: thread)
            _ = try await currentRelayClient.postMessage(
                mailboxHandle: route.mailboxHandle,
                deliveryCapability: route.deliveryCapability,
                message: outbound.relayTransportForm()
            )
            statusMessage = useFanoutCompatibility
                ? "Sent ciphertext over compatible group fanout transport."
                : "Sent ciphertext over RFC 9420 MLS."
        } catch {
            record.messageCache.removeValue(forKey: outbound.id)
            threadRecords[thread.id] = record
            try persistThreadStore()
            throw error
        }
    }

    private func sendPairwiseMessage(thread: ConversationThread, identity: LocalIdentity, payload: MessagePayload) async throws {
        guard var record = threadRecords[thread.id] else {
            throw NativeProtocolError.missingLocalBootstrap
        }
        guard let activeState = record.currentState ?? record.bootstrapState else {
            throw NativeProtocolError.missingLocalBootstrap
        }

        let previousState = activeState
        let sealed = try NotrusCrypto.sealPairwiseMessage(
            payload: payload,
            senderId: identity.id,
            senderSigningRepresentation: identity.signingRepresentation,
            threadId: thread.id,
            threadState: activeState
        )

        record.currentState = sealed.nextState
        record.messageCache[sealed.message.id] = CachedMessageState(body: payload.text, hidden: payload.cover == true, status: "ok")
        record.pendingSentStates[sealed.message.id] = sealed.nextState
        threadRecords[thread.id] = record
        try persistThreadStore()

        do {
            let route = try routingState(for: thread)
            _ = try await currentRelayClient.postMessage(
                mailboxHandle: route.mailboxHandle,
                deliveryCapability: route.deliveryCapability,
                message: sealed.message.relayTransportForm()
            )
            statusMessage = "Sent ciphertext over Experimental Pairwise Ratchet."
        } catch {
            record.currentState = previousState
            record.messageCache.removeValue(forKey: sealed.message.id)
            record.pendingSentStates.removeValue(forKey: sealed.message.id)
            threadRecords[thread.id] = record
            try persistThreadStore()
            throw error
        }
    }

    private func sendGroupTreeMessage(thread: ConversationThread, identity: LocalIdentity, payload: MessagePayload) async throws {
        guard var record = threadRecords[thread.id], let state = record.groupTreeState else {
            throw RelayClientError.requestFailed("This group thread is missing its local tree state on this Mac.")
        }

        let previousState = state
        let usersById = Dictionary(uniqueKeysWithValues: users.map { ($0.id, $0) })
        let createdAt = NotrusCrypto.isoNow()
        var activeState = state
        var groupCommit: RelayGroupCommit? = nil

        if state.epochMessageCount >= groupEpochRotationInterval {
            let commit = try NotrusCrypto.createRotatedGroupCommit(
                createdAt: createdAt,
                committedBy: identity.id,
                participantIds: thread.participants.map(\.id),
                senderEncryptionRepresentation: identity.encryptionRepresentation,
                senderSigningRepresentation: identity.signingRepresentation,
                threadId: thread.id,
                threadState: state,
                usersById: usersById
            )
            activeState = commit.nextState
            groupCommit = commit.groupCommit
        }

        let sealed = try NotrusCrypto.sealGroupTreeMessage(
            payload: payload,
            senderId: identity.id,
            senderSigningRepresentation: identity.signingRepresentation,
            threadId: thread.id,
            threadState: activeState,
            groupCommit: groupCommit
        )

        record.groupTreeState = sealed.nextState
        record.messageCache[sealed.message.id] = CachedMessageState(body: payload.text, hidden: payload.cover == true, status: "ok")
        threadRecords[thread.id] = record
        try persistThreadStore()

        do {
            let route = try routingState(for: thread)
            _ = try await currentRelayClient.postMessage(
                mailboxHandle: route.mailboxHandle,
                deliveryCapability: route.deliveryCapability,
                message: sealed.message.relayTransportForm()
            )
            statusMessage = groupCommit == nil
                ? "Sent ciphertext over Experimental Group Tree v3."
                : "Sent ciphertext over Experimental Group Tree v3 and rotated the epoch."
        } catch {
            record.groupTreeState = previousState
            record.messageCache.removeValue(forKey: sealed.message.id)
            threadRecords[thread.id] = record
            try persistThreadStore()
            throw error
        }
    }

    private func sortConversationThreads(_ left: ConversationThread, _ right: ConversationThread) -> Bool {
        let leftDate = left.rawThread.messages.last?.createdAt ?? left.rawThread.createdAt
        let rightDate = right.rawThread.messages.last?.createdAt ?? right.rawThread.createdAt
        return leftDate > rightDate
    }

    @discardableResult
    private func restoreHiddenDirectThreadIfPresent(remoteUserId: String) -> Bool {
        guard let entry = threadRecords.first(where: { $0.value.standardsSignalPeerUserId == remoteUserId && $0.value.hiddenAt != nil }) else {
            return false
        }
        var record = entry.value
        record.hiddenAt = nil
        threadRecords[entry.key] = record
        try? persistThreadStore()
        return true
    }

    private func restoreDeletedContactsIfPresent(_ userIds: [String]) throws {
        var changed = false
        for userId in userIds {
            guard var record = contactSecurityState.contacts[userId], record.deletedAt != nil else {
                continue
            }
            record.deletedAt = nil
            contactSecurityState.contacts[userId] = record
            changed = true
        }

        if changed {
            try persistSecurityState()
        }
    }

    private func hasUsableContactHandle(_ user: RelayUser) -> Bool {
        guard let contactHandle = user.contactHandle, !contactHandle.isEmpty else {
            return false
        }
        guard let expiresAt = user.contactHandleExpiresAt, !expiresAt.isEmpty else {
            return true
        }
        guard let expiry = ISO8601DateFormatter().date(from: expiresAt) else {
            return true
        }
        return expiry.timeIntervalSinceNow > 15
    }

    private func refreshedRoutingUsers(
        selectedUserIds: [String],
        participantsById: [String: RelayUser]
    ) async throws -> [String: RelayUser] {
        var resolved = participantsById
        var refreshedUsers: [RelayUser] = []

        for userId in selectedUserIds {
            guard let user = resolved[userId] else {
                continue
            }
            if hasUsableContactHandle(user) {
                continue
            }

            let response = try await currentRelayClient.searchDirectory(query: user.username.lowercased())
            guard let refreshed = response.results.first(where: { $0.id == user.id && hasUsableContactHandle($0) }) else {
                throw RelayClientError.requestFailed("\(user.displayName) is missing a current opaque routing handle. Search the username again and try once more.")
            }
            resolved[userId] = refreshed
            refreshedUsers.append(refreshed)
        }

        if !refreshedUsers.isEmpty {
            users = mergeDirectoryMatches(users, refreshedUsers)
            directorySearchResults = mergeDirectoryMatches(directorySearchResults, refreshedUsers)
        }

        return resolved
    }

    private func mergeDirectoryMatches(_ lists: [RelayUser]...) -> [RelayUser] {
        Dictionary(uniqueKeysWithValues: lists.flatMap { $0 }.map { ($0.id, $0) })
            .values
            .sorted { $0.username.localizedCaseInsensitiveCompare($1.username) == .orderedAscending }
    }

    private func matchesDirectoryQuery(_ user: RelayUser, query: String) -> Bool {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return true
        }
        let normalized = trimmed.lowercased()
        let compact = directorySearchCompact(trimmed)
        let username = user.username.lowercased()
        let displayName = user.displayName.lowercased()
        let compactUsername = directorySearchCompact(user.username)
        let compactDisplayName = directorySearchCompact(user.displayName)
        let normalizedCode = normalizeDirectoryCode(trimmed)

        return username.contains(normalized) ||
            displayName.contains(normalized) ||
            (normalizedCode != nil && (user.directoryCode == normalizedCode || user.directoryCode?.hasPrefix(normalizedCode!) == true)) ||
            (!compact.isEmpty && (compactUsername.contains(compact) || compactDisplayName.contains(compact)))
    }

    private func directorySearchCompact(_ value: String) -> String {
        String(value.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) })
    }

    private func normalizeDirectoryCode(_ value: String) -> String? {
        let normalized = String(value.uppercased().unicodeScalars.filter { CharacterSet(charactersIn: "ABCDEF0123456789").contains($0) })
        return normalized.count >= 4 ? normalized : nil
    }

    private func persistSecurityState() throws {
        guard let identity = currentIdentity else {
            return
        }
        try securityStateStore.saveState(contactSecurityState, for: identity)
    }

    func reconcileContactSecurityState(users directory: [RelayUser], identity: LocalIdentity) -> ContactSecurityState {
        var state = contactSecurityState
        let now = NotrusCrypto.isoNow()

        for user in directory where user.id != identity.id {
            if var existing = state.contacts[user.id] {
                existing.username = user.username
                existing.displayName = user.displayName
                existing.lastSeenAt = now

                if existing.observedFingerprint != user.fingerprint {
                    let previousObserved = existing.observedFingerprint
                    existing.observedFingerprint = user.fingerprint
                    existing.observedPrekeyFingerprint = user.prekeyFingerprint
                    existing.lastKeyChangeAt = now
                    if existing.trustedFingerprint != user.fingerprint {
                        existing.status = .changed
                        state.events = appendSecurityEvent(
                            to: state.events,
                            ContactSecurityEvent(
                                id: "identity-change:\(user.id):\(user.fingerprint)",
                                userId: user.id,
                                username: user.username,
                                displayName: user.displayName,
                                createdAt: now,
                                kind: "identity-key-changed",
                                message: "\(user.displayName)'s identity key changed on the relay. Do not trust the new key until you verify the safety number out of band.",
                                severity: "warning",
                                requiresAction: true,
                                dismissedAt: nil,
                                observedFingerprint: user.fingerprint,
                                trustedFingerprint: previousObserved
                            )
                        )
                    }
                } else if
                    existing.observedPrekeyFingerprint != user.prekeyFingerprint,
                    existing.trustedFingerprint == user.fingerprint
                {
                    existing.observedPrekeyFingerprint = user.prekeyFingerprint
                    existing.trustedPrekeyFingerprint = user.prekeyFingerprint
                    existing.lastPrekeyRotationAt = now
                    state.events = appendSecurityEvent(
                        to: state.events,
                        ContactSecurityEvent(
                            id: "prekey-rotation:\(user.id):\(user.prekeyFingerprint ?? "none")",
                            userId: user.id,
                            username: user.username,
                            displayName: user.displayName,
                            createdAt: now,
                            kind: "prekey-rotated",
                            message: "\(user.displayName) rotated their published prekey material. This is expected and does not replace identity verification.",
                            severity: "info",
                            requiresAction: false,
                            dismissedAt: nil,
                            observedFingerprint: user.fingerprint,
                            trustedFingerprint: existing.trustedFingerprint
                        )
                    )
                }

                state.contacts[user.id] = existing
            } else {
                state.contacts[user.id] = ContactTrustRecord(
                    userId: user.id,
                    username: user.username,
                    displayName: user.displayName,
                    observedFingerprint: user.fingerprint,
                    trustedFingerprint: user.fingerprint,
                    observedPrekeyFingerprint: user.prekeyFingerprint,
                    trustedPrekeyFingerprint: user.prekeyFingerprint,
                    firstSeenAt: now,
                    lastSeenAt: now,
                    lastVerifiedAt: nil,
                    verificationMethod: nil,
                    lastKeyChangeAt: nil,
                    lastPrekeyRotationAt: nil,
                    status: .unverified
                )
                state.events = appendSecurityEvent(
                    to: state.events,
                    ContactSecurityEvent(
                        id: "first-seen:\(user.id):\(user.fingerprint)",
                        userId: user.id,
                        username: user.username,
                        displayName: user.displayName,
                        createdAt: now,
                        kind: "first-seen",
                        message: "\(user.displayName) is new to this Mac. The first contact state is unverified until you compare the safety number out of band.",
                        severity: "info",
                        requiresAction: true,
                        dismissedAt: nil,
                        observedFingerprint: user.fingerprint,
                        trustedFingerprint: user.fingerprint
                    )
                )
            }
        }

        state.events.sort { $0.createdAt > $1.createdAt }
        return state
    }

    private func appendSecurityEvent(
        to events: [ContactSecurityEvent],
        _ candidate: ContactSecurityEvent
    ) -> [ContactSecurityEvent] {
        guard events.contains(where: { $0.id == candidate.id }) == false else {
            return events
        }
        return [candidate] + events
    }

    private func contactSecurityWarnings(for participants: [RelayUser], identityId: String) -> [String] {
        let remoteParticipants = participants.filter { $0.id != identityId }
        if remoteParticipants.contains(where: { contactSecurityState.contacts[$0.id]?.status == .changed }) {
            return ["A contact in this conversation presented a different identity key than the one previously trusted on this Mac. Verify the safety number before sending anything sensitive."]
        }

        if remoteParticipants.contains(where: { contactSecurityState.contacts[$0.id]?.status == .unverified }) {
            return ["A contact in this conversation is still unverified on this Mac. Compare the safety number out of band before relying on the conversation for high-risk content."]
        }

        return []
    }

    private func materialize(
        thread: RelayThread,
        usersById: [String: RelayUser],
        identity: inout LocalIdentity
    ) throws -> ConversationThread {
        let participants = thread.participantIds.compactMap { usersById[$0] }
        let title = resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id)
        let protocolName = thread.protocolField ?? "static-room-v1"
        var warnings = contactSecurityWarnings(for: participants, identityId: identity.id)

        switch protocolName {
        case "signal-pqxdh-double-ratchet-v1" where participants.count == 2:
            return try materializeStandardsSignalThread(
                thread: thread,
                usersById: usersById,
                participants: participants,
                identity: &identity,
                warnings: warnings
            )
        case "mls-rfc9420-v1" where participants.count >= 3:
            return try materializeStandardsMlsThread(
                thread: thread,
                usersById: usersById,
                participants: participants,
                identity: &identity,
                warnings: warnings
            )
        case "pairwise-v2" where participants.count == 2:
            let roomKey = resolveLegacyRoomKey(thread: thread, usersById: usersById, identity: identity, warnings: &warnings)
            return try materializePairwiseThread(
                thread: thread,
                usersById: usersById,
                participants: participants,
                identity: identity,
                roomKey: roomKey,
                warnings: warnings
            )
        case "group-tree-v3" where participants.count >= 3:
            let roomKey = resolveLegacyRoomKey(thread: thread, usersById: usersById, identity: identity, warnings: &warnings)
            return try materializeGroupTreeThread(
                thread: thread,
                usersById: usersById,
                participants: participants,
                identity: identity,
                roomKey: roomKey,
                warnings: warnings
            )
        case "group-epoch-v2":
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: title,
                protocolName: protocolName,
                reason: "Group Epoch v2 is still metadata-only in the native client.",
                warnings: warnings
            )
        case "static-room-v1":
            let roomKey = resolveLegacyRoomKey(thread: thread, usersById: usersById, identity: identity, warnings: &warnings)
            return try materializeStaticThread(
                thread: thread,
                usersById: usersById,
                participants: participants,
                title: title,
                roomKey: roomKey,
                warnings: warnings
            )
        default:
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: title,
                protocolName: protocolName,
                reason: "This thread advertises a protocol the native client does not recognize.",
                warnings: warnings
            )
        }
    }

    private func resolveLegacyRoomKey(
        thread: RelayThread,
        usersById: [String: RelayUser],
        identity: LocalIdentity,
        warnings: inout [String]
    ) -> Data? {
        guard let envelope = thread.envelopes.first(where: { $0.toUserId == identity.id }) else {
            warnings.append("This Mac is missing a room-key envelope for the thread.")
            return nil
        }

        guard let sender = usersById[envelope.fromUserId] else {
            warnings.append("The room-key sender is missing from the relay directory.")
            return nil
        }

        do {
            return try NotrusCrypto.unwrapRoomKeyEnvelope(
                envelope: envelope,
                recipientEncryptionRepresentation: identity.encryptionRepresentation,
                senderEncryptionPublicJwk: sender.encryptionPublicJwk,
                senderSigningPublicJwk: sender.signingPublicJwk
            )
        } catch {
            warnings.append(error.localizedDescription)
            return nil
        }
    }

    private func materializeStandardsSignalThread(
        thread: RelayThread,
        usersById: [String: RelayUser],
        participants: [RelayUser],
        identity: inout LocalIdentity,
        warnings: [String]
    ) throws -> ConversationThread {
        var threadWarnings = warnings
        guard let remoteUser = participants.first(where: { $0.id != identity.id }) else {
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolName: "signal-pqxdh-double-ratchet-v1",
                reason: "The Signal direct thread is missing its remote participant.",
                warnings: threadWarnings
            )
        }

        guard var signalState = identity.standardsSignalState else {
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolName: "signal-pqxdh-double-ratchet-v1",
                reason: "This macOS profile does not have its local Signal standards state.",
                warnings: threadWarnings
            )
        }

        var record = threadRecords[thread.id] ?? ThreadStoreRecord(
            protocolField: "signal-pqxdh-double-ratchet-v1",
            standardsSignalPeerUserId: remoteUser.id
        )
        record.standardsSignalPeerUserId = remoteUser.id

        if
            record.processedMessageCount > thread.messages.count ||
            (
                record.processedMessageCount > 0 &&
                thread.messages[record.processedMessageCount - 1].id != record.lastProcessedMessageId
            )
        {
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolName: "signal-pqxdh-double-ratchet-v1",
                reason: "The local Signal session history on this Mac no longer matches the relay transcript. Recreate the conversation or restore a newer recovery archive.",
                warnings: threadWarnings
            )
        }

        for message in thread.messages.dropFirst(record.processedMessageCount) {
            guard let sender = usersById[message.senderId] else {
                record.messageCache[message.id] = CachedMessageState(
                    body: "Sender record missing from directory.",
                    hidden: false,
                    status: "missing-sender"
                )
                record.processedMessageCount += 1
                record.lastProcessedMessageId = message.id
                continue
            }

            if message.senderId == identity.id {
                record.messageCache[message.id] = record.messageCache[message.id] ?? CachedMessageState(
                    body: "Local plaintext unavailable on this Mac for that previously-sent Signal message.",
                    hidden: false,
                    status: "missing-local-state"
                )
            } else if let messageKind = message.messageKind, let wireMessage = message.wireMessage {
                do {
                    let opened = try StandardsCoreBridge.signalDecrypt(
                        localSignalState: signalState,
                        localUserId: identity.id,
                        messageKind: messageKind,
                        remoteUserId: sender.id,
                        wireMessage: wireMessage
                    )
                    let decodedPayload = decodeStandardsPayload(opened.plaintext)
                    signalState = opened.localSignalState
                    identity = identity.updatingStandards(signalState: signalState)
                    record.messageCache[message.id] = CachedMessageState(
                        attachments: decodedPayload.attachments,
                        body: decodedPayload.text,
                        hidden: false,
                        status: "ok"
                    )
                } catch {
                    threadWarnings.append("A Signal message from \(sender.displayName) failed decryption or authentication.")
                    record.messageCache[message.id] = CachedMessageState(
                        body: error.localizedDescription,
                        hidden: false,
                        status: "invalid"
                    )
                }
            } else {
                threadWarnings.append("A Signal message was missing its authenticated wire payload.")
                record.messageCache[message.id] = CachedMessageState(
                    body: "The Signal wire message was incomplete.",
                    hidden: false,
                    status: "invalid"
                )
            }

            record.processedMessageCount += 1
            record.lastProcessedMessageId = message.id
        }

        threadRecords[thread.id] = record

        let messages = thread.messages.compactMap { message -> DecryptedMessage? in
            let cached = record.messageCache[message.id]
            if cached?.hidden == true {
                return nil
            }

            return DecryptedMessage(
                attachments: cached?.attachments ?? [],
                id: message.id,
                senderId: message.senderId,
                senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                createdAt: message.createdAt,
                body: cached?.body ?? "Local plaintext unavailable for this Signal message.",
                status: cached?.status ?? "missing-local-state"
            )
        }

        return ConversationThread(
            id: thread.id,
            title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
            protocolLabel: NotrusProtocolCatalog.spec(for: "signal-pqxdh-double-ratchet-v1").label,
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: threadWarnings.first,
            supported: true
        )
    }

    private func materializeStandardsMlsThread(
        thread: RelayThread,
        usersById: [String: RelayUser],
        participants: [RelayUser],
        identity: inout LocalIdentity,
        warnings: [String]
    ) throws -> ConversationThread {
        var threadWarnings = warnings
        if isMlsFanoutCompatibleThread(thread) {
            guard var signalState = identity.standardsSignalState else {
                return materializeUnsupportedThread(
                    thread: thread,
                    participants: participants,
                    usersById: usersById,
                    title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                    protocolName: "mls-rfc9420-v1",
                    reason: "This macOS profile is missing the local Signal standards state required for compatible group fanout.",
                    warnings: threadWarnings
                )
            }

            var record = threadRecords[thread.id] ?? ThreadStoreRecord(protocolField: "mls-rfc9420-v1")
            if
                record.processedMessageCount > thread.messages.count ||
                (
                    record.processedMessageCount > 0 &&
                    thread.messages[record.processedMessageCount - 1].id != record.lastProcessedMessageId
                )
            {
                record = ThreadStoreRecord(
                    hiddenAt: record.hiddenAt,
                    localTitle: record.localTitle,
                    messageCache: [:],
                    processedMessageCount: 0,
                    protocolField: "mls-rfc9420-v1"
                )
            }

            for message in thread.messages.dropFirst(record.processedMessageCount) {
                if message.senderId == identity.id {
                    record.messageCache[message.id] = record.messageCache[message.id] ?? CachedMessageState(
                        body: "Local plaintext unavailable on this Mac for that previously-sent compatible group message.",
                        hidden: false,
                        status: "missing-local-state"
                    )
                } else if let wireMessage = message.wireMessage {
                    do {
                        guard let envelope = try decodeMlsFanoutEnvelope(wireMessage), envelope.senderId == message.senderId else {
                            throw RelayClientError.requestFailed("The compatible group envelope was malformed.")
                        }
                        guard let recipient = envelope.recipients.first(where: { $0.toUserId == identity.id }) else {
                            throw RelayClientError.requestFailed("This Mac did not receive a recipient envelope for that group message.")
                        }
                        let opened = try StandardsCoreBridge.signalDecrypt(
                            localSignalState: signalState,
                            localUserId: identity.id,
                            messageKind: recipient.messageKind,
                            remoteUserId: message.senderId,
                            wireMessage: recipient.wireMessage
                        )
                        let decodedPayload = decodeStandardsPayload(opened.plaintext)
                        signalState = opened.localSignalState
                        identity = identity.updatingStandards(signalState: signalState)
                        record.messageCache[message.id] = CachedMessageState(
                            attachments: decodedPayload.attachments,
                            body: decodedPayload.text,
                            hidden: false,
                            status: "ok"
                        )
                    } catch {
                        threadWarnings.append("A compatible group envelope from \(usersById[message.senderId]?.displayName ?? "Unknown user") failed decryption.")
                        record.messageCache[message.id] = CachedMessageState(
                            body: error.localizedDescription,
                            hidden: false,
                            status: "invalid"
                        )
                    }
                } else {
                    threadWarnings.append("A compatible group message was missing its envelope payload.")
                    record.messageCache[message.id] = CachedMessageState(
                        body: "The compatible group envelope payload was incomplete.",
                        hidden: false,
                        status: "invalid"
                    )
                }

                record.processedMessageCount += 1
                record.lastProcessedMessageId = message.id
            }

            threadRecords[thread.id] = record
            let messages = thread.messages.compactMap { message -> DecryptedMessage? in
                let cached = record.messageCache[message.id]
                if cached?.hidden == true {
                    return nil
                }
                return DecryptedMessage(
                    attachments: cached?.attachments ?? [],
                    id: message.id,
                    senderId: message.senderId,
                    senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                    createdAt: message.createdAt,
                    body: cached?.body ?? "Local plaintext unavailable for this compatible group message.",
                    status: cached?.status ?? "missing-local-state"
                )
            }

            return ConversationThread(
                id: thread.id,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolLabel: NotrusProtocolCatalog.spec(for: "mls-rfc9420-v1").label,
                participants: participants,
                rawThread: thread,
                messages: messages,
                warning: threadWarnings.first,
                supported: true
            )
        }

        guard var mlsState = identity.standardsMlsState else {
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolName: "mls-rfc9420-v1",
                reason: "This macOS profile does not have its local MLS account state.",
                warnings: threadWarnings
            )
        }

        func joinFromWelcome() throws -> ThreadStoreRecord {
            guard let bootstrap = thread.mlsBootstrap else {
                throw RelayClientError.requestFailed("This MLS thread is missing its bootstrap welcome on the relay.")
            }

            let joined = try StandardsCoreBridge.mlsJoinGroup(
                localMlsState: mlsState,
                localUserId: identity.id,
                threadBootstrap: bootstrap
            )
            mlsState = joined.localMlsState
            identity = identity.updatingStandards(mlsState: mlsState)
            return ThreadStoreRecord(
                processedMessageCount: 0,
                protocolField: "mls-rfc9420-v1",
                standardsMlsThreadState: joined.threadState
            )
        }

        var record = threadRecords[thread.id] ?? {
            if thread.createdBy == identity.id {
                return ThreadStoreRecord(protocolField: "mls-rfc9420-v1")
            }

            do {
                return try joinFromWelcome()
            } catch {
                threadWarnings.append(error.localizedDescription)
                return ThreadStoreRecord(protocolField: "mls-rfc9420-v1")
            }
        }()

        if
            record.processedMessageCount > thread.messages.count ||
            (
                record.processedMessageCount > 0 &&
                thread.messages[record.processedMessageCount - 1].id != record.lastProcessedMessageId
            )
        {
            if thread.createdBy == identity.id {
                return materializeUnsupportedThread(
                    thread: thread,
                    participants: participants,
                    usersById: usersById,
                    title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                    protocolName: "mls-rfc9420-v1",
                    reason: "This Mac no longer has a valid creator-side MLS transcript for the group. Restore a newer recovery archive or recreate the group.",
                    warnings: threadWarnings
                )
            }

            record = try joinFromWelcome()
            threadWarnings.append("Local MLS state was rebuilt from the welcome because the transcript changed.")
        }

        if record.standardsMlsThreadState == nil {
            if thread.createdBy == identity.id {
                return materializeUnsupportedThread(
                    thread: thread,
                    participants: participants,
                    usersById: usersById,
                    title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                    protocolName: "mls-rfc9420-v1",
                    reason: "This Mac is missing the creator-side MLS group state. Restore a recovery archive or recreate the group.",
                    warnings: threadWarnings
                )
            }

            record = try joinFromWelcome()
        }

        for message in thread.messages.dropFirst(record.processedMessageCount) {
            guard let sender = usersById[message.senderId] else {
                record.messageCache[message.id] = CachedMessageState(
                    body: "Sender record missing from directory.",
                    hidden: false,
                    status: "missing-sender"
                )
                record.processedMessageCount += 1
                record.lastProcessedMessageId = message.id
                continue
            }

            if message.senderId == identity.id {
                record.messageCache[message.id] = record.messageCache[message.id] ?? CachedMessageState(
                    body: "Local plaintext unavailable on this Mac for that previously-sent MLS message.",
                    hidden: false,
                    status: "missing-local-state"
                )
            } else if let wireMessage = message.wireMessage, let threadState = record.standardsMlsThreadState {
                do {
                    let opened = try StandardsCoreBridge.mlsProcessMessage(
                        localMlsState: mlsState,
                        threadState: threadState,
                        wireMessage: wireMessage
                    )
                    let decodedPayload = decodeStandardsPayload(opened.plaintext)
                    mlsState = opened.localMlsState
                    identity = identity.updatingStandards(mlsState: mlsState)
                    record.standardsMlsThreadState = opened.threadState
                    record.messageCache[message.id] = CachedMessageState(
                        attachments: decodedPayload.attachments,
                        body: decodedPayload.text,
                        hidden: false,
                        status: "ok"
                    )
                } catch {
                    threadWarnings.append("An MLS message from \(sender.displayName) failed decryption or processing.")
                    record.messageCache[message.id] = CachedMessageState(
                        body: error.localizedDescription,
                        hidden: false,
                        status: "invalid"
                    )
                }
            } else {
                threadWarnings.append("An MLS message was missing its authenticated wire payload.")
                record.messageCache[message.id] = CachedMessageState(
                    body: "The MLS wire message was incomplete.",
                    hidden: false,
                    status: "invalid"
                )
            }

            record.processedMessageCount += 1
            record.lastProcessedMessageId = message.id
        }

        threadRecords[thread.id] = record

        let messages = thread.messages.compactMap { message -> DecryptedMessage? in
            let cached = record.messageCache[message.id]
            if cached?.hidden == true {
                return nil
            }

            return DecryptedMessage(
                attachments: cached?.attachments ?? [],
                id: message.id,
                senderId: message.senderId,
                senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                createdAt: message.createdAt,
                body: cached?.body ?? "Local plaintext unavailable for this MLS message.",
                status: cached?.status ?? "missing-local-state"
            )
        }

        return ConversationThread(
            id: thread.id,
            title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
            protocolLabel: NotrusProtocolCatalog.spec(for: "mls-rfc9420-v1").label,
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: threadWarnings.first,
            supported: true
        )
    }

    private func materializeStaticThread(
        thread: RelayThread,
        usersById: [String: RelayUser],
        participants: [RelayUser],
        title: String,
        roomKey: Data?,
        warnings: [String]
    ) throws -> ConversationThread {
        var threadWarnings = warnings
        let messages = thread.messages.map { message -> DecryptedMessage in
            guard let sender = usersById[message.senderId] else {
                return DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: "Unknown user",
                    createdAt: message.createdAt,
                    body: "Sender record missing from the directory.",
                    status: "missing-sender"
                )
            }

            guard let roomKey else {
                return DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: sender.displayName,
                    createdAt: message.createdAt,
                    body: "Unable to decrypt because this Mac does not currently trust the room key.",
                    status: "missing-room-key"
                )
            }

            do {
                let body = try NotrusCrypto.openMessage(
                    message: message,
                    roomKey: roomKey,
                    senderSigningPublicJwk: sender.signingPublicJwk
                )
                return DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: sender.displayName,
                    createdAt: message.createdAt,
                    body: body,
                    status: "ok"
                )
            } catch {
                threadWarnings.append("A message from \(sender.displayName) failed integrity verification.")
                return DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: sender.displayName,
                    createdAt: message.createdAt,
                    body: error.localizedDescription,
                    status: "invalid"
                )
            }
        }

        return ConversationThread(
            id: thread.id,
            title: title,
            protocolLabel: NotrusCrypto.protocolLabel("static-room-v1"),
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: threadWarnings.first,
            supported: true
        )
    }

    private func materializePairwiseThread(
        thread: RelayThread,
        usersById: [String: RelayUser],
        participants: [RelayUser],
        identity: LocalIdentity,
        roomKey: Data?,
        warnings: [String]
    ) throws -> ConversationThread {
        var threadWarnings = warnings
        guard let remoteUser = participants.first(where: { $0.id != identity.id }) else {
            return materializeUnsupportedThread(
                thread: thread,
                participants: participants,
                usersById: usersById,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolName: "pairwise-v2",
                reason: "Pairwise thread is missing its remote participant record.",
                warnings: warnings
            )
        }

        if !(try NotrusCrypto.verifySignedPrekeyRecord(remoteUser)) {
            threadWarnings.append("\(remoteUser.displayName)'s signed prekey could not be verified from the relay directory.")
        }

        guard let roomKey else {
            let messages = thread.messages.map { message in
                DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                    createdAt: message.createdAt,
                    body: "Unable to initialize the pairwise ratchet because this Mac could not unlock the bootstrap room secret.",
                    status: "missing-room-key"
                )
            }
            return ConversationThread(
                id: thread.id,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolLabel: NotrusCrypto.protocolLabel("pairwise-v2"),
                participants: participants,
                rawThread: thread,
                messages: messages,
                warning: threadWarnings.first,
                supported: true
            )
        }

        var record = threadRecords[thread.id]
        if record == nil {
            if thread.createdBy == identity.id {
                threadWarnings.append("Local ratchet bootstrap state is missing for this direct thread on this Mac.")
                let messages = thread.messages.map { message in
                    DecryptedMessage(
                        id: message.id,
                        senderId: message.senderId,
                        senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                        createdAt: message.createdAt,
                        body: "Local ratchet bootstrap state is missing on this Mac. Recreate the conversation or restore a newer native state snapshot.",
                        status: "missing-local-state"
                    )
                }
                return ConversationThread(
                    id: thread.id,
                    title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                    protocolLabel: NotrusCrypto.protocolLabel("pairwise-v2"),
                    participants: participants,
                    rawThread: thread,
                    messages: messages,
                    warning: threadWarnings.first,
                    supported: true
                )
            }

            guard let initialRatchetPublicJwk = thread.initialRatchetPublicJwk else {
                throw RelayClientError.requestFailed("This pairwise thread is missing its initial ratchet bootstrap key.")
            }

            record = ThreadStoreRecord(
                bootstrapState: try NotrusCrypto.createPairwiseRecipientThreadState(
                    creatorId: thread.createdBy,
                    creatorRatchetPublicJwk: initialRatchetPublicJwk,
                    localUserId: identity.id,
                    recipientPrekeyRepresentation: identity.prekeyRepresentation,
                    roomKey: roomKey,
                    threadId: thread.id
                ),
                currentState: nil,
                groupTreeState: nil,
                lastProcessedMessageId: nil,
                messageCache: [:],
                pendingSentStates: [:],
                processedMessageCount: 0,
                protocolField: "pairwise-v2"
            )
        }

        guard var resolvedRecord = record else {
            throw NativeProtocolError.missingLocalBootstrap
        }
        resolvedRecord.currentState = resolvedRecord.currentState ?? resolvedRecord.bootstrapState

        if
            resolvedRecord.processedMessageCount > thread.messages.count ||
            (
                resolvedRecord.processedMessageCount > 0 &&
                thread.messages[resolvedRecord.processedMessageCount - 1].id != resolvedRecord.lastProcessedMessageId
            )
        {
            resolvedRecord.currentState = resolvedRecord.bootstrapState
            resolvedRecord.processedMessageCount = 0
            resolvedRecord.lastProcessedMessageId = nil
            threadWarnings.append("Local pairwise ratchet state was replayed from bootstrap because the transcript changed.")
        }

        for message in thread.messages.dropFirst(resolvedRecord.processedMessageCount) {
            guard let sender = usersById[message.senderId] else {
                resolvedRecord.messageCache[message.id] = CachedMessageState(
                    body: "Sender record missing from directory.",
                    hidden: false,
                    status: "missing-sender"
                )
                resolvedRecord.processedMessageCount += 1
                resolvedRecord.lastProcessedMessageId = message.id
                continue
            }

            if message.senderId == identity.id {
                if let pending = resolvedRecord.pendingSentStates.removeValue(forKey: message.id) {
                    resolvedRecord.currentState = pending
                }
                resolvedRecord.messageCache[message.id] = resolvedRecord.messageCache[message.id] ?? CachedMessageState(
                    body: "Local plaintext unavailable on this Mac for that previously-sent ratcheted message.",
                    hidden: false,
                    status: "missing-local-state"
                )
            } else if let activeState = resolvedRecord.currentState {
                do {
                    let opened = try NotrusCrypto.openPairwiseMessage(
                        message: message,
                        senderSigningPublicJwk: sender.signingPublicJwk,
                        threadState: activeState
                    )
                    resolvedRecord.currentState = opened.nextState
                    resolvedRecord.messageCache[message.id] = CachedMessageState(
                        body: opened.payload.text,
                        hidden: opened.payload.cover == true,
                        status: "ok"
                    )
                } catch {
                    threadWarnings.append("A ratcheted message from \(sender.displayName) failed verification or decryption.")
                    resolvedRecord.messageCache[message.id] = CachedMessageState(
                        body: error.localizedDescription,
                        hidden: false,
                        status: "invalid"
                    )
                }
            }

            resolvedRecord.processedMessageCount += 1
            resolvedRecord.lastProcessedMessageId = message.id
        }

        threadRecords[thread.id] = resolvedRecord

        let messages = thread.messages.compactMap { message -> DecryptedMessage? in
            let cached = resolvedRecord.messageCache[message.id]
            if cached?.hidden == true {
                return nil
            }

            return DecryptedMessage(
                id: message.id,
                senderId: message.senderId,
                senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                createdAt: message.createdAt,
                body: cached?.body ?? "Local plaintext unavailable for this ratcheted message.",
                status: cached?.status ?? "missing-local-state"
            )
        }

        return ConversationThread(
            id: thread.id,
            title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
            protocolLabel: NotrusCrypto.protocolLabel("pairwise-v2"),
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: threadWarnings.first,
            supported: true
        )
    }

    private func materializeGroupTreeThread(
        thread: RelayThread,
        usersById: [String: RelayUser],
        participants: [RelayUser],
        identity: LocalIdentity,
        roomKey: Data?,
        warnings: [String]
    ) throws -> ConversationThread {
        var threadWarnings = warnings

        guard let roomKey else {
            let messages = thread.messages.map { message in
                DecryptedMessage(
                    id: message.id,
                    senderId: message.senderId,
                    senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                    createdAt: message.createdAt,
                    body: "Unable to initialize the group tree state because this Mac could not unlock the current group epoch secret.",
                    status: "missing-room-key"
                )
            }
            return ConversationThread(
                id: thread.id,
                title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
                protocolLabel: NotrusCrypto.protocolLabel("group-tree-v3"),
                participants: participants,
                rawThread: thread,
                messages: messages,
                warning: threadWarnings.first,
                supported: true
            )
        }

        var record = threadRecords[thread.id]
        if record == nil {
            let initialState = try NotrusCrypto.createGroupTreeThreadState(
                participantIds: thread.groupState?.participantIds ?? thread.participantIds,
                roomKey: roomKey,
                startingEpoch: thread.groupState?.epoch ?? 1,
                threadId: thread.id,
                transcriptHash: thread.groupState?.transcriptHash,
                treeHash: thread.groupState?.treeHash
            )
            record = ThreadStoreRecord(
                bootstrapState: nil,
                currentState: nil,
                groupTreeState: initialState,
                lastProcessedMessageId: nil,
                messageCache: [:],
                pendingSentStates: [:],
                processedMessageCount: 0,
                protocolField: "group-tree-v3"
            )
        }

        guard var resolvedRecord = record, let currentState = resolvedRecord.groupTreeState else {
            throw RelayClientError.requestFailed("This group thread is missing its local tree state on this Mac.")
        }

        if
            resolvedRecord.processedMessageCount > thread.messages.count ||
            (
                resolvedRecord.processedMessageCount > 0 &&
                thread.messages[resolvedRecord.processedMessageCount - 1].id != resolvedRecord.lastProcessedMessageId
            )
        {
            resolvedRecord.groupTreeState = try NotrusCrypto.createGroupTreeThreadState(
                participantIds: thread.groupState?.participantIds ?? thread.participantIds,
                roomKey: roomKey,
                startingEpoch: thread.groupState?.epoch ?? 1,
                threadId: thread.id,
                transcriptHash: thread.groupState?.transcriptHash,
                treeHash: thread.groupState?.treeHash
            )
            resolvedRecord.processedMessageCount = 0
            resolvedRecord.lastProcessedMessageId = nil
            threadWarnings.append("Local group tree state was replayed from the latest committed epoch because the transcript changed.")
        }

        for message in thread.messages.dropFirst(resolvedRecord.processedMessageCount) {
            guard let sender = usersById[message.senderId] else {
                resolvedRecord.messageCache[message.id] = CachedMessageState(
                    body: "Sender record missing from directory.",
                    hidden: false,
                    status: "missing-sender"
                )
                resolvedRecord.processedMessageCount += 1
                resolvedRecord.lastProcessedMessageId = message.id
                continue
            }

            if message.senderId == identity.id {
                resolvedRecord.messageCache[message.id] = resolvedRecord.messageCache[message.id] ?? CachedMessageState(
                    body: "Local plaintext unavailable on this Mac for that previously-sent group-tree message.",
                    hidden: false,
                    status: "missing-local-state"
                )
                resolvedRecord.processedMessageCount += 1
                resolvedRecord.lastProcessedMessageId = message.id
                continue
            }

            if
                (message.epoch ?? 1) < currentState.currentEpoch,
                currentState.epochSecrets[String(message.epoch ?? 1)] == nil
            {
                resolvedRecord.messageCache[message.id] = CachedMessageState(
                    body: "This Mac only has the current group epoch secret. Restore a newer native state snapshot to open older group history.",
                    hidden: false,
                    status: "missing-local-state"
                )
                resolvedRecord.processedMessageCount += 1
                resolvedRecord.lastProcessedMessageId = message.id
                continue
            }

            do {
                let opened = try NotrusCrypto.openGroupTreeMessage(
                    message: message,
                    recipientEncryptionRepresentation: identity.encryptionRepresentation,
                    senderEncryptionPublicJwk: sender.encryptionPublicJwk,
                    senderSigningPublicJwk: sender.signingPublicJwk,
                    threadState: resolvedRecord.groupTreeState ?? currentState,
                    userId: identity.id
                )
                resolvedRecord.groupTreeState = opened.nextState
                resolvedRecord.messageCache[message.id] = CachedMessageState(
                    body: opened.payload.text,
                    hidden: opened.payload.cover == true,
                    status: "ok"
                )
            } catch {
                threadWarnings.append("A Group Tree v3 message from \(sender.displayName) failed verification or decryption.")
                resolvedRecord.messageCache[message.id] = CachedMessageState(
                    body: error.localizedDescription,
                    hidden: false,
                    status: "invalid"
                )
            }

            resolvedRecord.processedMessageCount += 1
            resolvedRecord.lastProcessedMessageId = message.id
        }

        threadRecords[thread.id] = resolvedRecord

        let messages = thread.messages.compactMap { message -> DecryptedMessage? in
            let cached = resolvedRecord.messageCache[message.id]
            if cached?.hidden == true {
                return nil
            }

            return DecryptedMessage(
                id: message.id,
                senderId: message.senderId,
                senderName: usersById[message.senderId]?.displayName ?? "Unknown user",
                createdAt: message.createdAt,
                body: cached?.body ?? "Local plaintext unavailable for this Group Tree v3 message.",
                status: cached?.status ?? "missing-local-state"
            )
        }

        return ConversationThread(
            id: thread.id,
            title: resolvedThreadTitle(thread: thread, participants: participants, identityID: identity.id),
            protocolLabel: NotrusCrypto.protocolLabel("group-tree-v3"),
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: threadWarnings.first,
            supported: true
        )
    }

    private func materializeUnsupportedThread(
        thread: RelayThread,
        participants: [RelayUser],
        usersById: [String: RelayUser],
        title: String,
        protocolName: String,
        reason: String,
        warnings: [String]
    ) -> ConversationThread {
        let messages = thread.messages.map { message in
            DecryptedMessage(
                id: message.id,
                senderId: message.senderId,
                senderName: usersById[message.senderId]?.displayName ?? "Unknown",
                createdAt: message.createdAt,
                body: reason,
                status: "unsupported"
            )
        }

        return ConversationThread(
            id: thread.id,
            title: title,
            protocolLabel: NotrusCrypto.protocolLabel(protocolName),
            participants: participants,
            rawThread: thread,
            messages: messages,
            warning: warnings.first ?? reason,
            supported: false
        )
    }

    private func roomKeyForThread(
        _ thread: RelayThread,
        identity: LocalIdentity,
        usersById: [String: RelayUser]? = nil
    ) throws -> Data {
        guard let envelope = thread.envelopes.first(where: { $0.toUserId == identity.id }) else {
            throw RelayClientError.requestFailed("This Mac does not have a wrapped room key for the selected thread.")
        }

        let directory = usersById ?? Dictionary(uniqueKeysWithValues: users.map { ($0.id, $0) })
        guard let sender = directory[envelope.fromUserId] else {
            throw RelayClientError.requestFailed("The room-key sender is missing from the relay directory.")
        }

        return try NotrusCrypto.unwrapRoomKeyEnvelope(
            envelope: envelope,
            recipientEncryptionRepresentation: identity.encryptionRepresentation,
            senderEncryptionPublicJwk: sender.encryptionPublicJwk,
            senderSigningPublicJwk: sender.signingPublicJwk
        )
    }

    private func persistThreadStore() throws {
        guard let identity = currentIdentity else {
            return
        }
        try threadStateStore.saveRecords(threadRecords, for: identity)
    }

    private func resolvedThreadTitle(thread: RelayThread, participants: [RelayUser], identityID: String) -> String {
        if let localTitle = threadRecords[thread.id]?.localTitle, !localTitle.isEmpty {
            return localTitle
        }

        if !thread.title.isEmpty {
            return thread.title
        }

        let names = participants
            .filter { $0.id != identityID }
            .map(\.displayName)
            .joined(separator: ", ")
        return names.isEmpty ? "Only this Mac" : names
    }

    private func verifyTransparency(
        entryCount: Int,
        entries: [TransparencyEntry],
        expectedHead: String?,
        expectedSignature: String?,
        signer: TransparencySignerInfo?
    ) async throws -> TransparencyVerificationResult {
        let sortedEntries = entries.sorted { $0.sequence < $1.sequence }
        var previousHash: String? = nil
        var warnings: [String] = []

        for entry in sortedEntries {
            if entry.previousHash != previousHash {
                warnings.append("Transparency log hash chain is inconsistent.")
                break
            }

            let entryHash = SHA256.hash(
                data: Data(
                    """
                    {"createdAt":"\(entry.createdAt)","fingerprint":"\(entry.fingerprint)","kind":"\(entry.kind)","prekeyFingerprint":\(entry.prekeyFingerprint.map(NotrusCrypto.jsonString) ?? "null"),"previousHash":\(entry.previousHash.map(NotrusCrypto.jsonString) ?? "null"),"sequence":\(entry.sequence),"userId":"\(entry.userId)","username":"\(entry.username)"}
                    """.utf8
                )
            ).map { String(format: "%02x", $0) }.joined()

            if entryHash != entry.entryHash {
                warnings.append("Transparency log entry hash verification failed.")
                break
            }

            previousHash = entry.entryHash
        }

        if let expectedHead, previousHash != expectedHead {
            warnings.append("Transparency log head does not match the relay's advertised head.")
        }

        if !verifyTransparencySignature(
            entryCount: entryCount,
            expectedHead: expectedHead,
            expectedSignature: expectedSignature,
            signer: signer
        ) {
            warnings.append("Transparency signer verification failed for the relay's advertised key-directory head.")
        }

        var chainHeads = Set(sortedEntries.map(\.entryHash))
        if let expectedHead {
            chainHeads.insert(expectedHead)
        }

        let pinnedHead = transparencyPins[relayOrigin]
        if let pinnedHead, !chainHeads.contains(pinnedHead) {
            warnings.append("This relay presented a transparency history that does not include the head previously pinned on this Mac.")
        }
        let signerKeyId = signer?.keyId
        let pinnedSignerKeyId = transparencySignerPins[relayOrigin]
        if let pinnedSignerKeyId, let signerKeyId, pinnedSignerKeyId != signerKeyId {
            warnings.append("This relay changed its transparency signing key for the Mac key directory.")
        }

        let witnesses = await fetchWitnessObservations(expectedHead: expectedHead, chainHeads: chainHeads, warnings: &warnings)

        if let expectedHead, warnings.isEmpty {
            transparencyPins[relayOrigin] = expectedHead
            Self.persistPinnedHeads(transparencyPins)
            if let signerKeyId {
                transparencySignerPins[relayOrigin] = signerKeyId
                Self.persistPinnedSignerKeys(transparencySignerPins)
            }
        }

        return TransparencyVerificationResult(
            chainValid: warnings.isEmpty,
            entries: sortedEntries,
            head: expectedHead,
            pinnedHead: pinnedHead,
            pinnedSignerKeyId: pinnedSignerKeyId,
            signerKeyId: signerKeyId,
            warnings: warnings,
            witnesses: witnesses
        )
    }

    private func verifyTransparencySignature(
        entryCount: Int,
        expectedHead: String?,
        expectedSignature: String?,
        signer: TransparencySignerInfo?
    ) -> Bool {
        guard
            let signer,
            signer.algorithm == "ed25519",
            let signature = Data(base64Encoded: expectedSignature ?? ""),
            let publicKeyData = Data(base64Encoded: signer.publicKeyRaw)
        else {
            return false
        }

        do {
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
            let payload = Data(transparencyStatementPayload(
                entryCount: entryCount,
                expectedHead: expectedHead,
                signerKeyId: signer.keyId
            ).utf8)
            return publicKey.isValidSignature(signature, for: payload)
        } catch {
            return false
        }
    }

    private func transparencyStatementPayload(
        entryCount: Int,
        expectedHead: String?,
        signerKeyId: String
    ) -> String {
        #"{"entryCount":"# +
        "\(entryCount)" +
        #","signerKeyId":"\#(signerKeyId)","transparencyHead":"# +
        (expectedHead.map(NotrusCrypto.jsonString) ?? "null") +
        "}"
    }

    private func fetchWitnessObservations(
        expectedHead: String?,
        chainHeads: Set<String>,
        warnings: inout [String]
    ) async -> [WitnessObservation] {
        let relayOrigin = self.relayOrigin
        var observations: [WitnessObservation] = []

        for origin in witnessOrigins {
            do {
                guard
                    let url = URL(string: "/api/witness/head?relayOrigin=\(relayOrigin.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? relayOrigin)", relativeTo: URL(string: origin))
                else {
                    observations.append(WitnessObservation(origin: origin, entryCount: nil, head: nil, observedAt: nil, status: "unreachable"))
                    continue
                }

                var request = URLRequest(url: url)
                request.timeoutInterval = TransportSecurityPolicy.witnessTimeout
                let (data, _) = try await TransportSecurityPolicy.session().data(for: request)
                let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                let latest = payload?["latest"] as? [String: Any]
                let witnessHead = latest?["transparencyHead"] as? String
                let entryCount = latest?["entryCount"] as? Int
                let observedAt = latest?["observedAt"] as? String

                let status: String
                if witnessHead == expectedHead {
                    status = "current"
                } else if let witnessHead, chainHeads.contains(witnessHead) {
                    status = "lagging"
                } else if witnessHead != nil {
                    status = "conflict"
                    warnings.append("Witness \(origin) reported a transparency head that does not appear in the relay's current chain.")
                } else {
                    status = "missing"
                }

                observations.append(
                    WitnessObservation(
                        origin: origin,
                        entryCount: entryCount,
                        head: witnessHead,
                        observedAt: observedAt,
                        status: status
                    )
                )
            } catch {
                observations.append(WitnessObservation(origin: origin, entryCount: nil, head: nil, observedAt: nil, status: "unreachable"))
            }
        }

        return observations
    }

    private static func loadPinnedHeads() -> [String: String] {
        guard
            let raw = UserDefaults.standard.data(forKey: "NotrusMac.transparencyPins"),
            let decoded = try? JSONDecoder().decode([String: String].self, from: raw)
        else {
            return [:]
        }

        return decoded
    }

    private static func persistPinnedHeads(_ pins: [String: String]) {
        let encoder = JSONEncoder()
        if let data = try? encoder.encode(pins) {
            UserDefaults.standard.set(data, forKey: "NotrusMac.transparencyPins")
        }
    }

    private static func loadPinnedSignerKeys() -> [String: String] {
        guard
            let raw = UserDefaults.standard.data(forKey: "NotrusMac.transparencySignerPins"),
            let decoded = try? JSONDecoder().decode([String: String].self, from: raw)
        else {
            return [:]
        }

        return decoded
    }

    private static func persistPinnedSignerKeys(_ pins: [String: String]) {
        let encoder = JSONEncoder()
        if let data = try? encoder.encode(pins) {
            UserDefaults.standard.set(data, forKey: "NotrusMac.transparencySignerPins")
        }
    }

    private static func bootstrapRelayOrigin(_ storedOrigin: String?) -> String {
        let trimmed = storedOrigin?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let trimmed, !trimmed.isEmpty else {
            return defaultRemoteRelayOrigin
        }
        return isBootstrapLocalRelay(trimmed) ? defaultRemoteRelayOrigin : trimmed
    }

    private static func isBootstrapLocalRelay(_ origin: String) -> Bool {
        let trimmed = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed == defaultLocalRelayOrigin || trimmed == "http://localhost:3000"
    }

    private var transparencyWarningsAreResettable: Bool {
        !transparency.chainValid &&
            !transparency.warnings.isEmpty &&
            transparency.warnings.allSatisfy { Self.resettableTransparencyWarnings.contains($0) }
    }
}
