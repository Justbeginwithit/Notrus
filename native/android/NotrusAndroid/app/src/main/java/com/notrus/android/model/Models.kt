package com.notrus.android.model

data class Jwk(
    val crv: String = "P-256",
    val kty: String = "EC",
    val x: String,
    val y: String,
)

data class DeviceAttestationProof(
    val certificateChain: List<String> = emptyList(),
    val generatedAt: String,
    val keyFingerprint: String,
    val keyRole: String,
    val proofPayload: String,
    val proofSignature: String,
    val publicJwk: Jwk,
)

data class PublicSignalBundle(
    val deviceId: Int,
    val identityKey: String,
    val kyberPreKeyId: Int,
    val kyberPreKeyPublic: String,
    val kyberPreKeySignature: String,
    val preKeyId: Int,
    val preKeyPublic: String,
    val registrationId: Int,
    val signedPreKeyId: Int,
    val signedPreKeyPublic: String,
    val signedPreKeySignature: String,
)

data class PublicMlsKeyPackage(
    val ciphersuite: String,
    val keyPackage: String,
)

data class RelayMlsWelcomeEnvelope(
    val toUserId: String,
    val welcome: String,
)

data class RelayMlsBootstrap(
    val ciphersuite: String,
    val groupId: String,
    val welcomes: List<RelayMlsWelcomeEnvelope> = emptyList(),
)

data class SignalProtocolState(
    val deviceId: Int = 1,
    val identityKeyPair: String,
    val knownIdentities: Map<String, String> = emptyMap(),
    val kyberPreKeyId: Int,
    val kyberPreKeyRecord: String,
    val preKeyId: Int,
    val preKeyRecord: String,
    val registrationId: Int,
    val senderKeys: Map<String, String> = emptyMap(),
    val sessions: Map<String, String> = emptyMap(),
    val signedPreKeyId: Int,
    val signedPreKeyRecord: String,
)

data class LocalIdentity(
    val id: String,
    val username: String,
    val displayName: String,
    val createdAt: String,
    val directoryCode: String? = null,
    val storageMode: String,
    val fingerprint: String,
    val recoveryFingerprint: String,
    val recoveryPublicJwk: Jwk,
    val signingPublicJwk: Jwk,
    val encryptionPublicJwk: Jwk,
    val prekeyCreatedAt: String,
    val prekeyFingerprint: String,
    val prekeyPublicJwk: Jwk,
    val prekeySignature: String,
    val standardsSignalReady: Boolean,
    val standardsMlsReady: Boolean,
    val standardsSignalBundle: PublicSignalBundle? = null,
    val standardsSignalState: SignalProtocolState? = null,
)

data class DeviceDescriptor(
    val createdAt: String,
    val id: String,
    val label: String,
    val platform: String,
    val publicJwk: Jwk,
    val riskLevel: String,
    val storageMode: String? = null,
    val attestation: DeviceAttestationProof? = null,
)

data class RelayUser(
    val id: String,
    val username: String,
    val displayName: String,
    val contactHandle: String? = null,
    val contactHandleExpiresAt: String? = null,
    val directoryCode: String? = null,
    val fingerprint: String,
    val createdAt: String,
    val updatedAt: String? = null,
    val mlsKeyPackage: PublicMlsKeyPackage? = null,
    val prekeyCreatedAt: String? = null,
    val prekeyFingerprint: String? = null,
    val prekeyPublicJwk: Jwk? = null,
    val prekeySignature: String? = null,
    val signingPublicJwk: Jwk? = null,
    val encryptionPublicJwk: Jwk? = null,
    val signalBundle: PublicSignalBundle? = null,
)

data class RelayLinkedDevice(
    val attestationNote: String? = null,
    val attestationStatus: String? = null,
    val attestedAt: String? = null,
    val createdAt: String,
    val current: Boolean,
    val id: String,
    val label: String,
    val platform: String,
    val revokedAt: String? = null,
    val riskLevel: String,
    val storageMode: String? = null,
    val updatedAt: String,
)

data class RelayDeviceEvent(
    val actorDeviceId: String? = null,
    val createdAt: String,
    val deviceId: String,
    val id: String,
    val kind: String,
    val label: String? = null,
    val platform: String? = null,
    val revokedAt: String? = null,
)

data class RelayMessage(
    val id: String,
    val senderId: String,
    val threadId: String? = null,
    val createdAt: String,
    val messageKind: String? = null,
    val protocol: String? = null,
    val wireMessage: String? = null,
    val counter: Int? = null,
    val epoch: Int? = null,
)

data class AttachmentUploadRequest(
    val byteLength: Int,
    val ciphertext: String,
    val createdAt: String,
    val id: String,
    val iv: String,
    val senderId: String? = null,
    val sha256: String,
    val threadId: String? = null,
    val transportPadding: String? = null,
)

data class AttachmentUploadResponse(
    val ok: Boolean,
    val attachmentId: String,
)

data class RelayAttachment(
    val byteLength: Int,
    val ciphertext: String,
    val createdAt: String,
    val id: String,
    val iv: String,
    val senderId: String,
    val sha256: String,
    val threadId: String,
)

data class RelayThread(
    val deliveryCapability: String? = null,
    val deliveryCapabilityExpiresAt: String? = null,
    val id: String,
    val mailboxHandle: String? = null,
    val mailboxHandleExpiresAt: String? = null,
    val mlsBootstrap: RelayMlsBootstrap? = null,
    val title: String,
    val protocol: String,
    val createdAt: String,
    val createdBy: String,
    val participantIds: List<String>,
    val attachmentCount: Int,
    val messages: List<RelayMessage>,
)

data class RelayAbuseControls(
    val powDifficultyBits: Int? = null,
    val powRequiredForRemoteUntrustedClients: Boolean? = null,
)

data class RelayHealth(
    val ok: Boolean,
    val abuseControls: RelayAbuseControls? = null,
    val androidKeyAttestationRequired: Boolean? = null,
    val androidPlayIntegrityRequired: Boolean? = null,
    val appleDeviceCheckRequired: Boolean? = null,
    val attestationConfigured: Boolean? = null,
    val attestationRequired: Boolean? = null,
    val directoryDiscoveryMode: String? = null,
    val protocolLabel: String,
    val protocolNote: String,
    val transparencySigner: TransparencySignerInfo? = null,
    val transportLabel: String,
    val users: Int,
    val threads: Int,
)

data class RelaySyncPayload(
    val directoryDiscoveryMode: String? = null,
    val relayTime: String? = null,
    val users: List<RelayUser>,
    val threads: List<RelayThread>,
)

data class RelayTransparencySnapshot(
    val entryCount: Int? = null,
    val relayTime: String? = null,
    val transparencyEntries: List<TransparencyEntry> = emptyList(),
    val transparencyHead: String? = null,
    val transparencySignature: String? = null,
    val transparencySigner: TransparencySignerInfo? = null,
)

data class RelaySecurityDevicesResponse(
    val deviceEvents: List<RelayDeviceEvent> = emptyList(),
    val devices: List<RelayLinkedDevice> = emptyList(),
)

data class RelaySession(
    val expiresAt: String,
    val privacyMode: String,
    val sessionId: String,
    val token: String,
)

data class RegisterResponse(
    val deviceEvents: List<RelayDeviceEvent> = emptyList(),
    val devices: List<RelayLinkedDevice> = emptyList(),
    val privacyMode: String? = null,
    val session: RelaySession? = null,
    val user: RelayUser,
)

data class TransparencyEntry(
    val createdAt: String,
    val entryHash: String,
    val fingerprint: String,
    val kind: String,
    val prekeyFingerprint: String? = null,
    val previousHash: String? = null,
    val sequence: Int,
    val userId: String,
    val username: String,
)

data class TransparencySignerInfo(
    val algorithm: String,
    val keyId: String,
    val publicKeyRaw: String,
    val publicKeySpki: String,
)

data class WitnessObservation(
    val entryCount: Int? = null,
    val head: String? = null,
    val observedAt: String? = null,
    val origin: String,
    val status: String,
)

data class TransparencyVerificationResult(
    val chainValid: Boolean = true,
    val entries: List<TransparencyEntry> = emptyList(),
    val head: String? = null,
    val pinnedHead: String? = null,
    val pinnedSignerKeyId: String? = null,
    val signerKeyId: String? = null,
    val warnings: List<String> = emptyList(),
    val witnesses: List<WitnessObservation> = emptyList(),
) {
    companion object {
        val empty = TransparencyVerificationResult()
    }
}

data class ClientIntegrityReport(
    val bundleIdentifier: String,
    val codeSignatureStatus: String,
    val deviceCheckStatus: String,
    val deviceCheckToken: String? = null,
    val deviceCheckTokenPresented: Boolean,
    val playIntegrityToken: String? = null,
    val playIntegrityTokenPresented: Boolean = false,
    val generatedAt: String,
    val note: String? = null,
    val riskLevel: String,
)

data class DeviceRevokeResponse(
    val deviceEvents: List<RelayDeviceEvent>,
    val devices: List<RelayLinkedDevice>,
    val ok: Boolean,
    val revokedDeviceId: String,
)

data class AccountDeleteResponse(
    val deletedAt: String? = null,
    val deletedUsername: String? = null,
    val ok: Boolean,
    val tombstoned: Boolean? = null,
    val tombstonedUsername: String? = null,
    val userId: String,
)

data class SecureAttachmentReference(
    val attachmentKey: String,
    val byteLength: Int,
    val fileName: String,
    val id: String,
    val mediaType: String,
    val sha256: String,
)

data class CachedMessageState(
    val attachments: List<SecureAttachmentReference> = emptyList(),
    val body: String,
    val hidden: Boolean = false,
    val status: String = "ok",
)

data class ConversationThreadRecord(
    val hiddenAt: String? = null,
    val localTitle: String? = null,
    val messageCache: Map<String, CachedMessageState> = emptyMap(),
    val lastProcessedMessageId: String? = null,
    val processedMessageCount: Int = 0,
    val protocol: String,
    val signalPeerUserId: String? = null,
)

data class LocalAttachmentDraft(
    val id: String,
    val byteLength: Int,
    val fileName: String,
    val mediaType: String,
    val uri: String,
)

data class StoredIdentityRecord(
    val identity: LocalIdentity,
    val recoveryRepresentation: String,
    val savedContacts: List<RelayUser> = emptyList(),
    val threadRecords: Map<String, ConversationThreadRecord> = emptyMap(),
)

data class AccountResetRequest(
    val createdAt: String,
    val device: DeviceDescriptor? = null,
    val displayName: String,
    val encryptionPublicJwk: Jwk,
    val fingerprint: String,
    val mlsKeyPackage: PublicMlsKeyPackage? = null,
    val prekeyCreatedAt: String,
    val prekeyFingerprint: String,
    val prekeyPublicJwk: Jwk,
    val prekeySignature: String,
    val recoveryFingerprint: String,
    val recoveryPublicJwk: Jwk,
    val recoverySignature: String,
    val signalBundle: PublicSignalBundle? = null,
    val signingPublicJwk: Jwk,
    val userId: String,
    val username: String,
)

data class AccountResetResponse(
    val deviceEvents: List<RelayDeviceEvent> = emptyList(),
    val devices: List<RelayLinkedDevice> = emptyList(),
    val ok: Boolean,
    val privacyMode: String? = null,
    val session: RelaySession? = null,
    val user: RelayUser,
)

data class IdentityCatalog(
    val version: Int = 2,
    val activeIdentityId: String? = null,
    val identities: List<StoredIdentityRecord> = emptyList(),
)

data class DeviceInventoryProfile(
    val id: String,
    val username: String,
    val displayName: String,
    val createdAt: String,
    val directoryCode: String? = null,
    val fingerprint: String,
    val storageMode: String,
    val expectedAliases: List<String> = emptyList(),
    val missingAliasKinds: List<String> = emptyList(),
)

data class DeviceInventoryAlias(
    val alias: String,
    val ownerId: String? = null,
    val kind: String,
    val storageMode: String,
    val linkedProfileId: String? = null,
)

data class LocalDeviceInventory(
    val appInstanceId: String? = null,
    val vaultCatalogPresent: Boolean = false,
    val vaultMasterAlias: String = "notrus.vault.master",
    val vaultMasterAliasPresent: Boolean = false,
    val deviceKeyAlias: String? = null,
    val deviceKeyAliasPresent: Boolean = false,
    val deviceKeyStorageMode: String? = null,
    val profiles: List<DeviceInventoryProfile> = emptyList(),
    val hardwareAliases: List<DeviceInventoryAlias> = emptyList(),
) {
    companion object {
        val empty = LocalDeviceInventory()
    }
}

data class DecryptedMessage(
    val attachments: List<SecureAttachmentReference> = emptyList(),
    val body: String,
    val createdAt: String,
    val id: String,
    val senderId: String,
    val senderName: String,
    val status: String,
)

data class ConversationThread(
    val deliveryCapability: String? = null,
    val id: String,
    val title: String,
    val mailboxHandle: String? = null,
    val protocol: String,
    val protocolLabel: String,
    val participants: List<RelayUser>,
    val participantIds: List<String>,
    val messages: List<DecryptedMessage>,
    val messageCount: Int,
    val attachmentCount: Int,
    val lastActivityAt: String,
    val supported: Boolean,
    val warning: String? = null,
)

data class AppUiState(
    val relayOriginInput: String = "",
    val privacyModeEnabled: Boolean = false,
    val visualEffectsEnabled: Boolean = true,
    val colorThemePreset: String = "ocean",
    val themeMode: String = "system",
    val deviceInventory: LocalDeviceInventory = LocalDeviceInventory.empty,
    val currentDevice: DeviceDescriptor? = null,
    val currentIdentity: LocalIdentity? = null,
    val currentDirectoryCode: String? = null,
    val linkedDeviceEvents: List<RelayDeviceEvent> = emptyList(),
    val linkedDevices: List<RelayLinkedDevice> = emptyList(),
    val profiles: List<LocalIdentity> = emptyList(),
    val contacts: List<RelayUser> = emptyList(),
    val directoryResults: List<RelayUser> = emptyList(),
    val integrityReport: ClientIntegrityReport? = null,
    val transparency: TransparencyVerificationResult = TransparencyVerificationResult.empty,
    val threads: List<ConversationThread> = emptyList(),
    val selectedThreadId: String? = null,
    val relayHealth: RelayHealth? = null,
    val vaultLocked: Boolean = false,
    val isBusy: Boolean = false,
    val statusMessage: String = "Android native client ready.",
    val errorMessage: String? = null,
    val onboardingDisplayName: String = "",
    val onboardingUsername: String = "",
    val exportPassphrase: String = "",
    val importPassphrase: String = "",
    val directoryQuery: String = "",
    val draftText: String = "",
    val pendingAttachments: List<LocalAttachmentDraft> = emptyList(),
    val witnessOriginsInput: String = "",
    val protocolEngineMessage: String = "Signal direct messaging and MLS-compatible group transport are linked into this Android build.",
    val transparencyResetAvailable: Boolean = false,
)

val AppUiState.selectedThread: ConversationThread?
    get() = threads.firstOrNull { it.id == selectedThreadId }
