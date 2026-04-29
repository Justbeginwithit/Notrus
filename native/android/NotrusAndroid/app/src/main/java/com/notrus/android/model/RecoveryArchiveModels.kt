package com.notrus.android.model

data class EncryptedPortableAccountArchive(
    val version: Int,
    val exportedAt: String,
    val iv: String,
    val salt: String,
    val rounds: Int,
    val ciphertext: String,
)

data class PortableArchiveIdentitySnapshot(
    val id: String,
    val username: String,
    val displayName: String,
    val createdAt: String,
    val recoveryFingerprint: String,
    val recoveryPublicJwk: Jwk,
    val recoveryRepresentation: String,
)

data class RecoveryTransferArchive(
    val version: Int,
    val exportedAt: String,
    val sourcePlatform: String,
    val transferMode: String,
    val identity: PortableArchiveIdentitySnapshot,
)

data class ChatBackupIdentitySnapshot(
    val id: String,
    val username: String,
    val displayName: String,
    val createdAt: String,
    val recoveryFingerprint: String,
    val standardsSignalBundle: PublicSignalBundle? = null,
    val standardsSignalState: SignalProtocolState? = null,
)

data class ChatBackupArchive(
    val version: Int,
    val exportedAt: String,
    val sourcePlatform: String,
    val backupKind: String,
    val identity: ChatBackupIdentitySnapshot,
    val attachmentsIncluded: Boolean,
    val threadRecords: Map<String, ConversationThreadRecord>,
)

sealed interface ImportedRecoveryPayload {
    val exportedAt: String
    val identity: PortableArchiveIdentitySnapshot

    data class Portable(
        override val exportedAt: String,
        override val identity: PortableArchiveIdentitySnapshot,
    ) : ImportedRecoveryPayload

    data class Transfer(
        override val exportedAt: String,
        val sourcePlatform: String,
        val transferMode: String,
        override val identity: PortableArchiveIdentitySnapshot,
    ) : ImportedRecoveryPayload
}
