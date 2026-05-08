package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.ChatBackupArchive
import com.notrus.android.model.ChatBackupIdentitySnapshot
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.EncryptedPortableAccountArchive
import com.notrus.android.model.ImportedRecoveryPayload
import com.notrus.android.model.PortableArchiveIdentitySnapshot
import com.notrus.android.model.RecoveryTransferArchive
import com.notrus.android.model.SignalProtocolState
import com.notrus.android.model.StoredIdentityRecord
import com.notrus.android.serialization.NotrusJsonCodecs.jwkToJson
import com.notrus.android.serialization.NotrusJsonCodecs.jsonToJwk
import com.notrus.android.serialization.NotrusJsonCodecs.jsonToSignalBundle
import com.notrus.android.serialization.NotrusJsonCodecs.jsonToSignalState
import com.notrus.android.serialization.NotrusJsonCodecs.jsonToThreadRecord
import com.notrus.android.serialization.NotrusJsonCodecs.signalBundleToJson
import com.notrus.android.serialization.NotrusJsonCodecs.signalStateToJson
import com.notrus.android.serialization.NotrusJsonCodecs.threadRecordToJson
import java.nio.charset.StandardCharsets
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

object RecoveryArchiveManager {
    private const val ARCHIVE_VERSION = 1
    private const val ARCHIVE_ROUNDS = 120_000
    private const val TRANSFER_MODE = "recovery-authorized-reset"
    private const val CHAT_BACKUP_KIND = "notrus-chat-history-v1"

    fun exportAndroidTransferArchive(
        record: StoredIdentityRecord,
        passphrase: String,
    ): ByteArray {
        val exportedAt = Instant.now().toString()
        val identity = PortableArchiveIdentitySnapshot(
            id = record.identity.id,
            username = record.identity.username,
            displayName = record.identity.displayName,
            createdAt = record.identity.createdAt,
            recoveryFingerprint = record.identity.recoveryFingerprint,
            recoveryPublicJwk = record.identity.recoveryPublicJwk,
            recoveryRepresentation = record.recoveryRepresentation,
        )
        val archive = RecoveryTransferArchive(
            version = ARCHIVE_VERSION,
            exportedAt = exportedAt,
            sourcePlatform = "android",
            transferMode = TRANSFER_MODE,
            identity = identity,
        )
        return encryptEnvelope(transferArchiveToJson(archive).toString(), passphrase, exportedAt)
    }

    fun importArchive(
        bytes: ByteArray,
        passphrase: String,
    ): ImportedRecoveryPayload {
        require(bytes.isNotEmpty()) { "The selected recovery archive is empty. Export it again from the source device." }
        val envelopeJson = JSONObject(String(bytes, StandardCharsets.UTF_8))
        val envelope = EncryptedPortableAccountArchive(
            version = envelopeJson.optInt("version", ARCHIVE_VERSION),
            exportedAt = envelopeJson.optString("exportedAt"),
            iv = envelopeJson.optString("iv"),
            salt = envelopeJson.optString("salt"),
            rounds = envelopeJson.optInt("rounds", ARCHIVE_ROUNDS),
            ciphertext = envelopeJson.optString("ciphertext"),
        )
        val plaintext = decryptEnvelope(envelope, passphrase)
        val root = JSONObject(String(plaintext, StandardCharsets.UTF_8))
        require(root.optString("backupKind") != CHAT_BACKUP_KIND) {
            "This file is an encrypted chat backup. Recover the account first, then use Restore chat backup."
        }

        return if (root.optString("transferMode") == TRANSFER_MODE) {
            ImportedRecoveryPayload.Transfer(
                exportedAt = root.optString("exportedAt", envelope.exportedAt),
                sourcePlatform = root.optString("sourcePlatform", "unknown"),
                transferMode = root.optString("transferMode", TRANSFER_MODE),
                identity = parseIdentitySnapshot(root.optJSONObject("identity") ?: JSONObject()),
            )
        } else {
            val identityJson = root.optJSONObject("identity") ?: throw IllegalArgumentException("Recovery archive identity is missing.")
            ImportedRecoveryPayload.Portable(
                exportedAt = root.optString("exportedAt", envelope.exportedAt),
                identity = parseIdentitySnapshot(identityJson),
            )
        }
    }

    fun exportChatBackup(
        record: StoredIdentityRecord,
        passphrase: String,
    ): ByteArray {
        val exportedAt = Instant.now().toString()
        val identity = ChatBackupIdentitySnapshot(
            id = record.identity.id,
            username = record.identity.username,
            displayName = record.identity.displayName,
            createdAt = record.identity.createdAt,
            recoveryFingerprint = record.identity.recoveryFingerprint,
            standardsSignalBundle = record.identity.standardsSignalBundle,
            standardsSignalState = record.identity.standardsSignalState,
        )
        val backup = ChatBackupArchive(
            version = ARCHIVE_VERSION,
            exportedAt = exportedAt,
            sourcePlatform = "android",
            backupKind = CHAT_BACKUP_KIND,
            identity = identity,
            attachmentsIncluded = false,
            threadRecords = record.threadRecords,
        )
        return encryptEnvelope(chatBackupToJson(backup).toString(), passphrase, exportedAt)
    }

    fun importChatBackup(
        bytes: ByteArray,
        passphrase: String,
    ): ChatBackupArchive {
        require(bytes.isNotEmpty()) { "The selected chat backup is empty. Export it again from the source device." }
        val envelopeJson = JSONObject(String(bytes, StandardCharsets.UTF_8))
        val envelope = EncryptedPortableAccountArchive(
            version = envelopeJson.optInt("version", ARCHIVE_VERSION),
            exportedAt = envelopeJson.optString("exportedAt"),
            iv = envelopeJson.optString("iv"),
            salt = envelopeJson.optString("salt"),
            rounds = envelopeJson.optInt("rounds", ARCHIVE_ROUNDS),
            ciphertext = envelopeJson.optString("ciphertext"),
        )
        val plaintext = decryptEnvelope(envelope, passphrase)
        val root = JSONObject(String(plaintext, StandardCharsets.UTF_8))
        require(root.optString("backupKind") == CHAT_BACKUP_KIND) {
            "The selected file is not a Notrus encrypted chat backup."
        }
        return jsonToChatBackup(root, envelope.exportedAt)
    }

    fun suggestedExportFileName(identityUsername: String): String =
        "notrus-$identityUsername-recovery.json"

    fun suggestedChatBackupFileName(identityUsername: String): String =
        "notrus-$identityUsername-chat-backup.json"

    private fun encryptEnvelope(
        plaintext: String,
        passphrase: String,
        exportedAt: String,
    ): ByteArray {
        val salt = NotrusSecureRandom.randomBytes(16)
        val iv = NotrusSecureRandom.randomBytes(12)
        val key = RecoveryKeyManager.deriveArchiveKey(passphrase, salt, ARCHIVE_ROUNDS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(RecoveryKeyManager.archiveAuthenticationData())
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        return JSONObject()
            .put("version", ARCHIVE_VERSION)
            .put("exportedAt", exportedAt)
            .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            .put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .put("rounds", ARCHIVE_ROUNDS)
            .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
    }

    private fun decryptEnvelope(
        envelope: EncryptedPortableAccountArchive,
        passphrase: String,
    ): ByteArray {
        val key = RecoveryKeyManager.deriveArchiveKey(
            passphrase = passphrase,
            salt = Base64.decode(envelope.salt, Base64.NO_WRAP),
            rounds = envelope.rounds,
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, Base64.decode(envelope.iv, Base64.NO_WRAP)),
        )
        cipher.updateAAD(RecoveryKeyManager.archiveAuthenticationData())
        return cipher.doFinal(Base64.decode(envelope.ciphertext, Base64.NO_WRAP))
    }

    private fun transferArchiveToJson(archive: RecoveryTransferArchive): JSONObject =
        JSONObject()
            .put("version", archive.version)
            .put("exportedAt", archive.exportedAt)
            .put("sourcePlatform", archive.sourcePlatform)
            .put("transferMode", archive.transferMode)
            .put("identity", identitySnapshotToJson(archive.identity))

    private fun chatBackupToJson(backup: ChatBackupArchive): JSONObject =
        JSONObject()
            .put("version", backup.version)
            .put("exportedAt", backup.exportedAt)
            .put("sourcePlatform", backup.sourcePlatform)
            .put("backupKind", backup.backupKind)
            .put("identity", chatBackupIdentityToJson(backup.identity))
            .put("attachmentsIncluded", backup.attachmentsIncluded)
            .put("threadRecords", JSONObject().apply {
                backup.threadRecords.forEach { (threadId, record) ->
                    put(threadId, threadRecordToJson(record))
                }
            })

    private fun jsonToChatBackup(json: JSONObject, fallbackExportedAt: String): ChatBackupArchive {
        val threadRecords = linkedMapOf<String, ConversationThreadRecord>()
        val threadRecordsJson = json.optJSONObject("threadRecords") ?: JSONObject()
        val keys = threadRecordsJson.keys()
        while (keys.hasNext()) {
            val threadId = keys.next()
            threadRecordsJson.optJSONObject(threadId)?.let {
                threadRecords[threadId] = jsonToThreadRecord(it, legacyPeerKey = "standardsSignalPeerUserId")
            }
        }
        return ChatBackupArchive(
            version = json.optInt("version", ARCHIVE_VERSION),
            exportedAt = json.optString("exportedAt", fallbackExportedAt),
            sourcePlatform = json.optString("sourcePlatform", "unknown"),
            backupKind = json.optString("backupKind", CHAT_BACKUP_KIND),
            identity = parseChatBackupIdentity(json.optJSONObject("identity") ?: JSONObject()),
            attachmentsIncluded = json.optBoolean("attachmentsIncluded", false),
            threadRecords = threadRecords,
        )
    }

    private fun identitySnapshotToJson(identity: PortableArchiveIdentitySnapshot): JSONObject =
        JSONObject()
            .put("id", identity.id)
            .put("username", identity.username)
            .put("displayName", identity.displayName)
            .put("createdAt", identity.createdAt)
            .put("recoveryFingerprint", identity.recoveryFingerprint)
            .put("recoveryPublicJwk", jwkToJson(identity.recoveryPublicJwk))
            .put("recoveryRepresentation", identity.recoveryRepresentation)

    private fun chatBackupIdentityToJson(identity: ChatBackupIdentitySnapshot): JSONObject =
        JSONObject()
            .put("id", identity.id)
            .put("username", identity.username)
            .put("displayName", identity.displayName)
            .put("createdAt", identity.createdAt)
            .put("recoveryFingerprint", identity.recoveryFingerprint)
            .put("standardsSignalBundle", identity.standardsSignalBundle?.let(::signalBundleToJson))
            .put("standardsSignalState", identity.standardsSignalState?.let(::signalStateToJson))

    private fun parseIdentitySnapshot(json: JSONObject): PortableArchiveIdentitySnapshot =
        PortableArchiveIdentitySnapshot(
            id = json.optString("id"),
            username = json.optString("username"),
            displayName = json.optString("displayName"),
            createdAt = json.optString("createdAt"),
            recoveryFingerprint = json.optString("recoveryFingerprint"),
            recoveryPublicJwk = jsonToJwk(json.optJSONObject("recoveryPublicJwk") ?: JSONObject()),
            recoveryRepresentation = json.optString("recoveryRepresentation"),
        )

    private fun parseChatBackupIdentity(json: JSONObject): ChatBackupIdentitySnapshot =
        ChatBackupIdentitySnapshot(
            id = json.optString("id"),
            username = json.optString("username"),
            displayName = json.optString("displayName"),
            createdAt = json.optString("createdAt"),
            recoveryFingerprint = json.optString("recoveryFingerprint"),
            standardsSignalBundle = json.optJSONObject("standardsSignalBundle")?.let(::jsonToSignalBundle),
            standardsSignalState = parseSignalState(json.opt("standardsSignalState")),
        )

    private fun parseSignalState(raw: Any?): SignalProtocolState? = when (raw) {
        is JSONObject -> jsonToSignalState(raw)
        is String -> runCatching { JSONObject(raw) }.getOrNull()?.let(::jsonToSignalState)
        else -> null
    }
}

private object NotrusSecureRandom {
    private val random = java.security.SecureRandom()

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)
}
