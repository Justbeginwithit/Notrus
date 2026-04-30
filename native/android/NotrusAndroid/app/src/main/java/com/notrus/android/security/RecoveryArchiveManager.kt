package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ChatBackupArchive
import com.notrus.android.model.ChatBackupIdentitySnapshot
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.EncryptedPortableAccountArchive
import com.notrus.android.model.ImportedRecoveryPayload
import com.notrus.android.model.Jwk
import com.notrus.android.model.PortableArchiveIdentitySnapshot
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.RecoveryTransferArchive
import com.notrus.android.model.SecureAttachmentReference
import com.notrus.android.model.SignalProtocolState
import com.notrus.android.model.StoredIdentityRecord
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
            threadRecordsJson.optJSONObject(threadId)?.let { threadRecords[threadId] = jsonToThreadRecord(it) }
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

    private fun jwkToJson(jwk: Jwk): JSONObject =
        JSONObject()
            .put("crv", jwk.crv)
            .put("kty", jwk.kty)
            .put("x", jwk.x)
            .put("y", jwk.y)

    private fun jsonToJwk(json: JSONObject): Jwk =
        Jwk(
            crv = json.optString("crv", "P-256"),
            kty = json.optString("kty", "EC"),
            x = json.optString("x"),
            y = json.optString("y"),
        )

    private fun signalBundleToJson(bundle: PublicSignalBundle): JSONObject =
        JSONObject()
            .put("deviceId", bundle.deviceId)
            .put("identityKey", bundle.identityKey)
            .put("kyberPreKeyId", bundle.kyberPreKeyId)
            .put("kyberPreKeyPublic", bundle.kyberPreKeyPublic)
            .put("kyberPreKeySignature", bundle.kyberPreKeySignature)
            .put("preKeyId", bundle.preKeyId)
            .put("preKeyPublic", bundle.preKeyPublic)
            .put("registrationId", bundle.registrationId)
            .put("signedPreKeyId", bundle.signedPreKeyId)
            .put("signedPreKeyPublic", bundle.signedPreKeyPublic)
            .put("signedPreKeySignature", bundle.signedPreKeySignature)

    private fun jsonToSignalBundle(json: JSONObject): PublicSignalBundle =
        PublicSignalBundle(
            deviceId = jsonInt32(json, "deviceId", 1),
            identityKey = json.optString("identityKey"),
            kyberPreKeyId = jsonInt32(json, "kyberPreKeyId", 1),
            kyberPreKeyPublic = json.optString("kyberPreKeyPublic"),
            kyberPreKeySignature = json.optString("kyberPreKeySignature"),
            preKeyId = jsonInt32(json, "preKeyId", 1),
            preKeyPublic = json.optString("preKeyPublic"),
            registrationId = jsonInt32(json, "registrationId", 1),
            signedPreKeyId = jsonInt32(json, "signedPreKeyId", 1),
            signedPreKeyPublic = json.optString("signedPreKeyPublic"),
            signedPreKeySignature = json.optString("signedPreKeySignature"),
        )

    private fun signalStateToJson(state: SignalProtocolState): JSONObject =
        JSONObject()
            .put("deviceId", state.deviceId)
            .put("identityKeyPair", state.identityKeyPair)
            .put("knownIdentities", JSONObject(state.knownIdentities))
            .put("kyberPreKeyId", state.kyberPreKeyId)
            .put("kyberPreKeyRecord", state.kyberPreKeyRecord)
            .put("preKeyId", state.preKeyId)
            .put("preKeyRecord", state.preKeyRecord)
            .put("registrationId", state.registrationId)
            .put("senderKeys", JSONObject(state.senderKeys))
            .put("sessions", JSONObject(state.sessions))
            .put("signedPreKeyId", state.signedPreKeyId)
            .put("signedPreKeyRecord", state.signedPreKeyRecord)

    private fun parseSignalState(raw: Any?): SignalProtocolState? = when (raw) {
        is JSONObject -> jsonToSignalState(raw)
        is String -> runCatching { JSONObject(raw) }.getOrNull()?.let(::jsonToSignalState)
        else -> null
    }

    private fun jsonToSignalState(json: JSONObject): SignalProtocolState =
        SignalProtocolState(
            deviceId = jsonInt32(json, "deviceId", 1),
            identityKeyPair = json.optString("identityKeyPair"),
            knownIdentities = jsonObjectToMap(json.optJSONObject("knownIdentities")),
            kyberPreKeyId = jsonInt32(json, "kyberPreKeyId", 1),
            kyberPreKeyRecord = json.optString("kyberPreKeyRecord"),
            preKeyId = jsonInt32(json, "preKeyId", 1),
            preKeyRecord = json.optString("preKeyRecord"),
            registrationId = jsonInt32(json, "registrationId", 1),
            senderKeys = jsonObjectToMap(json.optJSONObject("senderKeys")),
            sessions = jsonObjectToMap(json.optJSONObject("sessions")),
            signedPreKeyId = jsonInt32(json, "signedPreKeyId", 1),
            signedPreKeyRecord = json.optString("signedPreKeyRecord"),
        )

    private fun jsonObjectToMap(json: JSONObject?): Map<String, String> {
        val source = json ?: return emptyMap()
        val result = linkedMapOf<String, String>()
        val keys = source.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            result[key] = source.optString(key)
        }
        return result
    }

    private fun jsonInt32(json: JSONObject, key: String, defaultValue: Int): Int {
        if (!json.has(key) || json.isNull(key)) {
            return defaultValue
        }
        val raw = json.opt(key) ?: return defaultValue
        val longValue = when (raw) {
            is Number -> raw.toLong()
            is String -> raw.toLongOrNull() ?: return defaultValue
            else -> return defaultValue
        }
        return if (longValue in Int.MIN_VALUE.toLong()..0xFFFF_FFFFL) {
            longValue.toInt()
        } else {
            defaultValue
        }
    }

    private fun threadRecordToJson(record: ConversationThreadRecord): JSONObject =
        JSONObject()
            .put("hiddenAt", record.hiddenAt)
            .put("localTitle", record.localTitle)
            .put("mutedAt", record.mutedAt)
            .put("purgedAt", record.purgedAt)
            .put("lastProcessedMessageId", record.lastProcessedMessageId)
            .put("processedMessageCount", record.processedMessageCount)
            .put("protocol", record.protocol)
            .put("signalPeerUserId", record.signalPeerUserId)
            .put("messageCache", JSONObject().apply {
                record.messageCache.forEach { (messageId, cached) ->
                    put(messageId, cachedMessageToJson(cached))
                }
            })

    private fun jsonToThreadRecord(json: JSONObject): ConversationThreadRecord {
        val messageCache = linkedMapOf<String, CachedMessageState>()
        val messageCacheJson = json.optJSONObject("messageCache") ?: JSONObject()
        val keys = messageCacheJson.keys()
        while (keys.hasNext()) {
            val messageId = keys.next()
            messageCacheJson.optJSONObject(messageId)?.let { messageCache[messageId] = jsonToCachedMessage(it) }
        }
        return ConversationThreadRecord(
            hiddenAt = json.optString("hiddenAt").ifBlank { null },
            localTitle = json.optString("localTitle").ifBlank { null },
            mutedAt = json.optString("mutedAt").ifBlank { null },
            purgedAt = json.optString("purgedAt").ifBlank { null },
            lastProcessedMessageId = json.optString("lastProcessedMessageId").ifBlank { null },
            messageCache = messageCache,
            processedMessageCount = json.optInt("processedMessageCount", 0),
            protocol = json.optString("protocol", "signal-pqxdh-double-ratchet-v1"),
            signalPeerUserId = json.optString("signalPeerUserId").ifBlank {
                json.optString("standardsSignalPeerUserId").ifBlank { null }
            },
        )
    }

    private fun cachedMessageToJson(message: CachedMessageState): JSONObject =
        JSONObject()
            .put("body", message.body)
            .put("hidden", message.hidden)
            .put("status", message.status)
            .put("relayCounter", message.relayCounter)
            .put("relayCreatedAt", message.relayCreatedAt)
            .put("relayEpoch", message.relayEpoch)
            .put("relayMessageKind", message.relayMessageKind)
            .put("relayProtocol", message.relayProtocol)
            .put("relaySenderId", message.relaySenderId)
            .put("relayThreadId", message.relayThreadId)
            .put("relayWireMessage", message.relayWireMessage)
            .put("attachments", org.json.JSONArray().apply {
                message.attachments.forEach { put(attachmentReferenceToJson(it)) }
            })

    private fun jsonToCachedMessage(json: JSONObject): CachedMessageState {
        val attachments = mutableListOf<SecureAttachmentReference>()
        val attachmentsJson = json.optJSONArray("attachments") ?: org.json.JSONArray()
        for (index in 0 until attachmentsJson.length()) {
            attachmentsJson.optJSONObject(index)?.let { attachments += jsonToAttachmentReference(it) }
        }
        return CachedMessageState(
            attachments = attachments,
            body = json.optString("body"),
            hidden = json.optBoolean("hidden", false),
            relayCounter = json.takeIf { it.has("relayCounter") && !it.isNull("relayCounter") }?.optInt("relayCounter"),
            relayCreatedAt = json.optString("relayCreatedAt").ifBlank { null },
            relayEpoch = json.takeIf { it.has("relayEpoch") && !it.isNull("relayEpoch") }?.optInt("relayEpoch"),
            relayMessageKind = json.optString("relayMessageKind").ifBlank { null },
            relayProtocol = json.optString("relayProtocol").ifBlank { null },
            relaySenderId = json.optString("relaySenderId").ifBlank { null },
            relayThreadId = json.optString("relayThreadId").ifBlank { null },
            relayWireMessage = json.optString("relayWireMessage").ifBlank { null },
            status = json.optString("status", "ok"),
        )
    }

    private fun attachmentReferenceToJson(reference: SecureAttachmentReference): JSONObject =
        JSONObject()
            .put("attachmentKey", reference.attachmentKey)
            .put("byteLength", reference.byteLength)
            .put("fileName", reference.fileName)
            .put("id", reference.id)
            .put("mediaType", reference.mediaType)
            .put("sha256", reference.sha256)

    private fun jsonToAttachmentReference(json: JSONObject): SecureAttachmentReference =
        SecureAttachmentReference(
            attachmentKey = json.optString("attachmentKey"),
            byteLength = json.optInt("byteLength", 0),
            fileName = json.optString("fileName"),
            id = json.optString("id"),
            mediaType = json.optString("mediaType"),
            sha256 = json.optString("sha256"),
        )
}

private object NotrusSecureRandom {
    private val random = java.security.SecureRandom()

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)
}
