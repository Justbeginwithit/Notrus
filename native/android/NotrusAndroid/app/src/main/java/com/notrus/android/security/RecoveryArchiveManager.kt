package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.EncryptedPortableAccountArchive
import com.notrus.android.model.ImportedRecoveryPayload
import com.notrus.android.model.Jwk
import com.notrus.android.model.PortableArchiveIdentitySnapshot
import com.notrus.android.model.RecoveryTransferArchive
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

    fun suggestedExportFileName(identityUsername: String): String =
        "notrus-$identityUsername-recovery.json"

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

    private fun identitySnapshotToJson(identity: PortableArchiveIdentitySnapshot): JSONObject =
        JSONObject()
            .put("id", identity.id)
            .put("username", identity.username)
            .put("displayName", identity.displayName)
            .put("createdAt", identity.createdAt)
            .put("recoveryFingerprint", identity.recoveryFingerprint)
            .put("recoveryPublicJwk", jwkToJson(identity.recoveryPublicJwk))
            .put("recoveryRepresentation", identity.recoveryRepresentation)

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
}

private object NotrusSecureRandom {
    private val random = java.security.SecureRandom()

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)
}
