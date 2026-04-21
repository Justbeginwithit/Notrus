package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.AttachmentUploadRequest
import com.notrus.android.model.RelayAttachment
import com.notrus.android.model.SecureAttachmentReference
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import kotlin.math.ceil

data class SealedAttachment(
    val request: AttachmentUploadRequest,
    val reference: SecureAttachmentReference,
)

object AttachmentCrypto {
    const val MaxAttachmentSizeBytes: Int = 25 * 1024 * 1024
    private val random = SecureRandom()
    private val messagePadBuckets = intArrayOf(256, 512, 1024, 2048, 4096)

    fun sealAttachment(
        data: ByteArray,
        fileName: String = "attachment.bin",
        mediaType: String = "application/octet-stream",
        senderId: String,
        threadId: String,
    ): SealedAttachment {
        require(data.size <= MaxAttachmentSizeBytes) {
            "Attachments above ${MaxAttachmentSizeBytes / (1024 * 1024)} MB are not allowed on Android."
        }

        val attachmentKey = randomBytes(32)
        val attachmentId = UUID.randomUUID().toString().lowercase()
        val createdAt = Instant.now().toString()
        val iv = randomBytes(12)
        val padded = padAttachmentPayload(data)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(attachmentKey, "AES"),
            GCMParameterSpec(128, iv),
        )
        cipher.updateAAD(
            attachmentAad(
                attachmentId = attachmentId,
                createdAt = createdAt,
                senderId = senderId,
                threadId = threadId,
            ).toByteArray(Charsets.UTF_8)
        )
        val ciphertextWithTag = cipher.doFinal(padded.serialized)
        val combined = iv + ciphertextWithTag
        val sha256 = sha256Hex(combined)

        return SealedAttachment(
            request = AttachmentUploadRequest(
                byteLength = padded.paddingBucket,
                ciphertext = Base64.encodeToString(ciphertextWithTag, Base64.NO_WRAP),
                createdAt = createdAt,
                id = attachmentId,
                iv = Base64.encodeToString(iv, Base64.NO_WRAP),
                senderId = senderId,
                sha256 = sha256,
                threadId = threadId,
                transportPadding = null,
            ),
            reference = SecureAttachmentReference(
                attachmentKey = Base64.encodeToString(attachmentKey, Base64.NO_WRAP),
                byteLength = data.size,
                fileName = sanitizeFileName(fileName),
                id = attachmentId,
                mediaType = if (mediaType.isBlank()) "application/octet-stream" else mediaType,
                sha256 = sha256,
            ),
        )
    }

    fun openAttachment(attachment: RelayAttachment, reference: SecureAttachmentReference): ByteArray {
        val iv = Base64.decode(attachment.iv, Base64.NO_WRAP)
        val ciphertextWithTag = Base64.decode(attachment.ciphertext, Base64.NO_WRAP)
        val combined = iv + ciphertextWithTag
        val digest = sha256Hex(combined)
        require(digest.equals(reference.sha256, ignoreCase = true)) {
            "Attachment integrity verification failed on Android."
        }

        val key = Base64.decode(reference.attachmentKey, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, iv),
        )
        cipher.updateAAD(
            attachmentAad(
                attachmentId = attachment.id,
                createdAt = attachment.createdAt,
                senderId = attachment.senderId,
                threadId = attachment.threadId,
            ).toByteArray(Charsets.UTF_8)
        )
        val plaintext = cipher.doFinal(ciphertextWithTag)
        return runCatching { unpadAttachmentPayload(plaintext) }
            .getOrElse { plaintext }
    }

    fun sanitizeFileName(name: String): String {
        val normalized = name.trim()
            .replace("\\", "_")
            .replace("/", "_")
        return normalized.ifBlank { "attachment.bin" }
    }

    private fun attachmentAad(
        attachmentId: String,
        createdAt: String,
        senderId: String,
        threadId: String,
    ): String =
        """{"attachmentId":${JSONObject.quote(attachmentId)},"createdAt":${JSONObject.quote(createdAt)},"kind":"notrus-attachment","senderId":${JSONObject.quote(senderId)},"threadId":${JSONObject.quote(threadId)}}"""

    private fun attachmentPayloadData(base64Payload: String, padding: String, size: Int): ByteArray =
        """{"padding":${JSONObject.quote(padding)},"payload":${JSONObject.quote(base64Payload)},"size":$size}""".toByteArray(Charsets.UTF_8)

    private fun padAttachmentPayload(data: ByteArray): PaddedAttachmentPayload {
        val payload = Base64.encodeToString(data, Base64.NO_WRAP)
        var padding = ""
        val target = choosePaddingBucket(attachmentPayloadData(payload, padding, data.size).size)

        while (attachmentPayloadData(payload, padding, data.size).size < target) {
            padding += "."
        }

        while (padding.isNotEmpty()) {
            val currentSize = attachmentPayloadData(payload, padding, data.size).size
            if (currentSize <= target) {
                break
            }
            padding = padding.dropLast(1)
        }

        return PaddedAttachmentPayload(
            serialized = attachmentPayloadData(payload, padding, data.size),
            paddingBucket = target,
        )
    }

    private fun unpadAttachmentPayload(data: ByteArray): ByteArray {
        val payload = JSONObject(String(data, Charsets.UTF_8)).optString("payload")
        require(payload.isNotBlank()) { "Attachment payload was missing in encrypted envelope." }
        return Base64.decode(payload, Base64.NO_WRAP)
    }

    private fun choosePaddingBucket(byteLength: Int): Int {
        for (bucket in messagePadBuckets) {
            if (byteLength <= bucket) {
                return bucket
            }
        }
        return ceil(byteLength / 2048.0).toInt() * 2048
    }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(data)
            .joinToString("") { byte -> "%02x".format(byte) }
}

private data class PaddedAttachmentPayload(
    val serialized: ByteArray,
    val paddingBucket: Int,
)
