package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.AttachmentChunkRecord
import com.notrus.android.model.AttachmentUploadRequest
import com.notrus.android.model.RelayAttachment
import com.notrus.android.model.SecureAttachmentReference
import java.io.File
import java.io.InputStream
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
    val chunkFiles: List<EncryptedAttachmentChunkFile> = emptyList(),
)

data class EncryptedAttachmentChunkFile(
    val descriptor: AttachmentChunkRecord,
    val file: File,
)

object AttachmentCrypto {
    const val MaxAttachmentSizeBytes: Long = 1024L * 1024L * 1024L
    const val LegacyInlineMaxPlaintextBytes: Int = 4 * 1024 * 1024
    const val ChunkPlaintextSizeBytes: Int = 4 * 1024 * 1024
    const val ChunkedTransport: String = "chunked-aes-gcm-v1"
    private val random = SecureRandom()
    private val messagePadBuckets = intArrayOf(256, 512, 1024, 2048, 4096)

    fun sealAttachment(
        data: ByteArray,
        fileName: String = "attachment.bin",
        mediaType: String = "application/octet-stream",
        senderId: String,
        threadId: String,
    ): SealedAttachment {
        require(data.size.toLong() <= MaxAttachmentSizeBytes) {
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

    fun sealAttachmentToChunkFiles(
        input: InputStream,
        declaredByteLength: Long?,
        outputDirectory: File,
        fileName: String = "attachment.bin",
        mediaType: String = "application/octet-stream",
        senderId: String,
        threadId: String,
    ): SealedAttachment {
        if (declaredByteLength != null && declaredByteLength > MaxAttachmentSizeBytes) {
            error("Attachments above ${MaxAttachmentSizeBytes / (1024 * 1024)} MB are not allowed on Android.")
        }

        outputDirectory.mkdirs()
        val attachmentKey = randomBytes(32)
        val attachmentId = UUID.randomUUID().toString().lowercase()
        val createdAt = Instant.now().toString()
        val key = SecretKeySpec(attachmentKey, "AES")
        val descriptors = mutableListOf<AttachmentChunkRecord>()
        val chunkFiles = mutableListOf<EncryptedAttachmentChunkFile>()
        val buffer = ByteArray(ChunkPlaintextSizeBytes)
        var totalBytes = 0L
        var index = 0

        while (true) {
            val read = input.read(buffer)
            if (read < 0) {
                break
            }
            if (read == 0) {
                continue
            }
            totalBytes += read.toLong()
            if (totalBytes > MaxAttachmentSizeBytes) {
                error("Attachments above ${MaxAttachmentSizeBytes / (1024 * 1024)} MB are not allowed on Android.")
            }

            val plaintext = buffer.copyOf(read)
            val iv = randomBytes(12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.updateAAD(
                attachmentChunkAad(
                    attachmentId = attachmentId,
                    chunkIndex = index,
                    createdAt = createdAt,
                    senderId = senderId,
                    threadId = threadId,
                ).toByteArray(Charsets.UTF_8)
            )
            val ciphertextWithTag = cipher.doFinal(plaintext)
            val ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
            val ciphertextBase64 = Base64.encodeToString(ciphertextWithTag, Base64.NO_WRAP)
            val chunkSha256 = sha256Hex(iv + ciphertextWithTag)
            val descriptor = AttachmentChunkRecord(
                byteLength = read,
                index = index,
                iv = ivBase64,
                sha256 = chunkSha256,
            )
            val chunkFile = File(outputDirectory, "$index.json")
            chunkFile.writeText(
                JSONObject()
                    .put("byteLength", read)
                    .put("ciphertext", ciphertextBase64)
                    .put("index", index)
                    .put("iv", ivBase64)
                    .put("sha256", chunkSha256)
                    .toString(),
                Charsets.UTF_8,
            )
            descriptors += descriptor
            chunkFiles += EncryptedAttachmentChunkFile(descriptor = descriptor, file = chunkFile)
            index += 1
        }

        require(totalBytes > 0) { "Empty attachments are not supported." }
        if (declaredByteLength != null && declaredByteLength > 0 && declaredByteLength != totalBytes) {
            error("Android could not read the complete attachment. Expected $declaredByteLength bytes but read $totalBytes.")
        }

        val manifestSha256 = chunkedManifestSha256(descriptors)
        val safeFileName = sanitizeFileName(fileName)
        val safeMediaType = if (mediaType.isBlank()) "application/octet-stream" else mediaType
        val totalByteLength = totalBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

        return SealedAttachment(
            request = AttachmentUploadRequest(
                byteLength = totalByteLength,
                createdAt = createdAt,
                id = attachmentId,
                senderId = senderId,
                sha256 = manifestSha256,
                threadId = threadId,
                transport = ChunkedTransport,
                chunkSize = ChunkPlaintextSizeBytes,
                chunkCount = descriptors.size,
                chunks = descriptors,
                transportPadding = null,
            ),
            reference = SecureAttachmentReference(
                attachmentKey = Base64.encodeToString(attachmentKey, Base64.NO_WRAP),
                byteLength = totalByteLength,
                fileName = safeFileName,
                id = attachmentId,
                mediaType = safeMediaType,
                sha256 = manifestSha256,
            ),
            chunkFiles = chunkFiles,
        )
    }

    fun openAttachment(attachment: RelayAttachment, reference: SecureAttachmentReference): ByteArray {
        require(attachment.transport != ChunkedTransport) {
            "Chunked attachments must be opened one encrypted chunk at a time."
        }
        val iv = Base64.decode(attachment.iv ?: "", Base64.NO_WRAP)
        val ciphertextWithTag = Base64.decode(attachment.ciphertext ?: "", Base64.NO_WRAP)
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

    fun verifyChunkedManifest(attachment: RelayAttachment, reference: SecureAttachmentReference) {
        require(attachment.transport == ChunkedTransport) { "Attachment is not chunked." }
        require(attachment.sha256.equals(reference.sha256, ignoreCase = true)) {
            "Attachment manifest integrity verification failed on Android."
        }
        val digest = chunkedManifestSha256(attachment.chunks)
        require(digest.equals(reference.sha256, ignoreCase = true)) {
            "Attachment chunk manifest integrity verification failed on Android."
        }
    }

    fun openAttachmentChunk(
        attachment: RelayAttachment,
        chunk: AttachmentChunkRecord,
        reference: SecureAttachmentReference,
    ): ByteArray {
        require(attachment.transport == ChunkedTransport) { "Attachment is not chunked." }
        val ciphertext = chunk.ciphertext ?: error("Encrypted attachment chunk payload is missing.")
        val iv = Base64.decode(chunk.iv, Base64.NO_WRAP)
        val ciphertextWithTag = Base64.decode(ciphertext, Base64.NO_WRAP)
        val digest = sha256Hex(iv + ciphertextWithTag)
        require(digest.equals(chunk.sha256, ignoreCase = true)) {
            "Attachment chunk integrity verification failed on Android."
        }
        val expected = attachment.chunks.getOrNull(chunk.index)
            ?: error("Attachment chunk ${chunk.index} is not in the manifest.")
        require(expected.sha256.equals(chunk.sha256, ignoreCase = true) && expected.iv == chunk.iv) {
            "Attachment chunk metadata did not match the manifest on Android."
        }

        val key = Base64.decode(reference.attachmentKey, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, iv),
        )
        cipher.updateAAD(
            attachmentChunkAad(
                attachmentId = attachment.id,
                chunkIndex = chunk.index,
                createdAt = attachment.createdAt,
                senderId = attachment.senderId,
                threadId = attachment.threadId,
            ).toByteArray(Charsets.UTF_8)
        )
        return cipher.doFinal(ciphertextWithTag)
    }

    fun readEncryptedChunkFile(file: File): AttachmentChunkRecord {
        val json = JSONObject(file.readText(Charsets.UTF_8))
        return AttachmentChunkRecord(
            byteLength = json.optInt("byteLength", 0),
            ciphertext = json.optString("ciphertext"),
            index = json.optInt("index", -1),
            iv = json.optString("iv"),
            sha256 = json.optString("sha256"),
        )
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

    private fun attachmentChunkAad(
        attachmentId: String,
        chunkIndex: Int,
        createdAt: String,
        senderId: String,
        threadId: String,
    ): String =
        """{"attachmentId":${JSONObject.quote(attachmentId)},"chunkIndex":$chunkIndex,"createdAt":${JSONObject.quote(createdAt)},"kind":"notrus-attachment-chunk","senderId":${JSONObject.quote(senderId)},"threadId":${JSONObject.quote(threadId)}}"""

    private fun chunkedManifestSha256(chunks: List<AttachmentChunkRecord>): String {
        val manifest = buildString {
            append("notrus-chunked-aes-gcm-v1\n")
            chunks.sortedBy { it.index }.forEach { chunk ->
                append(chunk.index).append('\n')
                append(chunk.byteLength).append('\n')
                append(chunk.iv).append('\n')
                append(chunk.sha256).append('\n')
            }
        }
        return sha256Hex(manifest.toByteArray(Charsets.UTF_8))
    }

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
