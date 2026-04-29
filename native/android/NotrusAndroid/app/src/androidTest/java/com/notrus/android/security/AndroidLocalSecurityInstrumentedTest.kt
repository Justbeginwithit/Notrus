package com.notrus.android.security

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.Jwk
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.MessageCachePolicy
import com.notrus.android.model.RelayAttachment
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.RelayMessage
import com.notrus.android.model.SecureAttachmentReference
import com.notrus.android.model.SignalProtocolState
import com.notrus.android.model.StoredIdentityRecord
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidLocalSecurityInstrumentedTest {
    @Test
    fun attachmentSealAndOpenRoundTripWithDigestVerification() {
        val plaintext = "Android attachment crypto round-trip".toByteArray(StandardCharsets.UTF_8)
        val sealed = AttachmentCrypto.sealAttachment(
            data = plaintext,
            fileName = "proof.txt",
            mediaType = "text/plain",
            senderId = "user-a",
            threadId = "thread-a",
        )
        val request = sealed.request
        val reference = sealed.reference
        val relayAttachment = RelayAttachment(
            byteLength = request.byteLength,
            ciphertext = request.ciphertext,
            createdAt = request.createdAt,
            id = request.id,
            iv = request.iv,
            senderId = requireNotNull(request.senderId),
            sha256 = request.sha256,
            threadId = requireNotNull(request.threadId),
        )

        val opened = AttachmentCrypto.openAttachment(relayAttachment, reference)
        assertArrayEquals(plaintext, opened)

        val tamperedCiphertext = Base64.decode(relayAttachment.ciphertext, Base64.NO_WRAP).also { bytes ->
            bytes[0] = (bytes[0].toInt() xor 0x01).toByte()
        }
        val tampered = relayAttachment.copy(
            ciphertext = Base64.encodeToString(tamperedCiphertext, Base64.NO_WRAP),
        )
        val tamperError = runCatching {
            AttachmentCrypto.openAttachment(tampered, reference)
        }.exceptionOrNull()
        assertNotNull(tamperError)
    }

    @Test
    fun recoveryArchiveExportImportRoundTripPreservesSnapshot() {
        val recovery = RecoveryKeyManager.create()
        val identity = LocalIdentity(
            id = "user-a",
            username = "alice",
            displayName = "Alice",
            createdAt = "2026-04-21T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-a",
            recoveryFingerprint = recovery.fingerprint,
            recoveryPublicJwk = recovery.publicJwk,
            signingPublicJwk = Jwk(x = "sx", y = "sy"),
            encryptionPublicJwk = Jwk(x = "ex", y = "ey"),
            prekeyCreatedAt = "2026-04-21T00:00:00Z",
            prekeyFingerprint = "prekey-fp-a",
            prekeyPublicJwk = Jwk(x = "px", y = "py"),
            prekeySignature = "prekey-signature-a",
            standardsSignalReady = false,
            standardsMlsReady = false,
        )
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryRepresentation = recovery.recoveryRepresentation,
        )

        val exported = RecoveryArchiveManager.exportAndroidTransferArchive(record, "correct horse battery staple")
        val imported = RecoveryArchiveManager.importArchive(exported, "correct horse battery staple")

        when (imported) {
            is com.notrus.android.model.ImportedRecoveryPayload.Transfer -> {
                assertEquals("android", imported.sourcePlatform)
                assertEquals("recovery-authorized-reset", imported.transferMode)
                assertEquals(identity.id, imported.identity.id)
                assertEquals(identity.username, imported.identity.username)
                assertEquals(identity.displayName, imported.identity.displayName)
                assertEquals(identity.recoveryFingerprint, imported.identity.recoveryFingerprint)
                assertEquals(identity.recoveryPublicJwk, imported.identity.recoveryPublicJwk)
                assertEquals(recovery.recoveryRepresentation, imported.identity.recoveryRepresentation)
            }
            is com.notrus.android.model.ImportedRecoveryPayload.Portable ->
                error("Expected Android transfer archive to import as transfer payload.")
        }
    }

    @Test
    fun recoveryArchiveRejectsWrongPassphrase() {
        val recovery = RecoveryKeyManager.create()
        val identity = LocalIdentity(
            id = "user-b",
            username = "bob",
            displayName = "Bob",
            createdAt = "2026-04-21T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-b",
            recoveryFingerprint = recovery.fingerprint,
            recoveryPublicJwk = recovery.publicJwk,
            signingPublicJwk = Jwk(x = "sx2", y = "sy2"),
            encryptionPublicJwk = Jwk(x = "ex2", y = "ey2"),
            prekeyCreatedAt = "2026-04-21T00:00:00Z",
            prekeyFingerprint = "prekey-fp-b",
            prekeyPublicJwk = Jwk(x = "px2", y = "py2"),
            prekeySignature = "prekey-signature-b",
            standardsSignalReady = false,
            standardsMlsReady = false,
        )
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryRepresentation = recovery.recoveryRepresentation,
        )
        val exported = RecoveryArchiveManager.exportAndroidTransferArchive(record, "valid-passphrase")

        val error = runCatching {
            RecoveryArchiveManager.importArchive(exported, "wrong-passphrase")
        }.exceptionOrNull()
        assertNotNull(error)
    }

    @Test
    fun chatBackupRoundTripsThreadRecordsSeparatelyFromRecovery() {
        val recovery = RecoveryKeyManager.create()
        val identity = LocalIdentity(
            id = "user-history",
            username = "history",
            displayName = "History",
            createdAt = "2026-04-21T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-history",
            recoveryFingerprint = recovery.fingerprint,
            recoveryPublicJwk = recovery.publicJwk,
            signingPublicJwk = Jwk(x = "sx3", y = "sy3"),
            encryptionPublicJwk = Jwk(x = "ex3", y = "ey3"),
            prekeyCreatedAt = "2026-04-21T00:00:00Z",
            prekeyFingerprint = "prekey-fp-history",
            prekeyPublicJwk = Jwk(x = "px3", y = "py3"),
            prekeySignature = "prekey-signature-history",
            standardsSignalReady = true,
            standardsMlsReady = false,
            standardsSignalBundle = PublicSignalBundle(
                deviceId = 7,
                identityKey = "identity-key-history",
                kyberPreKeyId = 8,
                kyberPreKeyPublic = "kyber-public-history",
                kyberPreKeySignature = "kyber-signature-history",
                preKeyId = 9,
                preKeyPublic = "prekey-public-history",
                registrationId = 10,
                signedPreKeyId = 11,
                signedPreKeyPublic = "signed-prekey-public-history",
                signedPreKeySignature = "signed-prekey-signature-history",
            ),
            standardsSignalState = SignalProtocolState(
                deviceId = 7,
                identityKeyPair = "identity-keypair-history",
                knownIdentities = mapOf("peer" to "peer-identity"),
                kyberPreKeyId = 8,
                kyberPreKeyRecord = "kyber-record-history",
                preKeyId = 9,
                preKeyRecord = "prekey-record-history",
                registrationId = 10,
                senderKeys = mapOf("group" to "sender-key"),
                sessions = mapOf("peer" to "session-state"),
                signedPreKeyId = 11,
                signedPreKeyRecord = "signed-prekey-record-history",
            ),
        )
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryRepresentation = recovery.recoveryRepresentation,
            threadRecords = mapOf(
                "thread-1" to ConversationThreadRecord(
                    lastProcessedMessageId = "message-1",
                    messageCache = mapOf(
                        "message-1" to CachedMessageState(
                            attachments = listOf(
                                SecureAttachmentReference(
                                    attachmentKey = "attachment-key",
                                    byteLength = 42,
                                    fileName = "note.txt",
                                    id = "attachment-1",
                                    mediaType = "text/plain",
                                    sha256 = "sha",
                                )
                            ),
                            body = "restored",
                            relayCreatedAt = "2026-04-21T00:00:01Z",
                            relayMessageKind = "signal-msg",
                            relayProtocol = "signal-pqxdh-double-ratchet-v1",
                            relaySenderId = "peer",
                            relayThreadId = "thread-1",
                            relayWireMessage = "ciphertext-wire",
                            status = "ok",
                        )
                    ),
                    processedMessageCount = 1,
                    protocol = "signal-pqxdh-double-ratchet-v1",
                    signalPeerUserId = "peer",
                )
            ),
        )

        val exported = RecoveryArchiveManager.exportChatBackup(record, "correct horse battery staple")
        val imported = RecoveryArchiveManager.importChatBackup(exported, "correct horse battery staple")

        assertEquals("notrus-chat-history-v1", imported.backupKind)
        assertEquals(identity.id, imported.identity.id)
        assertEquals("restored", imported.threadRecords["thread-1"]?.messageCache?.get("message-1")?.body)
        assertEquals(
            "note.txt",
            imported.threadRecords["thread-1"]?.messageCache?.get("message-1")?.attachments?.firstOrNull()?.fileName,
        )
        assertEquals(
            "ciphertext-wire",
            imported.threadRecords["thread-1"]?.messageCache?.get("message-1")?.relayWireMessage,
        )
        assertEquals("peer", imported.threadRecords["thread-1"]?.messageCache?.get("message-1")?.relaySenderId)
        assertEquals(identity.standardsSignalBundle, imported.identity.standardsSignalBundle)
        assertEquals(identity.standardsSignalState, imported.identity.standardsSignalState)
    }

    @Test
    fun recoveryAndChatBackupImportsRejectEmptyFiles() {
        val recoveryError = runCatching {
            RecoveryArchiveManager.importArchive(ByteArray(0), "correct horse battery staple")
        }.exceptionOrNull()
        val chatError = runCatching {
            RecoveryArchiveManager.importChatBackup(ByteArray(0), "correct horse battery staple")
        }.exceptionOrNull()

        assertNotNull(recoveryError)
        assertNotNull(chatError)
        assertTrue(recoveryError?.message?.contains("empty") == true)
        assertTrue(chatError?.message?.contains("empty") == true)
    }

    @Test
    fun accountRecoveryImportRejectsChatBackupArchive() {
        val recovery = RecoveryKeyManager.create()
        val identity = LocalIdentity(
            id = "user-split",
            username = "split",
            displayName = "Split",
            createdAt = "2026-04-21T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-split",
            recoveryFingerprint = recovery.fingerprint,
            recoveryPublicJwk = recovery.publicJwk,
            signingPublicJwk = Jwk(x = "sx4", y = "sy4"),
            encryptionPublicJwk = Jwk(x = "ex4", y = "ey4"),
            prekeyCreatedAt = "2026-04-21T00:00:00Z",
            prekeyFingerprint = "prekey-fp-split",
            prekeyPublicJwk = Jwk(x = "px4", y = "py4"),
            prekeySignature = "prekey-signature-split",
            standardsSignalReady = false,
            standardsMlsReady = false,
        )
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryRepresentation = recovery.recoveryRepresentation,
        )
        val exported = RecoveryArchiveManager.exportChatBackup(record, "correct horse battery staple")

        val error = runCatching {
            RecoveryArchiveManager.importArchive(exported, "correct horse battery staple")
        }.exceptionOrNull()

        assertNotNull(error)
        assertTrue(error?.message?.contains("encrypted chat backup") == true)
    }

    @Test
    fun relayEnvelopePersistenceDoesNotReplaceReadableMessageCache() {
        val readable = CachedMessageState(
            body = "already readable",
            status = "ok",
        )
        val relayMessage = RelayMessage(
            createdAt = "2026-04-21T00:00:02Z",
            id = "message-readable",
            messageKind = "signal-msg",
            protocol = "signal-pqxdh-double-ratchet-v1",
            senderId = "peer",
            threadId = "thread-readable",
            wireMessage = "new-ciphertext",
        )

        val merged = MessageCachePolicy.mergeRelayEnvelope(readable, relayMessage)

        assertEquals("already readable", merged.body)
        assertEquals("ok", merged.status)
        assertEquals("new-ciphertext", merged.relayWireMessage)
        assertTrue(MessageCachePolicy.canSkipLocalDecrypt(merged))
    }

    @Test
    fun ciphertextOnlyBackgroundCacheMustBeDecryptedLater() {
        val relayMessage = RelayMessage(
            createdAt = "2026-04-21T00:00:03Z",
            id = "message-background",
            messageKind = "signal-msg",
            protocol = "signal-pqxdh-double-ratchet-v1",
            senderId = "peer",
            threadId = "thread-background",
            wireMessage = "background-ciphertext",
        )

        val cached = MessageCachePolicy.mergeRelayEnvelope(null, relayMessage)

        assertEquals(MessageCachePolicy.STATUS_CIPHERTEXT_STORED, cached.status)
        assertEquals("background-ciphertext", cached.relayWireMessage)
        assertTrue(!MessageCachePolicy.canSkipLocalDecrypt(cached))
    }

    @Test
    fun syncMergeDoesNotDowngradeReadableLocalMessages() {
        val existing = ConversationThreadRecord(
            lastProcessedMessageId = "message-sync",
            messageCache = mapOf(
                "message-sync" to CachedMessageState(
                    body = "readable before sync",
                    status = "ok",
                ),
            ),
            processedMessageCount = 1,
            protocol = "signal-pqxdh-double-ratchet-v1",
            signalPeerUserId = "peer",
        )
        val incoming = existing.copy(
            messageCache = mapOf(
                "message-sync" to CachedMessageState(
                    body = "This secure message could not be opened with the current local session history.",
                    relayWireMessage = "new-wire-envelope",
                    status = "invalid",
                ),
            ),
        )

        val merged = MessageCachePolicy.mergeThreadCaches(existing, incoming)
        val cached = requireNotNull(merged.messageCache["message-sync"])

        assertEquals("readable before sync", cached.body)
        assertEquals("ok", cached.status)
        assertEquals("new-wire-envelope", cached.relayWireMessage)
        assertTrue(MessageCachePolicy.canSkipLocalDecrypt(cached))
    }

    @Test
    fun recoveryAuthorityRebuildFromRepresentationMatchesGeneratedMaterial() {
        val created = RecoveryKeyManager.create()
        val rebuilt = RecoveryKeyManager.recoveryAuthorityFromRepresentation(created.recoveryRepresentation)
        assertEquals(created.fingerprint, rebuilt.fingerprint)
        assertEquals(created.publicJwk, rebuilt.publicJwk)
        assertTrue(rebuilt.fingerprint.isNotBlank())
    }
}
