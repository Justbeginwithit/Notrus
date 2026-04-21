package com.notrus.android.security

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.notrus.android.model.Jwk
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.RelayAttachment
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
    fun recoveryAuthorityRebuildFromRepresentationMatchesGeneratedMaterial() {
        val created = RecoveryKeyManager.create()
        val rebuilt = RecoveryKeyManager.recoveryAuthorityFromRepresentation(created.recoveryRepresentation)
        assertEquals(created.fingerprint, rebuilt.fingerprint)
        assertEquals(created.publicJwk, rebuilt.publicJwk)
        assertTrue(rebuilt.fingerprint.isNotBlank())
    }
}
