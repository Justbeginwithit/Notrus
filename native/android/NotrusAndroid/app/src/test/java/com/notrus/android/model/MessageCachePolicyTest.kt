package com.notrus.android.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageCachePolicyTest {
    @Test
    fun mergeThreadCachesAllowsArchiveRestoreToClearHiddenState() {
        val existing = ConversationThreadRecord(
            hiddenAt = "2026-04-29T20:00:00Z",
            mutedAt = "2026-04-29T20:00:01Z",
            messageCache = mapOf(
                "old" to CachedMessageState(body = "kept locally"),
            ),
            protocol = "signal-direct-v1",
            signalPeerUserId = "remote-user",
        )
        val incoming = existing.copy(
            hiddenAt = null,
            mutedAt = null,
            messageCache = mapOf(
                "new" to CachedMessageState(body = "synced later"),
            ),
        )

        val merged = MessageCachePolicy.mergeThreadCaches(existing, incoming)

        assertNull(merged.hiddenAt)
        assertNull(merged.mutedAt)
        assertEquals(setOf("old", "new"), merged.messageCache.keys)
    }

    @Test
    fun archivedThreadIsNotLocallyDeleted() {
        val record = ConversationThreadRecord(
            hiddenAt = "2026-05-05T10:00:00Z",
            protocol = "signal-pqxdh-double-ratchet-v1",
        )

        assertTrue(MessageCachePolicy.isArchived(record))
        assertFalse(MessageCachePolicy.isLocallyDeleted(record))
    }

    @Test
    fun purgedThreadIsDeletedNotArchived() {
        val record = ConversationThreadRecord(
            hiddenAt = "2026-05-05T10:00:00Z",
            purgedAt = "2026-05-05T10:01:00Z",
            protocol = "signal-pqxdh-double-ratchet-v1",
        )

        assertFalse(MessageCachePolicy.isArchived(record))
        assertTrue(MessageCachePolicy.isLocallyDeleted(record))
    }

    @Test
    fun unarchivedThreadStaysActive() {
        val record = ConversationThreadRecord(
            hiddenAt = null,
            purgedAt = null,
            protocol = "signal-pqxdh-double-ratchet-v1",
        )

        assertFalse(MessageCachePolicy.isArchived(record))
        assertFalse(MessageCachePolicy.isLocallyDeleted(record))
    }

    @Test
    fun attachmentOnlyMessagesAreReusableLocalPlaintext() {
        val cached = CachedMessageState(
            attachments = listOf(
                SecureAttachmentReference(
                    attachmentKey = "key",
                    byteLength = 12,
                    fileName = "photo.jpg",
                    id = "att-1",
                    mediaType = "image/jpeg",
                    sha256 = "sha",
                ),
            ),
            body = "",
            status = "ok",
        )

        assertTrue(MessageCachePolicy.canSkipLocalDecrypt(cached))
    }

    @Test
    fun attachmentOnlyCacheBeatsLaterReplayFailure() {
        val cached = CachedMessageState(
            attachments = listOf(
                SecureAttachmentReference(
                    attachmentKey = "key",
                    byteLength = 12,
                    fileName = "photo.jpg",
                    id = "att-1",
                    mediaType = "image/jpeg",
                    sha256 = "sha",
                ),
            ),
            body = "",
            status = "ok",
        )
        val replayFailure = CachedMessageState(
            body = "Unable to decrypt the Signal message: message with old counter 3 / 2",
            status = "invalid",
        )

        val merged = MessageCachePolicy.mergeCachedStates(cached, replayFailure)

        assertEquals("ok", merged.status)
        assertEquals(1, merged.attachments.size)
        assertEquals("", merged.body)
    }
}
