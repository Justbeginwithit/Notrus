package com.notrus.android.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
}
