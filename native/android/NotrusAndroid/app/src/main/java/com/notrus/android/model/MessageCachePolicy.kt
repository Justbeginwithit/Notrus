package com.notrus.android.model

object MessageCachePolicy {
    const val STATUS_CIPHERTEXT_STORED = "ciphertext-stored"

    fun canSkipLocalDecrypt(cached: CachedMessageState?): Boolean =
        localStateQuality(cached) >= 2

    fun attachRelayEnvelope(
        cached: CachedMessageState,
        message: RelayMessage,
    ): CachedMessageState =
        mergeCachedStates(
            existing = cached,
            incoming = relayEnvelopeOnly(message),
        )

    fun mergeRelayEnvelope(
        existing: CachedMessageState?,
        message: RelayMessage,
    ): CachedMessageState =
        mergeCachedStates(
            existing = existing,
            incoming = relayEnvelopeOnly(message),
        )

    fun mergeCachedStates(
        existing: CachedMessageState?,
        incoming: CachedMessageState?,
    ): CachedMessageState {
        if (existing == null) {
            return incoming ?: CachedMessageState(body = "", status = STATUS_CIPHERTEXT_STORED)
        }
        if (incoming == null) {
            return existing
        }
        val preferred = if (localStateQuality(incoming) >= localStateQuality(existing)) {
            incoming
        } else {
            existing
        }
        return preferred.copy(
            relayCounter = incoming.relayCounter ?: existing.relayCounter,
            relayCreatedAt = incoming.relayCreatedAt ?: existing.relayCreatedAt,
            relayEpoch = incoming.relayEpoch ?: existing.relayEpoch,
            relayMessageKind = incoming.relayMessageKind ?: existing.relayMessageKind,
            relayProtocol = incoming.relayProtocol ?: existing.relayProtocol,
            relaySenderId = incoming.relaySenderId ?: existing.relaySenderId,
            relayThreadId = incoming.relayThreadId ?: existing.relayThreadId,
            relayWireMessage = incoming.relayWireMessage ?: existing.relayWireMessage,
        )
    }

    fun mergeThreadCaches(
        existing: ConversationThreadRecord?,
        incoming: ConversationThreadRecord,
    ): ConversationThreadRecord {
        if (existing == null) {
            return incoming
        }
        val mergedCache = linkedMapOf<String, CachedMessageState>()
        existing.messageCache.forEach { (messageId, cached) ->
            mergedCache[messageId] = cached
        }
        incoming.messageCache.forEach { (messageId, cached) ->
            mergedCache[messageId] = mergeCachedStates(mergedCache[messageId], cached)
        }
        return incoming.copy(
            hiddenAt = incoming.hiddenAt,
            localTitle = incoming.localTitle ?: existing.localTitle,
            mutedAt = incoming.mutedAt,
            messageCache = mergedCache,
            purgedAt = incoming.purgedAt,
        )
    }

    private fun relayEnvelopeOnly(message: RelayMessage): CachedMessageState =
        CachedMessageState(
            body = "",
            relayCounter = message.counter,
            relayCreatedAt = message.createdAt.trim().takeIf(String::isNotBlank),
            relayEpoch = message.epoch,
            relayMessageKind = message.messageKind?.trim()?.takeIf(String::isNotBlank),
            relayProtocol = message.protocol?.trim()?.takeIf(String::isNotBlank),
            relaySenderId = message.senderId.trim().takeIf(String::isNotBlank),
            relayThreadId = message.threadId?.trim()?.takeIf(String::isNotBlank),
            relayWireMessage = message.wireMessage?.trim()?.takeIf(String::isNotBlank),
            status = STATUS_CIPHERTEXT_STORED,
        )

    private fun localStateQuality(cached: CachedMessageState?): Int {
        if (cached == null) {
            return -1
        }
        if (cached.hidden) {
            return 3
        }
        if (cached.status == "ok" && cached.body.isNotBlank()) {
            return 3
        }
        if (cached.status == "missing-local-state" && cached.body.isNotBlank()) {
            return 2
        }
        if (cached.status != STATUS_CIPHERTEXT_STORED && cached.body.isNotBlank()) {
            return 1
        }
        return 0
    }
}
