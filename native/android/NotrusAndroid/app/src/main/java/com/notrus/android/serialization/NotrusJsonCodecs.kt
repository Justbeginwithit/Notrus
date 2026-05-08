package com.notrus.android.serialization

import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.Jwk
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.SecureAttachmentReference
import com.notrus.android.model.SignalProtocolState
import org.json.JSONArray
import org.json.JSONObject

internal object NotrusJsonCodecs {
    const val SignalDirectProtocol = "signal-pqxdh-double-ratchet-v1"
    const val MessageStatusOk = "ok"

    fun jwkToJson(jwk: Jwk): JSONObject =
        JSONObject()
            .put("crv", jwk.crv)
            .put("kty", jwk.kty)
            .put("x", jwk.x)
            .put("y", jwk.y)

    fun jsonToJwk(json: JSONObject): Jwk =
        Jwk(
            crv = json.optString("crv", "P-256"),
            kty = json.optString("kty", "EC"),
            x = json.optString("x"),
            y = json.optString("y"),
        )

    fun signalBundleToJson(bundle: PublicSignalBundle): JSONObject =
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

    fun jsonToSignalBundle(json: JSONObject): PublicSignalBundle =
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

    fun signalStateToJson(state: SignalProtocolState): JSONObject =
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

    fun jsonToSignalState(json: JSONObject): SignalProtocolState =
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

    fun threadRecordToJson(record: ConversationThreadRecord): JSONObject =
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

    fun jsonToThreadRecord(
        json: JSONObject,
        legacyPeerKey: String? = null,
    ): ConversationThreadRecord {
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
            protocol = json.optString("protocol", SignalDirectProtocol),
            signalPeerUserId = json.optString("signalPeerUserId").ifBlank {
                legacyPeerKey?.let { json.optString(it).ifBlank { null } }
            },
        )
    }

    fun cachedMessageToJson(message: CachedMessageState): JSONObject =
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
            .put("attachments", JSONArray().apply {
                message.attachments.forEach { put(attachmentReferenceToJson(it)) }
            })

    fun jsonToCachedMessage(json: JSONObject): CachedMessageState {
        val attachments = mutableListOf<SecureAttachmentReference>()
        val attachmentsJson = json.optJSONArray("attachments") ?: JSONArray()
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
            status = json.optString("status", MessageStatusOk),
        )
    }

    fun attachmentReferenceToJson(reference: SecureAttachmentReference): JSONObject =
        JSONObject()
            .put("attachmentKey", reference.attachmentKey)
            .put("byteLength", reference.byteLength)
            .put("fileName", reference.fileName)
            .put("id", reference.id)
            .put("mediaType", reference.mediaType)
            .put("sha256", reference.sha256)

    fun jsonToAttachmentReference(json: JSONObject): SecureAttachmentReference =
        SecureAttachmentReference(
            attachmentKey = json.optString("attachmentKey"),
            byteLength = json.optInt("byteLength", 0),
            fileName = json.optString("fileName"),
            id = json.optString("id"),
            mediaType = json.optString("mediaType"),
            sha256 = json.optString("sha256"),
        )

    fun jsonInt32(json: JSONObject, key: String, defaultValue: Int): Int {
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

    fun jsonObjectToMap(json: JSONObject?): Map<String, String> {
        val source = json ?: return emptyMap()
        val result = linkedMapOf<String, String>()
        val keys = source.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            result[key] = source.optString(key)
        }
        return result
    }
}
