package com.notrus.android.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.IdentityCatalog
import com.notrus.android.model.Jwk
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.RelayUser
import com.notrus.android.model.SecureAttachmentReference
import com.notrus.android.model.SignalProtocolState
import com.notrus.android.model.StoredIdentityRecord
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class VaultStore(context: Context) {
    private val preferences = context.getSharedPreferences("notrus_vault", Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun hasCatalog(): Boolean = preferences.contains(KEY_CATALOG)

    fun loadCatalog(): IdentityCatalog {
        val payload = preferences.getString(KEY_CATALOG, null) ?: return IdentityCatalog()
        return runCatching {
            val decrypted = decrypt(payload)
            jsonToCatalog(JSONObject(decrypted))
        }.getOrElse {
            IdentityCatalog()
        }
    }

    fun saveCatalog(catalog: IdentityCatalog) {
        val serialized = catalogToJson(catalog).toString()
        preferences.edit().putString(KEY_CATALOG, encrypt(serialized)).apply()
    }

    fun inventorySnapshot(): VaultInventorySnapshot =
        VaultInventorySnapshot(
            catalogPresent = hasCatalog(),
            masterKeyAlias = KEY_ALIAS,
            masterKeyAliasPresent = keyStore.containsAlias(KEY_ALIAS),
        )

    private fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        val iv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
        val body = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
        return JSONObject()
            .put("iv", iv)
            .put("ciphertext", body)
            .toString()
    }

    private fun decrypt(envelope: String): String {
        val json = JSONObject(envelope)
        val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8)
    }

    private fun masterKey(): SecretKey {
        val existing = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    private fun catalogToJson(catalog: IdentityCatalog): JSONObject {
        val identities = JSONArray()
        catalog.identities.forEach { record ->
            identities.put(
                JSONObject()
                    .put("recoveryRepresentation", record.recoveryRepresentation)
                    .put("identity", identityToJson(record.identity))
                    .put("savedContacts", JSONArray().apply {
                        record.savedContacts.forEach { put(relayUserToJson(it)) }
                    })
                    .put("threadRecords", JSONObject().apply {
                        record.threadRecords.forEach { (threadId, threadRecord) ->
                            put(threadId, threadRecordToJson(threadRecord))
                        }
                    })
            )
        }

        return JSONObject()
            .put("version", catalog.version)
            .put("activeIdentityId", catalog.activeIdentityId)
            .put("identities", identities)
    }

    private fun jsonToCatalog(json: JSONObject): IdentityCatalog {
        val identities = mutableListOf<StoredIdentityRecord>()
        val records = json.optJSONArray("identities") ?: JSONArray()
        for (index in 0 until records.length()) {
            val entry = records.optJSONObject(index) ?: continue
            val identityJson = entry.optJSONObject("identity") ?: continue
            val savedContacts = mutableListOf<RelayUser>()
            val savedContactsJson = entry.optJSONArray("savedContacts") ?: JSONArray()
            for (contactIndex in 0 until savedContactsJson.length()) {
                savedContactsJson.optJSONObject(contactIndex)?.let { savedContacts += jsonToRelayUser(it) }
            }
            val threadRecords = linkedMapOf<String, ConversationThreadRecord>()
            val threadRecordsJson = entry.optJSONObject("threadRecords") ?: JSONObject()
            val keys = threadRecordsJson.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                threadRecordsJson.optJSONObject(key)?.let { threadRecords[key] = jsonToThreadRecord(it) }
            }
            identities += StoredIdentityRecord(
                identity = jsonToIdentity(identityJson),
                recoveryRepresentation = entry.optString("recoveryRepresentation").ifBlank {
                    RecoveryKeyManager.recoveryRepresentationFromPkcs8(entry.optString("recoveryPrivateKeyPkcs8"))
                },
                savedContacts = savedContacts,
                threadRecords = threadRecords,
            )
        }
        return IdentityCatalog(
            version = json.optInt("version", 2),
            activeIdentityId = json.optString("activeIdentityId").ifBlank { null },
            identities = identities,
        )
    }

    private fun identityToJson(identity: LocalIdentity): JSONObject =
        JSONObject()
            .put("id", identity.id)
            .put("username", identity.username)
            .put("displayName", identity.displayName)
            .put("createdAt", identity.createdAt)
            .put("directoryCode", identity.directoryCode)
            .put("storageMode", identity.storageMode)
            .put("fingerprint", identity.fingerprint)
            .put("recoveryFingerprint", identity.recoveryFingerprint)
            .put("recoveryPublicJwk", jwkToJson(identity.recoveryPublicJwk))
            .put("signingPublicJwk", jwkToJson(identity.signingPublicJwk))
            .put("encryptionPublicJwk", jwkToJson(identity.encryptionPublicJwk))
            .put("prekeyCreatedAt", identity.prekeyCreatedAt)
            .put("prekeyFingerprint", identity.prekeyFingerprint)
            .put("prekeyPublicJwk", jwkToJson(identity.prekeyPublicJwk))
            .put("prekeySignature", identity.prekeySignature)
            .put("standardsSignalReady", identity.standardsSignalReady)
            .put("standardsMlsReady", identity.standardsMlsReady)
            .put("standardsSignalBundle", identity.standardsSignalBundle?.let(::signalBundleToJson))
            .put("standardsSignalState", identity.standardsSignalState?.let(::signalStateToJson))

    private fun jsonToIdentity(json: JSONObject): LocalIdentity =
        LocalIdentity(
            id = json.optString("id"),
            username = json.optString("username"),
            displayName = json.optString("displayName"),
            createdAt = json.optString("createdAt"),
            directoryCode = json.optString("directoryCode").ifBlank { null },
            storageMode = json.optString("storageMode").ifBlank { "android-keystore" },
            fingerprint = json.optString("fingerprint"),
            recoveryFingerprint = json.optString("recoveryFingerprint"),
            recoveryPublicJwk = jsonToJwk(json.optJSONObject("recoveryPublicJwk") ?: JSONObject()),
            signingPublicJwk = jsonToJwk(json.optJSONObject("signingPublicJwk") ?: JSONObject()),
            encryptionPublicJwk = jsonToJwk(json.optJSONObject("encryptionPublicJwk") ?: JSONObject()),
            prekeyCreatedAt = json.optString("prekeyCreatedAt"),
            prekeyFingerprint = json.optString("prekeyFingerprint"),
            prekeyPublicJwk = jsonToJwk(json.optJSONObject("prekeyPublicJwk") ?: JSONObject()),
            prekeySignature = json.optString("prekeySignature"),
            standardsSignalReady = json.optBoolean("standardsSignalReady", false),
            standardsMlsReady = json.optBoolean("standardsMlsReady", false),
            standardsSignalBundle = json.optJSONObject("standardsSignalBundle")?.let(::jsonToSignalBundle),
            standardsSignalState = json.optJSONObject("standardsSignalState")?.let(::jsonToSignalState),
        )

    private fun relayUserToJson(user: RelayUser): JSONObject =
        JSONObject()
            .put("id", user.id)
            .put("username", user.username)
            .put("displayName", user.displayName)
            .put("fingerprint", user.fingerprint)
            .put("createdAt", user.createdAt)
            .put("signingPublicJwk", user.signingPublicJwk?.let(::jwkToJson))
            .put("encryptionPublicJwk", user.encryptionPublicJwk?.let(::jwkToJson))
            .put("signalBundle", user.signalBundle?.let(::signalBundleToJson))

    private fun jsonToRelayUser(json: JSONObject): RelayUser =
        RelayUser(
            id = json.optString("id"),
            username = json.optString("username"),
            displayName = json.optString("displayName"),
            directoryCode = json.optString("directoryCode").ifBlank { null },
            fingerprint = json.optString("fingerprint"),
            createdAt = json.optString("createdAt"),
            updatedAt = json.optString("updatedAt").ifBlank { null },
            signingPublicJwk = json.optJSONObject("signingPublicJwk")?.let(::jsonToJwk),
            encryptionPublicJwk = json.optJSONObject("encryptionPublicJwk")?.let(::jsonToJwk),
            signalBundle = json.optJSONObject("signalBundle")?.let(::jsonToSignalBundle),
        )

    private fun threadRecordToJson(record: ConversationThreadRecord): JSONObject =
        JSONObject()
            .put("hiddenAt", record.hiddenAt)
            .put("localTitle", record.localTitle)
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
            val key = keys.next()
            messageCacheJson.optJSONObject(key)?.let { messageCache[key] = jsonToCachedMessage(it) }
        }
        return ConversationThreadRecord(
            hiddenAt = json.optString("hiddenAt").ifBlank { null },
            localTitle = json.optString("localTitle").ifBlank { null },
            lastProcessedMessageId = json.optString("lastProcessedMessageId").ifBlank { null },
            messageCache = messageCache,
            processedMessageCount = json.optInt("processedMessageCount", 0),
            protocol = json.optString("protocol", "signal-pqxdh-double-ratchet-v1"),
            signalPeerUserId = json.optString("signalPeerUserId").ifBlank { null },
        )
    }

    private fun cachedMessageToJson(message: CachedMessageState): JSONObject =
        JSONObject()
            .put("body", message.body)
            .put("hidden", message.hidden)
            .put("status", message.status)
            .put("attachments", JSONArray().apply {
                message.attachments.forEach { put(attachmentReferenceToJson(it)) }
            })

    private fun jsonToCachedMessage(json: JSONObject): CachedMessageState {
        val attachments = mutableListOf<SecureAttachmentReference>()
        val attachmentsJson = json.optJSONArray("attachments") ?: JSONArray()
        for (index in 0 until attachmentsJson.length()) {
            attachmentsJson.optJSONObject(index)?.let { attachments += jsonToAttachmentReference(it) }
        }
        return CachedMessageState(
            attachments = attachments,
            body = json.optString("body"),
            hidden = json.optBoolean("hidden", false),
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

    private fun jsonObjectToMap(json: JSONObject?): Map<String, String> {
        if (json == null) {
            return emptyMap()
        }
        val values = linkedMapOf<String, String>()
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            values[key] = json.optString(key)
        }
        return values
    }

    companion object {
        private const val KEY_ALIAS = "notrus.vault.master"
        private const val KEY_CATALOG = "catalog"
    }
}

data class VaultInventorySnapshot(
    val catalogPresent: Boolean,
    val masterKeyAlias: String,
    val masterKeyAliasPresent: Boolean,
)
