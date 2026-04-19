package com.notrus.android.relay

import android.util.Base64
import com.notrus.android.model.AccountResetRequest
import com.notrus.android.model.AccountResetResponse
import com.notrus.android.model.AccountDeleteResponse
import com.notrus.android.model.ClientIntegrityReport
import com.notrus.android.model.DeviceDescriptor
import com.notrus.android.model.DeviceRevokeResponse
import com.notrus.android.model.Jwk
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.PublicMlsKeyPackage
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.RelayAbuseControls
import com.notrus.android.model.RelayDeviceEvent
import com.notrus.android.model.RelayHealth
import com.notrus.android.model.RelayLinkedDevice
import com.notrus.android.model.RelayMessage
import com.notrus.android.model.RelaySecurityDevicesResponse
import com.notrus.android.model.RelaySession
import com.notrus.android.model.RelaySyncPayload
import com.notrus.android.model.RelayThread
import com.notrus.android.model.RelayTransparencySnapshot
import com.notrus.android.model.RelayUser
import com.notrus.android.model.RegisterResponse
import com.notrus.android.model.TransparencyEntry
import com.notrus.android.model.TransparencySignerInfo
import com.notrus.android.model.WitnessObservation
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

class RelayClient(
    private val origin: String,
    private val integrityReport: ClientIntegrityReport? = null,
    private val appInstanceId: String? = null,
    private val deviceDescriptor: DeviceDescriptor? = null,
    private val sessionToken: String? = null,
) {
    suspend fun health(): RelayHealth = withContext(Dispatchers.IO) {
        val json = request("/api/health")
        RelayHealth(
            ok = json.optBoolean("ok", false),
            abuseControls = RelayAbuseControls(
                powDifficultyBits = json.optJSONObject("abuseControls")?.optInt("powDifficultyBits"),
                powRequiredForRemoteUntrustedClients = json.optJSONObject("abuseControls")?.optBoolean("powRequiredForRemoteUntrustedClients"),
            ),
            attestationConfigured = json.optJSONObject("attestation")?.optBoolean("configured"),
            attestationRequired = json.optJSONObject("attestation")?.optBoolean("required"),
            directoryDiscoveryMode = json.optString("directoryDiscoveryMode").ifBlank { null },
            protocolLabel = json.optJSONObject("protocolPolicy")?.optString("label", "Unknown") ?: "Unknown",
            protocolNote = json.optJSONObject("protocolPolicy")?.optString("note", "") ?: "",
            transparencySigner = parseTransparencySigner(json.optJSONObject("transparency")?.optJSONObject("signer")),
            transportLabel = json.optJSONObject("transport")?.optString("tls", "unknown") ?: "unknown",
            users = json.optInt("users", 0),
            threads = json.optInt("threads", 0),
        )
    }

    suspend fun register(identity: LocalIdentity): RegisterResponse = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("userId", identity.id)
            .put("username", identity.username)
            .put("displayName", identity.displayName)
            .put("createdAt", identity.createdAt)
            .put("fingerprint", identity.fingerprint)
            .put("recoveryFingerprint", identity.recoveryFingerprint)
            .put("recoveryPublicJwk", jwk(identity.recoveryPublicJwk))
            .put("signingPublicJwk", jwk(identity.signingPublicJwk))
            .put("encryptionPublicJwk", jwk(identity.encryptionPublicJwk))
            .put("prekeyCreatedAt", identity.prekeyCreatedAt)
            .put("prekeyFingerprint", identity.prekeyFingerprint)
            .put("prekeyPublicJwk", jwk(identity.prekeyPublicJwk))
            .put("prekeySignature", identity.prekeySignature)
            .put("signalBundle", identity.standardsSignalBundle?.let(::signalBundleJson))

        deviceDescriptor?.let { body.put("device", deviceJson(it)) }

        val response = request("/api/bootstrap/register", method = "POST", body = body, includeBootstrapHeaders = true)
        RegisterResponse(
            deviceEvents = parseDeviceEvents(response.optJSONArray("deviceEvents")),
            devices = parseDevices(response.optJSONArray("devices")),
            privacyMode = nullableString(response, "privacyMode"),
            session = parseSession(response.optJSONObject("session")),
            user = parseUser(response.optJSONObject("user") ?: JSONObject()),
        )
    }

    suspend fun resetAccount(request: AccountResetRequest): AccountResetResponse = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("createdAt", request.createdAt)
            .put("displayName", request.displayName)
            .put("encryptionPublicJwk", jwk(request.encryptionPublicJwk))
            .put("fingerprint", request.fingerprint)
            .put("mlsKeyPackage", request.mlsKeyPackage?.let(::mlsKeyPackageJson))
            .put("prekeyCreatedAt", request.prekeyCreatedAt)
            .put("prekeyFingerprint", request.prekeyFingerprint)
            .put("prekeyPublicJwk", jwk(request.prekeyPublicJwk))
            .put("prekeySignature", request.prekeySignature)
            .put("recoveryFingerprint", request.recoveryFingerprint)
            .put("recoveryPublicJwk", jwk(request.recoveryPublicJwk))
            .put("recoverySignature", request.recoverySignature)
            .put("signalBundle", request.signalBundle?.let(::signalBundleJson))
            .put("signingPublicJwk", jwk(request.signingPublicJwk))
            .put("userId", request.userId)
            .put("username", request.username)

        request.device?.let { body.put("device", deviceJson(it)) }

        val response = request("/api/bootstrap/account-reset", method = "POST", body = body, includeBootstrapHeaders = true)
        AccountResetResponse(
            deviceEvents = parseDeviceEvents(response.optJSONArray("deviceEvents")),
            devices = parseDevices(response.optJSONArray("devices")),
            ok = response.optBoolean("ok", false),
            privacyMode = nullableString(response, "privacyMode"),
            session = parseSession(response.optJSONObject("session")),
            user = parseUser(response.optJSONObject("user") ?: JSONObject()),
        )
    }

    suspend fun sync(): RelaySyncPayload = withContext(Dispatchers.IO) {
        val json = request("/api/sync/state", authorizationToken = requireSessionToken())
        RelaySyncPayload(
            directoryDiscoveryMode = json.optString("directoryDiscoveryMode").ifBlank { null },
            relayTime = json.optString("relayTime").ifBlank { null },
            users = parseUsers(json.optJSONArray("users")),
            threads = parseThreads(json.optJSONArray("threads")),
        )
    }

    suspend fun securityDevices(): RelaySecurityDevicesResponse = withContext(Dispatchers.IO) {
        val response = request("/api/security/devices", authorizationToken = requireSessionToken())
        RelaySecurityDevicesResponse(
            deviceEvents = parseDeviceEvents(response.optJSONArray("deviceEvents")),
            devices = parseDevices(response.optJSONArray("devices")),
        )
    }

    suspend fun transparency(): RelayTransparencySnapshot = withContext(Dispatchers.IO) {
        val response = request("/api/security/transparency", authorizationToken = requireSessionToken())
        RelayTransparencySnapshot(
            entryCount = response.takeIf { it.has("entryCount") }?.optInt("entryCount"),
            relayTime = nullableString(response, "relayTime"),
            transparencyEntries = parseTransparencyEntries(response.optJSONArray("transparencyEntries")),
            transparencyHead = nullableString(response, "transparencyHead"),
            transparencySignature = nullableString(response, "transparencySignature"),
            transparencySigner = parseTransparencySigner(response.optJSONObject("transparencySigner")),
        )
    }

    suspend fun searchDirectory(query: String): List<RelayUser> = withContext(Dispatchers.IO) {
        val encodedQuery = URLEncoder.encode(query.trim(), Charsets.UTF_8.name())
        val json = request("/api/directory/search?q=$encodedQuery", authorizationToken = requireSessionToken())
        parseUsers(json.optJSONArray("results"))
    }

    suspend fun createDirectThread(remoteContactHandle: String): String = withContext(Dispatchers.IO) {
        val response = request(
            "/api/routing/threads",
            method = "POST",
            authorizationToken = requireSessionToken(),
            body = JSONObject()
                .put("createdAt", Instant.now().toString())
                .put("id", UUID.randomUUID().toString().lowercase())
                .put("participantHandles", JSONArray().put(remoteContactHandle))
                .put("protocol", "signal-pqxdh-double-ratchet-v1")
                .put("title", "")
        )
        response.optString("threadId")
    }

    suspend fun postSignalMessage(
        mailboxHandle: String,
        deliveryCapability: String,
        messageKind: String,
        wireMessage: String,
    ): String = withContext(Dispatchers.IO) {
        val messageId = UUID.randomUUID().toString().lowercase()
        val response = request(
            "/api/mailboxes/$mailboxHandle/messages",
            method = "POST",
            authorizationToken = deliveryCapability,
            body = JSONObject()
                .put("createdAt", Instant.now().toString())
                .put("id", messageId)
                .put("messageKind", messageKind)
                .put("paddingBucket", nextTransportBucket(wireMessage.length))
                .put("protocol", "signal-pqxdh-double-ratchet-v1")
                .put("transportPadding", transportPadding(wireMessage.length))
                .put("wireMessage", wireMessage)
        )
        response.optString("messageId", messageId)
    }

    suspend fun revokeDevice(
        userId: String,
        signerDeviceId: String,
        targetDeviceId: String,
        createdAt: String,
        signature: String,
    ): DeviceRevokeResponse = withContext(Dispatchers.IO) {
        val response = request(
            "/api/devices/revoke",
            method = "POST",
            authorizationToken = requireSessionToken(),
            body = JSONObject()
                .put("createdAt", createdAt)
                .put("signature", signature)
                .put("signerDeviceId", signerDeviceId)
                .put("targetDeviceId", targetDeviceId)
                .put("userId", userId)
        )
        DeviceRevokeResponse(
            deviceEvents = parseDeviceEvents(response.optJSONArray("deviceEvents")),
            devices = parseDevices(response.optJSONArray("devices")),
            ok = response.optBoolean("ok", false),
            revokedDeviceId = response.optString("revokedDeviceId"),
        )
    }

    suspend fun deleteAccount(): AccountDeleteResponse = withContext(Dispatchers.IO) {
        val response = request(
            "/api/account/delete",
            method = "POST",
            authorizationToken = requireSessionToken(),
            body = JSONObject(),
        )
        AccountDeleteResponse(
            deletedAt = nullableString(response, "deletedAt"),
            deletedUsername = nullableString(response, "deletedUsername"),
            ok = response.optBoolean("ok", false),
            tombstoned = response.takeIf { it.has("tombstoned") }?.optBoolean("tombstoned"),
            tombstonedUsername = nullableString(response, "tombstonedUsername"),
            userId = response.optString("userId"),
        )
    }

    suspend fun fetchWitnessHead(witnessOrigin: String, relayOrigin: String): WitnessObservation? = withContext(Dispatchers.IO) {
        val encodedRelayOrigin = URLEncoder.encode(validateOrigin(relayOrigin), Charsets.UTF_8.name())
        val connection = URL("$witnessOrigin/api/witness/head?relayOrigin=$encodedRelayOrigin").openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.setRequestProperty("Accept", "application/json")
        val response = readResponse(connection)
        if (response.status !in 200..299) {
            return@withContext null
        }
        val latest = response.json.optJSONObject("latest") ?: return@withContext null
        WitnessObservation(
            entryCount = latest.takeIf { it.has("entryCount") }?.optInt("entryCount"),
            head = latest.optString("transparencyHead").ifBlank { null },
            observedAt = latest.optString("observedAt").ifBlank { null },
            origin = witnessOrigin.trimEnd('/'),
            status = "observed",
        )
    }

    private fun parseUsers(array: JSONArray?): List<RelayUser> {
        val users = mutableListOf<RelayUser>()
        val safeArray = array ?: JSONArray()
        for (index in 0 until safeArray.length()) {
            safeArray.optJSONObject(index)?.let { users += parseUser(it) }
        }
        return users
    }

    private fun parseUser(json: JSONObject): RelayUser =
        RelayUser(
            id = json.optString("id"),
            username = json.optString("username"),
            displayName = json.optString("displayName"),
            contactHandle = nullableString(json, "contactHandle"),
            contactHandleExpiresAt = nullableString(json, "contactHandleExpiresAt"),
            directoryCode = nullableString(json, "directoryCode"),
            fingerprint = json.optString("fingerprint"),
            createdAt = json.optString("createdAt"),
            updatedAt = nullableString(json, "updatedAt"),
            mlsKeyPackage = json.optJSONObject("mlsKeyPackage")?.let(::parseMlsKeyPackage),
            prekeyCreatedAt = nullableString(json, "prekeyCreatedAt"),
            prekeyFingerprint = nullableString(json, "prekeyFingerprint"),
            prekeyPublicJwk = json.optJSONObject("prekeyPublicJwk")?.let(::jsonJwk),
            prekeySignature = nullableString(json, "prekeySignature"),
            signingPublicJwk = json.optJSONObject("signingPublicJwk")?.let(::jsonJwk),
            encryptionPublicJwk = json.optJSONObject("encryptionPublicJwk")?.let(::jsonJwk),
            signalBundle = json.optJSONObject("signalBundle")?.let(::parseSignalBundle),
        )

    private fun parseThreads(array: JSONArray?): List<RelayThread> {
        val threads = mutableListOf<RelayThread>()
        val safeArray = array ?: JSONArray()
        for (index in 0 until safeArray.length()) {
            val json = safeArray.optJSONObject(index) ?: continue
            val participants = mutableListOf<String>()
            val participantArray = json.optJSONArray("participantIds") ?: JSONArray()
            for (participantIndex in 0 until participantArray.length()) {
                participantArray.optString(participantIndex).takeIf { it.isNotBlank() }?.let(participants::add)
            }

            val messages = mutableListOf<RelayMessage>()
            val messageArray = json.optJSONArray("messages") ?: JSONArray()
            for (messageIndex in 0 until messageArray.length()) {
                messageArray.optJSONObject(messageIndex)?.let { messageJson ->
                    messages += RelayMessage(
                        id = messageJson.optString("id"),
                        senderId = messageJson.optString("senderId"),
                        threadId = nullableString(messageJson, "threadId"),
                        createdAt = messageJson.optString("createdAt"),
                        messageKind = nullableString(messageJson, "messageKind"),
                        protocol = nullableString(messageJson, "protocol"),
                        wireMessage = nullableString(messageJson, "wireMessage"),
                        counter = messageJson.takeIf { it.has("counter") }?.optInt("counter"),
                        epoch = messageJson.takeIf { it.has("epoch") }?.optInt("epoch"),
                    )
                }
            }

            val lastActivity = buildList {
                add(json.optString("createdAt"))
                messages.forEach { add(it.createdAt) }
            }.filter { it.isNotBlank() }.maxOrNull() ?: json.optString("createdAt", Instant.now().toString())

            threads += RelayThread(
                deliveryCapability = nullableString(json, "deliveryCapability"),
                deliveryCapabilityExpiresAt = nullableString(json, "deliveryCapabilityExpiresAt"),
                id = json.optString("id"),
                mailboxHandle = nullableString(json, "mailboxHandle"),
                mailboxHandleExpiresAt = nullableString(json, "mailboxHandleExpiresAt"),
                title = json.optString("title"),
                protocol = json.optString("protocol", "unknown"),
                createdAt = json.optString("createdAt", Instant.now().toString()),
                createdBy = json.optString("createdBy"),
                participantIds = participants,
                attachmentCount = (json.optJSONArray("attachments") ?: JSONArray()).length(),
                messages = messages.sortedBy { it.createdAt },
            )
        }
        return threads.sortedByDescending { thread ->
            thread.messages.lastOrNull()?.createdAt ?: thread.createdAt
        }
    }

    private fun parseDevices(array: JSONArray?): List<RelayLinkedDevice> {
        val devices = mutableListOf<RelayLinkedDevice>()
        val safeArray = array ?: JSONArray()
        for (index in 0 until safeArray.length()) {
            val json = safeArray.optJSONObject(index) ?: continue
            devices += RelayLinkedDevice(
                attestationNote = json.optString("attestationNote").ifBlank { null },
                attestationStatus = json.optString("attestationStatus").ifBlank { null },
                attestedAt = json.optString("attestedAt").ifBlank { null },
                createdAt = json.optString("createdAt"),
                current = json.optBoolean("current", false),
                id = json.optString("id"),
                label = json.optString("label"),
                platform = json.optString("platform"),
                revokedAt = json.optString("revokedAt").ifBlank { null },
                riskLevel = json.optString("riskLevel", "unknown"),
                storageMode = json.optString("storageMode").ifBlank { null },
                updatedAt = json.optString("updatedAt", json.optString("createdAt")),
            )
        }
        return devices
    }

    private fun parseSession(json: JSONObject?): RelaySession? {
        val value = json ?: return null
        val expiresAt = value.optString("expiresAt").ifBlank { return null }
        val privacyMode = value.optString("privacyMode").ifBlank { return null }
        val sessionId = value.optString("sessionId").ifBlank { return null }
        val token = value.optString("token").ifBlank { return null }
        return RelaySession(
            expiresAt = expiresAt,
            privacyMode = privacyMode,
            sessionId = sessionId,
            token = token,
        )
    }

    private fun parseMlsKeyPackage(json: JSONObject): PublicMlsKeyPackage =
        PublicMlsKeyPackage(
            ciphersuite = json.optString("ciphersuite"),
            keyPackage = json.optString("keyPackage"),
        )

    private fun requireSessionToken(): String =
        sessionToken?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("The Notrus relay session expired. Bootstrap the session again on Android.")

    private fun nextTransportBucket(visibleSize: Int): Int =
        listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
            .firstOrNull { visibleSize <= it }
            ?: maxOf(visibleSize, 65536)

    private fun transportPadding(visibleSize: Int): String? {
        val target = nextTransportBucket(visibleSize)
        val deficit = (target - visibleSize).coerceAtLeast(0)
        if (deficit <= 32) {
            return null
        }
        val seed = UUID.randomUUID().toString().replace("-", "")
        return buildString(capacity = deficit) {
            while (length < deficit) {
                append(seed)
            }
        }.take(deficit)
    }

    private fun parseTransparencyEntries(array: JSONArray?): List<TransparencyEntry> {
        val entries = mutableListOf<TransparencyEntry>()
        val safeArray = array ?: JSONArray()
        for (index in 0 until safeArray.length()) {
            val json = safeArray.optJSONObject(index) ?: continue
            entries += TransparencyEntry(
                createdAt = json.optString("createdAt"),
                entryHash = json.optString("entryHash"),
                fingerprint = json.optString("fingerprint"),
                kind = json.optString("kind"),
                prekeyFingerprint = nullableString(json, "prekeyFingerprint"),
                previousHash = nullableString(json, "previousHash"),
                sequence = json.optInt("sequence", index + 1),
                userId = json.optString("userId"),
                username = json.optString("username"),
            )
        }
        return entries
    }

    private fun nullableString(json: JSONObject, key: String): String? =
        if (!json.has(key) || json.isNull(key)) {
            null
        } else {
            json.optString(key).takeUnless { it.isBlank() || it == "null" }
        }

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

    private fun parseTransparencySigner(json: JSONObject?): TransparencySignerInfo? {
        val value = json ?: return null
        val algorithm = value.optString("algorithm").ifBlank { return null }
        val keyId = value.optString("keyId").ifBlank { return null }
        val publicKeyRaw = value.optString("publicKeyRaw").ifBlank { return null }
        val publicKeySpki = value.optString("publicKeySpki").ifBlank { return null }
        return TransparencySignerInfo(
            algorithm = algorithm,
            keyId = keyId,
            publicKeyRaw = publicKeyRaw,
            publicKeySpki = publicKeySpki,
        )
    }

    private fun parseDeviceEvents(array: JSONArray?): List<RelayDeviceEvent> {
        val events = mutableListOf<RelayDeviceEvent>()
        val safeArray = array ?: JSONArray()
        for (index in 0 until safeArray.length()) {
            val json = safeArray.optJSONObject(index) ?: continue
            events += RelayDeviceEvent(
                actorDeviceId = json.optString("actorDeviceId").ifBlank { null },
                createdAt = json.optString("createdAt"),
                deviceId = json.optString("deviceId"),
                id = json.optString("id"),
                kind = json.optString("kind"),
                label = json.optString("label").ifBlank { null },
                platform = json.optString("platform").ifBlank { null },
                revokedAt = json.optString("revokedAt").ifBlank { null },
            )
        }
        return events
    }

    private fun signalBundleJson(bundle: PublicSignalBundle): JSONObject =
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

    private fun mlsKeyPackageJson(bundle: PublicMlsKeyPackage): JSONObject =
        JSONObject()
            .put("ciphersuite", bundle.ciphersuite)
            .put("keyPackage", bundle.keyPackage)

    private fun parseSignalBundle(json: JSONObject): PublicSignalBundle =
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

    private fun jwk(value: Jwk): JSONObject =
        JSONObject()
            .put("crv", value.crv)
            .put("kty", value.kty)
            .put("x", value.x)
            .put("y", value.y)

    private fun jsonJwk(json: JSONObject): Jwk =
        Jwk(
            crv = json.optString("crv", "P-256"),
            kty = json.optString("kty", "EC"),
            x = json.optString("x"),
            y = json.optString("y"),
        )

    private fun deviceJson(device: DeviceDescriptor): JSONObject =
        JSONObject()
            .put("createdAt", device.createdAt)
            .put("id", device.id)
            .put("label", device.label)
            .put("platform", device.platform)
            .put("publicJwk", jwk(device.publicJwk))
            .put("riskLevel", device.riskLevel)
            .put("storageMode", device.storageMode)
            .put(
                "attestation",
                device.attestation?.let { attestation ->
                    JSONObject()
                        .put("certificateChain", JSONArray(attestation.certificateChain))
                        .put("generatedAt", attestation.generatedAt)
                        .put("keyFingerprint", attestation.keyFingerprint)
                        .put("keyRole", attestation.keyRole)
                        .put("proofPayload", attestation.proofPayload)
                        .put("proofSignature", attestation.proofSignature)
                        .put("publicJwk", jwk(attestation.publicJwk))
                }
            )

    private fun request(
        path: String,
        method: String = "GET",
        body: JSONObject? = null,
        authorizationToken: String? = null,
        includeBootstrapHeaders: Boolean = false,
    ): JSONObject {
        val connection = open(path, method, body, authorizationToken = authorizationToken, includeBootstrapHeaders = includeBootstrapHeaders)
        val initial = readResponse(connection)
        if (initial.status == 428 && initial.json.optJSONObject("powChallenge") != null) {
            val challenge = initial.json.getJSONObject("powChallenge")
            val retried = open(
                path = path,
                method = method,
                body = body,
                authorizationToken = authorizationToken,
                includeBootstrapHeaders = includeBootstrapHeaders,
                extraHeaders = mapOf(
                    challenge.optString("tokenField", "X-Notrus-Pow-Token") to challenge.getString("token"),
                    challenge.optString("nonceField", "X-Notrus-Pow-Nonce") to solvePow(challenge),
                ),
            )
            val retriedResponse = readResponse(retried)
            if (retriedResponse.status !in 200..299) {
                throw IllegalStateException(retriedResponse.json.optString("error", "Relay returned HTTP ${retriedResponse.status}"))
            }
            return retriedResponse.json
        }

        if (initial.status !in 200..299) {
            throw IllegalStateException(initial.json.optString("error", "Relay returned HTTP ${initial.status}"))
        }
        return initial.json
    }

    private fun open(
        path: String,
        method: String,
        body: JSONObject?,
        authorizationToken: String? = null,
        includeBootstrapHeaders: Boolean = false,
        extraHeaders: Map<String, String> = emptyMap(),
    ): HttpURLConnection {
        val connection = URL(resolve(path)).openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("Content-Type", "application/json")
        extraHeaders.forEach { (name, value) ->
            connection.setRequestProperty(name, value)
        }
        if (!authorizationToken.isNullOrBlank()) {
            connection.setRequestProperty("Authorization", "Bearer $authorizationToken")
        }
        if (includeBootstrapHeaders && !appInstanceId.isNullOrBlank()) {
            connection.setRequestProperty("X-Notrus-Instance-Id", appInstanceId)
        }
        if (includeBootstrapHeaders && deviceDescriptor != null) {
            connection.setRequestProperty("X-Notrus-Device-Id", deviceDescriptor.id)
        }
        if (includeBootstrapHeaders && integrityReport != null) {
            connection.setRequestProperty(
                "X-Notrus-Integrity",
                Base64.encodeToString(
                    JSONObject()
                        .put("bundleIdentifier", integrityReport.bundleIdentifier)
                        .put("codeSignatureStatus", integrityReport.codeSignatureStatus)
                        .put("deviceCheckStatus", integrityReport.deviceCheckStatus)
                        .put("deviceCheckTokenPresented", integrityReport.deviceCheckTokenPresented)
                        .put("generatedAt", integrityReport.generatedAt)
                        .put("note", integrityReport.note)
                        .put("riskLevel", integrityReport.riskLevel)
                        .toString()
                        .toByteArray(),
                    Base64.NO_WRAP,
                )
            )
        }
        connection.doInput = true

        if (body != null) {
            connection.doOutput = true
            connection.outputStream.use { stream ->
                stream.write(body.toString().toByteArray())
            }
        }
        return connection
    }

    private fun readResponse(connection: HttpURLConnection): RelayResponse {
        val status = connection.responseCode
        val stream = if (status in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream ?: runCatching { connection.inputStream }.getOrNull()
        }
        val payload = stream?.use {
            BufferedReader(InputStreamReader(it)).readText()
        } ?: "{}"
        val json = decodePayload(payload)
        return RelayResponse(status = status, json = json)
    }

    private fun solvePow(challenge: JSONObject): String {
        val token = challenge.getString("token")
        val difficultyBits = challenge.getInt("difficultyBits")
        var counter = 0L
        while (counter < 50_000_000L) {
            val nonce = java.lang.Long.toHexString(counter)
            val digest = MessageDigest.getInstance("SHA-256").digest("$token:$nonce".toByteArray())
            if (leadingZeroBits(digest) >= difficultyBits) {
                return nonce
            }
            counter += 1
        }
        throw IllegalStateException("Unable to satisfy the relay proof-of-work challenge.")
    }

    private fun leadingZeroBits(bytes: ByteArray): Int {
        var count = 0
        for (value in bytes) {
            val byte = value.toInt() and 0xFF
            if (byte == 0) {
                count += 8
                continue
            }
            for (shift in 7 downTo 0) {
                if ((byte and (1 shl shift)) == 0) {
                    count += 1
                } else {
                    return count
                }
            }
        }
        return count
    }

    private fun resolve(path: String): String {
        val base = validateOrigin(origin)
        val uri = URI(base)
        return uri.resolve(path).toString()
    }

    companion object {
        internal fun decodePayload(payload: String): JSONObject {
            val trimmed = payload.trim()
            val parsed = trimmed.takeIf { it.isNotBlank() }?.let { raw ->
                if (raw.startsWith("{") || raw.startsWith("[") || raw.startsWith("\"")) {
                    runCatching { JSONTokener(raw).nextValue() }.getOrElse { raw }
                } else {
                    raw
                }
            }
            return when (parsed) {
                is JSONObject -> parsed
                is JSONArray -> JSONObject().put("items", parsed)
                null -> JSONObject()
                else -> JSONObject()
                    .put("error", parsed.toString())
                    .put("message", parsed.toString())
            }
        }

        fun validateOrigin(candidate: String): String {
            val uri = URI(candidate.trim())
            val scheme = uri.scheme?.lowercase() ?: throw IllegalArgumentException("Relay URL is missing a scheme.")
            val host = uri.host?.lowercase() ?: throw IllegalArgumentException("Relay URL is missing a host.")
            val isLocal =
                host == "localhost" ||
                host == "10.0.2.2" ||
                host == "127.0.0.1"

            if (scheme != "https" && !(scheme == "http" && isLocal)) {
                throw IllegalArgumentException("Android only allows HTTPS relay origins, except local emulator/localhost HTTP during development.")
            }
            return uri.toString().trimEnd('/')
        }
    }
}

private data class RelayResponse(
    val status: Int,
    val json: JSONObject,
)
