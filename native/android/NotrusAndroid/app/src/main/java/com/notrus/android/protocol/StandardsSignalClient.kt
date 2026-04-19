package com.notrus.android.protocol

import android.util.Base64
import com.notrus.android.model.PublicSignalBundle
import com.notrus.android.model.SignalProtocolState
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.InvalidVersionException
import org.signal.libsignal.protocol.LegacyMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyStore
import org.signal.libsignal.protocol.util.KeyHelper

data class StandardsSignalIdentity(
    val bundle: PublicSignalBundle,
    val fingerprint: String,
    val state: SignalProtocolState,
)

data class StandardsSignalEnvelope(
    val messageKind: String,
    val state: SignalProtocolState,
    val wireMessage: String,
)

data class StandardsSignalPlaintext(
    val plaintext: String,
    val state: SignalProtocolState,
)

object StandardsSignalClient {
    fun createIdentity(): StandardsSignalIdentity {
        val identityKeys = ECKeyPair.generate()
        val identityKeyPair = IdentityKeyPair(
            IdentityKey(identityKeys.publicKey),
            identityKeys.privateKey,
        )
        val store = PersistedSignalProtocolStore(
            localIdentityKeyPair = identityKeyPair,
            registrationId = KeyHelper.generateRegistrationId(false),
            deviceId = 1,
        )
        ensurePublishedBundle(store, null)
        val bundle = store.currentBundle()
        return StandardsSignalIdentity(
            bundle = bundle,
            fingerprint = identityFingerprint(identityKeyPair.publicKey.serialize()),
            state = store.snapshot(),
        )
    }

    fun refreshBundle(state: SignalProtocolState): StandardsSignalIdentity {
        val store = PersistedSignalProtocolStore.from(state)
        ensurePublishedBundle(store, state)
        val bundle = store.currentBundle()
        return StandardsSignalIdentity(
            bundle = bundle,
            fingerprint = identityFingerprint(store.localIdentity.publicKey.serialize()),
            state = store.snapshot(),
        )
    }

    @Throws(
        InvalidKeyException::class,
        UntrustedIdentityException::class,
        InvalidKeyIdException::class,
    )
    fun encrypt(
        state: SignalProtocolState,
        localUserId: String,
        plaintext: String,
        remoteBundle: PublicSignalBundle,
        remoteUserId: String,
    ): StandardsSignalEnvelope {
        val store = PersistedSignalProtocolStore.from(state)
        ensurePublishedBundle(store, state)
        val remoteAddress = SignalProtocolAddress(remoteUserId, remoteBundle.deviceId)
        if (!store.containsSession(remoteAddress)) {
            SessionBuilder(store, remoteAddress).process(preKeyBundle(remoteBundle))
        }
        val cipher = SessionCipher(store, SignalProtocolAddress(localUserId, state.deviceId), remoteAddress)
        val encrypted = cipher.encrypt(plaintext.toByteArray(Charsets.UTF_8))
        return StandardsSignalEnvelope(
            messageKind = when (encrypted.type) {
                CiphertextMessage.PREKEY_TYPE -> "signal-prekey"
                CiphertextMessage.WHISPER_TYPE -> "signal-whisper"
                else -> error("Unsupported Signal ciphertext type ${encrypted.type}.")
            },
            state = store.snapshot(),
            wireMessage = base64(encrypted.serialize()),
        )
    }

    @Throws(
        DuplicateMessageException::class,
        InvalidKeyException::class,
        InvalidMessageException::class,
        InvalidVersionException::class,
        LegacyMessageException::class,
        NoSessionException::class,
        UntrustedIdentityException::class,
    )
    fun decrypt(
        state: SignalProtocolState,
        localUserId: String,
        messageKind: String,
        remoteUserId: String,
        wireMessage: String,
    ): StandardsSignalPlaintext {
        val store = PersistedSignalProtocolStore.from(state)
        ensurePublishedBundle(store, state)
        val remoteAddress = SignalProtocolAddress(remoteUserId, state.deviceId)
        val cipher = SessionCipher(store, SignalProtocolAddress(localUserId, state.deviceId), remoteAddress)
        val plaintext = when (messageKind) {
            "signal-prekey" -> cipher.decrypt(PreKeySignalMessage(base64Data(wireMessage)))
            "signal-whisper" -> cipher.decrypt(SignalMessage(base64Data(wireMessage)))
            else -> throw InvalidMessageException("Unsupported Signal message kind $messageKind.")
        }
        return StandardsSignalPlaintext(
            plaintext = String(plaintext, Charsets.UTF_8),
            state = store.snapshot(),
        )
    }

    fun resetPeer(state: SignalProtocolState, remoteUserId: String): SignalProtocolState {
        val store = PersistedSignalProtocolStore.from(state)
        store.deleteAllSessions(remoteUserId)
        return store.snapshot()
    }

    private fun ensurePublishedBundle(store: PersistedSignalProtocolStore, state: SignalProtocolState?) {
        val preKeyId = state?.preKeyId ?: 1
        if (!store.containsPreKey(preKeyId)) {
            val nextId = if (state == null) preKeyId else preKeyId + 1
            val keyPair = ECKeyPair.generate()
            store.storePreKey(nextId, PreKeyRecord(nextId, keyPair))
            store.preKeyId = nextId
        }

        val signedPreKeyId = state?.signedPreKeyId ?: 1
        if (!store.containsSignedPreKey(signedPreKeyId)) {
            val nextId = if (state == null) signedPreKeyId else signedPreKeyId + 1
            val keyPair = ECKeyPair.generate()
            val signature = store.localIdentity.privateKey.calculateSignature(keyPair.publicKey.serialize())
            store.storeSignedPreKey(
                nextId,
                SignedPreKeyRecord(nextId, System.currentTimeMillis(), keyPair, signature),
            )
            store.signedPreKeyId = nextId
        }

        val kyberPreKeyId = state?.kyberPreKeyId ?: 1
        if (!store.containsKyberPreKey(kyberPreKeyId)) {
            val nextId = if (state == null) kyberPreKeyId else kyberPreKeyId + 1
            val keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val signature = store.localIdentity.privateKey.calculateSignature(keyPair.publicKey.serialize())
            store.storeKyberPreKey(
                nextId,
                KyberPreKeyRecord(nextId, System.currentTimeMillis(), keyPair, signature),
            )
            store.kyberPreKeyId = nextId
        }
    }

    private fun preKeyBundle(bundle: PublicSignalBundle): PreKeyBundle =
        PreKeyBundle(
            bundle.registrationId,
            bundle.deviceId,
            bundle.preKeyId,
            ECPublicKey(base64Data(bundle.preKeyPublic)),
            bundle.signedPreKeyId,
            ECPublicKey(base64Data(bundle.signedPreKeyPublic)),
            base64Data(bundle.signedPreKeySignature),
            IdentityKey(base64Data(bundle.identityKey)),
            bundle.kyberPreKeyId,
            KEMPublicKey(base64Data(bundle.kyberPreKeyPublic)),
            base64Data(bundle.kyberPreKeySignature),
        )

    private fun identityFingerprint(serializedIdentityKey: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(serializedIdentityKey)
            .joinToString("") { "%02x".format(it) }

    private fun base64Data(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)

    private fun base64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
}

private class PersistedSignalProtocolStore(
    private val localIdentityKeyPair: IdentityKeyPair,
    private val registrationId: Int,
    var deviceId: Int,
    var preKeyId: Int = 1,
    var signedPreKeyId: Int = 1,
    var kyberPreKeyId: Int = 1,
    private val identities: MutableMap<String, String> = linkedMapOf(),
    private val preKeys: MutableMap<Int, String> = linkedMapOf(),
    private val signedPreKeys: MutableMap<Int, String> = linkedMapOf(),
    private val kyberPreKeys: MutableMap<Int, String> = linkedMapOf(),
    private val sessions: MutableMap<String, String> = linkedMapOf(),
    private val senderKeys: MutableMap<String, String> = linkedMapOf(),
) : SignalProtocolStore {

    val localIdentity: IdentityKeyPair
        get() = localIdentityKeyPair

    companion object {
        fun from(state: SignalProtocolState): PersistedSignalProtocolStore =
            PersistedSignalProtocolStore(
                localIdentityKeyPair = IdentityKeyPair(Base64.decode(state.identityKeyPair, Base64.NO_WRAP)),
                registrationId = state.registrationId,
                deviceId = state.deviceId,
                preKeyId = state.preKeyId,
                signedPreKeyId = state.signedPreKeyId,
                kyberPreKeyId = state.kyberPreKeyId,
                identities = state.knownIdentities.toMutableMap(),
                preKeys = linkedMapOf<Int, String>().apply {
                    if (state.preKeyRecord.isNotBlank()) {
                        put(state.preKeyId, state.preKeyRecord)
                    }
                },
                signedPreKeys = linkedMapOf<Int, String>().apply {
                    if (state.signedPreKeyRecord.isNotBlank()) {
                        put(state.signedPreKeyId, state.signedPreKeyRecord)
                    }
                },
                kyberPreKeys = linkedMapOf<Int, String>().apply {
                    if (state.kyberPreKeyRecord.isNotBlank()) {
                        put(state.kyberPreKeyId, state.kyberPreKeyRecord)
                    }
                },
                sessions = state.sessions.toMutableMap(),
                senderKeys = state.senderKeys.toMutableMap(),
            )
    }

    fun snapshot(): SignalProtocolState =
        SignalProtocolState(
            deviceId = deviceId,
            identityKeyPair = Base64.encodeToString(localIdentity.serialize(), Base64.NO_WRAP),
            knownIdentities = identities.toMap(),
            kyberPreKeyId = kyberPreKeyId,
            kyberPreKeyRecord = kyberPreKeys[kyberPreKeyId].orEmpty(),
            preKeyId = preKeyId,
            preKeyRecord = preKeys[preKeyId].orEmpty(),
            registrationId = registrationId,
            senderKeys = senderKeys.toMap(),
            sessions = sessions.toMap(),
            signedPreKeyId = signedPreKeyId,
            signedPreKeyRecord = signedPreKeys[signedPreKeyId].orEmpty(),
        )

    fun currentBundle(): PublicSignalBundle {
        val preKeyRecord = loadPreKey(preKeyId)
        val signedPreKeyRecord = loadSignedPreKey(signedPreKeyId)
        val kyberPreKeyRecord = loadKyberPreKey(kyberPreKeyId)
        return PublicSignalBundle(
            deviceId = deviceId,
            identityKey = Base64.encodeToString(localIdentity.publicKey.serialize(), Base64.NO_WRAP),
            kyberPreKeyId = kyberPreKeyRecord.id,
            kyberPreKeyPublic = Base64.encodeToString(kyberPreKeyRecord.keyPair.publicKey.serialize(), Base64.NO_WRAP),
            kyberPreKeySignature = Base64.encodeToString(kyberPreKeyRecord.signature, Base64.NO_WRAP),
            preKeyId = preKeyRecord.id,
            preKeyPublic = Base64.encodeToString(preKeyRecord.keyPair.publicKey.serialize(), Base64.NO_WRAP),
            registrationId = registrationId,
            signedPreKeyId = signedPreKeyRecord.id,
            signedPreKeyPublic = Base64.encodeToString(signedPreKeyRecord.keyPair.publicKey.serialize(), Base64.NO_WRAP),
            signedPreKeySignature = Base64.encodeToString(signedPreKeyRecord.signature, Base64.NO_WRAP),
        )
    }

    override fun getIdentityKeyPair(): IdentityKeyPair = localIdentityKeyPair

    override fun getLocalRegistrationId(): Int = registrationId

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
    ): IdentityKeyStore.IdentityChange {
        val key = address.key()
        val serialized = Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP)
        val previous = identities[key]
        identities[key] = serialized
        return if (previous == null || previous == serialized) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val previous = identities[address.key()] ?: return true
        return previous == Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP)
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        identities[address.key()]?.let { IdentityKey(Base64.decode(it, Base64.NO_WRAP)) }

    override fun loadPreKey(preKeyId: Int): PreKeyRecord {
        val serialized = preKeys[preKeyId] ?: throw InvalidKeyIdException("Missing pre-key $preKeyId.")
        return PreKeyRecord(Base64.decode(serialized, Base64.NO_WRAP))
    }

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        preKeys[preKeyId] = Base64.encodeToString(record.serialize(), Base64.NO_WRAP)
    }

    override fun containsPreKey(preKeyId: Int): Boolean = preKeys.containsKey(preKeyId)

    override fun removePreKey(preKeyId: Int) {
        preKeys.remove(preKeyId)
    }

    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        val serialized = sessions[address.key()] ?: return SessionRecord()
        return SessionRecord(Base64.decode(serialized, Base64.NO_WRAP))
    }

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>?): List<SessionRecord> {
        val safeAddresses = addresses ?: emptyList()
        val results = mutableListOf<SessionRecord>()
        for (address in safeAddresses) {
            val serialized = sessions[address.key()] ?: throw NoSessionException(address, "No active session for ${address.getName()}.")
            results += SessionRecord(Base64.decode(serialized, Base64.NO_WRAP))
        }
        return results
    }

    override fun getSubDeviceSessions(name: String): MutableList<Int> =
        sessions.keys
            .mapNotNull { key ->
                val (addressName, device) = key.split('#', limit = 2)
                if (addressName == name) device.toIntOrNull() else null
            }
            .toMutableList()

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        sessions[address.key()] = Base64.encodeToString(record.serialize(), Base64.NO_WRAP)
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean = sessions.containsKey(address.key())

    override fun deleteSession(address: SignalProtocolAddress) {
        sessions.remove(address.key())
    }

    override fun deleteAllSessions(name: String) {
        sessions.keys
            .filter { it.substringBefore('#') == name }
            .toList()
            .forEach(sessions::remove)
    }

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        val serialized = signedPreKeys[signedPreKeyId] ?: throw InvalidKeyIdException("Missing signed pre-key $signedPreKeyId.")
        return SignedPreKeyRecord(Base64.decode(serialized, Base64.NO_WRAP))
    }

    override fun loadSignedPreKeys(): MutableList<SignedPreKeyRecord> =
        signedPreKeys.values.mapTo(mutableListOf()) { SignedPreKeyRecord(Base64.decode(it, Base64.NO_WRAP)) }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        signedPreKeys[signedPreKeyId] = Base64.encodeToString(record.serialize(), Base64.NO_WRAP)
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = signedPreKeys.containsKey(signedPreKeyId)

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        signedPreKeys.remove(signedPreKeyId)
    }

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        val serialized = kyberPreKeys[kyberPreKeyId] ?: throw InvalidKeyIdException("Missing kyber pre-key $kyberPreKeyId.")
        return KyberPreKeyRecord(Base64.decode(serialized, Base64.NO_WRAP))
    }

    override fun loadKyberPreKeys(): MutableList<KyberPreKeyRecord> =
        kyberPreKeys.values.mapTo(mutableListOf()) { KyberPreKeyRecord(Base64.decode(it, Base64.NO_WRAP)) }

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        kyberPreKeys[kyberPreKeyId] = Base64.encodeToString(record.serialize(), Base64.NO_WRAP)
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = kyberPreKeys.containsKey(kyberPreKeyId)

    override fun markKyberPreKeyUsed(
        kyberPreKeyId: Int,
        signedPreKeyId: Int,
        baseKey: ECPublicKey,
    ) {
        if (!kyberPreKeys.containsKey(kyberPreKeyId)) {
            throw ReusedBaseKeyException("Missing kyber pre-key $kyberPreKeyId.")
        }
    }

    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        senderKeys["${sender.key()}:${distributionId}"] = Base64.encodeToString(record.serialize(), Base64.NO_WRAP)
    }

    override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? =
        senderKeys["${sender.key()}:${distributionId}"]?.let { SenderKeyRecord(Base64.decode(it, Base64.NO_WRAP)) }
}

private fun SignalProtocolAddress.key(): String = "${getName()}#${getDeviceId()}"
