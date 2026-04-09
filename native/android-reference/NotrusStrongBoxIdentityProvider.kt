package com.notrus.nativebridge

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

data class NotrusJwk(
    val crv: String = "P-256",
    val kty: String = "EC",
    val x: String,
    val y: String,
)

data class HardwareIdentityBundle(
    val userId: String,
    val username: String,
    val displayName: String,
    val fingerprint: String,
    val signingPublicJwk: NotrusJwk,
    val encryptionPublicJwk: NotrusJwk,
    val prekeyPublicJwk: NotrusJwk,
    val prekeyCreatedAt: String,
    val prekeyFingerprint: String,
    val prekeySignature: String,
)

class NotrusStrongBoxIdentityProvider(
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) },
) {
    fun createIdentity(userId: String, username: String, displayName: String): HardwareIdentityBundle {
        val signingAlias = alias(userId, "signing")
        val encryptionAlias = alias(userId, "encryption")
        val prekeyAlias = alias(userId, "prekey")

        val signingKey = generateEcKey(signingAlias, KeyProperties.PURPOSE_SIGN, preferStrongBox = true)
        val encryptionKey = generateEcKey(
            encryptionAlias,
            KeyProperties.PURPOSE_AGREE_KEY,
            preferStrongBox = true
        )
        val prekey = generateEcKey(
            prekeyAlias,
            KeyProperties.PURPOSE_AGREE_KEY,
            preferStrongBox = true
        )

        val signingPublicJwk = toJwk(signingKey.public as ECPublicKey)
        val encryptionPublicJwk = toJwk(encryptionKey.public as ECPublicKey)
        val prekeyPublicJwk = toJwk(prekey.public as ECPublicKey)
        val prekeyCreatedAt = java.time.Instant.now().toString()
        val prekeySignature = sign(
            signingAlias,
            signedPrekeyPayload(prekeyCreatedAt, prekeyPublicJwk, userId)
        )

        return HardwareIdentityBundle(
            userId = userId,
            username = username,
            displayName = displayName,
            fingerprint = identityFingerprint(encryptionPublicJwk, signingPublicJwk),
            signingPublicJwk = signingPublicJwk,
            encryptionPublicJwk = encryptionPublicJwk,
            prekeyPublicJwk = prekeyPublicJwk,
            prekeyCreatedAt = prekeyCreatedAt,
            prekeyFingerprint = fingerprint(prekeyPublicJwk),
            prekeySignature = prekeySignature,
        )
    }

    fun rotatePrekey(userId: String): Triple<NotrusJwk, String, String> {
        val signingAlias = alias(userId, "signing")
        val prekeyAlias = alias(userId, "prekey")

        if (keyStore.containsAlias(prekeyAlias)) {
            keyStore.deleteEntry(prekeyAlias)
        }

        val prekey = generateEcKey(
            prekeyAlias,
            KeyProperties.PURPOSE_AGREE_KEY,
            preferStrongBox = true
        )
        val prekeyPublicJwk = toJwk(prekey.public as ECPublicKey)
        val createdAt = java.time.Instant.now().toString()
        val signature = sign(signingAlias, signedPrekeyPayload(createdAt, prekeyPublicJwk, userId))
        return Triple(prekeyPublicJwk, createdAt, signature)
    }

    fun sign(alias: String, payload: String): String {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        signature.update(payload.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun keyInfo(alias: String): KeyInfo {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
        return factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    }

    private fun generateEcKey(alias: String, purpose: Int, preferStrongBox: Boolean): java.security.KeyPair {
        val builder = KeyGenParameterSpec.Builder(alias, purpose)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(preferStrongBox)
        }

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(builder.build())
        return generator.generateKeyPair()
    }

    private fun alias(userId: String, kind: String): String = "notrus:$userId:$kind"

    private fun toJwk(publicKey: ECPublicKey): NotrusJwk {
        val x = unsigned32(publicKey.w.affineX.toByteArray())
        val y = unsigned32(publicKey.w.affineY.toByteArray())
        return NotrusJwk(
            x = base64url(x),
            y = base64url(y),
        )
    }

    private fun identityFingerprint(encryption: NotrusJwk, signing: NotrusJwk): String {
        val source = """{"encryption":${canonicalFingerprintSource(encryption)},"signing":${canonicalFingerprintSource(signing)}}"""
        return formatFingerprint(sha256Hex(source))
    }

    private fun fingerprint(jwk: NotrusJwk): String = formatFingerprint(sha256Hex(canonicalFingerprintSource(jwk)))

    private fun canonicalFingerprintSource(jwk: NotrusJwk): String =
        """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""

    private fun signedPrekeyPayload(createdAt: String, prekey: NotrusJwk, userId: String): String =
        """{"createdAt":"$createdAt","kind":"notrus-signed-prekey","prekey":"${canonicalFingerprintSource(prekey)}","userId":"$userId"}"""

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun formatFingerprint(hex: String): String =
        hex.chunked(4).joinToString(" ")

    private fun unsigned32(bytes: ByteArray): ByteArray {
        val withoutSign = if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        return when {
            withoutSign.size == 32 -> withoutSign
            withoutSign.size < 32 -> ByteArray(32 - withoutSign.size) + withoutSign
            else -> withoutSign.copyOfRange(withoutSign.size - 32, withoutSign.size)
        }
    }

    private fun base64url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
            .replace("+", "-")
            .replace("/", "_")
            .replace("=", "")
}
