package com.notrus.android.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import com.notrus.android.model.Jwk
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Collections
import java.util.UUID

data class HardwareIdentityBundle(
    val userId: String,
    val username: String,
    val displayName: String,
    val storageMode: String,
    val fingerprint: String,
    val signingPublicJwk: Jwk,
    val encryptionPublicJwk: Jwk,
    val prekeyPublicJwk: Jwk,
    val prekeyCreatedAt: String,
    val prekeyFingerprint: String,
    val prekeySignature: String,
)

class StrongBoxIdentityProvider(
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) },
) {
    fun createIdentity(username: String, displayName: String): HardwareIdentityBundle {
        return createIdentity(
            userId = UUID.randomUUID().toString(),
            username = username,
            displayName = displayName,
        )
    }

    fun createIdentity(userId: String, username: String, displayName: String): HardwareIdentityBundle {
        val signingAlias = alias(userId, "signing")
        val encryptionAlias = alias(userId, "encryption")
        val prekeyAlias = alias(userId, "prekey")

        val signingKey = generateEcKey(signingAlias, KeyProperties.PURPOSE_SIGN, preferStrongBox = true)
        val encryptionKey = generateEcKey(encryptionAlias, KeyProperties.PURPOSE_AGREE_KEY, preferStrongBox = true)
        val prekey = generateEcKey(prekeyAlias, KeyProperties.PURPOSE_AGREE_KEY, preferStrongBox = true)
        val storageMode = listOf(signingKey, encryptionKey, prekey)
            .map { it.storageMode }
            .firstOrNull { it == "strongbox-keystore" }
            ?: "android-keystore"

        val signingPublicJwk = toJwk(signingKey.keyPair.public as ECPublicKey)
        val encryptionPublicJwk = toJwk(encryptionKey.keyPair.public as ECPublicKey)
        val prekeyPublicJwk = toJwk(prekey.keyPair.public as ECPublicKey)
        val prekeyCreatedAt = Instant.now().toString()
        val prekeySignature = sign(signingAlias, signedPrekeyPayload(prekeyCreatedAt, prekeyPublicJwk, userId))

        return HardwareIdentityBundle(
            userId = userId,
            username = username,
            displayName = displayName,
            storageMode = storageMode,
            fingerprint = identityFingerprint(encryptionPublicJwk, signingPublicJwk),
            signingPublicJwk = signingPublicJwk,
            encryptionPublicJwk = encryptionPublicJwk,
            prekeyPublicJwk = prekeyPublicJwk,
            prekeyCreatedAt = prekeyCreatedAt,
            prekeyFingerprint = fingerprint(prekeyPublicJwk),
            prekeySignature = prekeySignature,
        )
    }

    private fun sign(alias: String, payload: String): String {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        signature.update(payload.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    private fun generateEcKey(alias: String, purpose: Int, preferStrongBox: Boolean): GeneratedKeyPair {
        return if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching { generateEcKeyWithStorageMode(alias, purpose, strongBoxBacked = true) }
                .recoverCatching {
                    runCatching { keyStore.deleteEntry(alias) }
                    generateEcKeyWithStorageMode(alias, purpose, strongBoxBacked = false)
                }
                .getOrThrow()
        } else {
            generateEcKeyWithStorageMode(alias, purpose, strongBoxBacked = false)
        }
    }

    private fun generateEcKeyWithStorageMode(alias: String, purpose: Int, strongBoxBacked: Boolean): GeneratedKeyPair {
        val builder = KeyGenParameterSpec.Builder(alias, purpose)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAttestationChallenge("notrus-android-identity-v1".toByteArray(StandardCharsets.UTF_8))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(strongBoxBacked)
        }

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(builder.build())
        return GeneratedKeyPair(
            keyPair = generator.generateKeyPair(),
            storageMode = if (strongBoxBacked) "strongbox-keystore" else "android-keystore",
        )
    }

    private fun alias(userId: String, kind: String): String = "notrus:$userId:$kind"

    fun expectedAliases(userId: String): List<String> = listOf(
        alias(userId, "signing"),
        alias(userId, "encryption"),
        alias(userId, "prekey"),
    )

    fun deleteIdentityAliases(userId: String) {
        expectedAliases(userId).forEach { alias ->
            runCatching {
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            }
        }
    }

    fun listIdentityAliases(): List<HardwareAliasSnapshot> {
        val aliases = Collections.list(keyStore.aliases())
        return aliases
            .filter { it.startsWith("notrus:") && !it.startsWith("notrus:device:") }
            .filterNot { it == "notrus.vault.master" }
            .sorted()
            .mapNotNull(::parseAlias)
    }

    private fun parseAlias(alias: String): HardwareAliasSnapshot? {
        val parts = alias.split(':')
        if (parts.size != 3) {
            return null
        }
        return HardwareAliasSnapshot(
            alias = alias,
            ownerId = parts[1],
            kind = parts[2],
            storageMode = certificateStorageMode(alias),
        )
    }

    private fun certificateStorageMode(alias: String): String {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return "unknown-keystore"
        val keyInfo = runCatching {
            KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(entry.privateKey, KeyInfo::class.java)
        }.getOrNull()
        return when {
            keyInfo == null -> "android-keystore"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && keyInfo.isInsideSecureHardware -> "strongbox-keystore"
            else -> "android-keystore"
        }
    }

    private fun toJwk(publicKey: ECPublicKey): Jwk {
        val x = unsigned32(publicKey.w.affineX.toByteArray())
        val y = unsigned32(publicKey.w.affineY.toByteArray())
        return Jwk(
            x = base64Url(x),
            y = base64Url(y),
        )
    }

    private fun identityFingerprint(encryption: Jwk, signing: Jwk): String {
        val source = """{"encryption":${canonicalJwk(encryption)},"signing":${canonicalJwk(signing)}}"""
        return formatFingerprint(sha256Hex(source))
    }

    private fun fingerprint(jwk: Jwk): String = formatFingerprint(sha256Hex(canonicalJwk(jwk)))

    private fun canonicalJwk(jwk: Jwk): String =
        """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""

    private fun signedPrekeyPayload(createdAt: String, prekey: Jwk, userId: String): String =
        """{"createdAt":"$createdAt","kind":"notrus-signed-prekey","prekey":"${canonicalJwk(prekey)}","userId":"$userId"}"""

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun formatFingerprint(hex: String): String = hex.chunked(4).joinToString(" ")

    private fun unsigned32(bytes: ByteArray): ByteArray {
        val withoutSign = if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        return when {
            withoutSign.size == 32 -> withoutSign
            withoutSign.size < 32 -> ByteArray(32 - withoutSign.size) + withoutSign
            else -> withoutSign.copyOfRange(withoutSign.size - 32, withoutSign.size)
        }
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
            .replace("+", "-")
            .replace("/", "_")
            .replace("=", "")
}

private data class GeneratedKeyPair(
    val keyPair: java.security.KeyPair,
    val storageMode: String,
)

data class HardwareAliasSnapshot(
    val alias: String,
    val ownerId: String,
    val kind: String,
    val storageMode: String,
)
