package com.notrus.android.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import com.notrus.android.model.DeviceAttestationProof
import com.notrus.android.model.DeviceDescriptor
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

class DeviceIdentityProvider(
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) },
) {
    fun descriptor(context: Context, appInstanceId: String): DeviceDescriptor {
        val alias = alias(appInstanceId)
        val keyMaterial = ensureKey(alias, context.packageManager)
        val publicKey = keyMaterial.keyPair.public as ECPublicKey
        val settings = context.getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
        val createdAt = settings.getString(KEY_DEVICE_CREATED_AT, null)
            ?: Instant.now().toString().also {
                settings.edit().putString(KEY_DEVICE_CREATED_AT, it).apply()
            }
        val storageMode = keyMaterial.storageMode
        val publicJwk = toJwk(publicKey)
        val generatedAt = Instant.now().toString()
        val proofPayload = deviceAttestationPayload(
            createdAt = createdAt,
            deviceId = appInstanceId,
            generatedAt = generatedAt,
            publicJwk = publicJwk,
            storageMode = storageMode,
        )

        return DeviceDescriptor(
            createdAt = createdAt,
            id = appInstanceId,
            label = "${Build.MANUFACTURER} ${Build.MODEL}".trim().ifBlank { "This Android device" },
            platform = "android",
            publicJwk = publicJwk,
            riskLevel = "unknown",
            storageMode = storageMode,
            attestation = DeviceAttestationProof(
                certificateChain = certificateChain(alias),
                generatedAt = generatedAt,
                keyFingerprint = fingerprint(publicJwk),
                keyRole = "device-management",
                proofPayload = proofPayload,
                proofSignature = sign(alias, proofPayload),
                publicJwk = publicJwk,
            ),
        )
    }

    fun signAction(appInstanceId: String, payload: String, packageManager: PackageManager): String {
        val alias = alias(appInstanceId)
        ensureKey(alias, packageManager)
        return sign(alias, payload)
    }

    private fun sign(alias: String, payload: String): String {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        signature.update(payload.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    private fun ensureKey(alias: String, packageManager: PackageManager): GeneratedDeviceKeyPair {
        val certificate = keyStore.getCertificate(alias)
        if (certificate != null) {
            val publicKey = certificate.publicKey as ECPublicKey
            return GeneratedDeviceKeyPair(
                keyPair = java.security.KeyPair(publicKey, null),
                storageMode = if (packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                    "strongbox-device-key"
                } else {
                    "android-keystore-device-key"
                },
            )
        }

        val preferStrongBox =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        return if (preferStrongBox) {
            runCatching { generateDeviceKey(alias, strongBoxBacked = true) }
                .recoverCatching {
                    runCatching { keyStore.deleteEntry(alias) }
                    generateDeviceKey(alias, strongBoxBacked = false)
                }
                .getOrThrow()
        } else {
            generateDeviceKey(alias, strongBoxBacked = false)
        }
    }

    private fun generateDeviceKey(alias: String, strongBoxBacked: Boolean): GeneratedDeviceKeyPair {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAttestationChallenge("notrus-android-device-v1".toByteArray(StandardCharsets.UTF_8))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(strongBoxBacked)
        }

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(builder.build())
        return GeneratedDeviceKeyPair(
            keyPair = generator.generateKeyPair(),
            storageMode = if (strongBoxBacked) "strongbox-device-key" else "android-keystore-device-key",
        )
    }

    private fun alias(appInstanceId: String): String = "notrus:device:$appInstanceId"

    fun aliasFor(appInstanceId: String): String = alias(appInstanceId)

    fun hasAlias(appInstanceId: String): Boolean = keyStore.containsAlias(alias(appInstanceId))

    fun deleteAlias(alias: String) {
        if (!alias.startsWith("notrus:device:")) {
            return
        }
        runCatching {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }

    fun listDeviceAliases(): List<DeviceAliasSnapshot> =
        java.util.Collections.list(keyStore.aliases())
            .filter { it.startsWith("notrus:device:") }
            .sorted()
            .map { alias ->
                DeviceAliasSnapshot(
                    alias = alias,
                    appInstanceId = alias.removePrefix("notrus:device:"),
                    storageMode = storageMode(alias),
                )
            }

    private fun certificateChain(alias: String): List<String> =
        keyStore.getCertificateChain(alias)
            ?.map { certificate -> Base64.encodeToString(certificate.encoded, Base64.NO_WRAP) }
            ?.toList()
            ?: emptyList()

    private fun deviceAttestationPayload(
        createdAt: String,
        deviceId: String,
        generatedAt: String,
        publicJwk: Jwk,
        storageMode: String,
    ): String =
        """{"createdAt":"$createdAt","deviceId":"$deviceId","generatedAt":"$generatedAt","keyFingerprint":"${fingerprint(publicJwk)}","keyRole":"device-management","platform":"android","publicJwk":${canonicalJwk(publicJwk)},"storageMode":"$storageMode"}"""

    private fun toJwk(publicKey: ECPublicKey): Jwk {
        val x = unsigned32(publicKey.w.affineX.toByteArray())
        val y = unsigned32(publicKey.w.affineY.toByteArray())
        return Jwk(
            x = base64Url(x),
            y = base64Url(y),
        )
    }

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

    private fun canonicalJwk(jwk: Jwk): String =
        """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""

    private fun fingerprint(jwk: Jwk): String =
        MessageDigest.getInstance("SHA-256")
            .digest(canonicalJwk(jwk).toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    companion object {
        private const val KEY_DEVICE_CREATED_AT = "device_created_at"
    }

    private fun storageMode(alias: String): String {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return "unknown-device-key"
        val keyInfo = runCatching {
            KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(entry.privateKey, KeyInfo::class.java)
        }.getOrNull()
        return when {
            keyInfo == null -> "android-keystore-device-key"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && keyInfo.isInsideSecureHardware -> "strongbox-device-key"
            else -> "android-keystore-device-key"
        }
    }
}

private data class GeneratedDeviceKeyPair(
    val keyPair: java.security.KeyPair,
    val storageMode: String,
)

data class DeviceAliasSnapshot(
    val alias: String,
    val appInstanceId: String,
    val storageMode: String,
)
