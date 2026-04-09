package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.Jwk
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

data class RecoveryKeyMaterial(
    val publicJwk: Jwk,
    val privateKeyPkcs8: String,
    val fingerprint: String,
)

object RecoveryKeyManager {
    fun create(): RecoveryKeyMaterial {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val publicKey = pair.public as ECPublicKey
        val publicJwk = Jwk(
            x = base64Url(unsigned32(publicKey.w.affineX.toByteArray())),
            y = base64Url(unsigned32(publicKey.w.affineY.toByteArray())),
        )
        return RecoveryKeyMaterial(
            publicJwk = publicJwk,
            privateKeyPkcs8 = Base64.encodeToString(pair.private.encoded, Base64.NO_WRAP),
            fingerprint = formatFingerprint(sha256Hex(canonicalJwk(publicJwk))),
        )
    }

    private fun canonicalJwk(jwk: Jwk): String =
        """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray())
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
