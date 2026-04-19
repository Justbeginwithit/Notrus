package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.AccountResetRequest
import com.notrus.android.model.Jwk
import com.notrus.android.model.PublicSignalBundle
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.text.Normalizer

data class RecoveryAuthority(
    val fingerprint: String,
    val publicJwk: Jwk,
)

data class RecoveryKeyMaterial(
    val publicJwk: Jwk,
    val privateKeyPkcs8: String,
    val recoveryRepresentation: String,
    val fingerprint: String,
)

object RecoveryKeyManager {
    private const val ARCHIVE_AAD = "notrus-native-account-archive-v1"

    fun create(): RecoveryKeyMaterial {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val publicKey = pair.public as ECPublicKey
        val privateKey = pair.private as ECPrivateKey
        val publicJwk = Jwk(
            x = base64Url(unsigned32(publicKey.w.affineX.toByteArray())),
            y = base64Url(unsigned32(publicKey.w.affineY.toByteArray())),
        )
        return RecoveryKeyMaterial(
            publicJwk = publicJwk,
            privateKeyPkcs8 = Base64.encodeToString(pair.private.encoded, Base64.NO_WRAP),
            recoveryRepresentation = Base64.encodeToString(unsigned32(privateKey.s.toByteArray()), Base64.NO_WRAP),
            fingerprint = formatFingerprint(sha256Hex(canonicalJwk(publicJwk))),
        )
    }

    fun recoveryRepresentationFromPkcs8(pkcs8: String): String {
        if (pkcs8.isBlank()) {
            return ""
        }
        val privateKey = KeyFactory.getInstance("EC")
            .generatePrivate(PKCS8EncodedKeySpec(Base64.decode(pkcs8, Base64.NO_WRAP))) as ECPrivateKey
        return Base64.encodeToString(unsigned32(privateKey.s.toByteArray()), Base64.NO_WRAP)
    }

    fun recoveryAuthorityFromRepresentation(recoveryRepresentation: String): RecoveryAuthority {
        val privateKey = privateKeyFromRepresentation(recoveryRepresentation) as ECPrivateKey
        val params = privateKey.params
        val point = scalarMultiply(params.generator, privateKey.s, params)
        val publicJwk = Jwk(
            x = base64Url(unsigned32(point.affineX.toByteArray())),
            y = base64Url(unsigned32(point.affineY.toByteArray())),
        )
        return RecoveryAuthority(
            fingerprint = formatFingerprint(sha256Hex(canonicalJwk(publicJwk))),
            publicJwk = publicJwk,
        )
    }

    fun signAccountReset(request: AccountResetRequest, recoveryRepresentation: String): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKeyFromRepresentation(recoveryRepresentation))
        signature.update(accountResetSignaturePayload(request).toByteArray())
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun archiveAuthenticationData(): ByteArray = ARCHIVE_AAD.toByteArray()

    fun deriveArchiveKey(passphrase: String, salt: ByteArray, rounds: Int): ByteArray {
        var state = Normalizer.normalize(passphrase, Normalizer.Form.NFC).toByteArray() + salt
        val digest = MessageDigest.getInstance("SHA-256")
        repeat(maxOf(1, rounds)) { round ->
            state = digest.digest(state + salt + round.toString().toByteArray())
        }
        return digest.digest(state + salt)
    }

    fun accountResetSignaturePayload(request: AccountResetRequest): String =
        """{"createdAt":${jsonString(request.createdAt)},"displayName":${jsonString(request.displayName)},"encryption":${canonicalJwk(request.encryptionPublicJwk)},"fingerprint":${jsonString(request.fingerprint)},"mlsKeyPackage":${request.mlsKeyPackage?.let { jsonString(it.keyPackage) } ?: "null"},"prekeyCreatedAt":${jsonString(request.prekeyCreatedAt)},"prekeyFingerprint":${jsonString(request.prekeyFingerprint)},"prekeyPublicJwk":${canonicalJwk(request.prekeyPublicJwk)},"prekeySignature":${jsonString(request.prekeySignature)},"recoveryFingerprint":${jsonString(request.recoveryFingerprint)},"recoveryPublicJwk":${canonicalJwk(request.recoveryPublicJwk)},"signalBundle":${request.signalBundle?.let(::signalBundleCanonicalSource) ?: "null"},"signing":${canonicalJwk(request.signingPublicJwk)},"userId":${jsonString(request.userId)},"username":${jsonString(request.username)}}"""

    private fun signalBundleCanonicalSource(bundle: PublicSignalBundle): String =
        """{"deviceId":${bundle.deviceId},"identityKey":"${bundle.identityKey}","kyberPreKeyId":${bundle.kyberPreKeyId},"kyberPreKeyPublic":"${bundle.kyberPreKeyPublic}","kyberPreKeySignature":"${bundle.kyberPreKeySignature}","preKeyId":${bundle.preKeyId},"preKeyPublic":"${bundle.preKeyPublic}","registrationId":${bundle.registrationId},"signedPreKeyId":${bundle.signedPreKeyId},"signedPreKeyPublic":"${bundle.signedPreKeyPublic}","signedPreKeySignature":"${bundle.signedPreKeySignature}"}"""

    private fun jsonString(value: String): String =
        "\"" + value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"") + "\""

    private fun privateKeyFromRepresentation(recoveryRepresentation: String): java.security.PrivateKey {
        val raw = Base64.decode(recoveryRepresentation, Base64.NO_WRAP)
        val params = java.security.AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(java.math.BigInteger(1, raw), params)
        )
    }

    private fun canonicalJwk(jwk: Jwk): String =
        """{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}"""

    private fun scalarMultiply(
        point: ECPoint,
        scalar: java.math.BigInteger,
        params: java.security.spec.ECParameterSpec,
    ): ECPoint {
        var result: ECPoint? = null
        var addend: ECPoint? = point
        var k = scalar
        while (k.signum() > 0 && addend != null) {
            if (k.testBit(0)) {
                result = result?.let { add(params, it, addend) } ?: addend
            }
            addend = add(params, addend, addend)
            k = k.shiftRight(1)
        }
        return result ?: ECPoint.POINT_INFINITY
    }

    private fun add(
        params: java.security.spec.ECParameterSpec,
        left: ECPoint,
        right: ECPoint,
    ): ECPoint {
        if (left == ECPoint.POINT_INFINITY) return right
        if (right == ECPoint.POINT_INFINITY) return left

        val p = (params.curve.field as java.security.spec.ECFieldFp).p
        val a = params.curve.a

        val x1 = left.affineX
        val y1 = left.affineY
        val x2 = right.affineX
        val y2 = right.affineY

        if (x1 == x2) {
            if (y1.add(y2).mod(p) == java.math.BigInteger.ZERO) {
                return ECPoint.POINT_INFINITY
            }
            if (y1 == java.math.BigInteger.ZERO) {
                return ECPoint.POINT_INFINITY
            }
        }

        val lambda = if (left == right) {
            val numerator = x1.multiply(x1).multiply(java.math.BigInteger.valueOf(3)).add(a).mod(p)
            val denominator = y1.multiply(java.math.BigInteger.TWO).modInverse(p)
            numerator.multiply(denominator).mod(p)
        } else {
            val numerator = y2.subtract(y1).mod(p)
            val denominator = x2.subtract(x1).mod(p).modInverse(p)
            numerator.multiply(denominator).mod(p)
        }

        val x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(p)
        val y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p)
        return ECPoint(x3.normalize(p), y3.normalize(p))
    }

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

    private fun java.math.BigInteger.normalize(modulus: java.math.BigInteger): java.math.BigInteger {
        val value = this.mod(modulus)
        return if (value.signum() < 0) value.add(modulus) else value
    }
}
