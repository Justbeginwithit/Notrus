package com.notrus.android.security

import android.util.Base64
import com.notrus.android.model.TransparencyEntry
import com.notrus.android.model.TransparencySignerInfo
import com.notrus.android.model.TransparencyVerificationResult
import com.notrus.android.model.WitnessObservation
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object TransparencyVerifier {
    suspend fun verify(
        relayOrigin: String,
        entryCount: Int,
        entries: List<TransparencyEntry>,
        expectedHead: String?,
        expectedSignature: String?,
        signer: TransparencySignerInfo?,
        pinnedHeads: Map<String, String>,
        pinnedSignerKeys: Map<String, String>,
        witnessOrigins: List<String>,
        fetchWitness: suspend (String, String) -> WitnessObservation?,
    ): TransparencyVerificationResult {
        val sortedEntries = entries.sortedBy { it.sequence }
        var previousHash: String? = null
        val warnings = mutableListOf<String>()

        for (entry in sortedEntries) {
            if (entry.previousHash != previousHash) {
                warnings += "Transparency log hash chain is inconsistent."
                break
            }

            val computedHash = sha256Hex(
                """{"createdAt":"${entry.createdAt}","fingerprint":"${entry.fingerprint}","kind":"${entry.kind}","prekeyFingerprint":${entry.prekeyFingerprint?.let(::jsonString) ?: "null"},"previousHash":${entry.previousHash?.let(::jsonString) ?: "null"},"sequence":${entry.sequence},"userId":"${entry.userId}","username":"${entry.username}"}"""
            )
            if (computedHash != entry.entryHash) {
                warnings += "Transparency log entry hash verification failed."
                break
            }

            previousHash = entry.entryHash
        }

        if (expectedHead != null && previousHash != expectedHead) {
            warnings += "Transparency log head does not match the relay's advertised head."
        }

        if (!verifySignedHead(entryCount, expectedHead, expectedSignature, signer)) {
            warnings += "Transparency signer verification failed for the relay's advertised key-directory head."
        }

        val chainHeads = sortedEntries.mapTo(linkedSetOf()) { it.entryHash }.apply {
            if (expectedHead != null) {
                add(expectedHead)
            }
        }

        val pinnedHead = pinnedHeads[relayOrigin]
        if (pinnedHead != null && !chainHeads.contains(pinnedHead)) {
            warnings += "This relay presented a transparency history that does not include the head previously pinned on this Android device."
        }
        val signerKeyId = signer?.keyId
        val pinnedSignerKeyId = pinnedSignerKeys[relayOrigin]
        if (pinnedSignerKeyId != null && signerKeyId != null && pinnedSignerKeyId != signerKeyId) {
            warnings += "This relay changed its transparency signing key for the Android key directory."
        }

        val witnesses = fetchWitnesses(
            relayOrigin = relayOrigin,
            expectedHead = expectedHead,
            chainHeads = chainHeads,
            witnessOrigins = witnessOrigins,
            fetchWitness = fetchWitness,
            warnings = warnings,
        )

        return TransparencyVerificationResult(
            chainValid = warnings.isEmpty(),
            entries = sortedEntries,
            head = expectedHead,
            pinnedHead = pinnedHead,
            pinnedSignerKeyId = pinnedSignerKeyId,
            signerKeyId = signerKeyId,
            warnings = warnings,
            witnesses = witnesses,
        )
    }

    private suspend fun fetchWitnesses(
        relayOrigin: String,
        expectedHead: String?,
        chainHeads: Set<String>,
        witnessOrigins: List<String>,
        fetchWitness: suspend (String, String) -> WitnessObservation?,
        warnings: MutableList<String>,
    ): List<WitnessObservation> {
        val observations = mutableListOf<WitnessObservation>()
        for (origin in witnessOrigins) {
            val latest = runCatching { fetchWitness(origin, relayOrigin) }.getOrNull()
            if (latest == null) {
                observations += WitnessObservation(origin = origin, status = "unreachable")
                continue
            }

            val resolvedStatus = when {
                latest.head == expectedHead -> "current"
                latest.head != null && chainHeads.contains(latest.head) -> "lagging"
                latest.head != null -> {
                    warnings += "Witness $origin reported a transparency head that does not appear in the relay's current chain."
                    "conflict"
                }
                else -> "missing"
            }

            observations += latest.copy(status = resolvedStatus)
        }
        return observations
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun verifySignedHead(
        entryCount: Int,
        expectedHead: String?,
        expectedSignature: String?,
        signer: TransparencySignerInfo?,
    ): Boolean {
        if (signer == null || expectedSignature.isNullOrBlank()) {
            return false
        }
        if (signer.algorithm != "ed25519") {
            return false
        }

        return runCatching {
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val publicKey = keyFactory.generatePublic(
                X509EncodedKeySpec(Base64.decode(signer.publicKeySpki, Base64.NO_WRAP))
            )
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(publicKey)
            verifier.update(transparencyStatementPayload(entryCount, expectedHead, signer.keyId).toByteArray(Charsets.UTF_8))
            verifier.verify(Base64.decode(expectedSignature, Base64.NO_WRAP))
        }.getOrDefault(false)
    }

    private fun transparencyStatementPayload(
        entryCount: Int,
        expectedHead: String?,
        signerKeyId: String,
    ): String =
        """{"entryCount":$entryCount,"signerKeyId":"$signerKeyId","transparencyHead":${expectedHead?.let(::jsonString) ?: "null"}}"""

    private fun jsonString(value: String): String =
        buildString(value.length + 2) {
            append('"')
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(character)
                }
            }
            append('"')
        }
}
