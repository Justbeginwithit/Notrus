package com.notrus.android.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.notrus.android.model.ClientIntegrityReport
import java.security.MessageDigest
import java.time.Instant

object DeviceRiskSignals {
    fun capture(context: Context): ClientIntegrityReport {
        val packageManager = context.packageManager
        val packageName = context.packageName
        val installer = runCatching {
            packageManager.getInstallSourceInfo(packageName).installingPackageName ?: "unknown-installer"
        }.getOrDefault("unknown-installer")

        val isDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val isEmulator = isEmulator()
        val hasStrongBox = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val signatureDigest = runCatching {
            val info = packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
            )
            val signer = info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() ?: byteArrayOf()
            MessageDigest.getInstance("SHA-256")
                .digest(signer)
                .joinToString("") { "%02x".format(it) }
                .take(16)
        }.getOrDefault("unknown")

        val codeSignatureStatus = when {
            signatureDigest == "unknown" -> "missing"
            isDebuggable -> "debuggable"
            else -> "valid"
        }

        val deviceCheckStatus = when {
            isEmulator -> "emulator"
            hasStrongBox -> "keystore-attestation-ready"
            else -> "keystore-only"
        }

        val note = buildList {
            add("installer=$installer")
            add("signer=$signatureDigest")
            if (hasStrongBox) add("strongbox")
            if (isEmulator) add("emulator")
        }.joinToString(", ")

        val riskLevel = when {
            isDebuggable || isEmulator -> "high"
            hasStrongBox -> "low"
            else -> "medium"
        }

        return ClientIntegrityReport(
            bundleIdentifier = packageName,
            codeSignatureStatus = codeSignatureStatus,
            deviceCheckStatus = deviceCheckStatus,
            deviceCheckToken = null,
            deviceCheckTokenPresented = false,
            playIntegrityToken = null,
            playIntegrityTokenPresented = false,
            generatedAt = Instant.now().toString(),
            note = note,
            riskLevel = riskLevel,
        )
    }

    private fun isEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        return fingerprint.contains("generic") ||
            fingerprint.contains("emulator") ||
            model.contains("sdk") ||
            Build.HARDWARE.lowercase().contains("ranchu")
    }
}
