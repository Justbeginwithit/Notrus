package com.notrus.android.notifications

import android.app.ActivityManager
import android.content.Context
import android.os.Process
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.notrus.android.BuildConfig
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.MessageCachePolicy
import com.notrus.android.model.NotificationContentVisibility
import com.notrus.android.model.RelayMessage
import com.notrus.android.model.RelayThread
import com.notrus.android.model.RelayUser
import com.notrus.android.model.StoredIdentityRecord
import com.notrus.android.protocol.StandardsSignalClient
import com.notrus.android.relay.RelayClient
import com.notrus.android.security.DeviceIdentityProvider
import com.notrus.android.security.DeviceRiskSignals
import com.notrus.android.security.VaultStore
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

private const val DIRECT_PROTOCOL = "signal-pqxdh-double-ratchet-v1"
private const val GROUP_PROTOCOL = "mls-rfc9420-v1"
private const val MLS_FANOUT_FORMAT = "notrus-mls-signal-fanout-v1"

class NotrusBackgroundSyncWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    private val appContext = context.applicationContext
    private val vaultStore = VaultStore(appContext)
    private val deviceIdentityProvider = DeviceIdentityProvider()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        var scheduleFollowupRolling = false
        try {
            val notificationPrefs = NotrusNotificationPrefs.notificationPreferences(appContext)
            if (!notificationPrefs.enabled) {
                cancelAll(appContext)
                return@withContext Result.success()
            }
            scheduleFollowupRolling = true

            val catalog = vaultStore.loadCatalog()
            if (catalog.identities.isEmpty()) {
                scheduleRolling(appContext)
                return@withContext Result.success()
            }
            val appInstanceId = NotrusNotificationPrefs.appInstanceId(appContext)
            val relayOrigin = readRelayOrigin()
            val currentDevice = deviceIdentityProvider.descriptor(appContext, appInstanceId)
            val integrityReport = DeviceRiskSignals.capture(appContext)
            val privacyModeEnabled = appContext
                .getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
                .getBoolean(NotrusNotificationPrefs.KEY_PRIVACY_MODE_ENABLED, false)

            val bootstrapClient = RelayClient(
                origin = relayOrigin,
                integrityReport = integrityReport,
                appInstanceId = appInstanceId,
                deviceDescriptor = currentDevice,
                sessionToken = null,
            )
            fun routineClient(token: String?): RelayClient = RelayClient(
                origin = relayOrigin,
                integrityReport = integrityReport,
                appInstanceId = appInstanceId,
                deviceDescriptor = currentDevice,
                sessionToken = token,
            )

            val threadNotifications = mutableListOf<ThreadNotificationPayload>()
            val updatedRecordById = mutableMapOf<String, StoredIdentityRecord>()
            var failedIdentities = 0
            val shouldNotifyNow = shouldPostNotifications()

            catalog.identities.forEach { record ->
                runCatching {
                    var mergedIdentity = refreshIdentityMaterial(record.identity)
                    var activeSession = NotrusNotificationPrefs.loadRelaySessionForIdentity(appContext, mergedIdentity.id)

                    if (!NotrusNotificationPrefs.sessionIsUsable(activeSession)) {
                        val registration = bootstrapClient.register(mergedIdentity)
                        activeSession = registration.session
                        mergedIdentity = mergeRegisteredIdentity(mergedIdentity, registration.user)
                    }

                    NotrusNotificationPrefs.saveRelaySessionForIdentity(appContext, mergedIdentity.id, activeSession)
                    if (catalog.activeIdentityId == mergedIdentity.id) {
                        NotrusNotificationPrefs.saveRelaySession(appContext, activeSession)
                    }

                    var scopedRelay = routineClient(activeSession?.token)
                    val sync = runCatching { scopedRelay.sync() }.getOrElse {
                        val registration = bootstrapClient.register(mergedIdentity)
                        activeSession = registration.session
                        NotrusNotificationPrefs.saveRelaySessionForIdentity(appContext, mergedIdentity.id, activeSession)
                        if (catalog.activeIdentityId == mergedIdentity.id) {
                            NotrusNotificationPrefs.saveRelaySession(appContext, activeSession)
                        }
                        mergedIdentity = mergeRegisteredIdentity(mergedIdentity, registration.user)
                        scopedRelay = routineClient(activeSession?.token)
                        scopedRelay.sync()
                    }

                    runCatching {
                        scopedRelay.registerNotificationWakeup(
                            mode = "workmanager-poll-v1",
                            platform = "android",
                            registrationId = NotrusNotificationPrefs.wakeupRegistrationId(appContext, currentDevice.id),
                        )
                    }

                    val usersById = sync.users.associateBy { it.id }
                    val updatedRecord = mergeRelayEnvelopesForRecord(
                        record = record.copy(identity = mergedIdentity),
                        relayThreads = sync.threads,
                    )
                    val seenIds = NotrusNotificationPrefs.loadSeenMessageIds(appContext, mergedIdentity.id)
                    val primed = NotrusNotificationPrefs.isIdentityNotificationPrimed(appContext, mergedIdentity.id)
                    if (!primed) {
                        sync.threads.asSequence()
                            .flatMap { it.messages.asSequence() }
                            .filter { it.senderId != mergedIdentity.id }
                            .mapNotNull { it.id.trim().takeIf(String::isNotBlank) }
                            .forEach { seenIds.add(it) }
                        NotrusNotificationPrefs.saveSeenMessageIds(appContext, mergedIdentity.id, seenIds)
                        NotrusNotificationPrefs.markIdentityNotificationPrimed(appContext, mergedIdentity.id)
                        updatedRecordById[mergedIdentity.id] = updatedRecord
                        return@runCatching
                    }

                    var previewSignalState = mergedIdentity.standardsSignalState

                    sync.threads.forEach { thread ->
                        val localThreadRecord = updatedRecord.threadRecords[thread.id]
                        if (localThreadRecord?.mutedAt != null) {
                            return@forEach
                        }
                        val incoming = thread.messages
                            .filter { it.senderId != mergedIdentity.id }
                            .filter { it.id.isNotBlank() }
                            .filterNot { seenIds.contains(it.id) }
                        if (incoming.isEmpty()) {
                            return@forEach
                        }

                        val orderedIncoming = incoming.sortedBy { it.createdAt }
                        val newestIncoming = orderedIncoming.last()
                        val senderName = usersById[newestIncoming.senderId]?.displayName?.ifBlank { null }
                            ?: usersById[newestIncoming.senderId]?.username?.ifBlank { null }
                        var newestPreview: String? = null
                        if (shouldAttemptNotificationPreview(notificationPrefs, privacyModeEnabled, shouldNotifyNow, thread) && previewSignalState != null) {
                            orderedIncoming.forEach { incomingMessage ->
                                val previewResult = decryptPreview(
                                    identityId = mergedIdentity.id,
                                    message = incomingMessage,
                                    signalState = previewSignalState!!,
                                    thread = thread,
                                )
                                if (previewResult != null) {
                                    previewSignalState = previewResult.updatedSignalState
                                    if (incomingMessage.id == newestIncoming.id) {
                                        newestPreview = previewResult.previewText
                                    }
                                }
                            }
                        }

                        threadNotifications += ThreadNotificationPayload(
                            identityId = mergedIdentity.id,
                            threadId = thread.id,
                            senderName = senderName,
                            messagePreview = newestPreview,
                            messageCount = incoming.size,
                            messageIds = incoming.map { it.id },
                            isGroup = thread.participantIds.size > 2,
                        )
                        if (!shouldNotifyNow) {
                            incoming.forEach { seenIds.add(it.id) }
                        }
                    }

                    NotrusNotificationPrefs.saveSeenMessageIds(appContext, mergedIdentity.id, seenIds)
                    updatedRecordById[mergedIdentity.id] = updatedRecord.copy(identity = mergedIdentity)
                }.onFailure {
                    failedIdentities += 1
                }
            }

            persistUpdatedRecords(
                catalog = catalog,
                updatedRecords = updatedRecordById,
            )

            if (shouldNotifyNow) {
                threadNotifications.forEach { payload ->
                    val posted = NotrusNotificationCenter.postThreadNotification(
                        context = appContext,
                        settings = notificationPrefs,
                        privacyModeEnabled = privacyModeEnabled,
                        payload = payload,
                    )
                    if (posted) {
                        val seenIds = NotrusNotificationPrefs.loadSeenMessageIds(appContext, payload.identityId)
                        payload.messageIds.forEach { seenIds.add(it) }
                        NotrusNotificationPrefs.saveSeenMessageIds(appContext, payload.identityId, seenIds)
                    }
                }
            }

            if (failedIdentities == catalog.identities.size) {
                Result.retry()
            } else {
                Result.success()
            }
        } catch (error: Exception) {
            Result.retry()
        } finally {
            if (scheduleFollowupRolling) {
                scheduleRolling(appContext)
            }
        }
    }

    private fun shouldPostNotifications(): Boolean {
        if (!NotrusNotificationPrefs.isAppForeground(appContext)) {
            return true
        }
        val manager = appContext.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return true
        val process = manager.runningAppProcesses?.firstOrNull { it.pid == Process.myPid() } ?: return true
        return process.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND &&
            process.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE
    }

    private fun shouldAttemptNotificationPreview(
        settings: NotrusNotificationPreferences,
        privacyModeEnabled: Boolean,
        shouldNotifyNow: Boolean,
        thread: RelayThread,
    ): Boolean {
        if (!shouldNotifyNow) {
            return false
        }
        val effectiveVisibility = if (privacyModeEnabled && !settings.privacyModeOverride) {
            NotificationContentVisibility.Hidden
        } else {
            NotificationContentVisibility.fromKey(settings.contentVisibility)
        }
        if (effectiveVisibility != NotificationContentVisibility.FullPreview) {
            return false
        }
        return thread.participantIds.size <= 2 || settings.groupPreviewEnabled
    }

    private fun readRelayOrigin(): String {
        val settings = appContext.getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
        val configured = settings.getString(NotrusNotificationPrefs.KEY_RELAY_ORIGIN, null)?.trim().orEmpty()
        val candidate = if (configured.isBlank()) BuildConfig.DEFAULT_RELAY_ORIGIN else configured
        return RelayClient.validateOrigin(candidate)
    }

    private fun refreshIdentityMaterial(identity: LocalIdentity): LocalIdentity {
        val signalState = identity.standardsSignalState ?: return identity
        val refreshed = StandardsSignalClient.refreshBundle(signalState)
        return identity.copy(
            standardsSignalReady = true,
            standardsSignalBundle = refreshed.bundle,
            standardsSignalState = refreshed.state,
        )
    }

    private fun mergeRegisteredIdentity(identity: LocalIdentity, user: RelayUser): LocalIdentity =
        identity.copy(
            displayName = user.displayName.ifBlank { identity.displayName },
            directoryCode = user.directoryCode ?: identity.directoryCode,
            username = user.username.ifBlank { identity.username },
        )

    private fun mergeRelayEnvelopesForRecord(
        record: StoredIdentityRecord,
        relayThreads: List<RelayThread>,
    ): StoredIdentityRecord {
        var changed = false
        val updatedThreadRecords = record.threadRecords.toMutableMap()
        relayThreads.forEach { thread ->
            if (thread.messages.isEmpty()) {
                return@forEach
            }
            val existing = updatedThreadRecords[thread.id]
            var nextRecord = existing ?: ConversationThreadRecord(
                protocol = thread.protocol,
                signalPeerUserId = if (thread.protocol == DIRECT_PROTOCOL) {
                    thread.participantIds.firstOrNull { it != record.identity.id }
                } else {
                    null
                },
            )
            var nextCache = nextRecord.messageCache
            thread.messages.forEach { message ->
                val merged = MessageCachePolicy.mergeRelayEnvelope(nextCache[message.id], message)
                if (merged != nextCache[message.id]) {
                    nextCache = nextCache + (message.id to merged)
                    changed = true
                }
            }
            nextRecord = nextRecord.copy(
                messageCache = nextCache,
                protocol = thread.protocol,
                signalPeerUserId = if (thread.protocol == DIRECT_PROTOCOL) {
                    nextRecord.signalPeerUserId ?: thread.participantIds.firstOrNull { it != record.identity.id }
                } else {
                    nextRecord.signalPeerUserId
                },
            )
            updatedThreadRecords[thread.id] = nextRecord
        }
        return if (changed) {
            record.copy(threadRecords = updatedThreadRecords)
        } else {
            record
        }
    }

    private fun persistUpdatedRecords(
        catalog: com.notrus.android.model.IdentityCatalog,
        updatedRecords: Map<String, StoredIdentityRecord>,
    ) {
        if (updatedRecords.isEmpty()) {
            return
        }
        var changed = false
        val nextRecords = catalog.identities.map { record ->
            val updatedRecord = updatedRecords[record.identity.id]
            if (updatedRecord != null && updatedRecord != record) {
                changed = true
                updatedRecord
            } else {
                record
            }
        }
        if (!changed) {
            return
        }
        vaultStore.saveCatalog(
            catalog.copy(
                identities = nextRecords,
                activeIdentityId = catalog.activeIdentityId ?: nextRecords.firstOrNull()?.identity?.id,
            ),
        )
    }

    private fun decryptPreview(
        identityId: String,
        message: RelayMessage,
        signalState: com.notrus.android.model.SignalProtocolState,
        thread: RelayThread,
    ): PreviewDecryptResult? {
        val directResult = if (thread.protocol == DIRECT_PROTOCOL) {
            decryptDirectPreview(
                identityId = identityId,
                message = message,
                signalState = signalState,
            )
        } else {
            null
        }
        if (directResult != null) {
            return directResult
        }
        return if (thread.protocol == GROUP_PROTOCOL) {
            decryptGroupPreview(
                identityId = identityId,
                message = message,
                signalState = signalState,
            )
        } else {
            null
        }
    }

    private fun decryptDirectPreview(
        identityId: String,
        message: RelayMessage,
        signalState: com.notrus.android.model.SignalProtocolState,
    ): PreviewDecryptResult? {
        val messageKind = message.messageKind ?: return null
        val wireMessage = message.wireMessage ?: return null
        return runCatching {
            val opened = StandardsSignalClient.decrypt(
                state = signalState,
                localUserId = identityId,
                messageKind = messageKind,
                remoteUserId = message.senderId,
                wireMessage = wireMessage,
            )
            PreviewDecryptResult(
                previewText = decodeStandardsPayload(opened.plaintext),
                updatedSignalState = opened.state,
            )
        }.getOrNull()
    }

    private fun decryptGroupPreview(
        identityId: String,
        message: RelayMessage,
        signalState: com.notrus.android.model.SignalProtocolState,
    ): PreviewDecryptResult? {
        if (message.messageKind != "mls-application") {
            return null
        }
        val envelope = decodeMlsFanoutEnvelope(message.wireMessage) ?: return null
        if (envelope.senderId != message.senderId) {
            return null
        }
        val recipient = envelope.recipients.firstOrNull { it.toUserId == identityId } ?: return null
        return runCatching {
            val opened = StandardsSignalClient.decrypt(
                state = signalState,
                localUserId = identityId,
                messageKind = recipient.messageKind,
                remoteUserId = message.senderId,
                wireMessage = recipient.wireMessage,
            )
            PreviewDecryptResult(
                previewText = decodeStandardsPayload(opened.plaintext),
                updatedSignalState = opened.state,
            )
        }.getOrNull()
    }

    private fun decodeMlsFanoutEnvelope(wireMessage: String?): MlsFanoutEnvelope? {
        if (wireMessage.isNullOrBlank()) {
            return null
        }
        val json = runCatching { JSONObject(wireMessage) }.getOrNull() ?: return null
        if (!json.optString("format").equals(MLS_FANOUT_FORMAT, ignoreCase = false)) {
            return null
        }
        val senderId = json.optString("senderId").trim()
        if (senderId.isBlank()) {
            return null
        }
        if (json.optInt("version", 0) != 1) {
            return null
        }
        val recipients = mutableListOf<MlsFanoutRecipientEnvelope>()
        val recipientArray = json.optJSONArray("recipients") ?: JSONArray()
        for (index in 0 until recipientArray.length()) {
            val recipient = recipientArray.optJSONObject(index) ?: continue
            val messageKind = recipient.optString("messageKind").trim()
            val toUserId = recipient.optString("toUserId").trim()
            val recipientWire = recipient.optString("wireMessage").trim()
            if (messageKind.isBlank() || toUserId.isBlank() || recipientWire.isBlank()) {
                continue
            }
            recipients += MlsFanoutRecipientEnvelope(
                messageKind = messageKind,
                toUserId = toUserId,
                wireMessage = recipientWire,
            )
        }
        if (recipients.isEmpty()) {
            return null
        }
        return MlsFanoutEnvelope(
            format = MLS_FANOUT_FORMAT,
            senderId = senderId,
            version = 1,
            recipients = recipients,
        )
    }

    private fun decodeStandardsPayload(plaintext: String): String {
        val normalizedLegacy = normalizeLegacyDisplayBody(plaintext)
        val envelope = runCatching { JSONObject(plaintext) }.getOrNull() ?: return normalizedLegacy
        if (envelope.optInt("version", 0) != 1) {
            return normalizedLegacy
        }
        return envelope.optString("text").ifBlank { normalizedLegacy }
    }

    private fun normalizeLegacyDisplayBody(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) {
            return raw
        }
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            runCatching {
                val json = JSONObject(trimmed)
                val text = json.optString("text").ifBlank {
                    json.optString("body").ifBlank {
                        json.optString("message")
                    }
                }
                if (text.isNotBlank()) {
                    return text
                }
            }
        }
        return trimmed
    }

    companion object {
        private const val PERIODIC_WORK_NAME = "notrus_background_sync_periodic"
        private const val IMMEDIATE_WORK_NAME = "notrus_background_sync_now"
        private const val ROLLING_WORK_NAME = "notrus_background_sync_rolling"
        private const val ROLLING_DELAY_MINUTES = 2L

        fun schedulePeriodic(context: Context) {
            val request = PeriodicWorkRequestBuilder<NotrusBackgroundSyncWorker>(15, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(PERIODIC_WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
        }

        fun scheduleRolling(context: Context) {
            val request = OneTimeWorkRequestBuilder<NotrusBackgroundSyncWorker>()
                .setInitialDelay(ROLLING_DELAY_MINUTES, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork(ROLLING_WORK_NAME, ExistingWorkPolicy.REPLACE, request)
        }

        fun enqueueImmediate(context: Context) {
            val request = OneTimeWorkRequestBuilder<NotrusBackgroundSyncWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork(IMMEDIATE_WORK_NAME, ExistingWorkPolicy.REPLACE, request)
        }

        fun cancelAll(context: Context) {
            WorkManager.getInstance(context).apply {
                cancelUniqueWork(PERIODIC_WORK_NAME)
                cancelUniqueWork(IMMEDIATE_WORK_NAME)
                cancelUniqueWork(ROLLING_WORK_NAME)
            }
        }
    }
}

private data class MlsFanoutRecipientEnvelope(
    val messageKind: String,
    val toUserId: String,
    val wireMessage: String,
)

private data class MlsFanoutEnvelope(
    val format: String,
    val senderId: String,
    val version: Int,
    val recipients: List<MlsFanoutRecipientEnvelope>,
)

private data class PreviewDecryptResult(
    val previewText: String,
    val updatedSignalState: com.notrus.android.model.SignalProtocolState,
)
