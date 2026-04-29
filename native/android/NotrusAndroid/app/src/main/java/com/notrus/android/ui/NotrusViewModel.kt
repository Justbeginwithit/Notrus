package com.notrus.android.ui

import android.app.Application
import android.app.ActivityManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.notrus.android.BuildConfig
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notrus.android.model.AccountResetRequest
import com.notrus.android.model.AndroidContactTrustRecord
import com.notrus.android.model.AppUiState
import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ConversationThread
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.DecryptedMessage
import com.notrus.android.model.DeviceInventoryAlias
import com.notrus.android.model.DeviceInventoryProfile
import com.notrus.android.model.IdentityCatalog
import com.notrus.android.model.LocalDeviceInventory
import com.notrus.android.model.LocalAttachmentDraft
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.MessageCachePolicy
import com.notrus.android.model.NotificationContentVisibility
import com.notrus.android.model.NotificationLockscreenVisibility
import com.notrus.android.model.RelayMessage
import com.notrus.android.model.RelayThread
import com.notrus.android.model.RelayUser
import com.notrus.android.model.SecureAttachmentReference
import com.notrus.android.model.StoredIdentityRecord
import com.notrus.android.model.selectedThread
import com.notrus.android.notifications.NotrusBackgroundSyncWorker
import com.notrus.android.notifications.NotrusNotificationCenter
import com.notrus.android.notifications.NotrusNotificationPrefs
import com.notrus.android.notifications.NotrusNotificationService
import com.notrus.android.protocol.ProtocolCatalog
import com.notrus.android.protocol.StandardsSignalClient
import com.notrus.android.relay.RelayClient
import com.notrus.android.security.AttachmentCrypto
import com.notrus.android.security.BiometricGate
import com.notrus.android.security.DeviceAliasSnapshot
import com.notrus.android.security.DeviceIdentityProvider
import com.notrus.android.security.HardwareAliasSnapshot
import com.notrus.android.security.DeviceRiskSignals
import com.notrus.android.security.RecoveryArchiveManager
import com.notrus.android.security.RecoveryKeyManager
import com.notrus.android.security.StrongBoxIdentityProvider
import com.notrus.android.security.TransparencyVerifier
import com.notrus.android.security.VaultStore
import com.notrus.android.ui.theme.NotrusColorTheme
import com.notrus.android.ui.theme.NotrusThemeMode
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import kotlin.random.Random

private const val DIRECT_PROTOCOL = "signal-pqxdh-double-ratchet-v1"
private const val GROUP_PROTOCOL = "mls-rfc9420-v1"
private const val MLS_FANOUT_CIPHERSUITE = "MLS-compat-signal-fanout-v1"
private const val MLS_FANOUT_FORMAT = "notrus-mls-signal-fanout-v1"
private const val MAX_PENDING_ATTACHMENT_DRAFTS = 8
private val localIpv4LoopbackHost = listOf(127, 0, 0, 1).joinToString(".")
private val androidEmulatorHost = listOf(10, 0, 2, 2).joinToString(".")
private val BOOTSTRAP_LOCAL_RELAY_ORIGINS = setOf(
    "http://$androidEmulatorHost:3000",
    "http://$localIpv4LoopbackHost:3000",
    "http://localhost:3000",
)

private data class MaterializedSyncState(
    val identity: LocalIdentity,
    val threadRecords: Map<String, ConversationThreadRecord>,
    val threads: List<ConversationThread>,
    val archivedThreads: List<ConversationThread>,
)

private data class StandardsMessagePayload(
    val attachments: List<SecureAttachmentReference>,
    val text: String,
)

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

private enum class PrivacyDelayKind {
    Sync,
    Interactive,
    Delivery,
}

private enum class SyncPresentation {
    Interactive,
    Silent,
}

private data class PreparedAndroidArchiveExport(
    val bytes: ByteArray,
    val displayName: String,
    val successMessage: String,
)

class NotrusViewModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(AppUiState())
        private set

    private val applicationContext = application.applicationContext
    private val vaultStore = VaultStore(applicationContext)
    private val deviceIdentityProvider = DeviceIdentityProvider()
    private val identityProvider = StrongBoxIdentityProvider()
    private var preparedProfileExport: PreparedAndroidArchiveExport? = null
    private var preparedChatBackupExport: PreparedAndroidArchiveExport? = null
    private val settings = applicationContext.getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
    private val defaultRemoteRelayOrigin = BuildConfig.DEFAULT_RELAY_ORIGIN.trim()
    private val defaultEnhancedVisualsEnabled = !isLowRamDevice(applicationContext)
    private val appInstanceId = settings.getString(NotrusNotificationPrefs.KEY_APP_INSTANCE_ID, null)
        ?: UUID.randomUUID().toString().also {
            settings.edit().putString(NotrusNotificationPrefs.KEY_APP_INSTANCE_ID, it).apply()
        }
    private var lastSensitiveAuthAtMs: Long = 0L
    private var relaySession: com.notrus.android.model.RelaySession? =
        NotrusNotificationPrefs.loadRelaySession(applicationContext)
    private var liveEventsJob: Job? = null
    private var liveSyncDebounceJob: Job? = null
    private var appInForeground: Boolean = false
    private var pendingNotificationThreadId: String? = null
    private val lastSentReadReceiptByThread = mutableMapOf<String, String>()

    init {
        val integrity = DeviceRiskSignals.capture(applicationContext)
        state = state.copy(
            currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId),
            integrityReport = integrity,
            privacyModeEnabled = settings.getBoolean(KEY_PRIVACY_MODE_ENABLED, false),
            notificationsEnabled = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATIONS_ENABLED, true),
            notificationRealtimeEnabled = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_REALTIME_ENABLED, true),
            notificationContentVisibility = settings.getString(
                NotrusNotificationPrefs.KEY_NOTIFICATION_CONTENT_VISIBILITY,
                NotificationContentVisibility.Hidden.key,
            ) ?: NotificationContentVisibility.Hidden.key,
            notificationLockscreenVisibility = settings.getString(
                NotrusNotificationPrefs.KEY_NOTIFICATION_LOCKSCREEN_VISIBILITY,
                NotificationLockscreenVisibility.Private.key,
            ) ?: NotificationLockscreenVisibility.Private.key,
            notificationGroupPreviewEnabled = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_GROUP_PREVIEW_ENABLED, false),
            notificationPrivacyModeOverride = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_PRIVACY_MODE_OVERRIDE, false),
            notificationSoundEnabled = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_SOUND_ENABLED, true),
            notificationVibrationEnabled = settings.getBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_VIBRATION_ENABLED, true),
            visualEffectsEnabled = settings.getBoolean(KEY_VISUAL_EFFECTS_ENABLED, defaultEnhancedVisualsEnabled),
            colorThemePreset = settings.getString(
                KEY_COLOR_THEME_PRESET,
                NotrusColorTheme.Default.key,
            ) ?: NotrusColorTheme.Default.key,
            themeMode = settings.getString(
                KEY_THEME_MODE,
                NotrusThemeMode.Default.key,
            ) ?: NotrusThemeMode.Default.key,
            sendReadReceiptsToOthers = settings.getBoolean(KEY_SEND_READ_RECEIPTS_TO_OTHERS, true),
            relayOriginInput = bootstrapRelayOrigin(settings.getString(KEY_RELAY_ORIGIN, null)),
            witnessOriginsInput = settings.getString(KEY_WITNESS_ORIGINS, "") ?: "",
        )
        NotrusNotificationCenter.ensureChannels(applicationContext)
        if (state.notificationsEnabled) {
            NotrusBackgroundSyncWorker.schedulePeriodic(applicationContext)
            NotrusBackgroundSyncWorker.scheduleRolling(applicationContext)
            if (state.notificationRealtimeEnabled) {
                NotrusNotificationService.startIfAllowed(applicationContext)
            }
        } else {
            NotrusBackgroundSyncWorker.cancelAll(applicationContext)
            NotrusNotificationService.stop(applicationContext)
        }
        refreshDeviceInventory()
        bootstrap()
    }

    fun updateRelayOrigin(value: String) {
        updateRelaySession(null)
        stopLiveEvents()
        state = state.copy(relayOriginInput = value, errorMessage = null, relayHealth = null)
        settings.edit().putString(KEY_RELAY_ORIGIN, value).apply()
    }

    fun updatePrivacyMode(enabled: Boolean) {
        state = state.copy(privacyModeEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(KEY_PRIVACY_MODE_ENABLED, enabled).apply()
    }

    fun updateNotificationsEnabled(enabled: Boolean) {
        state = state.copy(notificationsEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATIONS_ENABLED, enabled).apply()
        if (enabled) {
            NotrusNotificationCenter.ensureChannels(applicationContext)
            NotrusBackgroundSyncWorker.schedulePeriodic(applicationContext)
            NotrusBackgroundSyncWorker.scheduleRolling(applicationContext)
            NotrusBackgroundSyncWorker.enqueueImmediate(applicationContext)
            if (state.notificationRealtimeEnabled) {
                NotrusNotificationService.startIfAllowed(applicationContext)
            }
            startLiveEventsIfPossible()
        } else {
            val currentDeviceId = state.currentDevice?.id
            if (sessionIsUsable() && !currentDeviceId.isNullOrBlank()) {
                viewModelScope.launch {
                    runCatching {
                        relayClient().unregisterNotificationWakeup(
                            registrationId = NotrusNotificationPrefs.wakeupRegistrationId(
                                applicationContext,
                                currentDeviceId,
                            ),
                        )
                    }
                }
            }
            if (!appInForeground) {
                stopLiveEvents()
            }
            NotrusBackgroundSyncWorker.cancelAll(applicationContext)
            NotrusNotificationService.stop(applicationContext)
        }
    }

    fun updateNotificationRealtimeEnabled(enabled: Boolean) {
        state = state.copy(notificationRealtimeEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_REALTIME_ENABLED, enabled).apply()
        if (state.notificationsEnabled && enabled) {
            NotrusBackgroundSyncWorker.schedulePeriodic(applicationContext)
            NotrusBackgroundSyncWorker.scheduleRolling(applicationContext)
            NotrusBackgroundSyncWorker.enqueueImmediate(applicationContext)
            NotrusNotificationService.startIfAllowed(applicationContext)
        } else {
            NotrusNotificationService.stop(applicationContext)
        }
    }

    fun updateNotificationContentVisibility(value: String) {
        val resolved = NotificationContentVisibility.fromKey(value).key
        state = state.copy(notificationContentVisibility = resolved, errorMessage = null)
        settings.edit().putString(NotrusNotificationPrefs.KEY_NOTIFICATION_CONTENT_VISIBILITY, resolved).apply()
    }

    fun updateNotificationLockscreenVisibility(value: String) {
        val resolved = NotificationLockscreenVisibility.fromKey(value).key
        state = state.copy(notificationLockscreenVisibility = resolved, errorMessage = null)
        settings.edit().putString(NotrusNotificationPrefs.KEY_NOTIFICATION_LOCKSCREEN_VISIBILITY, resolved).apply()
    }

    fun updateNotificationGroupPreviewEnabled(enabled: Boolean) {
        state = state.copy(notificationGroupPreviewEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_GROUP_PREVIEW_ENABLED, enabled).apply()
    }

    fun updateNotificationPrivacyModeOverride(enabled: Boolean) {
        state = state.copy(notificationPrivacyModeOverride = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_PRIVACY_MODE_OVERRIDE, enabled).apply()
    }

    fun updateNotificationSoundEnabled(enabled: Boolean) {
        state = state.copy(notificationSoundEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_SOUND_ENABLED, enabled).apply()
    }

    fun updateNotificationVibrationEnabled(enabled: Boolean) {
        state = state.copy(notificationVibrationEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(NotrusNotificationPrefs.KEY_NOTIFICATION_VIBRATION_ENABLED, enabled).apply()
    }

    fun updateSendReadReceiptsToOthers(enabled: Boolean) {
        state = state.copy(sendReadReceiptsToOthers = enabled, errorMessage = null)
        settings.edit().putBoolean(KEY_SEND_READ_RECEIPTS_TO_OTHERS, enabled).apply()
        if (enabled) {
            state.selectedThreadId?.let(::sendReadReceiptForThreadId)
        }
    }

    fun updateVisualEffects(enabled: Boolean) {
        state = state.copy(visualEffectsEnabled = enabled, errorMessage = null)
        settings.edit().putBoolean(KEY_VISUAL_EFFECTS_ENABLED, enabled).apply()
    }

    fun updateColorTheme(themeKey: String) {
        val resolved = NotrusColorTheme.fromKey(themeKey).key
        state = state.copy(colorThemePreset = resolved, errorMessage = null)
        settings.edit().putString(KEY_COLOR_THEME_PRESET, resolved).apply()
    }

    fun updateThemeMode(themeModeKey: String) {
        val resolved = NotrusThemeMode.fromKey(themeModeKey).key
        state = state.copy(themeMode = resolved, errorMessage = null)
        settings.edit().putString(KEY_THEME_MODE, resolved).apply()
    }

    fun updateOnboardingDisplayName(value: String) {
        state = state.copy(onboardingDisplayName = value)
    }

    fun updateOnboardingUsername(value: String) {
        state = state.copy(
            onboardingUsername = value.lowercase().filter { it.isLetterOrDigit() || it == '_' || it == '.' },
        )
    }

    fun updateExportPassphrase(value: String) {
        state = state.copy(exportPassphrase = value)
    }

    fun updateImportPassphrase(value: String) {
        state = state.copy(importPassphrase = value)
    }

    fun updateChatBackupPassphrase(value: String) {
        state = state.copy(chatBackupPassphrase = value)
    }

    fun updateChatBackupImportPassphrase(value: String) {
        state = state.copy(chatBackupImportPassphrase = value)
    }

    fun canChooseRecoveryExportDestination(): Boolean {
        if (state.currentIdentity == null) {
            state = state.copy(errorMessage = "Choose a local Android profile before exporting account recovery.")
            return false
        }
        if (state.exportPassphrase.trim().length < 8) {
            state = state.copy(errorMessage = "Use an account-recovery export passphrase with at least 8 characters.")
            return false
        }
        return true
    }

    fun canChooseRecoveryImportFile(): Boolean {
        if (state.importPassphrase.trim().length < 8) {
            state = state.copy(errorMessage = "Use the recovery archive passphrase before choosing a file.")
            return false
        }
        return true
    }

    fun canChooseChatBackupExportDestination(): Boolean {
        if (state.currentIdentity == null) {
            state = state.copy(errorMessage = "Choose a local Android profile before exporting chat history.")
            return false
        }
        if (state.chatBackupPassphrase.trim().length < 8) {
            state = state.copy(errorMessage = "Use a chat-backup passphrase with at least 8 characters before choosing where to save.")
            return false
        }
        return true
    }

    fun canChooseChatBackupImportFile(): Boolean {
        if (state.currentIdentity == null) {
            state = state.copy(errorMessage = "Recover or create the account before restoring chat history.")
            return false
        }
        if (state.chatBackupImportPassphrase.trim().length < 8) {
            state = state.copy(errorMessage = "Use the chat-backup passphrase before choosing a backup file.")
            return false
        }
        return true
    }

    fun updateWitnessOrigins(value: String) {
        state = state.copy(witnessOriginsInput = value, errorMessage = null)
        settings.edit().putString(KEY_WITNESS_ORIGINS, value).apply()
    }

    fun updateDirectoryQuery(value: String) {
        state = state.copy(directoryQuery = value, errorMessage = null)
    }

    fun updateDraftText(value: String) {
        state = state.copy(draftText = value)
    }

    fun addPendingAttachment(uri: Uri) {
        val thread = state.selectedThread
        if (thread == null) {
            state = state.copy(errorMessage = "Open a conversation before adding attachments on Android.")
            return
        }
        if (!thread.supported || thread.protocol != DIRECT_PROTOCOL) {
            state = state.copy(errorMessage = "Android attachment send is currently available on standards direct chats only.")
            return
        }
        if (state.pendingAttachments.size >= MAX_PENDING_ATTACHMENT_DRAFTS) {
            state = state.copy(errorMessage = "Android currently allows up to $MAX_PENDING_ATTACHMENT_DRAFTS attachments per message.")
            return
        }

        viewModelScope.launch {
            runCatching {
                val draft = resolveAttachmentDraft(uri)
                if (state.pendingAttachments.any { it.uri == draft.uri }) {
                    return@runCatching
                }
                val updated = (state.pendingAttachments + draft).take(MAX_PENDING_ATTACHMENT_DRAFTS)
                state = state.copy(
                    pendingAttachments = updated,
                    statusMessage = "Added ${draft.fileName} to this Android message.",
                    errorMessage = null,
                )
            }.onFailure { error ->
                state = state.copy(errorMessage = error.message)
            }
        }
    }

    fun removePendingAttachment(attachmentId: String) {
        state = state.copy(
            pendingAttachments = state.pendingAttachments.filterNot { it.id == attachmentId },
            errorMessage = null,
        )
    }

    fun saveAttachment(
        activity: FragmentActivity,
        threadId: String,
        reference: SecureAttachmentReference,
        destinationUri: Uri,
    ) {
        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize decrypting and exporting an encrypted attachment on Android.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Decrypting and saving attachment on Android...")
            runCatching {
                val thread = state.threads.firstOrNull { it.id == threadId }
                    ?: error("This Android conversation is no longer available. Sync and try again.")
                val mailboxHandle = thread.mailboxHandle
                    ?: error("This Android conversation is missing its mailbox handle.")
                val deliveryCapability = thread.deliveryCapability
                    ?: error("This Android conversation is missing its delivery capability.")

                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Delivery)
                val encrypted = relayClient().fetchAttachment(
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    attachmentId = reference.id,
                )
                val plaintext = AttachmentCrypto.openAttachment(encrypted, reference)
                applicationContext.contentResolver.openOutputStream(destinationUri, "w")?.use { output ->
                    output.write(plaintext)
                } ?: error("Android could not open the selected destination.")
                state = state.copy(
                    isBusy = false,
                    statusMessage = "Saved ${reference.fileName} to the selected location.",
                    errorMessage = null,
                )
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message)
            }
        }
    }

    fun selectThread(threadId: String) {
        state = state.copy(
            selectedThreadId = threadId,
            pendingAttachments = if (state.selectedThreadId == threadId) state.pendingAttachments else emptyList(),
            errorMessage = null,
        )
        sendReadReceiptForThreadId(threadId)
    }

    fun clearSelectedThread() {
        state = state.copy(
            selectedThreadId = null,
            draftText = "",
            pendingAttachments = emptyList(),
            errorMessage = null,
        )
    }

    private fun sendReadReceiptForThreadId(threadId: String) {
        if (!state.sendReadReceiptsToOthers) {
            return
        }
        val identity = state.currentIdentity ?: return
        val thread = state.threads.firstOrNull { it.id == threadId } ?: return
        val latestRemoteMessage = thread.messages.lastOrNull { it.senderId != identity.id } ?: return
        if (lastSentReadReceiptByThread[thread.id] == latestRemoteMessage.id) {
            return
        }
        val mailboxHandle = thread.mailboxHandle ?: return
        val deliveryCapability = thread.deliveryCapability ?: return
        viewModelScope.launch {
            runCatching {
                relayClient().postReadReceipt(
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    lastReadMessageId = latestRemoteMessage.id,
                    readAt = Instant.now().toString(),
                )
                lastSentReadReceiptByThread[thread.id] = latestRemoteMessage.id
            }
        }
    }

    private fun readReceiptSummaryFor(
        message: RelayMessage,
        thread: RelayThread,
        participants: List<RelayUser>,
        identityId: String,
    ): String? {
        if (message.senderId != identityId) {
            return null
        }
        val messageIndex = thread.messages.indexOfFirst { it.id == message.id }
        if (messageIndex < 0) {
            return null
        }
        val indexByMessageId = thread.messages.mapIndexed { index, relayMessage ->
            relayMessage.id to index
        }.toMap()
        val readers = thread.readReceipts
            .asSequence()
            .filter { it.userId != identityId }
            .filter { receipt -> (indexByMessageId[receipt.lastReadMessageId] ?: -1) >= messageIndex }
            .mapNotNull { receipt -> participants.firstOrNull { it.id == receipt.userId }?.displayName }
            .distinct()
            .sorted()
            .toList()
        return when (readers.size) {
            0 -> null
            1 -> "Read by ${readers.first()}"
            else -> "Read by ${readers.size} people"
        }
    }

    fun onAppForegroundChanged(inForeground: Boolean) {
        appInForeground = inForeground
        NotrusNotificationPrefs.setAppForeground(applicationContext, inForeground)
        if (inForeground) {
            val identity = state.currentIdentity
            if (identity != null && !state.isBusy) {
                viewModelScope.launch {
                    if (sessionIsUsable()) {
                        startLiveEventsIfPossible()
                    } else {
                        registerAndSync(identity, presentation = SyncPresentation.Silent)
                    }
                }
            } else {
                startLiveEventsIfPossible()
            }
        } else {
            if (state.notificationsEnabled) {
                if (state.notificationRealtimeEnabled) {
                    NotrusNotificationService.startIfAllowed(applicationContext)
                }
                NotrusBackgroundSyncWorker.enqueueImmediate(applicationContext)
                stopLiveEvents()
            } else {
                stopLiveEvents()
            }
        }
    }

    fun onNotificationPermissionResult(granted: Boolean) {
        if (!granted) {
            updateNotificationsEnabled(false)
            state = state.copy(
                errorMessage = "Android notification permission is required for background message alerts.",
            )
            return
        }
        if (!state.notificationsEnabled) {
            return
        }
        NotrusNotificationCenter.ensureChannels(applicationContext)
        NotrusBackgroundSyncWorker.enqueueImmediate(applicationContext)
        if (state.notificationRealtimeEnabled) {
            NotrusNotificationService.startIfAllowed(applicationContext)
        }
        startLiveEventsIfPossible()
    }

    fun openThreadFromNotification(threadId: String?, identityId: String?) {
        val normalizedThreadId = threadId?.trim().orEmpty()
        if (normalizedThreadId.isBlank()) {
            return
        }
        if (!identityId.isNullOrBlank() && state.currentIdentity?.id != identityId) {
            val targetIdentity = state.profiles.firstOrNull { it.id == identityId }
            if (targetIdentity != null) {
                pendingNotificationThreadId = normalizedThreadId
                switchProfile(identityId)
                return
            }
        }

        if (state.threads.any { it.id == normalizedThreadId }) {
            selectThread(normalizedThreadId)
            return
        }

        pendingNotificationThreadId = normalizedThreadId
        state.currentIdentity?.let { identity ->
            viewModelScope.launch {
                registerAndSync(
                    identity = identity,
                    preferredThreadId = normalizedThreadId,
                    presentation = SyncPresentation.Silent,
                )
            }
        }
    }

    fun dismissStatusMessage(expectedMessage: String? = null) {
        if (expectedMessage == null || state.statusMessage == expectedMessage) {
            state = state.copy(statusMessage = DefaultStatusMessage)
        }
    }

    fun dismissErrorMessage(expectedMessage: String? = null) {
        if (expectedMessage == null || state.errorMessage == expectedMessage) {
            state = state.copy(errorMessage = null)
        }
    }

    fun resetTransparencyTrust() {
        val relayOrigin = runCatching { RelayClient.validateOrigin(state.relayOriginInput.ifBlank { defaultRemoteRelayOrigin }) }
            .getOrNull() ?: return
        clearPinnedValue(KEY_TRANSPARENCY_PINS, relayOrigin)
        clearPinnedValue(KEY_TRANSPARENCY_SIGNER_PINS, relayOrigin)
        state = state.copy(
            transparencyResetAvailable = false,
            statusMessage = "Reset Android transparency trust for this relay. Syncing the current key-directory state again...",
            errorMessage = null,
        )
        val identity = state.currentIdentity ?: return
        viewModelScope.launch {
            registerAndSync(identity)
        }
    }

    fun unlock(activity: FragmentActivity) {
        viewModelScope.launch {
            val available = BiometricGate.isAvailable(activity)
            if (!available) {
                state = state.copy(
                    errorMessage = "This Android profile requires device authentication, but no biometric or device-credential unlock is available here.",
                )
                return@launch
            }

            val unlocked = BiometricGate.authenticate(
                activity = activity,
                executor = activity.mainExecutor,
                title = "Unlock Notrus",
                subtitle = "Open the encrypted local vault for identities and relay state.",
            )

            if (!unlocked) {
                state = state.copy(errorMessage = "Vault unlock was cancelled.")
                return@launch
            }

            val catalog = vaultStore.loadCatalog()
            val profiles = catalog.identities.map { it.identity }
            val current = catalog.identities.firstOrNull { it.identity.id == catalog.activeIdentityId }?.identity
                ?: profiles.firstOrNull()
            updateRelaySession(null)

                state = state.copy(
                    currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId),
                    vaultLocked = false,
                    integrityReport = DeviceRiskSignals.capture(applicationContext),
                    profiles = profiles,
                    currentIdentity = current,
                    currentDirectoryCode = current?.directoryCode,
                    pendingAttachments = emptyList(),
                    statusMessage = "Vault unlocked on this Android device.",
                    errorMessage = null,
                )
            refreshDeviceInventory(catalog = catalog, currentDevice = state.currentDevice)
            lastSensitiveAuthAtMs = System.currentTimeMillis()

            if (current != null) {
                registerAndSync(current)
            }
        }
    }

    fun createProfile() {
        val displayName = state.onboardingDisplayName.trim()
        val username = state.onboardingUsername.trim().lowercase()

        if (displayName.length < 2 || username.length < 3) {
            state = state.copy(errorMessage = "Choose a display name and a username with at least 3 characters.")
            return
        }
        val localCatalog = vaultStore.loadCatalog()
        val existingLocal = localCatalog.identities.firstOrNull { it.identity.username.equals(username, ignoreCase = true) }
        if (existingLocal != null) {
            state = state.copy(
                errorMessage = "That username is already stored locally on this device as ${existingLocal.identity.displayName} (${existingLocal.identity.id}). Delete or switch that profile first.",
            )
            refreshDeviceInventory(catalog = localCatalog, currentDevice = state.currentDevice)
            return
        }

        viewModelScope.launch {
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Creating a hardware-backed Android identity...")
            var generatedIdentityId: String? = null
            runCatching {
                val relayOrigin = RelayClient.validateOrigin(state.relayOriginInput.ifBlank { defaultRemoteRelayOrigin })
                val currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId)
                state = state.copy(currentDevice = currentDevice)
                val hardware = identityProvider.createIdentity(username = username, displayName = displayName)
                generatedIdentityId = hardware.userId
                val recovery = RecoveryKeyManager.create()
                val standards = StandardsSignalClient.createIdentity()
                val identity = LocalIdentity(
                    id = hardware.userId,
                    username = hardware.username,
                    displayName = hardware.displayName,
                    createdAt = Instant.now().toString(),
                    directoryCode = null,
                    storageMode = hardware.storageMode,
                    fingerprint = hardware.fingerprint,
                    recoveryFingerprint = recovery.fingerprint,
                    recoveryPublicJwk = recovery.publicJwk,
                    signingPublicJwk = hardware.signingPublicJwk,
                    encryptionPublicJwk = hardware.encryptionPublicJwk,
                    prekeyCreatedAt = hardware.prekeyCreatedAt,
                    prekeyFingerprint = hardware.prekeyFingerprint,
                    prekeyPublicJwk = hardware.prekeyPublicJwk,
                    prekeySignature = hardware.prekeySignature,
                    standardsSignalReady = true,
                    standardsMlsReady = false,
                    standardsSignalBundle = standards.bundle,
                    standardsSignalState = standards.state,
                )
                val client = relayClient(relayOrigin)
                val relayHealth = client.health()
                val registered = client.register(identity)
                updateRelaySession(registered.session, identityId = identity.id)
                val registeredIdentity = mergeRegisteredIdentity(identity, registered.user)
                saveIdentity(registeredIdentity, recovery.recoveryRepresentation)
                state = state.copy(
                    currentDevice = currentDevice,
                    linkedDeviceEvents = registered.deviceEvents,
                    linkedDevices = registered.devices,
                    relayHealth = relayHealth,
                )
                registerAndSync(registeredIdentity)
            }.onFailure { error ->
                generatedIdentityId?.let { identityProvider.deleteIdentityAliases(it) }
                updateRelaySession(null, identityId = generatedIdentityId)
                state = state.copy(
                    isBusy = false,
                    errorMessage = renderProfileCreationError(error, username),
                )
            }
        }
    }

    fun prepareCurrentProfileExport(activity: FragmentActivity, onReady: (String) -> Unit) {
        val identity = state.currentIdentity ?: run {
            state = state.copy(errorMessage = "Choose a local Android profile before exporting a recovery archive.")
            return
        }
        val passphrase = state.exportPassphrase.trim()
        if (passphrase.length < 8) {
            state = state.copy(errorMessage = "Use an export passphrase with at least 8 characters.")
            return
        }

        viewModelScope.launch {
            try {
                if (!authorizeSensitiveOperation(activity, "Authorize exporting this Android recovery archive.", maxAgeMs = 0L)) {
                    return@launch
                }
                state = state.copy(
                    isBusy = true,
                    errorMessage = null,
                    statusMessage = "Encrypting the Android recovery archive...",
                )
                val archiveBytes = withContext(Dispatchers.IO) {
                    val record = currentStoredRecord(identity.id)
                        ?: error("The local Android profile record is missing from the encrypted vault.")
                    RecoveryArchiveManager.exportAndroidTransferArchive(record, passphrase)
                }
                require(archiveBytes.isNotEmpty()) {
                    "Android refused to export an empty recovery archive."
                }
                preparedProfileExport = PreparedAndroidArchiveExport(
                    bytes = archiveBytes,
                    displayName = identity.displayName,
                    successMessage = "Exported ${identity.displayName}'s encrypted Android recovery archive.",
                )
                state = state.copy(
                    isBusy = false,
                    statusMessage = "Choose where to save ${identity.displayName}'s encrypted recovery archive.",
                    errorMessage = null,
                )
                onReady(RecoveryArchiveManager.suggestedExportFileName(identity.username))
            } catch (error: Throwable) {
                preparedProfileExport = null
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android export failed.",
                )
            }
        }
    }

    fun completePreparedProfileExport(destination: Uri?) {
        completePreparedExport(
            prepared = preparedProfileExport,
            destination = destination,
            clearPrepared = { preparedProfileExport = null },
            clearPassphrase = { state = state.copy(exportPassphrase = "") },
            cancelledMessage = "Cancelled Android recovery archive export before writing a file.",
        )
    }

    private fun completePreparedExport(
        prepared: PreparedAndroidArchiveExport?,
        destination: Uri?,
        clearPrepared: () -> Unit,
        clearPassphrase: () -> Unit,
        cancelledMessage: String,
    ) {
        val export = prepared
        clearPrepared()
        if (destination == null) {
            state = state.copy(
                isBusy = false,
                statusMessage = cancelledMessage,
                errorMessage = null,
            )
            return
        }
        if (export == null) {
            state = state.copy(errorMessage = "The encrypted archive was not prepared. Start export again.")
            return
        }
        if (export.bytes.isEmpty()) {
            state = state.copy(errorMessage = "Android refused to write an empty Notrus archive.")
            return
        }
        viewModelScope.launch {
            state = state.copy(
                isBusy = true,
                errorMessage = null,
                statusMessage = "Writing encrypted Notrus archive...",
            )
            runCatching {
                withContext(Dispatchers.IO) {
                    applicationContext.contentResolver.openOutputStream(destination, "w")?.use { output ->
                        output.write(export.bytes)
                        output.flush()
                    } ?: error("The selected Android document could not be opened for writing.")
                }
                clearPassphrase()
                state = state.copy(
                    isBusy = false,
                    statusMessage = export.successMessage,
                    errorMessage = null,
                )
            }.onFailure { error ->
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android archive write failed.",
                )
            }
        }
    }

    fun importProfile(activity: FragmentActivity, source: Uri) {
        val passphrase = state.importPassphrase.trim()
        if (passphrase.length < 8) {
            state = state.copy(errorMessage = "Use the archive passphrase to import a profile onto Android.")
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize importing this recovery archive onto Android.", maxAgeMs = 0L)) {
                return@launch
            }
            state = state.copy(
                isBusy = true,
                errorMessage = null,
                statusMessage = "Importing the encrypted recovery archive onto Android...",
            )
            runCatching {
                val bytes = applicationContext.contentResolver.openInputStream(source)?.use { input ->
                    input.readBytes()
                } ?: error("The selected recovery archive could not be opened on Android.")
                require(bytes.isNotEmpty()) { "The selected recovery archive is empty. Export it again from the source device." }
                val imported = RecoveryArchiveManager.importArchive(bytes, passphrase)
                val snapshot = imported.identity
                require(snapshot.id.isNotBlank() && snapshot.username.isNotBlank() && snapshot.displayName.isNotBlank()) {
                    "The recovery archive is missing required account fields."
                }
                val recoveryAuthority = RecoveryKeyManager.recoveryAuthorityFromRepresentation(snapshot.recoveryRepresentation)

                identityProvider.deleteIdentityAliases(snapshot.id)
                val currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId)
                state = state.copy(currentDevice = currentDevice)

                val hardware = identityProvider.createIdentity(
                    userId = snapshot.id,
                    username = snapshot.username,
                    displayName = snapshot.displayName,
                )
                val standards = StandardsSignalClient.createIdentity()
                val rebuiltIdentity = LocalIdentity(
                    id = snapshot.id,
                    username = snapshot.username,
                    displayName = snapshot.displayName,
                    createdAt = snapshot.createdAt,
                    directoryCode = null,
                    storageMode = hardware.storageMode,
                    fingerprint = hardware.fingerprint,
                    recoveryFingerprint = recoveryAuthority.fingerprint,
                    recoveryPublicJwk = recoveryAuthority.publicJwk,
                    signingPublicJwk = hardware.signingPublicJwk,
                    encryptionPublicJwk = hardware.encryptionPublicJwk,
                    prekeyCreatedAt = hardware.prekeyCreatedAt,
                    prekeyFingerprint = hardware.prekeyFingerprint,
                    prekeyPublicJwk = hardware.prekeyPublicJwk,
                    prekeySignature = hardware.prekeySignature,
                    standardsSignalReady = true,
                    standardsMlsReady = false,
                    standardsSignalBundle = standards.bundle,
                    standardsSignalState = standards.state,
                )
                val unsignedRequest = AccountResetRequest(
                    createdAt = Instant.now().toString(),
                    device = currentDevice,
                    displayName = rebuiltIdentity.displayName,
                    encryptionPublicJwk = rebuiltIdentity.encryptionPublicJwk,
                    fingerprint = rebuiltIdentity.fingerprint,
                    mlsKeyPackage = null,
                    prekeyCreatedAt = rebuiltIdentity.prekeyCreatedAt,
                    prekeyFingerprint = rebuiltIdentity.prekeyFingerprint,
                    prekeyPublicJwk = rebuiltIdentity.prekeyPublicJwk,
                    prekeySignature = rebuiltIdentity.prekeySignature,
                    recoveryFingerprint = rebuiltIdentity.recoveryFingerprint,
                    recoveryPublicJwk = rebuiltIdentity.recoveryPublicJwk,
                    recoverySignature = "",
                    signalBundle = rebuiltIdentity.standardsSignalBundle,
                    signingPublicJwk = rebuiltIdentity.signingPublicJwk,
                    userId = rebuiltIdentity.id,
                    username = rebuiltIdentity.username,
                )
                val resetRequest = unsignedRequest.copy(
                    recoverySignature = RecoveryKeyManager.signAccountReset(unsignedRequest, snapshot.recoveryRepresentation),
                )
                val resetResponse = relayClient().resetAccount(resetRequest)
                updateRelaySession(resetResponse.session)

                val mergedIdentity = mergeRegisteredIdentity(rebuiltIdentity, resetResponse.user)
                persistStoredRecord(
                    StoredIdentityRecord(
                        identity = mergedIdentity,
                        recoveryRepresentation = snapshot.recoveryRepresentation,
                        savedContacts = emptyList(),
                        threadRecords = emptyMap(),
                    ),
                    makeActive = true,
                )
                state = state.copy(
                    currentIdentity = mergedIdentity,
                    currentDirectoryCode = mergedIdentity.directoryCode,
                    contacts = emptyList(),
                    directoryResults = emptyList(),
                    threads = emptyList(),
                    selectedThreadId = null,
                    draftText = "",
                    pendingAttachments = emptyList(),
                    importPassphrase = "",
                    statusMessage = when (imported) {
                        is com.notrus.android.model.ImportedRecoveryPayload.Transfer ->
                            "Imported ${mergedIdentity.displayName}'s ${imported.sourcePlatform} recovery archive onto Android."
                        is com.notrus.android.model.ImportedRecoveryPayload.Portable ->
                            "Imported ${mergedIdentity.displayName}'s portable recovery archive onto Android."
                    },
                    errorMessage = null,
                )
                registerAndSync(mergedIdentity)
            }.onFailure { error ->
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android import failed.",
                )
                refreshDeviceInventory(currentDevice = state.currentDevice)
            }
        }
    }

    fun prepareCurrentChatBackupExport(activity: FragmentActivity, onReady: (String) -> Unit) {
        val identity = state.currentIdentity ?: run {
            state = state.copy(errorMessage = "Choose a local Android profile before exporting chat history.")
            return
        }
        val passphrase = state.chatBackupPassphrase.trim()
        if (passphrase.length < 8) {
            state = state.copy(errorMessage = "Use a chat-backup passphrase with at least 8 characters.")
            return
        }

        viewModelScope.launch {
            try {
                if (!authorizeSensitiveOperation(activity, "Authorize exporting encrypted chat history from Android.", maxAgeMs = 0L)) {
                    return@launch
                }
                state = state.copy(
                    isBusy = true,
                    errorMessage = null,
                    statusMessage = "Encrypting Android chat backup...",
                )
                val archiveBytes = withContext(Dispatchers.IO) {
                    val record = currentStoredRecord(identity.id)
                        ?: error("The local Android profile record is missing from the encrypted vault.")
                    RecoveryArchiveManager.exportChatBackup(record, passphrase)
                }
                require(archiveBytes.isNotEmpty()) {
                    "Android refused to export an empty chat backup."
                }
                preparedChatBackupExport = PreparedAndroidArchiveExport(
                    bytes = archiveBytes,
                    displayName = identity.displayName,
                    successMessage = "Exported ${identity.displayName}'s encrypted Android chat backup.",
                )
                state = state.copy(
                    isBusy = false,
                    statusMessage = "Choose where to save ${identity.displayName}'s encrypted chat backup.",
                    errorMessage = null,
                )
                onReady(RecoveryArchiveManager.suggestedChatBackupFileName(identity.username))
            } catch (error: Throwable) {
                preparedChatBackupExport = null
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android chat backup export failed.",
                )
            }
        }
    }

    fun completePreparedChatBackupExport(destination: Uri?) {
        completePreparedExport(
            prepared = preparedChatBackupExport,
            destination = destination,
            clearPrepared = { preparedChatBackupExport = null },
            clearPassphrase = { state = state.copy(chatBackupPassphrase = "") },
            cancelledMessage = "Cancelled Android chat backup export before writing a file.",
        )
    }

    fun importChatBackup(activity: FragmentActivity, source: Uri) {
        val identity = state.currentIdentity ?: run {
            state = state.copy(errorMessage = "Recover or create the account before restoring chat history.")
            return
        }
        val passphrase = state.chatBackupImportPassphrase.trim()
        if (passphrase.length < 8) {
            state = state.copy(errorMessage = "Use the chat-backup passphrase to restore message history.")
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize restoring encrypted chat history onto Android.", maxAgeMs = 0L)) {
                return@launch
            }
            state = state.copy(
                isBusy = true,
                errorMessage = null,
                statusMessage = "Restoring Android chat backup...",
            )
            runCatching {
                val bytes = applicationContext.contentResolver.openInputStream(source)?.use { input ->
                    input.readBytes()
                } ?: error("The selected chat backup could not be opened on Android.")
                require(bytes.isNotEmpty()) { "The selected chat backup is empty. Export it again from the source device." }
                val backup = RecoveryArchiveManager.importChatBackup(bytes, passphrase)
                require(backup.identity.id == identity.id) {
                    "This chat backup belongs to @${backup.identity.username}, not the active account."
                }
                val record = currentStoredRecord(identity.id)
                    ?: error("The local Android profile record is missing from the encrypted vault.")
                val restoredIdentity = record.identity.copy(
                    standardsSignalReady = backup.identity.standardsSignalState != null || record.identity.standardsSignalReady,
                    standardsSignalBundle = backup.identity.standardsSignalBundle ?: record.identity.standardsSignalBundle,
                    standardsSignalState = backup.identity.standardsSignalState ?: record.identity.standardsSignalState,
                )
                val restoredRecord = record.copy(
                    identity = restoredIdentity,
                    threadRecords = record.threadRecords + backup.threadRecords,
                )
                persistStoredRecord(restoredRecord, makeActive = true)
                state = state.copy(
                    isBusy = false,
                    chatBackupImportPassphrase = "",
                    statusMessage = "Restored ${backup.threadRecords.size} conversations from encrypted chat backup. Attachment blobs remain relay-backed unless separately available.",
                    errorMessage = null,
                )
                registerAndSync(restoredRecord.identity, presentation = SyncPresentation.Silent)
            }.onFailure { error ->
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android chat backup import failed.",
                )
            }
        }
    }

    fun switchProfile(identityId: String) {
        stopLiveEvents()
        val catalog = vaultStore.loadCatalog()
        val updatedCatalog = catalog.copy(activeIdentityId = identityId)
        vaultStore.saveCatalog(updatedCatalog)
        updateRelaySession(null)
        val current = updatedCatalog.identities.firstOrNull { it.identity.id == identityId }?.identity
        state = state.copy(
            currentIdentity = current,
            currentDirectoryCode = current?.directoryCode,
            selectedThreadId = null,
            draftText = "",
            pendingAttachments = emptyList(),
        )
        refreshDeviceInventory(catalog = updatedCatalog, currentDevice = state.currentDevice)
        if (current != null) {
            viewModelScope.launch {
                registerAndSync(current)
            }
        }
    }

    fun deleteProfile(activity: FragmentActivity, identityId: String) {
        val catalog = vaultStore.loadCatalog()
        val record = catalog.identities.firstOrNull { it.identity.id == identityId } ?: return

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize deleting this local Android profile and its hardware aliases.", maxAgeMs = 0L)) {
                return@launch
            }

            state = state.copy(isBusy = true, errorMessage = null)
            runCatching {
                val deletingCurrentIdentity = state.currentIdentity?.id == identityId
                if (deletingCurrentIdentity) {
                    val activeIdentity = ensureRegisteredIdentity(record.identity)
                    val currentDeviceId = state.currentDevice?.id
                    runCatching {
                        relayClient().unregisterNotificationWakeup(
                            registrationId = currentDeviceId?.let {
                                NotrusNotificationPrefs.wakeupRegistrationId(applicationContext, it)
                            },
                        )
                    }
                    relayClient().deleteAccount()
                    updateRelaySession(null)
                    state = state.copy(
                        currentIdentity = activeIdentity,
                        currentDirectoryCode = activeIdentity.directoryCode,
                    )
                }
                identityProvider.deleteIdentityAliases(identityId)
                val remaining = catalog.identities.filterNot { it.identity.id == identityId }
                val nextActiveId = when {
                    catalog.activeIdentityId == identityId -> remaining.firstOrNull()?.identity?.id
                    else -> catalog.activeIdentityId?.takeIf { activeId -> remaining.any { it.identity.id == activeId } }
                }
                val updatedCatalog = catalog.copy(
                    version = maxOf(2, catalog.version),
                    activeIdentityId = nextActiveId,
                    identities = remaining,
                )
                vaultStore.saveCatalog(updatedCatalog)
                updateRelaySession(null)

                val nextIdentity = remaining.firstOrNull { it.identity.id == nextActiveId }?.identity
                if (nextIdentity == null) {
                    stopLiveEvents()
                    state = state.copy(
                        currentIdentity = null,
                        currentDirectoryCode = null,
                        profiles = emptyList(),
                        contacts = emptyList(),
                        directoryResults = emptyList(),
                        threads = emptyList(),
                        selectedThreadId = null,
                        draftText = "",
                        pendingAttachments = emptyList(),
                        linkedDeviceEvents = emptyList(),
                        linkedDevices = emptyList(),
                        relayHealth = null,
                        transparency = com.notrus.android.model.TransparencyVerificationResult.empty,
                        transparencyResetAvailable = false,
                        isBusy = false,
                        statusMessage = "Deleted ${record.identity.displayName}'s local Android profile.",
                    )
                    refreshDeviceInventory(catalog = updatedCatalog, currentDevice = state.currentDevice)
                } else {
                    state = state.copy(
                        currentIdentity = nextIdentity,
                        currentDirectoryCode = nextIdentity.directoryCode,
                        profiles = updatedCatalog.identities.map { it.identity },
                        selectedThreadId = null,
                        draftText = "",
                        pendingAttachments = emptyList(),
                    )
                    refreshDeviceInventory(catalog = updatedCatalog, currentDevice = state.currentDevice)
                    registerAndSync(nextIdentity)
                    state = state.copy(statusMessage = "Deleted ${record.identity.displayName}'s Android profile.")
                }
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message)
                refreshDeviceInventory(currentDevice = state.currentDevice)
            }
        }
    }

    fun purgeStaleLocalAliases(activity: FragmentActivity) {
        val staleAliases = state.deviceInventory.hardwareAliases.filter { it.linkedProfileId == null }
        if (staleAliases.isEmpty()) {
            state = state.copy(
                statusMessage = "No stale Android Keystore aliases were found.",
                errorMessage = null,
            )
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize deleting stale Android Keystore aliases.", maxAgeMs = 0L)) {
                return@launch
            }

            state = state.copy(isBusy = true, errorMessage = null)
            runCatching {
                staleAliases.forEach { alias ->
                    if (alias.alias.startsWith("notrus:device:")) {
                        deviceIdentityProvider.deleteAlias(alias.alias)
                    } else {
                        identityProvider.deleteAlias(alias.alias)
                    }
                }
                refreshDeviceInventory(currentDevice = state.currentDevice)
                state = state.copy(
                    isBusy = false,
                    statusMessage = "Removed ${staleAliases.size} stale Android Keystore alias${if (staleAliases.size == 1) "" else "es"}.",
                    errorMessage = null,
                )
            }.onFailure { error ->
                refreshDeviceInventory(currentDevice = state.currentDevice)
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Android could not delete stale Keystore aliases.",
                )
            }
        }
    }

    fun refresh() {
        val identity = state.currentIdentity ?: return
        viewModelScope.launch {
            registerAndSync(identity)
        }
    }

    fun searchDirectory() {
        val identity = state.currentIdentity ?: return
        val query = state.directoryQuery.trim()
        val localMatches = localDirectoryMatches(query, identity.id)
        if (query.length < 3) {
            state = if (localMatches.isEmpty()) {
                state.copy(
                    directoryResults = emptyList(),
                    errorMessage = "Search by username or invite code needs at least 3 characters.",
                )
            } else {
                state.copy(
                    directoryResults = localMatches,
                    errorMessage = null,
                    statusMessage = "Showing local Android matches for that short search query.",
                )
            }
            return
        }

        viewModelScope.launch {
            state = state.copy(isBusy = true, errorMessage = null)
            runCatching {
                val activeIdentity = ensureRegisteredIdentity(identity)
                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Interactive)
                val results = mergeUsers(
                    localMatches,
                    relayClient().searchDirectory(query)
                        .filter { it.id != activeIdentity.id },
                )
                state = state.copy(
                    isBusy = false,
                    currentIdentity = activeIdentity,
                    currentDirectoryCode = activeIdentity.directoryCode,
                    directoryResults = results,
                    statusMessage = if (results.isEmpty()) {
                        "No relay users matched that username or invite code."
                    } else {
                        "Android directory lookup refreshed for username or invite code."
                    },
                )
            }.onFailure { error ->
                state = if (localMatches.isEmpty()) {
                    state.copy(isBusy = false, errorMessage = error.message)
                } else {
                    state.copy(
                        isBusy = false,
                        directoryResults = localMatches,
                        errorMessage = null,
                        statusMessage = "Relay lookup failed, so Android is showing local matches only.",
                    )
                }
            }
        }
    }

    fun saveContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val user = resolveUser(userId) ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val savedContacts = mergeUsers(record.savedContacts, listOf(user))
        persistStoredRecord(record.copy(savedContacts = savedContacts))
        val contactTrustRecords = observeContactTrust(identity.id, user)
        state = state.copy(
            contacts = savedContacts,
            contactTrustRecords = contactTrustRecords,
            statusMessage = "Saved ${user.displayName} for secure direct messaging.",
            errorMessage = null,
        )
    }

    fun deleteContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val user = resolveUser(userId) ?: record.savedContacts.firstOrNull { it.id == userId } ?: return
        val savedContacts = record.savedContacts.filterNot { it.id == userId }
        persistStoredRecord(record.copy(savedContacts = savedContacts))
        state = state.copy(
            contacts = savedContacts,
            directoryResults = state.directoryResults.filterNot { it.id == userId },
            statusMessage = "Removed ${user.displayName} from the local Android contact vault.",
            errorMessage = null,
        )
    }

    fun verifyContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val record = contactTrustRecord(userId) ?: return
        val now = Instant.now().toString()
        val wasChanged = record.status == "changed"
        val updatedTrust = record.copy(
            lastVerifiedAt = now,
            status = "verified",
            trustedFingerprint = record.observedFingerprint,
            trustedPrekeyFingerprint = record.observedPrekeyFingerprint,
        )
        val trustRecords = upsertContactTrust(identity.id, updatedTrust)
        if (wasChanged) {
            val storedRecord = currentStoredRecord(identity.id)
            val currentSignalState = identity.standardsSignalState
            if (storedRecord != null && currentSignalState != null) {
                val resetSignalState = StandardsSignalClient.resetPeer(currentSignalState, userId)
                val refreshed = StandardsSignalClient.refreshBundle(resetSignalState)
                val updatedIdentity = identity.copy(
                    standardsSignalReady = true,
                    standardsSignalBundle = refreshed.bundle,
                    standardsSignalState = refreshed.state,
                )
                persistStoredRecord(
                    storedRecord.copy(
                        identity = updatedIdentity,
                    ),
                )
                state = state.copy(
                    currentIdentity = updatedIdentity,
                )
                viewModelScope.launch {
                    runCatching {
                        registerAndSync(
                            updatedIdentity,
                            preferredThreadId = state.selectedThreadId,
                            presentation = SyncPresentation.Silent,
                        )
                    }.onFailure { error ->
                        state = state.copy(
                            errorMessage = error.message ?: "Android verified the contact, but could not republish fresh secure-session keys.",
                        )
                    }
                }
            }
        }
        state = state.copy(
            contactTrustRecords = trustRecords,
            statusMessage = if (wasChanged) {
                "Verified ${record.displayName}'s new security number, kept local chat history, and republished fresh secure-session keys."
            } else {
                "Marked ${record.displayName}'s current security number as verified on Android."
            },
            errorMessage = null,
        )
    }

    fun blockContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val record = contactTrustRecord(userId) ?: return
        val updatedTrust = record.copy(blockedAt = Instant.now().toString())
        state = state.copy(
            contactTrustRecords = upsertContactTrust(identity.id, updatedTrust),
            statusMessage = "Blocked ${record.displayName} on this Android device.",
            errorMessage = null,
        )
    }

    fun unblockContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val record = contactTrustRecord(userId) ?: return
        val updatedTrust = record.copy(blockedAt = null)
        state = state.copy(
            contactTrustRecords = upsertContactTrust(identity.id, updatedTrust),
            statusMessage = "Unblocked ${record.displayName} on this Android device.",
            errorMessage = null,
        )
    }

    fun reportContact(userId: String) {
        val identity = state.currentIdentity ?: return
        val record = contactTrustRecord(userId) ?: return
        viewModelScope.launch {
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Submitting abuse report to the relay...")
            runCatching {
                val relevantThread = state.threads.firstOrNull { thread ->
                    thread.participantIds.contains(identity.id) && thread.participantIds.contains(userId)
                }
                relayClient().reportAbuse(
                    reporterId = identity.id,
                    targetUserId = userId,
                    threadId = relevantThread?.id,
                    messageIds = relevantThread?.messages?.takeLast(10)?.map { it.id }.orEmpty(),
                    reason = "abuse-or-spam",
                )
                val updatedTrust = record.copy(lastReportedAt = Instant.now().toString())
                state = state.copy(
                    isBusy = false,
                    contactTrustRecords = upsertContactTrust(identity.id, updatedTrust),
                    statusMessage = "Reported ${record.displayName} to the relay operator.",
                    errorMessage = null,
                )
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message ?: "Android could not submit that report.")
            }
        }
    }

    fun hideConversation(threadId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val existing = record.threadRecords[threadId] ?: return
        val thread = (state.threads + state.archivedThreads).firstOrNull { it.id == threadId }
        val threadTitle = thread?.title?.ifBlank { "conversation" } ?: "conversation"
        val hiddenAt = Instant.now().toString()
        val archivedThread = thread?.copy(archived = true, muted = existing.mutedAt != null)
        persistStoredRecord(
            record.copy(
                threadRecords = record.threadRecords + mapOf(
                    threadId to existing.copy(hiddenAt = hiddenAt),
                ),
            ),
        )
        val hidingSelectedThread = state.selectedThreadId == threadId
        state = state.copy(
            threads = state.threads.filterNot { it.id == threadId },
            archivedThreads = if (archivedThread == null) {
                state.archivedThreads
            } else {
                (state.archivedThreads.filterNot { it.id == threadId } + archivedThread)
                    .sortedByDescending { it.lastActivityAt }
            },
            selectedThreadId = if (hidingSelectedThread) null else state.selectedThreadId,
            draftText = if (hidingSelectedThread) "" else state.draftText,
            pendingAttachments = if (hidingSelectedThread) emptyList() else state.pendingAttachments,
            statusMessage = "Archived ${threadTitle}. Message history and secure-session state were kept.",
            errorMessage = null,
        )
    }

    fun restoreConversation(threadId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val existing = record.threadRecords[threadId] ?: return
        val thread = state.archivedThreads.firstOrNull { it.id == threadId }
        val threadTitle = thread?.title?.ifBlank { "conversation" } ?: "conversation"
        persistStoredRecord(
            record.copy(
                threadRecords = record.threadRecords + mapOf(
                    threadId to existing.copy(hiddenAt = null),
                ),
            ),
        )
        val restoredThread = thread?.copy(archived = false, muted = existing.mutedAt != null)
        state = state.copy(
            threads = if (restoredThread == null) {
                state.threads
            } else {
                (state.threads.filterNot { it.id == threadId } + restoredThread)
                    .sortedByDescending { it.lastActivityAt }
            },
            archivedThreads = state.archivedThreads.filterNot { it.id == threadId },
            selectedThreadId = threadId,
            pendingAttachments = emptyList(),
            statusMessage = "Restored ${threadTitle}.",
            errorMessage = null,
        )
    }

    fun toggleConversationMuted(threadId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val existing = record.threadRecords[threadId] ?: return
        val mutedAt = if (existing.mutedAt == null) Instant.now().toString() else null
        persistStoredRecord(
            record.copy(
                threadRecords = record.threadRecords + mapOf(
                    threadId to existing.copy(mutedAt = mutedAt),
                ),
            ),
        )
        fun ConversationThread.updateMute(): ConversationThread =
            if (id == threadId) copy(muted = mutedAt != null) else this
        state = state.copy(
            threads = state.threads.map { it.updateMute() },
            archivedThreads = state.archivedThreads.map { it.updateMute() },
            statusMessage = if (mutedAt == null) "Unmuted conversation notifications." else "Muted conversation notifications.",
            errorMessage = null,
        )
    }

    fun deleteConversation(threadId: String) {
        deleteConversationHistory(threadId)
    }

    fun deleteConversationHistory(threadId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val existing = record.threadRecords[threadId] ?: return
        val thread = (state.threads + state.archivedThreads).firstOrNull { it.id == threadId }
        val threadTitle = thread?.title?.ifBlank { "conversation" } ?: "conversation"
        val purgeAt = Instant.now().toString()
        val preservedCount = maxOf(existing.processedMessageCount, thread?.messageCount ?: existing.processedMessageCount)
        val preservedLastMessageId = thread?.messages?.lastOrNull()?.id ?: existing.lastProcessedMessageId
        persistStoredRecord(
            record.copy(
                threadRecords = record.threadRecords + mapOf(
                    threadId to existing.copy(
                        hiddenAt = purgeAt,
                        purgedAt = purgeAt,
                        messageCache = emptyMap(),
                        processedMessageCount = preservedCount,
                        lastProcessedMessageId = preservedLastMessageId,
                    ),
                ),
            ),
        )
        lastSentReadReceiptByThread.remove(threadId)
        val visibleThreads = state.threads.filterNot { it.id == threadId }
        val deletingSelectedThread = state.selectedThreadId == threadId
        state = state.copy(
            threads = visibleThreads,
            archivedThreads = if (thread == null) {
                state.archivedThreads
            } else {
                (state.archivedThreads.filterNot { it.id == threadId } + thread.copy(
                    archived = true,
                    muted = existing.mutedAt != null,
                    messages = emptyList(),
                    messageCount = 0,
                )).sortedByDescending { it.lastActivityAt }
            },
            selectedThreadId = if (deletingSelectedThread) null else state.selectedThreadId,
            draftText = if (deletingSelectedThread) "" else state.draftText,
            pendingAttachments = if (deletingSelectedThread) emptyList() else state.pendingAttachments,
            statusMessage = "Deleted local message history for ${threadTitle} and moved it to Archived. Secure-session state was kept for future messages.",
            errorMessage = null,
        )
    }

    fun resetConversationSession(threadId: String) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val existing = record.threadRecords[threadId] ?: return
        val remoteUserId = existing.signalPeerUserId
        val thread = state.threads.firstOrNull { it.id == threadId }
        val threadTitle = thread?.title?.ifBlank { "conversation" } ?: "conversation"
        val signalState = identity.standardsSignalState
        if (remoteUserId == null || signalState == null) {
            state = state.copy(errorMessage = "Only direct chats with local secure-message state can reset their secure session.")
            return
        }

        val resetState = StandardsSignalClient.resetPeer(signalState, remoteUserId)
        val refreshed = StandardsSignalClient.refreshBundle(resetState)
        val resetIdentity = identity.copy(
            standardsSignalReady = true,
            standardsSignalBundle = refreshed.bundle,
            standardsSignalState = refreshed.state,
        )
        persistStoredRecord(
            record.copy(
                identity = resetIdentity,
                threadRecords = record.threadRecords + mapOf(
                    threadId to existing.copy(protocol = DIRECT_PROTOCOL, signalPeerUserId = remoteUserId),
                ),
            ),
        )
        state = state.copy(
            currentIdentity = resetIdentity,
            statusMessage = "Reset the secure session for ${threadTitle}. Publishing a fresh pre-key bundle now.",
            errorMessage = null,
        )
        viewModelScope.launch {
            runCatching {
                registerAndSync(
                    resetIdentity,
                    preferredThreadId = threadId,
                    presentation = SyncPresentation.Silent,
                )
            }.onSuccess {
                state = state.copy(
                    statusMessage = "Reset and republished the secure session for ${threadTitle}. Existing local messages were kept.",
                    errorMessage = null,
                )
            }.onFailure { error ->
                state = state.copy(
                    errorMessage = error.message ?: "Android reset the local secure session, but could not publish the fresh pre-key bundle.",
                )
            }
        }
    }

    fun deleteMessageLocally(threadId: String, messageId: String) {
        val identity = state.currentIdentity ?: return
        val storedRecord = currentStoredRecord(identity.id) ?: return
        val thread = state.threads.firstOrNull { it.id == threadId } ?: return
        val existingRecord = storedRecord.threadRecords[threadId] ?: ConversationThreadRecord(protocol = thread.protocol)
        val cached = existingRecord.messageCache[messageId]
        val updatedThreadRecord = existingRecord.copy(
            messageCache = existingRecord.messageCache + (
                messageId to CachedMessageState(
                    attachments = cached?.attachments ?: emptyList(),
                    body = cached?.body.orEmpty(),
                    hidden = true,
                    status = cached?.status ?: "deleted-local",
                )
            ),
        )
        persistStoredRecord(
            storedRecord.copy(
                threadRecords = storedRecord.threadRecords + mapOf(threadId to updatedThreadRecord),
            ),
        )
        state = state.copy(
            threads = state.threads.map { existingThread ->
                if (existingThread.id == threadId) {
                    existingThread.copy(messages = existingThread.messages.filterNot { it.id == messageId })
                } else {
                    existingThread
                }
            },
            statusMessage = "Deleted one local Android message.",
            errorMessage = null,
        )
    }

    fun openDirectChat(activity: FragmentActivity, userId: String) {
        val identity = state.currentIdentity ?: return
        val user = resolveUser(userId)
        if (user == null) {
            state = state.copy(errorMessage = "That contact is not available in the local directory cache yet.")
            return
        }
        if (!state.transparency.chainValid) {
            if (state.transparencyResetAvailable) {
                resetTransparencyTrust()
                return
            }
            state = state.copy(errorMessage = transparencyBlockMessage("before starting a new secure chat on Android"))
            return
        }
        if (user.signalBundle == null) {
            state = state.copy(errorMessage = "${user.displayName} has not published a current secure-message bundle yet.")
            return
        }
        contactTrustRecord(user.id)?.let { trust ->
            when {
                trust.blockedAt != null -> {
                    state = state.copy(errorMessage = "${user.displayName} is blocked on this Android device. Unblock the contact in Security before messaging.")
                    return
                }

                trust.status == "changed" -> {
                    state = state.copy(errorMessage = "${user.displayName}'s security number changed. Verify the contact in Security before starting another chat.")
                    return
                }
            }
        }

        val existingThread = state.threads.firstOrNull { thread ->
            thread.protocol == DIRECT_PROTOCOL &&
                thread.participantIds.toSet() == setOf(identity.id, user.id)
        }
        if (existingThread != null) {
            saveContact(user.id)
            state = state.copy(
                selectedThreadId = existingThread.id,
                pendingAttachments = emptyList(),
                statusMessage = "Opened secure direct chat with ${user.displayName}.",
                errorMessage = null,
            )
            return
        }

        val archivedThread = state.archivedThreads.firstOrNull { thread ->
            thread.protocol == DIRECT_PROTOCOL &&
                thread.participantIds.toSet() == setOf(identity.id, user.id)
        }
        if (archivedThread != null) {
            saveContact(user.id)
            restoreConversation(archivedThread.id)
            state = state.copy(
                statusMessage = "Restored archived secure direct chat with ${user.displayName}.",
                errorMessage = null,
            )
            return
        }

        val storedRecord = currentStoredRecord(identity.id)
        val hiddenDirectThreadId = storedRecord?.threadRecords
            ?.entries
            ?.firstOrNull { (_, threadRecord) ->
                threadRecord.protocol == DIRECT_PROTOCOL && threadRecord.signalPeerUserId == user.id
            }
            ?.key
        if (storedRecord != null && hiddenDirectThreadId != null) {
            val threadRecord = requireNotNull(storedRecord.threadRecords[hiddenDirectThreadId])
            persistStoredRecord(
                storedRecord.copy(
                    threadRecords = storedRecord.threadRecords + mapOf(
                        hiddenDirectThreadId to threadRecord.copy(hiddenAt = null),
                    ),
                ),
            )
            saveContact(user.id)
            viewModelScope.launch {
                registerAndSync(
                    identity,
                    preferredThreadId = hiddenDirectThreadId,
                    presentation = SyncPresentation.Silent,
                )
                state = state.copy(
                    selectedThreadId = hiddenDirectThreadId,
                    pendingAttachments = emptyList(),
                    statusMessage = "Reopened secure direct chat with ${user.displayName}.",
                    errorMessage = null,
                )
            }
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize establishing or reopening a direct secure chat session on this Android device.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Creating a direct secure chat with ${user.displayName}...")
            runCatching {
                var activeIdentity = ensureRegisteredIdentity(identity)
                val routingUser = ensureRoutingUser(activeIdentity, user)
                activeIdentity = routingUser.first
                val resolvedUser = routingUser.second
                saveResolvedContact(resolvedUser)
                activeIdentity = resetSignalPeerForFreshDirectChat(activeIdentity, resolvedUser.id)
                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Interactive)
                val threadId = relayClient().createDirectThread(requireNotNull(resolvedUser.contactHandle))
                registerAndSync(activeIdentity, preferredThreadId = threadId)
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message)
            }
        }
    }

    fun sendSelectedMessage(activity: FragmentActivity) {
        val identity = state.currentIdentity ?: return
        val thread = state.selectedThread ?: return
        val body = state.draftText.trim()
        val pendingAttachments = state.pendingAttachments

        if (body.isEmpty() && pendingAttachments.isEmpty()) {
            state = state.copy(errorMessage = "Type a message or attach a file before sending.")
            return
        }
        if (!state.transparency.chainValid) {
            if (state.transparencyResetAvailable) {
                resetTransparencyTrust()
                return
            }
            state = state.copy(errorMessage = transparencyBlockMessage("before Android sends more ciphertext"))
            return
        }
        if (!thread.supported) {
            state = state.copy(errorMessage = thread.warning ?: "This thread is not writable on Android yet.")
            return
        }
        val blockedParticipant = thread.participants.firstOrNull { user ->
            user.id != identity.id && contactTrustRecord(user.id)?.blockedAt != null
        }
        if (blockedParticipant != null) {
            state = state.copy(errorMessage = "${blockedParticipant.displayName} is blocked on this Android device. Unblock them in Security before sending.")
            return
        }
        val changedParticipant = thread.participants.firstOrNull { user ->
            user.id != identity.id && contactTrustRecord(user.id)?.status == "changed"
        }
        if (changedParticipant != null) {
            state = state.copy(errorMessage = "${changedParticipant.displayName}'s security number changed. Verify the contact in Security before sending.")
            return
        }

        when (thread.protocol) {
            DIRECT_PROTOCOL -> {
                val remoteUser = thread.participants.firstOrNull { it.id != identity.id }
                if (remoteUser == null || remoteUser.signalBundle == null) {
                    state = state.copy(errorMessage = "The remote secure-message bundle is missing for this thread.")
                    return
                }
                sendDirectSelectedMessage(
                    activity = activity,
                    body = body,
                    identity = identity,
                    pendingAttachments = pendingAttachments,
                    remoteUser = remoteUser,
                    thread = thread,
                )
            }

            GROUP_PROTOCOL -> {
                val remoteParticipants = thread.participants
                    .asSequence()
                    .filter { it.id != identity.id }
                    .distinctBy { it.id }
                    .toList()
                if (remoteParticipants.size < 2) {
                    state = state.copy(errorMessage = "Android group send requires at least two remote participants.")
                    return
                }
                val missingSignal = remoteParticipants.firstOrNull { it.signalBundle == null }
                if (missingSignal != null) {
                    state = state.copy(errorMessage = "${missingSignal.displayName} is missing a secure-message bundle for Android group fanout.")
                    return
                }
                sendGroupSelectedMessage(
                    activity = activity,
                    body = body,
                    identity = identity,
                    pendingAttachments = pendingAttachments,
                    remoteParticipants = remoteParticipants,
                    thread = thread,
                )
            }

            else -> {
                state = state.copy(errorMessage = "Android cannot send this protocol yet.")
            }
        }
    }

    private fun sendDirectSelectedMessage(
        activity: FragmentActivity,
        body: String,
        identity: LocalIdentity,
        pendingAttachments: List<LocalAttachmentDraft>,
        remoteUser: RelayUser,
        thread: ConversationThread,
    ) {
        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize sending ciphertext from this Android device.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Encrypting and sending from Android...")
            runCatching {
                val signalState = identity.standardsSignalState
                    ?: error("This Android profile does not have local secure-message state.")
                val mailboxHandle = thread.mailboxHandle
                    ?: error("This Android conversation is missing its current mailbox handle. Sync once, then send again.")
                val deliveryCapability = thread.deliveryCapability
                    ?: error("This Android conversation is missing its current delivery capability. Sync once, then send again.")
                val attachmentReferences = uploadPendingAttachments(
                    identity = identity,
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    pendingAttachments = pendingAttachments,
                    threadId = thread.id,
                )
                val standardsPayload = encodeStandardsPayload(
                    StandardsMessagePayload(
                        attachments = attachmentReferences,
                        text = body,
                    )
                )
                val sealed = StandardsSignalClient.encrypt(
                    state = signalState,
                    localUserId = identity.id,
                    plaintext = standardsPayload,
                    remoteBundle = requireNotNull(remoteUser.signalBundle),
                    remoteUserId = remoteUser.id,
                )
                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Delivery)
                val messageId = relayClient().postSignalMessage(
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    messageKind = sealed.messageKind,
                    wireMessage = sealed.wireMessage,
                )
                val refreshed = StandardsSignalClient.refreshBundle(sealed.state)
                val updatedIdentity = identity.copy(
                    standardsSignalReady = true,
                    standardsSignalBundle = refreshed.bundle,
                    standardsSignalState = refreshed.state,
                )
                val currentRecord = currentStoredRecord(identity.id)
                    ?: error("The local Android profile record is missing.")
                val threadRecord = currentRecord.threadRecords[thread.id]
                    ?: ConversationThreadRecord(protocol = DIRECT_PROTOCOL, signalPeerUserId = remoteUser.id)
                val updatedThreadRecord = threadRecord.copy(
                    protocol = DIRECT_PROTOCOL,
                    signalPeerUserId = remoteUser.id,
                    messageCache = threadRecord.messageCache + (
                        messageId to MessageCachePolicy.mergeCachedStates(
                            threadRecord.messageCache[messageId],
                            CachedMessageState(
                                attachments = attachmentReferences,
                                body = body,
                                relayCreatedAt = Instant.now().toString(),
                                relayMessageKind = sealed.messageKind,
                                relaySenderId = identity.id,
                                relayWireMessage = sealed.wireMessage,
                                status = "ok",
                            ),
                        )
                    ),
                )
                persistStoredRecord(
                    currentRecord.copy(
                        identity = updatedIdentity,
                        threadRecords = currentRecord.threadRecords + mapOf(thread.id to updatedThreadRecord),
                    ),
                )
                state = state.copy(
                    currentIdentity = updatedIdentity,
                    draftText = "",
                    pendingAttachments = emptyList(),
                    isBusy = false,
                )
                registerAndSync(updatedIdentity, preferredThreadId = thread.id, presentation = SyncPresentation.Silent)
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = normalizeSignalSendFailure(error))
            }
        }
    }

    private fun sendGroupSelectedMessage(
        activity: FragmentActivity,
        body: String,
        identity: LocalIdentity,
        pendingAttachments: List<LocalAttachmentDraft>,
        remoteParticipants: List<RelayUser>,
        thread: ConversationThread,
    ) {
        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize sending group ciphertext from this Android device.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Encrypting group fanout and sending from Android...")
            runCatching {
                var signalState = identity.standardsSignalState
                    ?: error("This Android profile does not have local secure-message state.")
                val mailboxHandle = thread.mailboxHandle
                    ?: error("This Android group is missing its current mailbox handle. Sync once, then send again.")
                val deliveryCapability = thread.deliveryCapability
                    ?: error("This Android group is missing its current delivery capability. Sync once, then send again.")

                val attachmentReferences = uploadPendingAttachments(
                    identity = identity,
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    pendingAttachments = pendingAttachments,
                    threadId = thread.id,
                )
                val encodedPayload = encodeStandardsPayload(
                    StandardsMessagePayload(
                        attachments = attachmentReferences,
                        text = body,
                    )
                )

                val recipientEnvelopes = buildList {
                    for (participant in remoteParticipants.sortedBy { it.id }) {
                        val sealed = StandardsSignalClient.encrypt(
                            state = signalState,
                            localUserId = identity.id,
                            plaintext = encodedPayload,
                            remoteBundle = requireNotNull(participant.signalBundle),
                            remoteUserId = participant.id,
                        )
                        signalState = sealed.state
                        add(
                            MlsFanoutRecipientEnvelope(
                                messageKind = sealed.messageKind,
                                toUserId = participant.id,
                                wireMessage = sealed.wireMessage,
                            ),
                        )
                    }
                }

                val fanoutWire = encodeMlsFanoutEnvelope(
                    MlsFanoutEnvelope(
                        format = MLS_FANOUT_FORMAT,
                        senderId = identity.id,
                        version = 1,
                        recipients = recipientEnvelopes,
                    ),
                )

                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Delivery)
                val messageId = relayClient().postMlsMessage(
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    wireMessage = fanoutWire,
                )

                val refreshed = StandardsSignalClient.refreshBundle(signalState)
                val updatedIdentity = identity.copy(
                    standardsSignalReady = true,
                    standardsSignalBundle = refreshed.bundle,
                    standardsSignalState = refreshed.state,
                )
                val currentRecord = currentStoredRecord(identity.id)
                    ?: error("The local Android profile record is missing.")
                val threadRecord = currentRecord.threadRecords[thread.id]
                    ?: ConversationThreadRecord(protocol = GROUP_PROTOCOL)
                val updatedThreadRecord = threadRecord.copy(
                    protocol = GROUP_PROTOCOL,
                    signalPeerUserId = null,
                    messageCache = threadRecord.messageCache + (
                        messageId to MessageCachePolicy.mergeCachedStates(
                            threadRecord.messageCache[messageId],
                            CachedMessageState(
                                attachments = attachmentReferences,
                                body = body,
                                relayCreatedAt = Instant.now().toString(),
                                relayMessageKind = "mls-application",
                                relaySenderId = identity.id,
                                relayWireMessage = fanoutWire,
                                status = "ok",
                            ),
                        )
                    ),
                )
                persistStoredRecord(
                    currentRecord.copy(
                        identity = updatedIdentity,
                        threadRecords = currentRecord.threadRecords + mapOf(thread.id to updatedThreadRecord),
                    ),
                )
                state = state.copy(
                    currentIdentity = updatedIdentity,
                    draftText = "",
                    pendingAttachments = emptyList(),
                    isBusy = false,
                )
                registerAndSync(updatedIdentity, preferredThreadId = thread.id, presentation = SyncPresentation.Silent)
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = normalizeSignalSendFailure(error))
            }
        }
    }

    private suspend fun uploadPendingAttachments(
        identity: LocalIdentity,
        mailboxHandle: String,
        deliveryCapability: String,
        pendingAttachments: List<LocalAttachmentDraft>,
        threadId: String,
    ): List<SecureAttachmentReference> {
        if (pendingAttachments.isEmpty()) {
            return emptyList()
        }
        return buildList {
            for (draft in pendingAttachments) {
                val plaintext = readAttachmentBytes(
                    uri = Uri.parse(draft.uri),
                    expectedName = draft.fileName,
                )
                val sealedAttachment = AttachmentCrypto.sealAttachment(
                    data = plaintext,
                    fileName = draft.fileName,
                    mediaType = draft.mediaType,
                    senderId = identity.id,
                    threadId = threadId,
                )
                applyPrivacyDelayIfEnabled(PrivacyDelayKind.Delivery)
                relayClient().uploadAttachment(
                    mailboxHandle = mailboxHandle,
                    deliveryCapability = deliveryCapability,
                    attachment = sealedAttachment.request,
                )
                add(sealedAttachment.reference)
            }
        }
    }

    fun revokeLinkedDevice(activity: FragmentActivity, deviceId: String) {
        val identity = state.currentIdentity ?: return
        val currentDevice = state.currentDevice ?: return

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize revoking a linked Android or macOS device from this account.", maxAgeMs = 0L)) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null)
            runCatching {
                val createdAt = Instant.now().toString()
                val payload = deviceActionPayload(
                    action = "device-revoke",
                    createdAt = createdAt,
                    signerDeviceId = currentDevice.id,
                    targetDeviceId = deviceId,
                    userId = identity.id,
                )
                val signature = deviceIdentityProvider.signAction(appInstanceId, payload, applicationContext.packageManager)
                val response = relayClient().revokeDevice(
                    userId = identity.id,
                    signerDeviceId = currentDevice.id,
                    targetDeviceId = deviceId,
                    createdAt = createdAt,
                    signature = signature,
                )
                state = state.copy(
                    isBusy = false,
                    linkedDeviceEvents = response.deviceEvents,
                    linkedDevices = response.devices,
                    statusMessage = "Revoked linked device ${response.revokedDeviceId}.",
                )
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message)
            }
        }
    }

    private fun bootstrap() {
        state = state.copy(vaultLocked = vaultStore.hasCatalog())
        refreshDeviceInventory()
        if (!state.vaultLocked) {
            state = state.copy(statusMessage = "Create the first Android profile to join your relay.")
        }
    }

    private suspend fun registerAndSync(
        identity: LocalIdentity,
        preferredThreadId: String? = state.selectedThreadId,
        presentation: SyncPresentation = SyncPresentation.Interactive,
    ) {
        val interactiveSync = presentation == SyncPresentation.Interactive
        val previousStatusMessage = state.statusMessage
        if (interactiveSync) {
            state = state.copy(
                isBusy = true,
                showSyncProgress = true,
                errorMessage = null,
                statusMessage = "Registering profile and syncing relay state...",
            )
        } else {
            state = state.copy(errorMessage = null)
        }
        var latestKnownIdentity = identity
        runCatching {
            var workingIdentity = identity
            val currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId)
            state = state.copy(currentDevice = currentDevice)
            val existingRecord = currentStoredRecord(identity.id)
            if (workingIdentity.standardsSignalState != null) {
                val refreshed = StandardsSignalClient.refreshBundle(workingIdentity.standardsSignalState)
                workingIdentity = workingIdentity.copy(
                    standardsSignalReady = true,
                    standardsSignalBundle = refreshed.bundle,
                    standardsSignalState = refreshed.state,
                )
            }

            if (existingRecord != null && workingIdentity != existingRecord.identity) {
                persistStoredRecord(existingRecord.copy(identity = workingIdentity))
            }

            val (bootstrapRelay, relayHealth) = if (state.relayHealth == null) {
                relayClientAndHealth()
            } else {
                relayClient() to requireNotNull(state.relayHealth)
            }
            val registered = if (sessionIsUsable()) {
                null
            } else {
                bootstrapRelay.register(workingIdentity).also { updateRelaySession(it.session, identityId = workingIdentity.id) }
            }
            workingIdentity = registered?.let { mergeRegisteredIdentity(workingIdentity, it.user) } ?: workingIdentity
            latestKnownIdentity = workingIdentity
            existingRecord?.let { persistStoredRecord(it.copy(identity = workingIdentity)) }
            state = state.copy(
                currentIdentity = workingIdentity,
                currentDirectoryCode = workingIdentity.directoryCode,
            )
            val routineRelay = relayClient()
            applyPrivacyDelayIfEnabled(PrivacyDelayKind.Sync)
            val sync = routineRelay.sync()
            val transparencySnapshot = routineRelay.transparency()
            val securitySnapshot = routineRelay.securityDevices()
            runCatching {
                val registrationId = NotrusNotificationPrefs.wakeupRegistrationId(applicationContext, currentDevice.id)
                if (state.notificationsEnabled) {
                    routineRelay.registerNotificationWakeup(
                        mode = "workmanager-poll-v1",
                        platform = "android",
                        registrationId = registrationId,
                    )
                } else {
                    routineRelay.unregisterNotificationWakeup(registrationId = registrationId)
                }
            }
            val remoteUsers = sync.users.filter { it.id != workingIdentity.id }
            val currentDirectoryCode = sync.users.firstOrNull { it.id == workingIdentity.id }?.directoryCode ?: registered?.user?.directoryCode
            if (currentDirectoryCode != null && currentDirectoryCode != workingIdentity.directoryCode) {
                workingIdentity = workingIdentity.copy(directoryCode = currentDirectoryCode)
                latestKnownIdentity = workingIdentity
            }
            val storedRecord = currentStoredRecord(workingIdentity.id)
                ?: error("The Android profile record is missing from the local vault.")
            val mergedUsers = mergeUsers(remoteUsers, storedRecord.savedContacts)
            val contactTrustRecords = reconcileContactTrust(workingIdentity.id, mergedUsers)
            val transparency = TransparencyVerifier.verify(
                relayOrigin = RelayClient.validateOrigin(state.relayOriginInput),
                entryCount = transparencySnapshot.entryCount ?: transparencySnapshot.transparencyEntries.size,
                entries = transparencySnapshot.transparencyEntries,
                expectedHead = transparencySnapshot.transparencyHead,
                expectedSignature = transparencySnapshot.transparencySignature,
                signer = transparencySnapshot.transparencySigner,
                pinnedHeads = loadTransparencyPins(),
                pinnedSignerKeys = loadTransparencySignerPins(),
                witnessOrigins = witnessOrigins(),
                fetchWitness = { witnessOrigin, relayOrigin ->
                    routineRelay.fetchWitnessHead(witnessOrigin, relayOrigin)
                },
            )
            persistTransparencyPinIfNeeded(transparency)
            val usersById = (sync.users + storedRecord.savedContacts).associateBy { it.id }
            val materialized = materializeThreads(
                identity = workingIdentity,
                relayThreads = sync.threads,
                usersById = usersById,
                threadRecords = storedRecord.threadRecords,
            )
            val updatedRecord = storedRecord.copy(
                identity = materialized.identity,
                savedContacts = mergedUsers,
                threadRecords = materialized.threadRecords,
            )
            persistStoredRecord(updatedRecord)
            if (state.notificationsEnabled) {
                val seenIds = NotrusNotificationPrefs.loadSeenMessageIds(applicationContext, workingIdentity.id)
                sync.threads.asSequence()
                    .flatMap { it.messages.asSequence() }
                    .filter { it.senderId != workingIdentity.id }
                    .mapNotNull { message -> message.id.trim().takeIf(String::isNotBlank) }
                    .forEach { seenIds.add(it) }
                NotrusNotificationPrefs.saveSeenMessageIds(applicationContext, workingIdentity.id, seenIds)
                NotrusNotificationPrefs.markIdentityNotificationPrimed(applicationContext, workingIdentity.id)
            }
            val profiles = vaultStore.loadCatalog().identities.map { it.identity }
            val selectedThreadId = pendingNotificationThreadId
                ?.takeIf { pending -> materialized.threads.any { it.id == pending } }
                ?: preferredThreadId
                ?.takeIf { preferred -> materialized.threads.any { it.id == preferred } }
                ?: state.selectedThreadId?.takeIf { current -> materialized.threads.any { it.id == current } }
            pendingNotificationThreadId = null

            state = state.copy(
                currentIdentity = materialized.identity,
                currentDirectoryCode = currentDirectoryCode,
                currentDevice = currentDevice,
                profiles = profiles,
                contacts = mergedUsers,
                contactTrustRecords = contactTrustRecords,
                transparency = transparency,
                transparencyResetAvailable = canResetTransparencyTrust(transparency),
                linkedDeviceEvents = securitySnapshot.deviceEvents,
                linkedDevices = securitySnapshot.devices,
                threads = materialized.threads,
                archivedThreads = materialized.archivedThreads,
                relayHealth = relayHealth,
                selectedThreadId = selectedThreadId,
                pendingAttachments = if (selectedThreadId == state.selectedThreadId) state.pendingAttachments else emptyList(),
                statusMessage = if (interactiveSync) {
                    if (!transparency.chainValid) {
                        "Android sync completed, but transparency verification needs attention before you trust new keys or create new chats."
                    } else if (sync.directoryDiscoveryMode == "exact-username-or-invite" || sync.directoryDiscoveryMode == "username-or-invite") {
                        "Android sync complete. Search contacts by username or invite code, save them locally, then open secure chats and compatible group threads from this device."
                    } else {
                        "Android sync complete. Contacts, secure direct chats, and compatible group threads are ready on this device."
                    }
                } else {
                    previousStatusMessage
                },
                errorMessage = null,
                isBusy = if (interactiveSync) false else state.isBusy,
                showSyncProgress = false,
            )
            refreshDeviceInventory(currentDevice = currentDevice)
            startLiveEventsIfPossible()
            selectedThreadId?.let(::sendReadReceiptForThreadId)
            if (!appInForeground && state.notificationsEnabled) {
                NotrusBackgroundSyncWorker.enqueueImmediate(applicationContext)
            }
        }.onFailure { error ->
            state = if (interactiveSync) {
                state.copy(
                    isBusy = false,
                    currentIdentity = latestKnownIdentity,
                    currentDirectoryCode = latestKnownIdentity.directoryCode,
                    errorMessage = error.message ?: "Relay sync failed.",
                    showSyncProgress = false,
                )
            } else {
                state.copy(
                    currentIdentity = latestKnownIdentity,
                    currentDirectoryCode = latestKnownIdentity.directoryCode,
                    showSyncProgress = false,
                )
            }
            if (interactiveSync) {
                stopLiveEvents()
            }
            refreshDeviceInventory(currentDevice = state.currentDevice)
        }
    }

    private fun materializeThreads(
        identity: LocalIdentity,
        relayThreads: List<RelayThread>,
        usersById: Map<String, RelayUser>,
        threadRecords: Map<String, ConversationThreadRecord>,
    ): MaterializedSyncState {
        var updatedIdentity = identity
        val updatedRecords = threadRecords.toMutableMap()
        val conversations = relayThreads.sortedByDescending { relayThreadLastActivity(it) }.map { thread ->
            val participants = thread.participantIds.map { userId ->
                usersById[userId] ?: placeholderUser(userId)
            }
            val existingRecord = updatedRecords[thread.id]

            when {
                thread.protocol == DIRECT_PROTOCOL && participants.size == 2 -> {
                    val materialized = materializeDirectSignalThread(
                        thread = thread,
                        participants = participants,
                        identity = updatedIdentity,
                        existingRecord = existingRecord,
                    )
                    updatedIdentity = materialized.identity
                    updatedRecords[thread.id] = materialized.record
                    materialized.thread
                }

                thread.protocol == GROUP_PROTOCOL && participants.size >= 3 -> {
                    val materialized = materializeStandardsGroupThread(
                        thread = thread,
                        participants = participants,
                        identity = updatedIdentity,
                        existingRecord = existingRecord,
                    )
                    updatedIdentity = materialized.identity
                    updatedRecords[thread.id] = materialized.record
                    materialized.thread
                }

                else -> {
                    materializeUnsupportedThread(
                        thread = thread,
                        participants = participants,
                        existingRecord = existingRecord,
                        identityId = updatedIdentity.id,
                    )
                }
            }
        }
        val conversationsWithLocalState = conversations.map { conversation ->
            val record = updatedRecords[conversation.id]
            conversation.copy(
                archived = record?.hiddenAt != null,
                muted = record?.mutedAt != null,
            )
        }
        val visibleConversations = conversationsWithLocalState.filter { !it.archived }
        val archivedConversations = conversationsWithLocalState.filter { it.archived }
        return MaterializedSyncState(
            identity = updatedIdentity,
            threadRecords = updatedRecords,
            threads = visibleConversations,
            archivedThreads = archivedConversations,
        )
    }

    private fun hiddenMaterializedThread(
        thread: RelayThread,
        participants: List<RelayUser>,
        identityId: String,
        record: ConversationThreadRecord,
    ): ConversationThread =
        ConversationThread(
            deliveryCapability = thread.deliveryCapability,
            id = thread.id,
            title = resolveThreadTitle(thread, participants, identityId, record.localTitle),
            mailboxHandle = thread.mailboxHandle,
            protocol = thread.protocol,
            protocolLabel = ProtocolCatalog.label(thread.protocol),
            participants = participants,
            participantIds = thread.participantIds,
            messages = emptyList(),
            messageCount = thread.messages.size,
            attachmentCount = thread.attachmentCount,
            lastActivityAt = relayThreadLastActivity(thread),
            supported = false,
            warning = "This local conversation was deleted on this Android device.",
        )

    private fun materializeDirectSignalThread(
        thread: RelayThread,
        participants: List<RelayUser>,
        identity: LocalIdentity,
        existingRecord: ConversationThreadRecord?,
    ): MaterializedThread {
        val remoteUser = participants.firstOrNull { it.id != identity.id }
        if (remoteUser == null) {
            return MaterializedThread(
                identity = identity,
                record = existingRecord ?: ConversationThreadRecord(protocol = DIRECT_PROTOCOL),
                thread = materializeUnsupportedThread(
                    thread = thread,
                    participants = participants,
                    existingRecord = existingRecord,
                    identityId = identity.id,
                    warning = "This direct thread is missing its remote participant.",
                ),
            )
        }

        var signalState = identity.standardsSignalState
            ?: return MaterializedThread(
                identity = identity,
                record = existingRecord ?: ConversationThreadRecord(protocol = DIRECT_PROTOCOL),
                thread = materializeUnsupportedThread(
                    thread = thread,
                    participants = participants,
                    existingRecord = existingRecord,
                    identityId = identity.id,
                    warning = "This Android profile is missing its local secure-message state.",
                ),
            )
        var record = existingRecord ?: ConversationThreadRecord(
            protocol = DIRECT_PROTOCOL,
            signalPeerUserId = remoteUser.id,
        )

        if (
            record.processedMessageCount > thread.messages.size ||
            thread.messages.take(record.processedMessageCount).any { !MessageCachePolicy.canSkipLocalDecrypt(record.messageCache[it.id]) } ||
            (
                record.processedMessageCount > 0 &&
                    thread.messages.getOrNull(record.processedMessageCount - 1)?.id != record.lastProcessedMessageId
                )
        ) {
            record = ConversationThreadRecord(
                hiddenAt = record.hiddenAt,
                localTitle = record.localTitle,
                mutedAt = record.mutedAt,
                purgedAt = record.purgedAt,
                messageCache = record.messageCache,
                lastProcessedMessageId = null,
                processedMessageCount = 0,
                protocol = DIRECT_PROTOCOL,
                signalPeerUserId = remoteUser.id,
            )
        }

        for (message in thread.messages.drop(record.processedMessageCount)) {
            record = when {
                MessageCachePolicy.canSkipLocalDecrypt(record.messageCache[message.id]) -> record.copy(
                    messageCache = record.messageCache + (
                        message.id to MessageCachePolicy.attachRelayEnvelope(
                            requireNotNull(record.messageCache[message.id]),
                            message,
                        )
                    ),
                )

                message.senderId == identity.id -> record.copy(
                    messageCache = record.messageCache + (
                        message.id to MessageCachePolicy.attachRelayEnvelope(
                            CachedMessageState(
                                body = normalizeLegacyDisplayBody("Sent from this Android device."),
                                status = "missing-local-state",
                            ),
                            message,
                        )
                    ),
                )

                message.messageKind != null && message.wireMessage != null -> {
                    try {
                        val opened = StandardsSignalClient.decrypt(
                            state = signalState,
                            localUserId = identity.id,
                            messageKind = message.messageKind,
                            remoteUserId = message.senderId,
                            wireMessage = message.wireMessage,
                        )
                        val payload = decodeStandardsPayload(opened.plaintext)
                        signalState = opened.state
                        record.copy(
                            messageCache = record.messageCache + (
                                message.id to MessageCachePolicy.attachRelayEnvelope(
                                    CachedMessageState(
                                        attachments = payload.attachments,
                                        body = payload.text,
                                        status = "ok",
                                    ),
                                    message,
                                )
                            ),
                        )
                    } catch (error: Exception) {
                        record.copy(
                            messageCache = record.messageCache + (
                                message.id to MessageCachePolicy.attachRelayEnvelope(
                                    CachedMessageState(
                                        body = normalizeSignalDecryptionFailure(error),
                                        status = "invalid",
                                    ),
                                    message,
                                )
                            ),
                        )
                    }
                }

                else -> record.copy(
                    messageCache = record.messageCache + (
                        message.id to MessageCachePolicy.attachRelayEnvelope(
                            CachedMessageState(
                                body = normalizeLegacyDisplayBody("The Notrus message was missing its authenticated wire payload."),
                                status = "invalid",
                            ),
                            message,
                        )
                    ),
                )
            }.copy(
                lastProcessedMessageId = message.id,
                processedMessageCount = record.processedMessageCount + 1,
                protocol = DIRECT_PROTOCOL,
                signalPeerUserId = remoteUser.id,
            )
        }

        val updatedIdentity = identity.copy(
            standardsSignalReady = true,
            standardsSignalState = signalState,
        )
        val decryptedMessages = thread.messages.mapNotNull { message ->
            val cached = record.messageCache[message.id]
            if (!shouldDisplayMessageAfterLocalPurge(record, message, cached)) {
                null
            } else {
                DecryptedMessage(
                    attachments = cached?.attachments ?: emptyList(),
                    body = cached?.body?.takeIf(String::isNotBlank) ?: "Local plaintext is unavailable on this Android device for that Notrus message.",
                    createdAt = message.createdAt,
                    id = message.id,
                    senderId = message.senderId,
                    senderName = participants.firstOrNull { it.id == message.senderId }?.displayName ?: "Unknown user",
                    status = cached?.status ?: "missing-local-state",
                    readReceiptSummary = readReceiptSummaryFor(message, thread, participants, identity.id),
                )
            }
        }

        return MaterializedThread(
            identity = updatedIdentity,
            record = record,
            thread = ConversationThread(
                deliveryCapability = thread.deliveryCapability,
                id = thread.id,
                title = resolveThreadTitle(thread, participants, updatedIdentity.id, record.localTitle),
                mailboxHandle = thread.mailboxHandle,
                protocol = thread.protocol,
                protocolLabel = ProtocolCatalog.label(thread.protocol),
                participants = participants,
                participantIds = thread.participantIds,
                messages = decryptedMessages,
                messageCount = thread.messages.size,
                attachmentCount = thread.attachmentCount,
                lastActivityAt = relayThreadLastActivity(thread),
                supported = true,
                warning = null,
            ),
        )
    }

    private fun materializeStandardsGroupThread(
        thread: RelayThread,
        participants: List<RelayUser>,
        identity: LocalIdentity,
        existingRecord: ConversationThreadRecord?,
    ): MaterializedThread {
        val fanoutCompatible = isMlsFanoutThread(thread)
        var signalState = identity.standardsSignalState
            ?: return MaterializedThread(
                identity = identity,
                record = existingRecord ?: ConversationThreadRecord(protocol = GROUP_PROTOCOL),
                thread = materializeUnsupportedThread(
                    thread = thread,
                    participants = participants,
                    existingRecord = existingRecord,
                    identityId = identity.id,
                    warning = "This Android profile is missing local secure-message state required for MLS-compatible group fanout.",
                ),
            )

        var record = existingRecord ?: ConversationThreadRecord(protocol = GROUP_PROTOCOL)
        if (
            record.processedMessageCount > thread.messages.size ||
            thread.messages.take(record.processedMessageCount).any { !MessageCachePolicy.canSkipLocalDecrypt(record.messageCache[it.id]) } ||
            (
                record.processedMessageCount > 0 &&
                    thread.messages.getOrNull(record.processedMessageCount - 1)?.id != record.lastProcessedMessageId
                )
        ) {
            record = ConversationThreadRecord(
                hiddenAt = record.hiddenAt,
                localTitle = record.localTitle,
                mutedAt = record.mutedAt,
                purgedAt = record.purgedAt,
                messageCache = record.messageCache,
                lastProcessedMessageId = null,
                processedMessageCount = 0,
                protocol = GROUP_PROTOCOL,
                signalPeerUserId = null,
            )
        }

        var decodeFailures = 0
        for (message in thread.messages.drop(record.processedMessageCount)) {
            record = when {
                MessageCachePolicy.canSkipLocalDecrypt(record.messageCache[message.id]) -> record.copy(
                    messageCache = record.messageCache + (
                        message.id to MessageCachePolicy.attachRelayEnvelope(
                            requireNotNull(record.messageCache[message.id]),
                            message,
                        )
                    ),
                )

                message.senderId == identity.id -> {
                    record.copy(
                        messageCache = record.messageCache + (
                            message.id to MessageCachePolicy.attachRelayEnvelope(
                                CachedMessageState(
                                    body = normalizeLegacyDisplayBody("Sent from this Android device."),
                                    status = "missing-local-state",
                                ),
                                message,
                            )
                        ),
                    )
                }

                !fanoutCompatible -> {
                    decodeFailures += 1
                    record.copy(
                        messageCache = record.messageCache + (
                            message.id to MessageCachePolicy.attachRelayEnvelope(
                                CachedMessageState(
                                    body = normalizeLegacyDisplayBody("This group uses native MLS envelopes that are not linked into this Android build yet."),
                                    status = "unsupported",
                                ),
                                message,
                            )
                        ),
                    )
                }

                message.messageKind == "mls-application" && !message.wireMessage.isNullOrBlank() -> {
                    val envelope = decodeMlsFanoutEnvelope(message.wireMessage)
                    if (envelope == null || envelope.senderId != message.senderId) {
                        decodeFailures += 1
                        record.copy(
                            messageCache = record.messageCache + (
                                message.id to MessageCachePolicy.attachRelayEnvelope(
                                    CachedMessageState(
                                        body = normalizeLegacyDisplayBody("The group envelope could not be parsed on Android."),
                                        status = "invalid",
                                    ),
                                    message,
                                )
                            ),
                        )
                    } else {
                        val recipient = envelope.recipients.firstOrNull { it.toUserId == identity.id }
                        if (recipient == null) {
                            decodeFailures += 1
                            record.copy(
                                messageCache = record.messageCache + (
                                    message.id to MessageCachePolicy.attachRelayEnvelope(
                                        CachedMessageState(
                                            body = normalizeLegacyDisplayBody("This Android device did not receive a recipient envelope for that group message."),
                                            status = "invalid",
                                        ),
                                        message,
                                    )
                                ),
                            )
                        } else {
                            try {
                                val opened = StandardsSignalClient.decrypt(
                                    state = signalState,
                                    localUserId = identity.id,
                                    messageKind = recipient.messageKind,
                                    remoteUserId = message.senderId,
                                    wireMessage = recipient.wireMessage,
                                )
                                val payload = decodeStandardsPayload(opened.plaintext)
                                signalState = opened.state
                                record.copy(
                                    messageCache = record.messageCache + (
                                        message.id to MessageCachePolicy.attachRelayEnvelope(
                                            CachedMessageState(
                                                attachments = payload.attachments,
                                                body = payload.text,
                                                status = "ok",
                                            ),
                                            message,
                                        )
                                    ),
                                )
                            } catch (error: Exception) {
                                decodeFailures += 1
                                record.copy(
                                    messageCache = record.messageCache + (
                                        message.id to MessageCachePolicy.attachRelayEnvelope(
                                            CachedMessageState(
                                                body = normalizeSignalDecryptionFailure(error),
                                                status = "invalid",
                                            ),
                                            message,
                                        )
                                    ),
                                )
                            }
                        }
                    }
                }

                else -> {
                    decodeFailures += 1
                    record.copy(
                        messageCache = record.messageCache + (
                            message.id to MessageCachePolicy.attachRelayEnvelope(
                                CachedMessageState(
                                    body = normalizeLegacyDisplayBody("The group message was missing its authenticated envelope payload."),
                                    status = "invalid",
                                ),
                                message,
                            )
                        ),
                    )
                }
            }.copy(
                lastProcessedMessageId = message.id,
                processedMessageCount = record.processedMessageCount + 1,
                protocol = GROUP_PROTOCOL,
                signalPeerUserId = null,
            )
        }

        val refreshed = StandardsSignalClient.refreshBundle(signalState)
        val updatedIdentity = identity.copy(
            standardsMlsReady = fanoutCompatible,
            standardsSignalReady = true,
            standardsSignalBundle = refreshed.bundle,
            standardsSignalState = refreshed.state,
        )

        val fallbackMessages = thread.messages.mapNotNull { message ->
            val cached = record.messageCache[message.id]
            if (!shouldDisplayMessageAfterLocalPurge(record, message, cached)) {
                null
            } else {
                DecryptedMessage(
                    attachments = cached?.attachments ?: emptyList(),
                    body = cached?.body?.takeIf(String::isNotBlank) ?: "Local plaintext unavailable on this Android device for that group message.",
                    createdAt = message.createdAt,
                    id = message.id,
                    senderId = message.senderId,
                    senderName = participants.firstOrNull { it.id == message.senderId }?.displayName ?: "Unknown user",
                    status = cached?.status ?: "missing-local-state",
                    readReceiptSummary = readReceiptSummaryFor(message, thread, participants, identity.id),
                )
            }
        }

        val warning = when {
            !fanoutCompatible -> "This thread uses native RFC 9420 MLS envelopes that this Android build cannot decrypt yet."
            decodeFailures > 0 -> "One or more group envelopes failed decryption on this Android device."
            else -> null
        }

        return MaterializedThread(
            identity = updatedIdentity,
            record = record,
            thread = ConversationThread(
                deliveryCapability = thread.deliveryCapability,
                id = thread.id,
                title = resolveThreadTitle(thread, participants, updatedIdentity.id, record.localTitle),
                mailboxHandle = thread.mailboxHandle,
                protocol = thread.protocol,
                protocolLabel = ProtocolCatalog.label(thread.protocol),
                participants = participants,
                participantIds = thread.participantIds,
                messages = fallbackMessages,
                messageCount = thread.messages.size,
                attachmentCount = thread.attachmentCount,
                lastActivityAt = relayThreadLastActivity(thread),
                supported = fanoutCompatible,
                warning = warning,
            ),
        )
    }

    private fun isMlsFanoutThread(thread: RelayThread): Boolean {
        if (thread.protocol != GROUP_PROTOCOL) {
            return false
        }
        val bootstrap = thread.mlsBootstrap
        if (bootstrap != null) {
            if (bootstrap.ciphersuite.equals(MLS_FANOUT_CIPHERSUITE, ignoreCase = true)) {
                return true
            }
            if (bootstrap.groupId.startsWith("fanout-signal:", ignoreCase = true)) {
                return true
            }
        }
        return thread.messages.any { message ->
            !message.wireMessage.isNullOrBlank() && decodeMlsFanoutEnvelope(message.wireMessage) != null
        }
    }

    private fun materializeUnsupportedThread(
        thread: RelayThread,
        participants: List<RelayUser>,
        existingRecord: ConversationThreadRecord?,
        identityId: String,
        warning: String? = null,
    ): ConversationThread {
        val fallbackMessages = thread.messages.mapNotNull { message ->
            val cached = existingRecord?.messageCache?.get(message.id)
            if (!shouldDisplayMessageAfterLocalPurge(existingRecord, message, cached)) {
                return@mapNotNull null
            }
            DecryptedMessage(
                attachments = cached?.attachments ?: emptyList(),
                body = normalizeLegacyDisplayBody(cached?.body?.takeIf(String::isNotBlank) ?: "This thread can be viewed on Android, but only standards direct chats are writable right now."),
                createdAt = message.createdAt,
                id = message.id,
                senderId = message.senderId,
                senderName = participants.firstOrNull { it.id == message.senderId }?.displayName ?: "Unknown user",
                status = cached?.status ?: "unsupported",
            )
        }
        val finalWarning = warning ?: when (thread.protocol) {
            GROUP_PROTOCOL -> "This group thread is not writable on Android in this build."
            else -> "This thread uses ${ProtocolCatalog.label(thread.protocol)}, which is not writable on Android yet."
        }
        return ConversationThread(
            deliveryCapability = thread.deliveryCapability,
            id = thread.id,
            title = resolveThreadTitle(thread, participants, identityId, existingRecord?.localTitle),
            mailboxHandle = thread.mailboxHandle,
            protocol = thread.protocol,
            protocolLabel = ProtocolCatalog.label(thread.protocol),
            participants = participants,
            participantIds = thread.participantIds,
            messages = fallbackMessages,
            messageCount = thread.messages.size,
            attachmentCount = thread.attachmentCount,
            lastActivityAt = relayThreadLastActivity(thread),
            supported = false,
            warning = finalWarning,
        )
    }

    private fun saveIdentity(identity: LocalIdentity, recoveryRepresentation: String) {
        val catalog = vaultStore.loadCatalog()
        val remaining = catalog.identities.filterNot { it.identity.id == identity.id }
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryRepresentation = recoveryRepresentation,
            savedContacts = emptyList(),
            threadRecords = emptyMap(),
        )
        vaultStore.saveCatalog(
            IdentityCatalog(
                version = 2,
                activeIdentityId = identity.id,
                identities = remaining + record,
            ),
        )
        state = state.copy(
            vaultLocked = false,
            currentIdentity = identity,
            currentDirectoryCode = identity.directoryCode,
            profiles = (remaining + record).map { it.identity },
            onboardingDisplayName = "",
            onboardingUsername = "",
        )
        refreshDeviceInventory(
            catalog = IdentityCatalog(
                version = 2,
                activeIdentityId = identity.id,
                identities = remaining + record,
            ),
            currentDevice = state.currentDevice,
        )
    }

    private fun persistStoredRecord(updatedRecord: StoredIdentityRecord, makeActive: Boolean = true) {
        val catalog = vaultStore.loadCatalog()
        val durableRecord = mergeStoredRecordForPersistence(
            existing = catalog.identities.firstOrNull { it.identity.id == updatedRecord.identity.id },
            incoming = updatedRecord,
        )
        var replaced = false
        val identities = catalog.identities.map { record ->
            if (record.identity.id == durableRecord.identity.id) {
                replaced = true
                durableRecord
            } else {
                record
            }
        }.let { records ->
            if (replaced) records else records + durableRecord
        }
        val nextCatalog = catalog.copy(
            version = maxOf(2, catalog.version),
            activeIdentityId = if (makeActive) durableRecord.identity.id else catalog.activeIdentityId,
            identities = identities,
        )
        vaultStore.saveCatalog(nextCatalog)
        refreshDeviceInventory(
            catalog = nextCatalog,
            currentDevice = state.currentDevice,
        )
    }

    private fun mergeStoredRecordForPersistence(
        existing: StoredIdentityRecord?,
        incoming: StoredIdentityRecord,
    ): StoredIdentityRecord {
        if (existing == null) {
            return incoming
        }
        val mergedThreads = linkedMapOf<String, ConversationThreadRecord>()
        existing.threadRecords.forEach { (threadId, record) -> mergedThreads[threadId] = record }
        incoming.threadRecords.forEach { (threadId, record) ->
            mergedThreads[threadId] = MessageCachePolicy.mergeThreadCaches(
                existing = mergedThreads[threadId],
                incoming = record,
            )
        }
        return incoming.copy(threadRecords = mergedThreads)
    }

    private fun refreshDeviceInventory(
        catalog: IdentityCatalog? = null,
        currentDevice: com.notrus.android.model.DeviceDescriptor? = state.currentDevice,
    ) {
        val effectiveCatalog = catalog ?: runCatching { vaultStore.loadCatalog() }.getOrDefault(IdentityCatalog())
        val vaultInventory = vaultStore.inventorySnapshot()
        val identityAliases = identityProvider.listIdentityAliases()
        val deviceAliases = deviceIdentityProvider.listDeviceAliases()
        val profileIds = effectiveCatalog.identities.associateBy { it.identity.id }

        val profiles = effectiveCatalog.identities
            .map { record ->
                val expectedAliases = identityProvider.expectedAliases(record.identity.id)
                val attachedKinds = identityAliases
                    .filter { it.ownerId == record.identity.id }
                    .map { it.kind }
                    .toSet()
                DeviceInventoryProfile(
                    id = record.identity.id,
                    username = record.identity.username,
                    displayName = record.identity.displayName,
                    createdAt = record.identity.createdAt,
                    directoryCode = record.identity.directoryCode,
                    fingerprint = record.identity.fingerprint,
                    storageMode = record.identity.storageMode,
                    expectedAliases = expectedAliases,
                    missingAliasKinds = listOf("signing", "encryption", "prekey").filterNot(attachedKinds::contains),
                )
            }
            .sortedBy { it.username }

        val aliases = buildList {
            addAll(identityAliases.map { snapshot ->
                snapshot.toInventoryAlias(linkedProfileId = profileIds[snapshot.ownerId]?.identity?.id)
            })
            addAll(deviceAliases.map { snapshot ->
                snapshot.toInventoryAlias(linkedProfileId = null)
            })
        }.sortedWith(compareBy<DeviceInventoryAlias> { it.ownerId ?: "~" }.thenBy { it.alias })

        state = state.copy(
            deviceInventory = LocalDeviceInventory(
                appInstanceId = appInstanceId,
                vaultCatalogPresent = vaultInventory.catalogPresent,
                vaultMasterAlias = vaultInventory.masterKeyAlias,
                vaultMasterAliasPresent = vaultInventory.masterKeyAliasPresent,
                deviceKeyAlias = deviceIdentityProvider.aliasFor(appInstanceId),
                deviceKeyAliasPresent = deviceAliases.any { it.appInstanceId == appInstanceId },
                deviceKeyStorageMode = currentDevice?.storageMode,
                profiles = profiles,
                hardwareAliases = aliases,
            ),
        )
    }

    private fun currentStoredRecord(identityId: String): StoredIdentityRecord? =
        vaultStore.loadCatalog().identities.firstOrNull { it.identity.id == identityId }

    private fun renderProfileCreationError(error: Throwable, attemptedUsername: String): String {
        val baseMessage = error.message?.trim().orEmpty()
        val normalized = baseMessage.lowercase()
        val localProfiles = vaultStore.loadCatalog().identities
            .map { it.identity }
            .sortedBy { it.username }
        val sameUsernameLocal = localProfiles.filter { it.username.equals(attemptedUsername, ignoreCase = true) }
        val profileSummary = localProfiles.joinToString(separator = "; ") { profile ->
            "@${profile.username} (${profile.id})"
        }
        return when {
            normalized.contains("already bound to a different device identity") ||
                normalized.contains("device identity does not match the stored account record") -> {
                val relayConflict = sameUsernameLocal.isEmpty()
                buildString {
                    append(
                        if (relayConflict) {
                            "That username is already registered on the relay by a different account identity."
                        } else if (baseMessage.isNotBlank()) {
                            baseMessage
                        } else {
                            "That username is already bound to a different identity."
                        },
                    )
                    append(" Local profiles on this Android device: ")
                    append(if (profileSummary.isBlank()) "none" else profileSummary)
                    if (sameUsernameLocal.isNotEmpty()) {
                        append(". The same username is already present in your local vault.")
                    }
                }
            }

            baseMessage.isNotBlank() -> baseMessage
            else -> "Unable to create the Android profile."
        }
    }

    private fun resetSignalPeerForFreshDirectChat(identity: LocalIdentity, remoteUserId: String): LocalIdentity {
        val signalState = identity.standardsSignalState ?: return identity
        val resetState = StandardsSignalClient.resetPeer(signalState, remoteUserId)
        val refreshed = StandardsSignalClient.refreshBundle(resetState)
        val updatedIdentity = identity.copy(
            standardsSignalReady = true,
            standardsSignalBundle = refreshed.bundle,
            standardsSignalState = refreshed.state,
        )
        currentStoredRecord(identity.id)?.let { record ->
            persistStoredRecord(record.copy(identity = updatedIdentity))
        }
        state = state.copy(currentIdentity = updatedIdentity)
        return updatedIdentity
    }

    private fun resolveUser(userId: String): RelayUser? {
        val threadUser = state.threads.asSequence()
            .flatMap { it.participants.asSequence() }
            .firstOrNull { it.id == userId }
        return threadUser
            ?: state.directoryResults.firstOrNull { it.id == userId }
            ?: state.contacts.firstOrNull { it.id == userId }
    }

    private fun contactTrustRecord(userId: String): AndroidContactTrustRecord? =
        state.contactTrustRecords.firstOrNull { it.userId == userId }

    private fun observeContactTrust(identityId: String, user: RelayUser): List<AndroidContactTrustRecord> {
        val records = loadContactTrustRecords(identityId).toMutableMap()
        records[user.id] = mergedTrustRecord(records[user.id], user)
        return saveContactTrustRecords(identityId, records)
    }

    private fun reconcileContactTrust(
        identityId: String,
        users: List<RelayUser>,
    ): List<AndroidContactTrustRecord> {
        val records = loadContactTrustRecords(identityId).toMutableMap()
        users
            .filter { it.id != identityId }
            .distinctBy { it.id }
            .forEach { user ->
                records[user.id] = mergedTrustRecord(records[user.id], user)
            }
        return saveContactTrustRecords(identityId, records)
    }

    private fun upsertContactTrust(
        identityId: String,
        trustRecord: AndroidContactTrustRecord,
    ): List<AndroidContactTrustRecord> {
        val records = loadContactTrustRecords(identityId).toMutableMap()
        records[trustRecord.userId] = trustRecord
        return saveContactTrustRecords(identityId, records)
    }

    private fun mergedTrustRecord(
        existing: AndroidContactTrustRecord?,
        user: RelayUser,
    ): AndroidContactTrustRecord {
        val observedFingerprint = user.fingerprint.ifBlank { existing?.observedFingerprint ?: "unknown" }
        val observedPrekeyFingerprint = user.prekeyFingerprint ?: existing?.observedPrekeyFingerprint
        val fingerprintChanged = existing != null &&
            existing.observedFingerprint.isNotBlank() &&
            existing.observedFingerprint != "unknown" &&
            observedFingerprint != existing.observedFingerprint
        val trustedMismatch = existing?.trustedFingerprint != null && existing.trustedFingerprint != observedFingerprint
        val trustedPrekeyMismatch = existing?.trustedPrekeyFingerprint != null &&
            observedPrekeyFingerprint != null &&
            existing.trustedPrekeyFingerprint != observedPrekeyFingerprint
        val status = when {
            fingerprintChanged || trustedMismatch || trustedPrekeyMismatch -> "changed"
            existing?.trustedFingerprint == observedFingerprint && !existing.trustedFingerprint.isNullOrBlank() -> "verified"
            else -> "unverified"
        }
        return AndroidContactTrustRecord(
            blockedAt = existing?.blockedAt,
            displayName = user.displayName.ifBlank { existing?.displayName ?: user.username },
            lastReportedAt = existing?.lastReportedAt,
            lastVerifiedAt = existing?.lastVerifiedAt.takeIf { status == "verified" },
            observedFingerprint = observedFingerprint,
            observedPrekeyFingerprint = observedPrekeyFingerprint,
            status = status,
            trustedFingerprint = existing?.trustedFingerprint,
            trustedPrekeyFingerprint = existing?.trustedPrekeyFingerprint,
            userId = user.id,
            username = user.username.ifBlank { existing?.username ?: user.id.take(8) },
        )
    }

    private fun loadContactTrustRecords(identityId: String): Map<String, AndroidContactTrustRecord> {
        val raw = settings.getString(contactTrustStorageKey(identityId), null) ?: return emptyMap()
        return runCatching {
            val json = JSONObject(raw)
            val records = linkedMapOf<String, AndroidContactTrustRecord>()
            val array = json.optJSONArray("records") ?: JSONArray()
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val userId = item.optString("userId").trim()
                if (userId.isBlank()) {
                    continue
                }
                records[userId] = AndroidContactTrustRecord(
                    blockedAt = nullableString(item, "blockedAt"),
                    displayName = item.optString("displayName").ifBlank { item.optString("username").ifBlank { userId.take(8) } },
                    lastReportedAt = nullableString(item, "lastReportedAt"),
                    lastVerifiedAt = nullableString(item, "lastVerifiedAt"),
                    observedFingerprint = item.optString("observedFingerprint").ifBlank { "unknown" },
                    observedPrekeyFingerprint = nullableString(item, "observedPrekeyFingerprint"),
                    status = item.optString("status").ifBlank { "unverified" },
                    trustedFingerprint = nullableString(item, "trustedFingerprint"),
                    trustedPrekeyFingerprint = nullableString(item, "trustedPrekeyFingerprint"),
                    userId = userId,
                    username = item.optString("username").ifBlank { userId.take(8) },
                )
            }
            records
        }.getOrDefault(emptyMap())
    }

    private fun saveContactTrustRecords(
        identityId: String,
        records: Map<String, AndroidContactTrustRecord>,
    ): List<AndroidContactTrustRecord> {
        val sorted = records.values.sortedWith(
            compareBy<AndroidContactTrustRecord> { it.status != "changed" }
                .thenBy { it.blockedAt == null }
                .thenBy { it.username.lowercase() },
        )
        val array = JSONArray()
        sorted.forEach { record ->
            array.put(
                JSONObject()
                    .put("blockedAt", record.blockedAt ?: JSONObject.NULL)
                    .put("displayName", record.displayName)
                    .put("lastReportedAt", record.lastReportedAt ?: JSONObject.NULL)
                    .put("lastVerifiedAt", record.lastVerifiedAt ?: JSONObject.NULL)
                    .put("observedFingerprint", record.observedFingerprint)
                    .put("observedPrekeyFingerprint", record.observedPrekeyFingerprint ?: JSONObject.NULL)
                    .put("status", record.status)
                    .put("trustedFingerprint", record.trustedFingerprint ?: JSONObject.NULL)
                    .put("trustedPrekeyFingerprint", record.trustedPrekeyFingerprint ?: JSONObject.NULL)
                    .put("userId", record.userId)
                    .put("username", record.username),
            )
        }
        settings.edit()
            .putString(contactTrustStorageKey(identityId), JSONObject().put("records", array).toString())
            .apply()
        return sorted
    }

    private fun contactTrustStorageKey(identityId: String): String =
        "$KEY_CONTACT_TRUST_PREFIX$identityId"

    private fun nullableString(json: JSONObject, key: String): String? =
        if (!json.has(key) || json.isNull(key)) {
            null
        } else {
            json.optString(key).trim().takeIf { value ->
                value.isNotBlank() &&
                    !value.equals("null", ignoreCase = true) &&
                    !value.equals("nil", ignoreCase = true)
            }
        }

    private fun hasUsableContactHandle(user: RelayUser): Boolean {
        if (user.contactHandle.isNullOrBlank()) {
            return false
        }
        val expiresAt = user.contactHandleExpiresAt ?: return true
        return runCatching { Instant.parse(expiresAt).isAfter(Instant.now().plusSeconds(15)) }.getOrDefault(true)
    }

    private fun saveResolvedContact(user: RelayUser) {
        val identity = state.currentIdentity ?: return
        val record = currentStoredRecord(identity.id) ?: return
        val updatedContacts = mergeUsers(record.savedContacts, listOf(user))
        persistStoredRecord(record.copy(savedContacts = updatedContacts))
        val contactTrustRecords = observeContactTrust(identity.id, user)
        state = state.copy(
            contacts = updatedContacts,
            directoryResults = mergeUsers(state.directoryResults, listOf(user)),
            contactTrustRecords = contactTrustRecords,
        )
    }

    private suspend fun ensureRoutingUser(identity: LocalIdentity, user: RelayUser): Pair<LocalIdentity, RelayUser> {
        if (hasUsableContactHandle(user)) {
            return identity to user
        }

        val refreshed = relayClient().searchDirectory(user.username)
            .firstOrNull { candidate -> candidate.id == user.id && hasUsableContactHandle(candidate) }
            ?: error("${user.displayName} is missing a current opaque routing handle. Search the username again and try once more.")

        state = state.copy(
            directoryResults = mergeUsers(state.directoryResults, listOf(refreshed)),
            contacts = mergeUsers(state.contacts, listOf(refreshed)),
        )
        return identity to refreshed
    }

    private fun localDirectoryMatches(query: String, currentIdentityId: String): List<RelayUser> {
        if (query.isBlank()) {
            return emptyList()
        }
        val threadUsers = state.threads.asSequence()
            .flatMap { it.participants.asSequence() }
            .toList()
        return mergeUsers(state.contacts, threadUsers, state.directoryResults)
            .filter { it.id != currentIdentityId }
            .filter { matchesDirectoryQuery(it, query) }
    }

    private fun matchesDirectoryQuery(user: RelayUser, query: String): Boolean {
        val trimmed = query.trim()
        if (trimmed.isEmpty()) {
            return true
        }
        val normalized = trimmed.lowercase()
        val compact = trimmed.lowercase().filter { it.isLetterOrDigit() }
        val username = user.username.lowercase()
        val displayName = user.displayName.lowercase()
        val compactUsername = user.username.lowercase().filter { it.isLetterOrDigit() }
        val compactDisplayName = user.displayName.lowercase().filter { it.isLetterOrDigit() }
        val code = trimmed.uppercase().filter { it in "ABCDEF0123456789" }.takeIf { it.length >= 4 }
        return username.contains(normalized) ||
            displayName.contains(normalized) ||
            (code != null && (user.directoryCode == code || user.directoryCode?.startsWith(code) == true)) ||
            (compact.isNotEmpty() && (compactUsername.contains(compact) || compactDisplayName.contains(compact)))
    }

    private suspend fun ensureRegisteredIdentity(identity: LocalIdentity): LocalIdentity {
        var publishable = identity
        identity.standardsSignalState?.let { signalState ->
            val refreshed = StandardsSignalClient.refreshBundle(signalState)
            publishable = identity.copy(
                standardsSignalReady = true,
                standardsSignalBundle = refreshed.bundle,
                standardsSignalState = refreshed.state,
            )
        }
        val registered = relayClient().register(publishable)
        updateRelaySession(registered.session, identityId = publishable.id)
        val updated = mergeRegisteredIdentity(publishable, registered.user)
        if (updated != identity) {
            currentStoredRecord(identity.id)?.let { persistStoredRecord(it.copy(identity = updated)) }
        }
        return updated
    }

    private fun mergeRegisteredIdentity(identity: LocalIdentity, registered: RelayUser): LocalIdentity =
        identity.copy(
            displayName = registered.displayName.ifBlank { identity.displayName },
            directoryCode = registered.directoryCode ?: identity.directoryCode,
            username = registered.username.ifBlank { identity.username },
        )

    private fun relayClient(): RelayClient =
        relayClient(state.relayOriginInput.ifBlank { defaultRemoteRelayOrigin })

    private fun relayClient(origin: String): RelayClient =
        RelayClient(
            origin = origin,
            integrityReport = state.integrityReport,
            appInstanceId = appInstanceId,
            deviceDescriptor = state.currentDevice,
            sessionToken = relaySession?.token,
        )

    private fun updateRelaySession(
        session: com.notrus.android.model.RelaySession?,
        identityId: String? = state.currentIdentity?.id,
    ) {
        relaySession = session
        NotrusNotificationPrefs.saveRelaySession(applicationContext, session)
        identityId?.takeIf { it.isNotBlank() }?.let {
            NotrusNotificationPrefs.saveRelaySessionForIdentity(applicationContext, it, session)
        }
    }

    private fun sessionIsUsable(): Boolean {
        return NotrusNotificationPrefs.sessionIsUsable(relaySession)
    }

    private fun startLiveEventsIfPossible() {
        val keepLive = appInForeground
        if (!keepLive) {
            return
        }
        val identity = state.currentIdentity ?: return
        if (!sessionIsUsable()) {
            return
        }
        if (liveEventsJob?.isActive == true) {
            return
        }

        val identityId = identity.id
        liveEventsJob = viewModelScope.launch {
            var backoffMs = 1_200L
            while (isActive && appInForeground && state.currentIdentity?.id == identityId) {
                val activeIdentity = state.currentIdentity ?: break
                try {
                    relayClient().streamEvents { _, threadId ->
                        if (appInForeground) {
                            scheduleLiveSync(threadId)
                        }
                    }
                    backoffMs = 1_200L
                } catch (_: Exception) {
                    if (
                        !isActive ||
                        !appInForeground ||
                        state.currentIdentity?.id != activeIdentity.id
                    ) {
                        break
                    }
                    if (appInForeground) {
                        scheduleLiveSync(null)
                    }
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(15_000L)
                }
            }
        }
    }

    private fun stopLiveEvents() {
        liveEventsJob?.cancel()
        liveEventsJob = null
        liveSyncDebounceJob?.cancel()
        liveSyncDebounceJob = null
    }

    private fun scheduleLiveSync(preferredThreadId: String?) {
        liveSyncDebounceJob?.cancel()
        liveSyncDebounceJob = viewModelScope.launch {
            delay(360L)
            val identity = state.currentIdentity ?: return@launch
                registerAndSync(
                    identity = identity,
                    preferredThreadId = state.selectedThreadId,
                    presentation = SyncPresentation.Silent,
                )
        }
    }

    private suspend fun applyPrivacyDelayIfEnabled(kind: PrivacyDelayKind) {
        if (!state.privacyModeEnabled) {
            return
        }
        val delayWindow = when (kind) {
            PrivacyDelayKind.Sync -> 250L..900L
            PrivacyDelayKind.Interactive -> 120L..420L
            PrivacyDelayKind.Delivery -> 150L..500L
        }
        delay(Random.nextLong(from = delayWindow.first, until = delayWindow.last + 1))
    }

    private suspend fun bootstrapRelaySession(identity: LocalIdentity): LocalIdentity {
        val registration = relayClient().register(identity)
        updateRelaySession(registration.session, identityId = identity.id)
        state = state.copy(
            currentDirectoryCode = registration.user.directoryCode ?: state.currentDirectoryCode,
            linkedDeviceEvents = registration.deviceEvents,
            linkedDevices = registration.devices,
        )
        return mergeRegisteredIdentity(identity, registration.user)
    }

    private suspend fun relayClientAndHealth(): Pair<RelayClient, com.notrus.android.model.RelayHealth> {
        val currentOrigin = RelayClient.validateOrigin(state.relayOriginInput.ifBlank { defaultRemoteRelayOrigin })
        val primary = relayClient(currentOrigin)
        return runCatching { primary to primary.health() }
            .recoverCatching { error ->
                if (!isBootstrapLocalRelay(currentOrigin) || defaultRemoteRelayOrigin.isBlank()) {
                    throw error
                }
                val fallbackOrigin = RelayClient.validateOrigin(defaultRemoteRelayOrigin)
                val fallbackClient = relayClient(fallbackOrigin)
                val fallbackHealth = fallbackClient.health()
                settings.edit().putString(KEY_RELAY_ORIGIN, fallbackOrigin).apply()
                state = state.copy(
                    relayOriginInput = fallbackOrigin,
                    statusMessage = "Switched Android to the HTTPS relay.",
                    errorMessage = null,
                )
                fallbackClient to fallbackHealth
            }
            .getOrThrow()
    }

    private fun mergeUsers(vararg lists: List<RelayUser>): List<RelayUser> {
        val merged = linkedMapOf<String, RelayUser>()
        lists.forEach { users ->
            users.forEach { user ->
                val existing = merged[user.id]
                merged[user.id] = if (existing == null) {
                    user
                } else {
                    existing.copy(
                        username = user.username.ifBlank { existing.username },
                        displayName = user.displayName.ifBlank { existing.displayName },
                        contactHandle = user.contactHandle ?: existing.contactHandle,
                        contactHandleExpiresAt = user.contactHandleExpiresAt ?: existing.contactHandleExpiresAt,
                        directoryCode = user.directoryCode ?: existing.directoryCode,
                        fingerprint = user.fingerprint.ifBlank { existing.fingerprint },
                        createdAt = user.createdAt.ifBlank { existing.createdAt },
                        updatedAt = user.updatedAt ?: existing.updatedAt,
                        mlsKeyPackage = user.mlsKeyPackage ?: existing.mlsKeyPackage,
                        prekeyCreatedAt = user.prekeyCreatedAt ?: existing.prekeyCreatedAt,
                        prekeyFingerprint = user.prekeyFingerprint ?: existing.prekeyFingerprint,
                        prekeyPublicJwk = user.prekeyPublicJwk ?: existing.prekeyPublicJwk,
                        prekeySignature = user.prekeySignature ?: existing.prekeySignature,
                        signingPublicJwk = user.signingPublicJwk ?: existing.signingPublicJwk,
                        encryptionPublicJwk = user.encryptionPublicJwk ?: existing.encryptionPublicJwk,
                        signalBundle = user.signalBundle ?: existing.signalBundle,
                    )
                }
            }
        }
        return merged.values.sortedBy { it.username.lowercase() }
    }

    private fun resolveThreadTitle(
        thread: RelayThread,
        participants: List<RelayUser>,
        identityId: String,
        localTitle: String? = null,
    ): String {
        if (!localTitle.isNullOrBlank()) {
            return localTitle
        }
        if (thread.title.isNotBlank()) {
            return thread.title
        }
        val remoteNames = participants.filter { it.id != identityId }.map { it.displayName.ifBlank { it.username } }
        return remoteNames.joinToString(", ").ifBlank { thread.id }
    }

    private fun relayThreadLastActivity(thread: RelayThread): String =
        thread.messages.lastOrNull()?.createdAt ?: thread.createdAt

    private fun placeholderUser(userId: String): RelayUser =
        RelayUser(
            id = userId,
            username = userId.take(8),
            displayName = "Unknown user",
            fingerprint = "unknown",
            createdAt = Instant.EPOCH.toString(),
        )

    private fun resolveAttachmentDraft(uri: Uri): LocalAttachmentDraft {
        val resolver = applicationContext.contentResolver
        var displayName = "attachment.bin"
        var byteLength = -1L
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex >= 0) {
                        displayName = cursor.getString(nameIndex) ?: displayName
                    }
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) {
                        byteLength = cursor.getLong(sizeIndex)
                    }
                }
            }
        val mediaType = resolver.getType(uri).orEmpty().ifBlank { "application/octet-stream" }
        if (byteLength > AttachmentCrypto.MaxAttachmentSizeBytes) {
            error("Android attachments are limited to ${AttachmentCrypto.MaxAttachmentSizeBytes / (1024 * 1024)} MB per file.")
        }

        return LocalAttachmentDraft(
            id = UUID.randomUUID().toString().lowercase(),
            byteLength = byteLength.coerceAtLeast(0L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            fileName = AttachmentCrypto.sanitizeFileName(displayName),
            mediaType = mediaType,
            uri = uri.toString(),
        )
    }

    private fun readAttachmentBytes(uri: Uri, expectedName: String): ByteArray {
        val bytes = applicationContext.contentResolver.openInputStream(uri)?.use { stream ->
            stream.readBytes()
        } ?: error("Android could not open $expectedName.")
        if (bytes.size > AttachmentCrypto.MaxAttachmentSizeBytes) {
            error("$expectedName exceeds Android's ${AttachmentCrypto.MaxAttachmentSizeBytes / (1024 * 1024)} MB attachment limit.")
        }
        return bytes
    }

    private fun encodeStandardsPayload(payload: StandardsMessagePayload): String {
        val attachments = JSONArray()
        payload.attachments.forEach { reference ->
            attachments.put(
                JSONObject()
                    .put("attachmentKey", reference.attachmentKey)
                    .put("byteLength", reference.byteLength)
                    .put("fileName", reference.fileName)
                    .put("id", reference.id)
                    .put("mediaType", reference.mediaType)
                    .put("sha256", reference.sha256)
            )
        }
        return JSONObject()
            .put("attachments", attachments)
            .put("text", payload.text)
            .put("version", 1)
            .toString()
    }

    private fun encodeMlsFanoutEnvelope(envelope: MlsFanoutEnvelope): String {
        val recipients = JSONArray()
        envelope.recipients.forEach { recipient ->
            recipients.put(
                JSONObject()
                    .put("messageKind", recipient.messageKind)
                    .put("toUserId", recipient.toUserId)
                    .put("wireMessage", recipient.wireMessage),
            )
        }
        return JSONObject()
            .put("format", envelope.format)
            .put("senderId", envelope.senderId)
            .put("version", envelope.version)
            .put("recipients", recipients)
            .toString()
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
        val version = json.optInt("version", 0)
        if (version != 1) {
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
            version = version,
            recipients = recipients,
        )
    }

    private fun decodeStandardsPayload(plaintext: String): StandardsMessagePayload {
        val normalizedLegacy = normalizeLegacyDisplayBody(plaintext)
        val envelope = runCatching { JSONObject(plaintext) }.getOrNull()
            ?: return StandardsMessagePayload(attachments = emptyList(), text = normalizedLegacy)
        if (envelope.optInt("version", 0) != 1) {
            return StandardsMessagePayload(attachments = emptyList(), text = normalizedLegacy)
        }

        val text = envelope.optString("text", "")
        val attachments = buildList {
            val array = envelope.optJSONArray("attachments") ?: JSONArray()
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val id = item.optString("id").trim()
                val attachmentKey = item.optString("attachmentKey").trim()
                val fileName = item.optString("fileName").trim()
                val mediaType = item.optString("mediaType").trim()
                val sha256 = item.optString("sha256").trim()
                if (id.isBlank() || attachmentKey.isBlank() || fileName.isBlank() || mediaType.isBlank() || sha256.isBlank()) {
                    continue
                }
                add(
                    SecureAttachmentReference(
                        attachmentKey = attachmentKey,
                        byteLength = item.optInt("byteLength", 0).coerceAtLeast(0),
                        fileName = fileName,
                        id = id,
                        mediaType = mediaType,
                        sha256 = sha256,
                    )
                )
            }
        }

        return StandardsMessagePayload(
            attachments = attachments,
            text = text,
        )
    }

    private fun normalizeSignalDecryptionFailure(error: Throwable): String {
        val message = error.message?.trim().orEmpty()
        val normalized = message.lowercase()
        return when {
            normalized.contains("counter") ||
                normalized.contains("duplicate") ||
                normalized.contains("chain key") ->
                "This secure message could not be opened with the current local session history. Send a new message to re-establish the session."

            normalized.contains("no session") ||
                normalized.contains("missing session") ->
                "This secure session is out of sync on this device. Send a new message to re-establish encryption state."

            normalized.contains("prekey") ->
                "The sender must publish fresh prekeys before this device can open that secure message."

            message.isNotBlank() -> normalizeLegacyDisplayBody(message)
            else -> "Android could not decrypt that secure message."
        }
    }

    private fun normalizeSignalSendFailure(error: Throwable): String {
        val message = error.message?.trim().orEmpty()
        val normalized = message.lowercase()
        return when {
            normalized.contains("prekey") ->
                "This contact needs to open Notrus once to refresh secure messaging keys, then sending can continue."

            normalized.contains("no session") ||
                normalized.contains("missing session") ->
                "This secure session is out of sync. Use Reset secure session from the chat menu, then try again."

            normalized.contains("untrusted identity") ->
                "This contact's security number changed. Verify the contact in Security before sending again."

            message.isNotBlank() -> normalizeLegacyDisplayBody(message)
            else -> "Android could not send that secure message."
        }
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

        val explicitText = listOf(
            "\"text\":\"",
            "text=",
            "text:",
        ).firstNotNullOfOrNull { marker ->
            extractLegacyField(trimmed, marker)
        }
        if (!explicitText.isNullOrBlank()) {
            return explicitText
        }

        return trimmed
    }

    private fun extractLegacyField(source: String, marker: String): String? {
        val start = source.indexOf(marker)
        if (start < 0) {
            return null
        }
        val valueStart = start + marker.length
        val terminators = listOf(", attachments", ", version", ", cover", ", epochCommit", ", padding", "\",", ")", "}")
        val valueEnd = terminators
            .map { terminator -> source.indexOf(terminator, startIndex = valueStart) }
            .filter { it >= 0 }
            .minOrNull()
            ?: source.length
        return source.substring(valueStart, valueEnd)
            .trim()
            .trim('"')
    }

    private fun shouldDisplayMessageAfterLocalPurge(
        record: ConversationThreadRecord?,
        message: RelayMessage,
        cached: CachedMessageState?,
    ): Boolean {
        if (cached?.hidden == true) {
            return false
        }
        val purgedAt = record?.purgedAt ?: return true
        if (isoTimestampAtOrBefore(message.createdAt, purgedAt)) {
            return false
        }
        return true
    }

    private fun isoTimestampAtOrBefore(left: String, right: String): Boolean {
        val leftInstant = runCatching { Instant.parse(left) }.getOrNull() ?: return left <= right
        val rightInstant = runCatching { Instant.parse(right) }.getOrNull() ?: return left <= right
        return !leftInstant.isAfter(rightInstant)
    }

    private fun deviceActionPayload(
        action: String,
        createdAt: String,
        signerDeviceId: String,
        targetDeviceId: String,
        userId: String,
    ): String =
        """{"action":"$action","createdAt":"$createdAt","signerDeviceId":"$signerDeviceId","targetDeviceId":"$targetDeviceId","userId":"$userId"}"""

    private suspend fun authorizeSensitiveOperation(
        activity: FragmentActivity,
        reason: String,
        maxAgeMs: Long = 120_000L,
    ): Boolean {
        val now = System.currentTimeMillis()
        if (maxAgeMs > 0 && now - lastSensitiveAuthAtMs <= maxAgeMs) {
            return true
        }
        if (!BiometricGate.isAvailable(activity)) {
            state = state.copy(
                errorMessage = "This Android device requires biometric or device-credential confirmation for that action.",
            )
            return false
        }
        val approved = BiometricGate.authenticate(
            activity = activity,
            executor = activity.mainExecutor,
            title = "Authorize sensitive action",
            subtitle = reason,
        )
        if (!approved) {
            state = state.copy(errorMessage = "Sensitive action cancelled.")
            return false
        }
        lastSensitiveAuthAtMs = now
        return true
    }

    private fun witnessOrigins(): List<String> =
        state.witnessOriginsInput
            .split(',', '\n')
            .map { it.trim().trimEnd('/') }
            .filter { it.isNotEmpty() }

    private fun loadTransparencyPins(): Map<String, String> {
        return loadPinnedMap(KEY_TRANSPARENCY_PINS)
    }

    private fun loadTransparencySignerPins(): Map<String, String> {
        return loadPinnedMap(KEY_TRANSPARENCY_SIGNER_PINS)
    }

    private fun loadPinnedMap(key: String): Map<String, String> {
        val raw = settings.getString(key, null) ?: return emptyMap()
        return runCatching {
            val json = JSONObject(raw)
            json.keys().asSequence().associateWith { key -> json.optString(key) }
                .filterValues { value -> value.isNotBlank() }
        }.getOrDefault(emptyMap())
    }

    private fun persistTransparencyPinIfNeeded(result: com.notrus.android.model.TransparencyVerificationResult) {
        val head = result.head ?: return
        if (!result.chainValid) {
            return
        }
        val relayOrigin = RelayClient.validateOrigin(state.relayOriginInput)
        val pins = loadTransparencyPins().toMutableMap()
        pins[relayOrigin] = head
        val editor = settings.edit()
        editor.putString(KEY_TRANSPARENCY_PINS, JSONObject(pins as Map<*, *>).toString())

        result.signerKeyId?.let { signerKeyId ->
            val signerPins = loadTransparencySignerPins().toMutableMap()
            signerPins[relayOrigin] = signerKeyId
            editor.putString(KEY_TRANSPARENCY_SIGNER_PINS, JSONObject(signerPins as Map<*, *>).toString())
        }

        editor.apply()
    }

    private fun clearPinnedValue(key: String, relayOrigin: String) {
        val updated = loadPinnedMap(key).toMutableMap().apply {
            remove(relayOrigin)
        }
        val editor = settings.edit()
        if (updated.isEmpty()) {
            editor.remove(key)
        } else {
            editor.putString(key, JSONObject(updated as Map<*, *>).toString())
        }
        editor.apply()
    }

    private fun bootstrapRelayOrigin(storedOrigin: String?): String {
        val trimmed = storedOrigin?.trim().orEmpty()
        if (trimmed.isBlank()) {
            return defaultRemoteRelayOrigin
        }
        return if (isBootstrapLocalRelay(trimmed)) defaultRemoteRelayOrigin else trimmed
    }

    private fun isBootstrapLocalRelay(origin: String): Boolean =
        BOOTSTRAP_LOCAL_RELAY_ORIGINS.contains(origin.trim().trimEnd('/'))

    private fun canResetTransparencyTrust(result: com.notrus.android.model.TransparencyVerificationResult): Boolean {
        if (result.chainValid || result.warnings.isEmpty()) {
            return false
        }
        return result.warnings.all { warning ->
            warning.contains("previously pinned", ignoreCase = true) ||
                warning.contains("changed its transparency signing key", ignoreCase = true)
        }
    }

    private fun transparencyBlockMessage(context: String): String =
        if (state.transparencyResetAvailable) {
            "Transparency verification needs attention $context. Reset transparency trust for this relay, then sync again."
        } else {
            "Transparency verification needs attention $context."
        }

    override fun onCleared() {
        stopLiveEvents()
        super.onCleared()
    }

    companion object {
        private const val DefaultStatusMessage = "Android native client ready."
        private const val KEY_PRIVACY_MODE_ENABLED = "privacy_mode_enabled"
        private const val KEY_VISUAL_EFFECTS_ENABLED = "visual_effects_enabled"
        private const val KEY_COLOR_THEME_PRESET = "color_theme_preset"
        private const val KEY_THEME_MODE = "theme_mode"
        private const val KEY_SEND_READ_RECEIPTS_TO_OTHERS = "send_read_receipts_to_others"
        private const val KEY_CONTACT_TRUST_PREFIX = "contact_trust_"
        private const val KEY_RELAY_ORIGIN = "relay_origin"
        private const val KEY_TRANSPARENCY_PINS = "transparency_pins"
        private const val KEY_TRANSPARENCY_SIGNER_PINS = "transparency_signer_pins"
        private const val KEY_WITNESS_ORIGINS = "witness_origins"

        private fun isLowRamDevice(context: Context): Boolean {
            val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            return manager?.isLowRamDevice == true
        }
    }
}

private data class MaterializedThread(
    val identity: LocalIdentity,
    val record: ConversationThreadRecord,
    val thread: ConversationThread,
)

private fun HardwareAliasSnapshot.toInventoryAlias(linkedProfileId: String?): DeviceInventoryAlias =
    DeviceInventoryAlias(
        alias = alias,
        ownerId = ownerId,
        kind = kind,
        storageMode = storageMode,
        linkedProfileId = linkedProfileId,
    )

private fun DeviceAliasSnapshot.toInventoryAlias(linkedProfileId: String?): DeviceInventoryAlias =
    DeviceInventoryAlias(
        alias = alias,
        ownerId = appInstanceId,
        kind = "device-management",
        storageMode = storageMode,
        linkedProfileId = linkedProfileId,
    )
