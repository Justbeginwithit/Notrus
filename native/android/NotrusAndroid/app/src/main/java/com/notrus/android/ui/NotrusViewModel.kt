package com.notrus.android.ui

import android.app.Application
import android.content.Context
import com.notrus.android.BuildConfig
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notrus.android.model.AppUiState
import com.notrus.android.model.CachedMessageState
import com.notrus.android.model.ConversationThread
import com.notrus.android.model.ConversationThreadRecord
import com.notrus.android.model.DecryptedMessage
import com.notrus.android.model.IdentityCatalog
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.RelayMessage
import com.notrus.android.model.RelayThread
import com.notrus.android.model.RelayUser
import com.notrus.android.model.StoredIdentityRecord
import com.notrus.android.model.selectedThread
import com.notrus.android.protocol.ProtocolCatalog
import com.notrus.android.protocol.StandardsSignalClient
import com.notrus.android.relay.RelayClient
import com.notrus.android.security.BiometricGate
import com.notrus.android.security.DeviceIdentityProvider
import com.notrus.android.security.DeviceRiskSignals
import com.notrus.android.security.RecoveryKeyManager
import com.notrus.android.security.StrongBoxIdentityProvider
import com.notrus.android.security.TransparencyVerifier
import com.notrus.android.security.VaultStore
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.launch
import org.json.JSONObject

private const val DIRECT_PROTOCOL = "signal-pqxdh-double-ratchet-v1"
private const val GROUP_PROTOCOL = "mls-rfc9420-v1"
private val BOOTSTRAP_LOCAL_RELAY_ORIGINS = setOf(
    "http://10.0.2.2:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
)

private data class MaterializedSyncState(
    val identity: LocalIdentity,
    val threadRecords: Map<String, ConversationThreadRecord>,
    val threads: List<ConversationThread>,
)

class NotrusViewModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(AppUiState())
        private set

    private val applicationContext = application.applicationContext
    private val vaultStore = VaultStore(applicationContext)
    private val deviceIdentityProvider = DeviceIdentityProvider()
    private val identityProvider = StrongBoxIdentityProvider()
    private val settings = applicationContext.getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
    private val defaultRemoteRelayOrigin = BuildConfig.DEFAULT_RELAY_ORIGIN.trim()
    private val appInstanceId = settings.getString(KEY_APP_INSTANCE_ID, null)
        ?: UUID.randomUUID().toString().also {
            settings.edit().putString(KEY_APP_INSTANCE_ID, it).apply()
        }
    private var lastSensitiveAuthAtMs: Long = 0L

    init {
        val integrity = DeviceRiskSignals.capture(applicationContext)
        state = state.copy(
            currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId),
            integrityReport = integrity,
            relayOriginInput = bootstrapRelayOrigin(settings.getString(KEY_RELAY_ORIGIN, null)),
            witnessOriginsInput = settings.getString(KEY_WITNESS_ORIGINS, "") ?: "",
        )
        bootstrap()
    }

    fun updateRelayOrigin(value: String) {
        state = state.copy(relayOriginInput = value, errorMessage = null)
        settings.edit().putString(KEY_RELAY_ORIGIN, value).apply()
    }

    fun updateOnboardingDisplayName(value: String) {
        state = state.copy(onboardingDisplayName = value)
    }

    fun updateOnboardingUsername(value: String) {
        state = state.copy(
            onboardingUsername = value.lowercase().filter { it.isLetterOrDigit() || it == '_' || it == '.' },
        )
    }

    fun updateWitnessOrigins(value: String) {
        state = state.copy(witnessOriginsInput = value, errorMessage = null)
        settings.edit().putString(KEY_WITNESS_ORIGINS, value).apply()
    }

    fun updateDirectoryQuery(value: String) {
        state = state.copy(directoryQuery = value)
    }

    fun updateDraftText(value: String) {
        state = state.copy(draftText = value)
    }

    fun selectThread(threadId: String) {
        state = state.copy(selectedThreadId = threadId, errorMessage = null)
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
                title = "Unlock Notrus Android",
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

            state = state.copy(
                currentDevice = deviceIdentityProvider.descriptor(applicationContext, appInstanceId),
                vaultLocked = false,
                integrityReport = DeviceRiskSignals.capture(applicationContext),
                profiles = profiles,
                currentIdentity = current,
                currentDirectoryCode = current?.directoryCode,
                statusMessage = "Vault unlocked on this Android device.",
                errorMessage = null,
            )
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

        viewModelScope.launch {
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Creating a hardware-backed Android identity...")
            runCatching {
                RelayClient.validateOrigin(state.relayOriginInput.ifBlank { defaultRemoteRelayOrigin })
                val hardware = identityProvider.createIdentity(username = username, displayName = displayName)
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
                saveIdentity(identity, recovery.privateKeyPkcs8)
                registerAndSync(identity)
            }.onFailure { error ->
                state = state.copy(
                    isBusy = false,
                    errorMessage = error.message ?: "Unable to create the Android profile.",
                )
            }
        }
    }

    fun switchProfile(identityId: String) {
        val catalog = vaultStore.loadCatalog()
        val updatedCatalog = catalog.copy(activeIdentityId = identityId)
        vaultStore.saveCatalog(updatedCatalog)
        val current = updatedCatalog.identities.firstOrNull { it.identity.id == identityId }?.identity
        state = state.copy(
            currentIdentity = current,
            currentDirectoryCode = current?.directoryCode,
            selectedThreadId = null,
            draftText = "",
        )
        if (current != null) {
            viewModelScope.launch {
                registerAndSync(current)
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
                val results = mergeUsers(
                    localMatches,
                    relayClient().searchDirectory(activeIdentity.id, query)
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
        state = state.copy(
            contacts = savedContacts,
            statusMessage = "Saved ${user.displayName} for secure direct messaging.",
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
            state = state.copy(errorMessage = "${user.displayName} has not published a Signal bundle yet.")
            return
        }

        val existingThread = state.threads.firstOrNull { thread ->
            thread.protocol == DIRECT_PROTOCOL &&
                thread.participantIds.toSet() == setOf(identity.id, user.id)
        }
        if (existingThread != null) {
            saveContact(user.id)
            state = state.copy(
                selectedThreadId = existingThread.id,
                statusMessage = "Opened secure direct chat with ${user.displayName}.",
                errorMessage = null,
            )
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize establishing or reopening a direct Signal session on this Android device.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Creating a direct Signal thread with ${user.displayName}...")
            runCatching {
                val activeIdentity = ensureRegisteredIdentity(identity)
                saveContact(user.id)
                val threadId = relayClient().createDirectThread(activeIdentity.id, user.id)
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

        if (body.isEmpty()) {
            state = state.copy(errorMessage = "Type a message before sending.")
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
        if (thread.protocol != DIRECT_PROTOCOL) {
            state = state.copy(errorMessage = "Android can currently send only standards direct messages.")
            return
        }
        if (!thread.supported) {
            state = state.copy(errorMessage = thread.warning ?: "This thread is not writable on Android yet.")
            return
        }

        val remoteUser = thread.participants.firstOrNull { it.id != identity.id }
        if (remoteUser == null || remoteUser.signalBundle == null) {
            state = state.copy(errorMessage = "The remote Signal bundle is missing for this thread.")
            return
        }

        viewModelScope.launch {
            if (!authorizeSensitiveOperation(activity, "Authorize sending ciphertext from this Android device.")) {
                return@launch
            }
            state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Encrypting and sending your Signal message...")
            runCatching {
                val signalState = identity.standardsSignalState
                    ?: error("This Android profile does not have local Signal state.")
                val sealed = StandardsSignalClient.encrypt(
                    state = signalState,
                    localUserId = identity.id,
                    plaintext = body,
                    remoteBundle = remoteUser.signalBundle,
                    remoteUserId = remoteUser.id,
                )
                val messageId = relayClient().postSignalMessage(
                    threadId = thread.id,
                    senderId = identity.id,
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
                        messageId to CachedMessageState(
                            body = body,
                            status = "ok",
                        )
                    ),
                )
                persistStoredRecord(
                    currentRecord.copy(
                        identity = updatedIdentity,
                        threadRecords = currentRecord.threadRecords + mapOf(thread.id to updatedThreadRecord),
                    ),
                )
                state = state.copy(currentIdentity = updatedIdentity, draftText = "")
                registerAndSync(updatedIdentity, preferredThreadId = thread.id)
            }.onFailure { error ->
                state = state.copy(isBusy = false, errorMessage = error.message)
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
        if (!state.vaultLocked) {
            state = state.copy(statusMessage = "Create the first Android profile to join your relay.")
        }
    }

    private suspend fun registerAndSync(identity: LocalIdentity, preferredThreadId: String? = state.selectedThreadId) {
        state = state.copy(isBusy = true, errorMessage = null, statusMessage = "Registering profile and syncing relay state...")
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

            val (relay, relayHealth) = relayClientAndHealth()
            val registered = relay.register(workingIdentity)
            workingIdentity = mergeRegisteredIdentity(workingIdentity, registered)
            latestKnownIdentity = workingIdentity
            existingRecord?.let { persistStoredRecord(it.copy(identity = workingIdentity)) }
            state = state.copy(
                currentIdentity = workingIdentity,
                currentDirectoryCode = workingIdentity.directoryCode,
            )
            val sync = relay.sync(workingIdentity.id)
            val remoteUsers = sync.users.filter { it.id != workingIdentity.id }
            val currentDirectoryCode = sync.users.firstOrNull { it.id == workingIdentity.id }?.directoryCode ?: registered.directoryCode
            if (currentDirectoryCode != null && currentDirectoryCode != workingIdentity.directoryCode) {
                workingIdentity = workingIdentity.copy(directoryCode = currentDirectoryCode)
                latestKnownIdentity = workingIdentity
            }
            val storedRecord = currentStoredRecord(workingIdentity.id)
                ?: error("The Android profile record is missing from the local vault.")
            val mergedUsers = mergeUsers(remoteUsers, storedRecord.savedContacts)
            val transparency = TransparencyVerifier.verify(
                relayOrigin = RelayClient.validateOrigin(state.relayOriginInput),
                entryCount = sync.transparencyEntryCount,
                entries = sync.transparencyEntries,
                expectedHead = sync.transparencyHead,
                expectedSignature = sync.transparencySignature,
                signer = sync.transparencySigner,
                pinnedHeads = loadTransparencyPins(),
                pinnedSignerKeys = loadTransparencySignerPins(),
                witnessOrigins = witnessOrigins(),
                fetchWitness = { witnessOrigin, relayOrigin ->
                    relay.fetchWitnessHead(witnessOrigin, relayOrigin)
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
            val profiles = vaultStore.loadCatalog().identities.map { it.identity }
            val selectedThreadId = preferredThreadId
                ?.takeIf { preferred -> materialized.threads.any { it.id == preferred } }
                ?: state.selectedThreadId?.takeIf { current -> materialized.threads.any { it.id == current } }
                ?: materialized.threads.firstOrNull()?.id

            state = state.copy(
                currentIdentity = materialized.identity,
                currentDirectoryCode = currentDirectoryCode,
                currentDevice = currentDevice,
                profiles = profiles,
                contacts = mergedUsers,
                transparency = transparency,
                transparencyResetAvailable = canResetTransparencyTrust(transparency),
                linkedDeviceEvents = sync.deviceEvents,
                linkedDevices = sync.devices,
                threads = materialized.threads,
                relayHealth = relayHealth,
                selectedThreadId = selectedThreadId,
                statusMessage = if (!transparency.chainValid) {
                    "Android sync completed, but transparency verification needs attention before you trust new keys or create new chats."
                } else if (sync.directoryDiscoveryMode == "exact-username-or-invite" || sync.directoryDiscoveryMode == "username-or-invite") {
                    "Android sync complete. Search contacts by username or invite code, save them locally, then open direct Signal chats from this device."
                } else {
                    "Android sync complete. Contacts and direct Signal threads are ready on this device."
                },
                errorMessage = null,
                isBusy = false,
            )
        }.onFailure { error ->
            state = state.copy(
                isBusy = false,
                currentIdentity = latestKnownIdentity,
                currentDirectoryCode = latestKnownIdentity.directoryCode,
                errorMessage = error.message ?: "Relay sync failed.",
            )
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

            if (thread.protocol == DIRECT_PROTOCOL && participants.size == 2) {
                val materialized = materializeDirectSignalThread(
                    thread = thread,
                    participants = participants,
                    identity = updatedIdentity,
                    existingRecord = updatedRecords[thread.id],
                )
                updatedIdentity = materialized.identity
                updatedRecords[thread.id] = materialized.record
                materialized.thread
            } else {
                materializeUnsupportedThread(
                    thread = thread,
                    participants = participants,
                    existingRecord = updatedRecords[thread.id],
                    identityId = updatedIdentity.id,
                )
            }
        }
        return MaterializedSyncState(
            identity = updatedIdentity,
            threadRecords = updatedRecords,
            threads = conversations,
        )
    }

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
                    warning = "This Android profile is missing its local Signal state.",
                ),
            )
        var record = existingRecord ?: ConversationThreadRecord(
            protocol = DIRECT_PROTOCOL,
            signalPeerUserId = remoteUser.id,
        )

        if (
            record.processedMessageCount > thread.messages.size ||
            (
                record.processedMessageCount > 0 &&
                    thread.messages.getOrNull(record.processedMessageCount - 1)?.id != record.lastProcessedMessageId
                )
        ) {
            return MaterializedThread(
                identity = identity,
                record = record,
                thread = materializeUnsupportedThread(
                    thread = thread,
                    participants = participants,
                    existingRecord = record,
                    identityId = identity.id,
                    warning = "The local Signal session state no longer matches the relay transcript on this Android device.",
                ),
            )
        }

        for (message in thread.messages.drop(record.processedMessageCount)) {
            record = when {
                message.senderId == identity.id -> record.copy(
                    messageCache = if (record.messageCache.containsKey(message.id)) {
                        record.messageCache
                    } else {
                        record.messageCache + (
                            message.id to CachedMessageState(
                                body = "Sent from this Android device.",
                                status = "missing-local-state",
                            )
                        )
                    },
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
                        signalState = opened.state
                        record.copy(
                            messageCache = record.messageCache + (
                                message.id to CachedMessageState(
                                    body = opened.plaintext,
                                    status = "ok",
                                )
                            ),
                        )
                    } catch (error: Exception) {
                        record.copy(
                            messageCache = record.messageCache + (
                                message.id to CachedMessageState(
                                    body = error.message ?: "Signal decryption failed.",
                                    status = "invalid",
                                )
                            ),
                        )
                    }
                }

                else -> record.copy(
                    messageCache = record.messageCache + (
                        message.id to CachedMessageState(
                            body = "The Signal message was missing its authenticated wire payload.",
                            status = "invalid",
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
            if (cached?.hidden == true) {
                null
            } else {
                DecryptedMessage(
                    attachments = cached?.attachments ?: emptyList(),
                    body = cached?.body ?: "Local plaintext is unavailable on this Android device for that Signal message.",
                    createdAt = message.createdAt,
                    id = message.id,
                    senderId = message.senderId,
                    senderName = participants.firstOrNull { it.id == message.senderId }?.displayName ?: "Unknown user",
                    status = cached?.status ?: "missing-local-state",
                )
            }
        }

        return MaterializedThread(
            identity = updatedIdentity,
            record = record,
            thread = ConversationThread(
                id = thread.id,
                title = resolveThreadTitle(thread, participants, updatedIdentity.id, record.localTitle),
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

    private fun materializeUnsupportedThread(
        thread: RelayThread,
        participants: List<RelayUser>,
        existingRecord: ConversationThreadRecord?,
        identityId: String,
        warning: String? = null,
    ): ConversationThread {
        val fallbackMessages = thread.messages.map { message ->
            val cached = existingRecord?.messageCache?.get(message.id)
            DecryptedMessage(
                attachments = cached?.attachments ?: emptyList(),
                body = cached?.body ?: "This thread can be viewed on Android, but only standards direct chats are writable right now.",
                createdAt = message.createdAt,
                id = message.id,
                senderId = message.senderId,
                senderName = participants.firstOrNull { it.id == message.senderId }?.displayName ?: "Unknown user",
                status = cached?.status ?: "unsupported",
            )
        }
        val finalWarning = warning ?: when (thread.protocol) {
            GROUP_PROTOCOL -> "MLS groups can be inspected on Android, but full native group send support is not active in this alpha build yet."
            else -> "This thread uses ${ProtocolCatalog.label(thread.protocol)}, which is not writable on Android yet."
        }
        return ConversationThread(
            id = thread.id,
            title = resolveThreadTitle(thread, participants, identityId, existingRecord?.localTitle),
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

    private fun saveIdentity(identity: LocalIdentity, recoveryPrivateKeyPkcs8: String) {
        val catalog = vaultStore.loadCatalog()
        val remaining = catalog.identities.filterNot { it.identity.id == identity.id }
        val record = StoredIdentityRecord(
            identity = identity,
            recoveryPrivateKeyPkcs8 = recoveryPrivateKeyPkcs8,
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
    }

    private fun persistStoredRecord(updatedRecord: StoredIdentityRecord, makeActive: Boolean = true) {
        val catalog = vaultStore.loadCatalog()
        var replaced = false
        val identities = catalog.identities.map { record ->
            if (record.identity.id == updatedRecord.identity.id) {
                replaced = true
                updatedRecord
            } else {
                record
            }
        }.let { records ->
            if (replaced) records else records + updatedRecord
        }
        vaultStore.saveCatalog(
            catalog.copy(
                version = maxOf(2, catalog.version),
                activeIdentityId = if (makeActive) updatedRecord.identity.id else catalog.activeIdentityId,
                identities = identities,
            ),
        )
    }

    private fun currentStoredRecord(identityId: String): StoredIdentityRecord? =
        vaultStore.loadCatalog().identities.firstOrNull { it.identity.id == identityId }

    private fun resolveUser(userId: String): RelayUser? {
        val threadUser = state.threads.asSequence()
            .flatMap { it.participants.asSequence() }
            .firstOrNull { it.id == userId }
        return threadUser
            ?: state.directoryResults.firstOrNull { it.id == userId }
            ?: state.contacts.firstOrNull { it.id == userId }
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
        val registered = relayClient().register(identity)
        val updated = mergeRegisteredIdentity(identity, registered)
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
        )

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
                        directoryCode = user.directoryCode ?: existing.directoryCode,
                        fingerprint = user.fingerprint.ifBlank { existing.fingerprint },
                        createdAt = user.createdAt.ifBlank { existing.createdAt },
                        updatedAt = user.updatedAt ?: existing.updatedAt,
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

    companion object {
        private const val KEY_APP_INSTANCE_ID = "app_instance_id"
        private const val KEY_RELAY_ORIGIN = "relay_origin"
        private const val KEY_TRANSPARENCY_PINS = "transparency_pins"
        private const val KEY_TRANSPARENCY_SIGNER_PINS = "transparency_signer_pins"
        private const val KEY_WITNESS_ORIGINS = "witness_origins"
    }
}

private data class MaterializedThread(
    val identity: LocalIdentity,
    val record: ConversationThreadRecord,
    val thread: ConversationThread,
)
