package com.notrus.android.notifications

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.notrus.android.BuildConfig
import com.notrus.android.relay.RelayClient
import com.notrus.android.security.DeviceIdentityProvider
import com.notrus.android.security.DeviceRiskSignals
import com.notrus.android.security.VaultStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class NotrusNotificationService : Service() {
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private var eventJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        NotrusNotificationCenter.ensureChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val preferences = NotrusNotificationPrefs.notificationPreferences(this)
        if (!preferences.enabled || !preferences.realtimeEnabled) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(
            NotrusNotificationCenter.SERVICE_NOTIFICATION_ID,
            NotrusNotificationCenter.buildServiceNotification(this),
        )
        NotrusBackgroundSyncWorker.schedulePeriodic(this)
        NotrusBackgroundSyncWorker.scheduleRolling(this)
        NotrusBackgroundSyncWorker.enqueueImmediate(this)

        if (eventJob?.isActive != true) {
            eventJob = serviceScope.launch {
                runAuthenticatedEventLoop()
            }
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (NotrusNotificationPrefs.notificationPreferences(this).enabled) {
            NotrusBackgroundSyncWorker.enqueueImmediate(this)
            NotrusBackgroundSyncWorker.scheduleRolling(this)
        }
    }

    override fun onDestroy() {
        eventJob?.cancel()
        serviceJob.cancel()
        runCatching {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private suspend fun runAuthenticatedEventLoop() {
        val appContext = applicationContext
        val vaultStore = VaultStore(appContext)
        val deviceIdentityProvider = DeviceIdentityProvider()
        var backoffMs = 1_500L

        while (serviceScope.coroutineContext.isActive) {
            val preferences = NotrusNotificationPrefs.notificationPreferences(appContext)
            if (!preferences.enabled || !preferences.realtimeEnabled) {
                break
            }

            try {
                val catalog = vaultStore.loadCatalog()
                val activeIdentity = catalog.identities
                    .firstOrNull { it.identity.id == catalog.activeIdentityId }
                    ?.identity
                    ?: catalog.identities.firstOrNull()?.identity

                if (activeIdentity == null) {
                    delay(30_000L)
                    continue
                }

                val session = NotrusNotificationPrefs.loadRelaySessionForIdentity(appContext, activeIdentity.id)
                    ?: NotrusNotificationPrefs.loadRelaySession(appContext)
                if (!NotrusNotificationPrefs.sessionIsUsable(session)) {
                    NotrusBackgroundSyncWorker.enqueueImmediate(appContext)
                    delay(8_000L)
                    continue
                }

                val appInstanceId = NotrusNotificationPrefs.appInstanceId(appContext)
                val device = deviceIdentityProvider.descriptor(appContext, appInstanceId)
                val client = RelayClient(
                    origin = readRelayOrigin(appContext),
                    integrityReport = DeviceRiskSignals.capture(appContext),
                    appInstanceId = appInstanceId,
                    deviceDescriptor = device,
                    sessionToken = session?.token,
                )
                runCatching {
                    client.registerNotificationWakeup(
                        mode = "foreground-sse-v1",
                        platform = "android",
                        registrationId = NotrusNotificationPrefs.wakeupRegistrationId(appContext, device.id),
                    )
                }

                client.streamEvents { _, _ ->
                    NotrusBackgroundSyncWorker.enqueueImmediate(appContext)
                }
                backoffMs = 1_500L
            } catch (_: Exception) {
                NotrusBackgroundSyncWorker.enqueueImmediate(appContext)
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(30_000L)
            }
        }
    }

    private fun readRelayOrigin(context: Context): String {
        val settings = context.getSharedPreferences("notrus_settings", Context.MODE_PRIVATE)
        val configured = settings.getString(NotrusNotificationPrefs.KEY_RELAY_ORIGIN, null)?.trim().orEmpty()
        val candidate = if (configured.isBlank()) BuildConfig.DEFAULT_RELAY_ORIGIN else configured
        return RelayClient.validateOrigin(candidate)
    }

    companion object {
        fun startIfAllowed(context: Context) {
            val appContext = context.applicationContext
            val preferences = NotrusNotificationPrefs.notificationPreferences(appContext)
            if (!preferences.enabled || !preferences.realtimeEnabled) {
                stop(appContext)
                return
            }
            NotrusNotificationCenter.ensureChannels(appContext)
            val intent = Intent(appContext, NotrusNotificationService::class.java)
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    appContext.startForegroundService(intent)
                } else {
                    appContext.startService(intent)
                }
            }.onFailure {
                NotrusBackgroundSyncWorker.schedulePeriodic(appContext)
                NotrusBackgroundSyncWorker.scheduleRolling(appContext)
            }
        }

        fun stop(context: Context) {
            val appContext = context.applicationContext
            runCatching {
                appContext.stopService(Intent(appContext, NotrusNotificationService::class.java))
            }
        }
    }
}
