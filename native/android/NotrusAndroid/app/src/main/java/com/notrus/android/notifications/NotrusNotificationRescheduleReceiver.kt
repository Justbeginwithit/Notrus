package com.notrus.android.notifications

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class NotrusNotificationRescheduleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        val appContext = context.applicationContext
        val preferences = NotrusNotificationPrefs.notificationPreferences(appContext)
        if (!preferences.enabled) {
            NotrusBackgroundSyncWorker.cancelAll(appContext)
            NotrusNotificationService.stop(appContext)
            return
        }

        NotrusNotificationCenter.ensureChannels(appContext)
        NotrusBackgroundSyncWorker.schedulePeriodic(appContext)
        NotrusBackgroundSyncWorker.scheduleRolling(appContext)
        NotrusBackgroundSyncWorker.enqueueImmediate(appContext)
        if (preferences.realtimeEnabled) {
            NotrusNotificationService.startIfAllowed(appContext)
        }
    }
}
