package com.notrus.android.notifications

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.notrus.android.MainActivity
import com.notrus.android.model.NotificationContentVisibility
import com.notrus.android.model.NotificationLockscreenVisibility

data class ThreadNotificationPayload(
    val identityId: String,
    val threadId: String,
    val senderName: String?,
    val messagePreview: String?,
    val messageCount: Int,
    val messageIds: List<String>,
    val isGroup: Boolean,
)

object NotrusNotificationCenter {
    const val CHANNEL_MESSAGES = "notrus_messages_v1"
    const val CHANNEL_BACKGROUND_SERVICE = "notrus_background_service_v1"
    const val EXTRA_THREAD_ID = "notrus_notification_thread_id"
    const val EXTRA_IDENTITY_ID = "notrus_notification_identity_id"
    const val SERVICE_NOTIFICATION_ID = 18_412

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_MESSAGES) == null) {
            val channel = NotificationChannel(
                CHANNEL_MESSAGES,
                "Notrus messages",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Background secure-message notifications."
                enableVibration(true)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            }
            manager.createNotificationChannel(channel)
        }
        if (manager.getNotificationChannel(CHANNEL_BACKGROUND_SERVICE) == null) {
            val serviceChannel = NotificationChannel(
                CHANNEL_BACKGROUND_SERVICE,
                "Notrus background delivery",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Keeps secure-message wake-up delivery active in the background."
                setShowBadge(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_SECRET
            }
            manager.createNotificationChannel(serviceChannel)
        }
    }

    fun postThreadNotification(
        context: Context,
        settings: NotrusNotificationPreferences,
        privacyModeEnabled: Boolean,
        payload: ThreadNotificationPayload,
    ): Boolean {
        if (!settings.enabled) {
            return false
        }
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            return false
        }
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        ensureChannels(context)
        val contentVisibility = NotificationContentVisibility.fromKey(settings.contentVisibility)
        val lockscreenVisibility = NotificationLockscreenVisibility.fromKey(settings.lockscreenVisibility)
        val effectiveVisibility = if (privacyModeEnabled && !settings.privacyModeOverride) {
            NotificationContentVisibility.Hidden
        } else {
            contentVisibility
        }
        val (title, body) = renderNotificationText(
            visibility = effectiveVisibility,
            senderName = payload.senderName,
            messagePreview = payload.messagePreview,
            messageCount = payload.messageCount,
            isGroup = payload.isGroup,
            groupPreviewEnabled = settings.groupPreviewEnabled,
        )

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_THREAD_ID, payload.threadId)
            putExtra(EXTRA_IDENTITY_ID, payload.identityId)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            payload.threadId.hashCode(),
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(
                when (lockscreenVisibility) {
                    NotificationLockscreenVisibility.Secret -> NotificationCompat.VISIBILITY_SECRET
                    NotificationLockscreenVisibility.Private -> NotificationCompat.VISIBILITY_PRIVATE
                    NotificationLockscreenVisibility.Public -> NotificationCompat.VISIBILITY_PUBLIC
                },
            )
            .setOnlyAlertOnce(true)
            .setNumber(payload.messageCount)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)

        if (!settings.soundEnabled && !settings.vibrationEnabled) {
            builder.setSilent(true)
        } else if (!settings.soundEnabled) {
            builder.setSilent(true)
            builder.setVibrate(longArrayOf(0L, 160L, 120L, 160L))
        } else if (!settings.vibrationEnabled) {
            builder.setVibrate(longArrayOf(0L))
        }

        NotificationManagerCompat.from(context).notify(notificationId(payload), builder.build())
        return true
    }

    fun buildServiceNotification(context: Context): Notification {
        ensureChannels(context)
        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            SERVICE_NOTIFICATION_ID,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL_BACKGROUND_SERVICE)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Notrus background delivery")
            .setContentText("Listening for secure-message wake-ups.")
            .setContentIntent(pendingIntent)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .build()
    }

    private fun notificationId(payload: ThreadNotificationPayload): Int =
        "${payload.identityId}:${payload.threadId}".hashCode()

    private fun renderNotificationText(
        visibility: NotificationContentVisibility,
        senderName: String?,
        messagePreview: String?,
        messageCount: Int,
        isGroup: Boolean,
        groupPreviewEnabled: Boolean,
    ): Pair<String, String> {
        val sender = senderName?.trim().takeUnless { it.isNullOrBlank() } ?: "a contact"
        val effectivePreview = if (isGroup && !groupPreviewEnabled) null else messagePreview?.trim().takeIf { !it.isNullOrBlank() }
        val countSuffix = if (messageCount > 1) " ($messageCount)" else ""
        return when (visibility) {
            NotificationContentVisibility.Hidden -> "New secure message$countSuffix" to "Open Notrus to read."
            NotificationContentVisibility.SenderOnly ->
                "New message from $sender$countSuffix" to "Open Notrus to read."

            NotificationContentVisibility.FullPreview -> {
                val fallback = if (effectivePreview == null) "Open Notrus to read." else effectivePreview
                "New message from $sender$countSuffix" to fallback
            }
        }
    }
}
