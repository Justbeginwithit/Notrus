package com.notrus.android.notifications

import android.content.Context
import com.notrus.android.model.RelaySession
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

data class NotrusNotificationPreferences(
    val enabled: Boolean,
    val realtimeEnabled: Boolean,
    val contentVisibility: String,
    val lockscreenVisibility: String,
    val groupPreviewEnabled: Boolean,
    val privacyModeOverride: Boolean,
    val soundEnabled: Boolean,
    val vibrationEnabled: Boolean,
)

object NotrusNotificationPrefs {
    private const val PREFERENCES_NAME = "notrus_settings"
    private const val MAX_TRACKED_IDS_PER_IDENTITY = 512

    const val KEY_APP_INSTANCE_ID = "app_instance_id"
    const val KEY_PRIVACY_MODE_ENABLED = "privacy_mode_enabled"
    const val KEY_RELAY_ORIGIN = "relay_origin"

    const val KEY_NOTIFICATIONS_ENABLED = "notifications_enabled"
    const val KEY_NOTIFICATION_REALTIME_ENABLED = "notification_realtime_enabled"
    const val KEY_NOTIFICATION_CONTENT_VISIBILITY = "notification_content_visibility"
    const val KEY_NOTIFICATION_LOCKSCREEN_VISIBILITY = "notification_lockscreen_visibility"
    const val KEY_NOTIFICATION_GROUP_PREVIEW_ENABLED = "notification_group_preview_enabled"
    const val KEY_NOTIFICATION_PRIVACY_MODE_OVERRIDE = "notification_privacy_mode_override"
    const val KEY_NOTIFICATION_SOUND_ENABLED = "notification_sound_enabled"
    const val KEY_NOTIFICATION_VIBRATION_ENABLED = "notification_vibration_enabled"
    const val KEY_NOTIFICATION_WAKEUP_IDS = "notification_wakeup_ids"
    const val KEY_NOTIFICATION_SEEN_MESSAGE_IDS = "notification_seen_message_ids"
    const val KEY_NOTIFICATION_PRIMED_IDENTITIES = "notification_primed_identities"
    const val KEY_APP_FOREGROUND = "app_foreground"
    const val KEY_RELAY_SESSION = "relay_session"
    const val KEY_RELAY_SESSIONS_BY_IDENTITY = "relay_sessions_by_identity"

    fun notificationPreferences(context: Context): NotrusNotificationPreferences {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        return NotrusNotificationPreferences(
            enabled = preferences.getBoolean(KEY_NOTIFICATIONS_ENABLED, true),
            realtimeEnabled = preferences.getBoolean(KEY_NOTIFICATION_REALTIME_ENABLED, true),
            contentVisibility = preferences.getString(KEY_NOTIFICATION_CONTENT_VISIBILITY, "hidden") ?: "hidden",
            lockscreenVisibility = preferences.getString(KEY_NOTIFICATION_LOCKSCREEN_VISIBILITY, "private") ?: "private",
            groupPreviewEnabled = preferences.getBoolean(KEY_NOTIFICATION_GROUP_PREVIEW_ENABLED, false),
            privacyModeOverride = preferences.getBoolean(KEY_NOTIFICATION_PRIVACY_MODE_OVERRIDE, false),
            soundEnabled = preferences.getBoolean(KEY_NOTIFICATION_SOUND_ENABLED, true),
            vibrationEnabled = preferences.getBoolean(KEY_NOTIFICATION_VIBRATION_ENABLED, true),
        )
    }

    fun isAppForeground(context: Context): Boolean {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        return preferences.getBoolean(KEY_APP_FOREGROUND, false)
    }

    fun setAppForeground(context: Context, value: Boolean) {
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_APP_FOREGROUND, value)
            .apply()
    }

    fun appInstanceId(context: Context): String {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val existing = preferences.getString(KEY_APP_INSTANCE_ID, null)
        if (!existing.isNullOrBlank()) {
            return existing
        }
        val created = UUID.randomUUID().toString()
        preferences.edit().putString(KEY_APP_INSTANCE_ID, created).apply()
        return created
    }

    fun loadSeenMessageIds(context: Context, identityId: String): LinkedHashSet<String> {
        if (identityId.isBlank()) {
            return linkedSetOf()
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val raw = preferences.getString(KEY_NOTIFICATION_SEEN_MESSAGE_IDS, null) ?: return linkedSetOf()
        return runCatching {
            val root = JSONObject(raw)
            val values = root.optJSONArray(identityId) ?: JSONArray()
            linkedSetOf<String>().apply {
                for (index in 0 until values.length()) {
                    values.optString(index).trim().takeIf { it.isNotBlank() }?.let(::add)
                }
            }
        }.getOrDefault(linkedSetOf())
    }

    fun saveSeenMessageIds(context: Context, identityId: String, seenIds: Collection<String>) {
        if (identityId.isBlank()) {
            return
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val root = runCatching {
            JSONObject(preferences.getString(KEY_NOTIFICATION_SEEN_MESSAGE_IDS, "{}") ?: "{}")
        }.getOrDefault(JSONObject())

        val trimmed = seenIds
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .takeLast(MAX_TRACKED_IDS_PER_IDENTITY)
            .toList()
        root.put(identityId, JSONArray(trimmed))
        preferences.edit().putString(KEY_NOTIFICATION_SEEN_MESSAGE_IDS, root.toString()).apply()
    }

    fun isIdentityNotificationPrimed(context: Context, identityId: String): Boolean {
        if (identityId.isBlank()) {
            return false
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val raw = preferences.getString(KEY_NOTIFICATION_PRIMED_IDENTITIES, null) ?: return false
        return runCatching {
            val root = JSONObject(raw)
            root.optBoolean(identityId, false)
        }.getOrDefault(false)
    }

    fun markIdentityNotificationPrimed(context: Context, identityId: String) {
        if (identityId.isBlank()) {
            return
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val root = runCatching {
            JSONObject(preferences.getString(KEY_NOTIFICATION_PRIMED_IDENTITIES, "{}") ?: "{}")
        }.getOrDefault(JSONObject())
        root.put(identityId, true)
        preferences.edit().putString(KEY_NOTIFICATION_PRIMED_IDENTITIES, root.toString()).apply()
    }

    fun wakeupRegistrationId(context: Context, deviceId: String): String {
        val trimmedDeviceId = deviceId.trim()
        if (trimmedDeviceId.isBlank()) {
            return UUID.randomUUID().toString()
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val root = runCatching {
            JSONObject(preferences.getString(KEY_NOTIFICATION_WAKEUP_IDS, "{}") ?: "{}")
        }.getOrDefault(JSONObject())
        val existing = root.optString(trimmedDeviceId).trim()
        if (existing.isNotBlank()) {
            return existing
        }
        val created = UUID.randomUUID().toString()
        root.put(trimmedDeviceId, created)
        preferences.edit().putString(KEY_NOTIFICATION_WAKEUP_IDS, root.toString()).apply()
        return created
    }

    fun loadRelaySession(context: Context): RelaySession? {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val raw = preferences.getString(KEY_RELAY_SESSION, null) ?: return null
        return runCatching { relaySessionFromJson(JSONObject(raw)) }.getOrNull()
    }

    fun saveRelaySession(context: Context, session: RelaySession?) {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (session == null) {
            preferences.edit().remove(KEY_RELAY_SESSION).apply()
            return
        }
        val serialized = JSONObject()
            .put("expiresAt", session.expiresAt)
            .put("privacyMode", session.privacyMode)
            .put("sessionId", session.sessionId)
            .put("token", session.token)
            .toString()
        preferences.edit().putString(KEY_RELAY_SESSION, serialized).apply()
    }

    fun loadRelaySessionForIdentity(context: Context, identityId: String): RelaySession? {
        val normalizedIdentityId = identityId.trim()
        if (normalizedIdentityId.isBlank()) {
            return null
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val raw = preferences.getString(KEY_RELAY_SESSIONS_BY_IDENTITY, null) ?: return null
        return runCatching {
            val root = JSONObject(raw)
            val candidate = root.optJSONObject(normalizedIdentityId)
            if (candidate == null) {
                null
            } else {
                relaySessionFromJson(candidate)
            }
        }.getOrNull()
    }

    fun saveRelaySessionForIdentity(context: Context, identityId: String, session: RelaySession?) {
        val normalizedIdentityId = identityId.trim()
        if (normalizedIdentityId.isBlank()) {
            return
        }
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val root = runCatching {
            JSONObject(preferences.getString(KEY_RELAY_SESSIONS_BY_IDENTITY, "{}") ?: "{}")
        }.getOrDefault(JSONObject())
        if (session == null) {
            root.remove(normalizedIdentityId)
        } else {
            root.put(
                normalizedIdentityId,
                JSONObject()
                    .put("expiresAt", session.expiresAt)
                    .put("privacyMode", session.privacyMode)
                    .put("sessionId", session.sessionId)
                    .put("token", session.token),
            )
        }
        preferences.edit().putString(KEY_RELAY_SESSIONS_BY_IDENTITY, root.toString()).apply()
    }

    fun sessionIsUsable(session: RelaySession?, skewSeconds: Long = 30): Boolean {
        val candidate = session ?: return false
        if (candidate.token.isBlank()) {
            return false
        }
        return runCatching { Instant.parse(candidate.expiresAt) }
            .map { expiry -> expiry.isAfter(Instant.now().plusSeconds(skewSeconds)) }
            .getOrDefault(false)
    }

    private fun relaySessionFromJson(json: JSONObject): RelaySession? {
        val expiresAt = json.optString("expiresAt").trim()
        val privacyMode = json.optString("privacyMode").trim()
        val sessionId = json.optString("sessionId").trim()
        val token = json.optString("token").trim()
        if (expiresAt.isBlank() || privacyMode.isBlank() || sessionId.isBlank() || token.isBlank()) {
            return null
        }
        return RelaySession(
            expiresAt = expiresAt,
            privacyMode = privacyMode,
            sessionId = sessionId,
            token = token,
        )
    }

    private fun <T> Sequence<T>.takeLast(count: Int): List<T> {
        if (count <= 0) {
            return emptyList()
        }
        val buffer = ArrayDeque<T>(count)
        for (value in this) {
            if (buffer.size == count) {
                buffer.removeFirst()
            }
            buffer.addLast(value)
        }
        return buffer.toList()
    }
}
