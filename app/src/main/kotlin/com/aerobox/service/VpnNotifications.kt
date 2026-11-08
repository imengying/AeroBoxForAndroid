package com.aerobox.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.aerobox.AeroBoxApplication
import com.aerobox.MainActivity
import com.aerobox.NotificationSwitchActivity
import com.aerobox.R
import com.aerobox.utils.AppLocaleManager
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

internal class VpnNotifications(private val context: Context, private val stopAction: String) {
    private var notificationLanguageJob: Job? = null
    @Volatile var languageTag = AppLocaleManager.SYSTEM_LANGUAGE_TAG
        private set

    fun show(notification: Notification) {
        notificationManager.notify(AeroBoxVpnService.NOTIFICATION_ID, notification)
    }

    private val notificationManager by lazy {
        context.getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
    }
    private val contentPendingIntent by lazy {
        PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
    private val stopPendingIntent by lazy {
        val stopIntent = Intent(stopAction).setPackage(context.packageName)
        PendingIntent.getBroadcast(
            context, 101, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
    private val switchPendingIntent by lazy {
        val switchIntent = Intent(context, NotificationSwitchActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                    Intent.FLAG_ACTIVITY_NO_HISTORY
            )
        }
        PendingIntent.getActivity(
            context, 102, switchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    fun observeLanguage(scope: CoroutineScope) {
        if (notificationLanguageJob?.isActive == true) return
        notificationLanguageJob = scope.launch {
            PreferenceManager.languageTagFlow(context).collect { value ->
                languageTag = AppLocaleManager.normalize(value)
            }
        }
    }

    suspend fun refreshLanguage() {
        languageTag = AppLocaleManager.normalize(
            PreferenceManager.languageTagFlow(context).first()
        )
    }

    fun string(resId: Int, vararg formatArgs: Any) =
        AppLocaleManager.string(context, languageTag, resId, *formatArgs)

    fun build(nodeName: String?, contentText: String = "", connected: Boolean = false): Notification {
        val title = nodeName?.takeIf { it.isNotBlank() } ?: string(R.string.notification_title)
        val mergedContent = when {
            connected && contentText.isNotBlank() -> contentText
            connected -> "↑ 0 B/s  ↓ 0 B/s"
            contentText.isBlank() -> string(R.string.notification_connecting)
            else -> contentText
        }

        val builder = NotificationCompat.Builder(context, AeroBoxApplication.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(mergedContent)
            .setSubText(null)
            .setSmallIcon(R.drawable.ic_stat_aerobox)
            .setContentIntent(contentPendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)

        if (connected) {
            builder
                .addAction(
                    android.R.drawable.ic_menu_rotate,
                    string(R.string.notification_action_switch),
                    switchPendingIntent
                )
                .addAction(
                    android.R.drawable.ic_media_pause,
                    string(R.string.notification_action_stop),
                    stopPendingIntent
                )
        } else {
            builder.addAction(
                android.R.drawable.ic_media_pause,
                string(R.string.notification_action_stop),
                stopPendingIntent
            )
        }

        return builder.build()
    }

}
