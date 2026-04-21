package com.aerobox.utils

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import kotlin.math.max

fun VpnState.toTrafficStats(): TrafficStats {
    return TrafficStats(
        uploadSpeed = uploadSpeed,
        downloadSpeed = downloadSpeed,
        totalUpload = totalUpload,
        totalDownload = totalDownload
    )
}

fun Long.formatDuration(): String {
    if (this <= 0L) return "00:00:00"
    val elapsedSeconds = max(0L, (System.currentTimeMillis() - this) / 1000)
    val hours = elapsedSeconds / 3600
    val minutes = (elapsedSeconds % 3600) / 60
    val seconds = elapsedSeconds % 60
    return "%02d:%02d:%02d".format(hours, minutes, seconds)
}

fun Context.needsNotificationPermission(): Boolean {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS
        ) != PackageManager.PERMISSION_GRANTED
}
