package com.aerobox.utils

import android.Manifest
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import com.aerobox.data.model.TrafficStats
import com.aerobox.data.model.VpnState
import java.util.Locale
import kotlin.math.max

fun VpnState.toTrafficStats(): TrafficStats = traffic

fun Long.formatDuration(): String {
    if (this <= 0L) return "00:00:00"
    val elapsedSeconds = max(0L, (System.currentTimeMillis() - this) / 1000)
    val hours = elapsedSeconds / 3600
    val minutes = (elapsedSeconds % 3600) / 60
    val seconds = elapsedSeconds % 60
    return "%02d:%02d:%02d".format(Locale.ROOT, hours, minutes, seconds)
}

fun Context.needsNotificationPermission(): Boolean {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
}

fun Context.findComponentActivity(): ComponentActivity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is ComponentActivity) return current
        current = current.baseContext
    }
    return current as? ComponentActivity
}
