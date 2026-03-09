package com.aerobox.utils

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
