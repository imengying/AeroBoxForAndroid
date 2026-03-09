package com.aerobox.utils

import kotlin.math.ln
import kotlin.math.pow

object NetworkUtils {

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB")
        val digitGroups = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceIn(0, units.lastIndex)
        val value = bytes / 1024.0.pow(digitGroups.toDouble())
        return "%.2f %s".format(value, units[digitGroups])
    }
    fun formatSpeed(bps: Long): String = "${formatBytes(bps)}/s"
}
