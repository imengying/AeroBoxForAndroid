package com.aerobox.utils

import java.util.Locale
import kotlin.math.ln
import kotlin.math.pow

object NetworkUtils {

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB")
        val digitGroups = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceIn(0, units.lastIndex)
        val value = bytes / 1024.0.pow(digitGroups.toDouble())
        return "%.2f %s".format(Locale.ROOT, value, units[digitGroups])
    }

    fun formatBytesCompact(bytes: Long): String {
        if (bytes <= 0) return "0B"
        val units = arrayOf("B", "KB", "MB", "GB")
        val digitGroups = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceIn(0, units.lastIndex)
        if (digitGroups == 0) return "${bytes}B"
        val value = bytes / 1024.0.pow(digitGroups.toDouble())
        val pattern = when {
            value >= 100 -> "%.0f%s"
            value >= 10 -> "%.1f%s"
            else -> "%.2f%s"
        }
        return pattern.format(Locale.ROOT, value, units[digitGroups])
    }
}
