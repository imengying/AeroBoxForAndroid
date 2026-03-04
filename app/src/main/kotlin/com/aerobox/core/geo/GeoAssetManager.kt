package com.aerobox.core.geo

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit

/**
 * Manages GeoIP and GeoSite database files used by sing-box for rule-based routing.
 * Downloads from GitHub releases and stores in app internal storage.
 */
object GeoAssetManager {

    private const val GEOIP_URL = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
    private const val GEOSITE_URL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"

    private const val GEOIP_FILE = "geoip.db"
    private const val GEOSITE_FILE = "geosite.db"

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    /**
     * Get the local path for the geo database files.
     */
    fun getGeoDir(context: Context): File {
        val dir = File(context.filesDir, "geo")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun getGeoIpFile(context: Context): File = File(getGeoDir(context), GEOIP_FILE)
    fun getGeoSiteFile(context: Context): File = File(getGeoDir(context), GEOSITE_FILE)

    /**
     * Check whether both geo database files exist locally.
     */
    fun hasLocalFiles(context: Context): Boolean {
        return getGeoIpFile(context).exists() && getGeoSiteFile(context).exists()
    }

    /**
     * Get file sizes for display (returns "X.X MB" strings).
     */
    fun getGeoIpSize(context: Context): String = formatFileSize(getGeoIpFile(context))
    fun getGeoSiteSize(context: Context): String = formatFileSize(getGeoSiteFile(context))

    /**
     * Get last modified time of geo files.
     */
    fun getGeoIpLastModified(context: Context): Long = getGeoIpFile(context).lastModified()
    fun getGeoSiteLastModified(context: Context): Long = getGeoSiteFile(context).lastModified()

    /**
     * Download or update GeoIP database.
     * Returns true on success, false on failure.
     */
    suspend fun updateGeoIp(context: Context): Boolean = withContext(Dispatchers.IO) {
        downloadFile(GEOIP_URL, getGeoIpFile(context))
    }

    /**
     * Download or update GeoSite database.
     * Returns true on success, false on failure.
     */
    suspend fun updateGeoSite(context: Context): Boolean = withContext(Dispatchers.IO) {
        downloadFile(GEOSITE_URL, getGeoSiteFile(context))
    }

    /**
     * Update both databases.
     */
    suspend fun updateAll(context: Context): Boolean {
        val ip = updateGeoIp(context)
        val site = updateGeoSite(context)
        return ip && site
    }

    private fun downloadFile(url: String, target: File): Boolean {
        return try {
            val request = Request.Builder().url(url).build()
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return false

            val tmpFile = File(target.parentFile, "${target.name}.tmp")
            response.body?.byteStream()?.use { input ->
                FileOutputStream(tmpFile).use { output ->
                    input.copyTo(output, bufferSize = 8192)
                }
            }

            // Atomic rename
            if (tmpFile.exists() && tmpFile.length() > 0) {
                target.delete()
                tmpFile.renameTo(target)
            } else {
                tmpFile.delete()
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun formatFileSize(file: File): String {
        if (!file.exists()) return "未下载"
        val sizeBytes = file.length()
        return when {
            sizeBytes < 1024 -> "$sizeBytes B"
            sizeBytes < 1024 * 1024 -> "%.1f KB".format(sizeBytes / 1024.0)
            else -> "%.1f MB".format(sizeBytes / (1024.0 * 1024.0))
        }
    }
}
