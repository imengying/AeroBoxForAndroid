package com.aerobox.core.geo

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import org.tukaani.xz.XZInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit

/**
 * Manages bundled and updated sing-box rule-set assets.
 * We keep a small official subset aligned with the current UI toggles:
 * - geoip-cn.srs
 * - geosite-cn.srs
 * - geosite-category-ads-all.srs
 */
object GeoAssetManager {

    private const val TAG = "GeoAssetManager"

    private const val GEOIP_REPO = "SagerNet/sing-geoip"
    private const val GEOSITE_REPO = "SagerNet/sing-geosite"

    private const val GEOIP_CN_URL =
        "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
    private const val GEOSITE_CN_URL =
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
    private const val GEOSITE_ADS_URL =
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"

    private const val ASSET_PREFIX = "sing-box/"
    private const val CUSTOM_VERSION = "Custom"

    private const val GEOIP_CN_FILE = "geoip-cn.srs"
    private const val GEOSITE_CN_FILE = "geosite-cn.srs"
    private const val GEOSITE_ADS_FILE = "geosite-category-ads-all.srs"
    private const val GEOIP_VERSION_FILE = "geoip.version.txt"
    private const val GEOSITE_VERSION_FILE = "geosite.version.txt"

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    fun getGeoDir(context: Context): File {
        val dir = File(context.filesDir, "geo")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun getGeoIpFile(context: Context): File = File(getGeoDir(context), GEOIP_CN_FILE)
    fun getGeoSiteFile(context: Context): File = File(getGeoDir(context), GEOSITE_CN_FILE)
    fun getGeoAdsFile(context: Context): File = File(getGeoDir(context), GEOSITE_ADS_FILE)

    private fun getGeoIpVersionFile(context: Context): File = File(getGeoDir(context), GEOIP_VERSION_FILE)
    private fun getGeoSiteVersionFile(context: Context): File = File(getGeoDir(context), GEOSITE_VERSION_FILE)

    fun hasLocalFiles(context: Context): Boolean {
        return getGeoIpFile(context).exists() &&
            getGeoSiteFile(context).exists() &&
            getGeoAdsFile(context).exists()
    }

    fun getGeoIpSize(context: Context): String = formatFileSize(getGeoIpFile(context))
    fun getGeoSiteSize(context: Context): String = formatFileSize(getGeoSiteFile(context))
    fun getGeoAdsSize(context: Context): String = formatFileSize(getGeoAdsFile(context))

    fun getGeoIpLastModified(context: Context): Long = getGeoIpFile(context).lastModified()
    fun getGeoSiteLastModified(context: Context): Long = maxOf(
        getGeoSiteFile(context).lastModified(),
        getGeoAdsFile(context).lastModified()
    )

    suspend fun updateGeoIp(context: Context): Boolean = withContext(Dispatchers.IO) {
        val ok = downloadFile(GEOIP_CN_URL, getGeoIpFile(context))
        if (ok) {
            writeVersionFile(getGeoIpVersionFile(context), fetchLatestReleaseTag(GEOIP_REPO))
        }
        ok
    }

    suspend fun updateGeoSite(context: Context): Boolean = withContext(Dispatchers.IO) {
        val cnOk = downloadFile(GEOSITE_CN_URL, getGeoSiteFile(context))
        val adsOk = downloadFile(GEOSITE_ADS_URL, getGeoAdsFile(context))
        val ok = cnOk && adsOk
        if (ok) {
            writeVersionFile(getGeoSiteVersionFile(context), fetchLatestReleaseTag(GEOSITE_REPO))
        }
        ok
    }

    suspend fun updateAll(context: Context): Boolean {
        val ip = updateGeoIp(context)
        val site = updateGeoSite(context)
        return ip && site
    }

    @Synchronized
    fun ensureBundledAssets(context: Context, useOfficialAssets: Boolean = true) {
        runCatching {
            ensureBundledAsset(
                context = context,
                fileName = GEOIP_CN_FILE,
                versionFileName = GEOIP_VERSION_FILE,
                useOfficialAssets = useOfficialAssets
            )
            ensureBundledAsset(
                context = context,
                fileName = GEOSITE_CN_FILE,
                versionFileName = GEOSITE_VERSION_FILE,
                useOfficialAssets = useOfficialAssets
            )
            ensureBundledAsset(
                context = context,
                fileName = GEOSITE_ADS_FILE,
                versionFileName = GEOSITE_VERSION_FILE,
                useOfficialAssets = useOfficialAssets
            )
        }.onFailure { e ->
            Log.w(TAG, "ensureBundledAssets failed: ${e.message}")
        }
    }

    private fun downloadFile(url: String, target: File): Boolean {
        return try {
            val request = Request.Builder().url(url).build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return false

                val tmpFile = File(target.parentFile, "${target.name}.tmp")
                response.body.byteStream().use { input ->
                    FileOutputStream(tmpFile).use { output ->
                        input.copyTo(output, bufferSize = 8192)
                    }
                }

                if (tmpFile.exists() && tmpFile.length() > 0) {
                    target.delete()
                    tmpFile.renameTo(target)
                } else {
                    tmpFile.delete()
                    false
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun ensureBundledAsset(
        context: Context,
        fileName: String,
        versionFileName: String,
        useOfficialAssets: Boolean
    ) {
        val target = File(getGeoDir(context), fileName)
        val versionFile = File(getGeoDir(context), versionFileName)

        val assetVersion = readAssetText(context, ASSET_PREFIX + versionFileName) ?: return
        val localVersion = versionFile.takeIf { it.isFile }?.readText()?.trim().orEmpty()

        val shouldExtract = when {
            !target.isFile -> true
            !useOfficialAssets -> false
            localVersion == CUSTOM_VERSION -> false
            localVersion.isBlank() -> true
            else -> shouldReplaceByVersion(assetVersion, localVersion)
        }

        if (!shouldExtract) return

        val tmpFile = File(target.parentFile, "${target.name}.tmp")
        tmpFile.delete()

        val extracted = extractBundledFile(context, fileName, tmpFile)
        if (!extracted || tmpFile.length() <= 0L) {
            tmpFile.delete()
            return
        }

        target.delete()
        if (!tmpFile.renameTo(target)) {
            tmpFile.inputStream().use { input ->
                FileOutputStream(target).use { output -> input.copyTo(output) }
            }
            tmpFile.delete()
        }

        writeVersionFile(versionFile, assetVersion)
    }

    private fun extractBundledFile(context: Context, fileName: String, outputFile: File): Boolean {
        val xzAssetPath = ASSET_PREFIX + fileName + ".xz"
        return try {
            context.assets.open(xzAssetPath).use { raw ->
                XZInputStream(raw).use { xz ->
                    FileOutputStream(outputFile).use { out ->
                        xz.copyTo(out, bufferSize = 8192)
                    }
                }
            }
            true
        } catch (_: FileNotFoundException) {
            try {
                context.assets.open(ASSET_PREFIX + fileName).use { raw ->
                    FileOutputStream(outputFile).use { out ->
                        raw.copyTo(out, bufferSize = 8192)
                    }
                }
                true
            } catch (_: Exception) {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun readAssetText(context: Context, assetPath: String): String? {
        return try {
            context.assets.open(assetPath).bufferedReader().use { it.readText().trim() }
        } catch (_: Exception) {
            null
        }
    }

    private fun shouldReplaceByVersion(assetVersion: String, localVersion: String): Boolean {
        if (assetVersion == localVersion) return false
        val assetNum = assetVersion.toLongOrNull()
        val localNum = localVersion.toLongOrNull()
        return if (assetNum != null && localNum != null) {
            assetNum > localNum
        } else {
            assetVersion != localVersion
        }
    }

    private fun fetchLatestReleaseTag(repo: String): String {
        val url = "https://api.github.com/repos/$repo/releases/latest".toHttpUrlOrNull()
            ?: return "Unknown-${System.currentTimeMillis()}"
        return try {
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/vnd.github+json")
                .build()
            val response = client.newCall(request).execute()
            response.use {
                if (!it.isSuccessful) return "Unknown-${System.currentTimeMillis()}"
                val body = it.body.string()
                val tag = JSONObject(body).optString("tag_name").trim()
                if (tag.isNotEmpty()) tag else "Unknown-${System.currentTimeMillis()}"
            }
        } catch (_: Exception) {
            "Unknown-${System.currentTimeMillis()}"
        }
    }

    private fun writeVersionFile(file: File, version: String) {
        runCatching {
            file.parentFile?.takeIf { !it.exists() }?.mkdirs()
            file.writeText(version.trim())
        }
    }

    private fun formatFileSize(file: File): String {
        if (!file.exists()) return "未下载"
        val sizeBytes = file.length()
        return when {
            sizeBytes < 1024 -> "${sizeBytes} B"
            sizeBytes < 1024 * 1024 -> "%.1f KB".format(sizeBytes / 1024.0)
            else -> "%.1f MB".format(sizeBytes / (1024.0 * 1024.0))
        }
    }
}
