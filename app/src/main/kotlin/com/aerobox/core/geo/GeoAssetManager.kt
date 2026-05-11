package com.aerobox.core.geo

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request
import com.aerobox.core.network.SharedHttpClient
import org.json.JSONObject
import org.tukaani.xz.XZInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.util.Locale
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
    // Internal logcat-only marker. The user-facing translated message is
    // R.string.error_rule_set_unavailable; callers that surface this to the
    // UI must throw LocalizedException(R.string.error_rule_set_unavailable)
    // instead of using this constant.
    private const val RULE_SET_UNAVAILABLE_LOG_TAG = "rule-set assets missing"

    data class GeoUpdateResult(
        val geoIpOk: Boolean,
        val geoSiteCnOk: Boolean,
        val geoAdsOk: Boolean
    ) {
        val allOk: Boolean get() = geoIpOk && geoSiteCnOk && geoAdsOk
    }

    data class GeoUpdateTargets(
        val geoIpCn: Boolean = true,
        val geoSiteCn: Boolean = true,
        val geoAds: Boolean = true
    ) {
        val hasAny: Boolean get() = geoIpCn || geoSiteCn || geoAds
    }

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

    private val client = SharedHttpClient.base.newBuilder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
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

    fun getGeoIpSize(context: Context): String = formatFileSize(context, getGeoIpFile(context))
    fun getGeoSiteSize(context: Context): String = formatFileSize(context, getGeoSiteFile(context))
    fun getGeoAdsSize(context: Context): String = formatFileSize(context, getGeoAdsFile(context))

    suspend fun updateAll(
        context: Context,
        targets: GeoUpdateTargets = GeoUpdateTargets()
    ): GeoUpdateResult = withContext(Dispatchers.IO) {
        if (!targets.hasAny) {
            return@withContext GeoUpdateResult(geoIpOk = true, geoSiteCnOk = true, geoAdsOk = true)
        }

        val ipOk = if (targets.geoIpCn) {
            downloadFile(GEOIP_CN_URL, getGeoIpFile(context))
        } else {
            true
        }
        if (targets.geoIpCn && ipOk) {
            writeVersionFile(getGeoIpVersionFile(context), fetchLatestReleaseTag(GEOIP_REPO))
        }
        val cnOk = if (targets.geoSiteCn) {
            downloadFile(GEOSITE_CN_URL, getGeoSiteFile(context))
        } else {
            true
        }
        val adsOk = if (targets.geoAds) {
            downloadFile(GEOSITE_ADS_URL, getGeoAdsFile(context))
        } else {
            true
        }
        if ((targets.geoSiteCn || targets.geoAds) && (!targets.geoSiteCn || cnOk) && (!targets.geoAds || adsOk)) {
            writeVersionFile(getGeoSiteVersionFile(context), fetchLatestReleaseTag(GEOSITE_REPO))
        }
        GeoUpdateResult(geoIpOk = ipOk, geoSiteCnOk = cnOk, geoAdsOk = adsOk)
    }

    suspend fun ensureRuleSetAssets(context: Context): Boolean = withContext(Dispatchers.IO) {
        ensureBundledAssets(context)
        if (hasLocalFiles(context)) {
            return@withContext true
        }

        val result = updateAll(context)
        val available = result.allOk && hasLocalFiles(context)
        if (!available) {
            Log.w(TAG, RULE_SET_UNAVAILABLE_LOG_TAG)
        }
        available
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
                    if (tmpFile.renameTo(target)) {
                        true
                    } else {
                        // renameTo can fail across filesystems; fall back to copy
                        tmpFile.inputStream().use { input ->
                            FileOutputStream(target).use { output -> input.copyTo(output) }
                        }
                        tmpFile.delete()
                        target.exists() && target.length() > 0
                    }
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

    private fun formatFileSize(context: Context, file: File): String {
        if (!file.exists()) return context.getString(com.aerobox.R.string.file_size_not_downloaded)
        val sizeBytes = file.length()
        return when {
            sizeBytes < 1024 -> "${sizeBytes} B"
            sizeBytes < 1024 * 1024 -> "%.1f KB".format(Locale.ROOT, sizeBytes / 1024.0)
            else -> "%.1f MB".format(Locale.ROOT, sizeBytes / (1024.0 * 1024.0))
        }
    }
}
