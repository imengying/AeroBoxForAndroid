package com.aerobox.data.repository

import com.aerobox.core.network.SharedHttpClient
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

class AppUpdateRepository(
    private val client: OkHttpClient = SharedHttpClient.base
) {
    fun checkLatestRelease(currentVersion: String): AppUpdateInfo {
        val url = LATEST_RELEASE_API_URL.toHttpUrlOrNull()
            ?: error("Invalid release API URL")
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "AeroBox-Android")
            .build()

        val response = client.newCall(request).execute()
        response.use {
            if (!it.isSuccessful) {
                error("GitHub releases API returned HTTP ${it.code}")
            }
            val body = it.body.string()
            val release = JSONObject(body)
            val latestTag = release.optString("tag_name").trim()
            if (latestTag.isBlank()) {
                error("GitHub release tag is empty")
            }
            val latestVersion = latestTag.trimStart('v', 'V')
            val releaseUrl = release.optString("html_url").trim()
                .ifBlank { LATEST_RELEASE_WEB_URL }
            val comparison = compareVersions(currentVersion, latestTag)
                ?: error("Unsupported release version: $latestTag")

            return AppUpdateInfo(
                currentVersion = currentVersion,
                latestVersion = latestVersion,
                latestTag = latestTag,
                releaseUrl = releaseUrl,
                isUpdateAvailable = comparison < 0
            )
        }
    }

    private fun compareVersions(current: String, latest: String): Int? {
        val currentVersion = parseVersion(current) ?: return null
        val latestVersion = parseVersion(latest) ?: return null
        val maxSize = maxOf(currentVersion.size, latestVersion.size, 3)
        for (index in 0 until maxSize) {
            val currentPart = currentVersion.getOrNull(index) ?: 0
            val latestPart = latestVersion.getOrNull(index) ?: 0
            if (currentPart != latestPart) return currentPart.compareTo(latestPart)
        }
        return 0
    }

    private fun parseVersion(raw: String): List<Int>? {
        val normalized = raw.trim()
            .trimStart('v', 'V')
            .substringBefore('+')
            .substringBefore('-')
        if (normalized.isBlank()) return null
        val parts = normalized.split('.')
        if (parts.isEmpty()) return null
        return parts.map { part ->
            part.toIntOrNull() ?: return null
        }
    }

    companion object {
        private const val REPOSITORY = "imengying/AeroBoxForAndroid"
        private const val LATEST_RELEASE_API_URL = "https://api.github.com/repos/$REPOSITORY/releases/latest"
        private const val LATEST_RELEASE_WEB_URL = "https://github.com/$REPOSITORY/releases"
    }
}

data class AppUpdateInfo(
    val currentVersion: String,
    val latestVersion: String,
    val latestTag: String,
    val releaseUrl: String,
    val isUpdateAvailable: Boolean
)
