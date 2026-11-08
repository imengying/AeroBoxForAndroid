package com.aerobox.core.subscription

import java.net.URLDecoder
import java.util.Base64
import okhttp3.Headers
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Header/comment metadata is parsed independently from node parsing and database writes. */
internal object SubscriptionMetadataParser {
    private val COMMENT_METADATA_REGEX =
        Regex("""^\s*(#|//|;)\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$""")
    private val SUPPORTED_COMMENT_METADATA_KEYS = setOf(
        "profile-title",
        "profile-update-interval",
        "subscription-userinfo",
        "moved-permanently-to"
    )
    private val CONTENT_DISPOSITION_UTF8_REGEX =
        Regex("""filename\*\s*=\s*UTF-8''([^;]+)""", RegexOption.IGNORE_CASE)
    private val CONTENT_DISPOSITION_FILENAME_REGEX =
        Regex("""filename\s*=\s*"?([^";]+)"?""", RegexOption.IGNORE_CASE)

    data class SubscriptionUserInfo(
        val uploadBytes: Long? = null,
        val downloadBytes: Long? = null,
        val totalBytes: Long? = null,
        val expireTimestamp: Long? = null
    ) {
        fun remainingBytes(): Long? {
            val total = totalBytes ?: return null
            return (total - (uploadBytes ?: 0L)).coerceAtLeast(0L)
                .let { (it - (downloadBytes ?: 0L)).coerceAtLeast(0L) }
        }
    }

    data class ImportMetadata(
        val sanitizedContent: String,
        val profileTitle: String? = null,
        val canonicalUrl: String? = null,
        val updateIntervalMs: Long? = null,
        val userInfo: SubscriptionUserInfo? = null
    )

    private data class CommentMetadata(
        val sanitizedContent: String,
        val values: Map<String, String>
    )

    private fun parseSubscriptionUserInfo(value: String?): SubscriptionUserInfo? {
        if (value.isNullOrBlank()) return null
        val pairs = value.split(";")
            .mapNotNull { entry ->
                val separator = entry.indexOf('=')
                if (separator <= 0 || separator >= entry.lastIndex) return@mapNotNull null
                val key = entry.substring(0, separator).trim().lowercase()
                val rawValue = entry.substring(separator + 1).trim()
                key to rawValue
            }
            .toMap()

        if (pairs.isEmpty()) return null

        return SubscriptionUserInfo(
            uploadBytes = pairs["upload"]?.toLongOrNull()?.takeIf { it >= 0L },
            downloadBytes = pairs["download"]?.toLongOrNull()?.takeIf { it >= 0L },
            totalBytes = pairs["total"]?.toLongOrNull()?.takeIf { it >= 0L } ?: pairs["totl"]?.toLongOrNull()?.takeIf { it >= 0L },
            expireTimestamp = pairs["expire"]?.toLongOrNull()?.takeIf { it >= 0L }?.let(::normalizeExpireTimestamp)
        )
    }

    fun parse(
        source: String,
        sourceUrl: String?,
        headers: Headers?
    ): ImportMetadata {
        val commentMetadata = parseLeadingCommentMetadata(source)
        val headerTitle = headers?.valueByName("Profile-Title")?.let(::decodeMetadataValue)
        val commentTitle = commentMetadata.values["profile-title"]?.let(::decodeMetadataValue)
        val contentDispositionTitle = headers?.valueByName("Content-Disposition")
            ?.let(::extractFilenameFromContentDisposition)
        val profileTitle = firstNonBlank(
            headerTitle,
            commentTitle,
            contentDispositionTitle,
            sourceUrl?.let(::deriveSubscriptionName)
        )
        val updateIntervalMs = headers?.valueByName("profile-update-interval")
            ?.let(::parseProfileUpdateInterval)
            ?: commentMetadata.values["profile-update-interval"]?.let(::parseProfileUpdateInterval)
        val canonicalUrl = firstNonBlank(
            headers?.valueByName("moved-permanently-to"),
            commentMetadata.values["moved-permanently-to"],
            sourceUrl
        )?.takeIf(::isValidRemoteSubscriptionUrl)
        val userInfo = parseSubscriptionUserInfo(
            headers?.valueByName("Subscription-Userinfo")
                ?: commentMetadata.values["subscription-userinfo"]
        )
        return ImportMetadata(
            sanitizedContent = commentMetadata.sanitizedContent,
            profileTitle = profileTitle,
            canonicalUrl = canonicalUrl,
            updateIntervalMs = updateIntervalMs,
            userInfo = userInfo
        )
    }

    private fun parseLeadingCommentMetadata(source: String): CommentMetadata {
        val lines = source.lines()
        if (lines.isEmpty()) {
            return CommentMetadata(source, emptyMap())
        }

        val metadata = linkedMapOf<String, String>()
        val sanitizedLines = lines.toMutableList()
        val maxLines = minOf(lines.size, 10)
        repeat(maxLines) { index ->
            val line = lines[index]
            val match = COMMENT_METADATA_REGEX.matchEntire(line) ?: return@repeat
            val key = match.groupValues[2].trim().lowercase()
            val value = match.groupValues[3].trim()
            if (key in SUPPORTED_COMMENT_METADATA_KEYS && value.isNotBlank()) {
                metadata[key] = value
                sanitizedLines[index] = ""
            }
        }
        return CommentMetadata(
            sanitizedContent = sanitizedLines.joinToString("\n"),
            values = metadata
        )
    }

    private fun Headers.valueByName(name: String): String? {
        return get(name)?.trim()?.takeIf { it.isNotBlank() }
    }

    private fun decodeMetadataValue(value: String): String {
        val trimmed = value.trim()
        val encodedValue = trimmed.drop(7)
        if (!trimmed.startsWith("base64:", ignoreCase = true) || encodedValue.isBlank()) {
            return trimmed
        }
        return runCatching {
            String(Base64.getDecoder().decode(encodedValue), Charsets.UTF_8)
        }.getOrDefault(trimmed)
    }

    private fun extractFilenameFromContentDisposition(value: String): String? {
        CONTENT_DISPOSITION_UTF8_REGEX.find(value)?.let { match ->
            return sanitizeProfileFileName(decodePercentEncoded(match.groupValues[1]))
        }
        CONTENT_DISPOSITION_FILENAME_REGEX.find(value)?.let { match ->
            return sanitizeProfileFileName(match.groupValues[1])
        }
        return null
    }

    private fun sanitizeProfileFileName(value: String): String? {
        val trimmed = value.trim().trim('"').trim('\'')
        if (trimmed.isBlank()) return null
        return trimmed.substringBeforeLast('.').ifBlank { trimmed }
    }

    fun deriveSubscriptionName(url: String): String? {
        return runCatching {
            val uri = url.toHttpUrlOrNull() ?: return null
            uri.fragment?.trim()?.takeIf { it.isNotBlank() }
                ?: sanitizeProfileFileName(uri.pathSegments.lastOrNull { it.isNotBlank() } ?: uri.host)
        }.getOrNull()
    }

    private fun parseProfileUpdateInterval(value: String): Long? {
        val hours = value.trim().toLongOrNull() ?: return null
        if (hours <= 0L) return null
        return runCatching { Math.multiplyExact(hours, 3_600_000L) }.getOrNull()
    }

    fun isValidRemoteSubscriptionUrl(url: String): Boolean {
        return runCatching {
            url.trim().toHttpUrlOrNull()?.isHttps == true
        }.getOrDefault(false)
    }

    private fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun normalizeExpireTimestamp(timestamp: Long): Long {
        return if (timestamp >= 1_000_000_000_000L) timestamp else timestamp * 1000L
    }

    private fun decodePercentEncoded(value: String): String =
        runCatching { URLDecoder.decode(value.replace("+", "%2B"), "UTF-8") }.getOrDefault(value)
}
