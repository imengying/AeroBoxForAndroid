package com.aerobox.core.subscription

import android.util.Log
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.connectionFingerprint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

data class ParsedSubscription(
    val nodes: List<ProxyNode>,
    val trafficBytes: Long = 0,
    val expireTimestamp: Long = 0,
    val diagnostics: ParseDiagnostics = ParseDiagnostics()
)

data class ParseDiagnostics(
    val ignoredEntryCount: Int = 0,
    val reasonCounts: Map<String, Int> = emptyMap()
) {
    fun withIgnored(reason: String): ParseDiagnostics {
        val normalized = reason.trim().ifEmpty { "unknown_reason" }
        return copy(
            ignoredEntryCount = ignoredEntryCount + 1,
            reasonCounts = reasonCounts + (normalized to ((reasonCounts[normalized] ?: 0) + 1))
        )
    }

    operator fun plus(other: ParseDiagnostics): ParseDiagnostics {
        if (other.ignoredEntryCount == 0 && other.reasonCounts.isEmpty()) return this
        val merged = reasonCounts.toMutableMap()
        other.reasonCounts.forEach { (reason, count) ->
            merged[reason] = (merged[reason] ?: 0) + count
        }
        return ParseDiagnostics(
            ignoredEntryCount = ignoredEntryCount + other.ignoredEntryCount,
            reasonCounts = merged.toMap()
        )
    }
}

internal fun parseUdpOverTcpValue(value: Any?): Pair<Boolean?, Int?> {
    return when (value) {
        null, JSONObject.NULL -> null to null
        is Boolean -> value to null
        is JSONObject -> {
            val enabled = if (value.has("enabled")) value.optBoolean("enabled") else true
            val version = value.optInt("version", -1).takeIf { it >= 0 }
            enabled to version
        }
        is Map<*, *> -> {
            val enabled = value.entries.firstOrNull {
                it.key?.toString()?.equals("enabled", ignoreCase = true) == true
            }?.value?.toString()?.toBooleanStrictOrNull() ?: true
            val version = value.entries.firstOrNull {
                it.key?.toString()?.equals("version", ignoreCase = true) == true
            }?.value?.toString()?.toIntOrNull()
            enabled to version
        }
        is Number -> true to value.toInt()
        is String -> {
            val trimmed = value.trim()
            when {
                trimmed.isEmpty() -> null to null
                trimmed == "1" -> true to null
                trimmed == "0" -> false to null
                trimmed.equals("true", ignoreCase = true) ||
                    trimmed.equals("false", ignoreCase = true) -> trimmed.toBoolean() to null
                else -> true to trimmed.toIntOrNull()
            }
        }
        else -> null to null
    }
}

object SubscriptionParser {
    private const val TAG = "SubscriptionParser"
    internal val supportedTransportTypes = setOf("ws", "grpc", "http", "h2", "httpupgrade", "quic")

    private data class NodeParseBatch(
        val nodes: List<ProxyNode>,
        val diagnostics: ParseDiagnostics = ParseDiagnostics()
    )

    private val trafficInfoPrefixes = listOf(
        "剩余流量",
        "流量剩余",
        "总流量",
        "已用流量",
        "使用流量",
        "流量信息",
        "remaining traffic",
        "used traffic",
        "total traffic",
        "traffic"
    )

    private val resetInfoPrefixes = listOf(
        "距离下次重置剩余",
        "距离下次重置",
        "下次重置剩余",
        "下次重置",
        "重置剩余",
        "重置时间",
        "next reset",
        "traffic reset",
        "reset in",
        "reset time",
        "reset"
    )

    private val expiryInfoPrefixes = listOf(
        "套餐到期",
        "订阅到期",
        "到期时间",
        "过期时间",
        "有效期",
        "到期",
        "expire date",
        "expires",
        "expiry",
        "valid until"
    )

    private val announcementInfoPrefixes = listOf(
        "官网",
        "官方网址",
        "更新地址",
        "公告",
        "通知",
        "官方群",
        "官方频道",
        "频道",
        "群组",
        "交流群",
        "客服",
        "联系",
        "购买",
        "续费",
        "telegram",
        "tg",
        "channel",
        "group",
        "website",
        "support",
        "contact"
    )

    private val allInformationalPrefixes = (
        trafficInfoPrefixes +
            resetInfoPrefixes +
            expiryInfoPrefixes +
            announcementInfoPrefixes
        ).distinct().sortedByDescending { it.length }

    private val announcementValuePattern = Regex(
        """
        (?ix)
        (https?://|t\.me/|telegram|tg[:/\s]|@\w{3,}|qq[:：]?\d{5,}|wechat|wx[:：]?\w+)
        """.trimIndent()
    )

    private val trafficValuePattern = Regex(
        """
        (?ix)
        ^
        \d+(?:\.\d+)?\s*
        (?:B|KB|MB|GB|TB|PB|KIB|MIB|GIB|TIB|PIB|BYTE|BYTES|字节|字節)
        (?:\s*/\s*\d+(?:\.\d+)?\s*(?:B|KB|MB|GB|TB|PB|KIB|MIB|GIB|TIB|PIB|BYTE|BYTES|字节|字節))?
        $
        """.trimIndent()
    )

    private val relativeTimeValuePattern = Regex(
        """
        (?ix)
        ^
        \d+\s*
        (?:
            天|日|小时|小時|时|時|分钟|分鐘|分|秒|秒钟|秒鐘|
            day|days|hour|hours|hr|hrs|minute|minutes|min|mins|second|seconds|sec|secs|
            d|h|m|s
        )
        $
        """.trimIndent()
    )

    private val permanentValidityValuePattern = Regex(
        """
        (?ix)
        ^
        (?:
            长期有效|永久有效|长期|永久|永不过期|不过期|
            forever|permanent|permanently|never\s+expire(?:s|d)?|no\s+expiry|unlimited
        )
        $
        """.trimIndent()
    )

    private val dateValuePattern = Regex(
        """
        ^
        \d{4}[-/.]\d{1,2}[-/.]\d{1,2}
        (?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?
        $
        """.trimIndent(),
        setOf(RegexOption.IGNORE_CASE, RegexOption.COMMENTS)
    )

    private val timestampValuePattern = Regex("^\\d{10,13}$")

    suspend fun parseSubscriptionContent(content: String): ParsedSubscription = withContext(Dispatchers.Default) {
        runCatching {
            val normalized = content.trim()
            if (normalized.isBlank()) {
                return@runCatching ParsedSubscription(emptyList())
            }

            // Check for Clash/ClashMeta YAML format first
            if (ClashParser.isClashYaml(normalized)) {
                return@runCatching parseClashSubscription(normalized)
            }

            val base64Decoded = tryBase64Decode(normalized)

            // Also check if Base64-decoded content is Clash YAML
            if (base64Decoded != normalized && ClashParser.isClashYaml(base64Decoded)) {
                return@runCatching parseClashSubscription(base64Decoded)
            }

            val targetContent = when {
                normalized.startsWith("{") || normalized.startsWith("[") -> normalized
                normalized.contains("://") -> normalized
                base64Decoded.startsWith("{") || base64Decoded.startsWith("[") -> base64Decoded
                base64Decoded.contains("://") -> base64Decoded
                else -> normalized
            }
            val batch = when {
                targetContent.startsWith("{") || targetContent.startsWith("[") -> parseJsonContent(targetContent)
                targetContent.contains("://") -> parseUriList(targetContent)
                else -> NodeParseBatch(
                    nodes = emptyList(),
                    diagnostics = ParseDiagnostics().withIgnored("unsupported_subscription_content")
                )
            }

            sanitizeParsedNodes(batch.nodes, batch.diagnostics)
        }.getOrDefault(ParsedSubscription(emptyList()))
    }

    private fun parseClashSubscription(content: String): ParsedSubscription {
        val result = ClashParser.parseClashYamlDetailed(content)
        return sanitizeParsedNodes(result.nodes, result.diagnostics)
    }

    private fun sanitizeParsedNodes(
        nodes: List<ProxyNode>,
        diagnostics: ParseDiagnostics = ParseDiagnostics()
    ): ParsedSubscription {
        val (infoNodes, validNodes) = nodes.partition(::isInformationalNode)
        if (infoNodes.isNotEmpty()) {
            Log.i(TAG, "Filtered ${infoNodes.size} informational nodes: ${infoNodes.joinToString { it.name }}")
        }
        val dedupedNodes = dedupeNodes(validNodes)
        val duplicateCount = (validNodes.size - dedupedNodes.size).coerceAtLeast(0)
        var finalDiagnostics = diagnostics
        repeat(infoNodes.size) {
            finalDiagnostics = finalDiagnostics.withIgnored("informational_entry")
        }
        repeat(duplicateCount) {
            finalDiagnostics = finalDiagnostics.withIgnored("duplicate_entry")
        }
        return ParsedSubscription(
            nodes = dedupedNodes,
            trafficBytes = infoNodes.mapNotNull { extractTrafficBytes(it.name) }.firstOrNull() ?: 0L,
            expireTimestamp = infoNodes.mapNotNull { extractExpireTimestamp(it.name) }.firstOrNull() ?: 0L,
            diagnostics = finalDiagnostics
        )
    }

    private fun dedupeNodes(nodes: List<ProxyNode>): List<ProxyNode> {
        return nodes
            .distinctBy { it.connectionFingerprint() }
    }

    private fun isInformationalNode(node: ProxyNode): Boolean {
        val info = parseInformationalNode(node.name) ?: return false
        return when {
            info.prefix.matchesAnyPrefix(resetInfoPrefixes) -> {
                relativeTimeValuePattern.matches(info.value) || dateValuePattern.matches(info.value) || timestampValuePattern.matches(info.value)
            }
            info.prefix.matchesAnyPrefix(expiryInfoPrefixes) -> {
                dateValuePattern.matches(info.value) ||
                    relativeTimeValuePattern.matches(info.value) ||
                    timestampValuePattern.matches(info.value) ||
                    isPermanentValidityValue(info.value)
            }
            info.prefix.matchesAnyPrefix(trafficInfoPrefixes) -> trafficValuePattern.matches(info.value)
            info.prefix.matchesAnyPrefix(announcementInfoPrefixes) -> announcementValuePattern.containsMatchIn(info.value)
            else -> false
        }
    }

    private fun extractTrafficBytes(name: String): Long? {
        val info = parseInformationalNode(name) ?: return null
        if (!info.prefix.matchesAnyPrefix(trafficInfoPrefixes)) return null
        return parseTrafficBytes(info.value)
    }

    private fun extractExpireTimestamp(name: String): Long? {
        val info = parseInformationalNode(name) ?: return null
        if (!info.prefix.matchesAnyPrefix(expiryInfoPrefixes)) return null
        if (isPermanentValidityValue(info.value)) return 0L
        return parseExpireTimestamp(info.value)
    }

    private fun parseInformationalNode(name: String): InformationalNode? {
        val normalizedName = name
            .replace(Regex("[\\u00A0\\u200B-\\u200D\\u2060\\uFEFF]"), "")
            .replace('：', ':')
            .replace('｜', '|')
            .replace('；', ';')
            .replace('，', ',')
            .trim()
            .trimStart { it.isWhitespace() || !it.isLetterOrDigit() }

        listOf(':', '|', ';', ',').forEach { separator ->
            val separatorIndex = normalizedName.indexOf(separator)
            if (separatorIndex > 0 && separatorIndex < normalizedName.lastIndex) {
                val prefix = normalizedName.substring(0, separatorIndex).trim()
                val value = normalizedName.substring(separatorIndex + 1).trim()
                if (prefix.isNotBlank() && value.isNotBlank()) {
                    return InformationalNode(prefix = prefix, value = value)
                }
            }
        }

        allInformationalPrefixes.forEach { prefix ->
            if (normalizedName.startsWith(prefix, ignoreCase = true)) {
                val value = normalizedName.substring(prefix.length)
                    .trimStart(' ', ':', '|', ';', ',', '-', '_', '/', '(', '[', '【', '；', '，', '。')
                    .trim()
                if (value.isNotBlank()) {
                    return InformationalNode(prefix = prefix, value = value)
                }
            }
        }

        return null
    }

    private fun isPermanentValidityValue(value: String): Boolean {
        val normalizedValue = value
            .replace(Regex("[\\u00A0\\u200B-\\u200D\\u2060\\uFEFF]"), "")
            .trim()
            .trim(' ', ':', '|', ';', ',', '-', '_', '/', '\\', '(', ')', '[', ']', '【', '】', '。', '.', '!', '！')

        return permanentValidityValuePattern.matches(normalizedValue) ||
            permanentValidityValuePattern.containsMatchIn(normalizedValue)
    }

    private fun parseTrafficBytes(value: String): Long? {
        val normalized = value.substringBefore('/').trim()
        val match = Regex(
            """(?ix)^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|PB|KIB|MIB|GIB|TIB|PIB|BYTE|BYTES|字节|字節)$"""
        ).find(normalized) ?: return null

        val amount = match.groupValues[1].toDoubleOrNull() ?: return null
        val multiplier = when (match.groupValues[2].uppercase(Locale.ROOT)) {
            "B", "BYTE", "BYTES", "字节", "字節" -> 1L
            "KB", "KIB" -> 1024L
            "MB", "MIB" -> 1024L * 1024L
            "GB", "GIB" -> 1024L * 1024L * 1024L
            "TB", "TIB" -> 1024L * 1024L * 1024L * 1024L
            "PB", "PIB" -> 1024L * 1024L * 1024L * 1024L * 1024L
            else -> return null
        }

        return (amount * multiplier).toLong()
    }

    private fun parseExpireTimestamp(value: String): Long? {
        if (timestampValuePattern.matches(value)) {
            val timestamp = value.toLongOrNull() ?: return null
            return if (value.length == 10) timestamp * 1000 else timestamp
        }

        parseRelativeDurationMillis(value)?.let { duration ->
            return System.currentTimeMillis() + duration
        }

        val normalized = value.replace('/', '-').replace('.', '-').replace('T', ' ').trim()
        val zoneId = ZoneId.systemDefault()
        val dateTimePatterns = listOf(
            "yyyy-M-d H:mm:ss",
            "yyyy-M-d H:mm"
        )

        dateTimePatterns.forEach { pattern ->
            runCatching {
                LocalDateTime.parse(normalized, DateTimeFormatter.ofPattern(pattern))
                    .atZone(zoneId)
                    .toInstant()
                    .toEpochMilli()
            }.getOrNull()?.let { return it }
        }

        val datePart = normalized.substringBefore(' ')
        return runCatching {
            LocalDate.parse(datePart, DateTimeFormatter.ofPattern("yyyy-M-d"))
                .atStartOfDay(zoneId)
                .toInstant()
                .toEpochMilli()
        }.getOrNull()
    }

    private fun parseRelativeDurationMillis(value: String): Long? {
        val match = Regex(
            """
            (?ix)
            ^
            (\d+)\s*
            (
                天|日|小时|小時|时|時|分钟|分鐘|分|秒|秒钟|秒鐘|
                day|days|hour|hours|hr|hrs|minute|minutes|min|mins|second|seconds|sec|secs|
                d|h|m|s
            )
            $
            """.trimIndent()
        ).find(value) ?: return null

        val amount = match.groupValues[1].toLongOrNull() ?: return null
        return when (match.groupValues[2].lowercase(Locale.ROOT)) {
            "天", "日", "day", "days", "d" -> amount * 24L * 60L * 60L * 1000L
            "小时", "小時", "时", "時", "hour", "hours", "hr", "hrs", "h" -> amount * 60L * 60L * 1000L
            "分钟", "分鐘", "分", "minute", "minutes", "min", "mins", "m" -> amount * 60L * 1000L
            "秒", "秒钟", "秒鐘", "second", "seconds", "sec", "secs", "s" -> amount * 1000L
            else -> null
        }
    }

    private fun String.matchesAnyPrefix(prefixes: List<String>): Boolean {
        return prefixes.any { startsWith(it, ignoreCase = true) }
    }

    private data class InformationalNode(
        val prefix: String,
        val value: String
    )

    // ─── Delegation to extracted parsers ───

    private fun parseUriList(content: String): NodeParseBatch {
        val batch = UriNodeParser.parseUriList(content)
        return NodeParseBatch(nodes = batch.nodes, diagnostics = batch.diagnostics)
    }

    private fun parseJsonContent(content: String): NodeParseBatch {
        val batch = JsonNodeParser.parseJsonContent(content)
        return NodeParseBatch(nodes = batch.nodes, diagnostics = batch.diagnostics)
    }

    private fun tryBase64Decode(value: String): String = UriNodeParser.tryBase64Decode(value)
}
