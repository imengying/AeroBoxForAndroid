package com.aerobox.core.subscription

import android.net.Uri
import android.util.Base64
import android.util.Log
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.SubscriptionType
import com.aerobox.data.model.connectionFingerprint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

data class ParsedSubscription(
    val nodes: List<ProxyNode>,
    val trafficBytes: Long = 0,
    val expireTimestamp: Long = 0,
    val sourceType: SubscriptionType = SubscriptionType.BASE64,
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

object SubscriptionParser {
    private const val TAG = "SubscriptionParser"
    internal val supportedTransportTypes = setOf("ws", "grpc", "http", "h2", "httpupgrade", "quic")
    private val supportedEnabledNetworks = setOf("tcp", "udp")

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
            val sourceType = when {
                targetContent.startsWith("{") || targetContent.startsWith("[") -> SubscriptionType.JSON
                else -> SubscriptionType.BASE64
            }

            val batch = when {
                targetContent.startsWith("{") || targetContent.startsWith("[") -> parseJsonContent(targetContent)
                targetContent.contains("://") -> parseUriList(targetContent)
                else -> NodeParseBatch(
                    nodes = emptyList(),
                    diagnostics = ParseDiagnostics().withIgnored("unsupported_subscription_content")
                )
            }

            sanitizeParsedNodes(batch.nodes, sourceType, batch.diagnostics)
        }.getOrDefault(ParsedSubscription(emptyList()))
    }

    private fun parseClashSubscription(content: String): ParsedSubscription {
        val result = ClashParser.parseClashYamlDetailed(content)
        return sanitizeParsedNodes(result.nodes, SubscriptionType.YAML, result.diagnostics)
    }

    private fun sanitizeParsedNodes(
        nodes: List<ProxyNode>,
        sourceType: SubscriptionType,
        diagnostics: ParseDiagnostics = ParseDiagnostics()
    ): ParsedSubscription {
        val (infoNodes, validNodes) = nodes.partition(::isInformationalNode)
        if (infoNodes.isNotEmpty()) {
            Log.i(TAG, "Filtered ${infoNodes.size} informational nodes: ${infoNodes.joinToString { it.name }}")
        }
        val dedupedNodes = dedupeNodes(validNodes)
        val duplicateCount = (validNodes.size - dedupedNodes.size).coerceAtLeast(0)
        val finalDiagnostics = buildDiagnostics {
            append(diagnostics)
            repeat(infoNodes.size) { appendIgnored("informational_entry") }
            repeat(duplicateCount) { appendIgnored("duplicate_entry") }
        }
        return ParsedSubscription(
            nodes = dedupedNodes,
            trafficBytes = infoNodes.mapNotNull { extractTrafficBytes(it.name) }.firstOrNull() ?: 0L,
            expireTimestamp = infoNodes.mapNotNull { extractExpireTimestamp(it.name) }.firstOrNull() ?: 0L,
            sourceType = sourceType,
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

    private fun parseUriList(content: String): NodeParseBatch {
        val nodes = mutableListOf<ProxyNode>()
        var diagnostics = ParseDiagnostics()
        content
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .forEach { uri ->
                when (val result = parseUriNode(uri)) {
                    is UriParseResult.Success -> nodes += result.node
                    is UriParseResult.Ignored -> diagnostics = diagnostics.withIgnored(result.reason)
                }
            }
        return NodeParseBatch(nodes = nodes, diagnostics = diagnostics)
    }

    private sealed interface UriParseResult {
        data class Success(val node: ProxyNode) : UriParseResult
        data class Ignored(val reason: String) : UriParseResult
    }

    private fun parseUriNode(uri: String): UriParseResult {
        return runCatching {
            val reasonPrefix = when {
                uri.startsWith("ss://", ignoreCase = true) -> "invalid_or_unsupported_shadowsocks_uri"
                uri.startsWith("vmess://", ignoreCase = true) -> "invalid_or_unsupported_vmess_uri"
                uri.startsWith("vless://", ignoreCase = true) -> "invalid_or_unsupported_vless_uri"
                uri.startsWith("trojan://", ignoreCase = true) -> "invalid_or_unsupported_trojan_uri"
                uri.startsWith("hysteria2://", ignoreCase = true) || uri.startsWith("hy2://", ignoreCase = true) ->
                    "invalid_or_unsupported_hysteria2_uri"
                uri.startsWith("tuic://", ignoreCase = true) -> "invalid_or_unsupported_tuic_uri"
                uri.startsWith("socks://", ignoreCase = true) ||
                    uri.startsWith("socks4://", ignoreCase = true) ||
                    uri.startsWith("socks4a://", ignoreCase = true) ||
                    uri.startsWith("socks5://", ignoreCase = true) -> "invalid_or_unsupported_socks_uri"
                uri.startsWith("http://", ignoreCase = true) || uri.startsWith("https://", ignoreCase = true) ->
                    "invalid_or_unsupported_http_uri"
                else -> return UriParseResult.Ignored("unsupported_uri_scheme")
            }
            val node = when {
                uri.startsWith("ss://", ignoreCase = true) -> parseShadowsocksUri(uri)
                uri.startsWith("vmess://", ignoreCase = true) -> parseVmessUri(uri)
                uri.startsWith("vless://", ignoreCase = true) -> parseVlessUri(uri)
                uri.startsWith("trojan://", ignoreCase = true) -> parseTrojanUri(uri)
                uri.startsWith("hysteria2://", ignoreCase = true) || uri.startsWith("hy2://", ignoreCase = true) -> parseHysteria2Uri(uri)
                uri.startsWith("tuic://", ignoreCase = true) -> parseTuicUri(uri)
                uri.startsWith("socks://", ignoreCase = true) ||
                    uri.startsWith("socks4://", ignoreCase = true) ||
                    uri.startsWith("socks4a://", ignoreCase = true) ||
                    uri.startsWith("socks5://", ignoreCase = true) -> parseSocksUri(uri)
                uri.startsWith("http://", ignoreCase = true) -> parseHttpProxyUri(uri)
                uri.startsWith("https://", ignoreCase = true) -> parseHttpProxyUri(uri)
                else -> null
            }
            if (node != null) UriParseResult.Success(node) else UriParseResult.Ignored(reasonPrefix)
        }.getOrElse {
            UriParseResult.Ignored("uri_parse_exception")
        }
    }

    private fun parseShadowsocksUri(uri: String): ProxyNode? {
        val raw = uri.removePrefix("ss://")
        val mainAndQuery = raw.substringBefore('#')
        val name = decodeName(raw.substringAfter('#', "Shadowsocks"))
        val params = parseUriParams(mainAndQuery.substringAfter('?', ""))
        val pluginSpec = parseShadowsocksPlugin(params["plugin"])

        val core = mainAndQuery.substringBefore('?')
        val normalizedCore = if (core.contains('@')) {
            val user = core.substringBefore('@')
            val hostPart = core.substringAfter('@')
            val decodedUser = if (user.contains(':')) user else tryBase64Decode(user)
            "$decodedUser@$hostPart"
        } else {
            tryBase64Decode(core)
        }

        val separatorIndex = normalizedCore.lastIndexOf('@')
        if (separatorIndex <= 0 || separatorIndex >= normalizedCore.lastIndex) return null

        val credentials = normalizedCore.substring(0, separatorIndex)
        val endpoint = normalizedCore.substring(separatorIndex + 1)
        val method = credentials.substringBefore(':').takeIf { it.isNotBlank() } ?: return null
        val password = credentials.substringAfter(':', "").takeIf { it.isNotBlank() } ?: return null
        val (server, port) = parseServerPort(endpoint) ?: return null

        return ProxyNode(
            name = name,
            type = if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS,
            server = server,
            port = port,
            password = password,
            method = method,
            network = normalizeEnabledNetwork(params["network"]),
            plugin = pluginSpec.first,
            pluginOpts = pluginSpec.second,
            udpOverTcpEnabled = parseBooleanOrNull(params["uot"], params["udp_over_tcp"])
        ).withUriSharedOptions(params)
    }

    private fun parseVmessUri(uri: String): ProxyNode? {
        val payload = uri.removePrefix("vmess://")
        val decoded = tryBase64Decode(payload)
        if (decoded.isBlank()) return null
        val json = JSONObject(decoded)

        val name = json.optString("ps", "VMess")
        val server = json.optString("add").ifBlank { return null }
        val port = json.optString("port").toIntOrNull() ?: return null
        val rawTransport = json.optString("net", "tcp")
        val transportType = resolveTransportType(
            rawNetwork = rawTransport,
            headerType = json.optString("type").ifBlank { null }
        )
        if (rawTransport.isNotBlank() && rawTransport.lowercase() != "tcp" && transportType == null) {
            return null
        }
        val rawPath = json.optString("path").ifBlank { null }

        return ProxyNode(
            name = name,
            type = ProxyType.VMESS,
            server = server,
            port = port,
            uuid = json.optString("id").ifBlank { null },
            alterId = json.optString("aid").toIntOrNull() ?: 0,
            security = json.optString("scy", json.optString("security", "auto")),
            transportType = transportType,
            tls = json.optString("tls").equals("tls", true),
            sni = json.optString("sni").ifBlank { null },
            transportHost = json.optString("host").ifBlank { null },
            transportPath = if (transportType == "grpc") null else rawPath,
            transportServiceName = json.optString("serviceName", json.optString("service_name", ""))
                .ifBlank { if (transportType == "grpc") rawPath else null },
            alpn = json.optString("alpn").ifBlank { null },
            fingerprint = firstNonBlank(
                json.optString("fp").ifBlank { null },
                json.optString("fingerprint").ifBlank { null }
            ),
            packetEncoding = firstNonBlank(
                json.optString("packetEncoding").ifBlank { null },
                json.optString("packet-encoding").ifBlank { null },
                json.optString("packet_encoding").ifBlank { null }
            ),
            allowInsecure = parseBooleanField(
                json.optString("allowInsecure"),
                json.optString("allow_insecure")
            )
        )
    }

    private fun parseVlessUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val userInfo = extractUserInfo(parsed) ?: return null
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val params = parseUriParams(parsed.query)
        val rawTransport = firstNonBlank(params["type"], params["network"])
        val transportType = resolveTransportType(rawTransport)
        if (rawTransport != null && rawTransport.lowercase() != "tcp" && transportType == null) return null

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "VLESS"),
            type = ProxyType.VLESS,
            server = server,
            port = port,
            uuid = userInfo,
            flow = params["flow"],
            security = params["security"],
            transportType = transportType,
            tls = params["security"].equals("tls", true) || params["security"].equals("reality", true),
            sni = params["sni"],
            transportHost = firstNonBlank(params["host"], params["authority"]),
            transportPath = if (transportType == "grpc") {
                null
            } else {
                params["path"]
            },
            transportServiceName = firstNonBlank(
                params["serviceName"],
                params["service_name"],
                if (transportType == "grpc") params["path"] else null
            ),
            alpn = params["alpn"],
            fingerprint = params["fp"],
            publicKey = firstNonBlank(params["pbk"], params["public-key"], params["public_key"]),
            shortId = firstNonBlank(params["sid"], params["short-id"], params["short_id"]),
            packetEncoding = firstNonBlank(
                params["packetEncoding"],
                params["packet-encoding"],
                params["packet_encoding"]
            ),
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        )
            .withUriTransportOptions(params)
            .withUriSharedOptions(params)
    }

    private fun parseTrojanUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val params = parseUriParams(parsed.query)
        val rawTransport = firstNonBlank(params["type"], params["network"])
        val transportType = resolveTransportType(rawTransport)
        if (rawTransport != null && rawTransport.lowercase() != "tcp" && transportType == null) return null

        val security = params["security"]?.lowercase()
        val isReality = security == "reality"

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "Trojan"),
            type = ProxyType.TROJAN,
            server = server,
            port = port,
            password = extractUserInfo(parsed),
            tls = true,
            sni = params["sni"],
            transportType = transportType,
            transportHost = firstNonBlank(params["host"], params["authority"]),
            transportPath = if (transportType == "grpc") {
                null
            } else {
                params["path"]
            },
            transportServiceName = firstNonBlank(
                params["serviceName"],
                params["service_name"],
                if (transportType == "grpc") params["path"] else null
            ),
            alpn = params["alpn"],
            fingerprint = firstNonBlank(params["fp"], params["fingerprint"]),
            publicKey = if (isReality) firstNonBlank(params["pbk"], params["public-key"]) else null,
            shortId = if (isReality) firstNonBlank(params["sid"], params["short-id"]) else null,
            packetEncoding = firstNonBlank(
                params["packetEncoding"],
                params["packet-encoding"],
                params["packet_encoding"]
            ),
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        )
            .withUriTransportOptions(params)
            .withUriSharedOptions(params)
    }

    private fun parseHysteria2Uri(uri: String): ProxyNode? {
        val normalized = if (uri.startsWith("hy2://", ignoreCase = true)) {
            uri.replaceFirst("hy2://", "hysteria2://")
        } else {
            uri
        }
        val parsed = Uri.parse(normalized)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val params = parseUriParams(parsed.query)

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "Hysteria2"),
            type = ProxyType.HYSTERIA2,
            server = server,
            port = port,
            password = extractUserInfo(parsed),
            network = normalizeEnabledNetwork(params["network"]),
            tls = true,
            sni = params["sni"],
            alpn = params["alpn"],
            obfsType = params["obfs"],
            obfsPassword = firstNonBlank(params["obfs-password"], params["obfs_password"]),
            serverPorts = firstNonBlank(params["mport"], params["server_ports"], params["server-ports"]),
            hopInterval = firstNonBlank(params["hop_interval"], params["hop-interval"]),
            upMbps = parseIntField(params["up_mbps"], params["upmbps"]),
            downMbps = parseIntField(params["down_mbps"], params["downmbps"]),
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        ).withUriSharedOptions(params)
    }

    private fun parseTuicUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val params = parseUriParams(parsed.query)

        val userInfo = extractUserInfo(parsed).orEmpty()
        val uuid = userInfo.substringBefore(':', userInfo)
        val password = userInfo.substringAfter(':', "")

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "TUIC"),
            type = ProxyType.TUIC,
            server = server,
            port = port,
            uuid = uuid.ifBlank { null },
            password = password.ifBlank { null },
            network = normalizeEnabledNetwork(params["network"]),
            tls = true,
            sni = params["sni"],
            alpn = params["alpn"],
            congestionControl = firstNonBlank(
                params["congestion_control"],
                params["congestion-control"]
            ),
            udpRelayMode = firstNonBlank(
                params["udp_relay_mode"],
                params["udp-relay-mode"]
            ),
            udpOverStream = parseBooleanOrNull(params["udp_over_stream"], params["udp-over-stream"]),
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        ).withUriSharedOptions(params)
    }

    private fun parseJsonContent(content: String): NodeParseBatch {
        return runCatching {
            if (content.trimStart().startsWith("[")) {
                parseJsonArray(JSONArray(content))
            } else {
                val jsonObject = JSONObject(content)
                when {
                    jsonObject.has("servers") -> parseJsonArray(jsonObject.getJSONArray("servers"))
                    jsonObject.has("outbounds") -> parseJsonArray(jsonObject.getJSONArray("outbounds"))
                    else -> parseJsonArray(JSONArray().put(jsonObject))
                }
            }
        }.getOrDefault(
            NodeParseBatch(
                nodes = emptyList(),
                diagnostics = ParseDiagnostics().withIgnored("invalid_json_content")
            )
        )
    }

    private fun parseJsonArray(array: JSONArray): NodeParseBatch {
        val result = mutableListOf<ProxyNode>()
        var diagnostics = ParseDiagnostics()
        for (index in 0 until array.length()) {
            val obj = array.optJSONObject(index) ?: run {
                diagnostics = diagnostics.withIgnored("invalid_json_item")
                continue
            }
            val transport = obj.optJSONObject("transport")
            val multiplex = obj.optJSONObject("multiplex")
            val tlsObject = obj.optJSONObject("tls")
            val realityObject = tlsObject?.optJSONObject("reality")
            val utlsObject = tlsObject?.optJSONObject("utls")
            val obfsObject = obj.optJSONObject("obfs")
            val headersObject = obj.optJSONObject("headers")
            val udpOverTcp = parseUdpOverTcp(obj.opt("udp_over_tcp"))
            val typeRaw = obj.optString("type", obj.optString("protocol", "")).lowercase()
            val type = when {
                typeRaw.contains("shadow") -> {
                    val method = obj.optString("method")
                    if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS
                }
                typeRaw.contains("vmess") -> ProxyType.VMESS
                typeRaw.contains("vless") -> ProxyType.VLESS
                typeRaw.contains("trojan") -> ProxyType.TROJAN
                typeRaw.contains("hysteria2") || typeRaw == "hy2" -> ProxyType.HYSTERIA2
                typeRaw.contains("tuic") -> ProxyType.TUIC
                typeRaw == "socks" || typeRaw == "socks4" || typeRaw == "socks4a" || typeRaw == "socks5" -> ProxyType.SOCKS
                typeRaw == "http" || typeRaw == "https" -> ProxyType.HTTP
                else -> {
                    diagnostics = diagnostics.withIgnored("unsupported_json_type")
                    continue
                }
            }

            val server = obj.optString("server", obj.optString("address", ""))
            val port = obj.optInt("server_port", obj.optInt("port", -1))
            if (server.isBlank() || port <= 0) {
                diagnostics = diagnostics.withIgnored("missing_json_endpoint")
                continue
            }
            val configuredNetwork = firstNonBlank(
                obj.optString("network", "").ifBlank { null },
                obj.optString("net", "").ifBlank { null }
            )
            val transportType = resolveTransportType(
                rawNetwork = firstNonBlank(
                    transport?.optString("type", "")?.ifBlank { null },
                    configuredNetwork
                ),
                headerType = firstNonBlank(
                    obj.optString("headerType", "").ifBlank { null },
                    obj.optString("header_type", "").ifBlank { null }
                )
            )
            val enabledNetwork = normalizeEnabledNetwork(configuredNetwork)
            if (!configuredNetwork.isNullOrBlank() && transport == null && transportType == null && enabledNetwork == null) {
                diagnostics = diagnostics.withIgnored("unsupported_json_network")
                continue
            }
            if (transport != null &&
                !transport.optString("type", "").isNullOrBlank() &&
                transportType == null
            ) {
                diagnostics = diagnostics.withIgnored("unsupported_json_transport")
                continue
            }

            result += ProxyNode(
                name = obj.optString("name", obj.optString("ps", type.name)),
                type = type,
                server = server,
                port = port,
                bindInterface = jsonScalarString(obj.opt("bind_interface")),
                connectTimeout = jsonScalarString(obj.opt("connect_timeout")),
                tcpFastOpen = optBooleanField(obj, "tcp_fast_open", "tcpFastOpen"),
                udpFragment = optBooleanField(obj, "udp_fragment", "udpFragment"),
                uuid = obj.optString("uuid", obj.optString("id", "")).ifBlank { null },
                alterId = parseIntField(
                    obj.optString("alter_id", "").ifBlank { null },
                    obj.optString("alterId", "").ifBlank { null },
                    obj.optString("aid", "").ifBlank { null }
                ) ?: 0,
                password = obj.optString("password", "").ifBlank { null },
                method = obj.optString("method", "").ifBlank { null },
                flow = obj.optString("flow", "").ifBlank { null },
                security = obj.optString("security", "").ifBlank { null },
                network = enabledNetwork,
                transportType = transportType,
                tls = typeRaw == "https"
                        || obj.optBoolean("tls", false)
                        || tlsObject?.optBoolean("enabled", false) == true
                        || realityObject?.optBoolean("enabled", false) == true,
                sni = firstNonBlank(
                    obj.optString("sni", "").ifBlank { null },
                    tlsObject?.optString("server_name", "")?.ifBlank { null },
                    tlsObject?.optString("sni", "")?.ifBlank { null }
                ),
                transportHost = firstNonBlank(
                    obj.optString("host", "").ifBlank { null },
                    transport?.optString("host", "")?.ifBlank { null },
                    extractHostHeader(headersObject),
                    transport?.optJSONObject("headers")?.optString("Host", "")?.ifBlank { null },
                    transport?.optJSONArray("host")?.toCommaSeparatedString()
                ),
                transportPath = firstNonBlank(
                    obj.optString("path", "").ifBlank { null },
                    transport?.optString("path", "")?.ifBlank { null }
                ),
                transportServiceName = firstNonBlank(
                    obj.optString("service_name", obj.optString("serviceName", "")).ifBlank { null },
                    transport?.optString("service_name", "")?.ifBlank { null },
                    transport?.optString("serviceName", "")?.ifBlank { null },
                    if (transportType == "grpc") {
                        firstNonBlank(
                            obj.optString("path", "").ifBlank { null },
                            transport?.optString("path", "")?.ifBlank { null }
                        )
                    } else {
                        null
                    }
                ),
                wsMaxEarlyData = transport?.optInt("max_early_data", -1)?.takeIf { it >= 0 },
                wsEarlyDataHeaderName = transport?.optString("early_data_header_name", "")?.ifBlank { null },
                alpn = firstNonBlank(
                    obj.optString("alpn", "").ifBlank { null },
                    tlsObject?.optJSONArray("alpn")?.toCommaSeparatedString(),
                    tlsObject?.optString("alpn", "")?.ifBlank { null }
                ),
                fingerprint = firstNonBlank(
                    obj.optString("fingerprint", obj.optString("fp", "")).ifBlank { null },
                    utlsObject?.optString("fingerprint", "")?.ifBlank { null }
                ),
                publicKey = firstNonBlank(
                    obj.optString("public_key", obj.optString("pbk", "")).ifBlank { null },
                    realityObject?.optString("public_key", "")?.ifBlank { null }
                ),
                shortId = firstNonBlank(
                    obj.optString("short_id", obj.optString("sid", "")).ifBlank { null },
                    realityObject?.optString("short_id", "")?.ifBlank { null }
                ),
                packetEncoding = firstNonBlank(
                    obj.optString("packet_encoding", obj.optString("packetEncoding", "")).ifBlank { null },
                    transport?.optString("packet_encoding", "")?.ifBlank { null },
                    transport?.optString("packetEncoding", "")?.ifBlank { null }
                ),
                username = obj.optString("username", "").ifBlank { null },
                socksVersion = firstNonBlank(
                    obj.optString("version", "").ifBlank { null },
                    when (typeRaw) {
                        "socks4" -> "4"
                        "socks4a" -> "4a"
                        "socks5" -> "5"
                        else -> null
                    }
                ),
                allowInsecure = obj.optBoolean("allowInsecure", false)
                        || obj.optBoolean("allow_insecure", false)
                        || tlsObject?.optBoolean("insecure", false) == true
                        || parseBooleanField(obj.optString("allowInsecure")),
                plugin = obj.optString("plugin", "").ifBlank { null },
                pluginOpts = firstNonBlank(
                    obj.optString("plugin_opts", "").ifBlank { null },
                    obj.optString("plugin-opts", "").ifBlank { null },
                    pluginOptionsValue(obj.optJSONObject("plugin_opts")),
                    pluginOptionsValue(obj.optJSONObject("plugin-opts"))
                ),
                udpOverTcpEnabled = udpOverTcp.first,
                udpOverTcpVersion = udpOverTcp.second,
                obfsType = firstNonBlank(
                    obfsObject?.optString("type", "")?.ifBlank { null },
                    obj.optString("obfs", "").ifBlank { null }
                ),
                obfsPassword = firstNonBlank(
                    obfsObject?.optString("password", "")?.ifBlank { null },
                    obj.optString("obfs_password", "").ifBlank { null },
                    obj.optString("obfs-password", "").ifBlank { null }
                ),
                serverPorts = firstNonBlank(
                    obj.optJSONArray("server_ports")?.toCommaSeparatedString(),
                    obj.optString("server_ports", "").ifBlank { null }
                ),
                hopInterval = obj.optString("hop_interval", "").ifBlank { null },
                upMbps = obj.optInt("up_mbps", -1).takeIf { it > 0 },
                downMbps = obj.optInt("down_mbps", -1).takeIf { it > 0 },
                muxEnabled = optBooleanField(multiplex, "enabled"),
                udpOverStream = optBooleanField(obj, "udp_over_stream")
            )
        }
        return NodeParseBatch(nodes = result, diagnostics = diagnostics)
    }
    private fun parseSocksUri(uri: String): ProxyNode? {
        val version = when {
            uri.startsWith("socks4a://", ignoreCase = true) -> "4a"
            uri.startsWith("socks4://", ignoreCase = true) -> "4"
            else -> "5"
        }
        val normalized = uri
            .replaceFirst(Regex("^socks4a://", RegexOption.IGNORE_CASE), "socks://")
            .replaceFirst(Regex("^socks4://", RegexOption.IGNORE_CASE), "socks://")
            .replaceFirst(Regex("^socks5?://", RegexOption.IGNORE_CASE), "socks://")
        val parsed = Uri.parse(normalized)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val userInfo = extractUserInfo(parsed)
        val username = userInfo?.substringBefore(':', userInfo)
        val password = userInfo?.substringAfter(':', "")?.ifBlank { null }

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "SOCKS$version"),
            type = ProxyType.SOCKS,
            server = server,
            port = port,
            username = username,
            password = password,
            socksVersion = version,
            udpOverTcpEnabled = parseBooleanOrNull(parsed.getQueryParameter("uot"))
        ).withUriSharedOptions(parseUriParams(parsed.query))
    }

    private fun parseHttpProxyUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val path = parsed.path.orEmpty()
        val params = parseUriParams(parsed.query)
        val userInfo = extractUserInfo(parsed)
        val username = userInfo?.substringBefore(':', userInfo)
        val password = userInfo?.substringAfter(':', "")?.ifBlank { null }
        val useTls = uri.startsWith("https://", ignoreCase = true)

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "HTTP"),
            type = ProxyType.HTTP,
            server = server,
            port = port,
            username = username,
            password = password,
            tls = useTls,
            transportPath = path.takeIf { it.isNotBlank() && it != "/" }
        ).withUriSharedOptions(params)
    }

    private fun ProxyNode.withUriTransportOptions(params: Map<String, String>): ProxyNode {
        return copy(
            wsMaxEarlyData = uriIntParam(
                params,
                "ed",
                "max_early_data",
                "ws_max_early_data"
            ) ?: wsMaxEarlyData,
            wsEarlyDataHeaderName = uriStringParam(
                params,
                "eh",
                "early_data_header_name",
                "ws_early_data_header_name"
            ) ?: wsEarlyDataHeaderName
        )
    }

    private fun ProxyNode.withUriSharedOptions(params: Map<String, String>): ProxyNode {
        val udpOverTcp = parseUdpOverTcp(
            firstNonBlank(
                params["udp_over_tcp"],
                params["udp-over-tcp"],
                params["uot"]
            )
        )
        return copy(
            bindInterface = uriStringParam(params, "bind_interface", "bind-interface", "interface_name", "interface-name")
                ?: bindInterface,
            connectTimeout = uriStringParam(params, "connect_timeout", "connect-timeout") ?: connectTimeout,
            tcpFastOpen = uriBooleanParam(params, "tcp_fast_open", "tcp-fast-open", "tfo") ?: tcpFastOpen,
            udpFragment = uriBooleanParam(params, "udp_fragment", "udp-fragment") ?: udpFragment,
            udpOverTcpEnabled = udpOverTcp.first ?: udpOverTcpEnabled,
            udpOverTcpVersion = udpOverTcp.second ?: udpOverTcpVersion,
            muxEnabled = uriBooleanParam(params, "mux", "smux", "multiplex", "mux_enabled", "smux_enabled")
                ?: muxEnabled
        )
    }

    private fun parseUriParams(query: String?): Map<String, String> {
        if (query.isNullOrBlank()) return emptyMap()
        return query.split("&")
            .mapNotNull { entry ->
                val parts = entry.split("=", limit = 2)
                if (parts.isEmpty()) return@mapNotNull null
                val key = decodeName(parts[0])
                val value = decodeName(parts.getOrElse(1) { "" })
                key to value
            }
            .toMap()
    }

    private fun uriStringParam(params: Map<String, String>, vararg keys: String): String? {
        return firstNonBlank(*keys.map { params[it] }.toTypedArray())
    }

    private fun uriBooleanParam(params: Map<String, String>, vararg keys: String): Boolean? {
        return parseBooleanOrNull(*keys.map { params[it] }.toTypedArray())
    }

    private fun uriIntParam(params: Map<String, String>, vararg keys: String): Int? {
        return parseIntField(*keys.map { params[it] }.toTypedArray())
    }

    private fun normalizeTransportType(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return when (normalized) {
            "websocket" -> "ws"
            "http-upgrade" -> "httpupgrade"
            else -> normalized
        }
    }

    private fun normalizeEnabledNetwork(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return normalized.takeIf { it in supportedEnabledNetworks }
    }

    private fun resolveTransportType(
        rawNetwork: String?,
        headerType: String? = null
    ): String? {
        val normalizedNetwork = normalizeTransportType(rawNetwork) ?: return null
        val normalizedHeaderType = headerType?.trim()?.lowercase()?.takeIf { it.isNotBlank() }
        val resolved = if (normalizedNetwork == "tcp" && normalizedHeaderType == "http") {
            "http"
        } else {
            normalizedNetwork
        }
        if (resolved == "tcp") return null
        return resolved.takeIf { it in supportedTransportTypes }
    }

    private fun parseServerPort(raw: String): Pair<String, Int>? {
        val value = raw.trim()
        if (value.isBlank()) return null

        if (value.startsWith("[")) {
            val closingBracket = value.indexOf(']')
            if (closingBracket <= 1 || closingBracket >= value.lastIndex) return null
            val host = value.substring(1, closingBracket)
            val port = value.substring(closingBracket + 1).removePrefix(":").toIntOrNull() ?: return null
            return host to port
        }

        val separatorIndex = value.lastIndexOf(':')
        if (separatorIndex <= 0 || separatorIndex >= value.lastIndex) return null
        val host = value.substring(0, separatorIndex)
        val port = value.substring(separatorIndex + 1).toIntOrNull() ?: return null
        return host to port
    }

    private fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun JSONArray.toCommaSeparatedString(): String? {
        val values = buildList {
            for (i in 0 until length()) {
                optString(i).trim().takeIf { it.isNotEmpty() }?.let { add(it) }
            }
        }
        return values.takeIf { it.isNotEmpty() }?.joinToString(",")
    }

    private fun extractHostHeader(headers: JSONObject?): String? {
        return firstNonBlank(
            headers?.optString("Host", "")?.ifBlank { null },
            headers?.optString("host", "")?.ifBlank { null }
        )
    }

    private fun jsonScalarString(value: Any?): String? {
        return when (value) {
            null, JSONObject.NULL -> null
            is JSONObject, is JSONArray -> null
            else -> value.toString().trim().takeIf { it.isNotEmpty() }
        }
    }

    private fun pluginOptionsValue(value: JSONObject?): String? {
        if (value == null || value.length() == 0) return null
        val parts = buildList {
            val keys = value.keys()
            while (keys.hasNext()) {
                val key = keys.next().trim()
                if (key.isEmpty()) continue
                val rawValue = value.opt(key)
                val optionValue = rawValue?.toString()?.trim().orEmpty()
                add(if (optionValue.isEmpty()) key else "$key=$optionValue")
            }
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(";")
    }

    private fun parseUdpOverTcp(value: Any?): Pair<Boolean?, Int?> {
        return when (value) {
            null, JSONObject.NULL -> null to null
            is Boolean -> value to null
            is JSONObject -> {
                val enabled = if (value.has("enabled")) value.optBoolean("enabled") else true
                val version = value.optInt("version", -1).takeIf { it >= 0 }
                enabled to version
            }
            is Number -> true to value.toInt()
            is String -> {
                val trimmed = value.trim()
                when {
                    trimmed.isEmpty() -> null to null
                    trimmed == "1" -> true to null
                    trimmed == "0" -> false to null
                    trimmed == "true" || trimmed == "false" -> trimmed.toBoolean() to null
                    else -> true to trimmed.toIntOrNull()
                }
            }
            else -> null to null
        }
    }

    private fun parseBooleanOrNull(vararg values: String?): Boolean? {
        return values.firstNotNullOfOrNull { value ->
            when (value?.trim()?.lowercase()) {
                "1", "true", "yes", "on" -> true
                "0", "false", "no", "off" -> false
                else -> null
            }
        }
    }

    private fun optBooleanField(obj: JSONObject?, vararg keys: String): Boolean? {
        val source = obj ?: return null
        for (key in keys) {
            if (source.has(key)) {
                return source.optBoolean(key)
            }
        }
        return null
    }

    private fun optIntField(obj: JSONObject?, vararg keys: String): Int? {
        val source = obj ?: return null
        for (key in keys) {
            if (!source.has(key)) continue
            val value = source.opt(key)
            return when (value) {
                is Number -> value.toInt()
                is String -> value.trim().toIntOrNull()
                else -> null
            }
        }
        return null
    }

    private fun tryBase64Decode(value: String): String {
        val sanitized = value.trim().replace("\n", "").replace("\r", "")
        if (sanitized.isBlank()) return value

        val candidates = buildList {
            add(sanitized)
            add(sanitized.trimEnd('='))
            add(sanitized.replace('-', '+').replace('_', '/'))
            add(sanitized.trimEnd('=').replace('-', '+').replace('_', '/'))
        }.distinct()

        val flags = listOf(
            Base64.DEFAULT,
            Base64.NO_WRAP,
            Base64.NO_WRAP or Base64.URL_SAFE,
            Base64.URL_SAFE
        )

        candidates.forEach { candidate ->
            if (candidate.isBlank()) return@forEach
            val padding = (4 - candidate.length % 4) % 4
            val adjusted = candidate + "=".repeat(padding)
            flags.forEach { flag ->
                runCatching {
                    String(Base64.decode(adjusted, flag), StandardCharsets.UTF_8).trim()
                }.getOrNull()?.let { return it }
            }
        }

        return value
    }

    private fun decodeName(value: String): String {
        return runCatching {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }.getOrDefault(value)
    }

    private fun extractUserInfo(uri: Uri): String? {
        val authority = uri.encodedAuthority ?: return null
        if (!authority.contains('@')) return null
        return decodeName(authority.substringBefore('@'))
    }

    private fun parseBooleanField(vararg values: String?): Boolean {
        return values.any { v ->
            v != null && (v == "1" || v.equals("true", true))
        }
    }

    private fun parseIntField(vararg values: String?): Int? {
        return values.firstNotNullOfOrNull { it?.trim()?.toIntOrNull() }
    }

    private fun parseShadowsocksPlugin(value: String?): Pair<String?, String?> {
        val normalized = value?.trim()?.takeIf { it.isNotEmpty() } ?: return null to null
        val parts = normalized.split(';', limit = 2)
        val plugin = parts.firstOrNull()?.trim()?.takeIf { it.isNotEmpty() }
        val options = parts.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
        return plugin to options
    }

    private fun buildDiagnostics(block: ParseDiagnosticsBuilder.() -> Unit): ParseDiagnostics {
        return ParseDiagnosticsBuilder().apply(block).build()
    }

    private class ParseDiagnosticsBuilder {
        private var diagnostics = ParseDiagnostics()

        fun append(other: ParseDiagnostics) {
            diagnostics += other
        }

        fun appendIgnored(reason: String) {
            diagnostics = diagnostics.withIgnored(reason)
        }

        fun build(): ParseDiagnostics = diagnostics
    }

}
