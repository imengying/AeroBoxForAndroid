package com.aerobox.core.subscription

import android.net.Uri
import android.util.Base64
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
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
    val expireTimestamp: Long = 0
)

object SubscriptionParser {
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

    suspend fun parseSubscription(content: String): List<ProxyNode> {
        return parseSubscriptionContent(content).nodes
    }

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

            val nodes = when {
                targetContent.startsWith("{") || targetContent.startsWith("[") -> parseJsonContent(targetContent)
                targetContent.contains("://") -> parseUriList(targetContent)
                else -> emptyList()
            }

            sanitizeParsedNodes(nodes)
        }.getOrDefault(ParsedSubscription(emptyList()))
    }

    private fun parseClashSubscription(content: String): ParsedSubscription {
        val rawNodes = ClashParser.parseClashYaml(content)
        return sanitizeParsedNodes(rawNodes)
    }

    private fun sanitizeParsedNodes(nodes: List<ProxyNode>): ParsedSubscription {
        val infoNodes = nodes.filter(::isInformationalNode)
        return ParsedSubscription(
            nodes = nodes
                .filterNot(::isInformationalNode)
                .let(::dedupeNodes),
            trafficBytes = infoNodes.mapNotNull { extractTrafficBytes(it.name) }.firstOrNull() ?: 0L,
            expireTimestamp = infoNodes.mapNotNull { extractExpireTimestamp(it.name) }.firstOrNull() ?: 0L
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
                dateValuePattern.matches(info.value) || relativeTimeValuePattern.matches(info.value) || timestampValuePattern.matches(info.value)
            }
            info.prefix.matchesAnyPrefix(trafficInfoPrefixes) -> trafficValuePattern.matches(info.value)
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
        return parseExpireTimestamp(info.value)
    }

    private fun parseInformationalNode(name: String): InformationalNode? {
        val normalizedName = name
            .replace('：', ':')
            .trim()
            .trimStart { it.isWhitespace() || !it.isLetterOrDigit() }

        val separatorIndex = normalizedName.indexOf(':')
        if (separatorIndex <= 0 || separatorIndex >= normalizedName.lastIndex) return null

        val prefix = normalizedName.substring(0, separatorIndex).trim()
        val value = normalizedName.substring(separatorIndex + 1).trim()
        if (prefix.isBlank() || value.isBlank()) return null

        return InformationalNode(prefix = prefix, value = value)
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

    private fun parseUriList(content: String): List<ProxyNode> {
        return content
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .mapNotNull { parseUriNode(it) }
            .toList()
    }

    private fun parseUriNode(uri: String): ProxyNode? {
        return runCatching {
            when {
                uri.startsWith("ss://", ignoreCase = true) -> parseShadowsocksUri(uri)
                uri.startsWith("vmess://", ignoreCase = true) -> parseVmessUri(uri)
                uri.startsWith("vless://", ignoreCase = true) -> parseVlessUri(uri)
                uri.startsWith("trojan://", ignoreCase = true) -> parseTrojanUri(uri)
                uri.startsWith("hysteria2://", ignoreCase = true) || uri.startsWith("hy2://", ignoreCase = true) -> parseHysteria2Uri(uri)
                uri.startsWith("tuic://", ignoreCase = true) -> parseTuicUri(uri)
                uri.startsWith("socks://", ignoreCase = true) || uri.startsWith("socks5://", ignoreCase = true) -> parseSocksUri(uri)
                uri.startsWith("http://", ignoreCase = true) && uri.contains("@") -> parseHttpProxyUri(uri)
                uri.startsWith("https://", ignoreCase = true) && uri.contains("@") -> parseHttpProxyUri(uri)
                else -> null
            }
        }.getOrNull()
    }

    private fun parseShadowsocksUri(uri: String): ProxyNode? {
        val raw = uri.removePrefix("ss://")
        val mainAndQuery = raw.substringBefore('#')
        val name = decodeName(raw.substringAfter('#', "Shadowsocks"))

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
            method = method
        )
    }

    private fun parseVmessUri(uri: String): ProxyNode? {
        val payload = uri.removePrefix("vmess://")
        val decoded = tryBase64Decode(payload)
        if (decoded.isBlank()) return null
        val json = JSONObject(decoded)

        val name = json.optString("ps", "VMess")
        val server = json.optString("add")
        val port = json.optString("port").toIntOrNull() ?: return null
        val network = normalizeNetwork(json.optString("net", "tcp"))
        val rawPath = json.optString("path").ifBlank { null }

        return ProxyNode(
            name = name,
            type = ProxyType.VMESS,
            server = server,
            port = port,
            uuid = json.optString("id").ifBlank { null },
            security = json.optString("scy", json.optString("security", "auto")),
            network = network,
            tls = json.optString("tls").equals("tls", true),
            sni = json.optString("sni").ifBlank { null },
            transportHost = json.optString("host").ifBlank { null },
            transportPath = if (network == "grpc") null else rawPath,
            transportServiceName = json.optString("serviceName", json.optString("service_name", ""))
                .ifBlank { if (network == "grpc") rawPath else null },
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
        val network = normalizeNetwork(params["type"] ?: params["network"])

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "VLESS"),
            type = ProxyType.VLESS,
            server = server,
            port = port,
            uuid = userInfo,
            flow = params["flow"],
            security = params["security"],
            network = network,
            tls = params["security"].equals("tls", true) || params["security"].equals("reality", true),
            sni = params["sni"],
            transportHost = firstNonBlank(params["host"], params["authority"]),
            transportPath = if (network == "grpc") {
                null
            } else {
                params["path"]
            },
            transportServiceName = firstNonBlank(
                params["serviceName"],
                params["service_name"],
                if (network == "grpc") params["path"] else null
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
    }

    private fun parseTrojanUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val params = parseUriParams(parsed.query)
        val network = normalizeNetwork(params["type"] ?: params["network"])

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "Trojan"),
            type = ProxyType.TROJAN,
            server = server,
            port = port,
            password = extractUserInfo(parsed),
            tls = true,
            sni = params["sni"],
            network = network,
            transportHost = firstNonBlank(params["host"], params["authority"]),
            transportPath = if (network == "grpc") {
                null
            } else {
                params["path"]
            },
            transportServiceName = firstNonBlank(
                params["serviceName"],
                params["service_name"],
                if (network == "grpc") params["path"] else null
            ),
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
            tls = true,
            sni = params["sni"],
            alpn = params["alpn"],
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        )
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
            tls = true,
            sni = params["sni"],
            alpn = params["alpn"],
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        )
    }

    private fun parseJsonContent(content: String): List<ProxyNode> {
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
        }.getOrDefault(emptyList())
    }

    private fun parseJsonArray(array: JSONArray): List<ProxyNode> {
        val result = mutableListOf<ProxyNode>()
        for (index in 0 until array.length()) {
            val obj = array.optJSONObject(index) ?: continue
            val transport = obj.optJSONObject("transport")
            val tlsObject = obj.optJSONObject("tls")
            val realityObject = tlsObject?.optJSONObject("reality")
            val utlsObject = tlsObject?.optJSONObject("utls")
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
                typeRaw == "socks" || typeRaw == "socks5" -> ProxyType.SOCKS
                typeRaw == "http" || typeRaw == "https" -> ProxyType.HTTP
                else -> continue
            }

            val server = obj.optString("server", obj.optString("address", ""))
            val port = obj.optInt("server_port", obj.optInt("port", -1))
            if (server.isBlank() || port <= 0) continue
            val network = normalizeNetwork(
                obj.optString("network", obj.optString("net", "")).ifBlank {
                    transport?.optString("type", "")?.ifBlank { null }
                }
            )

            result += ProxyNode(
                name = obj.optString("name", obj.optString("ps", type.name)),
                type = type,
                server = server,
                port = port,
                uuid = obj.optString("uuid", obj.optString("id", "")).ifBlank { null },
                password = obj.optString("password", "").ifBlank { null },
                method = obj.optString("method", "").ifBlank { null },
                flow = obj.optString("flow", "").ifBlank { null },
                security = obj.optString("security", "").ifBlank { null },
                network = network,
                tls = obj.optBoolean("tls", false)
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
                    if (network == "grpc") {
                        firstNonBlank(
                            obj.optString("path", "").ifBlank { null },
                            transport?.optString("path", "")?.ifBlank { null }
                        )
                    } else {
                        null
                    }
                ),
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
                allowInsecure = obj.optBoolean("allowInsecure", false)
                        || obj.optBoolean("allow_insecure", false)
                        || tlsObject?.optBoolean("insecure", false) == true
                        || parseBooleanField(obj.optString("allowInsecure"))
            )
        }
        return result
    }
    private fun parseSocksUri(uri: String): ProxyNode? {
        val normalized = uri.replaceFirst(Regex("^socks5?://", RegexOption.IGNORE_CASE), "socks://")
        val parsed = Uri.parse(normalized)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
        val userInfo = extractUserInfo(parsed)
        val username = userInfo?.substringBefore(':', userInfo)
        val password = userInfo?.substringAfter(':', "")?.ifBlank { null }

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "SOCKS5"),
            type = ProxyType.SOCKS,
            server = server,
            port = port,
            username = username,
            password = password
        )
    }

    private fun parseHttpProxyUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: return null
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
            tls = useTls
        )
    }

    fun parseUriParams(query: String?): Map<String, String> {
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

    private fun normalizeNetwork(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return when (normalized) {
            "websocket" -> "ws"
            "http-upgrade" -> "httpupgrade"
            else -> normalized
        }
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

    private fun tryBase64Decode(value: String): String {
        return runCatching {
            val sanitized = value.trim().replace("\n", "")
            val padding = (4 - sanitized.length % 4) % 4
            val adjusted = sanitized + "=".repeat(padding)
            val decoded = Base64.decode(adjusted, Base64.DEFAULT)
            String(decoded, StandardCharsets.UTF_8).trim()
        }.getOrDefault(value)
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
}
