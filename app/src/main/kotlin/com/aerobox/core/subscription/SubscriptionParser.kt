package com.aerobox.core.subscription

import android.net.Uri
import android.util.Base64
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object SubscriptionParser {
    suspend fun parseSubscription(content: String): List<ProxyNode> = withContext(Dispatchers.Default) {
        runCatching {
            val normalized = content.trim()
            if (normalized.isBlank()) {
                return@runCatching emptyList()
            }

            // Check for Clash/ClashMeta YAML format first
            if (ClashParser.isClashYaml(normalized)) {
                return@runCatching ClashParser.parseClashYaml(normalized)
                    .distinctBy { "${it.type}:${it.server}:${it.port}:${it.name}" }
            }

            val base64Decoded = tryBase64Decode(normalized)

            // Also check if Base64-decoded content is Clash YAML
            if (base64Decoded != normalized && ClashParser.isClashYaml(base64Decoded)) {
                return@runCatching ClashParser.parseClashYaml(base64Decoded)
                    .distinctBy { "${it.type}:${it.server}:${it.port}:${it.name}" }
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

            nodes.distinctBy { "${it.type}:${it.server}:${it.port}:${it.name}" }
        }.getOrDefault(emptyList())
    }

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

        val pattern = Regex("(.+):(.+)@([^:]+):(\\d+)")
        val match = pattern.find(normalizedCore) ?: return null

        val method = match.groupValues[1]
        val password = match.groupValues[2]
        val server = match.groupValues[3]
        val port = match.groupValues[4].toIntOrNull() ?: return null

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
