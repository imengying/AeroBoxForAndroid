package com.aerobox.core.subscription

import android.net.Uri
import android.util.Base64
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * URI-based proxy node parsers and shared parsing helpers.
 *
 * Extracted from [SubscriptionParser] for maintainability.
 */
internal object UriNodeParser {

    private val supportedTransportTypes = SubscriptionParser.supportedTransportTypes
    private val supportedEnabledNetworks = setOf("tcp", "udp")

    internal data class NodeParseBatch(
        val nodes: List<ProxyNode>,
        val diagnostics: ParseDiagnostics = ParseDiagnostics()
    )

    internal fun parseUriList(content: String): NodeParseBatch {
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

    internal sealed interface UriParseResult {
        data class Success(val node: ProxyNode) : UriParseResult
        data class Ignored(val reason: String) : UriParseResult
    }

    internal fun parseUriNode(uri: String): UriParseResult {
        return runCatching {
            val reasonPrefix = when {
                uri.startsWith("ss://", ignoreCase = true) -> "invalid_or_unsupported_shadowsocks_uri"
                uri.startsWith("vmess://", ignoreCase = true) -> "invalid_or_unsupported_vmess_uri"
                uri.startsWith("vless://", ignoreCase = true) -> "invalid_or_unsupported_vless_uri"
                uri.startsWith("trojan://", ignoreCase = true) -> "invalid_or_unsupported_trojan_uri"
                uri.startsWith("hysteria2://", ignoreCase = true) || uri.startsWith("hy2://", ignoreCase = true) ->
                    "invalid_or_unsupported_hysteria2_uri"
                uri.startsWith("tuic://", ignoreCase = true) -> "invalid_or_unsupported_tuic_uri"
                uri.startsWith("naive+https://", ignoreCase = true) ||
                    uri.startsWith("naive+quic://", ignoreCase = true) ||
                    uri.startsWith("naive://", ignoreCase = true) -> "invalid_or_unsupported_naive_uri"
                uri.startsWith("socks://", ignoreCase = true) ||
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
                uri.startsWith("naive+https://", ignoreCase = true) ||
                    uri.startsWith("naive+quic://", ignoreCase = true) ||
                    uri.startsWith("naive://", ignoreCase = true) -> parseNaiveUri(uri)
                uri.startsWith("socks://", ignoreCase = true) ||
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

    internal fun parseShadowsocksUri(uri: String): ProxyNode? {
        val raw = uri.removePrefix("ss://")
        val mainAndQuery = raw.substringBefore('#')
        val name = decodeName(raw.substringAfter('#', "Shadowsocks"))
        val params = parseUriParams(mainAndQuery.substringAfter('?', ""))
        val pluginSpec = parseShadowsocksPlugin(params["plugin"])
        val shadowTls = extractShadowTlsFromPluginString(pluginSpec.first, pluginSpec.second)

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
            udpOverTcpEnabled = parseBooleanOrNull(params["uot"], params["udp_over_tcp"]),
            shadowTlsVersion = shadowTls?.version,
            shadowTlsPassword = shadowTls?.password,
            shadowTlsServerName = shadowTls?.host,
            shadowTlsAlpn = shadowTls?.alpn
        ).withUriSharedOptions(params)
    }

    /** Parsed view of a Shadowsocks `plugin=shadow-tls;…` plugin-opts string. */
    internal data class ShadowTlsPluginInfo(
        val host: String?,
        val password: String?,
        val version: Int?,
        val alpn: String?
    )

    /**
     * Extract ShadowTLS configuration from an SS-URI `plugin` + `plugin-opts`
     * pair. Returns null when [plugin] is not the shadow-tls plugin.
     *
     * Recognises the common `host=…;password=…;version=3` form as well as
     * tolerant variations (`server-name=`, `alpn=h2,http/1.1`).
     */
    internal fun extractShadowTlsFromPluginString(plugin: String?, opts: String?): ShadowTlsPluginInfo? {
        if (plugin?.lowercase()?.trim() != "shadow-tls") return null
        val pairs = opts.orEmpty().split(';', '\n')
            .mapNotNull { entry ->
                val trimmed = entry.trim()
                if (trimmed.isEmpty()) return@mapNotNull null
                val sep = trimmed.indexOf('=')
                if (sep <= 0) return@mapNotNull null
                val key = trimmed.substring(0, sep).trim().lowercase()
                val value = trimmed.substring(sep + 1).trim()
                if (key.isBlank() || value.isBlank()) null else key to value
            }
            .toMap()
        if (pairs.isEmpty()) return null
        return ShadowTlsPluginInfo(
            host = pairs["host"] ?: pairs["server-name"] ?: pairs["server_name"],
            password = pairs["password"],
            version = pairs["version"]?.toIntOrNull(),
            alpn = pairs["alpn"]
        )
    }

    internal fun parseVmessUri(uri: String): ProxyNode? {
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

    internal fun parseVlessUri(uri: String): ProxyNode? {
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

    internal fun parseTrojanUri(uri: String): ProxyNode? {
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

    internal fun parseHysteria2Uri(uri: String): ProxyNode? {
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
            serverPorts = firstNonBlank(
                params["mport"],
                params["server_ports"],
                params["server-ports"],
                params["ports"]
            ),
            hopInterval = firstNonBlank(params["hop_interval"], params["hop-interval"]),
            upMbps = parseIntField(params["up_mbps"], params["upmbps"]),
            downMbps = parseIntField(params["down_mbps"], params["downmbps"]),
            allowInsecure = parseBooleanField(
                params["allowInsecure"],
                params["insecure"]
            )
        ).withUriSharedOptions(params)
    }

    internal fun parseTuicUri(uri: String): ProxyNode? {
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

    internal fun parseNaiveUri(uri: String): ProxyNode? {
        val parsed = Uri.parse(uri)
        val server = parsed.host ?: return null
        val port = parsed.port.takeIf { it > 0 } ?: 443
        val params = parseUriParams(parsed.query)
        val protocol = resolveNaiveProtocol(
            parsed.scheme,
            params["protocol"],
            params["proto"],
            parseBooleanOrNull(params["quic"])
        ) ?: return null
        val userInfo = extractUserInfo(parsed)
        val username = userInfo?.substringBefore(':', userInfo)?.ifBlank { null }
        val password = userInfo?.substringAfter(':', "")?.ifBlank { null }

        return ProxyNode(
            name = decodeName(parsed.fragment ?: "Naive"),
            type = ProxyType.NAIVE,
            server = server,
            port = port,
            username = username,
            password = password,
            tls = true,
            sni = params["sni"],
            transportType = if (protocol == "quic") "quic" else null,
            congestionControl = firstNonBlank(
                params["quic-congestion-control"],
                params["quic_congestion_control"]
            ),
            naiveProtocol = protocol,
            naiveExtraHeaders = firstNonBlank(
                params["extra-headers"],
                params["extra_headers"]
            ),
            naiveInsecureConcurrency = parseIntField(
                params["insecure-concurrency"],
                params["insecure_concurrency"]
            ),
            naiveCertificate = firstNonBlank(params["cert"], params["certificate"]),
            naiveCertificatePath = firstNonBlank(
                params["certificate-path"],
                params["certificate_path"]
            ),
            naiveEchEnabled = parseBooleanOrNull(
                params["ech"],
                params["ech-enabled"],
                params["ech_enabled"]
            ),
            naiveEchConfig = firstNonBlank(
                params["ech-config"],
                params["ech_config"]
            ),
            naiveEchConfigPath = firstNonBlank(
                params["ech-config-path"],
                params["ech_config_path"]
            ),
            naiveEchQueryServerName = firstNonBlank(
                params["ech-query-server-name"],
                params["ech_query_server_name"]
            )
        ).withUriSharedOptions(params)
    }

    internal fun parseSocksUri(uri: String): ProxyNode? {
        val normalized = uri
            .replaceFirst(Regex("^socks5?://", RegexOption.IGNORE_CASE), "socks://")
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
            password = password,
            socksVersion = "5",
            udpOverTcpEnabled = parseBooleanOrNull(parsed.getQueryParameter("uot"))
        ).withUriSharedOptions(parseUriParams(parsed.query))
    }

    internal fun parseHttpProxyUri(uri: String): ProxyNode? {
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

    internal fun ProxyNode.withUriTransportOptions(params: Map<String, String>): ProxyNode {
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

    internal fun ProxyNode.withUriSharedOptions(params: Map<String, String>): ProxyNode {
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

    internal fun parseUriParams(query: String?): Map<String, String> {
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

    internal fun uriStringParam(params: Map<String, String>, vararg keys: String): String? {
        return firstNonBlank(*keys.map { params[it] }.toTypedArray())
    }

    internal fun uriBooleanParam(params: Map<String, String>, vararg keys: String): Boolean? {
        return parseBooleanOrNull(*keys.map { params[it] }.toTypedArray())
    }

    internal fun uriIntParam(params: Map<String, String>, vararg keys: String): Int? {
        return parseIntField(*keys.map { params[it] }.toTypedArray())
    }

    internal fun resolveNaiveProtocol(
        schemeOrType: String?,
        protocol: String?,
        proto: String?,
        quic: Boolean?
    ): String? {
        val normalizedSource = schemeOrType?.trim()?.lowercase(Locale.ROOT)
        val configuredProtocol = firstNonBlank(protocol, proto)?.lowercase(Locale.ROOT)
        return when {
            normalizedSource == "naive+quic" || quic == true || configuredProtocol == "quic" -> "quic"
            normalizedSource == "naive+https" || normalizedSource == "naive" -> "https"
            normalizedSource?.contains("naive") == true -> "https"
            configuredProtocol == "https" -> "https"
            else -> null
        }
    }

    internal fun normalizeTransportType(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return when (normalized) {
            "websocket" -> "ws"
            "http-upgrade" -> "httpupgrade"
            else -> normalized
        }
    }

    internal fun normalizeEnabledNetwork(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return normalized.takeIf { it in supportedEnabledNetworks }
    }

    internal fun resolveTransportType(
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

    internal fun parseServerPort(raw: String): Pair<String, Int>? {
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

    internal fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }




    internal fun firstPortFromPortList(serverPorts: String?): Int? {
        return serverPorts
            ?.split(",")
            ?.firstNotNullOfOrNull { entry ->
                Regex("""\d{1,5}""")
                    .find(entry)
                    ?.value
                    ?.toIntOrNull()
                    ?.takeIf { it in 1..65535 }
            }
    }

    internal fun extractHostHeader(headers: JSONObject?): String? {
        return firstNonBlank(
            headers?.optString("Host", "")?.ifBlank { null },
            headers?.optString("host", "")?.ifBlank { null }
        )
    }

    internal fun jsonScalarString(value: Any?): String? {
        return when (value) {
            null, JSONObject.NULL -> null
            is JSONObject, is JSONArray -> null
            else -> value.toString().trim().takeIf { it.isNotEmpty() }
        }
    }

    internal fun jsonListOrScalarString(value: Any?): String? {
        return when (value) {
            is JSONArray -> buildList {
                for (index in 0 until value.length()) {
                    jsonScalarString(value.opt(index))?.let { add(it) }
                }
            }.takeIf { it.isNotEmpty() }?.joinToString("\n")
            else -> jsonScalarString(value)
        }
    }

    internal fun jsonObjectString(value: JSONObject?): String? {
        return value?.takeIf { it.length() > 0 }?.toString()
    }

    internal fun pluginOptionsValue(value: JSONObject?): String? {
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

    internal fun parseUdpOverTcp(value: Any?): Pair<Boolean?, Int?> = parseUdpOverTcpValue(value)

    internal fun parseBooleanOrNull(vararg values: String?): Boolean? {
        return values.firstNotNullOfOrNull { value ->
            when (value?.trim()?.lowercase()) {
                "1", "true", "yes", "on" -> true
                "0", "false", "no", "off" -> false
                else -> null
            }
        }
    }

    internal fun optBooleanField(obj: JSONObject?, vararg keys: String): Boolean? {
        val source = obj ?: return null
        for (key in keys) {
            if (source.has(key)) {
                return source.optBoolean(key)
            }
        }
        return null
    }

    internal fun tryBase64Decode(value: String): String {
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

    internal fun decodeName(value: String): String {
        return runCatching {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }.getOrDefault(value)
    }

    internal fun extractUserInfo(uri: Uri): String? {
        val authority = uri.encodedAuthority ?: return null
        if (!authority.contains('@')) return null
        return decodeName(authority.substringBefore('@'))
    }

    internal fun parseBooleanField(vararg values: String?): Boolean {
        return values.any { v ->
            v != null && (v == "1" || v.equals("true", true))
        }
    }

    internal fun parseIntField(vararg values: String?): Int? {
        return values.firstNotNullOfOrNull { it?.trim()?.toIntOrNull() }
    }

    internal fun parseShadowsocksPlugin(value: String?): Pair<String?, String?> {
        val normalized = value?.trim()?.takeIf { it.isNotEmpty() } ?: return null to null
        val parts = normalized.split(';', limit = 2)
        val plugin = parts.firstOrNull()?.trim()?.takeIf { it.isNotEmpty() }
        val options = parts.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
        return plugin to options
    }

}
