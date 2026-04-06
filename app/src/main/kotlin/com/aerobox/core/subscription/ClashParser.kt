package com.aerobox.core.subscription

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/**
 * Clash/Clash Meta YAML parser.
 * Only reads the `proxies:` list and maps each node into the app's internal model.
 */
object ClashParser {
    private val supportedTransportTypes get() = SubscriptionParser.supportedTransportTypes

    data class ClashParseResult(
        val nodes: List<ProxyNode>,
        val diagnostics: ParseDiagnostics = ParseDiagnostics()
    )

    fun parseClashYamlDetailed(content: String): ClashParseResult {
        val root = loadYamlRoot(content) ?: return ClashParseResult(
            nodes = emptyList(),
            diagnostics = ParseDiagnostics().withIgnored("invalid_clash_yaml")
        )
        val proxies = value(root, "proxies") as? List<*>
            ?: return ClashParseResult(
                nodes = emptyList(),
                diagnostics = ParseDiagnostics().withIgnored("missing_clash_proxies")
            )
        val nodes = mutableListOf<ProxyNode>()
        var diagnostics = ParseDiagnostics()
        proxies.forEach { item ->
            when (val result = parseProxyItemDetailed(item as? Map<*, *>)) {
                is ProxyParseResult.Success -> nodes += result.node
                is ProxyParseResult.Ignored -> diagnostics = diagnostics.withIgnored(result.reason)
            }
        }
        return ClashParseResult(nodes = nodes, diagnostics = diagnostics)
    }

    fun isClashYaml(content: String): Boolean {
        if (!content.contains("proxies:")) return false
        val root = loadYamlRoot(content) ?: return false
        val proxies = value(root, "proxies") as? List<*> ?: return false
        return proxies.any { item ->
            val proxy = item as? Map<*, *> ?: return@any false
            stringValue(proxy, "name") != null &&
                (stringValue(proxy, "type") != null || stringValue(proxy, "server") != null)
        }
    }


    private fun loadYamlRoot(content: String): Any? {
        return runCatching {
            val options = LoaderOptions().apply {
                maxAliasesForCollections = 50
                codePointLimit = 8 * 1024 * 1024 // 8 MB limit
            }
            Yaml(SafeConstructor(options)).load<Any?>(content)
        }.getOrNull()
    }
    private sealed interface ProxyParseResult {
        data class Success(val node: ProxyNode) : ProxyParseResult
        data class Ignored(val reason: String) : ProxyParseResult
    }

    private fun parseProxyItemDetailed(map: Map<*, *>?): ProxyParseResult {
        if (map.isNullOrEmpty()) return ProxyParseResult.Ignored("invalid_clash_proxy_item")

        val name = stringValue(map, "name")
            ?: return ProxyParseResult.Ignored("missing_clash_name")
        val typeStr = stringValue(map, "type")?.lowercase()
            ?: return ProxyParseResult.Ignored("missing_clash_type")
        val server = stringValue(map, "server")
            ?: return ProxyParseResult.Ignored("missing_clash_endpoint")
        val port = intValue(map, "port")
            ?: return ProxyParseResult.Ignored("missing_clash_endpoint")

        val type = when (typeStr) {
            "ss", "shadowsocks" -> {
                val method = firstNonBlank(
                    stringValue(map, "cipher"),
                    stringValue(map, "method")
                ).orEmpty()
                if (method.startsWith("2022-")) ProxyType.SHADOWSOCKS_2022 else ProxyType.SHADOWSOCKS
            }
            "vmess" -> ProxyType.VMESS
            "vless" -> ProxyType.VLESS
            "trojan" -> ProxyType.TROJAN
            "hysteria2", "hy2" -> ProxyType.HYSTERIA2
            "tuic" -> ProxyType.TUIC
            "socks", "socks5" -> ProxyType.SOCKS
            "http", "https" -> ProxyType.HTTP
            else -> return ProxyParseResult.Ignored("unsupported_clash_type")
        }
        val hasRealityKey = !stringValue(map, "reality-opts", "public-key").isNullOrBlank() ||
            !stringValue(map, "reality-opts", "public_key").isNullOrBlank() ||
            !stringValue(map, "public-key").isNullOrBlank() ||
            !stringValue(map, "pbk").isNullOrBlank()
        val security = firstNonBlank(
            stringValue(map, "security"),
            if (hasRealityKey) "reality" else null
        )

        val tls = when {
            type == ProxyType.TROJAN || type == ProxyType.HYSTERIA2 || type == ProxyType.TUIC -> true
            typeStr == "https" -> true
            booleanValue(map, "tls") == true -> true
            security?.lowercase() in listOf("tls", "reality") -> true
            else -> false
        }

        val network = firstNonBlank(
            stringValue(map, "network"),
            stringValue(map, "net")
        ) ?: when {
            hasValue(map, "ws-opts", "path") || hasValue(map, "ws-opts", "headers", "Host") || hasValue(map, "ws-path") -> "ws"
            hasValue(map, "grpc-opts", "grpc-service-name") || hasValue(map, "grpc-service-name") -> "grpc"
            hasValue(map, "h2-opts", "path") || hasValue(map, "h2-opts", "host") -> "h2"
            hasValue(map, "http-opts", "path") || hasValue(map, "http-opts", "host") || hasValue(map, "http-opts", "headers", "Host") -> "http"
            hasValue(map, "http-upgrade-path") || hasValue(map, "http-upgrade-host") -> "httpupgrade"
            else -> null
        }
        val transportType = resolveTransportType(network)
        if (network != null && network.lowercase() != "tcp" && transportType == null) {
            return ProxyParseResult.Ignored("unsupported_clash_transport")
        }
        val wsOpts = value(map, "ws-opts")
        val smux = value(map, "smux")
        val udpOverTcp = parseUdpOverTcp(
            firstNonNullValue(
                value(map, "udp-over-tcp"),
                value(map, "udp_over_tcp"),
                value(map, "uot")
            )
        )
        val transportPath = firstNonBlank(
            stringValue(map, "ws-opts", "path"),
            stringValue(map, "ws-path"),
            stringValue(map, "h2-opts", "path"),
            stringValue(map, "http-opts", "path"),
            stringValue(map, "http-upgrade-path"),
            stringValue(map, "path")
        )
        val transportHost = firstNonBlank(
            joinedValue(map, "ws-opts", "headers", "Host"),
            joinedValue(map, "ws-opts", "headers", "host"),
            joinedValue(map, "ws-opts", "host"),
            joinedValue(map, "h2-opts", "host"),
            joinedValue(map, "http-opts", "host"),
            joinedValue(map, "http-opts", "headers", "Host"),
            joinedValue(map, "http-opts", "headers", "host"),
            joinedValue(map, "http-upgrade-host"),
            joinedValue(map, "host")
        )
        val transportServiceName = firstNonBlank(
            stringValue(map, "grpc-opts", "grpc-service-name"),
            stringValue(map, "grpc-opts", "service-name"),
            stringValue(map, "grpc-opts", "serviceName"),
            stringValue(map, "grpc-service-name"),
            stringValue(map, "service-name"),
            stringValue(map, "serviceName"),
            if (transportType == "grpc") transportPath else null
        )

        val insecure = booleanValue(map, "skip-cert-verify") == true
                || booleanValue(map, "allow-insecure") == true
                || booleanValue(map, "insecure") == true

        val fingerprint = firstNonBlank(
            stringValue(map, "fingerprint"),
            stringValue(map, "client-fingerprint"),
            stringValue(map, "global-client-fingerprint")
        )

        val publicKey = firstNonBlank(
            stringValue(map, "public-key"),
            stringValue(map, "pbk"),
            stringValue(map, "reality-opts", "public-key"),
            stringValue(map, "reality-opts", "public_key")
        )

        val shortId = firstNonBlank(
            stringValue(map, "short-id"),
            stringValue(map, "sid"),
            stringValue(map, "reality-opts", "short-id"),
            stringValue(map, "reality-opts", "short_id"),
            stringValue(map, "reality-opts", "shortid")
        )

        return ProxyParseResult.Success(
            ProxyNode(
            name = name,
            type = type,
            server = server,
            port = port,
            bindInterface = firstNonBlank(
                stringValue(map, "interface-name"),
                stringValue(map, "interface_name")
            ),
            connectTimeout = firstNonBlank(
                stringValue(map, "connect-timeout"),
                stringValue(map, "connect_timeout")
            ),
            tcpFastOpen = booleanValue(map, "tfo"),
            udpFragment = booleanValue(map, "udp-fragment") ?: booleanValue(map, "udp_fragment"),
            uuid = firstNonBlank(stringValue(map, "uuid"), stringValue(map, "id")),
            alterId = intValue(map, "alterId") ?: intValue(map, "alter_id") ?: intValue(map, "aid") ?: 0,
            password = firstNonBlank(
                stringValue(map, "password"),
                stringValue(map, "passwd"),
                stringValue(map, "auth"),
                stringValue(map, "token")
            ),
            method = firstNonBlank(stringValue(map, "cipher"), stringValue(map, "method")),
            flow = stringValue(map, "flow"),
            security = security,
            transportType = transportType,
            tls = tls,
            sni = firstNonBlank(
                stringValue(map, "sni"),
                stringValue(map, "servername"),
                stringValue(map, "server-name")
            ),
            transportHost = transportHost,
            transportPath = if (transportType == "grpc") null else transportPath,
            transportServiceName = transportServiceName,
            wsMaxEarlyData = intValue(wsOpts, "max-early-data") ?: intValue(wsOpts, "max_early_data"),
            wsEarlyDataHeaderName = firstNonBlank(
                stringValue(wsOpts, "early-data-header-name"),
                stringValue(wsOpts, "early_data_header_name")
            ),
            alpn = joinedValue(map, "alpn"),
            fingerprint = fingerprint,
            publicKey = publicKey,
            shortId = shortId,
            packetEncoding = firstNonBlank(
                stringValue(map, "packet-encoding"),
                stringValue(map, "packet_encoding")
            ),
            username = stringValue(map, "username"),
            socksVersion = stringValue(map, "version"),
            allowInsecure = insecure,
            plugin = stringValue(map, "plugin"),
            pluginOpts = firstNonBlank(
                pluginOptionsValue(value(map, "plugin-opts")),
                pluginOptionsValue(value(map, "plugin_opts"))
            ),
            udpOverTcpEnabled = udpOverTcp.first,
            udpOverTcpVersion = udpOverTcp.second,
            obfsType = stringValue(map, "obfs"),
            obfsPassword = firstNonBlank(
                stringValue(map, "obfs-password"),
                stringValue(map, "obfs_password")
            ),
            serverPorts = firstNonBlank(
                joinedValue(map, "server-ports"),
                joinedValue(map, "server_ports"),
                joinedValue(map, "ports"),
                stringValue(map, "mport")
            ),
            hopInterval = firstNonBlank(
                stringValue(map, "hop-interval"),
                stringValue(map, "hop_interval")
            ),
            upMbps = intValue(map, "up-mbps") ?: intValue(map, "up_mbps"),
            downMbps = intValue(map, "down-mbps") ?: intValue(map, "down_mbps"),
            muxEnabled = booleanValue(smux, "enabled"),
            congestionControl = firstNonBlank(
                stringValue(map, "congestion-controller"),
                stringValue(map, "congestion_control"),
                stringValue(map, "congestion-control")
            ),
            udpRelayMode = firstNonBlank(
                stringValue(map, "udp-relay-mode"),
                stringValue(map, "udp_relay_mode")
            ),
            udpOverStream = booleanValue(map, "udp-over-stream") ?: booleanValue(map, "udp_over_stream")
            )
        )
    }

    private fun value(source: Any?, vararg path: String): Any? {
        var current: Any? = source
        for (segment in path) {
            val map = current as? Map<*, *> ?: return null
            current = map.entries.firstOrNull { entry ->
                entry.key?.toString()?.equals(segment, ignoreCase = true) == true
            }?.value
        }
        return current
    }

    private fun hasValue(source: Any?, vararg path: String): Boolean {
        return value(source, *path) != null
    }

    private fun firstNonNullValue(vararg values: Any?): Any? {
        return values.firstOrNull { it != null }
    }

    private fun stringValue(source: Any?, vararg path: String): String? {
        return scalarString(value(source, *path))
    }

    private fun joinedValue(source: Any?, vararg path: String): String? {
        val resolved = value(source, *path)
        val parts = when (resolved) {
            is List<*> -> resolved.mapNotNull { scalarString(it) }
            else -> listOfNotNull(scalarString(resolved))
        }
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(",")
    }

    private fun intValue(source: Any?, vararg path: String): Int? {
        val resolved = value(source, *path) ?: return null
        return when (resolved) {
            is Number -> resolved.toInt()
            else -> resolved.toString().trim().toIntOrNull()
        }
    }

    private fun booleanValue(source: Any?, vararg path: String): Boolean? {
        val resolved = value(source, *path) ?: return null
        return when (resolved) {
            is Boolean -> resolved
            is Number -> resolved.toInt() != 0
            is String -> when (resolved.trim().lowercase()) {
                "true", "yes", "on", "1" -> true
                "false", "no", "off", "0" -> false
                else -> null
            }
            else -> null
        }
    }

    private fun scalarString(value: Any?): String? {
        return when (value) {
            null -> null
            is String -> value.trim().takeIf { it.isNotEmpty() }
            is Number, is Boolean -> value.toString()
            else -> null
        }
    }

    private fun normalizeTransportType(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotBlank() } ?: return null
        return when (normalized) {
            "websocket" -> "ws"
            "http-upgrade" -> "httpupgrade"
            else -> normalized
        }
    }

    private fun resolveTransportType(rawNetwork: String?): String? {
        val normalized = normalizeTransportType(rawNetwork) ?: return null
        if (normalized == "tcp") return null
        return normalized.takeIf { it in supportedTransportTypes }
    }

    private fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun pluginOptionsValue(value: Any?): String? {
        return when (value) {
            null -> null
            is String -> value.trim().takeIf { it.isNotEmpty() }
            is Map<*, *> -> value.entries
                .mapNotNull { (key, raw) ->
                    val optionKey = key?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                    val optionValue = raw?.toString()?.trim().orEmpty()
                    if (optionValue.isEmpty()) optionKey else "$optionKey=$optionValue"
                }
                .takeIf { it.isNotEmpty() }
                ?.joinToString(";")
            else -> value.toString().trim().takeIf { it.isNotEmpty() }
        }
    }

    private fun parseUdpOverTcp(value: Any?): Pair<Boolean?, Int?> = parseUdpOverTcpValue(value)
}
