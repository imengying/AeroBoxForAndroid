package com.aerobox.core.config

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.effectiveEnabledNetwork
import com.aerobox.data.model.effectiveTransportType
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds the proxy outbound JSON for a sing-box configuration.
 *
 * Extracted from [ConfigGenerator] for readability — all methods are
 * package-private and called exclusively by the generator.
 */
internal object OutboundConfigBuilder {

    fun buildProxyOutbound(node: ProxyNode): JSONObject {
        validateTlsServerNameRequirements(node)
        val cleanServer = ConfigGenerator.normalizeOutboundServer(node.server)
        if (cleanServer.isBlank()) {
            throw IllegalArgumentException("节点服务器地址为空")
        }
        val enabledNetwork = node.effectiveEnabledNetwork()
        val transportType = node.effectiveTransportType()
        val outbound = JSONObject()
            .put("server", cleanServer)
            .put("server_port", node.port)

        when (node.type) {
            ProxyType.SHADOWSOCKS,
            ProxyType.SHADOWSOCKS_2022 -> {
                outbound.put("type", "shadowsocks")
                outbound.put("method", node.method ?: "aes-128-gcm")
                node.password?.takeIf { it.isNotBlank() }?.let { outbound.put("password", it) }
                node.plugin?.takeIf { it.isNotBlank() }?.let { outbound.put("plugin", it) }
                node.pluginOpts?.takeIf { it.isNotBlank() }?.let { outbound.put("plugin_opts", it) }
                enabledNetwork?.let { outbound.put("network", it) }
                buildUdpOverTcp(node.udpOverTcpEnabled, node.udpOverTcpVersion)?.let {
                    outbound.put("udp_over_tcp", it)
                }
            }

            ProxyType.VMESS -> {
                outbound.put("type", "vmess")
                node.uuid?.takeIf { it.isNotBlank() }?.let { outbound.put("uuid", it) }
                outbound.put("security", node.security ?: "auto")
                outbound.put("alter_id", node.alterId)
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node))
                enabledNetwork?.let { outbound.put("network", it) }
            }

            ProxyType.VLESS -> {
                outbound.put("type", "vless")
                node.uuid?.takeIf { it.isNotBlank() }?.let { outbound.put("uuid", it) }
                node.flow?.takeIf { it.isNotBlank() }?.let { outbound.put("flow", it) }
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node, includeReality = true))
                enabledNetwork?.let { outbound.put("network", it) }
            }

            ProxyType.TROJAN -> {
                outbound.put("type", "trojan")
                node.password?.takeIf { it.isNotBlank() }?.let { outbound.put("password", it) }
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node, includeReality = true))
                enabledNetwork?.let { outbound.put("network", it) }
            }

            ProxyType.HYSTERIA2 -> {
                outbound.put("type", "hysteria2")
                node.password?.takeIf { it.isNotBlank() }?.let { outbound.put("password", it) }
                outbound.put("tls", buildTlsObject(node))
                enabledNetwork?.let { outbound.put("network", it) }
                if (!node.obfsType.isNullOrBlank()) {
                    val obfs = JSONObject()
                        .put("type", node.obfsType)
                    node.obfsPassword?.takeIf { it.isNotBlank() }?.let { obfs.put("password", it) }
                    outbound.put("obfs", obfs)
                }
                normalizedHysteriaServerPorts(node.serverPorts)
                    .takeIf { it.isNotEmpty() }
                    ?.let { ports ->
                        outbound.remove("server_port")
                        val portArray = JSONArray()
                        ports.forEach { portArray.put(it) }
                        outbound.put("server_ports", portArray)
                    }
                node.hopInterval
                    ?.takeIf { it.isNotBlank() }
                    ?.let(::normalizeHysteriaHopInterval)
                    ?.let { outbound.put("hop_interval", it) }
                node.upMbps?.takeIf { it > 0 }?.let { outbound.put("up_mbps", it) }
                node.downMbps?.takeIf { it > 0 }?.let { outbound.put("down_mbps", it) }
            }

            ProxyType.TUIC -> {
                outbound.put("type", "tuic")
                node.uuid?.takeIf { it.isNotBlank() }?.let { outbound.put("uuid", it) }
                node.password?.takeIf { it.isNotBlank() }?.let { outbound.put("password", it) }
                node.congestionControl?.takeIf { it.isNotBlank() }?.let { outbound.put("congestion_control", it) }
                node.udpRelayMode?.takeIf { it.isNotBlank() }?.let { outbound.put("udp_relay_mode", it) }
                node.udpOverStream?.let { outbound.put("udp_over_stream", it) }
                outbound.put("tls", buildTlsObject(node))
                enabledNetwork?.let { outbound.put("network", it) }
            }

            ProxyType.NAIVE -> {
                outbound.put("type", "naive")
                node.username?.takeIf { it.isNotBlank() }?.let { outbound.put("username", it) }
                node.password?.takeIf { it.isNotBlank() }?.let { outbound.put("password", it) }
                outbound.put("tls", buildNaiveTlsObject(node))
                enabledNetwork?.let { outbound.put("network", it) }
                if (node.naiveProtocol.equals("quic", ignoreCase = true) || node.transportType.equals("quic", ignoreCase = true)) {
                    outbound.put("quic", true)
                    node.congestionControl?.takeIf { it.isNotBlank() }?.let {
                        outbound.put("quic_congestion_control", it)
                    }
                }
                node.naiveInsecureConcurrency?.takeIf { it > 0 }?.let {
                    outbound.put("insecure_concurrency", it)
                }
                buildNaiveExtraHeaders(node.naiveExtraHeaders)?.let { outbound.put("extra_headers", it) }
                buildUdpOverTcp(node.udpOverTcpEnabled, node.udpOverTcpVersion)?.let {
                    outbound.put("udp_over_tcp", it)
                }
            }

            ProxyType.SOCKS -> {
                outbound.put("type", "socks")
                node.username?.let { outbound.put("username", it) }
                node.password?.let { outbound.put("password", it) }
                node.socksVersion?.takeIf { it == "5" }?.let { outbound.put("version", it) }
                enabledNetwork?.let { outbound.put("network", it) }
                buildUdpOverTcp(node.udpOverTcpEnabled, node.udpOverTcpVersion)?.let {
                    outbound.put("udp_over_tcp", it)
                }
            }

            ProxyType.HTTP -> {
                outbound.put("type", "http")
                node.username?.let { outbound.put("username", it) }
                node.password?.let { outbound.put("password", it) }
                if (node.tls) {
                    outbound.put("tls", buildTlsObject(node))
                }
                normalizedTransportPath(node.transportPath)?.let { outbound.put("path", it) }
                mergeHeaderJson(node.transportHost)?.let { headers ->
                    outbound.put("headers", headers)
                }
            }
        }

        applyDialFields(outbound, node)
        transportType?.takeIf {
            node.type == ProxyType.VMESS ||
                node.type == ProxyType.VLESS ||
                node.type == ProxyType.TROJAN
        }?.let {
            outbound.put("transport", buildTransport(node, it))
        }
        applyMultiplex(outbound, node)
        if (!outbound.has("domain_resolver") && !ConfigGenerator.isIpLiteral(cleanServer)) {
            // Resolve only the proxy server address locally. Applying a global
            // address strategy here would also resolve destination domains and
            // break DNS64/NAT64 setups on IPv6-only servers.
            outbound.put(
                "domain_resolver",
                JSONObject()
                    .put("server", ConfigGenerator.DNS_DIRECT_TAG)
                    .put("strategy", "prefer_ipv4")
            )
        }
        return outbound
    }

    // ── Private helpers ──────────────────────────────────────────────

    private fun validateTlsServerNameRequirements(node: ProxyNode) {
        val cleanServer = ConfigGenerator.normalizeOutboundServer(node.server)
        val usesReality = !node.publicKey.isNullOrBlank()
        if (usesReality && ConfigGenerator.isIpLiteral(cleanServer) && node.sni.isNullOrBlank()) {
            throw IllegalArgumentException("Reality 节点使用 IP 地址时必须显式填写 SNI")
        }
    }

    private fun applyDialFields(outbound: JSONObject, node: ProxyNode) {
        node.bindInterface?.takeIf { it.isNotBlank() }?.let { outbound.put("bind_interface", it) }
        node.connectTimeout?.takeIf { it.isNotBlank() }?.let { outbound.put("connect_timeout", it) }
        node.tcpFastOpen?.let { outbound.put("tcp_fast_open", it) }
        node.udpFragment?.let { outbound.put("udp_fragment", it) }
    }

    private fun applyMultiplex(outbound: JSONObject, node: ProxyNode) {
        val enabled = node.muxEnabled ?: return

        val multiplex = JSONObject()
        multiplex.put("enabled", enabled)
        outbound.put("multiplex", multiplex)
    }

    private fun buildNaiveTlsObject(node: ProxyNode): JSONObject {
        val tls = JSONObject()
            .put("enabled", true)
        node.sni?.takeIf { it.isNotBlank() }?.let { tls.put("server_name", it) }
        node.naiveCertificate?.takeIf { it.isNotBlank() }?.let { tls.put("certificate", it) }
        node.naiveCertificatePath?.takeIf { it.isNotBlank() }?.let { tls.put("certificate_path", it) }
        buildNaiveEchObject(node)?.let { tls.put("ech", it) }
        return tls
    }

    private fun buildNaiveEchObject(node: ProxyNode): JSONObject? {
        val config = node.naiveEchConfig?.trim()?.takeIf { it.isNotEmpty() }
        val configPath = node.naiveEchConfigPath?.trim()?.takeIf { it.isNotEmpty() }
        val queryServerName = node.naiveEchQueryServerName?.trim()?.takeIf { it.isNotEmpty() }
        if (node.naiveEchEnabled == null && config == null && configPath == null && queryServerName == null) {
            return null
        }

        val ech = JSONObject()
            .put("enabled", node.naiveEchEnabled ?: true)
        config?.let { ech.put("config", it) }
        configPath?.let { ech.put("config_path", it) }
        queryServerName?.let { ech.put("query_server_name", it) }
        return ech
    }

    private fun buildNaiveExtraHeaders(raw: String?): JSONObject? {
        val value = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (value.startsWith("{")) {
            return runCatching { JSONObject(value) }
                .getOrNull()
                ?.takeIf { it.length() > 0 }
        }

        val headers = JSONObject()
        value
            .replace("\r\n", "\n")
            .replace('\r', '\n')
            .split('\n', ';')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { entry ->
                val separator = listOf(entry.indexOf(':'), entry.indexOf('='))
                    .filter { it > 0 }
                    .minOrNull()
                    ?: return@forEach
                val key = entry.substring(0, separator).trim()
                val headerValue = entry.substring(separator + 1).trim()
                if (key.isNotEmpty() && headerValue.isNotEmpty()) {
                    headers.put(key, headerValue)
                }
            }
        return headers.takeIf { it.length() > 0 }
    }

    private fun buildTlsObject(node: ProxyNode, includeReality: Boolean = false): JSONObject {
        // Force TLS enabled when Reality is in use — Reality requires TLS.
        val effectiveTls = node.tls || (includeReality && !node.publicKey.isNullOrBlank())
        val tls = JSONObject()
            .put("enabled", effectiveTls)
        if (node.allowInsecure) {
            tls.put("insecure", true)
        }
        val sniToUse = node.sni?.takeIf { it.isNotBlank() } ?: if (includeReality) node.server else null
        sniToUse?.let { tls.put("server_name", it) }

        val alpn = node.alpn
        if (!alpn.isNullOrBlank()) {
            val alpnArray = JSONArray()
            alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { alpnArray.put(it) }
            if (alpnArray.length() > 0) {
                tls.put("alpn", alpnArray)
            }
        }

        if (includeReality && !node.publicKey.isNullOrBlank()) {
            val realityObj = JSONObject()
                .put("enabled", true)
                .put("public_key", node.publicKey)
            if (!node.shortId.isNullOrBlank()) {
                realityObj.put("short_id", node.shortId)
            }
            tls.put("reality", realityObj)
        }

        if (!node.fingerprint.isNullOrBlank()) {
            tls.put(
                "utls",
                JSONObject()
                    .put("enabled", true)
                    .put("fingerprint", node.fingerprint)
            )
        }

        return tls
    }

    // ── Transport ───────────────────────────────────────────────────

    private fun buildTransport(node: ProxyNode, transportType: String): JSONObject {
        val transport = JSONObject()
        when (transportType.lowercase()) {
            "ws", "websocket" -> {
                transport.put("type", "ws")
                normalizedTransportPath(node.transportPath)?.let { transport.put("path", it) }
                mergeHeaderJson(firstTransportHost(node))?.let {
                    transport.put("headers", it)
                }
                node.wsMaxEarlyData?.let { transport.put("max_early_data", it) }
                node.wsEarlyDataHeaderName?.takeIf { it.isNotBlank() }?.let {
                    transport.put("early_data_header_name", it)
                }
            }
            "grpc" -> {
                transport.put("type", "grpc")
                node.transportServiceName?.takeIf { it.isNotBlank() }?.let {
                    transport.put("service_name", it)
                }
            }
            "h2", "http" -> {
                transport.put("type", "http")
                normalizedTransportPath(node.transportPath)?.let { transport.put("path", it) }
                firstTransportHost(node)?.let { hostValue ->
                    val hostArray = JSONArray()
                    hostValue.split(",")
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .forEach { hostArray.put(it) }
                    if (hostArray.length() > 0) {
                        transport.put("host", hostArray)
                    }
                }
            }
            "httpupgrade", "http-upgrade" -> {
                transport.put("type", "httpupgrade")
                normalizedTransportPath(node.transportPath)?.let { transport.put("path", it) }
                firstTransportHost(node)?.let { transport.put("host", it) }
            }
            "quic" -> {
                transport.put("type", "quic")
            }
        }
        return transport
    }

    private fun buildUdpOverTcp(enabled: Boolean?, version: Int?): Any? {
        if (enabled == null && version == null) return null
        if (version != null) {
            return JSONObject()
                .put("enabled", enabled ?: true)
                .put("version", version)
        }
        return enabled
    }

    private fun normalizedHysteriaServerPorts(serverPorts: String?): List<String> {
        return serverPorts
            ?.split(",")
            ?.mapNotNull(::normalizeHysteriaServerPortEntry)
            .orEmpty()
    }

    private fun normalizeHysteriaServerPortEntry(entry: String): String? {
        val trimmed = entry.trim()
        if (trimmed.isEmpty()) return null

        val dashRange = Regex("""^(\d{1,5})\s*-\s*(\d{1,5})$""").matchEntire(trimmed)
        if (dashRange != null) {
            val start = dashRange.groupValues[1]
            val end = dashRange.groupValues[2]
            return "$start:$end"
        }

        return trimmed.replace(" ", "")
    }

    private fun normalizeHysteriaHopInterval(value: String): String {
        val trimmed = value.trim()
        return if (Regex("""^\d+$""").matches(trimmed)) "${trimmed}s" else trimmed
    }

    private fun mergeHeaderJson(host: String?): JSONObject? {
        val headers = JSONObject()
        host?.takeIf { it.isNotBlank() }?.let { headers.put("Host", it) }
        return headers.takeIf { it.length() > 0 }
    }

    private fun firstTransportHost(node: ProxyNode): String? {
        return node.transportHost?.takeIf { it.isNotBlank() }
            ?: node.sni?.takeIf { it.isNotBlank() }
    }

    private fun normalizedTransportPath(path: String?): String? {
        val value = path?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return if (value.startsWith("/")) value else "/$value"
    }
}
