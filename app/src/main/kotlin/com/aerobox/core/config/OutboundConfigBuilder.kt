package com.aerobox.core.config

import com.aerobox.R
import com.aerobox.core.errors.LocalizedException
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
            throw LocalizedException.of(R.string.error_node_server_empty)
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
                if (!hasShadowTlsCompanion(node)) {
                    // sing-box doesn't accept plugin=shadow-tls on the SS outbound;
                    // the handshake is emitted as a separate `shadowtls` outbound
                    // (see buildShadowTlsCompanion) and chained via `detour`.
                    node.plugin?.takeIf { it.isNotBlank() }?.let { outbound.put("plugin", it) }
                    node.pluginOpts?.takeIf { it.isNotBlank() }?.let { outbound.put("plugin_opts", it) }
                }
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
        if (supportsMultiplex(node) && !outbound.has("udp_over_tcp")) {
            applyMultiplex(outbound, node)
        }
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
            throw LocalizedException.of(R.string.error_reality_requires_sni)
        }
    }

    /**
     * Whether the given node should be paired with a sibling `shadowtls`
     * outbound. True when the user imported a Shadowsocks node that originally
     * carried a `shadow-tls` plugin in its Clash / SS-URI form.
     */
    internal fun hasShadowTlsCompanion(node: ProxyNode): Boolean {
        if (node.type != ProxyType.SHADOWSOCKS && node.type != ProxyType.SHADOWSOCKS_2022) {
            return false
        }
        return !node.shadowTlsPassword.isNullOrBlank() ||
            !node.shadowTlsServerName.isNullOrBlank() ||
            (node.shadowTlsVersion != null && node.shadowTlsVersion > 0)
    }

    /**
     * Build the companion `shadowtls` outbound that performs the TLS-style
     * handshake on behalf of the paired Shadowsocks outbound. Returns null
     * when the node does not use ShadowTLS.
     *
     * The caller is responsible for adding `"detour": companion.tag` to the
     * primary SS outbound — see [ConfigGenerator.generateSingBoxConfig].
     */
    internal fun buildShadowTlsCompanion(node: ProxyNode, primaryTag: String): JSONObject? {
        if (!hasShadowTlsCompanion(node)) return null
        val cleanServer = ConfigGenerator.normalizeOutboundServer(node.server)
        if (cleanServer.isBlank()) return null

        val tag = "$primaryTag-shadowtls"
        val outbound = JSONObject()
            .put("type", "shadowtls")
            .put("tag", tag)
            .put("server", cleanServer)
            .put("server_port", node.port)
        // sing-box supports ShadowTLS v1/v2/v3; default to v3 (most common).
        outbound.put(
            "version",
            node.shadowTlsVersion?.takeIf { it in 1..3 } ?: 3
        )
        node.shadowTlsPassword
            ?.takeIf { it.isNotBlank() }
            ?.let { outbound.put("password", it) }

        val tls = JSONObject().put("enabled", true)
        val sni = node.shadowTlsServerName?.takeIf { it.isNotBlank() }
            ?: node.sni?.takeIf { it.isNotBlank() }
        sni?.let { tls.put("server_name", it) }

        val alpnSource = node.shadowTlsAlpn?.takeIf { it.isNotBlank() }
            ?: node.alpn?.takeIf { it.isNotBlank() }
        if (alpnSource != null) {
            val alpnArray = JSONArray()
            alpnSource.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                .forEach { alpnArray.put(it) }
            if (alpnArray.length() > 0) tls.put("alpn", alpnArray)
        }
        if (node.allowInsecure) tls.put("insecure", true)
        if (!node.fingerprint.isNullOrBlank()) {
            tls.put(
                "utls",
                JSONObject()
                    .put("enabled", true)
                    .put("fingerprint", node.fingerprint)
            )
        }
        outbound.put("tls", tls)
        return outbound
    }

    private fun applyDialFields(outbound: JSONObject, node: ProxyNode) {
        node.bindInterface?.takeIf { it.isNotBlank() }?.let { outbound.put("bind_interface", it) }
        node.connectTimeout?.takeIf { it.isNotBlank() }?.let { outbound.put("connect_timeout", it) }
        node.tcpFastOpen?.let { outbound.put("tcp_fast_open", it) }
        node.udpFragment?.let { outbound.put("udp_fragment", it) }
        // sing-box 1.13 dial-level TCP keep-alive triplet. All optional;
        // omitting a key falls back to sing-box's defaults (5m initial /
        // 75s interval, keep-alive on).
        node.disableTcpKeepAlive?.let { outbound.put("disable_tcp_keep_alive", it) }
        node.tcpKeepAlive?.takeIf { it.isNotBlank() }?.let { outbound.put("tcp_keep_alive", it) }
        node.tcpKeepAliveInterval
            ?.takeIf { it.isNotBlank() }
            ?.let { outbound.put("tcp_keep_alive_interval", it) }
    }

    private fun applyMultiplex(outbound: JSONObject, node: ProxyNode) {
        val enabled = node.muxEnabled ?: return

        val multiplex = JSONObject()
        multiplex.put("enabled", enabled)
        // sing-box accepts smux / yamux / h2mux. Anything else is silently
        // ignored so passing through unrecognised values is safe, but we
        // still gate-check to avoid emitting noise into the config.
        node.muxProtocol
            ?.trim()
            ?.lowercase()
            ?.takeIf { it in setOf("smux", "yamux", "h2mux") }
            ?.let { multiplex.put("protocol", it) }
        node.muxMaxConnections?.takeIf { it > 0 }?.let { multiplex.put("max_connections", it) }
        node.muxMinStreams?.takeIf { it > 0 }?.let { multiplex.put("min_streams", it) }
        node.muxMaxStreams?.takeIf { it > 0 }?.let { multiplex.put("max_streams", it) }
        node.muxPadding?.let { multiplex.put("padding", it) }

        // TCP Brutal — only emit when we have at least one bandwidth limit;
        // sing-box requires both up_mbps and down_mbps when brutal is on, so
        // missing values fall back to a permissive 1 Gbps.
        if (node.muxBrutalEnabled == true ||
            (node.muxBrutalUpMbps != null && node.muxBrutalUpMbps > 0) ||
            (node.muxBrutalDownMbps != null && node.muxBrutalDownMbps > 0)
        ) {
            val brutal = JSONObject()
                .put("enabled", node.muxBrutalEnabled ?: true)
                .put("up_mbps", node.muxBrutalUpMbps?.takeIf { it > 0 } ?: 1000)
                .put("down_mbps", node.muxBrutalDownMbps?.takeIf { it > 0 } ?: 1000)
            multiplex.put("brutal", brutal)
        }

        outbound.put("multiplex", multiplex)
    }

    private fun supportsMultiplex(node: ProxyNode): Boolean {
        return when (node.type) {
            ProxyType.SHADOWSOCKS,
            ProxyType.SHADOWSOCKS_2022,
            ProxyType.VMESS,
            ProxyType.VLESS,
            ProxyType.TROJAN -> true
            ProxyType.HYSTERIA2,
            ProxyType.TUIC,
            ProxyType.NAIVE,
            ProxyType.SOCKS,
            ProxyType.HTTP -> false
        }
    }

    private fun buildNaiveTlsObject(node: ProxyNode): JSONObject {
        val tls = JSONObject()
        node.sni?.takeIf { it.isNotBlank() }?.let { tls.put("server_name", it) }
        node.naiveCertificate?.takeIf { it.isNotBlank() }?.let { tls.put("certificate", it) }
        node.naiveCertificatePath?.takeIf { it.isNotBlank() }?.let { tls.put("certificate_path", it) }
        buildEchObject(node)?.let { tls.put("ech", it) }
        return tls
    }

    /**
     * Build the `tls.ech` sub-object for any TLS-bearing outbound.
     *
     * The backing fields keep their historical `naive*` prefix to avoid a
     * Room schema migration, but ECH (Encrypted Client Hello) is a generic
     * TLS feature in sing-box and applies equally to VMess/VLESS/Trojan/
     * Hysteria2/TUIC/HTTP/Naive when their server advertises an ECHConfig.
     */
    private fun buildEchObject(node: ProxyNode): JSONObject? {
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

        // ECH applies to any TLS-bearing outbound, not just NaiveProxy.
        buildEchObject(node)?.let { tls.put("ech", it) }

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
