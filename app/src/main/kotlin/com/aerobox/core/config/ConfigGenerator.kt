package com.aerobox.core.config

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.RoutingMode
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

object ConfigGenerator {

    private data class DnsServerSpec(
        val type: String,
        val server: String,
        val serverPort: Int,
        val path: String? = null
    )

    fun generateSingBoxConfig(
        node: ProxyNode,
        routingMode: RoutingMode = RoutingMode.RULE_BASED,
        remoteDns: String = "8.8.8.8",
        localDns: String = "223.5.5.5",
        enableDoh: Boolean = true,
        enableSocksInbound: Boolean = false,
        enableHttpInbound: Boolean = false,
        enableIPv6: Boolean = true,
        enableGeoCnDomainRule: Boolean = true,
        enableGeoCnIpRule: Boolean = true,
        enableGeoAdsBlock: Boolean = true,
        enableGeoBlockQuic: Boolean = true,
        geoIpCnRuleSetPath: String? = null,
        geoSiteCnRuleSetPath: String? = null,
        geoSiteAdsRuleSetPath: String? = null
    ): String {
        val config = JSONObject()
        val hasGeoSiteCn = !geoSiteCnRuleSetPath.isNullOrBlank()
        val hasGeoIpCn = !geoIpCnRuleSetPath.isNullOrBlank()
        val hasGeoAds = !geoSiteAdsRuleSetPath.isNullOrBlank()

        config.put(
            "log",
            JSONObject()
                .put("level", "info")
                .put("timestamp", true)
        )

        config.put(
            "dns",
            buildDns(
                remoteDns = remoteDns,
                localDns = localDns,
                enableDoh = enableDoh,
                routingMode = routingMode,
                enableGeoCnDomainRule = enableGeoCnDomainRule && hasGeoSiteCn
            )
        )
        config.put("inbounds", buildInbounds(enableSocksInbound, enableHttpInbound, enableIPv6))

        val proxyOutbound = buildProxyOutbound(node).put("tag", "proxy")
        config.put(
            "outbounds",
            JSONArray()
                .put(proxyOutbound)
                .put(JSONObject().put("type", "direct").put("tag", "direct"))
        )

        config.put(
            "route",
            buildRoute(
                routingMode = routingMode,
                geoIpCnRuleSetPath = geoIpCnRuleSetPath,
                geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
                geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath,
                enableGeoCnDomainRule = enableGeoCnDomainRule && hasGeoSiteCn,
                enableGeoCnIpRule = enableGeoCnIpRule && hasGeoIpCn,
                enableGeoAdsBlock = enableGeoAdsBlock && hasGeoAds,
                enableGeoBlockQuic = enableGeoBlockQuic
            )
        )

        return config.toString(2)
    }

    // ── DNS ──────────────────────────────────────────────────────────

    private fun buildDns(
        remoteDns: String,
        localDns: String,
        enableDoh: Boolean,
        routingMode: RoutingMode,
        enableGeoCnDomainRule: Boolean
    ): JSONObject {
        val bootstrapServer = buildDnsServer(
            tag = "bootstrap",
            dns = "1.1.1.1"
        )

        val localServer = buildDnsServer(
            tag = "local",
            dns = normalizeLocalDnsAddress(localDns),
            resolverTag = "bootstrap"
        )

        // Strict direct mode: force DNS to local resolver only.
        if (routingMode == RoutingMode.DIRECT) {
            return JSONObject()
                .put("servers", JSONArray().put(localServer).put(bootstrapServer))
                .put("final", "local")
        }

        val remoteServer = buildDnsServer(
            tag = "remote",
            dns = normalizeRemoteDnsAddress(remoteDns, enableDoh),
            detour = "proxy",
            resolverTag = "bootstrap"
        )

        val dns = JSONObject()
            .put(
                "servers",
                JSONArray()
                    .put(remoteServer)
                    .put(localServer)
                    .put(bootstrapServer)
            )
            .put("final", "remote")

        // Only add DNS routing rules for rule-based modes
        if (routingMode == RoutingMode.RULE_BASED) {
            val dnsRules = JSONArray()
            fun addDnsLocalRule(country: String) {
                dnsRules.put(
                    JSONObject()
                        .put("rule_set", JSONArray().put("geosite-$country"))
                        .put("action", "route")
                        .put("server", "local")
                )
            }

            if (enableGeoCnDomainRule) addDnsLocalRule("cn")

            if (dnsRules.length() > 0) {
                dns.put("rules", dnsRules)
            }
        }

        return dns
    }

    private fun buildDnsServer(
        tag: String,
        dns: String,
        detour: String? = null,
        resolverTag: String? = null
    ): JSONObject {
        val spec = parseDnsServer(dns)
        return JSONObject()
            .put("type", spec.type)
            .put("tag", tag)
            .put("server", spec.server)
            .put("server_port", spec.serverPort)
            .apply {
                detour?.let { put("detour", it) }
                spec.path?.let { put("path", it) }
                if (!isIpLiteral(spec.server)) {
                    put("domain_resolver", resolverTag ?: "bootstrap")
                }
            }
    }

    private fun normalizeRemoteDnsAddress(remoteDns: String, enableDoh: Boolean): String {
        val trimmed = remoteDns.trim()
        if (trimmed.isBlank()) {
            return if (enableDoh) "https://dns.google/dns-query" else "8.8.8.8"
        }

        if (enableDoh) {
            return when {
                trimmed.startsWith("https://") -> normalizeEncryptedDnsEndpoint(trimmed, "https")
                trimmed.startsWith("tls://") -> normalizeEncryptedDnsEndpoint(trimmed, "tls")
                trimmed.startsWith("quic://") -> normalizeEncryptedDnsEndpoint(trimmed, "quic")
                isIpLiteral(trimmed) -> knownEncryptedDnsEndpoint(trimmed) ?: trimmed
                else -> "tls://$trimmed"
            }
        }

        return when {
            trimmed.startsWith("tls://") -> {
                val host = trimmed.removePrefix("tls://")
                parseHostAndPort(host, 853).first
            }
            trimmed.startsWith("https://") -> {
                runCatching { URI(trimmed).host }
                    .getOrNull()
                    ?.takeIf { it.isNotBlank() }
                    ?: trimmed.removePrefix("https://").substringBefore('/')
            }
            trimmed.startsWith("quic://") -> {
                val host = trimmed.removePrefix("quic://")
                parseHostAndPort(host, 853).first
            }
            else -> trimmed
        }
    }

    private fun normalizeEncryptedDnsEndpoint(value: String, scheme: String): String {
        return when (scheme) {
            "https" -> {
                val uri = URI(value)
                val mappedHost = uri.host?.let { knownEncryptedDnsHost(it) }
                if (mappedHost == null) {
                    value
                } else {
                    val portPart = if (uri.port > 0 && uri.port != 443) ":${uri.port}" else ""
                    val path = uri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query"
                    "https://$mappedHost$portPart$path"
                }
            }

            "tls", "quic" -> {
                val rawHost = value.removePrefix("$scheme://")
                val (host, port) = parseHostAndPort(rawHost, 853)
                val mappedHost = knownEncryptedDnsHost(host)
                when {
                    mappedHost != null -> {
                        val portPart = if (port != 853) ":$port" else ""
                        "$scheme://$mappedHost$portPart"
                    }

                    isIpLiteral(host) -> host
                    else -> value
                }
            }

            else -> value
        }
    }

    private fun normalizeLocalDnsAddress(localDns: String): String {
        val trimmed = localDns.trim()
        return if (trimmed.isBlank()) "https://dns.alidns.com/dns-query" else trimmed
    }

    private fun parseDnsServer(dns: String): DnsServerSpec {
        val trimmed = dns.trim()
        return when {
            trimmed.startsWith("https://") -> {
                val uri = URI(trimmed)
                val server = uri.host?.takeIf { it.isNotBlank() }
                    ?: trimmed.removePrefix("https://").substringBefore('/').substringBefore(':')
                DnsServerSpec(
                    type = "https",
                    server = server,
                    serverPort = if (uri.port > 0) uri.port else 443,
                    path = uri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query"
                )
            }

            trimmed.startsWith("tls://") -> {
                val (server, port) = parseHostAndPort(trimmed.removePrefix("tls://"), 853)
                DnsServerSpec("tls", server, port)
            }

            trimmed.startsWith("tcp://") -> {
                val (server, port) = parseHostAndPort(trimmed.removePrefix("tcp://"), 53)
                DnsServerSpec("tcp", server, port)
            }

            trimmed.startsWith("udp://") -> {
                val (server, port) = parseHostAndPort(trimmed.removePrefix("udp://"), 53)
                DnsServerSpec("udp", server, port)
            }

            trimmed.startsWith("quic://") -> {
                val (server, port) = parseHostAndPort(trimmed.removePrefix("quic://"), 853)
                DnsServerSpec("quic", server, port)
            }

            else -> {
                val (server, port) = parseHostAndPort(trimmed, 53)
                DnsServerSpec("udp", server, port)
            }
        }
    }

    private fun parseHostAndPort(raw: String, defaultPort: Int): Pair<String, Int> {
        val value = raw.trim()
        val parsed = runCatching { URI("dns://$value") }.getOrNull()
        val host = parsed?.host?.takeIf { it.isNotBlank() }
        if (host != null) {
            val port = if (parsed.port > 0) parsed.port else defaultPort
            return host to port
        }

        if (value.count { it == ':' } == 1 && !value.startsWith("[")) {
            val separator = value.lastIndexOf(':')
            val port = value.substring(separator + 1).toIntOrNull()
            if (port != null) {
                return value.substring(0, separator) to port
            }
        }

        return value.removePrefix("[").removeSuffix("]") to defaultPort
    }

    private fun isIpLiteral(server: String): Boolean {
        val normalized = server.removePrefix("[").removeSuffix("]")
        val ipv4 = normalized.split(".").let { octets ->
            octets.size == 4 && octets.all { octet ->
                octet.toIntOrNull()?.let { it in 0..255 } == true
            }
        }
        if (ipv4) return true

        return normalized.contains(':') &&
            normalized.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
    }

    private fun knownEncryptedDnsEndpoint(value: String): String? {
        val host = knownEncryptedDnsHost(value) ?: return null
        return when (host) {
            "dns.google" -> "https://dns.google/dns-query"
            "cloudflare-dns.com" -> "https://cloudflare-dns.com/dns-query"
            "dns.quad9.net" -> "https://dns.quad9.net/dns-query"
            "dns.alidns.com" -> "https://dns.alidns.com/dns-query"
            "doh.pub" -> "https://doh.pub/dns-query"
            else -> null
        }
    }

    private fun knownEncryptedDnsHost(value: String): String? {
        return when (value.removePrefix("[").removeSuffix("]").lowercase()) {
            "8.8.8.8", "8.8.4.4", "dns.google" -> "dns.google"
            "1.1.1.1", "1.0.0.1", "cloudflare-dns.com", "one.one.one.one" -> "cloudflare-dns.com"
            "9.9.9.9", "149.112.112.112", "dns.quad9.net" -> "dns.quad9.net"
            "223.5.5.5", "223.6.6.6", "dns.alidns.com" -> "dns.alidns.com"
            "119.29.29.29", "182.254.116.116", "doh.pub" -> "doh.pub"
            else -> null
        }
    }

    // ── Inbounds ─────────────────────────────────────────────────────

    private fun buildInbounds(
        enableSocks: Boolean,
        enableHttp: Boolean,
        enableIPv6: Boolean = true
    ): JSONArray {
        val inbounds = JSONArray()
        val tunAddresses = JSONArray()
            .put("172.19.0.1/28")
        if (enableIPv6) {
            tunAddresses.put("fdfe:dcba:9876::1/126")
        }

        val tunInbound = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("interface_name", "tun0")
            .put("address", tunAddresses)
            .put("mtu", 9000)
            .put("auto_route", true)
            .put("strict_route", true)
            .put("stack", "system")

        inbounds.put(tunInbound)

        // Optional SOCKS5 inbound (for Phase 6)
        if (enableSocks) {
            inbounds.put(
                JSONObject()
                    .put("type", "socks")
                    .put("tag", "socks-in")
                    .put("listen", "::")
                    .put("listen_port", 2080)
            )
        }

        // Optional HTTP inbound (for Phase 6)
        if (enableHttp) {
            inbounds.put(
                JSONObject()
                    .put("type", "http")
                    .put("tag", "http-in")
                    .put("listen", "::")
                    .put("listen_port", 2081)
            )
        }

        return inbounds
    }

    // ── Route ────────────────────────────────────────────────────────

    private fun buildRoute(
        routingMode: RoutingMode,
        geoIpCnRuleSetPath: String? = null,
        geoSiteCnRuleSetPath: String? = null,
        geoSiteAdsRuleSetPath: String? = null,
        enableGeoCnDomainRule: Boolean = true,
        enableGeoCnIpRule: Boolean = true,
        enableGeoAdsBlock: Boolean = true,
        enableGeoBlockQuic: Boolean = true
    ): JSONObject {
        val route = JSONObject()
            .put("auto_detect_interface", true)
            .put("default_domain_resolver", "bootstrap")

        val ruleSets = JSONArray()
        if (!geoIpCnRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geoip-cn", geoIpCnRuleSetPath))
        }
        if (!geoSiteCnRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geosite-cn", geoSiteCnRuleSetPath))
        }
        if (!geoSiteAdsRuleSetPath.isNullOrBlank()) {
            ruleSets.put(buildLocalRuleSet("geosite-category-ads-all", geoSiteAdsRuleSetPath))
        }
        if (ruleSets.length() > 0) {
            route.put("rule_set", ruleSets)
        }

        when (routingMode) {
            RoutingMode.GLOBAL_PROXY -> {
                route.put("final", "proxy")
                route.put(
                    "rules",
                    buildBaseRouteRules()
                )
            }

            RoutingMode.RULE_BASED -> {
                route.put("final", "proxy")
                val rules = buildBaseRouteRules()

                if (enableGeoBlockQuic) {
                    rules.put(
                        JSONObject()
                            .put("network", JSONArray().put("udp"))
                            .put("port", JSONArray().put(443))
                            .put("action", "reject")
                    )
                }

                if (enableGeoCnDomainRule) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geosite-cn"))
                            .put("action", "route")
                            .put("outbound", "direct")
                    )
                }

                if (enableGeoCnIpRule) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geoip-cn"))
                            .put("action", "route")
                            .put("outbound", "direct")
                    )
                }

                if (enableGeoAdsBlock) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geosite-category-ads-all"))
                            .put("action", "reject")
                    )
                }

                route.put(
                    "rules",
                    rules
                )
            }

            RoutingMode.DIRECT -> {
                route.put("final", "direct")
                route.put(
                    "rules",
                    buildBaseRouteRules()
                )
            }

        }

        return route
    }

    private fun buildLocalRuleSet(tag: String, path: String): JSONObject {
        return JSONObject()
            .put("tag", tag)
            .put("type", "local")
            .put("format", "binary")
            .put("path", path)
    }

    private fun buildBaseRouteRules(): JSONArray {
        return JSONArray()
            .put(
                JSONObject()
                    .put("action", "sniff")
            )
            .put(
                JSONObject()
                    .put("port", JSONArray().put(53))
                    .put("action", "hijack-dns")
            )
            .put(
                JSONObject()
                    .put("protocol", "dns")
                    .put("action", "hijack-dns")
                )
            .put(
                JSONObject()
                    .put("ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("source_ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("action", "reject")
            )
    }

    // ── Proxy Outbound ───────────────────────────────────────────────

    private fun buildProxyOutbound(node: ProxyNode): JSONObject {
        val outbound = JSONObject()
            .put("server", node.server)
            .put("server_port", node.port)

        when (node.type) {
            ProxyType.SHADOWSOCKS,
            ProxyType.SHADOWSOCKS_2022 -> {
                outbound.put("type", "shadowsocks")
                outbound.put("method", node.method ?: "aes-128-gcm")
                outbound.put("password", node.password ?: "")
            }

            ProxyType.VMESS -> {
                outbound.put("type", "vmess")
                outbound.put("uuid", node.uuid ?: "")
                outbound.put("security", node.security ?: "auto")
                outbound.put("alter_id", 0)
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node))
            }

            ProxyType.VLESS -> {
                outbound.put("type", "vless")
                outbound.put("uuid", node.uuid ?: "")
                node.flow?.let { outbound.put("flow", it) }
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node, includeReality = true))
            }

            ProxyType.TROJAN -> {
                outbound.put("type", "trojan")
                outbound.put("password", node.password ?: "")
                node.packetEncoding?.takeIf { it.isNotBlank() }?.let { outbound.put("packet_encoding", it) }
                outbound.put("tls", buildTlsObject(node))
            }

            ProxyType.HYSTERIA2 -> {
                outbound.put("type", "hysteria2")
                outbound.put("password", node.password ?: "")
                outbound.put("tls", buildTlsObject(node))
            }

            ProxyType.TUIC -> {
                outbound.put("type", "tuic")
                outbound.put("uuid", node.uuid ?: "")
                outbound.put("password", node.password ?: "")
                outbound.put("tls", buildTlsObject(node))
            }

            ProxyType.SOCKS -> {
                outbound.put("type", "socks")
                node.username?.let { outbound.put("username", it) }
                node.password?.let { outbound.put("password", it) }
            }

            ProxyType.HTTP -> {
                outbound.put("type", "http")
                node.username?.let { outbound.put("username", it) }
                node.password?.let { outbound.put("password", it) }
                if (node.tls) {
                    outbound.put("tls", JSONObject().put("enabled", true))
                }
            }
        }

        node.network?.let { network ->
            if (network != "tcp" && network.isNotBlank()) {
                outbound.put("transport", buildTransport(node))
            }
        }
        return outbound
    }

    private fun buildTlsObject(node: ProxyNode, includeReality: Boolean = false): JSONObject {
        val tls = JSONObject()
            .put("enabled", node.tls)
        if (node.allowInsecure) {
            tls.put("insecure", true)
        }
        node.sni?.let { tls.put("server_name", it) }

        if (!node.alpn.isNullOrBlank()) {
            val alpnArray = JSONArray()
            node.alpn!!.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { alpnArray.put(it) }
            if (alpnArray.length() > 0) {
                tls.put("alpn", alpnArray)
            }
        }

        if (includeReality && !node.publicKey.isNullOrBlank()) {
            tls.put(
                "reality",
                JSONObject()
                    .put("enabled", true)
                    .put("public_key", node.publicKey)
                    .put("short_id", node.shortId ?: "")
            )
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

    private fun buildTransport(node: ProxyNode): JSONObject {
        val transport = JSONObject()
        when (node.network?.lowercase()) {
            "ws", "websocket" -> {
                transport.put("type", "ws")
                normalizedTransportPath(node.transportPath)?.let { transport.put("path", it) }
                firstTransportHost(node)?.let { transport.put("headers", JSONObject().put("Host", it)) }
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
        }
        return transport
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
