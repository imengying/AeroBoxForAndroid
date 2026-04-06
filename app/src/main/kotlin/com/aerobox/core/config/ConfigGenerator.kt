package com.aerobox.core.config

import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.RoutingMode
import com.aerobox.data.model.effectiveEnabledNetwork
import com.aerobox.data.model.effectiveTransportType
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

object ConfigGenerator {
    private const val PROXY_OUTBOUND_TAG = "proxy"
    private const val DNS_LOCAL_TAG = "dns-local"
    private const val DNS_DIRECT_TAG = "dns-direct"
    private const val DNS_REMOTE_TAG = "dns-remote"
    private const val DNS_BOOTSTRAP_TAG = "dns-bootstrap"
    private const val DEFAULT_TUN_MTU = 9000
    const val V2RAY_API_LISTEN = "127.0.0.1:10085"

    private data class DnsServerSpec(
        val type: String,
        val server: String,
        val serverPort: Int,
        val path: String? = null
    )

    fun validateDnsSettings(
        remoteDns: String,
        directDns: String,
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE,
        nodeIsIpv6Only: Boolean = false
    ): String? {
        return runCatching {
            val normalizedRemote = normalizeRemoteDnsAddress(remoteDns, nodeIsIpv6Only)
            val normalizedDirect = normalizeDirectDnsAddress(directDns, nodeIsIpv6Only)
            validateDnsServerSpec(
                label = "远程 DNS",
                spec = parseDnsServer(normalizedRemote),
                ipv6Mode = ipv6Mode
            )
            validateDnsServerSpec(
                label = "直连 DNS",
                spec = parseDnsServer(normalizedDirect),
                ipv6Mode = ipv6Mode
            )
            null
        }.getOrElse { error ->
            error.message?.takeIf { it.isNotBlank() } ?: "DNS 地址格式无效"
        }
    }

    fun generateSingBoxConfig(
        node: ProxyNode,
        routingMode: RoutingMode = RoutingMode.RULE_BASED,
        remoteDns: String = "https://cloudflare-dns.com/dns-query",
        directDns: String = "udp://223.5.5.5",
        enableSocksInbound: Boolean = false,
        enableHttpInbound: Boolean = false,
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE,
        enableGeoCnDomainRule: Boolean = true,
        enableGeoCnIpRule: Boolean = true,
        enableGeoAdsBlock: Boolean = true,
        enableGeoBlockQuic: Boolean = true,
        geoIpCnRuleSetPath: String? = null,
        geoSiteCnRuleSetPath: String? = null,
        geoSiteAdsRuleSetPath: String? = null,
        nodeIsIpv6OnlyOverride: Boolean? = null
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

        val nodeIsIpv6Only = nodeIsIpv6OnlyOverride ?: isIpv6Literal(node.server)
        config.put(
            "dns",
            buildDns(
                remoteDns = remoteDns,
                directDns = directDns,
                routingMode = routingMode,
                enableGeoCnDomainRule = enableGeoCnDomainRule && hasGeoSiteCn,
                ipv6Mode = ipv6Mode,
                nodeIsIpv6Only = nodeIsIpv6Only,
                serverDomainHint = normalizeOutboundServer(node.server)
                    .takeUnless { it.isBlank() || isIpLiteral(it) }
            )
        )
        config.put("inbounds", buildInbounds(enableSocksInbound, enableHttpInbound, ipv6Mode))

        val proxyOutbound = buildProxyOutbound(node).put("tag", PROXY_OUTBOUND_TAG)
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
                ipv6Mode = ipv6Mode,
                nodeIsIpv6Only = nodeIsIpv6Only,
                geoIpCnRuleSetPath = geoIpCnRuleSetPath,
                geoSiteCnRuleSetPath = geoSiteCnRuleSetPath,
                geoSiteAdsRuleSetPath = geoSiteAdsRuleSetPath,
                enableGeoCnDomainRule = enableGeoCnDomainRule && hasGeoSiteCn,
                enableGeoCnIpRule = enableGeoCnIpRule && hasGeoIpCn,
                enableGeoAdsBlock = enableGeoAdsBlock && hasGeoAds,
                enableGeoBlockQuic = enableGeoBlockQuic
            )
        )
        config.put("experimental", buildExperimental())

        return config.toString(2)
    }

    fun generateUrlTestConfig(
        node: ProxyNode,
        directDns: String = "udp://223.5.5.5",
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE,
        nodeIsIpv6OnlyOverride: Boolean? = null
    ): String {
        val config = JSONObject()
        val nodeIsIpv6Only = nodeIsIpv6OnlyOverride ?: isIpv6Literal(node.server)
        config.put(
            "log",
            JSONObject()
                .put("level", "error")
                .put("timestamp", false)
        )
        config.put(
            "dns",
            buildDns(
                remoteDns = "https://cloudflare-dns.com/dns-query",
                directDns = directDns,
                routingMode = RoutingMode.DIRECT,
                enableGeoCnDomainRule = false,
                ipv6Mode = ipv6Mode,
                nodeIsIpv6Only = nodeIsIpv6Only,
                serverDomainHint = normalizeOutboundServer(node.server)
                    .takeUnless { it.isBlank() || isIpLiteral(it) }
            )
        )
        config.put("inbounds", JSONArray())
        config.put(
            "outbounds",
            JSONArray()
                .put(buildProxyOutbound(node).put("tag", PROXY_OUTBOUND_TAG))
                .put(JSONObject().put("type", "direct").put("tag", "direct"))
        )
        config.put(
            "route",
            JSONObject()
                .put("auto_detect_interface", false)
                .put("final", PROXY_OUTBOUND_TAG)
        )
        return config.toString()
    }

    private fun buildExperimental(): JSONObject {
        return JSONObject().put(
            "v2ray_api",
            JSONObject()
                .put("listen", V2RAY_API_LISTEN)
                .put(
                    "stats",
                    JSONObject()
                        .put("enabled", true)
                        .put("outbounds", JSONArray().put("proxy").put("direct"))
                )
        )
    }

    // ── DNS ──────────────────────────────────────────────────────────

    private fun buildDns(
        remoteDns: String,
        directDns: String,
        routingMode: RoutingMode,
        enableGeoCnDomainRule: Boolean,
        ipv6Mode: IPv6Mode,
        nodeIsIpv6Only: Boolean = false,
        serverDomainHint: String? = null
    ): JSONObject {
        // When proxy is IPv6-only, remote DNS domain resolution must prefer IPv6
        // so DoH endpoints resolve to IPv6 addresses reachable through the proxy.
        val remoteDnsStrategy = if (nodeIsIpv6Only) "prefer_ipv6" else ipv6Mode.domainStrategy()
        val localResolverServer = buildLocalPlatformDnsServer(
            tag = DNS_LOCAL_TAG
        )
        val bootstrapServer = buildDnsServer(
            tag = DNS_BOOTSTRAP_TAG,
            dns = bootstrapDnsAddress(nodeIsIpv6Only),
            ipv6Mode = ipv6Mode
        )

        val directServer = buildDnsServer(
            tag = DNS_DIRECT_TAG,
            dns = normalizeDirectDnsAddress(directDns, nodeIsIpv6Only),
            resolverTag = DNS_LOCAL_TAG,
            ipv6Mode = ipv6Mode
        )

        // Strict direct mode: force DNS to local resolver only.
        if (routingMode == RoutingMode.DIRECT) {
            return JSONObject()
                .put("servers", JSONArray().put(directServer).put(localResolverServer).put(bootstrapServer))
                .put("final", DNS_DIRECT_TAG)
                .putDnsQueryStrategy(ipv6Mode)
        }

        val remoteServer = buildDnsServer(
            tag = DNS_REMOTE_TAG,
            dns = normalizeRemoteDnsAddress(remoteDns, nodeIsIpv6Only),
            detour = "proxy",
            resolverTag = DNS_DIRECT_TAG,
            ipv6Mode = ipv6Mode,
            dialStrategyOverride = remoteDnsStrategy
        )

        val dns = JSONObject()
            .put(
                "servers",
                JSONArray()
                    .put(remoteServer)
                    .put(directServer)
                    .put(localResolverServer)
                    .put(bootstrapServer)
            )
            .put("final", DNS_REMOTE_TAG)
            .putDnsQueryStrategy(ipv6Mode)

        val dnsRules = JSONArray()
        serverDomainHint
            ?.lowercase()
            ?.takeIf { it.isNotBlank() }
            ?.let { serverDomain ->
                dnsRules.put(
                    JSONObject()
                        .put("domain", JSONArray().put(serverDomain))
                        .put("action", "route")
                        .put("server", DNS_DIRECT_TAG)
                )
            }

        // Only add Geo-specific DNS routing rules for rule-based modes
        if (routingMode == RoutingMode.RULE_BASED) {
            fun addDnsLocalRule(country: String) {
                dnsRules.put(
                    JSONObject()
                        .put("rule_set", JSONArray().put("geosite-$country"))
                        .put("action", "route")
                        .put("server", DNS_DIRECT_TAG)
                )
            }

            if (enableGeoCnDomainRule) addDnsLocalRule("cn")

        }

        if (dnsRules.length() > 0) {
            dns.put("rules", dnsRules)
        }

        return dns
    }

    private fun bootstrapDnsAddress(nodeIsIpv6Only: Boolean): String {
        return if (nodeIsIpv6Only) "2606:4700:4700::1111" else "1.1.1.1"
    }

    private fun buildLocalPlatformDnsServer(tag: String): JSONObject {
        return JSONObject()
            .put("type", "local")
            .put("tag", tag)
    }

    private fun buildDnsServer(
        tag: String,
        dns: String,
        detour: String? = null,
        resolverTag: String? = null,
        ipv6Mode: IPv6Mode,
        dialStrategyOverride: String? = null
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
                    val strategy = dialStrategyOverride ?: ipv6Mode.domainStrategy()
                    put(
                        "domain_resolver",
                        JSONObject()
                            .put("server", resolverTag ?: DNS_BOOTSTRAP_TAG)
                            .put("strategy", strategy)
                    )
                }
            }
    }

    private fun validateDnsServerSpec(
        label: String,
        spec: DnsServerSpec,
        ipv6Mode: IPv6Mode
    ) {
        require(spec.server.isNotBlank()) { "$label 地址无效" }
        require(spec.serverPort in 1..65535) { "$label 端口无效" }
        require(spec.type in setOf("https", "tls", "tcp", "udp", "quic")) { "$label 协议无效" }
        require(isValidDnsHostOrIp(spec.server)) { "$label 地址无效" }
        if (spec.type == "https") {
            require(!spec.path.isNullOrBlank() && spec.path.startsWith("/")) { "$label 路径无效" }
        }
        if (ipv6Mode == IPv6Mode.DISABLE) {
            require(!isIpv6Literal(spec.server)) { "$label 不能是 IPv6 地址" }
        }
    }

    private fun isValidDnsHostOrIp(server: String): Boolean {
        val normalized = server.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (normalized.isBlank() || normalized.any { it.isWhitespace() }) return false
        if (isIpLiteral(normalized)) return true
        return normalized.split('.').all { label ->
            label.isNotBlank() &&
                label.length <= 63 &&
                label.firstOrNull()?.let { it.isLetterOrDigit() } == true &&
                label.lastOrNull()?.let { it.isLetterOrDigit() } == true &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun normalizeRemoteDnsAddress(remoteDns: String, nodeIsIpv6Only: Boolean = false): String {
        val trimmed = remoteDns.trim()
        if (trimmed.isBlank()) {
            return "https://cloudflare-dns.com/dns-query"
        }

        return when {
            trimmed.startsWith("https://") -> normalizeEncryptedDnsEndpoint(trimmed, "https")
            trimmed.startsWith("tls://") -> {
                normalizeEncryptedDnsEndpoint(trimmed, "tls")
            }
            trimmed.startsWith("quic://") -> {
                normalizeEncryptedDnsEndpoint(trimmed, "quic")
            }
            trimmed.startsWith("tcp://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "tcp",
                defaultPort = 53
            ).takeIf { nodeIsIpv6Only } ?: trimmed
            trimmed.startsWith("udp://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "udp",
                defaultPort = 53
            ).takeIf { nodeIsIpv6Only } ?: trimmed
            else -> if (nodeIsIpv6Only) knownIpv6DnsAddress(trimmed) ?: trimmed else trimmed
        }
    }

    private fun knownIpv6DnsAddress(ipv4Dns: String): String? {
        return when (ipv4Dns.removePrefix("[").removeSuffix("]")) {
            "1.1.1.1", "1.0.0.1" -> "2606:4700:4700::1111"
            "8.8.8.8", "8.8.4.4" -> "2001:4860:4860::8888"
            "9.9.9.9" -> "2620:fe::fe"
            "223.5.5.5", "223.6.6.6" -> "2400:3200::1"
            "119.29.29.29" -> "2402:4e00::"
            else -> null
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

                    isIpLiteral(host) -> {
                        val portPart = if (port != 853) ":$port" else ""
                        "$scheme://$host$portPart"
                    }
                    else -> value
                }
            }

            else -> value
        }
    }

    private fun normalizeDirectDnsAddress(directDns: String, nodeIsIpv6Only: Boolean = false): String {
        val trimmed = directDns.trim()
        if (trimmed == "[ipv4]" || trimmed == "[ipv6]") {
            return if (nodeIsIpv6Only) "2400:3200::1" else "223.5.5.5"
        }
        if (trimmed.isBlank()) return "https://dns.alidns.com/dns-query"
        if (!nodeIsIpv6Only) return trimmed

        return when {
            trimmed.startsWith("https://") -> normalizeEncryptedDnsEndpoint(trimmed, "https")
            trimmed.startsWith("tls://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "tls",
                defaultPort = 853,
                preferKnownEncryptedHost = true
            )
            trimmed.startsWith("quic://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "quic",
                defaultPort = 853,
                preferKnownEncryptedHost = true
            )
            trimmed.startsWith("tcp://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "tcp",
                defaultPort = 53
            )
            trimmed.startsWith("udp://") -> normalizeIpv6OnlyDnsEndpoint(
                value = trimmed,
                scheme = "udp",
                defaultPort = 53
            )
            else -> normalizeIpv6OnlyDnsHostPort(trimmed, defaultPort = 53)
        }
    }

    private fun normalizeIpv6OnlyDnsEndpoint(
        value: String,
        scheme: String,
        defaultPort: Int,
        preferKnownEncryptedHost: Boolean = false
    ): String {
        val rawHost = value.removePrefix("$scheme://")
        val hadExplicitPort = hasExplicitPort(rawHost)
        val (host, port) = parseHostAndPort(rawHost, defaultPort)
        val mappedHost = if (preferKnownEncryptedHost) {
            knownEncryptedDnsHost(host) ?: knownIpv6DnsAddress(host)
        } else {
            knownIpv6DnsAddress(host)
        } ?: return value
        return buildDnsEndpoint(mappedHost, port, defaultPort, scheme, hadExplicitPort)
    }

    private fun normalizeIpv6OnlyDnsHostPort(value: String, defaultPort: Int): String {
        val hadExplicitPort = hasExplicitPort(value)
        val (host, port) = parseHostAndPort(value, defaultPort)
        val mappedHost = knownIpv6DnsAddress(host) ?: return value
        return buildDnsEndpoint(mappedHost, port, defaultPort, scheme = null, hadExplicitPort = hadExplicitPort)
    }

    private fun buildDnsEndpoint(
        host: String,
        port: Int,
        defaultPort: Int,
        scheme: String?,
        hadExplicitPort: Boolean
    ): String {
        val formattedHost = if (host.contains(':')) "[$host]" else host
        val authority = if (hadExplicitPort || port != defaultPort) "$formattedHost:$port" else formattedHost
        return if (scheme != null) "$scheme://$authority" else authority
    }

    private fun hasExplicitPort(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.startsWith("[")) {
            return trimmed.contains("]:")
        }
        return trimmed.count { it == ':' } == 1 && trimmed.substringAfterLast(':').toIntOrNull() != null
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
                val safeServer = if (server == "[ipv4]" || server == "[ipv6]") "1.1.1.1" else server
                DnsServerSpec("udp", safeServer, port)
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
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE
    ): JSONArray {
        val inbounds = JSONArray()
        val tunAddresses = JSONArray().apply {
            put("172.19.0.1/28")
            if (ipv6Mode.enablesIpv6Tun()) {
                put("fdfe:dcba:9876::1/126")
            }
        }
        val inboundListen = if (ipv6Mode == IPv6Mode.DISABLE) "0.0.0.0" else "::"

        val tunInbound = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("interface_name", "tun0")
            .put("address", tunAddresses)
            .put("mtu", DEFAULT_TUN_MTU)
            .put("auto_route", true)
            .put("stack", "system")

        inbounds.put(tunInbound)

        // Optional SOCKS5 inbound
        if (enableSocks) {
            inbounds.put(
                JSONObject()
                    .put("type", "socks")
                    .put("tag", "socks-in")
                    .put("listen", inboundListen)
                    .put("listen_port", 2080)
            )
        }

        // Optional HTTP inbound
        if (enableHttp) {
            inbounds.put(
                JSONObject()
                    .put("type", "http")
                    .put("tag", "http-in")
                    .put("listen", inboundListen)
                    .put("listen_port", 2081)
            )
        }

        return inbounds
    }

    // ── Route ────────────────────────────────────────────────────────

    private fun buildRoute(
        routingMode: RoutingMode,
        ipv6Mode: IPv6Mode,
        nodeIsIpv6Only: Boolean = false,
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
                    buildBaseRouteRules(nodeIsIpv6Only)
                )
            }

            RoutingMode.RULE_BASED -> {
                route.put("final", "proxy")
                val rules = buildBaseRouteRules(nodeIsIpv6Only)

                if (enableGeoBlockQuic) {
                    rules.put(
                        JSONObject()
                            .put("network", JSONArray().put("udp"))
                            .put("port", JSONArray().put(443))
                            .put("action", "reject")
                    )
                }

                if (enableGeoAdsBlock) {
                    rules.put(
                        JSONObject()
                            .put("rule_set", JSONArray().put("geosite-category-ads-all"))
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

                route.put(
                    "rules",
                    rules
                )
            }

            RoutingMode.DIRECT -> {
                route.put("final", "direct")
                route.put(
                    "rules",
                    buildBaseRouteRules(nodeIsIpv6Only)
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

    private fun buildBaseRouteRules(nodeIsIpv6Only: Boolean): JSONArray {
        return JSONArray().apply {
            // Sniff is still useful for routing and SNI extraction.
            put(JSONObject().put("action", "sniff"))

            // Avoid client-side destination resolution on IPv6-only nodes.
            // Some IPv6-only servers can still reach IPv4-only sites via
            // server-side resolver/NAT64 setup, but local resolve would turn a
            // domain into a missing AAAA record and fail before the proxy sees it.
            if (!nodeIsIpv6Only) {
                put(
                    JSONObject()
                        .put("action", "resolve")
                        .put("strategy", destinationDomainStrategy(nodeIsIpv6Only))
                )
            }

            put(
                JSONObject()
                    .put("port", JSONArray().put(53))
                    .put("action", "hijack-dns")
            )
            put(
                JSONObject()
                    .put("protocol", "dns")
                    .put("action", "hijack-dns")
            )
            put(
                JSONObject()
                    .put(
                        "ip_cidr",
                        JSONArray()
                            .put("127.0.0.0/8")
                            .put("10.0.0.0/8")
                            .put("172.16.0.0/12")
                            .put("192.168.0.0/16")
                            .put("169.254.0.0/16")
                            .put("100.64.0.0/10")
                            .put("198.18.0.0/15")
                            .put("::1/128")
                            .put("fc00::/7")
                            .put("fe80::/10")
                    )
                    .put("action", "route")
                    .put("outbound", "direct")
            )
            put(
                JSONObject()
                    .put("ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("source_ip_cidr", JSONArray().put("224.0.0.0/3").put("ff00::/8"))
                    .put("action", "reject")
            )
            put(
                JSONObject()
                    .put("ip_cidr", JSONArray()
                        .put("1.1.1.1/32").put("1.0.0.1/32")
                        .put("8.8.8.8/32").put("8.8.4.4/32")
                        .put("9.9.9.9/32").put("149.112.112.112/32")
                        .put("223.5.5.5/32").put("223.6.6.6/32")
                        .put("119.29.29.29/32").put("182.254.116.116/32")
                    )
                    .put("action", "route")
                    .put("outbound", "direct")
            )
        }
    }

    // ── Proxy Outbound ───────────────────────────────────────────────

    private fun buildProxyOutbound(node: ProxyNode): JSONObject {
        val cleanServer = normalizeOutboundServer(node.server)
        val enabledNetwork = node.effectiveEnabledNetwork()
        val transportType = node.effectiveTransportType()
        val outbound = JSONObject()
            .put("server", cleanServer.ifBlank { "127.0.0.1" })
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
                node.hopInterval?.takeIf { it.isNotBlank() }?.let { outbound.put("hop_interval", it) }
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

            ProxyType.SOCKS -> {
                outbound.put("type", "socks")
                node.username?.let { outbound.put("username", it) }
                node.password?.let { outbound.put("password", it) }
                node.socksVersion?.takeIf { it.isNotBlank() }?.let { outbound.put("version", it) }
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
        if (!outbound.has("domain_resolver") && !isIpLiteral(cleanServer)) {
            // Use domain_resolver (not domain_strategy) so that only the proxy
            // SERVER address is resolved locally.  domain_strategy would also
            // resolve the destination domain locally and send the IP instead of
            // the domain, breaking DNS64/NAT64 setups on IPv6-only servers.
            outbound.put(
                "domain_resolver",
                JSONObject()
                    .put("server", DNS_DIRECT_TAG)
                    .put("strategy", "prefer_ipv4")
            )
        }
        return outbound
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

    private fun normalizeOutboundServer(server: String): String {
        return server
            .replace("[ipv4]", "")
            .replace("[ipv6]", "")
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
            .trim()
    }

    fun normalizedServerHost(server: String): String = normalizeOutboundServer(server)

    fun isIpv6ServerLiteral(server: String): Boolean = isIpv6Literal(server)

    fun isIpLiteralHost(host: String): Boolean = isIpLiteral(host)

    private fun isIpv6Literal(server: String): Boolean {
        val normalized = server.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        return normalized.contains(':') &&
            normalized.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
    }

    private fun JSONObject.putDnsQueryStrategy(
        ipv6Mode: IPv6Mode
    ): JSONObject {
        put("strategy", ipv6Mode.domainStrategy())
        return this
    }

    private fun destinationDomainStrategy(nodeIsIpv6Only: Boolean): String {
        return when {
            nodeIsIpv6Only -> "prefer_ipv6"
            else -> "prefer_ipv4"
        }
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
