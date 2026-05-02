package com.aerobox.core.config

import android.content.Context
import com.aerobox.R
import com.aerobox.core.errors.LocalizedException
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.RoutingMode
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

/**
 * Builds the "dns" section of a sing-box configuration.
 *
 * Extracted from [ConfigGenerator] for readability — all methods are
 * package-private and called exclusively by the generator.
 */
internal object DnsConfigBuilder {

    internal data class DnsServerSpec(
        val type: String,
        val server: String,
        val serverPort: Int,
        val path: String? = null
    )

    fun buildDns(
        remoteDns: String,
        directDns: String,
        routingMode: RoutingMode,
        enableGeoCnDomainRule: Boolean,
        ipv6Mode: IPv6Mode,
        nodeIsIpv6Only: Boolean = false,
        serverDomainHint: String? = null
    ): JSONObject {
        // IPv6-only proxies need IPv6-first bootstrap resolution for remote DNS.
        val remoteDnsStrategy = if (nodeIsIpv6Only) "prefer_ipv6" else "ipv4_only"
        val localResolverServer = buildLocalPlatformDnsServer(
            tag = ConfigGenerator.DNS_LOCAL_TAG
        )

        val normalizedDirectDns = normalizeDirectDnsAddress(directDns, nodeIsIpv6Only)
        val directServer = buildDnsServer(
            tag = ConfigGenerator.DNS_DIRECT_TAG,
            dns = normalizedDirectDns,
            resolverTag = ConfigGenerator.DNS_LOCAL_TAG,
            ipv6Mode = ipv6Mode
        )

        val bootstrapServer = buildDnsServer(
            tag = ConfigGenerator.DNS_BOOTSTRAP_TAG,
            dns = buildBootstrapDnsAddress(nodeIsIpv6Only),
            resolverTag = ConfigGenerator.DNS_LOCAL_TAG,
            ipv6Mode = ipv6Mode
        )

        if (routingMode == RoutingMode.DIRECT) {
            return JSONObject()
                .put("servers", JSONArray().put(directServer).put(localResolverServer).put(bootstrapServer))
                .put("final", ConfigGenerator.DNS_DIRECT_TAG)
                .put("independent_cache", true)
                .put("strategy", ipv6Mode.domainStrategy())
        }

        val remoteServer = buildDnsServer(
            tag = ConfigGenerator.DNS_REMOTE_TAG,
            dns = normalizeRemoteDnsAddress(remoteDns, nodeIsIpv6Only),
            detour = "proxy",
            resolverTag = ConfigGenerator.DNS_DIRECT_TAG,
            ipv6Mode = ipv6Mode,
            dialStrategyOverride = remoteDnsStrategy
        )

        val servers = JSONArray().apply {
            put(remoteServer)
            put(directServer)
            put(localResolverServer)
            put(bootstrapServer)
            if (nodeIsIpv6Only) {
                put(buildFakeIpDnsServer())
            }
        }

        val dns = JSONObject()
            .put("servers", servers)
            .put("final", ConfigGenerator.DNS_REMOTE_TAG)
            .put("independent_cache", true)
            .put("strategy", if (nodeIsIpv6Only) "prefer_ipv6" else "ipv4_only")

        val dnsRules = JSONArray()
        if (nodeIsIpv6Only) {
            dnsRules.put(
                JSONObject()
                    .put("inbound", JSONArray().put("tun-in"))
                    .put("server", ConfigGenerator.DNS_FAKE_TAG)
                    .put("disable_cache", true)
            )
        }
        serverDomainHint
            ?.lowercase()
            ?.takeIf { it.isNotBlank() }
            ?.let { serverDomain ->
                dnsRules.put(
                    JSONObject()
                        .put("domain", JSONArray().put(serverDomain))
                        .put("action", "route")
                        .put("server", ConfigGenerator.DNS_DIRECT_TAG)
                )
            }
        if (routingMode == RoutingMode.RULE_BASED && enableGeoCnDomainRule) {
            dnsRules.put(
                JSONObject()
                    .put("rule_set", JSONArray().put("geosite-cn"))
                    .put("action", "route")
                    .put("server", ConfigGenerator.DNS_DIRECT_TAG)
            )
        }
        if (dnsRules.length() > 0) {
            dns.put("rules", dnsRules)
        }

        return dns
    }

    fun validateDnsSettings(
        context: Context,
        remoteDns: String,
        directDns: String,
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE,
        nodeIsIpv6Only: Boolean = false
    ): String? {
        return runCatching {
            val normalizedRemote = normalizeRemoteDnsAddress(remoteDns, nodeIsIpv6Only)
            val normalizedDirect = normalizeDirectDnsAddress(directDns, nodeIsIpv6Only)
            validateDnsServerSpec(
                label = context.getString(R.string.dns_label_remote),
                spec = parseDnsServer(normalizedRemote),
                ipv6Mode = ipv6Mode
            )
            validateDnsServerSpec(
                label = context.getString(R.string.dns_label_direct),
                spec = parseDnsServer(normalizedDirect),
                ipv6Mode = ipv6Mode
            )
            null
        }.getOrElse { error ->
            when (error) {
                is LocalizedException -> error.resolveMessage(context)
                else -> error.message?.takeIf { it.isNotBlank() }
                    ?: context.getString(R.string.error_dns_invalid_format_generic)
            }
        }
    }

    // ── Private helpers ──────────────────────────────────────────────

    private fun buildFakeIpDnsServer(): JSONObject {
        return JSONObject()
            .put("type", "fakeip")
            .put("tag", ConfigGenerator.DNS_FAKE_TAG)
            .put("inet4_range", "198.18.0.0/15")
            .put("inet6_range", "fc00::/18")
    }

    private fun buildBootstrapDnsAddress(nodeIsIpv6Only: Boolean): String {
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
                if (!ConfigGenerator.isIpLiteral(spec.server)) {
                    val strategy = dialStrategyOverride ?: ipv6Mode.domainStrategy()
                    put(
                        "domain_resolver",
                        JSONObject()
                            .put("server", resolverTag ?: ConfigGenerator.DNS_BOOTSTRAP_TAG)
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
        if (spec.server.isBlank()) {
            throw LocalizedException.of(R.string.error_dns_address_invalid_format, label)
        }
        if (spec.serverPort !in 1..65535) {
            throw LocalizedException.of(R.string.error_dns_port_invalid_format, label)
        }
        if (spec.type !in setOf("https", "tls", "tcp", "udp", "quic")) {
            throw LocalizedException.of(R.string.error_dns_protocol_invalid_format, label)
        }
        if (!isValidDnsHostOrIp(spec.server)) {
            throw LocalizedException.of(R.string.error_dns_address_invalid_format, label)
        }
        if (spec.type == "https" &&
            (spec.path.isNullOrBlank() || !spec.path.startsWith("/"))
        ) {
            throw LocalizedException.of(R.string.error_dns_path_invalid_format, label)
        }
        if (ipv6Mode == IPv6Mode.DISABLE && ConfigGenerator.isIpv6Literal(spec.server)) {
            throw LocalizedException.of(R.string.error_dns_no_ipv6_format, label)
        }
    }

    private fun isValidDnsHostOrIp(server: String): Boolean {
        val normalized = server.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (normalized.isBlank() || normalized.any { it.isWhitespace() }) return false
        if (ConfigGenerator.isIpLiteral(normalized)) return true
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

                    ConfigGenerator.isIpLiteral(host) -> {
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
}
