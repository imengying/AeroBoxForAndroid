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
    private val supportedDnsTypes = setOf("https", "tls", "tcp", "udp", "quic")

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
        enableFakeDns: Boolean = false,
        serverDomainHint: String? = null
    ): JSONObject {
        val localResolverServer = buildLocalPlatformDnsServer(
            tag = ConfigGenerator.DNS_LOCAL_TAG
        )

        val normalizedDirectDns = normalizeDirectDnsAddress(directDns)
        val directServer = buildDnsServer(
            tag = ConfigGenerator.DNS_DIRECT_TAG,
            dns = normalizedDirectDns,
            resolverTag = ConfigGenerator.DNS_LOCAL_TAG
        )

        if (routingMode == RoutingMode.DIRECT) {
            return JSONObject()
                .put("servers", JSONArray().put(directServer).put(localResolverServer))
                .put("final", ConfigGenerator.DNS_DIRECT_TAG)
                .put("strategy", ipv6Mode.domainStrategy())
        }

        val remoteServer = buildDnsServer(
            tag = ConfigGenerator.DNS_REMOTE_TAG,
            dns = normalizeRemoteDnsAddress(remoteDns),
            detour = "proxy",
            resolverTag = ConfigGenerator.DNS_DIRECT_TAG
        )

        val servers = JSONArray().apply {
            put(remoteServer)
            put(directServer)
            put(localResolverServer)
            if (enableFakeDns) {
                put(buildFakeIpDnsServer(ipv6Mode))
            }
        }

        val dns = JSONObject()
            .put("servers", servers)
            .put("final", ConfigGenerator.DNS_REMOTE_TAG)
            .put("strategy", ipv6Mode.domainStrategy())

        val dnsRules = JSONArray()
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
        if (enableFakeDns) {
            // Keep local names on real DNS; retain other VPN domain names until routing.
            dnsRules.put(
                JSONObject()
                    .put("domain_suffix", JSONArray().put(".lan").put(".local").put(".home.arpa"))
                    .put("action", "route")
                    .put("server", ConfigGenerator.DNS_DIRECT_TAG)
            )
            dnsRules.put(
                JSONObject()
                    .put("inbound", JSONArray().put("tun-in"))
                    .put("query_type", JSONArray().put("A").put("AAAA"))
                    .put("action", "route")
                    .put("server", ConfigGenerator.DNS_FAKE_TAG)
            )
            // Real address hints in HTTPS/SVCB records would bypass the FakeIP mapping.
            dnsRules.put(
                JSONObject()
                    .put("inbound", JSONArray().put("tun-in"))
                    .put("query_type", JSONArray().put("HTTPS").put("SVCB"))
                    .put("action", "predefined")
                    .put("rcode", "NOERROR")
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
        directDns: String
    ): String? {
        return runCatching {
            val normalizedRemote = normalizeRemoteDnsAddress(remoteDns)
            val normalizedDirect = normalizeDirectDnsAddress(directDns)
            validateDnsServerSpec(
                label = context.getString(R.string.dns_label_remote),
                spec = parseDnsServer(normalizedRemote)
            )
            validateDnsServerSpec(
                label = context.getString(R.string.dns_label_direct),
                spec = parseDnsServer(normalizedDirect)
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

    private fun buildFakeIpDnsServer(ipv6Mode: IPv6Mode): JSONObject {
        return JSONObject()
            .put("type", "fakeip")
            .put("tag", ConfigGenerator.DNS_FAKE_TAG)
            .put("inet4_range", "198.18.0.0/15")
            .apply { if (ipv6Mode.enablesIpv6Tun()) put("inet6_range", "fc00::/18") }
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
                if (!ConfigGenerator.isIpLiteral(spec.server)) {
                    put(
                        "domain_resolver",
                        JSONObject()
                            .put("server", resolverTag ?: ConfigGenerator.DNS_LOCAL_TAG)
                            .put("strategy", "prefer_ipv4")
                    )
                }
            }
    }

    private fun validateDnsServerSpec(
        label: String,
        spec: DnsServerSpec
    ) {
        if (spec.server.isBlank()) {
            throw LocalizedException.of(R.string.error_dns_address_invalid_format, label)
        }
        if (spec.serverPort !in 1..65535) {
            throw LocalizedException.of(R.string.error_dns_port_invalid_format, label)
        }
        if (spec.type !in supportedDnsTypes) {
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
    }

    private fun isValidDnsHostOrIp(server: String): Boolean {
        val normalized = server.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (normalized.isBlank() || normalized.any { it.isWhitespace() }) return false
        if (normalized.contains(':')) {
            return runCatching { URI("dns://[$normalized]").host != null }.getOrDefault(false)
        }
        if (normalized.all { it.isDigit() || it == '.' }) return ConfigGenerator.isIpLiteral(normalized)
        if (normalized.length > 253) return false
        return normalized.split('.').all { label ->
            label.isNotBlank() &&
                label.length <= 63 &&
                label.firstOrNull()?.let { it.isLetterOrDigit() } == true &&
                label.lastOrNull()?.let { it.isLetterOrDigit() } == true &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun normalizeRemoteDnsAddress(remoteDns: String): String {
        val trimmed = remoteDns.trim().ifBlank { "https://cloudflare-dns.com/dns-query" }
        parseDnsServer(trimmed) // Validate before normalizing a known encrypted DNS hostname.
        return when {
            trimmed.startsWith("https://") -> normalizeEncryptedDnsEndpoint(trimmed, "https")
            trimmed.startsWith("tls://") -> normalizeEncryptedDnsEndpoint(trimmed, "tls")
            trimmed.startsWith("quic://") -> normalizeEncryptedDnsEndpoint(trimmed, "quic")
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

                    ConfigGenerator.isIpLiteral(host) -> {
                        buildDnsEndpoint(host, port, 853, scheme, hasExplicitPort(rawHost))
                    }
                    else -> value
                }
            }

            else -> value
        }
    }

    private fun normalizeDirectDnsAddress(directDns: String): String {
        val trimmed = directDns.trim()
        // Preserve old backup values without guessing the proxy exit family.
        if (trimmed == "[ipv4]") return "223.5.5.5"
        if (trimmed == "[ipv6]") return "2400:3200::1"
        return trimmed.ifBlank { "https://dns.alidns.com/dns-query" }.also { parseDnsServer(it) }
    }

    private fun buildDnsEndpoint(
        host: String,
        port: Int,
        defaultPort: Int,
        scheme: String,
        hadExplicitPort: Boolean
    ): String {
        val formattedHost = if (host.contains(':')) "[$host]" else host
        val authority = if (hadExplicitPort || port != defaultPort) "$formattedHost:$port" else formattedHost
        return "$scheme://$authority"
    }

    private fun hasExplicitPort(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.startsWith("[")) {
            return trimmed.contains("]:")
        }
        return trimmed.count { it == ':' } == 1 && trimmed.substringAfterLast(':').toIntOrNull() != null
    }

    internal fun parseDnsServer(dns: String): DnsServerSpec {
        val value = dns.trim()
        // Old backup placeholders are still supported as plain UDP addresses.
        if (value == "[ipv4]") return DnsServerSpec("udp", "1.1.1.1", 53)
        if (value == "[ipv6]") return DnsServerSpec("udp", "2606:4700:4700::1111", 53)
        val scheme = if (value.contains("://")) value.substringBefore("://").lowercase() else "udp"
        requireDns(scheme in supportedDnsTypes)
        val defaultPort = when (scheme) {
            "https" -> 443
            "tls", "quic" -> 853
            else -> 53
        }
        val spec = if (scheme == "https") {
            val uri = parseDnsUri(value)
            requireDns(uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null)
            requireDns(uri.rawAuthority?.endsWith(":") == false)
            DnsServerSpec(scheme, uri.host.removePrefix("[").removeSuffix("]"),
                if (uri.port == -1) defaultPort else uri.port,
                uri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query")
        } else {
            val raw = if (value.contains("://")) value.substringAfter("://") else value
            val (host, port) = parseHostAndPort(raw, defaultPort)
            DnsServerSpec(scheme, host, port)
        }
        requireDns(spec.serverPort in 1..65535 && isValidDnsHostOrIp(spec.server))
        return spec
    }

    private fun parseHostAndPort(raw: String, defaultPort: Int): Pair<String, Int> {
        val value = raw.trim()
        // An unbracketed IPv6 literal has no explicit port.
        if (!value.startsWith("[") && value.count { it == ':' } >= 2) {
            requireDns(isValidDnsHostOrIp(value))
            return value to defaultPort
        }
        val uri = parseDnsUri("dns://$value")
        requireDns(uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null &&
            uri.rawFragment == null && uri.rawPath.isNullOrEmpty() && !value.endsWith(":"))
        return uri.host.removePrefix("[").removeSuffix("]") to
            if (uri.port == -1) defaultPort else uri.port
    }

    private fun parseDnsUri(value: String): URI = try {
        URI(value)
    } catch (_: java.net.URISyntaxException) {
        throw LocalizedException.of(R.string.error_dns_invalid_format_generic)
    }

    private fun requireDns(valid: Boolean) {
        if (!valid) throw LocalizedException.of(R.string.error_dns_invalid_format_generic)
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
