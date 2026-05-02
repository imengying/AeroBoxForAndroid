package com.aerobox.core.config

import android.content.Context
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.RoutingMode
import org.json.JSONArray
import org.json.JSONObject

/**
 * Top-level entry point for generating sing-box JSON configurations.
 *
 * Heavy-lifting is delegated to:
 * - [DnsConfigBuilder] — DNS server/rule construction
 * - [RouteConfigBuilder] — routing rule construction
 * - [OutboundConfigBuilder] — proxy outbound construction
 */
object ConfigGenerator {
    internal const val PROXY_OUTBOUND_TAG = "proxy"
    internal const val DNS_LOCAL_TAG = "dns-local"
    internal const val DNS_DIRECT_TAG = "dns-direct"
    internal const val DNS_REMOTE_TAG = "dns-remote"
    internal const val DNS_BOOTSTRAP_TAG = "dns-bootstrap"
    internal const val DNS_FAKE_TAG = "dns-fake"
    private const val DEFAULT_TUN_MTU = 9000
    const val V2RAY_API_LISTEN = "127.0.0.1:10085"

    fun validateDnsSettings(
        context: Context,
        remoteDns: String,
        directDns: String,
        ipv6Mode: IPv6Mode = IPv6Mode.ENABLE,
        nodeIsIpv6Only: Boolean = false
    ): String? {
        return DnsConfigBuilder.validateDnsSettings(context, remoteDns, directDns, ipv6Mode, nodeIsIpv6Only)
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
            DnsConfigBuilder.buildDns(
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

        val proxyOutbound = OutboundConfigBuilder.buildProxyOutbound(node).put("tag", PROXY_OUTBOUND_TAG)
        val shadowTlsCompanion = OutboundConfigBuilder.buildShadowTlsCompanion(node, PROXY_OUTBOUND_TAG)
        if (shadowTlsCompanion != null) {
            proxyOutbound.put("detour", shadowTlsCompanion.getString("tag"))
        }
        val outboundsArray = JSONArray().put(proxyOutbound)
        shadowTlsCompanion?.let { outboundsArray.put(it) }
        outboundsArray.put(JSONObject().put("type", "direct").put("tag", "direct"))
        config.put("outbounds", outboundsArray)

        config.put(
            "route",
            RouteConfigBuilder.buildRoute(
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
            DnsConfigBuilder.buildDns(
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

        val proxyOutbound = OutboundConfigBuilder.buildProxyOutbound(node).put("tag", PROXY_OUTBOUND_TAG)
        val shadowTlsCompanion = OutboundConfigBuilder.buildShadowTlsCompanion(node, PROXY_OUTBOUND_TAG)
        if (shadowTlsCompanion != null) {
            proxyOutbound.put("detour", shadowTlsCompanion.getString("tag"))
        }
        val urlTestOutbounds = JSONArray().put(proxyOutbound)
        shadowTlsCompanion?.let { urlTestOutbounds.put(it) }
        urlTestOutbounds.put(JSONObject().put("type", "direct").put("tag", "direct"))
        config.put("outbounds", urlTestOutbounds)

        config.put(
            "route",
            JSONObject()
                .put("auto_detect_interface", false)
                .put("final", PROXY_OUTBOUND_TAG)
        )

        return config.toString(2)
    }

    // ── Public utility methods ──────────────────────────────────────

    fun normalizedServerHost(server: String): String = normalizeOutboundServer(server)

    fun isIpv6ServerLiteral(server: String): Boolean = isIpv6Literal(server)

    fun isIpLiteralHost(host: String): Boolean = isIpLiteral(host)

    // ── Shared internal utilities ───────────────────────────────────

    internal fun normalizeOutboundServer(server: String): String {
        return server
            .replace("[ipv4]", "")
            .replace("[ipv6]", "")
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
            .trim()
    }

    internal fun isIpLiteral(server: String): Boolean {
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

    internal fun isIpv6Literal(server: String): Boolean {
        val normalized = server.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        return normalized.contains(':') &&
            normalized.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
    }

    // ── Private helpers ─────────────────────────────────────────────

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
            .put("stack", "mixed")

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
}
