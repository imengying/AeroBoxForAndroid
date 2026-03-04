package com.aerobox.core.config

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.RoutingMode
import org.json.JSONArray
import org.json.JSONObject

object ConfigGenerator {

    fun generateSingBoxConfig(
        node: ProxyNode,
        routingMode: RoutingMode = RoutingMode.RULE_BASED,
        remoteDns: String = "tls://8.8.8.8",
        localDns: String = "223.5.5.5",
        enableDoh: Boolean = true,
        enableSocksInbound: Boolean = false,
        enableHttpInbound: Boolean = false
    ): String {
        val config = JSONObject()

        config.put(
            "log",
            JSONObject()
                .put("level", "info")
                .put("timestamp", true)
        )

        config.put("dns", buildDns(remoteDns, localDns, enableDoh, routingMode))
        config.put("inbounds", buildInbounds(enableSocksInbound, enableHttpInbound))

        val proxyOutbound = buildProxyOutbound(node).put("tag", "proxy")
        config.put(
            "outbounds",
            JSONArray()
                .put(proxyOutbound)
                .put(JSONObject().put("type", "direct").put("tag", "direct"))
                .put(JSONObject().put("type", "block").put("tag", "block"))
                .put(JSONObject().put("type", "dns").put("tag", "dns-out"))
        )

        config.put("route", buildRoute(routingMode))

        return config.toString(2)
    }

    // ── DNS ──────────────────────────────────────────────────────────

    private fun buildDns(
        remoteDns: String,
        localDns: String,
        enableDoh: Boolean,
        routingMode: RoutingMode
    ): JSONObject {
        val remoteAddress = if (enableDoh && !remoteDns.startsWith("tls://") && !remoteDns.startsWith("https://")) {
            "tls://$remoteDns"
        } else {
            remoteDns
        }

        val servers = JSONArray()
            .put(
                JSONObject()
                    .put("tag", "remote")
                    .put("address", remoteAddress)
            )
            .put(
                JSONObject()
                    .put("tag", "local")
                    .put("address", localDns)
                    .put("detour", "direct")
            )

        val dns = JSONObject().put("servers", servers)

        // Only add DNS routing rules for rule-based modes
        if (routingMode == RoutingMode.RULE_BASED || routingMode == RoutingMode.GFW_LIST) {
            dns.put(
                "rules",
                JSONArray().put(
                    JSONObject()
                        .put("geosite", "cn")
                        .put("server", "local")
                )
            )
        }

        return dns
    }

    // ── Inbounds ─────────────────────────────────────────────────────

    private fun buildInbounds(
        enableSocks: Boolean,
        enableHttp: Boolean
    ): JSONArray {
        val inbounds = JSONArray()

        // TUN (always present)
        inbounds.put(
            JSONObject()
                .put("type", "tun")
                .put("interface_name", "tun0")
                .put("inet4_address", JSONArray().put("172.19.0.1/30"))
                .put("mtu", 9000)
                .put("auto_route", true)
                .put("strict_route", true)
                .put("stack", "mixed")
                .put("sniff", true)
        )

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

    private fun buildRoute(routingMode: RoutingMode): JSONObject {
        val route = JSONObject()
            .put("auto_detect_interface", true)

        when (routingMode) {
            RoutingMode.GLOBAL_PROXY -> {
                route.put("final", "proxy")
                route.put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("protocol", "dns")
                            .put("outbound", "dns-out")
                    )
                )
            }

            RoutingMode.RULE_BASED -> {
                route.put("final", "proxy")
                route.put(
                    "rules",
                    JSONArray()
                        .put(
                            JSONObject()
                                .put("protocol", "dns")
                                .put("outbound", "dns-out")
                        )
                        .put(
                            JSONObject()
                                .put("geosite", JSONArray().put("cn"))
                                .put("geoip", JSONArray().put("cn"))
                                .put("outbound", "direct")
                        )
                        .put(
                            JSONObject()
                                .put("geosite", JSONArray().put("category-ads-all"))
                                .put("outbound", "block")
                        )
                )
            }

            RoutingMode.DIRECT -> {
                route.put("final", "direct")
                route.put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("protocol", "dns")
                            .put("outbound", "dns-out")
                    )
                )
            }

            RoutingMode.GFW_LIST -> {
                route.put("final", "direct")
                route.put(
                    "rules",
                    JSONArray()
                        .put(
                            JSONObject()
                                .put("protocol", "dns")
                                .put("outbound", "dns-out")
                        )
                        .put(
                            JSONObject()
                                .put("geosite", JSONArray().put("gfw"))
                                .put("outbound", "proxy")
                        )
                        .put(
                            JSONObject()
                                .put("geosite", JSONArray().put("category-ads-all"))
                                .put("outbound", "block")
                        )
                )
            }
        }

        return route
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
                outbound.put("tls", buildTlsObject(node))
            }

            ProxyType.VLESS -> {
                outbound.put("type", "vless")
                outbound.put("uuid", node.uuid ?: "")
                node.flow?.let { outbound.put("flow", it) }
                outbound.put("tls", buildTlsObject(node, includeReality = true))
            }

            ProxyType.TROJAN -> {
                outbound.put("type", "trojan")
                outbound.put("password", node.password ?: "")
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

            ProxyType.WIREGUARD -> {
                outbound.put("type", "wireguard")
                node.privateKey?.let { outbound.put("private_key", it) }
                node.localAddress?.let {
                    outbound.put("local_address", JSONArray().put(it))
                }
                node.mtu?.let { outbound.put("mtu", it) }
                if (!node.reserved.isNullOrBlank()) {
                    // reserved can be "1,2,3" or a base64 string
                    val parts = node.reserved!!.split(",")
                    if (parts.size == 3 && parts.all { it.trim().toIntOrNull() != null }) {
                        val arr = JSONArray()
                        parts.forEach { arr.put(it.trim().toInt()) }
                        outbound.put("reserved", arr)
                    }
                }
                // Peer configuration
                val peer = JSONObject()
                    .put("server", node.server)
                    .put("server_port", node.port)
                node.peerPublicKey?.let { peer.put("public_key", it) }
                    ?: node.publicKey?.let { peer.put("public_key", it) }
                node.preSharedKey?.let { peer.put("pre_shared_key", it) }
                peer.put("allowed_ips", JSONArray().put("0.0.0.0/0").put("::/0"))
                outbound.put("peers", JSONArray().put(peer))
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

        node.network?.let { outbound.put("network", it) }
        return outbound
    }

    private fun buildTlsObject(node: ProxyNode, includeReality: Boolean = false): JSONObject {
        val tls = JSONObject()
            .put("enabled", node.tls)
        node.sni?.let { tls.put("server_name", it) }

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
}
