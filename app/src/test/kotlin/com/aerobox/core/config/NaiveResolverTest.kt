package com.aerobox.core.config

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.RoutingMode
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NaiveResolverTest {
    @Test fun naiveIpAndDomainServersHaveAResolverInRuntimeAndValidationConfigs() {
        for (server in listOf("127.0.0.1", "2001:db8::1", "proxy.example.invalid")) {
            val node = ProxyNode(name = "Naive", type = ProxyType.NAIVE, server = server, port = 443,
                username = "fixture", password = "fixture", tls = true, sni = "example.invalid")
            val configs = listOf(
                ConfigGenerator.generateUrlTestConfig(node),
                ConfigGenerator.generateSingBoxConfig(node, routingMode = RoutingMode.GLOBAL_PROXY)
            )
            for (raw in configs) {
                val config = JSONObject(raw)
                val resolver = config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("domain_resolver")
                val servers = config.getJSONObject("dns").getJSONArray("servers")
                assertTrue((0 until servers.length()).any { servers.getJSONObject(it).getString("tag") == resolver.getString("server") })
            }
            assertFalse(JSONObject(ConfigGenerator.exportNodes(listOf(node)))
                .getJSONArray("outbounds").getJSONObject(0).has("domain_resolver"))
        }
    }

    @Test fun ordinaryIpOutboundsStillAvoidUnnecessaryServerResolution() {
        val node = ProxyNode(name = "SOCKS", type = ProxyType.SOCKS, server = "127.0.0.1", port = 1080)
        assertFalse(OutboundConfigBuilder.buildProxyOutbound(node).has("domain_resolver"))
    }
}
