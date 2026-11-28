package com.aerobox.core.config

import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProbeNetworkPolicyTest {
    @Test fun editingAndProbingUseTheSamePhysicalNetworkPolicyAsVpn() {
        val base = ProxyNode(name = "SOCKS", type = ProxyType.SOCKS, server = "127.0.0.1", port = 1080)
        val nodes = listOf(
            base.copy(networkStrategy = "default"),
            base.copy(networkStrategy = "hybrid", networkType = "wifi,ethernet"),
            base.copy(networkStrategy = "fallback", networkType = "wifi", fallbackNetworkType = "cellular", fallbackDelay = "250ms"),
            base.copy(networkType = "wifi"),
            base.copy(fallbackNetworkType = "cellular"),
            base.copy(fallbackDelay = "500ms"),
        )
        for (node in nodes) {
            val probe = JSONObject(ConfigGenerator.generateUrlTestConfig(node))
            val vpn = JSONObject(ConfigGenerator.generateVpnConfig(node))
            assertTrue(probe.getJSONObject("route").getBoolean("auto_detect_interface"))
            assertEquals(0, probe.getJSONArray("inbounds").length())
            assertEquals("proxy", probe.getJSONObject("route").getString("final"))
            val probeNode = probe.getJSONArray("outbounds").getJSONObject(0)
            val vpnNode = vpn.getJSONArray("outbounds").getJSONObject(0)
            for (field in listOf("network_strategy", "network_type", "fallback_network_type", "fallback_delay")) {
                assertEquals(field, vpnNode.opt(field)?.toString(), probeNode.opt(field)?.toString())
            }
        }
    }
}
