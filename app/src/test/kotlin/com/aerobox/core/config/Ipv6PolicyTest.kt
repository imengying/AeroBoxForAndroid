package com.aerobox.core.config

import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.RoutingMode
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class Ipv6PolicyTest {
    private fun node(server: String) = ProxyNode(name = "test", type = ProxyType.SOCKS, server = server, port = 1080)

    @Test fun nodeEntranceCannotChangeWebsiteDnsOrImplicitlyEnableFakeIp() {
        for (mode in IPv6Mode.entries) {
            val configs = listOf("192.0.2.1", "2001:db8::1").map {
                JSONObject(ConfigGenerator.generateSingBoxConfig(node(it), RoutingMode.GLOBAL_PROXY, ipv6Mode = mode))
            }
            assertEquals(configs[0].getJSONObject("dns").toString(), configs[1].getJSONObject("dns").toString())
            assertEquals(configs[0].getJSONObject("route").toString(), configs[1].getJSONObject("route").toString())
            for (config in configs) {
                val servers = config.getJSONObject("dns").getJSONArray("servers")
                assertFalse((0 until servers.length()).any { servers.getJSONObject(it).getString("type") == "fakeip" })
                assertEquals(mode.domainStrategy(), config.getJSONObject("dns").getString("strategy"))
            }
        }
    }

    @Test fun ipv4WebsitesStillAllowIpv6DnsAndIpv6OnlyNodeEntrances() {
        val raw = ConfigGenerator.generateSingBoxConfig(node("proxy.example"), RoutingMode.GLOBAL_PROXY,
            directDns = "udp://[2001:db8::53]:5353", remoteDns = "tcp://[2001:db8::54]:5354", ipv6Mode = IPv6Mode.DISABLE)
        val config = JSONObject(raw)
        val dns = config.getJSONObject("dns")
        assertEquals("ipv4_only", dns.getString("strategy"))
        assertEquals("2001:db8::54", dns.getJSONArray("servers").getJSONObject(0).getString("server"))
        assertEquals("2001:db8::53", dns.getJSONArray("servers").getJSONObject(1).getString("server"))
        val resolver = config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("domain_resolver")
        assertEquals("prefer_ipv4", resolver.getString("strategy")) // Includes AAAA when no A exists.
        assertEquals(1, config.getJSONArray("inbounds").getJSONObject(0).getJSONArray("address").length())
        val test = JSONObject(ConfigGenerator.generateUrlTestConfig(node("proxy.example"), ipv6Mode = IPv6Mode.DISABLE))
        assertEquals(resolver.toString(), test.getJSONArray("outbounds").getJSONObject(0).getJSONObject("domain_resolver").toString())
        val domainDns = JSONObject(ConfigGenerator.generateSingBoxConfig(node("proxy.example"), RoutingMode.GLOBAL_PROXY,
            remoteDns = "https://dns.example/dns-query", ipv6Mode = IPv6Mode.DISABLE))
        assertEquals("prefer_ipv4", domainDns.getJSONObject("dns").getJSONArray("servers")
            .getJSONObject(0).getJSONObject("domain_resolver").getString("strategy"))
    }

    @Test fun fakeIpIsExplicitPreservesLocalAndBootstrapDnsAndPersistsMappings() {
        for (mode in IPv6Mode.entries) {
            val config = JSONObject(ConfigGenerator.generateSingBoxConfig(node("proxy.example"), RoutingMode.GLOBAL_PROXY,
                ipv6Mode = mode, enableFakeDns = true))
            val dns = config.getJSONObject("dns")
            val servers = dns.getJSONArray("servers")
            val fake = (0 until servers.length()).map(servers::getJSONObject).single { it.getString("type") == "fakeip" }
            assertEquals(mode.enablesIpv6Tun(), fake.has("inet6_range"))
            val rules = dns.getJSONArray("rules")
            assertEquals("proxy.example", rules.getJSONObject(0).getJSONArray("domain").getString(0))
            assertEquals("dns-direct", rules.getJSONObject(1).getString("server"))
            assertTrue(rules.getJSONObject(1).getJSONArray("domain_suffix").toString().contains("home.arpa"))
            assertEquals("[\"A\",\"AAAA\"]", rules.getJSONObject(2).getJSONArray("query_type").toString())
            assertEquals("[\"HTTPS\",\"SVCB\"]", rules.getJSONObject(3).getJSONArray("query_type").toString())
            assertEquals("predefined", rules.getJSONObject(3).getString("action"))
            assertEquals("NOERROR", rules.getJSONObject(3).getString("rcode"))
            assertTrue(config.getJSONObject("experimental").getJSONObject("cache_file").getBoolean("store_fakeip"))
        }
        val direct = JSONObject(ConfigGenerator.generateSingBoxConfig(node("2001:db8::1"), RoutingMode.DIRECT, enableFakeDns = true))
        assertFalse(direct.getJSONObject("dns").has("rules"))
        assertFalse(direct.getJSONObject("experimental").has("cache_file"))
    }
}
