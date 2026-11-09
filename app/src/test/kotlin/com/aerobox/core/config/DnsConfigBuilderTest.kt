package com.aerobox.core.config

import com.aerobox.core.errors.LocalizedException
import com.aerobox.data.model.IPv6Mode
import com.aerobox.data.model.RoutingMode
import org.junit.Assert.*
import org.junit.Test

class DnsConfigBuilderTest {
    @Test fun supportedEndpointsPreserveTheirProtocolHostAndPort() {
        val cases = mapOf(
            "1.1.1.1" to Triple("udp", "1.1.1.1", 53),
            "resolver.example:5353" to Triple("udp", "resolver.example", 5353),
            "2001:db8::53" to Triple("udp", "2001:db8::53", 53),
            "[2001:db8::53]:5353" to Triple("udp", "2001:db8::53", 5353),
            "udp://1.1.1.1:5353" to Triple("udp", "1.1.1.1", 5353),
            "tcp://[2001:db8::53]:5353" to Triple("tcp", "2001:db8::53", 5353),
            "tls://resolver.example" to Triple("tls", "resolver.example", 853),
            "quic://resolver.example:8853" to Triple("quic", "resolver.example", 8853),
            "https://resolver.example:8443/custom-dns" to Triple("https", "resolver.example", 8443)
        )
        for ((address, expected) in cases) {
            val actual = DnsConfigBuilder.parseDnsServer(address)
            assertEquals(address, expected, Triple(actual.type, actual.server, actual.serverPort))
        }
        assertEquals("/custom-dns", DnsConfigBuilder.parseDnsServer(cases.keys.last()).path)
        assertEquals("/dns-query", DnsConfigBuilder.parseDnsServer("https://resolver.example").path)
    }

    @Test fun malformedAddressesCannotSilentlyBecomeValidUdpServers() {
        for (address in listOf(
            "invalid://dns", "http://resolver.example/dns-query", "udp://1.1.1.1/path",
            "udp://user@1.1.1.1", "https://user@1.1.1.1/dns-query", "1.1.1.1#fragment",
            "1.1.1.1:0", "1.1.1.1:-1", "1.1.1.1:65536", "1.1.1.1:abc", "1.1.1.1:",
            "https://1.1.1.1:0/dns-query", "https://1.1.1.1:abc/dns-query", "https://",
            "udp://999.1.1.1", "2001:::53", "[2001:db8::53]:0", "resolver name"
        )) {
            try {
                DnsConfigBuilder.parseDnsServer(address)
                fail("Accepted malformed DNS endpoint: $address")
            } catch (_: LocalizedException) { }
        }
    }

    @Test fun normalizationDoesNotHideBadPortsOrSchemesOrRewriteDirectDns() {
        for (fakeDns in listOf(false, true)) {
            for (address in listOf("https://1.1.1.1:0/dns-query", "tls://1.1.1.1:0", "invalid://dns")) {
                for (remote in listOf(false, true)) {
                    try {
                        DnsConfigBuilder.buildDns(
                            if (remote) address else "https://cloudflare-dns.com/dns-query",
                            if (remote) "udp://223.5.5.5" else address,
                            RoutingMode.GLOBAL_PROXY, false, IPv6Mode.ENABLE, fakeDns
                        )
                        fail("Normalization accepted $address")
                    } catch (_: LocalizedException) { }
                }
            }
        }
        val dns = DnsConfigBuilder.buildDns("https://1.1.1.1/dns-query", "udp://223.5.5.5:5353",
            RoutingMode.GLOBAL_PROXY, false, IPv6Mode.ENABLE, true)
        assertEquals("cloudflare-dns.com", dns.getJSONArray("servers").getJSONObject(0).getString("server"))
        assertEquals("223.5.5.5", dns.getJSONArray("servers").getJSONObject(1).getString("server"))
        assertEquals(5353, dns.getJSONArray("servers").getJSONObject(1).getInt("server_port"))
    }
}
