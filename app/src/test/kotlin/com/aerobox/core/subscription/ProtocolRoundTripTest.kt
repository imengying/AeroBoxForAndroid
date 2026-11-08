package com.aerobox.core.subscription

import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.connectionFingerprint
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class ProtocolRoundTripTest(private val label: String, private val original: ProxyNode) {
    @Test fun exportImportPreservesProtocolCredentialsAndConnectionOptions() {
        val first = ConfigGenerator.exportNodes(listOf(original))
        val restored = JsonNodeParser.parseJsonContent(first).nodes.single()
        assertEquals(original.type, restored.type)
        assertEquals(original.name, restored.name)
        assertEquals(original.server, restored.server)
        assertEquals(original.port, restored.port)
        assertEquals(original.password, restored.password)
        assertEquals(original.uuid, restored.uuid)
        assertEquals(original.username, restored.username)
        assertEquals(original.sni, restored.sni)
        assertEquals(original.transportType, restored.transportType)
        assertEquals(original.transportPath, restored.transportPath)
        assertEquals(original.publicKey, restored.publicKey)
        assertEquals(original.obfsPassword, restored.obfsPassword)
        assertEquals(original.congestionControl, restored.congestionControl)
        val again = ConfigGenerator.exportNodes(listOf(restored))
        assertEquals(canonical(JSONObject(first)), canonical(JSONObject(again)))
        val twice = JsonNodeParser.parseJsonContent(again).nodes.single()
        assertEquals(restored.connectionFingerprint(), twice.connectionFingerprint())
    }

    private fun canonical(value: Any?): Any? = when (value) {
        is JSONObject -> value.keys().asSequence().sorted().associateWith { canonical(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { canonical(value.get(it)) }
        else -> value
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun cases(): List<Array<Any>> {
            fun node(type: ProxyType) = ProxyNode(name = "节点 ${type.name}", type = type,
                server = "192.0.2.1", port = 443, connectTimeout = "5s", tcpFastOpen = true)
            val id = "11111111-2222-3333-4444-555555555555"
            val cases = listOf(
                node(ProxyType.SHADOWSOCKS).copy(password = "fixture", method = "aes-128-gcm", udpOverTcpEnabled = true, udpOverTcpVersion = 2),
                node(ProxyType.SHADOWSOCKS_2022).copy(password = "AAAAAAAAAAAAAAAAAAAAAA==", method = "2022-blake3-aes-128-gcm"),
                node(ProxyType.VMESS).copy(uuid = id, security = "auto", globalPadding = true, authenticatedLength = true,
                    tls = true, sni = "example.invalid", transportType = "ws", transportPath = "/ws", transportHost = "example.invalid"),
                node(ProxyType.VLESS).copy(uuid = id, flow = "xtls-rprx-vision", tls = true, sni = "example.invalid",
                    publicKey = "fixture-public-key", shortId = "0123456789abcdef", fingerprint = "chrome"),
                node(ProxyType.TROJAN).copy(password = "fixture", tls = true, sni = "example.invalid",
                    transportType = "grpc", transportServiceName = "test", grpcPermitWithoutStream = true),
                node(ProxyType.ANYTLS).copy(password = "fixture", tls = true, sni = "example.invalid"),
                node(ProxyType.HYSTERIA2).copy(password = "fixture", tls = true, sni = "example.invalid",
                    obfsType = "salamander", obfsPassword = "obfs-fixture", upMbps = 10, downMbps = 50),
                node(ProxyType.TUIC).copy(uuid = id, password = "fixture", tls = true, sni = "example.invalid",
                    congestionControl = "bbr", udpRelayMode = "native", heartbeat = "10s"),
                node(ProxyType.SOCKS).copy(username = "fixture-user", password = "fixture", socksVersion = "5"),
                node(ProxyType.HTTP).copy(username = "fixture-user", password = "fixture", tls = true, sni = "example.invalid"),
                node(ProxyType.NAIVE).copy(username = "fixture-user", password = "fixture", tls = true,
                    sni = "example.invalid", naiveProtocol = "https"),
                node(ProxyType.NAIVE).copy(username = "fixture-user", password = "fixture", tls = true,
                    sni = "example.invalid", naiveProtocol = "quic", transportType = "quic", congestionControl = "bbr")
            )
            return cases.map { arrayOf(it.type.name + (it.naiveProtocol?.let { protocol -> "-$protocol" } ?: ""), it) }
        }
    }
}
