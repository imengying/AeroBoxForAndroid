package com.aerobox.viewmodel.nodeeditor

import com.aerobox.R
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NodeEditDraftTest {
    private val node = ProxyNode(id = 42, name = "Example", type = ProxyType.VLESS,
        server = "example.invalid", port = 443, uuid = "11111111-2222-3333-4444-555555555555")

    @Test fun renamingPreservesHiddenOptionsAndMetadata() {
        val original = node.copy(subscriptionId = 7, latency = 30, createdAt = 123,
            tls = true, tlsClientKey = "  private\nkey  ", echConfig = "imported ECH",
            muxEnabled = true, muxMaxStreams = 8, transportType = "ws", transportHeaders = "X-Test: value",
            wsMaxEarlyData = 1024, tcpKeepAlive = "30s", fallbackNetworkType = "cellular")
        val draft = NodeEditDraft(original).change("name", " Renamed ")
        assertEquals(original.copy(name = "Renamed"), draft.node())
        assertTrue(draft.errors().isEmpty())
        assertFalse(draft.change("name", original.name).changed)
    }

    @Test fun passwordWhitespaceAndMultilineCertificatesArePreserved() {
        val original = node.copy(type = ProxyType.TROJAN, password = "original")
        val draft = NodeEditDraft(original).change("password", "  new secret  ")
            .change("tlsClientCertificate", "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
        assertEquals("  new secret  ", draft.node().password)
        assertTrue(draft.node().tlsClientCertificate!!.endsWith("\n"))
        assertTrue(draft.errors().isEmpty())
    }

    @Test fun invalidNumbersCannotSilentlyBecomeDefaults() {
        val original = node.copy(type = ProxyType.VMESS, alterId = 4)
        for (raw in listOf("", "0", "65536", "999999999999", "abc")) {
            assertTrue(raw, "port" in NodeEditDraft(original).change("port", raw).errors())
        }
        for (raw in listOf("-1", "999999999999", "1.5", "oops")) {
            assertEquals(R.string.node_edit_invalid_number, NodeEditDraft(original).change("alterId", raw).errors()["alterId"])
        }
        val valid = NodeEditDraft(original).change("port", " 80 ").change("alterId", " 0 ")
        assertTrue(valid.errors().isEmpty())
        assertEquals(80, valid.node().port)
        assertEquals(0, valid.node().alterId)
    }

    @Test fun headersSupportJsonAndLinesButRejectMalformedInput() {
        val original = node.copy(transportType = "ws")
        for (value in listOf("Host: example.invalid\nX-Token: value", "Host=example.invalid;X-Token=value",
            "{\"Host\":\"example.invalid\",\"X-Test\":[\"a\",\"b\"]}")) {
            assertTrue(value, NodeEditDraft(original).change("transportHeaders", value).errors().isEmpty())
        }
        for (value in listOf("broken header", "{not json}", "{\"Host\":false}", "{\"Host\":[1]}", "Bad Name: value", "   : value", "{\"Bad Name\":\"value\"}")) {
            assertEquals(value, R.string.node_edit_invalid_headers,
                NodeEditDraft(original).change("transportHeaders", value).errors()["transportHeaders"])
        }
    }

    @Test fun validationMatchesProtocolSpecificUuidRules() {
        for (type in listOf(ProxyType.VMESS, ProxyType.VLESS)) {
            assertTrue(NodeEditDraft(node.copy(type = type)).change("uuid", "custom-user-id").errors().isEmpty())
        }
        val tuic = node.copy(type = ProxyType.TUIC, password = "fixture")
        assertEquals(R.string.node_edit_invalid_uuid, NodeEditDraft(tuic).change("uuid", "bad-id").errors()["uuid"])
        assertTrue(NodeEditDraft(tuic).change("uuid", "11111111222233334444555555555555").errors().isEmpty())
    }

    @Test fun realityValidatesKeyShortIdAndServerName() {
        val key = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 1 })
        val draft = NodeEditDraft(node.copy(server = "192.0.2.1"))
            .change("publicKey", key).change("shortId", "abc")
        assertEquals(R.string.error_reality_requires_sni, draft.errors()["sni"])
        assertEquals(R.string.node_edit_invalid_short_id, draft.errors()["shortId"])
        assertTrue(draft.change("shortId", "aabb").change("sni", "example.invalid").errors().isEmpty())
        assertEquals(R.string.node_edit_invalid_public_key, draft.change("publicKey", "bad-key").errors()["publicKey"])
    }

    @Test fun switchingTransportKeepsHiddenValuesAndValidationFollowsActiveTransport() {
        val draft = NodeEditDraft(node.copy(transportType = "ws", transportPath = "/ws", wsMaxEarlyData = 1024))
            .change("transportHeaders", "invalid").change("transportType", "grpc")
        assertTrue(draft.errors().isEmpty())
        assertEquals("/ws", draft.node().transportPath)
        assertEquals(1024, draft.node().wsMaxEarlyData)
        assertTrue("transportHeaders" in draft.change("transportType", "ws").errors())
        val keys = NodeEditFields.all.filter { it.visible(draft.node()) }.map { it.key }
        assertTrue("transportServiceName" in keys)
        assertFalse("wsMaxEarlyData" in keys)
    }

    @Test fun advancedFieldsReachTheGeneratedOutbound() {
        val draft = NodeEditDraft(node.copy(tls = true, transportType = "ws"))
            .change("muxEnabled", "true").change("muxMaxStreams", "8")
            .change("echEnabled", "true").change("echConfig", "fixture-ech")
            .change("wsMaxEarlyData", "1024").change("wsEarlyDataHeaderName", "Sec-WebSocket-Protocol")
        val outbound = JSONObject(ConfigGenerator.exportNodes(listOf(draft.node()))).getJSONArray("outbounds").getJSONObject(0)
        assertEquals(8, outbound.getJSONObject("multiplex").getInt("max_streams"))
        assertTrue(outbound.getJSONObject("tls").getJSONObject("ech").getBoolean("enabled"))
        assertEquals(1024, outbound.getJSONObject("transport").getInt("max_early_data"))
    }

    @Test fun legacyNaiveQuicCanBeChangedWithoutLosingOtherFields() {
        val original = node.copy(type = ProxyType.NAIVE, username = "u", password = "p", transportType = "quic",
            naiveProtocol = null, naiveExtraHeaders = "X-Test: yes")
        assertEquals(original, NodeEditDraft(original).node())
        val draft = NodeEditDraft(original).change("naiveProtocol", "https")
        assertNull(draft.node().transportType)
        assertEquals("https", draft.node().naiveProtocol)
        assertEquals(original.naiveExtraHeaders, draft.node().naiveExtraHeaders)
    }

    @Test fun protocolsDoNotExposeUnsupportedOrConflictingOptions() {
        fun keys(n: ProxyNode) = NodeEditFields.all.filter { it.visible(n) }.map { it.key }
        assertFalse("tcpFastOpen" in keys(node.copy(type = ProxyType.ANYTLS)))
        assertFalse("fingerprint" in keys(node.copy(type = ProxyType.NAIVE)))
        assertFalse("allowInsecure" in keys(node.copy(type = ProxyType.NAIVE)))
        assertFalse("tlsClientKey" in keys(node.copy(type = ProxyType.NAIVE)))
        assertTrue("tlsCertificate" in keys(node.copy(type = ProxyType.NAIVE)))
        assertFalse("muxEnabled" in keys(node.copy(type = ProxyType.SHADOWSOCKS, udpOverTcpEnabled = true)))
        assertFalse("sni" in keys(node.copy(type = ProxyType.HTTP, tls = false)))
        assertTrue("publicKey" in keys(node.copy(tls = false)))
    }

    @Test fun hysteriaPortRangesAreCheckedBeforeSaving() {
        val original = node.copy(type = ProxyType.HYSTERIA2, password = "fixture")
        assertTrue(NodeEditDraft(original).change("serverPorts", "443, 1000 - 2000, 3000:4000").errors().isEmpty())
        for (raw in listOf("0", "80,", "2000:1000", "65536", "100-200-300")) {
            assertEquals(raw, R.string.node_edit_invalid_ports, NodeEditDraft(original).change("serverPorts", raw).errors()["serverPorts"])
        }
    }
}
