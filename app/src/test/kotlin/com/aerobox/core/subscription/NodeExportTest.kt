package com.aerobox.core.subscription

import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.connectionFingerprint
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NodeExportTest {
    private val node = ProxyNode(name = "香港 A", type = ProxyType.SHADOWSOCKS,
        server = "192.0.2.1", port = 443, password = "fixture-only", method = "aes-128-gcm")

    @Test fun exportRoundTripKeepsNamesAndDistinctAliases() {
        val original = listOf(node, node.copy(name = "香港 B"))
        val exported = ConfigGenerator.exportNodes(original)
        val restored = JsonNodeParser.parseJsonContent(exported).nodes
        assertEquals(original.map { it.name }, restored.map { it.name })
        // The import pipeline deduplicates on this fingerprint, including the name.
        assertEquals(2, restored.distinctBy { it.connectionFingerprint() }.size)
        assertEquals(original.map { it.connectionFingerprint() }, restored.map { it.connectionFingerprint() })
    }

    @Test fun existingNameAndPsFieldsTakePrecedenceOverTag() {
        val outbound = JSONObject(ConfigGenerator.exportNodes(listOf(node))).getJSONArray("outbounds").getJSONObject(0)
        outbound.put("name", "Explicit name").put("ps", "VMess name")
        assertEquals("Explicit name", JsonNodeParser.parseJsonContent(outbound.toString()).nodes.single().name)
        outbound.put("name", " ")
        assertEquals("VMess name", JsonNodeParser.parseJsonContent(outbound.toString()).nodes.single().name)
        outbound.put("ps", JSONObject.NULL)
        assertEquals(node.name, JsonNodeParser.parseJsonContent(outbound.toString()).nodes.single().name)
        outbound.remove("tag")
        assertEquals("SHADOWSOCKS", JsonNodeParser.parseJsonContent(outbound.toString()).nodes.single().name)
    }
}
