package com.aerobox.core.`native`

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class ConnectionSnapshotsTest {
    @Test fun rowsKeepRoutedOutboundAndConnectionDetails() {
        val source = JSONArray()
        listOf(
            JSONArray().put("client-1").put("proxy"),
            JSONArray().put("direct").put("__aerobox_direct"),
            JSONArray().put("DIRECT"),
            JSONArray()
        ).forEachIndexed { index, chain ->
            source.put(JSONObject()
                .put("id", "flow-$index")
                .put("chains", chain)
                .put("rulePayload", "destination_port=443")
                .put("upload", 123L)
                .put("download", 456L)
                .put("metadata", JSONObject()
                    .put("network", "tcp")
                    .put("sourceIP", "fd00::1").put("sourcePort", "12345")
                    .put("destinationIP", "2001:db8::1").put("destinationPort", "443")
                    .put("sniffHost", "example.test")
                    .put("process", "com.example.browser")))
        }
        val rows = JSONArray(connectionSnapshotRows(source))
        assertEquals(listOf("proxy", "direct", "direct", ""),
            (0 until rows.length()).map { rows.getJSONObject(it).getString("outbound") })
        val first = rows.getJSONObject(0)
        assertEquals("flow-0", first.getString("id"))
        assertEquals("[fd00::1]:12345", first.getString("source"))
        assertEquals("[2001:db8::1]:443", first.getString("destination"))
        assertEquals("example.test", first.getString("domain"))
        assertEquals("com.example.browser", first.getString("process"))
        assertEquals("destination_port=443", first.getString("rule"))
        assertEquals(123L, first.getLong("upload"))
        assertEquals(456L, first.getLong("download"))
    }
}
