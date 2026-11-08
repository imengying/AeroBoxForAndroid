package com.aerobox.data.repository

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackupCodecTest {
    private val settings = JSONObject().put("theme", "深色 🌙")
    private val group = JSONObject().put("id", 7L).put("name", "订阅")
    private val node = JSONObject().put("id", 42L).put("password", "fixture-only").put("optional", JSONObject.NULL)

    private fun encode(codec: BackupCodec, groups: Int = 1, nodes: Int = 1): ByteArray =
        codec.encode(2, "test", settings, (1..groups).asSequence().map { group }, (1..nodes).asSequence().map { node })

    @Test fun roundTripPreservesEnvelopeSettingsAndRows() {
        val codec = BackupCodec()
        val restored = codec.read(encode(codec).inputStream())
        assertEquals("aerobox-backup", restored.getString("format"))
        assertEquals(1, restored.getInt("version"))
        assertEquals(2, restored.getInt("schema"))
        assertEquals("test", restored.getString("appVersion"))
        assertEquals("深色 🌙", restored.getJSONObject("settings").getString("theme"))
        assertEquals(7L, restored.getJSONArray("subscriptions").getJSONObject(0).getLong("id"))
        val restoredNode = restored.getJSONArray("proxy_nodes").getJSONObject(0)
        assertEquals("fixture-only", restoredNode.getString("password"))
        assertTrue(restoredNode.isNull("optional"))
    }

    @Test fun byteLimitIsIdenticalForExportAndRestoreIncludingMultibyteText() {
        val bytes = encode(BackupCodec())
        assertTrue(bytes.size > bytes.toString(Charsets.UTF_8).length)
        val exact = BackupCodec(BackupLimits(maxBytes = bytes.size))
        assertArrayEquals(bytes, encode(exact))
        assertEquals(1, exact.read(bytes.inputStream()).getJSONArray("proxy_nodes").length())
        val tooSmall = BackupCodec(BackupLimits(maxBytes = bytes.size - 1))
        assertThrows(BackupLimitExceededException::class.java) { encode(tooSmall) }
        assertThrows(BackupLimitExceededException::class.java) { tooSmall.read(bytes.inputStream()) }
    }

    @Test fun rowLimitsAreIdenticalForExportAndRestore() {
        val codec = BackupCodec(BackupLimits(maxSubscriptions = 2, maxNodes = 3))
        val accepted = codec.read(encode(codec, groups = 2, nodes = 3).inputStream())
        assertEquals(2, accepted.getJSONArray("subscriptions").length())
        assertEquals(3, accepted.getJSONArray("proxy_nodes").length())
        for ((groups, nodes) in listOf(3 to 3, 2 to 4)) {
            assertThrows(BackupLimitExceededException::class.java) { encode(codec, groups, nodes) }
            val oversized = encode(BackupCodec(), groups, nodes)
            assertThrows(BackupLimitExceededException::class.java) { codec.read(oversized.inputStream()) }
        }
    }

    @Test fun exportStopsReadingRowsWhenSizeLimitIsReached() {
        var rowsRead = 0
        val rows = generateSequence {
            rowsRead++
            JSONObject().put("data", "x".repeat(1024))
        }
        assertThrows(BackupLimitExceededException::class.java) {
            BackupCodec(BackupLimits(maxBytes = 1024)).encode(2, "test", settings, emptySequence(), rows)
        }
        assertTrue("The entire table must not be materialized", rowsRead < 50)
    }
}
