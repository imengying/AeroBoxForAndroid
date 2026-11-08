package com.aerobox.data.repository

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStreamWriter
import org.json.JSONObject

internal data class BackupLimits(
    val maxBytes: Int = 32 * 1024 * 1024,
    val maxSubscriptions: Int = 10_000,
    val maxNodes: Int = 50_000
)

internal class BackupLimitExceededException : IOException("Backup limit exceeded")

/** The same byte and row limits apply in both directions, including UTF-8 encoding. */
internal class BackupCodec(private val limits: BackupLimits = BackupLimits()) {
    fun encode(
        schema: Int,
        appVersion: String,
        settings: JSONObject,
        subscriptions: Sequence<JSONObject>,
        nodes: Sequence<JSONObject>
    ): ByteArray {
        val output = BoundedOutput(limits.maxBytes)
        OutputStreamWriter(output, Charsets.UTF_8).buffered().use { writer ->
            val header = JSONObject().put("format", "aerobox-backup").put("version", 1)
                .put("schema", schema).put("appVersion", appVersion).put("settings", settings)
            writer.write(header.toString().dropLast(1))
            fun writeRows(name: String, rows: Sequence<JSONObject>, maximum: Int) {
                writer.write(",\"$name\":[")
                var count = 0
                rows.forEach { row ->
                    if (count >= maximum) throw BackupLimitExceededException()
                    if (count++ > 0) writer.write(",")
                    writer.write(row.toString())
                }
                writer.write("]")
            }
            writeRows("subscriptions", subscriptions, limits.maxSubscriptions)
            writeRows("proxy_nodes", nodes, limits.maxNodes)
            writer.write("}")
        }
        return output.toByteArray()
    }

    fun read(input: InputStream): JSONObject {
        val output = BoundedOutput(limits.maxBytes)
        input.copyTo(output)
        return JSONObject(output.toString(Charsets.UTF_8.name())).also { backup ->
            if (backup.getJSONArray("subscriptions").length() > limits.maxSubscriptions ||
                backup.getJSONArray("proxy_nodes").length() > limits.maxNodes
            ) throw BackupLimitExceededException()
        }
    }

    private class BoundedOutput(private val maximum: Int) : ByteArrayOutputStream() {
        override fun write(value: Int) {
            if (count >= maximum) throw BackupLimitExceededException()
            super.write(value)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (length > maximum - count) throw BackupLimitExceededException()
            super.write(bytes, offset, length)
        }
    }
}
