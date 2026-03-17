package com.aerobox.core.logging

import android.content.Context
import android.util.Log
import com.aerobox.data.model.ProxyNode
import org.json.JSONObject
import java.io.File

object ConfigSnapshotWriter {
    private const val TAG = "ConfigSnapshotWriter"
    private const val CONFIG_FILE_NAME = "last-runtime-config.json"
    private const val METADATA_FILE_NAME = "last-runtime-config.meta.json"

    fun writeCurrentConfig(
        context: Context,
        node: ProxyNode,
        config: String,
        source: String
    ): File? {
        val debugDir = resolveDebugDirectory(context) ?: run {
            RuntimeLogBuffer.append("warn", "Config snapshot skipped: no writable debug directory")
            return null
        }

        return runCatching {
            if (!debugDir.exists()) {
                debugDir.mkdirs()
            }

            val configFile = File(debugDir, CONFIG_FILE_NAME)
            configFile.writeText(config)

            val metadataFile = File(debugDir, METADATA_FILE_NAME)
            metadataFile.writeText(
                JSONObject()
                    .put("timestamp", System.currentTimeMillis())
                    .put("source", source)
                    .put("nodeId", node.id)
                    .put("nodeName", node.name)
                    .put("nodeType", node.type.name)
                    .put("configPath", configFile.absolutePath)
                    .toString(2)
            )

            Log.w(TAG, "Saved current config snapshot to ${configFile.absolutePath}")
            RuntimeLogBuffer.append("info", "Config snapshot saved: ${configFile.absolutePath}")
            configFile
        }.onFailure {
            Log.e(TAG, "Failed to save config snapshot", it)
            RuntimeLogBuffer.append("warn", "Config snapshot save failed: ${it.message ?: it}")
        }.getOrNull()
    }

    private fun resolveDebugDirectory(context: Context): File? {
        val externalDir = context.getExternalFilesDir("debug")
        if (externalDir != null) {
            return externalDir
        }
        return context.filesDir?.let { File(it, "debug") }
    }
}
