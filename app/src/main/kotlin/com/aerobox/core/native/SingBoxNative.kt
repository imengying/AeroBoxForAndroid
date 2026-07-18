package com.aerobox.core.native

import android.content.Context
import android.util.Log
import com.aerobox.core.logging.RuntimeLogBuffer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions

/**
 * Wrapper around gomobile-generated libbox Java bindings.
 *
 * Uses direct imports of `io.nekohasekai.libbox.*` classes
 * generated from sing-box via gomobile/gobind.
 */
object SingBoxNative {

    private const val TAG = "SingBoxNative"
    @Volatile
    private var initialized = false

    data class OutboundTrafficStats(
        val uploadBytes: Long,
        val downloadBytes: Long
    )

    /**
     * Initialize libbox with app paths. Must be called once at startup.
     */
    fun setup(context: Context) {
        if (initialized) return
        try {
            val options = SetupOptions().apply {
                basePath = context.filesDir.absolutePath
                workingPath = context.getDir("singbox", Context.MODE_PRIVATE).absolutePath
                tempPath = context.cacheDir.absolutePath
                debug = true
                logMaxLines = 300
            }
            Libbox.setup(options)
            initialized = true
            Log.i(TAG, "libbox ${Libbox.version()} setup completed")
        } catch (e: Exception) {
            Log.w(TAG, "libbox setup failed: ${e.message}")
        }
    }

    /**
     * Validate a sing-box JSON config. Returns null on success, error message on failure.
     */
    fun checkConfig(configContent: String): String? {
        if (!initialized) {
            val msg = "libbox not initialized — cannot validate config"
            Log.e(TAG, msg)
            return msg
        }
        return try {
            Libbox.checkConfig(configContent)
            null // success
        } catch (e: Exception) {
            val msg = e.message ?: "unknown error"
            Log.w(TAG, "checkConfig failed: $msg")
            msg
        }
    }

    /**
     * Get the sing-box version string.
     */
    fun getVersion(): String {
        if (!initialized) return "unknown (not initialized)"
        return try {
            Libbox.version()
        } catch (e: Exception) {
            "unknown"
        }
    }

    fun urlTestOutbound(
        configContent: String,
        outboundTag: String = "proxy",
        testUrl: String = "http://cp.cloudflare.com/",
        timeoutMs: Int = 3000,
        platformInterface: PlatformInterface? = null
    ): Int {
        if (!initialized) {
            Log.e(TAG, "libbox not initialized — cannot run URL test")
            RuntimeLogBuffer.append("error", "libbox not initialized — cannot run URL test")
            return -1
        }
        return try {
            if (platformInterface != null) {
                Libbox.urlTestOutboundWithPlatform(
                    configContent,
                    outboundTag,
                    testUrl,
                    timeoutMs,
                    platformInterface
                )
            } else {
                Libbox.urlTestOutbound(configContent, outboundTag, testUrl, timeoutMs)
            }
        } catch (e: Exception) {
            val msg = e.message ?: "unknown error"
            Log.w(TAG, "urlTestOutbound failed: $msg")
            RuntimeLogBuffer.append("error", "urlTestOutbound failed: $msg")
            -1
        }
    }

    fun queryV2RayOutboundStats(
        apiAddress: String,
        outboundTags: List<String>,
        logErrors: Boolean = true
    ): OutboundTrafficStats? {
        if (outboundTags.isEmpty()) return OutboundTrafficStats(0L, 0L)
        if (!initialized) {
            if (logErrors) Log.e(TAG, "libbox not initialized — cannot query stats")
            return null
        }
        return try {
            val raw = Libbox.queryV2RayOutboundStats(
                apiAddress,
                outboundTags.joinToString(",")
            )
            val parts = raw.split(",", limit = 2)
            val upload = parts.getOrNull(0)?.trim()?.toLongOrNull() ?: 0L
            val download = parts.getOrNull(1)?.trim()?.toLongOrNull() ?: 0L
            OutboundTrafficStats(upload, download)
        } catch (e: Exception) {
            val msg = e.message ?: "unknown error"
            if (logErrors) {
                Log.w(TAG, "queryV2RayOutboundStats failed: $msg")
                RuntimeLogBuffer.append("error", "queryV2RayOutboundStats failed: $msg")
            }
            null
        }
    }

    fun closeV2RayOutboundStats() {
        if (!initialized) return
        runCatching { Libbox.closeV2RayOutboundStats() }
    }
}
