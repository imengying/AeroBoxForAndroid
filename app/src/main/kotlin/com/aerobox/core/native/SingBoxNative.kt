package com.aerobox.core.native

import android.content.Context
import android.util.Log
import com.aerobox.core.logging.RuntimeLogBuffer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions

/**
 * Wrapper around gomobile-generated libbox Java bindings.
 *
 * Uses direct imports of `io.nekohasekai.libbox.*` classes
 * generated from sing-box via gomobile/gobind.
 */
object SingBoxNative {

    private const val TAG = "SingBoxNative"
    private var initialized = false

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
        return try {
            Libbox.version()
        } catch (e: Exception) {
            "unknown"
        }
    }

    fun urlTestOutbound(
        configContent: String,
        outboundTag: String = "proxy",
        testUrl: String = "https://www.gstatic.com/generate_204",
        timeoutMs: Int = 3000
    ): Int {
        return try {
            Libbox.urlTestOutbound(configContent, outboundTag, testUrl, timeoutMs).toInt()
        } catch (e: Exception) {
            val msg = e.message ?: "unknown error"
            Log.w(TAG, "urlTestOutbound failed: $msg")
            RuntimeLogBuffer.append("error", "urlTestOutbound failed: $msg")
            -1
        }
    }
}
