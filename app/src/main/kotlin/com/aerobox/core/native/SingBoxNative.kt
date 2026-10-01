package com.aerobox.core.native

import android.content.Context
import android.util.Log
import com.aerobox.core.logging.CrashDiagnostics
import com.aerobox.core.logging.RuntimeLogBuffer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

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
    @Volatile
    private var initialization: Deferred<Unit>? = null
    private val _version = MutableStateFlow("...")
    val version = _version.asStateFlow()

    data class OutboundTrafficStats(
        val uploadBytes: Long,
        val downloadBytes: Long
    )

    @Synchronized
    fun initialize(context: Context, scope: CoroutineScope) {
        if (initialization != null) return
        val appContext = context.applicationContext
        initialization = scope.async(Dispatchers.IO) {
            try {
                CrashDiagnostics.setCoreVersion("initializing")
                val options = SetupOptions().apply {
                    basePath = appContext.filesDir.absolutePath
                    workingPath = appContext.getDir("singbox", Context.MODE_PRIVATE).absolutePath
                    tempPath = appContext.cacheDir.absolutePath
                    debug = true
                    logMaxLines = 300
                }
                Libbox.setup(options)
                _version.value = Libbox.version()
                CrashDiagnostics.setCoreVersion(_version.value)
                initialized = true
            } catch (error: CancellationException) {
                throw error
            } catch (error: Throwable) {
                _version.value = "unavailable"
                RuntimeLogBuffer.appendError("libbox initialization failed: ${error.message ?: error}")
                throw IllegalStateException("libbox initialization failed", error)
            }
        }
    }

    suspend fun awaitReady() {
        checkNotNull(initialization) { "libbox initialization has not been scheduled" }.await()
    }

    /**
     * Validate a sing-box JSON config. Returns null on success, error message on failure.
     */
    suspend fun checkConfig(configContent: String): String? = withContext(Dispatchers.IO) {
        awaitReady()
        try {
            Libbox.checkConfig(configContent)
            null // success
        } catch (e: Exception) {
            e.message ?: "unknown error"
        }
    }

    suspend fun urlTestOutbound(
        configContent: String,
        outboundTag: String = "proxy",
        testUrl: String = "http://cp.cloudflare.com/",
        timeoutMs: Int = 3000,
        platformInterface: PlatformInterface? = null
    ): Int = withContext(Dispatchers.IO) {
        awaitReady()
        try {
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
            RuntimeLogBuffer.appendError("urlTestOutbound failed: $msg")
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
                RuntimeLogBuffer.appendError("queryV2RayOutboundStats failed: $msg")
            }
            null
        }
    }

    fun closeV2RayOutboundStats() {
        if (!initialized) return
        runCatching { Libbox.closeV2RayOutboundStats() }
    }
}
