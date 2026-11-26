package com.aerobox.core.native

import android.content.Context
import android.net.NetworkCapabilities
import android.util.Log
import com.aerobox.AeroBoxApplication
import com.aerobox.core.logging.CrashDiagnostics
import com.aerobox.core.logging.RuntimeLogBuffer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

/** App-scoped Rust initialization, configuration checks and temporary node probes. */
object RustCore {
    private const val TAG = "AeroBoxRustCore"
    @Volatile private var initialization: Deferred<Unit>? = null
    private lateinit var applicationContext: Context
    private val _version = MutableStateFlow("...")
    val version = _version.asStateFlow()

    @Synchronized
    fun initialize(context: Context, scope: CoroutineScope) {
        if (initialization != null) return
        applicationContext = context.applicationContext
        initialization = scope.async(Dispatchers.IO) {
            try {
                CrashDiagnostics.setCoreVersion("initializing")
                _version.value = RustCoreNative.initialize(
                    storage = File(applicationContext.noBackupFilesDir, "rust-core")
                ).getString("version")
                CrashDiagnostics.setCoreVersion(_version.value)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Throwable) {
                _version.value = "unavailable"
                RuntimeLogBuffer.appendError("Rust core initialization failed: ${error.message ?: error}")
                throw IllegalStateException("Rust core initialization failed", error)
            }
        }
    }
    suspend fun awaitReady() {
        checkNotNull(initialization) { "Rust core initialization has not been scheduled" }.await()
    }
    suspend fun checkConfig(configContent: String): String? = withContext(Dispatchers.IO) {
        awaitReady()
        try {
            // Remote-rule contents are verified at startup, as reported by
            // deferredRemoteRules. This check never starts a tunnel or listener.
            RustCoreNative.checkConfig(configContent)
            null
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) { error.message ?: "unknown error" }
    }

    private val probesLock = Any()
    private var standalone: PhysicalNetworkCallbacks? = null
    private var probeUsers = 0
    private fun acquireProbePlatform(): PhysicalNetworkCallbacks = synchronized(probesLock) {
        val platform = standalone ?: run {
            val connectivity = AeroBoxApplication.connectivity
            val network = connectivity.activeNetwork?.takeIf {
                connectivity.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
            } ?: error("No physical network available for latency test")
            PhysicalNetworkCallbacks(applicationContext, connectivity, network).also {
                try { it.startNetworkMonitoring() } catch (failure: Throwable) { it.close(); throw failure }
                standalone = it
            }
        }
        probeUsers++
        platform
    }
    private fun releaseProbePlatform(platform: PhysicalNetworkCallbacks) = synchronized(probesLock) {
        check(standalone === platform && probeUsers > 0)
        if (--probeUsers == 0) {
            standalone = null
            platform.close()
        }
    }

    suspend fun urlTestOutbound(
        configContent: String,
        outboundTag: String,
        testUrl: String,
        timeoutMs: Int,
        platformInterface: RustCoreNative.PlatformCallbacks?
    ): Int = withContext(Dispatchers.IO) {
        awaitReady()
        var temporary: PhysicalNetworkCallbacks? = null
        try {
            val platform = platformInterface ?: acquireProbePlatform().also { temporary = it }
            RustCoreNative.urlTestConfig(configContent, outboundTag, testUrl, timeoutMs.toLong(), platform)
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) {
            val message = error.message ?: "unknown error"
            Log.w(TAG, "urlTestOutbound failed: $message")
            RuntimeLogBuffer.appendError("urlTestOutbound failed: $message")
            -1
        } finally { temporary?.let(::releaseProbePlatform) }
    }
}
