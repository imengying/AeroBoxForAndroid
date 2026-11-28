package com.aerobox.core.`native`

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.TimeUnit
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.withLock

/**
 * Owns the Rust core, Android TUN and network monitoring for a VPN session.
 * Start, stop and network changes run on IO workers. stop may run concurrently
 * with startOrReloadService to interrupt native startup.
 */
class RustVpnSession(
    service: VpnService,
    connectivity: ConnectivityManager,
    initialNetwork: PhysicalNetwork,
    private val onNetworkRefreshFailure: (Throwable) -> Unit = {
        Log.w("AeroBoxRustVpn", "Physical network refresh failed", it)
    },
) : AutoCloseable {
    val platform = VpnPlatformCallbacks(service, connectivity, initialNetwork)
    private val tunnels = RustTunController(service)
    private val lifecycle = ReentrantLock()
    private val networkLock = Any()
    private val networkRevision = AtomicLong()
    private val stopping = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private var networkWorker: ExecutorService? = null
    private var networkWorkQueued = false
    private var networkWorkId = 0L
    private var networkWorkerEpoch = 0L
    private val insideNetworkWorker = ThreadLocal<Boolean>()
    private var descriptor: ParcelFileDescriptor? = null
    @Volatile private var network: PhysicalNetwork? = initialNetwork
    @Volatile private var active = false

    /** A node switch deliberately starts a fresh TUN and resets its traffic totals. */
    fun startOrReloadService(config: String, applications: RustTunController.Applications = RustTunController.Applications()) {
        lifecycle.withLock {
            check(!closed.get()) { "VPN session is closed" }
            stopping.set(false)
            platform.setNetworkChangeListener(null)
            retireNetworkWorker()
            RustCoreNative.stop()
            platform.stopNetworkMonitoring()
            synchronized(networkLock) { active = false }
            descriptor?.close()
            descriptor = null
            RustCoreNative.checkConfig(config, platform)
            check(!stopping.get()) { "VPN start cancelled" }
            val startedOnRevision = networkRevision.get()
            val tun = tunnels.establish(config, applications, network?.network)
            try {
                check(!stopping.get()) { "VPN start cancelled" }
                platform.setNetworkChangeListener(::candidateNetworksChanged)
                platform.startNetworkMonitoring()
                RustCoreNative.start(config, tun.fd, platform)
                check(!stopping.get()) { "VPN start cancelled" }
                descriptor = tun
                val changedDuringStart = synchronized(networkLock) {
                    platform.applyUnderlyingNetwork()
                    active = true
                    networkRevision.get() != startedOnRevision
                }
                if (changedDuringStart) RustCoreNative.networkChanged()
            } catch (failure: Throwable) {
                active = false
                descriptor = null
                platform.setNetworkChangeListener(null)
                retireNetworkWorker()
                runCatching { RustCoreNative.stop() }.onFailure(failure::addSuppressed)
                runCatching { platform.stopNetworkMonitoring() }.onFailure(failure::addSuppressed)
                runCatching { tun.close() }.onFailure(failure::addSuppressed)
                throw failure
            }
        }
    }

    /** Publish the host's default first, then enqueue a serialized native refresh.
     * Native refresh failures are delivered to onNetworkRefreshFailure.
     */
    fun networkChanged(replacement: PhysicalNetwork?) {
        synchronized(networkLock) {
            if (closed.get()) return
            network = replacement
            platform.publishNetwork(replacement)
            networkRevision.incrementAndGet()
            enqueueNetworkRefreshLocked()
        }
    }

    private fun candidateNetworksChanged() {
        synchronized(networkLock) {
            if (closed.get()) return
            networkRevision.incrementAndGet()
            enqueueNetworkRefreshLocked()
        }
    }

    // Call under networkLock. Initial callbacks during startup only advance the
    // revision; startOrReloadService refreshes once native startup has completed.
    private fun enqueueNetworkRefreshLocked() {
        if (!active || stopping.get() || closed.get() || networkWorkQueued) return
        val worker = networkWorker ?: Executors.newSingleThreadExecutor { task ->
            Thread(task, "aerobox-network-refresh").apply { isDaemon = true }
        }.also { networkWorker = it }
        val epoch = networkWorkerEpoch
        val workId = ++networkWorkId
        networkWorkQueued = true
        worker.execute {
            insideNetworkWorker.set(true)
            var attemptedRevision: Long? = null
            try {
                lifecycle.withLock {
                    while (true) {
                        val revision = synchronized(networkLock) {
                            if (epoch != networkWorkerEpoch || !active || stopping.get() || closed.get()) {
                                return@withLock
                            }
                            networkRevision.get()
                        }
                        attemptedRevision = revision
                        platform.applyUnderlyingNetwork()
                        RustCoreNative.networkChanged()
                        val repeat = synchronized(networkLock) {
                            if (epoch != networkWorkerEpoch || !active || stopping.get() || closed.get()) {
                                false
                            } else if (revision != networkRevision.get()) {
                                true
                            } else {
                                networkWorkQueued = false
                                false
                            }
                        }
                        if (!repeat) return@withLock
                    }
                }
            } catch (failure: Throwable) {
                if (!stopping.get() && !closed.get()) {
                    runCatching { onNetworkRefreshFailure(failure) }.onFailure {
                        Log.w("AeroBoxRustVpn", "Network refresh failure callback failed", it)
                    }
                }
            } finally {
                synchronized(networkLock) {
                    if (epoch == networkWorkerEpoch && workId == networkWorkId) {
                        networkWorkQueued = false
                        if (attemptedRevision != networkRevision.get()) enqueueNetworkRefreshLocked()
                    }
                }
                insideNetworkWorker.remove()
            }
        }
    }

    private fun retireNetworkWorker(): ExecutorService? = synchronized(networkLock) {
        networkWorkerEpoch++
        networkWorkQueued = false
        networkWorker.also {
            networkWorker = null
            // An error callback may close the session on this worker. Do not
            // interrupt that thread while it is performing native cleanup.
            if (insideNetworkWorker.get() == true) it?.shutdown() else it?.shutdownNow()
        }
    }

    fun closeService() {
        stopping.set(true)
        platform.setNetworkChangeListener(null)
        val retiredWorker = retireNetworkWorker()
        var finalWorker: ExecutorService? = null
        // Do not acquire lifecycle first: start may be inside a blocking JNI call.
        // Retry while startup owns the lock: stop can race just before JNI has
        // registered the new startup token. The next retry cancels that token.
        while (true) {
            RustCoreNative.stop()
            if (lifecycle.tryLock(50, TimeUnit.MILLISECONDS)) break
        }
        try {
            active = false
            // Startup may have entered after the first cancellation request.
            // Once lifecycle is held, remove anything that it registered.
            platform.setNetworkChangeListener(null)
            finalWorker = retireNetworkWorker()
            try {
                // A start can finish between the last stop and acquiring this
                // lock. Closing our descriptor alone leaves native's TUN copy.
                RustCoreNative.stop()
            }
            finally {
                try { descriptor?.close() }
                finally {
                    descriptor = null
                    platform.stopNetworkMonitoring()
                }
            }
        } finally {
            lifecycle.unlock()
            // A worker may have been waiting for lifecycle; only join after
            // unlocking so it can observe the retired epoch and exit.
            if (insideNetworkWorker.get() != true) {
                retiredWorker?.awaitTermination(5, TimeUnit.SECONDS)
                finalWorker?.awaitTermination(5, TimeUnit.SECONDS)
            }
        }
    }
    override fun close() {
        closed.set(true)
        try { closeService() }
        finally { platform.close() }
    }
    fun isRunning() = active && RustCoreNative.isRunning()

    data class TrafficCounters(val uploadBytes: Long, val downloadBytes: Long)
    /** Combined totals used by the existing proxy + direct traffic monitor. */
    fun trafficCounters(): TrafficCounters {
        val stats = RustCoreNative.stats()
        return TrafficCounters(stats.getLong("upload_total"), stats.getLong("download_total"))
    }

    fun connectionSnapshot(): String =
        connectionSnapshotRows(RustCoreNative.connections().getJSONArray("connections"))

    fun closeTrackedConnection(id: String) = RustCoreNative.closeConnection(id)
    fun drainLogs(accept: (String) -> Unit) {
        val lines = RustCoreNative.drainLogs()
        for (index in 0 until lines.length()) accept(lines.getString(index))
    }
}

/** Preserves the flat fields consumed by AeroBox ConnectionsScreen. */
internal fun connectionSnapshotRows(native: JSONArray): String {
    val rows = JSONArray()
    for (index in 0 until native.length()) {
        val item = native.getJSONObject(index)
        val meta = item.getJSONObject("metadata")
        val chain = item.optJSONArray("chains") ?: JSONArray()
        rows.put(JSONObject().apply {
            put("id", item.getString("id"))
            put("network", meta.optString("network"))
            put("source", endpoint(meta.optString("sourceIP"), meta.optString("sourcePort")))
            put("destination", meta.optString("remoteDestination").ifBlank {
                endpoint(meta.optString("destinationIP"), meta.optString("destinationPort"))
            })
            put("domain", meta.optString("host").ifBlank { meta.optString("sniffHost") })
            put("process", meta.optString("process"))
            // The final chain entry is the routed outbound tag. Internal
            // client/group names are not part of the App's connection UI.
            val outbound = if (chain.length() == 0) "" else chain.getString(chain.length() - 1)
            put("outbound", when (outbound) {
                "__aerobox_direct", "DIRECT" -> "direct"
                else -> outbound
            })
            put("rule", item.optString("rulePayload"))
            put("upload", item.getLong("upload"))
            put("download", item.getLong("download"))
        })
    }
    return rows.toString()
}

private fun endpoint(ip: String, port: String) = when {
    ip.isEmpty() -> ""
    ':' in ip -> "[$ip]:$port"
    else -> "$ip:$port"
}
