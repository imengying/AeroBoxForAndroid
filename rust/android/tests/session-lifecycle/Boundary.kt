package com.aerobox.core.`native`
import android.net.*
import android.os.ParcelFileDescriptor
import org.json.*
import java.util.concurrent.atomic.AtomicInteger
class PhysicalNetworkRegistry(connectivity: ConnectivityManager, initial: Network?) : AutoCloseable {
    @Volatile var listener: (() -> Unit)? = null
    @Volatile var monitoring = false
    @Volatile var closed = false
    @Volatile var selectedDefault = initial
    init { latest = this }
    fun setChangeListener(value: (() -> Unit)?) { listener = value }
    fun start() { check(!closed); monitoring = true }
    fun stop() { monitoring = false }
    fun setDefaultNetwork(value: Network?) { check(!closed); selectedDefault = value }
    fun snapshotJson() = "{}"
    fun protectOnNetwork(fd: Int, generation: Long, handle: Long, protect: (Int) -> Boolean) = protect(fd)
    fun candidateChange() { if (monitoring) listener?.invoke() }
    override fun close() { closed = true; monitoring = false; listener = null }
    companion object { lateinit var latest: PhysicalNetworkRegistry }
}
class PlatformDnsQueries(registry: PhysicalNetworkRegistry) : AutoCloseable {
    fun start(id: Long, generation: Long, handle: Long, message: ByteArray) {}
    fun cancel(id: Long) {}
    override fun close() {}
}
class ConnectionOwners(connectivity: ConnectivityManager, packages: Any) {
    fun find(protocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int) = "null"
}
class RustTunController(service: VpnService) {
    class Applications
    fun establish(config: String, applications: Applications, network: Network?) = ParcelFileDescriptor()
}
object RustCoreNative {
    interface PlatformCallbacks {
        fun protect(fd: Int): Boolean
        fun dnsServers(): String
        fun supportsSystemDns(): Boolean
        fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray)
        fun cancelDnsQuery(id: Long)
        fun connectionOwner(ipProtocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int): String
        fun physicalNetworks(): String
        fun protectOnNetwork(fd: Int, generation: Long, handle: Long): Boolean
        fun storageDirectory(): String
    }
    @Volatile var running = false
    @Volatile var onStart: () -> Unit = {}
    @Volatile var onStop: () -> Unit = {}
    @Volatile var afterStop: () -> Unit = {}
    @Volatile var onRefresh: () -> Unit = {}
    val refreshes = AtomicInteger()
    val inFlight = AtomicInteger()
    val maxInFlight = AtomicInteger()
    val refreshThreads = java.util.concurrent.CopyOnWriteArrayList<String>()
    fun checkConfig(config: String, platform: VpnPlatformCallbacks) = JSONObject()
    fun start(config: String, fd: Int, platform: VpnPlatformCallbacks) { onStart(); running = true }
    fun stop() { onStop(); running = false; afterStop() }
    fun networkChanged() {
        check(running)
        refreshThreads.add(Thread.currentThread().name)
        refreshes.incrementAndGet()
        val active = inFlight.incrementAndGet()
        maxInFlight.updateAndGet { maxOf(it, active) }
        try { onRefresh() } finally { inFlight.decrementAndGet() }
    }
    fun isRunning() = running
    fun stats() = JSONObject()
    fun connections() = JSONObject()
    fun closeConnection(id: String) {}
    fun drainLogs() = JSONArray()
    fun urlTestConfig(config: String, tag: String, url: String, timeout: Long, platform: VpnPlatformCallbacks) = 0
    fun reset() {
        running = false; onStart = {}; onStop = {}; afterStop = {}; onRefresh = {}
        refreshes.set(0); inFlight.set(0); maxInFlight.set(0); refreshThreads.clear()
    }
}
