package com.aerobox.core.`native`

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.HandlerThread
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * Owns one coherent non-VPN inventory and the Network objects represented by it.
 * Default-network choice belongs to the host; this class only observes all
 * candidates. No callback here calls RustCoreNative or changes DNS policy.
 */
class PhysicalNetworkRegistry(
    private val connectivity: ConnectivityManager,
    initialDefault: Network?,
) : AutoCloseable {
    private data class Observed(
        val network: Network,
        val capabilities: NetworkCapabilities? = null,
        val links: LinkProperties? = null,
    )
    private data class Registration(
        val token: Any,
        val callback: ConnectivityManager.NetworkCallback,
        val thread: HandlerThread,
    )

    private val lock = Any()
    private val observed = mutableMapOf<Long, Observed>()
    private var defaultNetwork = initialDefault
    private var generation = nextGeneration()
    private var registration: Registration? = null
    private var closed = false
    @Volatile private var changeListener: (() -> Unit)? = null
    private val invalidationListeners = LinkedHashSet<() -> Unit>()

    internal fun addInvalidationListener(listener: () -> Unit): AutoCloseable {
        synchronized(lock) {
            check(!closed) { "Physical network registry is closed" }
            invalidationListeners.add(listener)
        }
        return AutoCloseable { synchronized(lock) { invalidationListeners.remove(listener) } }
    }
    private fun notifyInvalidated() {
        val listeners = synchronized(lock) { invalidationListeners.toList() }
        listeners.forEach { listener ->
            runCatching(listener).onFailure { Log.w("AeroBoxNetworkRegistry", "Network invalidation failed", it) }
        }
    }

    /** Listener runs only on a monitor event, outside the inventory lock.
     * Hosts should enqueue work; never synchronously reenter a native callback.
     */
    fun setChangeListener(listener: (() -> Unit)?) { changeListener = listener }

    /** Idempotent; registered only for explicit inventory use or host startup. */
    @Suppress("DEPRECATION")
    fun start() {
        synchronized(lock) {
            check(!closed) { "Physical network registry is closed" }
            if (registration != null) return
            val thread = HandlerThread("aerobox-physical-networks").apply { start() }
            val token = Any()
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = update(token, network) { old ->
                    old ?: Observed(network)
                }
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    update(token, network) { old ->
                        (old ?: Observed(network)).copy(capabilities = NetworkCapabilities(caps))
                    }
                override fun onLinkPropertiesChanged(network: Network, links: LinkProperties) =
                    update(token, network) { old ->
                        (old ?: Observed(network)).copy(links = copyLinks(links))
                    }
                override fun onLost(network: Network) = update(token, network) { null }
            }
            registration = Registration(token, callback, thread)
            var registered = false
            try {
                val request = NetworkRequest.Builder()
                    .clearCapabilities()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
                connectivity.registerNetworkCallback(request, callback, Handler(thread.looper))
                registered = true
                // Register before seeding: queued callbacks correct this initial
                // read, and their token cannot mutate a later monitoring session.
                observed.clear()
                for (network in connectivity.allNetworks) {
                    val caps = connectivity.getNetworkCapabilities(network) ?: continue
                    if (!physical(caps)) continue
                    val links = connectivity.getLinkProperties(network) ?: continue
                    observed[network.networkHandle] = Observed(
                        network, NetworkCapabilities(caps), copyLinks(links),
                    )
                }
                generation = nextGeneration()
            } catch (failure: Throwable) {
                registration = null
                observed.clear()
                generation = nextGeneration()
                if (registered) runCatching { connectivity.unregisterNetworkCallback(callback) }
                thread.quitSafely()
                throw failure
            }
        }
    }

    /** Stop releases Android callback/thread resources; a later start gets a new epoch. */
    fun stop() {
        val old = synchronized(lock) {
            registration.also {
                registration = null
                observed.clear()
                generation = nextGeneration()
            }
        }
        notifyInvalidated()
        if (old != null) {
            try { connectivity.unregisterNetworkCallback(old.callback) }
            finally { old.thread.quitSafely() }
        }
    }

    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            changeListener = null
        }
        stop()
    }

    /** Called in the same ordered monitor path that publishes the host's default. */
    fun setDefaultNetwork(network: Network?) {
        val changed = synchronized(lock) {
            check(!closed) { "Physical network registry is closed" }
            if (defaultNetwork == network) false else {
                defaultNetwork = network
                generation = nextGeneration()
                true
            }
        }
        if (changed) notifyInvalidated()
    }

    fun snapshotJson(): String {
        start()
        return synchronized(lock) {
            check(!closed && registration != null) { "Physical network monitor is stopped" }
            val candidates = candidates()
            check(candidates.size <= 64) { "Physical network snapshot exceeds 64 networks" }
            val default = defaultNetwork?.networkHandle?.takeIf { handle ->
                candidates.any { it.network.networkHandle == handle }
            }
            buildString {
                // Decimal u64 literals are appended directly. JSONObject's
                // Double/Number coercion must never round opaque identifiers.
                append("{\"generation\":").append(unsigned(generation))
                append(",\"default_handle\":").append(default?.let(::unsigned) ?: "null")
                append(",\"networks\":[")
                candidates.forEachIndexed { index, entry ->
                    if (index != 0) append(',')
                    val links = checkNotNull(entry.links)
                    val dns = links.dnsServers.map(::dnsEndpoint).distinct()
                    check(dns.size <= 64) { "Physical network exceeds 64 DNS servers" }
                    append("{\"handle\":").append(unsigned(entry.network.networkHandle))
                    append(",\"kind\":").append(JSONObject.quote(kind(checkNotNull(entry.capabilities))))
                    append(",\"interface\":").append(JSONObject.quote(links.interfaceName))
                    append(",\"dns\":").append(JSONArray(dns).toString())
                    append('}')
                }
                append("]}")
            }
        }
    }

    /** Resolve and bind under one lock. A stale epoch, vanished network or failed
     * protection never falls back to the current default network.
     */
    fun protectOnNetwork(fd: Int, expectedGeneration: Long, handle: Long, protect: (Int) -> Boolean): Boolean =
        synchronized(lock) {
            val network = networkForLocked(expectedGeneration, handle)
            if (!protect(fd)) return@synchronized false
            ParcelFileDescriptor.fromFd(fd).use {
                network.bindSocket(it.fileDescriptor)
            }
            true
        }

    /** Exact snapshot binding for Android DnsResolver; never picks another network. */
    internal fun networkFor(expectedGeneration: Long, handle: Long): Network = synchronized(lock) {
        networkForLocked(expectedGeneration, handle)
    }
    /** Used when a queued invalidation races a query already submitted in the new epoch. */
    internal fun currentGeneration(): Long? = synchronized(lock) {
        generation.takeIf { !closed && registration != null }
    }
    private fun networkForLocked(expectedGeneration: Long, handle: Long): Network {
        check(!closed && registration != null) { "Physical network monitor is stopped" }
        check(expectedGeneration == generation) { "Physical network snapshot is stale" }
        val selected = observed[handle]?.takeIf(::usable)
            ?: error("Requested physical network disappeared")
        // Recheck OS state as onLost may still be queued behind this call.
        val current = connectivity.getNetworkCapabilities(selected.network)
        check(current != null && physical(current)) { "Requested physical network disappeared" }
        // Capabilities include transient bandwidth/signal information and
        // fields redacted differently between callbacks and synchronous
        // queries. Only the physical/type predicates affect our selection.
        check(kind(current) == kind(checkNotNull(selected.capabilities)) &&
            connectivity.getLinkProperties(selected.network) == selected.links) {
            "Physical network changed before its monitor callback"
        }
        return selected.network
    }

    private fun update(token: Any, network: Network, change: (Observed?) -> Observed?) {
        val changed = synchronized(lock) {
            if (closed || registration?.token !== token) return
            val handle = network.networkHandle
            val before = observed[handle]
            val after = change(before)
            if (after == before) return
            if (after == null) observed.remove(handle) else observed[handle] = after
            // Keep the freshest object, but do not retire every connection for
            // a signal-strength update or an incomplete onAvailable placeholder.
            val beforeUsable = before?.let(::usable) == true
            val afterUsable = after?.let(::usable) == true
            if (!beforeUsable && !afterUsable) return
            if (beforeUsable && afterUsable &&
                kind(checkNotNull(before.capabilities)) == kind(checkNotNull(after.capabilities)) &&
                before.links == after.links) return
            generation = nextGeneration()
            true
        }
        if (changed) notifyInvalidated()
        if (changed) runCatching { changeListener?.invoke() }.onFailure {
            Log.w("AeroBoxNetworkRegistry", "Physical network listener failed", it)
        }
    }

    private fun candidates(): List<Observed> = observed.values.filter(::usable).sortedWith { a, b ->
        java.lang.Long.compareUnsigned(a.network.networkHandle, b.network.networkHandle)
    }

    private fun usable(entry: Observed): Boolean = entry.network.networkHandle != 0L &&
        entry.capabilities?.let(::physical) == true &&
        !entry.links?.interfaceName.isNullOrBlank()

    companion object {
        private val generations = AtomicLong()
        private fun nextGeneration(): Long = generations.updateAndGet {
            check(it != -1L) { "Physical network generation exhausted" }
            it + 1L
        }
        private fun unsigned(value: Long) = java.lang.Long.toUnsignedString(value)
        private fun physical(caps: NetworkCapabilities) =
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        private fun kind(caps: NetworkCapabilities) = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        private fun copyLinks(links: LinkProperties): LinkProperties {
            val parcel = Parcel.obtain()
            return try {
                links.writeToParcel(parcel, 0)
                parcel.setDataPosition(0)
                LinkProperties.CREATOR.createFromParcel(parcel)
            } finally { parcel.recycle() }
        }
        private fun dnsEndpoint(address: InetAddress): String {
            val ip = checkNotNull(address.hostAddress) { "Physical DNS has no address" }
            return if (address is Inet6Address && address.scopeId != 0) {
                "[${ip.substringBefore('%')}%${address.scopeId}]:53"
            } else ip
        }
    }
}
