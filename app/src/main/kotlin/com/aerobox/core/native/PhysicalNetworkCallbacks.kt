package com.aerobox.core.`native`

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicReference

/** For standalone latency probes before VpnService is active. */
class PhysicalNetworkCallbacks(
    private val context: Context,
    private val connectivity: ConnectivityManager,
    network: Network,
) : RustCoreNative.PlatformCallbacks, AutoCloseable {
    // Standalone probes have no original TUN socket owner. Keep the interface's
    // default connectionOwner == "null" instead of attributing the core itself.
    private val underlying = AtomicReference<Network?>(network)
    private val networks = PhysicalNetworkRegistry(connectivity, network)
    private val dnsQueries = PlatformDnsQueries(networks)

    init { requirePhysical(network) }
    private fun requirePhysical(network: Network) {
        check(connectivity.getNetworkCapabilities(network)
            ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true) {
            "A physical non-VPN network is required"
        }
    }
    fun setUnderlyingNetwork(network: Network?) {
        network?.let(::requirePhysical)
        underlying.set(network)
        networks.setDefaultNetwork(network)
    }
    fun startNetworkMonitoring() = networks.start()
    fun stopNetworkMonitoring() = networks.stop()
    fun setNetworkChangeListener(listener: (() -> Unit)?) = networks.setChangeListener(listener)
    override fun close() {
        try { dnsQueries.close() } finally { networks.close() }
    }
    override fun supportsSystemDns() = true
    override fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray) =
        dnsQueries.start(id, generation, networkHandle, message)
    override fun cancelDnsQuery(id: Long) = dnsQueries.cancel(id)
    override fun physicalNetworks(): String = networks.snapshotJson()
    override fun protectOnNetwork(fd: Int, generation: Long, handle: Long): Boolean =
        networks.protectOnNetwork(fd, generation, handle) { true }

    override fun protect(fd: Int): Boolean {
        val network = checkNotNull(underlying.get()) { "No physical network" }
        // bindSocket pins the actual socket to this non-VPN network. Duplicating
        // only borrows the Rust descriptor and closing the duplicate is safe.
        ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
        return true
    }
    override fun dnsServers(): String {
        val network = checkNotNull(underlying.get()) { "No physical network" }
        val links = checkNotNull(connectivity.getLinkProperties(network)) { "Physical network disappeared" }
        return JSONArray(links.dnsServers.map { it.hostAddress }).toString()
    }
    override fun storageDirectory() = java.io.File(context.noBackupFilesDir, "rust-core").absolutePath
}
