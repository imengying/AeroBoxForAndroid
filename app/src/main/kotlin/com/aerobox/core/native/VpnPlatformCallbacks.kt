package com.aerobox.core.`native`

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicReference

/** Supply a non-VPN physical network selected by the application's network monitor. */
class VpnPlatformCallbacks(
    private val service: VpnService,
    connectivity: ConnectivityManager,
    initialNetwork: PhysicalNetwork,
) : RustCoreNative.PlatformCallbacks, AutoCloseable {
    private val underlying = AtomicReference<PhysicalNetwork?>(initialNetwork)
    private val networks = PhysicalNetworkRegistry(connectivity, initialNetwork.network)
    private val dnsQueries = PlatformDnsQueries(networks)
    private val connectionOwners = ConnectionOwners(connectivity, service.packageManager)

    fun startNetworkMonitoring() = networks.start()
    fun stopNetworkMonitoring() = networks.stop()
    fun setNetworkChangeListener(listener: (() -> Unit)?) = networks.setChangeListener(listener)
    override fun close() {
        underlying.set(null)
        try { dnsQueries.close() } finally { networks.close() }
    }
    override fun supportsSystemDns() = true
    override fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray) =
        dnsQueries.start(id, generation, networkHandle, message)
    override fun cancelDnsQuery(id: Long) = dnsQueries.cancel(id)
    override fun connectionOwner(ipProtocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int): String =
        connectionOwners.find(ipProtocol, source, sourcePort, destination, destinationPort)
    override fun physicalNetworks(): String = networks.snapshotJson()
    override fun protectOnNetwork(fd: Int, generation: Long, handle: Long): Boolean =
        networks.protectOnNetwork(fd, generation, handle, service::protect)

    /** Callback-safe publication. Null immediately prevents new default bindings. */
    fun publishNetwork(network: PhysicalNetwork?) {
        underlying.set(network)
        networks.setDefaultNetwork(network?.network)
    }

    /** Worker-only; call after TUN establishment, before the native refresh. */
    fun applyUnderlyingNetwork() {
        val network = underlying.get()?.network
        check(service.setUnderlyingNetworks(network?.let { arrayOf(it) } ?: emptyArray())) {
            "Cannot update physical network for VPN"
        }
    }

    override fun protect(fd: Int): Boolean {
        val network = checkNotNull(underlying.get()) { "No physical network" }.network
        if (!service.protect(fd)) return false
        ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
        return true
    }

    override fun storageDirectory() = java.io.File(service.noBackupFilesDir, "rust-core").absolutePath

    override fun dnsServers(): String {
        val network = checkNotNull(underlying.get()) { "No physical network" }
        return JSONArray(network.dnsServers().map { it.hostAddress }).toString()
    }
}
