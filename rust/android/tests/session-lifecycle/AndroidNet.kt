package android.net
import android.os.Parcel
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

data class Network(val id: Int = 1) {
    val networkHandle: Long get() = id.toLong()
    fun bindSocket(fd: FileDescriptor) { bindings.add(id) }
    companion object { val bindings = CopyOnWriteArrayList<Int>() }
}
class ConnectivityManager {
    fun getNetworkCapabilities(network: Network): NetworkCapabilities? =
        error("Synchronous capabilities query is forbidden in this regression")
    fun getLinkProperties(network: Network): LinkProperties? =
        error("Synchronous link query is forbidden in this regression")
}
class NetworkCapabilities() {
    private val capabilities = mutableSetOf<Int>()
    private val transports = mutableSetOf<Int>()
    constructor(other: NetworkCapabilities) : this() {
        capabilities.addAll(other.capabilities); transports.addAll(other.transports)
    }
    fun addCapability(value: Int) = apply { capabilities.add(value) }
    fun removeCapability(value: Int) = apply { capabilities.remove(value) }
    fun hasCapability(value: Int) = value in capabilities
    fun addTransportType(value: Int) = apply { transports.add(value) }
    fun hasTransport(value: Int) = value in transports
    companion object {
        const val NET_CAPABILITY_INTERNET = 12
        const val NET_CAPABILITY_NOT_VPN = 15
        const val TRANSPORT_VPN = 4
    }
}
class LinkProperties {
    var interfaceName: String? = null
    val dnsServers = mutableListOf<InetAddress>()
    val routes = mutableListOf<String>()
    var privateDnsServerName: String? = null
    var mtu = 1500
    fun addDnsServer(address: InetAddress) { dnsServers.add(address) }
    private fun copy() = LinkProperties().also {
        it.interfaceName = interfaceName; it.dnsServers.addAll(dnsServers)
        it.routes.addAll(routes); it.privateDnsServerName = privateDnsServerName; it.mtu = mtu
    }
    fun writeToParcel(parcel: Parcel, flags: Int) { parcel.value = copy() }
    override fun equals(other: Any?) = other is LinkProperties &&
        interfaceName == other.interfaceName && dnsServers == other.dnsServers &&
        routes == other.routes && privateDnsServerName == other.privateDnsServerName && mtu == other.mtu
    override fun hashCode() = listOf(interfaceName, dnsServers, routes, privateDnsServerName, mtu).hashCode()
    companion object {
        val CREATOR = object : android.os.ParcelCreator<LinkProperties> {
            override fun createFromParcel(parcel: Parcel) = (parcel.value as LinkProperties).copy()
        }
    }
}
class VpnService {
    val packageManager = Any()
    val noBackupFilesDir = File("/unused-test-storage")
    val networkUpdates = CopyOnWriteArrayList<List<Network>>()
    val updateThreads = CopyOnWriteArrayList<String>()
    var onSetUnderlying: () -> Unit = {}
    var allowUnderlying = true
    var allowProtect = true
    var protectCalls = 0
    fun setUnderlyingNetworks(networks: Array<Network>): Boolean {
        onSetUnderlying()
        networkUpdates.add(networks.toList())
        updateThreads.add(Thread.currentThread().name)
        return allowUnderlying
    }
    fun protect(fd: Int): Boolean { protectCalls++; return allowProtect }
}
