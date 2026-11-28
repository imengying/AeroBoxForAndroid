package android.net

import java.io.FileDescriptor
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

data class Network(val id: Int) {
    fun bindSocket(fd: FileDescriptor) { bindings.add(id) }
    companion object { val bindings = CopyOnWriteArrayList<Int>() }
}

class NetworkCapabilities(val physical: Boolean = true) {
    fun hasCapability(capability: Int) = capability == NET_CAPABILITY_NOT_VPN && physical
    companion object { const val NET_CAPABILITY_NOT_VPN = 15 }
}

class LinkProperties {
    val dnsServers = listOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 53)))
}

class ConnectivityManager {
    @Volatile var activeNetwork: Network? = null
    private val capabilities = ConcurrentHashMap<Network, NetworkCapabilities>()
    fun select(network: Network?, physical: Boolean = true) {
        network?.let { capabilities[it] = NetworkCapabilities(physical) }
        activeNetwork = network
    }
    fun getNetworkCapabilities(network: Network) = capabilities[network]
    fun getLinkProperties(network: Network) = LinkProperties().takeIf { capabilities.containsKey(network) }
}
