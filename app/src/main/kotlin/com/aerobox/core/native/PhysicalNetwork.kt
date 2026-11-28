package com.aerobox.core.`native`

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Parcel
import java.net.InetAddress

/** A complete physical-network observation, built only from ordered callback arguments. */
class PhysicalNetwork private constructor(
    val network: Network,
    private val links: LinkProperties,
) {
    internal fun dnsServers(): List<InetAddress> = links.dnsServers.toList()

    /** Signal/capability bookkeeping alone must not close all existing connections. */
    fun hasSameConfiguration(other: PhysicalNetwork?): Boolean =
        other != null && network == other.network && links == other.links

    companion object {
        internal fun observed(
            network: Network,
            capabilities: NetworkCapabilities?,
            links: LinkProperties?,
        ): PhysicalNetwork? {
            if (network.networkHandle == 0L || capabilities == null || links == null ||
                links.interfaceName.isNullOrBlank() ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
            // PhysicalNetworkState owns this deep copy and never mutates it.
            return PhysicalNetwork(network, links)
        }
    }
}

/**
 * Confined to the application's ordered best-network callback thread. An
 * onAvailable event retires the previous best even if Android never sends an
 * onLost for it. Only caps and links for the new best can make it ready.
 */
class PhysicalNetworkState {
    private var selected: Network? = null
    private var capabilities: NetworkCapabilities? = null
    private var links: LinkProperties? = null
    var current: PhysicalNetwork? = null
        private set

    fun onAvailable(network: Network) {
        selected = network
        capabilities = null
        links = null
        current = null
    }

    fun onCapabilitiesChanged(network: Network, value: NetworkCapabilities) {
        if (selected != network) return
        capabilities = NetworkCapabilities(value)
        update(network)
    }

    fun onLinkPropertiesChanged(network: Network, value: LinkProperties) {
        if (selected != network) return
        // Preserve the entire Android parcel, including routes, MTU and Private
        // DNS state. A DNS-address-only copy would miss meaningful changes.
        val parcel = Parcel.obtain()
        links = try {
            value.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            LinkProperties.CREATOR.createFromParcel(parcel)
        } finally { parcel.recycle() }
        update(network)
    }

    fun onLost(network: Network) {
        if (selected != network) return
        selected = null
        capabilities = null
        links = null
        current = null
    }

    private fun update(network: Network) {
        current = PhysicalNetwork.observed(network, capabilities, links)
    }
}
