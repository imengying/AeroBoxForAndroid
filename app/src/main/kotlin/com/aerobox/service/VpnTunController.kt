package com.aerobox.service

import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.annotation.RequiresApi
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.TunOptions
import java.net.InetAddress

/** Owns the TUN descriptor shared by the lifecycle coroutine and native callback thread. */
internal class VpnTunController(
    private val service: VpnService,
    private val isCancelled: () -> Boolean,
    private val defaultNetwork: () -> Network?
) {
    private val tunnelLock = Any()
    private var vpnInterface: ParcelFileDescriptor? = null

    fun close() = synchronized(tunnelLock) {
        val previous = vpnInterface
        vpnInterface = null
        runCatching { previous?.close() }
        Unit
    }

    fun open(options: TunOptions): Int {
        check(!isCancelled()) { "VPN start was cancelled" }
        if (VpnService.prepare(service) != null) error("android: missing vpn permission")

        val builder = service.Builder()
            .setSession("AeroBox")
            .setMtu(options.mtu)

        // Read addresses
        val inet4Addresses = drainRouteAddresses(options.inet4Address)
        inet4Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        val inet6Addresses = drainRouteAddresses(options.inet6Address)
        inet6Addresses.forEach { (address, prefix) -> builder.addAddress(address, prefix) }

        val hasIpv6Tun = inet6Addresses.isNotEmpty()
        builder.setMetered(false)
        defaultNetwork()?.let { network ->
            runCatching {
                builder.setUnderlyingNetworks(arrayOf(network))
            }
        }

        if (options.autoRoute) {
            val inet4Routes = drainRouteAddresses(options.inet4RouteAddress)
            val inet6Routes = drainRouteAddresses(options.inet6RouteAddress)
            val inet4ExcludedRoutes = drainRouteAddresses(options.inet4RouteExcludeAddress)
            val inet6ExcludedRoutes = drainRouteAddresses(options.inet6RouteExcludeAddress)
            val dnsServers = options.dnsServerAddress
            while (dnsServers.hasNext()) {
                builder.addDnsServer(dnsServers.next())
            }
            // Add an IPv6 DNS server so Android advertises IPv6 capability
            // on the VPN network. sing-box hijacks all DNS traffic, so the
            // actual address doesn't matter – it just needs to be routable
            // through the TUN.
            if (hasIpv6Tun) {
                inet6Addresses.firstOrNull()?.let { (address, _) ->
                    runCatching { builder.addDnsServer(address) }
                }
            }

            if (inet4Routes.isNotEmpty()) {
                inet4Routes.forEach { (address, prefix) ->
                    builder.addRouteCompat(address, prefix)
                }
            } else if (inet4Addresses.isNotEmpty()) {
                builder.addRoute("0.0.0.0", 0)
            }
            if (inet6Routes.isNotEmpty()) {
                inet6Routes.forEach { (address, prefix) ->
                    builder.addRouteCompat(address, prefix)
                }
            } else if (inet6Addresses.isNotEmpty()) {
                builder.addRoute("::", 0)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                inet4ExcludedRoutes.forEach { (address, prefix) ->
                    toIpPrefixOrNull(address, prefix)?.let { builder.excludeRoute(it) }
                }
                inet6ExcludedRoutes.forEach { (address, prefix) ->
                    toIpPrefixOrNull(address, prefix)?.let { builder.excludeRoute(it) }
                }
            }
        }

        // Per-app proxy from OverrideOptions (handled by libbox include/exclude)
        val include = options.includePackage
        while (include.hasNext()) {
            runCatching { builder.addAllowedApplication(include.next()) }
        }
        val exclude = options.excludePackage
        while (exclude.hasNext()) {
            runCatching { builder.addDisallowedApplication(exclude.next()) }
        }

        val pfd = builder.establish()
            ?: error("android: failed to establish VPN interface")
        synchronized(tunnelLock) {
            if (isCancelled()) {
                pfd.close()
                error("VPN start was cancelled")
            }
            // Close any previous fd to prevent leaks during rapid switch
            runCatching { vpnInterface?.close() }
            vpnInterface = pfd
        }
        updateUnderlyingNetwork(defaultNetwork())
        return pfd.fd
    }

    fun updateUnderlyingNetwork(network: Network?) {
        runCatching {
            service.setUnderlyingNetworks(network?.let { arrayOf(it) })
        }
    }

    private fun VpnService.Builder.addRouteCompat(address: String, prefix: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            toIpPrefixOrNull(address, prefix)?.let(::addRoute) ?: addRoute(address, prefix)
        } else {
            addRoute(address, prefix)
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun toIpPrefixOrNull(address: String, prefix: Int): IpPrefix? {
        val normalized = address
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
            .substringBefore('%')
            .trim()
        if (normalized.isEmpty()) return null
        return runCatching {
            IpPrefix(InetAddress.getByName(normalized), prefix)
        }.getOrNull()
    }

    private fun drainRouteAddresses(
        iterator: RoutePrefixIterator
    ): List<Pair<String, Int>> {
        val result = mutableListOf<Pair<String, Int>>()
        while (iterator.hasNext()) {
            val prefix = iterator.next()
            result += prefix.address() to prefix.prefix()
        }
        return result
    }

}
