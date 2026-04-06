package com.aerobox.core.network

import android.net.Network
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.DefaultNetworkMonitor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress

object NodeAddressFamilyResolver {
    private const val LOOKUP_TIMEOUT_MS = 1_500L

    suspend fun isIpv6Only(node: ProxyNode): Boolean = isIpv6Only(node.server)

    suspend fun isIpv6Only(server: String): Boolean {
        val host = ConfigGenerator.normalizedServerHost(server)
        if (host.isBlank()) return false
        if (ConfigGenerator.isIpv6ServerLiteral(server)) return true
        if (ConfigGenerator.isIpLiteralHost(host)) return false

        val addresses = withTimeoutOrNull(LOOKUP_TIMEOUT_MS) {
            resolveAddresses(host)
        } ?: emptyList()

        if (addresses.isEmpty()) return false
        val hasIpv4 = addresses.any { it.address.size == 4 }
        val hasIpv6 = addresses.any { it.address.size == 16 }
        return hasIpv6 && !hasIpv4
    }

    private suspend fun resolveAddresses(host: String): List<InetAddress> = withContext(Dispatchers.IO) {
        val activeNetwork = DefaultNetworkMonitor.defaultNetwork ?: AeroBoxApplication.connectivity.activeNetwork
        val networkResolved = activeNetwork?.resolveAll(host).orEmpty()
        if (networkResolved.isNotEmpty()) {
            return@withContext networkResolved
        }
        runCatching { InetAddress.getAllByName(host).toList() }.getOrElse { emptyList() }
    }

    private fun Network.resolveAll(host: String): List<InetAddress> {
        return runCatching { getAllByName(host).toList() }.getOrElse { emptyList() }
    }
}
