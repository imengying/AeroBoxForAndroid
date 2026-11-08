package com.aerobox.core.network

import android.net.DnsResolver
import android.net.NetworkCapabilities
import android.os.CancellationSignal
import com.aerobox.AeroBoxApplication
import com.aerobox.core.config.ConfigGenerator
import com.aerobox.data.model.ProxyNode
import com.aerobox.service.DefaultNetworkMonitor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.util.concurrent.Executor
import kotlin.coroutines.resume

object NodeAddressFamilyResolver {
    private const val LOOKUP_TIMEOUT_MS = 1_500L

    suspend fun isIpv6Only(node: ProxyNode): Boolean = isIpv6Only(node.server)

    suspend fun isIpv6Only(server: String): Boolean {
        val host = ConfigGenerator.normalizeOutboundServer(server)
        if (host.isBlank()) return false
        if (ConfigGenerator.isIpv6Literal(server)) return true
        if (ConfigGenerator.isIpLiteral(host)) return false

        val addresses = withTimeoutOrNull(LOOKUP_TIMEOUT_MS) {
            resolveAddresses(host)
        } ?: emptyList()

        if (addresses.isEmpty()) return false
        val hasIpv4 = addresses.any { it.address.size == 4 }
        val hasIpv6 = addresses.any { it.address.size == 16 }
        return hasIpv6 && !hasIpv4
    }

    @Suppress("DEPRECATION") // Context-based acquisition is not available on all supported Android versions.
    private suspend fun resolveAddresses(host: String): List<InetAddress> =
        suspendCancellableCoroutine { continuation ->
            val connectivity = AeroBoxApplication.connectivity
            val network = DefaultNetworkMonitor.defaultNetwork ?: connectivity.activeNetwork?.takeIf {
                connectivity.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
            }
            val cancellation = CancellationSignal()
            continuation.invokeOnCancellation { cancellation.cancel() }
            try {
                DnsResolver.getInstance().query(
                    network, host, DnsResolver.FLAG_EMPTY, Executor { it.run() }, cancellation,
                    object : DnsResolver.Callback<List<InetAddress>> {
                        override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                            if (continuation.isActive) continuation.resume(if (rcode == 0) answer else emptyList())
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            if (continuation.isActive) continuation.resume(emptyList())
                        }
                    }
                )
            } catch (_: Exception) {
                if (continuation.isActive) continuation.resume(emptyList())
            }
        }
}
