package com.aerobox.core.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * Detects the public exit IP address by racing multiple endpoints.
 *
 * Uses a dedicated [OkHttpClient] with zero idle connections to ensure fresh
 * sockets per detection, avoiding stale connections from before VPN routing
 * changed. Callers must call [shutdown] when the detector is no longer needed.
 */
class PublicIpDetector internal constructor(
    private val endpointProvider: (IpFamily, Boolean) -> List<String> = ::endpoints
) {

    private companion object {
        val IPV4_REGEX = Regex("""^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$""")
        val IPV6_REGEX = Regex("""^[0-9A-Fa-f:]+(%[0-9A-Za-z._~-]+)?$""")

        val DIRECT_IPV4_ENDPOINTS = listOf(
            "https://4.ipw.cn",
            "https://api.ip.sb/ip"
        )
        val DIRECT_IPV6_ENDPOINTS = listOf(
            "https://6.ipw.cn",
            "https://api6.ipify.org"
        )
        val PROXIED_IPV4_ENDPOINTS = listOf(
            "https://api4.ipify.org",
            "https://v4.ident.me"
        )
        val PROXIED_IPV6_ENDPOINTS = listOf(
            "https://api6.ipify.org",
            "https://v6.ident.me"
        )

        fun endpoints(family: IpFamily, proxied: Boolean): List<String> = when (family) {
            IpFamily.IPV4 -> if (proxied) PROXIED_IPV4_ENDPOINTS else DIRECT_IPV4_ENDPOINTS + PROXIED_IPV4_ENDPOINTS
            IpFamily.IPV6 -> if (proxied) PROXIED_IPV6_ENDPOINTS else DIRECT_IPV6_ENDPOINTS + PROXIED_IPV6_ENDPOINTS
        }
    }

    // Standalone instance — intentionally NOT derived from SharedHttpClient so that
    // dispatcher.cancelAll() does not cancel subscription refreshes or Geo-asset
    // downloads running on the shared pool.
    private val client = OkHttpClient.Builder()
        .callTimeout(5, TimeUnit.SECONDS)
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(3, TimeUnit.SECONDS)
        .connectionPool(ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    /**
     * Test one exit address family independently through the application's network.
     *
     * @param useProxyFriendlyEndpoints true when VPN is connected (avoids
     *   China-only endpoints that may be unreachable through the proxy)
     * @return the detected IP address string, or null if detection fails
     */
    suspend fun detect(
        family: IpFamily,
        useProxyFriendlyEndpoints: Boolean
    ): String? = withContext(Dispatchers.IO) {
        raceEndpoints(endpointProvider(family, useProxyFriendlyEndpoints), family)
    }

    /** Release resources held by the internal HTTP client. */
    fun shutdown() {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
    }

    private suspend fun raceEndpoints(endpoints: List<String>, family: IpFamily): String? = supervisorScope {
        val uniqueEndpoints = endpoints.distinct()
        val resultChannel = Channel<String?>(capacity = uniqueEndpoints.size)
        val jobs = uniqueEndpoints.map { endpoint ->
            launch {
                resultChannel.trySend(fetchIpFromEndpoint(endpoint, family))
            }
        }

        try {
            repeat(jobs.size) {
                val ip = resultChannel.receive()
                if (!ip.isNullOrBlank()) {
                    return@supervisorScope ip
                }
            }
            null
        } finally {
            jobs.forEach { it.cancel() }
            resultChannel.close()
        }
    }

    private suspend fun fetchIpFromEndpoint(endpoint: String, family: IpFamily): String? =
        suspendCancellableCoroutine { continuation ->
            val request = Request.Builder()
                .url(endpoint)
                .header("User-Agent", "AeroBox/IP-Check")
                .header("Connection", "close")
                .build()
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) {
                        continuation.resume(null)
                    }
                }

                override fun onResponse(call: Call, response: Response) {
                    val normalized = try {
                        response.use {
                            val source = it.body.source()
                            if (!it.isSuccessful || source.request(257L)) null
                            else source.readUtf8().trim().takeIf { address -> matchesFamily(address, family) }
                        }
                    } catch (_: IOException) {
                        null
                    }
                    if (continuation.isActive) {
                        continuation.resume(normalized)
                    }
                }
            })
        }

    private fun matchesFamily(value: String, family: IpFamily): Boolean {
        return when (family) {
            IpFamily.IPV4 -> IPV4_REGEX.matches(value)
            IpFamily.IPV6 -> value.contains(':') && IPV6_REGEX.matches(value) &&
                runCatching { InetAddress.getByName(value) is Inet6Address }.getOrDefault(false)
        }
    }
}
