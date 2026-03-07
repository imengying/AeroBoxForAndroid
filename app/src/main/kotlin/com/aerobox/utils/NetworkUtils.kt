package com.aerobox.utils

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.TimeUnit
import kotlin.math.ln
import kotlin.math.pow
import kotlin.system.measureTimeMillis

object NetworkUtils {

    private const val URL_TEST_DEFAULT = "https://www.gstatic.com/generate_204"
    private const val URL_TEST_TIMEOUT = 5000
    private val URL_TEST_FALLBACKS = listOf(
        URL_TEST_DEFAULT,
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204"
    )

    /**
     * URL Test — NekoBox 方式 1：发起真实 HTTP 请求测量延迟。
     * 需要 VPN 已连接，流量走代理才能反映真实延迟。
     */
    suspend fun urlTest(
        testUrl: String = URL_TEST_DEFAULT,
        timeout: Int = URL_TEST_TIMEOUT
    ): Int = withContext(Dispatchers.IO) {
        val candidates = buildList {
            add(testUrl)
            URL_TEST_FALLBACKS.forEach { url ->
                if (url != testUrl) add(url)
            }
        }
        candidates.firstNotNullOfOrNull { candidate ->
            urlTestOnce(candidate, timeout).takeIf { it > 0 }
        } ?: -1
    }

    private fun urlTestOnce(testUrl: String, timeout: Int): Int {
        return runCatching {
            val client = OkHttpClient.Builder()
                .callTimeout(timeout.toLong(), TimeUnit.MILLISECONDS)
                .connectTimeout(timeout.toLong(), TimeUnit.MILLISECONDS)
                .readTimeout(timeout.toLong(), TimeUnit.MILLISECONDS)
                .followRedirects(true)
                .followSslRedirects(true)
                .retryOnConnectionFailure(true)
                .build()
            val request = Request.Builder()
                .url(testUrl)
                .header("User-Agent", "AeroBox/URLTest")
                .header("Cache-Control", "no-cache")
                .get()
                .build()
            measureTimeMillis {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful && response.code !in 300..399) {
                        error("HTTP ${response.code}")
                    }
                    response.body?.close()
                }
            }.toInt()
        }.getOrDefault(-1)
    }

    /**
     * TCP Ping — NekoBox 方式 2：TCP 连接到节点服务器测量延迟。
     * 不需要 VPN 连接，直接测试节点可达性。
     */
    suspend fun pingTcp(server: String, port: Int, timeout: Int = 3000): Int = withContext(Dispatchers.IO) {
        runCatching {
            measureTimeMillis {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(server, port), timeout)
                }
            }.toInt()
        }.getOrDefault(-1)
    }

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB")
        val digitGroups = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceIn(0, units.lastIndex)
        val value = bytes / 1024.0.pow(digitGroups.toDouble())
        return "%.2f %s".format(value, units[digitGroups])
    }

    fun formatSpeed(bps: Long): String = "${formatBytes(bps)}/s"

    fun isValidUrl(url: String): Boolean = "^https?://.*".toRegex().matches(url)
}
