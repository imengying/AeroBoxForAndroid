package com.aerobox.data.repository

import java.io.IOException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class SubscriptionDownload(val content: String, val headers: Headers)

fun interface SubscriptionDownloader {
    suspend fun fetch(url: String): SubscriptionDownload
}

class HttpSubscriptionDownloader(
    private val calls: Call.Factory,
    private val maxBytes: Long = 8L * 1024 * 1024
) : SubscriptionDownloader {
    companion object {
        const val RESPONSE_TOO_LARGE = "SUBSCRIPTION_RESPONSE_TOO_LARGE"
        private const val SUBSCRIPTION_USER_AGENT = "clash-verge/v1.3.8"
    }

    override suspend fun fetch(url: String): SubscriptionDownload =
        suspendCancellableCoroutine { cont ->
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", SUBSCRIPTION_USER_AGENT)
                .header("Accept-Encoding", "identity")
                .header("Connection", "keep-alive")
                .build()
            val call = calls.newCall(request)
            cont.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!cont.isActive) return
                        val result = runCatching {
                            if (!it.isSuccessful) {
                                throw IOException("HTTP ${it.code}")
                            }
                            SubscriptionDownload(
                                content = readBoundedBody(it.body, maxBytes),
                                headers = it.headers
                            )
                        }
                        if (!cont.isActive) return
                        result
                            .onSuccess { fetchResult ->
                                cont.resume(fetchResult)
                            }
                            .onFailure { error ->
                                cont.resumeWithException(error)
                            }
                    }
                }
                override fun onFailure(call: Call, e: IOException) {
                    if (cont.isActive) {
                        cont.resumeWithException(e)
                    }
                }
            })
        }

    /**
     * Read a [ResponseBody] into a UTF-8 string while enforcing an upper bound.
     *
     * Uses Okio to consume up to [maxBytes] from the source, then peeks one
     * additional byte. If any data remains the body exceeded the limit and we
     * abort instead of buffering the rest. This keeps memory usage bounded on
     * a hostile server even when `Content-Length` is missing or lies.
     */
    private fun readBoundedBody(body: ResponseBody, maxBytes: Long): String {
        val source = body.source()
        val buffer = Buffer()
        var remaining = maxBytes
        while (remaining > 0) {
            val read = source.read(buffer, remaining)
            if (read == -1L) break
            remaining -= read
        }
        if (source.request(1)) {
            throw IOException(RESPONSE_TOO_LARGE)
        }
        return buffer.readString(Charsets.UTF_8)
    }

}
