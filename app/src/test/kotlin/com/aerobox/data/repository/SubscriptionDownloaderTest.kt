package com.aerobox.data.repository

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.*
import org.junit.Test

class SubscriptionDownloaderTest {
    private fun client(text: String, status: Int = 200) = OkHttpClient.Builder().addInterceptor { chain ->
        assertEquals("identity", chain.request().header("Accept-Encoding"))
        Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
            .code(status).message("fixture").header("profile-title", "fixture")
            .body(text.toResponseBody()).build()
    }.build()

    @Test fun readsContentAndMetadataAtExactByteLimit() = runTest {
        val content = "香港 🌏"
        val downloader = HttpSubscriptionDownloader(client(content), content.toByteArray().size.toLong())
        val result = downloader.fetch("https://example.invalid/subscription")
        assertEquals(content, result.content)
        assertEquals("fixture", result.headers["profile-title"])
    }

    @Test fun rejectsOversizedBodyEvenWithoutTrustingContentLength() = runTest {
        try {
            HttpSubscriptionDownloader(client("12345"), 4).fetch("https://example.invalid/subscription")
            fail("Expected bounded download")
        } catch (error: IOException) {
            assertEquals(HttpSubscriptionDownloader.RESPONSE_TOO_LARGE, error.message)
        }
    }

    @Test fun httpFailureDoesNotBecomeAnEmptySubscription() = runTest {
        try {
            HttpSubscriptionDownloader(client("unavailable", 503)).fetch("https://example.invalid/subscription")
            fail("Expected HTTP failure")
        } catch (error: IOException) {
            assertEquals("HTTP 503", error.message)
        }
    }

    @Test fun coroutineCancellationCancelsTheHttpCall() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CountDownLatch(1)
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            entered.complete(Unit)
            check(release.await(5, TimeUnit.SECONDS))
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                .code(200).message("fixture").body("done".toResponseBody()).build()
        }.build()
        lateinit var call: Call
        val downloader = HttpSubscriptionDownloader(Call.Factory { request -> client.newCall(request).also { call = it } })
        val task = async { downloader.fetch("https://example.invalid/subscription") }
        try {
            entered.await()
            task.cancel()
            task.join()
            assertTrue(call.isCanceled())
        } finally {
            release.countDown()
            client.dispatcher.executorService.shutdown()
        }
    }
}
