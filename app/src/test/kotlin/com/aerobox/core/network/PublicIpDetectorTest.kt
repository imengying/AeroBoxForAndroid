package com.aerobox.core.network

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PublicIpDetectorTest {
    private class Endpoint(private val reply: (String) -> Pair<Int, String>) : AutoCloseable {
        private val server = ServerSocket(0)
        private val workers = Executors.newCachedThreadPool { runnable -> Thread(runnable).apply { isDaemon = true } }
        val url = "http://127.0.0.1:${server.localPort}"

        init {
            workers.execute {
                while (!server.isClosed) {
                    val socket = try { server.accept() } catch (_: java.io.IOException) { break }
                    workers.execute {
                        socket.use {
                            it.soTimeout = 2000
                            val input = it.getInputStream().bufferedReader()
                            val path = input.readLine().split(' ')[1]
                            while (!input.readLine().isNullOrEmpty()) { }
                            val (status, body) = reply(path)
                            val bytes = body.toByteArray()
                            it.getOutputStream().write("HTTP/1.1 $status Test\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray() + bytes)
                        }
                    }
                }
            }
        }

        override fun close() {
            server.close()
            workers.shutdownNow()
        }
    }

    @Test fun eachFamilyRequiresItsOwnSuccessfulIpResponse() = runBlocking {
        val ipv6Started = CountDownLatch(1)
        val ipv4Completed = CountDownLatch(1)
        Endpoint { path ->
            200 to if (path == "/4") {
                check(ipv6Started.await(2, TimeUnit.SECONDS))
                "203.0.113.8\n"
            } else {
                ipv6Started.countDown()
                check(ipv4Completed.await(2, TimeUnit.SECONDS))
                "2001:db8::8\n"
            }
        }.use { endpoint ->
            val detector = PublicIpDetector { family, _ -> listOf(endpoint.url + if (family == IpFamily.IPV4) "/4" else "/6") }
            try {
                withTimeout(4000) {
                    val v4 = async { detector.detect(IpFamily.IPV4, true) }
                    val v6 = async { detector.detect(IpFamily.IPV6, true) }
                    assertEquals("203.0.113.8", v4.await())
                    ipv4Completed.countDown()
                    assertEquals("2001:db8::8", v6.await())
                }
            } finally { detector.shutdown() }
        }
    }

    @Test fun ipv4ResponseDoesNotProveIpv6Connectivity() = runBlocking {
        Endpoint { 200 to "203.0.113.9" }.use { endpoint ->
            val detector = PublicIpDetector { _, _ -> listOf(endpoint.url) }
            try {
                assertNull(detector.detect(IpFamily.IPV6, true))
                assertEquals("203.0.113.9", detector.detect(IpFamily.IPV4, true))
            } finally { detector.shutdown() }
        }
    }

    @Test fun challengePagesAndOversizedBodiesCannotBecomeSuccessfulProbes() = runBlocking {
        Endpoint { path -> if (path == "/403") 403 to "203.0.113.8" else 200 to "1".repeat(257) }.use { endpoint ->
            val detector = PublicIpDetector { _, _ -> listOf(endpoint.url + "/403", endpoint.url + "/large") }
            try { assertNull(detector.detect(IpFamily.IPV4, true)) } finally { detector.shutdown() }
        }
    }
}
