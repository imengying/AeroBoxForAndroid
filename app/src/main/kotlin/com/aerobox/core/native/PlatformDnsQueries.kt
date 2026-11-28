package com.aerobox.core.`native`

import android.net.DnsResolver
import android.os.CancellationSignal
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/** Android's network-scoped resolver, including Private DNS. No raw socket fallback. */
internal class PlatformDnsQueries(
    private val networks: PhysicalNetworkRegistry,
    private val completion: (Long, ByteArray?, Int, Int, String?) -> Unit = RustCoreNative::completeDnsQuery,
    private val resolver: DnsResolver = DnsResolver.getInstance(),
    private val executor: Executor = callbackExecutor,
) : AutoCloseable {
    private class Query(
        val id: Long,
        val generation: Long,
        val handle: Long,
        val signal: CancellationSignal = CancellationSignal(),
    )
    private val lock = Any()
    private val pending = LinkedHashMap<Long, Query>()
    private var closed = false
    private val observer = networks.addInvalidationListener(::invalidate)

    /** Registration precedes dispatch; native IDs are globally unique u64 bit patterns. */
    fun start(id: Long, generation: Long, handle: Long, message: ByteArray) {
        require(id != 0L) { "DNS query ID must be nonzero" }
        require(message.size in 12..65535) { "DNS query must contain 12..65535 bytes" }
        val query = Query(id, generation, handle)
        var submitted = false
        // Network lookup runs while our own map lock is held so stop/epoch
        // invalidation cannot cancel the query before it has been submitted.
        // Registry never invokes listeners while holding its inventory lock.
        try {
            synchronized(lock) {
                check(!closed) { "Platform DNS transport is closed" }
                check(pending.size < MAX_PENDING) { "Too many platform DNS queries" }
                check(!pending.containsKey(id)) { "Duplicate DNS query ID" }
                val network = networks.networkFor(generation, handle)
                pending[id] = query
                submitted = true
                resolver.rawQuery(
                    network, message.copyOf(), DnsResolver.FLAG_NO_RETRY,
                    executor, query.signal,
                    object : DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(answer: ByteArray, rcode: Int) {
                            // Preserve error RCODE packets; Rust validates the
                            // packet ID/question/RCODE before exposing or caching it.
                            if (answer.size !in 12..65535) {
                                finish(query, null, 0, OsConstants.EIO, "Invalid platform DNS response length")
                                return
                            }
                            try {
                                networks.networkFor(query.generation, query.handle)
                                finish(query, answer, rcode, 0, null)
                            } catch (failure: Exception) {
                                finish(query, null, 0, OsConstants.ECANCELED, "Physical DNS network changed")
                            }
                        }
                        override fun onError(error: DnsResolver.DnsException) {
                            val errno = (error.cause as? ErrnoException)?.errno ?: OsConstants.EIO
                            finish(query, null, 0, errno, error.message ?: "Android DNS query failed")
                        }
                    },
                )
            }
        } catch (failure: Throwable) {
            if (!submitted) throw failure
            if (remove(query)) {
                // Submission can fail after Android has allocated work. Claim
                // the entry before cancelling so a synchronous callback loses.
                cancelSignal(query)
                complete(query.id, null, 0, OsConstants.EIO, failure.message ?: "Android DNS query submission failed")
            }
            // A synchronous result/cancellation may already have won. Preserve
            // that result instead of turning a late submission error into one.
        }
    }

    /** Unknown/late IDs are ignored; the native side serializes start before cancel. */
    fun cancel(id: Long) {
        val query = synchronized(lock) { pending.remove(id) } ?: return
        cancelRemoved(query)
    }

    private fun finish(query: Query, answer: ByteArray?, rcode: Int, errno: Int, message: String?) {
        if (remove(query)) complete(query.id, answer, rcode, errno, message)
    }
    private fun remove(query: Query): Boolean = synchronized(lock) {
            if (pending[query.id] !== query) false
            else { pending.remove(query.id); true }
    }
    private fun invalidate() {
        val old = synchronized(lock) {
            val current = if (closed) null else networks.currentGeneration()
            pending.values.filter { it.generation != current }.also { retired ->
                retired.forEach { pending.remove(it.id) }
            }
        }
        old.forEach(::cancelRemoved)
    }
    private fun cancelRemoved(query: Query) {
        // Remove first: Android can synchronously schedule a callback from cancel.
        // Complete even when Android omits the callback entirely.
        cancelSignal(query)
        complete(query.id, null, 0, OsConstants.ECANCELED, "DNS query cancelled")
    }
    private fun cancelSignal(query: Query) {
        runCatching { query.signal.cancel() }.onFailure {
            Log.w("AeroBoxPlatformDns", "Cannot cancel Android DNS query", it)
        }
    }
    private fun complete(id: Long, answer: ByteArray?, rcode: Int, errno: Int, message: String?) {
        runCatching { completion(id, answer, rcode, errno, message) }.onFailure {
            Log.w("AeroBoxPlatformDns", "Cannot deliver DNS completion", it)
        }
    }
    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
        }
        observer.close()
        invalidate()
    }
    companion object {
        private const val MAX_PENDING = 64
        // Process-wide: late Android callbacks remain accepted after a specific
        // platform closes, avoiding executor-rejection failures on Binder threads.
        private val callbackExecutor = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "aerobox-platform-dns").apply { isDaemon = true }
        }
    }
}
