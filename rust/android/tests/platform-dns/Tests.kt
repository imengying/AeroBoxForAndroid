package com.aerobox.core.`native`
import android.net.DnsResolver
import android.system.ErrnoException
import android.system.OsConstants
import java.util.concurrent.Executor

private data class Result(val id: Long, val bytes: ByteArray?, val rcode: Int, val errno: Int)
private class Fixture {
    val registry = PhysicalNetworkRegistry()
    val resolver = DnsResolver()
    val results = mutableListOf<Result>()
    val queries = PlatformDnsQueries(registry, { id, bytes, rcode, errno, _ -> results.add(Result(id,bytes,rcode,errno)) }, resolver, Executor { it.run() })
    fun start(id: Long = 1) = queries.start(id, registry.generation, registry.handle, ByteArray(12))
}
private inline fun rejects(block: () -> Unit) { check(runCatching(block).isFailure) }
fun main() {
    run {
        val f=Fixture()
        f.resolver.dispatch = { it.callback.onAnswer(ByteArray(12){3},3) }
        f.start(-1L)
        check(f.results.single().id == -1L && f.results.single().rcode == 3 && f.results.single().bytes!!.size == 12)
        val request=f.resolver.requests.single()
        request.callback.onAnswer(ByteArray(12),0)
        f.queries.cancel(-1L)
        check(f.results.size==1 && !request.signal.cancelled)
        f.queries.close()
    }
    run {
        val f=Fixture(); f.start()
        val request=f.resolver.requests.single()
        request.signal.onCancel = { request.callback.onAnswer(ByteArray(12),0) }
        f.queries.cancel(1)
        check(f.results.single().errno==OsConstants.ECANCELED && request.signal.cancelled)
        request.callback.onError(DnsResolver.DnsException("late"))
        check(f.results.size==1)
        f.queries.close()
    }
    run {
        val f=Fixture(); f.start(1); f.start(2)
        f.registry.invalidate()
        check(f.results.size==2 && f.results.all { it.errno==OsConstants.ECANCELED })
        check(f.resolver.requests.all { it.signal.cancelled })
        f.resolver.requests.forEach { it.callback.onAnswer(ByteArray(12),0) }
        check(f.results.size==2)
        f.start(3); f.queries.close()
        check(f.results.last().id==3L && f.results.last().errno==OsConstants.ECANCELED)
        rejects { f.start(4) }
    }
    run {
        val f=Fixture(); repeat(64) { f.start(it.toLong()+1) }
        rejects { f.start(65) }; rejects { f.start(1) }
        check(f.resolver.requests.size==64)
        f.resolver.requests[0].signal.onCancel = { error("cancel listener failed") }
        f.queries.close()
        check(f.results.size==64 && f.resolver.requests.all { it.signal.cancelled })
    }
    run {
        val f=Fixture()
        rejects { f.queries.start(0,1,-1,ByteArray(12)) }
        rejects { f.queries.start(1,1,-1,ByteArray(11)) }
        rejects { f.queries.start(1,1,-1,ByteArray(65536)) }
        rejects { f.queries.start(1,2,-1,ByteArray(12)) }
        check(f.resolver.requests.isEmpty())
        f.resolver.dispatch = { throw IllegalStateException("submission failed") }
        f.start(1)
        check(f.results.single().errno==OsConstants.EIO)
        check(f.resolver.requests.single().signal.cancelled)
        f.resolver.dispatch = null
        f.start(2); f.resolver.requests.last().callback.onError(DnsResolver.DnsException("denied",ErrnoException(13)))
        check(f.results.last().errno==13)
        f.start(3); f.resolver.requests.last().callback.onAnswer(ByteArray(11),0)
        check(f.results.last().errno==OsConstants.EIO)
        f.start(4); f.registry.active=false; f.resolver.requests.last().callback.onAnswer(ByteArray(12),0)
        check(f.results.last().errno==OsConstants.ECANCELED)
        f.queries.close()
    }
    run {
        // A snapshot can expose the new epoch before its invalidation listener
        // gets CPU time. Preserve queries submitted against that new snapshot.
        val f=Fixture(); f.start(1)
        f.registry.generation++
        f.start(2)
        f.registry.notifyInvalidated()
        check(f.results.single().id==1L && f.results.single().errno==OsConstants.ECANCELED)
        check(f.resolver.requests[0].signal.cancelled && !f.resolver.requests[1].signal.cancelled)
        f.resolver.requests[1].callback.onAnswer(ByteArray(12),0)
        check(f.results.size==2 && f.results.last().id==2L && f.results.last().errno==0)
        f.queries.close()
    }
    run {
        // Synchronous completion and partial submission failure both follow
        // the same first-result-wins contract as cancellation/late callbacks.
        val f=Fixture()
        f.resolver.dispatch = { it.callback.onAnswer(ByteArray(12),0); error("late dispatch failure") }
        f.start(1)
        check(f.results.single().id==1L && f.results.single().errno==0)
        check(!f.resolver.requests[0].signal.cancelled)
        f.resolver.dispatch = {
            it.signal.onCancel = { it.callback.onAnswer(ByteArray(12),0) }
            error("partial submission failed")
        }
        f.start(2)
        check(f.results.size==2 && f.results.last().id==2L && f.results.last().errno==OsConstants.EIO)
        check(f.resolver.requests[1].signal.cancelled)
        f.resolver.requests[1].callback.onError(DnsResolver.DnsException("late"))
        check(f.results.size==2)
        f.queries.close()
    }
    println("Platform DNS boundary: 7 groups passed")
}
