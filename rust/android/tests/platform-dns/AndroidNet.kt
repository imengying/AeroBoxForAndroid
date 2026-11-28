package android.net
import android.os.CancellationSignal
import java.util.concurrent.Executor
class Network(val handle: Long)
open class DnsResolver {
    interface Callback<T> { fun onAnswer(answer: T, rcode: Int); fun onError(error: DnsException) }
    class DnsException(message: String, cause: Throwable? = null) : Exception(message, cause)
    data class Request(val network: Network, val bytes: ByteArray, val signal: CancellationSignal, val callback: Callback<ByteArray>)
    val requests = mutableListOf<Request>()
    var dispatch: ((Request) -> Unit)? = null
    open fun rawQuery(network: Network, bytes: ByteArray, flags: Int, executor: Executor, signal: CancellationSignal, callback: Callback<ByteArray>) {
        check(flags == FLAG_NO_RETRY)
        val request = Request(network, bytes, signal, callback)
        requests.add(request)
        dispatch?.invoke(request)
    }
    companion object {
        const val FLAG_NO_RETRY = 1
        fun getInstance() = DnsResolver()
    }
}
