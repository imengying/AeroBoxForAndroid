package android.os
class CancellationSignal {
    var cancelled = false
    var onCancel: (() -> Unit)? = null
    fun cancel() { cancelled = true; onCancel?.invoke() }
}
