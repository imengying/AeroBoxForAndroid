package com.aerobox.core.`native`
import android.net.Network
class PhysicalNetworkRegistry {
    var generation = 1L
    var active = true
    var handle = -1L
    private val listeners = mutableSetOf<() -> Unit>()
    fun networkFor(expected: Long, selected: Long): Network {
        check(active && expected == generation && selected == handle) { "stale network" }
        return Network(handle)
    }
    fun currentGeneration(): Long? = generation.takeIf { active }
    fun addInvalidationListener(listener: () -> Unit): AutoCloseable {
        listeners.add(listener)
        return AutoCloseable { listeners.remove(listener) }
    }
    fun invalidate() { generation++; notifyInvalidated() }
    fun notifyInvalidated() { listeners.toList().forEach { it() } }
}
object RustCoreNative {
    fun completeDnsQuery(id: Long, bytes: ByteArray?, rcode: Int, errno: Int, message: String?): Unit = error("unexpected real JNI")
}
