package com.aerobox.core.`native`

import android.net.ConnectivityManager
import android.net.Network
import java.util.concurrent.CopyOnWriteArrayList

class PhysicalNetworkRegistry(connectivity: ConnectivityManager, initial: Network?) : AutoCloseable {
    @Volatile var selected = initial
    @Volatile var monitoring = false
    var closes = 0
    init { instances.add(this) }
    fun setDefaultNetwork(network: Network?) { check(closes == 0); selected = network }
    fun start() { onStart(); monitoring = true }
    fun stop() { monitoring = false }
    fun setChangeListener(listener: (() -> Unit)?) {}
    fun snapshotJson() = "{\"default_handle\":${selected?.id}}"
    fun protectOnNetwork(fd: Int, generation: Long, handle: Long, protect: (Int) -> Boolean): Boolean {
        check(selected?.id?.toLong() == handle)
        return protect(fd)
    }
    override fun close() { closes++; monitoring = false }
    companion object {
        val instances = CopyOnWriteArrayList<PhysicalNetworkRegistry>()
        var onStart: () -> Unit = {}
    }
}

class PlatformDnsQueries(registry: PhysicalNetworkRegistry) : AutoCloseable {
    var closes = 0
    init { instances.add(this) }
    fun start(id: Long, generation: Long, handle: Long, message: ByteArray) {}
    fun cancel(id: Long) {}
    override fun close() { closes++ }
    companion object { val instances = CopyOnWriteArrayList<PlatformDnsQueries>() }
}

object RustCoreNative {
    interface PlatformCallbacks {
        fun supportsSystemDns(): Boolean
        fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray)
        fun cancelDnsQuery(id: Long)
        fun physicalNetworks(): String
        fun protectOnNetwork(fd: Int, generation: Long, handle: Long): Boolean
        fun protect(fd: Int): Boolean
        fun dnsServers(): String
        fun storageDirectory(): String
    }
}
