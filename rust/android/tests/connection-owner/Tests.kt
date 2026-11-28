package com.aerobox.core.`native`

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors

private class Fixture {
    val connectivity = ConnectivityManager()
    val packages = PackageManager()
    val owners = ConnectionOwners(connectivity, packages)
    fun query(protocol: Int = 6, source: String = "172.19.0.2", sourcePort: Int = 48123,
        destination: String = "198.18.1.8", destinationPort: Int = 443) =
        owners.find(protocol, source, sourcePort, destination, destinationPort)
}

private fun originalIpv4TupleAndSharedUid() {
    val f = Fixture()
    f.connectivity.lookup = { 10123 }
    f.packages.lookup = { arrayOf("z.owner", "a.owner", "z.owner", "", "  ", null) }
    check(f.query() == "{\"uid\":10123,\"packages\":[\"a.owner\",\"z.owner\"]}")
    val query = f.connectivity.queries.single()
    check(query.protocol == 6 && query.local.port == 48123 && query.remote.port == 443)
    check(query.local.address.hostAddress == "172.19.0.2")
    // The original synthetic destination is preserved for Android's socket
    // table lookup. DNS/FakeIP restoration must never happen in this adapter.
    check(query.remote.address.hostAddress == "198.18.1.8")
    check(!query.local.isUnresolved && !query.remote.isUnresolved)
    check(f.packages.queries.single() == 10123)
}

private fun originalIpv6UdpAndUidZero() {
    val f = Fixture()
    f.connectivity.lookup = { 0 }
    check(f.query(17, "fd00::2", 1, "2001:db8:1:2:3:4:5:6", 65535) == "{\"uid\":0,\"packages\":[]}")
    val query = f.connectivity.queries.single()
    check(query.protocol == 17 && query.local.port == 1 && query.remote.port == 65535)
    check(query.local.address.address.contentEquals(byteArrayOf(0xfd.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)))
    check(query.remote.address.address.contentEquals(byteArrayOf(0x20, 1, 0x0d, 0xb8.toByte(), 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6)))
}

private fun invalidInputNeverCallsAndroid() {
    val f = Fixture()
    listOf(-1, 0, 1, 58, 256).forEach { check(f.query(protocol = it) == "null") }
    listOf(-1, 0, 65536, Int.MAX_VALUE).forEach {
        check(f.query(sourcePort = it) == "null")
        check(f.query(destinationPort = it) == "null")
    }
    listOf("", "example.com", "dead.beef", "1234", "1.2.3.999", " 1.2.3.4", "1.2.3.4\n",
        "[2001:db8::1]", "fe80::1%wlan0", "fe80::1%3", "::gg", ":::1", "a".repeat(46)).forEach {
        check(f.query(source = it) == "null")
        check(f.query(destination = it) == "null")
    }
    check(f.query(source = "2001:db8::1") == "null")
    check(f.query(source = "0.0.0.0") == "null")
    check(f.query(destination = "224.0.0.1") == "null")
    check(f.query(source = "::", destination = "2001:db8::1") == "null")
    check(f.query(source = "2001:db8::1", destination = "ff02::1") == "null")
    check(f.connectivity.queries.isEmpty() && f.packages.queries.isEmpty())
}

private fun lookupFailuresAreUnknown() {
    val f = Fixture()
    listOf(-1, -2, Int.MIN_VALUE).forEach { uid ->
        f.connectivity.lookup = { uid }; check(f.query() == "null")
    }
    check(f.packages.queries.isEmpty())
    f.connectivity.lookup = { throw SecurityException("not the active VPN") }
    check(f.query() == "null")
    f.connectivity.lookup = { Int.MAX_VALUE }
    f.packages.lookup = { throw IllegalStateException("package service unavailable") }
    check(f.query() == "null")
    f.packages.lookup = { null }
    check(f.query() == "{\"uid\":2147483647,\"packages\":[]}")
}

private fun packageLimitsPreserveCompleteOwnership() {
    val f = Fixture()
    f.packages.lookup = { Array(64) { "app.p${it.toString().padStart(2, '0')}" } }
    val answer = f.query()
    check(answer.count { it == ',' } == 64 && answer.length < 32768)
    f.packages.lookup = { Array(256) { "shared.owner" } }
    check(f.query() == "{\"uid\":10001,\"packages\":[\"shared.owner\"]}")
    f.packages.lookup = { Array(65) { "app.p$it" } }; check(f.query() == "null")
    f.packages.lookup = { Array(257) { "shared.owner" } }; check(f.query() == "null")
    listOf("a".repeat(256), "a.\"b", "a.\\b", "a.b c", "a.中文", "a.\u0000b", "a..b", ".ab", "ab.", "1.ab", "a.1b").forEach { name ->
        f.packages.lookup = { arrayOf(name) }; check(f.query() == "null")
    }
    f.packages.lookup = { arrayOf("a".repeat(255)) }
    check(f.query() != "null")
    f.packages.lookup = { arrayOf("_owner.p\$1") }
    check(f.query() == "{\"uid\":10001,\"packages\":[\"_owner.p\$1\"]}")
}

private fun concurrentLookupsKeepTheirOwnTuple() {
    val f = Fixture()
    val barrier = CountDownLatch(2)
    f.connectivity.lookup = { query ->
        barrier.countDown()
        check(barrier.await(2, TimeUnit.SECONDS))
        query.local.port
    }
    f.packages.lookup = { uid -> arrayOf("owner.p$uid") }
    val workers = Executors.newFixedThreadPool(2)
    try {
        val first = workers.submit<String> { f.query(sourcePort = 12001) }
        val second = workers.submit<String> { f.query(sourcePort = 12002) }
        check(first.get(3, TimeUnit.SECONDS) == "{\"uid\":12001,\"packages\":[\"owner.p12001\"]}")
        check(second.get(3, TimeUnit.SECONDS) == "{\"uid\":12002,\"packages\":[\"owner.p12002\"]}")
    } finally {
        workers.shutdownNow()
    }
}

fun main() {
    val cases = listOf(::originalIpv4TupleAndSharedUid, ::originalIpv6UdpAndUidZero,
        ::invalidInputNeverCallsAndroid, ::lookupFailuresAreUnknown,
        ::packageLimitsPreserveCompleteOwnership, ::concurrentLookupsKeepTheirOwnTuple)
    for (case in cases) { case(); println("PASS ${case.name}") }
    println("Connection owner boundary: ${cases.size} groups passed")
}
