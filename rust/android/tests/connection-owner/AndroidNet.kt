package android.net

import java.net.InetAddress
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList

open class ConnectivityManager {
    data class Query(val protocol: Int, val local: InetSocketAddress, val remote: InetSocketAddress)
    val queries = CopyOnWriteArrayList<Query>()
    var lookup: (Query) -> Int = { 10001 }
    open fun getConnectionOwnerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int {
        val query = Query(protocol, local, remote)
        queries.add(query)
        return lookup(query)
    }
}

/** Numeric test double only: it deliberately has no hostname-resolution API. */
object InetAddresses {
    fun parseNumericAddress(value: String): InetAddress {
        if (!value.contains(':')) return InetAddress.getByAddress(ipv4(value))
        require(value.count { it == ':' } <= 7)
        val split = value.split("::")
        require(split.size <= 2)
        fun groups(text: String): List<Int> {
            if (text.isEmpty()) return emptyList()
            val parts = text.split(':')
            return parts.flatMapIndexed { index, part ->
                if (part.contains('.')) {
                    require(index == parts.lastIndex)
                    val bytes = ipv4(part)
                    listOf((bytes[0].toInt() and 255) * 256 + (bytes[1].toInt() and 255),
                        (bytes[2].toInt() and 255) * 256 + (bytes[3].toInt() and 255))
                } else {
                    require(part.length in 1..4)
                    listOf(part.toInt(16))
                }
            }
        }
        val left = groups(split[0])
        val right = if (split.size == 2) groups(split[1]) else emptyList()
        val words = if (split.size == 1) {
            require(left.size == 8); left
        } else {
            require(left.size + right.size < 8)
            left + List(8 - left.size - right.size) { 0 } + right
        }
        val bytes = ByteArray(16)
        words.forEachIndexed { index, word -> bytes[index * 2] = (word ushr 8).toByte(); bytes[index * 2 + 1] = word.toByte() }
        return Inet6Address.getByAddress(null, bytes, -1)
    }
    private fun ipv4(value: String): ByteArray {
        val parts = value.split('.')
        require(parts.size == 4)
        return ByteArray(4) { index ->
            val part = parts[index]
            require(part.isNotEmpty() && part.all { it in '0'..'9' })
            val octet = part.toInt()
            require(octet in 0..255)
            octet.toByte()
        }
    }
}
