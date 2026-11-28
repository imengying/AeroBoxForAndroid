package com.aerobox.core.`native`

import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress

/** Creates the Android TUN described by ConfigGenerator. */
class RustTunController(private val service: VpnService) {
    data class Applications(val include: Set<String> = emptySet(), val exclude: Set<String> = emptySet()) {
        init { require(include.isEmpty() || exclude.isEmpty()) { "Choose include or exclude applications" } }
    }

    /** Caller owns the descriptor. RustCoreNative.start duplicates it. */
    fun establish(configJson: String, applications: Applications, network: Network?): ParcelFileDescriptor {
        check(VpnService.prepare(service) == null) { "VPN permission is required" }
        val config = JSONObject(configJson)
        val inbounds = config.getJSONArray("inbounds")
        val tunnels = (0 until inbounds.length()).map { inbounds.getJSONObject(it) }.filter { it.optString("type") == "tun" }
        require(tunnels.size == 1) { "Exactly one Android TUN inbound is required" }
        val tun = tunnels.single()
        val addresses = strings(tun.opt("address")).map(::prefix)
        require(addresses.isNotEmpty()) { "TUN requires numeric IP addresses with prefixes" }
        val mtu = tun.optInt("mtu", 9000)
        require(mtu in 576..65535) { "Invalid TUN MTU" }
        val builder = service.Builder().setSession("AeroBox").setMtu(mtu)
        addresses.forEach { (address, length) -> builder.addAddress(address, length) }
        builder.setMetered(false)
        builder.setUnderlyingNetworks(network?.let { arrayOf(it) } ?: emptyArray())
        if (tun.optBoolean("auto_route", true)) {
            val routes = strings(tun.opt("route_address")).map(::prefix)
            if (routes.isEmpty()) {
                if (addresses.any { it.first.address.size == 4 }) builder.addRoute("0.0.0.0", 0)
                if (addresses.any { it.first.address.size == 16 }) builder.addRoute("::", 0)
            } else routes.forEach { (address, length) -> builder.addRoute(address, length) }
            val excluded = strings(tun.opt("route_exclude_address")).map(::prefix)
            require(excluded.isEmpty() || Build.VERSION.SDK_INT >= 33) { "Excluded routes require Android 13" }
            if (Build.VERSION.SDK_INT >= 33) excluded.forEach { (address, length) -> builder.excludeRoute(IpPrefix(address, length)) }
            // A DNS address assigned to this interface is routed locally by
            // Android and never reaches the core's TUN interception. Use the
            // next unassigned address within the prefix for each IP family.
            addresses.distinctBy { it.first.address.size }.forEach { (address, length) ->
                builder.addDnsServer(dnsAddress(address, length, addresses))
            }
        }
        // Saved selections can outlive an installed package. Ignore only that
        // condition; permission and platform failures must still abort startup.
        var allowedApplications = 0
        applications.include.forEach { packageName ->
            try {
                builder.addAllowedApplication(packageName)
                allowedApplications++
            } catch (_: PackageManager.NameNotFoundException) {
                // A missing package has no traffic to include.
            }
        }
        check(applications.include.isEmpty() || allowedApplications > 0) {
            "None of the selected VPN applications are installed"
        }
        applications.exclude.forEach { packageName ->
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: PackageManager.NameNotFoundException) {
                // A missing package has no traffic to exclude.
            }
        }
        return checkNotNull(builder.establish()) { "Android could not establish TUN" }
    }

    private fun strings(value: Any?): List<String> = when (value) {
        null, JSONObject.NULL -> emptyList()
        is String -> listOf(value)
        is JSONArray -> (0 until value.length()).map(value::getString)
        else -> error("Expected address string or array")
    }

    private fun dnsAddress(address: InetAddress, prefixLength: Int, configured: List<Pair<InetAddress, Int>>): InetAddress {
        val original = address.address
        val next = original.copyOf()
        var index = next.lastIndex
        while (index >= 0 && (next[index].toInt() and 0xff) == 0xff) {
            next[index] = 0
            index--
        }
        require(index >= 0) { "TUN prefix has no next address for DNS: ${address.hostAddress}/$prefixLength" }
        next[index] = ((next[index].toInt() and 0xff) + 1).toByte()

        fun prefixMask(byteIndex: Int): Int {
            val bits = (prefixLength - byteIndex * 8).coerceIn(0, 8)
            return (0xff shl (8 - bits)) and 0xff
        }
        require(original.indices.all { byteIndex ->
            ((original[byteIndex].toInt() xor next[byteIndex].toInt()) and prefixMask(byteIndex)) == 0
        }) { "TUN prefix has no next address for DNS: ${address.hostAddress}/$prefixLength" }

        // IPv4 /31 prefixes are point-to-point pairs and have no broadcast address.
        require(original.size != 4 || prefixLength >= 31 || original.indices.any { byteIndex ->
            val hostMask = prefixMask(byteIndex) xor 0xff
            (next[byteIndex].toInt() and hostMask) != hostMask
        }) { "Next TUN address for DNS is an IPv4 broadcast address" }

        val candidate = InetAddress.getByAddress(next)
        require(configured.none { it.first == candidate }) {
            "Next TUN address for DNS is already assigned to the interface: ${candidate.hostAddress}"
        }
        return candidate
    }

    private fun prefix(value: String): Pair<InetAddress, Int> {
        val parts = value.split('/')
        require(parts.size == 2 && parts[0].matches(Regex("[0-9a-fA-F:.]+"))) { "Expected numeric IP/prefix: $value" }
        val ip = InetAddress.getByName(parts[0])
        val bits = parts[1].toInt()
        require(bits in 0..(ip.address.size * 8)) { "Invalid prefix: $value" }
        return ip to bits
    }
}
