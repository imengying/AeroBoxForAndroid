package com.aerobox.core.`native`

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.InetAddresses
import java.net.InetAddress
import java.net.InetSocketAddress

/** Diagnostic attribution for original TUN tuples, before DNS/FakeIP rewriting. */
internal class ConnectionOwners(
    private val connectivity: ConnectivityManager,
    private val packages: PackageManager,
) {
    /** Binder calls are scheduled and bounded by the native owner-lookup worker. */
    fun find(ipProtocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int): String {
        return try {
            if (ipProtocol != 6 && ipProtocol != 17) return UNKNOWN
            if (sourcePort !in 1..65535 || destinationPort !in 1..65535) return UNKNOWN
            val local = numericAddress(source) ?: return UNKNOWN
            val remote = numericAddress(destination) ?: return UNKNOWN
            if (local.address.size != remote.address.size) return UNKNOWN
            if (local.isAnyLocalAddress || remote.isAnyLocalAddress ||
                local.isMulticastAddress || remote.isMulticastAddress) return UNKNOWN
            val uid = connectivity.getConnectionOwnerUid(
                ipProtocol, InetSocketAddress(local, sourcePort), InetSocketAddress(remote, destinationPort),
            )
            // Android represents INVALID_UID as -1; no negative value can
            // represent an application UID. Never reinterpret it as unsigned.
            if (uid < 0) return UNKNOWN
            val reported = packages.getPackagesForUid(uid).orEmpty()
            if (reported.size > MAX_REPORTED_PACKAGES) return UNKNOWN
            val names = sortedSetOf<String>()
            for (name in reported) {
                if (name.isNullOrBlank()) continue
                if (name.length > MAX_PACKAGE_LENGTH || !name.all(::packageCharacter) ||
                    name.split('.').any { it.isEmpty() || !packageStart(it[0]) }) return UNKNOWN
                names.add(name)
                // Preserve all shared-UID owners, or return unknown. A truncated
                // package list could falsely imply one application's ownership.
                if (names.size > MAX_PACKAGES) return UNKNOWN
            }
            buildString {
                append("{\"uid\":").append(uid).append(",\"packages\":[")
                names.forEachIndexed { index, name ->
                    if (index != 0) append(',')
                    // Android package identifiers are bounded ASCII. Rejecting
                    // other input above also makes this JSON escaping exact.
                    append('"').append(name).append('"')
                }
                append("]}")
            }
        } catch (_: Exception) {
            // Permission changes, a vanished socket/app, and Binder errors are
            // unknown diagnostic metadata, never reasons to terminate a flow.
            UNKNOWN
        }
    }

    private fun numericAddress(value: String): InetAddress? {
        if (value.isEmpty() || value.length > 45 || !value.all(::addressCharacter)) return null
        // No getByName or String-based InetSocketAddress: even an unexpected
        // hostname must never trigger platform DNS from owner attribution.
        return InetAddresses.parseNumericAddress(value)
    }

    companion object {
        private const val UNKNOWN = "null"
        private const val MAX_PACKAGES = 64
        private const val MAX_REPORTED_PACKAGES = 256
        private const val MAX_PACKAGE_LENGTH = 255
        private fun addressCharacter(value: Char) = value in '0'..'9' || value in 'a'..'f' ||
            value in 'A'..'F' || value == ':' || value == '.'
        private fun packageStart(value: Char) = value in 'a'..'z' || value in 'A'..'Z' || value == '_'
        private fun packageCharacter(value: Char) = packageStart(value) ||
            value in '0'..'9' || value == '.' || value == '$'
    }
}
