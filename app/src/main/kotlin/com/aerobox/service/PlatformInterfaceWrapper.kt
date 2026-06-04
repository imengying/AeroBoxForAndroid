package com.aerobox.service

import android.net.NetworkCapabilities
import android.os.Process
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import com.aerobox.AeroBoxApplication
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.security.KeyStore
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface

/**
 * Default implementation of PlatformInterface for AeroBox.
 * Modeled after SFA's PlatformInterfaceWrapper.
 */
interface PlatformInterfaceWrapper : PlatformInterface {

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        // Subclass (VpnService) should override to call protect(fd)
    }

    override fun openTun(options: TunOptions): Int {
        error("openTun not implemented — must be overridden by VpnService")
    }

    override fun useProcFS(): Boolean = false

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        return runCatching {
            val connectivity = AeroBoxApplication.connectivity
            val uid = connectivity.getConnectionOwnerUid(
                ipProtocol,
                InetSocketAddress(sourceAddress, sourcePort),
                InetSocketAddress(destinationAddress, destinationPort),
            )
            if (uid == Process.INVALID_UID) {
                return emptyConnectionOwner()
            }
            val packages = AeroBoxApplication.appInstance.packageManager.getPackagesForUid(uid)
            val packageName = packages?.firstOrNull() ?: ""
            val owner = ConnectionOwner()
            owner.userId = uid
            owner.userName = packageName
            owner.setAndroidPackageNameCompat(packageName)
            return owner
        }.getOrElse {
            emptyConnectionOwner()
        }
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        DefaultNetworkMonitor.setListener(listener)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        DefaultNetworkMonitor.setListener(null)
    }

    @Suppress("DEPRECATION")
    override fun getInterfaces(): NetworkInterfaceIterator {
        val connectivity = AeroBoxApplication.connectivity
        val networks = connectivity.allNetworks
        val networkInterfaces = NetworkInterface.getNetworkInterfaces().toList()
        val interfaces = mutableListOf<LibboxNetworkInterface>()

        for (network in networks) {
            val boxInterface = LibboxNetworkInterface()
            val linkProperties = connectivity.getLinkProperties(network) ?: continue
            val networkCapabilities = connectivity.getNetworkCapabilities(network) ?: continue

            boxInterface.name = linkProperties.interfaceName
            val netIf = networkInterfaces.find { it.name == boxInterface.name } ?: continue

            boxInterface.dnsServer = StringArray(
                linkProperties.dnsServers.mapNotNull { it.hostAddress }.iterator()
            )
            boxInterface.type = when {
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                else -> Libbox.InterfaceTypeOther
            }
            boxInterface.index = netIf.index
            runCatching { boxInterface.mtu = netIf.mtu }
            boxInterface.addresses = StringArray(
                netIf.interfaceAddresses.map { it.toPrefix() }.iterator()
            )

            var flags = 0
            if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                flags = 0x1 or 0x40 // IFF_UP | IFF_RUNNING
            }
            if (netIf.isLoopback) flags = flags or 0x8      // IFF_LOOPBACK
            if (netIf.isPointToPoint) flags = flags or 0x10  // IFF_POINTOPOINT
            if (netIf.supportsMulticast()) flags = flags or 0x1000 // IFF_MULTICAST
            boxInterface.flags = flags
            boxInterface.metered =
                !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            interfaces.add(boxInterface)
        }
        return InterfaceArray(interfaces.iterator())
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun clearDNSCache() {}

    override fun readWIFIState(): WIFIState? = null

    override fun localDNSTransport(): LocalDNSTransport? = LocalResolverTransport

    override fun systemCertificates(): StringIterator {
        // Wrap the whole walk: KeyStore.load / aliases / getCertificate may
        // each throw KeyStoreException / CertificateEncodingException, and
        // libbox calls this from a JNI thread where an unhandled exception
        // would surface as a Go panic.
        val certificates = runCatching {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            buildList {
                val aliases = keyStore.aliases()
                while (aliases.hasMoreElements()) {
                    val cert = runCatching {
                        keyStore.getCertificate(aliases.nextElement())
                    }.getOrNull() ?: continue
                    val encoded = runCatching { cert.encoded }.getOrNull() ?: continue
                    add(
                        "-----BEGIN CERTIFICATE-----\n" +
                                android.util.Base64.encodeToString(
                                    encoded,
                                    android.util.Base64.NO_WRAP
                                ) +
                                "\n-----END CERTIFICATE-----"
                    )
                }
            }
        }.getOrDefault(emptyList())
        return StringArray(certificates.iterator())
    }

    // ── Iterator helpers ──

    private class InterfaceArray(
        private val iterator: Iterator<LibboxNetworkInterface>
    ) : NetworkInterfaceIterator {
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): LibboxNetworkInterface = iterator.next()
    }

    class StringArray(private val iterator: Iterator<String>) : StringIterator {
        override fun len(): Int = 0 // not used by core
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): String = iterator.next()
    }

    private fun emptyConnectionOwner(): ConnectionOwner {
        return ConnectionOwner().apply {
            userId = Process.INVALID_UID
            userName = ""
            setAndroidPackageNameCompat("")
        }
    }
}

private fun ConnectionOwner.setAndroidPackageNameCompat(value: String) {
    val setterNames = listOf("setAndroidPackageName", "setPackageName")
    for (setterName in setterNames) {
        val setter = javaClass.methods.firstOrNull { method ->
            method.name == setterName &&
                method.parameterCount == 1 &&
                method.parameterTypes.firstOrNull() == String::class.java
        }
        if (setter != null) {
            runCatching { setter.invoke(this, value) }
            return
        }
    }

    val fieldNames = listOf("androidPackageName", "packageName")
    for (fieldName in fieldNames) {
        val field = runCatching { javaClass.getField(fieldName) }.getOrNull() ?: continue
        runCatching { field.set(this, value) }
        return
    }
}

private fun InterfaceAddress.toPrefix(): String = if (address is Inet6Address) {
    "${Inet6Address.getByAddress(address.address).hostAddress}/$networkPrefixLength"
} else {
    "${address.hostAddress}/$networkPrefixLength"
}
