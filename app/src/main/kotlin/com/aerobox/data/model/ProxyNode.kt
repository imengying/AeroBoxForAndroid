package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class ProxyType {
    SHADOWSOCKS,
    SHADOWSOCKS_2022,
    VMESS,
    VLESS,
    TROJAN,
    HYSTERIA2,
    TUIC,
    WIREGUARD,
    SOCKS,
    HTTP
}

@Entity(tableName = "proxy_nodes")
data class ProxyNode(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val type: ProxyType,
    val server: String,
    val port: Int,
    val uuid: String? = null,
    val password: String? = null,
    val method: String? = null,
    val flow: String? = null,
    val security: String? = null,
    val network: String? = null,
    val tls: Boolean = false,
    val sni: String? = null,
    val alpn: String? = null,
    val fingerprint: String? = null,
    val publicKey: String? = null,
    val shortId: String? = null,
    val subscriptionId: Long = 0,
    val latency: Int = -1,
    val createdAt: Long = System.currentTimeMillis(),
    // SOCKS/HTTP auth
    val username: String? = null,
    // WireGuard specific
    val privateKey: String? = null,
    val localAddress: String? = null,
    val peerPublicKey: String? = null,
    val preSharedKey: String? = null,
    val reserved: String? = null,
    val mtu: Int? = null
)
