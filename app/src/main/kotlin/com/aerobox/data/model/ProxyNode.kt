package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.Locale

enum class ProxyType {
    SHADOWSOCKS,
    SHADOWSOCKS_2022,
    VMESS,
    VLESS,
    TROJAN,
    HYSTERIA2,
    TUIC,
    SOCKS,
    HTTP;

    fun displayName(): String {
        return name
            .lowercase(Locale.ROOT)
            .split('_')
            .joinToString(" ") { token ->
                token.replaceFirstChar { ch ->
                    if (ch.isLowerCase()) ch.titlecase(Locale.ROOT) else ch.toString()
                }
            }
    }
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
    val transportHost: String? = null,
    val transportPath: String? = null,
    val transportServiceName: String? = null,
    val alpn: String? = null,
    val fingerprint: String? = null,
    val publicKey: String? = null,
    val shortId: String? = null,
    val packetEncoding: String? = null,
    val subscriptionId: Long = 0,
    val latency: Int = -1,
    val createdAt: Long = System.currentTimeMillis(),
    // SOCKS/HTTP auth
    val username: String? = null,
    val allowInsecure: Boolean = false
)
