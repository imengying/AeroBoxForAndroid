package com.aerobox.data.model

enum class IPv6Mode {
    DISABLE,
    ENABLE;

    fun displayName(): String {
        return when (this) {
            DISABLE -> "关闭"
            ENABLE -> "启用"
        }
    }

    fun domainStrategy(): String {
        return when (this) {
            DISABLE -> "ipv4_only"
            ENABLE -> "prefer_ipv6"
        }
    }

    fun enablesIpv6Tun(): Boolean = this != DISABLE

    fun usesIpv6OnlyTun(): Boolean = false
}
