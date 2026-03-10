package com.aerobox.data.model

enum class IPv6Mode {
    DISABLE,
    ENABLE;

    fun domainStrategy(): String {
        return when (this) {
            DISABLE -> "ipv4_only"
            ENABLE -> "prefer_ipv4"
        }
    }

    fun enablesIpv6Tun(): Boolean = this != DISABLE
}
