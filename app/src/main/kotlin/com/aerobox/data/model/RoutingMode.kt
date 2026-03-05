package com.aerobox.data.model

enum class RoutingMode(val displayName: String) {
    GLOBAL_PROXY("全局代理"),
    RULE_BASED("规则分流"),
    DIRECT("直连模式")
}
