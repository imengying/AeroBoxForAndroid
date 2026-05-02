package com.aerobox.data.model

import androidx.annotation.StringRes
import com.aerobox.R

enum class RoutingMode(@StringRes val labelResId: Int) {
    GLOBAL_PROXY(R.string.routing_mode_global_proxy),
    RULE_BASED(R.string.routing_mode_rule_based),
    DIRECT(R.string.routing_mode_direct)
}
