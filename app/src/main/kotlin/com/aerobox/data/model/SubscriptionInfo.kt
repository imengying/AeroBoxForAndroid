package com.aerobox.data.model

data class SubscriptionInfo(
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
    val totalBytes: Long = 0,
    val expireTimestamp: Long = 0
) {
    val usedBytes: Long
        get() = (uploadBytes + downloadBytes).coerceAtLeast(0L)

    val remainingBytes: Long
        get() = if (hasTrafficQuota) {
            (totalBytes - usedBytes).coerceAtLeast(0L)
        } else {
            0L
        }

    val hasTrafficQuota: Boolean
        get() = totalBytes > 0L

    // Best-effort flag for subscriptions that expose some usage/expiry metadata
    // but do not provide a total quota.
    val hasUnlimitedTraffic: Boolean
        get() = !hasTrafficQuota && hasAnyInfo

    val progress: Float
        get() = if (hasTrafficQuota && totalBytes > 0L) {
            (usedBytes.toDouble() / totalBytes.toDouble())
                .coerceIn(0.0, 1.0)
                .toFloat()
        } else {
            0f
        }

    val hasExpiry: Boolean
        get() = expireTimestamp > 0L

    val hasAnyInfo: Boolean
        get() = hasTrafficQuota || usedBytes > 0L || hasExpiry
}
