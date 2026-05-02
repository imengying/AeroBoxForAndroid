package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class SubscriptionType {
    BASE64,
    JSON,
    YAML
}

@Entity(tableName = "subscriptions")
data class Subscription(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val url: String,
    // Reserved column. Currently no consumer reads this value; SubscriptionRepository
    // intentionally does not overwrite it on import/update so the field stays at the
    // default. Keep the column to preserve Room schema compatibility — once a real
    // use-case appears, write a Migration before changing the type semantics.
    val type: SubscriptionType = SubscriptionType.BASE64,
    val updateTime: Long = 0,
    val nodeCount: Int = 0,
    val autoUpdate: Boolean = false,
    val updateInterval: Long = 86_400_000,
    val createdAt: Long = System.currentTimeMillis(),
    val trafficBytes: Long = 0,
    val expireTimestamp: Long = 0
)

// A Subscription with a blank url is treated as a "local group" — a user-managed
// container for nodes imported from local files, QR codes, or manual paste. These
// groups do not participate in remote refresh and are the only valid targets for
// moving manually-imported nodes.
fun Subscription.isLocalGroup(): Boolean = url.isBlank()
