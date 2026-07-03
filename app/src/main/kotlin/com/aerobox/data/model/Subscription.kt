package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "subscriptions")
data class Subscription(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val url: String,
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
