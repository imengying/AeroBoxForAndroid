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
    val type: SubscriptionType = SubscriptionType.BASE64,
    val updateTime: Long = 0,
    val nodeCount: Int = 0,
    val autoUpdate: Boolean = false,
    val updateInterval: Long = 86_400_000,
    val createdAt: Long = System.currentTimeMillis(),
    val trafficBytes: Long = 0,
    val expireTimestamp: Long = 0
)
