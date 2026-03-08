package com.aerobox.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class SubscriptionType {
    BASE64,
    JSON,
    YAML,
    SIP008
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
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
    val totalBytes: Long = 0,
    val expireTimestamp: Long = 0
)

val Subscription.info: SubscriptionInfo
    get() = SubscriptionInfo(
        uploadBytes = uploadBytes,
        downloadBytes = downloadBytes,
        totalBytes = totalBytes,
        expireTimestamp = expireTimestamp
    )

fun Subscription.withInfo(info: SubscriptionInfo): Subscription {
    return copy(
        uploadBytes = info.uploadBytes,
        downloadBytes = info.downloadBytes,
        totalBytes = info.totalBytes,
        expireTimestamp = info.expireTimestamp
    )
}
