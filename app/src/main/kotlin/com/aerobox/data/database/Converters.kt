package com.aerobox.data.database

import androidx.room.TypeConverter
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.SubscriptionType

class Converters {
    @TypeConverter
    fun fromProxyType(type: ProxyType): String = type.name

    @TypeConverter
    fun toProxyType(value: String): ProxyType =
        runCatching { ProxyType.valueOf(value) }.getOrDefault(ProxyType.SHADOWSOCKS)

    @TypeConverter
    fun fromSubscriptionType(type: SubscriptionType): String = type.name

    @TypeConverter
    fun toSubscriptionType(value: String): SubscriptionType =
        runCatching { SubscriptionType.valueOf(value) }.getOrDefault(SubscriptionType.BASE64)
}
