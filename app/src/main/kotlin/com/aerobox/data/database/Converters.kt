package com.aerobox.data.database

import androidx.room.TypeConverter
import com.aerobox.data.model.ProxyType

class Converters {
    @TypeConverter
    fun fromProxyType(type: ProxyType): String = type.name

    @TypeConverter
    fun toProxyType(value: String): ProxyType = ProxyType.valueOf(value)
}
