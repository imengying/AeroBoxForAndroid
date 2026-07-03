package com.aerobox.data.database

import android.util.Log
import androidx.room.TypeConverter
import com.aerobox.data.model.ProxyType

class Converters {
    @TypeConverter
    fun fromProxyType(type: ProxyType): String = type.name

    @TypeConverter
    fun toProxyType(value: String): ProxyType =
        runCatching { ProxyType.valueOf(value) }.getOrElse {
            Log.w("Converters", "Unknown ProxyType '$value', falling back to SHADOWSOCKS")
            ProxyType.SHADOWSOCKS
        }
}
