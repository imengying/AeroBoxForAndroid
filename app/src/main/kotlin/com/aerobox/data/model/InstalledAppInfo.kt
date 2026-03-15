package com.aerobox.data.model

data class InstalledAppInfo(
    val label: String,
    val packageName: String,
    val isSystem: Boolean,
    val hasInternetPermission: Boolean,
    val lastUpdateTime: Long
)
