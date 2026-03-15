package com.aerobox.data.repository

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.aerobox.data.model.InstalledAppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Locale

class AppListRepository(context: Context) {
    private val appContext = context.applicationContext
    private val cacheMutex = Mutex()

    @Volatile
    private var cachedApps: List<InstalledAppInfo>? = null

    suspend fun getInstalledApps(forceRefresh: Boolean = false): List<InstalledAppInfo> {
        cachedApps?.takeIf { !forceRefresh }?.let { return it }
        return cacheMutex.withLock {
            cachedApps?.takeIf { !forceRefresh }?.let { return@withLock it }
            val loadedApps = withContext(Dispatchers.IO) {
                loadInstalledApps()
            }
            cachedApps = loadedApps
            loadedApps
        }
    }

    private fun loadInstalledApps(): List<InstalledAppInfo> {
        val packageManager = appContext.packageManager
        return getInstalledPackagesCompat(packageManager)
            .asSequence()
            .filter { info ->
                info.packageName != appContext.packageName && info.packageName != "android"
            }
            .map { info ->
                InstalledAppInfo(
                    label = info.applicationInfo?.loadLabel(packageManager)?.toString().orEmpty(),
                    packageName = info.packageName,
                    isSystem = info.applicationInfo.isSystemApp(),
                    hasInternetPermission = info.requestedPermissions
                        ?.contains(Manifest.permission.INTERNET) == true,
                    lastUpdateTime = info.lastUpdateTime
                )
            }
            .sortedWith(
                compareBy<InstalledAppInfo> { it.isSystem }
                    .thenBy { it.label.lowercase(Locale.ROOT) }
                    .thenBy { it.packageName.lowercase(Locale.ROOT) }
            )
            .toList()
    }

    @Suppress("DEPRECATION")
    private fun getInstalledPackagesCompat(packageManager: PackageManager): List<PackageInfo> {
        val flags = PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(flags.toLong())
            )
        } else {
            packageManager.getInstalledPackages(flags)
        }
    }

    private fun ApplicationInfo?.isSystemApp(): Boolean {
        val flags = this?.flags ?: 0
        return (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }
}
