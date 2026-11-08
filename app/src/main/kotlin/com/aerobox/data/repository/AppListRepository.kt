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

class AppListRepository internal constructor(
    private val loadApps: () -> List<InstalledAppInfo>
) {
    constructor(context: Context) : this(loadApps = context.applicationContext.let { appContext ->
        { loadInstalledApps(appContext) }
    })

    private val cacheMutex = Mutex()

    @Volatile
    private var cachedApps: List<InstalledAppInfo>? = null

    suspend fun getInstalledApps(
        forceRefresh: Boolean = false
    ): List<InstalledAppInfo> {
        cachedApps?.takeIf { !forceRefresh }?.let { return it }
        return cacheMutex.withLock {
            cachedApps?.takeIf { !forceRefresh }?.let { return@withLock it }
            val loadedApps = withContext(Dispatchers.IO) {
                loadApps()
            }
            // Some systems temporarily return no packages while access is restricted.
            // A later attempt must query PackageManager again instead of caching that failure.
            cachedApps = loadedApps.takeIf { it.isNotEmpty() }
            loadedApps
        }
    }

    companion object {
        private fun loadInstalledApps(appContext: Context): List<InstalledAppInfo> {
            val packageManager = appContext.packageManager
            return getInstalledPackages(packageManager)
                .asSequence()
                .filter { info -> info.packageName != appContext.packageName && info.packageName != "android" }
                .map { info ->
                    InstalledAppInfo(
                        label = appLabel(info.packageName) {
                            info.applicationInfo?.loadLabel(packageManager)?.toString()
                        },
                        packageName = info.packageName,
                        isSystem = info.applicationInfo.isSystemApp(),
                        hasInternetPermission = info.requestedPermissions
                            ?.contains(Manifest.permission.INTERNET) == true
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
        private fun getInstalledPackages(packageManager: PackageManager): List<PackageInfo> {
            val flags = PackageManager.GET_PERMISSIONS
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

        internal fun appLabel(packageName: String, loadLabel: () -> String?): String = try {
            loadLabel()?.takeIf { it.isNotBlank() } ?: packageName
        } catch (_: Exception) {
            // A removed package or broken resource must not hide every other app.
            packageName
        }
    }
}
