package com.aerobox.data.repository

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
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
    @Volatile
    private var cachedExplicitPackages: Set<String> = emptySet()

    suspend fun getInstalledApps(
        explicitPackages: Set<String> = emptySet(),
        forceRefresh: Boolean = false
    ): List<InstalledAppInfo> {
        val normalizedExplicitPackages = explicitPackages
            .asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toSet()
        cachedApps?.takeIf {
            !forceRefresh && cachedExplicitPackages == normalizedExplicitPackages
        }?.let { return it }
        return cacheMutex.withLock {
            cachedApps?.takeIf {
                !forceRefresh && cachedExplicitPackages == normalizedExplicitPackages
            }?.let { return@withLock it }
            val loadedApps = withContext(Dispatchers.IO) {
                loadInstalledApps(normalizedExplicitPackages)
            }
            cachedApps = loadedApps
            cachedExplicitPackages = normalizedExplicitPackages
            loadedApps
        }
    }

    private fun loadInstalledApps(explicitPackages: Set<String>): List<InstalledAppInfo> {
        val packageManager = appContext.packageManager
        val visiblePackages = queryVisiblePackageNames(packageManager) + explicitPackages
        return visiblePackages
            .asSequence()
            .mapNotNull { packageName -> getPackageInfoCompat(packageManager, packageName) }
            .distinctBy { it.packageName }
            .filter { info -> info.packageName != appContext.packageName && info.packageName != "android" }
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

    private fun queryVisiblePackageNames(packageManager: PackageManager): Set<String> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val leanbackIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER)
        return buildSet {
            addAll(queryIntentActivitiesCompat(packageManager, launcherIntent))
            addAll(queryIntentActivitiesCompat(packageManager, leanbackIntent))
        }
    }

    @Suppress("DEPRECATION")
    private fun getPackageInfoCompat(
        packageManager: PackageManager,
        packageName: String
    ): PackageInfo? {
        val flags = PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS
        return runCatching {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(flags.toLong())
                )
            } else {
                packageManager.getPackageInfo(packageName, flags)
            }
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun queryIntentActivitiesCompat(
        packageManager: PackageManager,
        intent: Intent
    ): Set<String> {
        val resolveInfos: List<ResolveInfo> =
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageManager.queryIntentActivities(
                    intent,
                    PackageManager.ResolveInfoFlags.of(0)
                )
            } else {
                packageManager.queryIntentActivities(intent, 0)
            }
        return resolveInfos.mapNotNull { resolveInfo ->
            resolveInfo.activityInfo?.packageName ?: resolveInfo.resolvePackageName
        }.toSet()
    }

    private fun ApplicationInfo?.isSystemApp(): Boolean {
        val flags = this?.flags ?: 0
        return (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }
}
