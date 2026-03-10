package com.aerobox.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.aerobox.data.repository.SubscriptionRepository
import kotlinx.coroutines.flow.first
import java.util.concurrent.TimeUnit

object SubscriptionUpdateScheduler {
    private const val WORK_NAME = "aerobox_subscription_auto_update"

    suspend fun reconfigure(context: Context) {
        val appContext = context.applicationContext
        val workManager = WorkManager.getInstance(appContext)
        val repository = SubscriptionRepository(appContext)
        val subscriptions = repository.getAllSubscriptions().first()
            .filter { it.autoUpdate }
        if (subscriptions.isEmpty()) {
            workManager.cancelUniqueWork(WORK_NAME)
            return
        }

        val minIntervalMs = subscriptions.minOf { subscription ->
            subscription.updateInterval.coerceAtLeast(SubscriptionRepository.MIN_UPDATE_INTERVAL_MS)
        }
        val now = System.currentTimeMillis()
        val initialDelayMs = subscriptions.minOf { subscription ->
            val interval = subscription.updateInterval.coerceAtLeast(SubscriptionRepository.MIN_UPDATE_INTERVAL_MS)
            val dueAt = if (subscription.updateTime <= 0L) now else subscription.updateTime + interval
            (dueAt - now).coerceAtLeast(0L)
        }

        val request = PeriodicWorkRequestBuilder<SubscriptionUpdateWorker>(
            minIntervalMs,
            TimeUnit.MILLISECONDS
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .setInitialDelay(initialDelayMs, TimeUnit.MILLISECONDS)
            .build()

        workManager.enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
            request
        )
    }
}
