package com.aerobox.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.aerobox.data.repository.SubscriptionRepository
import kotlinx.coroutines.flow.first

class SubscriptionUpdateWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val repository = SubscriptionRepository(applicationContext)
        val subscriptions = repository.getAllSubscriptions().first()
        val results = repository.refreshDueSubscriptions(
            subscriptions = subscriptions,
            reconfigureSchedule = false
        )
        if (results.isEmpty() || results.any { it.isSuccess }) {
            return Result.success()
        }
        return Result.retry()
    }
}
