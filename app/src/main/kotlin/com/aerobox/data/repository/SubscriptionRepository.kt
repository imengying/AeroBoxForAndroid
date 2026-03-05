package com.aerobox.data.repository

import android.content.Context
import com.aerobox.AeroBoxApplication
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class SubscriptionImportResult(
    val subscriptionId: Long,
    val nodeCount: Int,
    val error: Throwable? = null
)

class SubscriptionRepository(context: Context) {
    private val database = AeroBoxApplication.database
    private val subscriptionDao = database.subscriptionDao()
    private val proxyNodeDao = database.proxyNodeDao()

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun getAllSubscriptions(): Flow<List<Subscription>> = subscriptionDao.getAllSubscriptions()

    fun getNodesBySubscription(subscriptionId: Long): Flow<List<ProxyNode>> =
        proxyNodeDao.getNodesBySubscription(subscriptionId)

    suspend fun getNodesBySubscriptionOnce(subscriptionId: Long): List<ProxyNode> =
        proxyNodeDao.getNodesBySubscriptionOnce(subscriptionId)

    suspend fun addSubscription(
        name: String,
        url: String,
        autoUpdate: Boolean = false,
        updateInterval: Long = DEFAULT_UPDATE_INTERVAL_MS
    ): SubscriptionImportResult {
        val normalizedInterval = normalizeUpdateInterval(updateInterval)
        val subscription = Subscription(
            name = name,
            url = url,
            autoUpdate = autoUpdate,
            updateInterval = normalizedInterval,
            createdAt = System.currentTimeMillis()
        )
        val subscriptionId = subscriptionDao.insert(subscription)
        val importResult = runCatching {
            val content = fetchSubscriptionContent(url)
            val parsedNodes = SubscriptionParser.parseSubscription(content)
            val nodes = parsedNodes.map { it.copy(subscriptionId = subscriptionId) }

            if (nodes.isNotEmpty()) {
                proxyNodeDao.insertAll(nodes)
            }

            val noNodesError = if (nodes.isEmpty()) {
                IllegalStateException(NO_VALID_NODES_ERROR)
            } else {
                null
            }
            subscriptionDao.update(
                subscription.copy(
                    id = subscriptionId,
                    updateTime = System.currentTimeMillis(),
                    nodeCount = nodes.size
                )
            )
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = nodes.size,
                error = noNodesError
            )
        }.getOrElse { error ->
            subscriptionDao.update(subscription.copy(id = subscriptionId))
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = 0,
                error = error
            )
        }
        return importResult
    }

    suspend fun deleteSubscription(subscription: Subscription) {
        proxyNodeDao.deleteBySubscription(subscription.id)
        subscriptionDao.deleteById(subscription.id)
    }

    suspend fun updateSubscription(subscription: Subscription) {
        val content = fetchSubscriptionContent(subscription.url)
        val parsedNodes = SubscriptionParser.parseSubscription(content)
        val nodes = parsedNodes.map { it.copy(subscriptionId = subscription.id) }

        proxyNodeDao.deleteBySubscription(subscription.id)
        if (nodes.isNotEmpty()) {
            proxyNodeDao.insertAll(nodes)
        }

        subscriptionDao.update(
            subscription.copy(
                updateTime = System.currentTimeMillis(),
                nodeCount = nodes.size
            )
        )
    }

    suspend fun refreshAllSubscriptions(subscriptions: List<Subscription>) {
        subscriptions.forEach { subscription ->
            runCatching { updateSubscription(subscription) }
        }
    }

    suspend fun refreshDueSubscriptions(
        subscriptions: List<Subscription>,
        now: Long = System.currentTimeMillis()
    ) {
        subscriptions.forEach { subscription ->
            if (!shouldAutoUpdate(subscription, now)) return@forEach
            runCatching { updateSubscription(subscription) }
        }
    }

    suspend fun updateNodeLatency(nodeId: Long, latency: Int) {
        proxyNodeDao.updateLatency(nodeId, latency)
    }

    suspend fun getNodeById(nodeId: Long): ProxyNode? = proxyNodeDao.getNodeById(nodeId)

    private suspend fun fetchSubscriptionContent(url: String): String =
        suspendCancellableCoroutine { cont ->
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "ClashForAndroid/2.5.12")
                .build()
            val call = client.newCall(request)
            cont.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!it.isSuccessful) {
                            cont.resumeWithException(IOException("HTTP ${it.code}"))
                        } else {
                            cont.resume(it.body?.string() ?: "")
                        }
                    }
                }
                override fun onFailure(call: Call, e: IOException) {
                    cont.resumeWithException(e)
                }
            })
        }

    private fun shouldAutoUpdate(subscription: Subscription, now: Long): Boolean {
        if (!subscription.autoUpdate) return false
        val interval = normalizeUpdateInterval(subscription.updateInterval)
        if (subscription.updateTime <= 0L) return true
        return now - subscription.updateTime >= interval
    }

    private fun normalizeUpdateInterval(interval: Long): Long {
        return interval.coerceAtLeast(MIN_UPDATE_INTERVAL_MS)
    }

    companion object {
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
    }
}
