package com.aerobox.data.repository

import android.content.Context
import androidx.room.withTransaction
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

data class SubscriptionFetchResult(
    val content: String,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
    val totalBytes: Long = 0,
    val expireTimestamp: Long = 0
)

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

        return runCatching {
            val prepared = prepareSubscriptionNodes(url)
            val updatedAt = System.currentTimeMillis()
            val subscriptionId = database.withTransaction {
                val insertedId = subscriptionDao.insert(subscription)
                val nodes = prepared.nodes.map { it.copy(subscriptionId = insertedId) }
                proxyNodeDao.insertAll(nodes)
                subscriptionDao.update(
                    subscription.copy(
                        id = insertedId,
                        updateTime = updatedAt,
                        nodeCount = nodes.size,
                        uploadBytes = prepared.fetchResult.uploadBytes,
                        downloadBytes = prepared.fetchResult.downloadBytes,
                        totalBytes = prepared.fetchResult.totalBytes,
                        expireTimestamp = prepared.fetchResult.expireTimestamp
                    )
                )
                insertedId
            }
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = prepared.nodes.size,
                error = null
            )
        }.getOrElse { error ->
            SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = error
            )
        }
    }

    suspend fun deleteSubscription(subscription: Subscription) {
        database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            subscriptionDao.deleteById(subscription.id)
        }
    }

    suspend fun updateSubscription(subscription: Subscription) {
        val prepared = prepareSubscriptionNodes(subscription.url)
        val updatedAt = System.currentTimeMillis()
        val nodes = prepared.nodes.map { it.copy(subscriptionId = subscription.id) }

        database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            proxyNodeDao.insertAll(nodes)
            subscriptionDao.update(
                subscription.copy(
                    updateTime = updatedAt,
                    nodeCount = nodes.size,
                    uploadBytes = prepared.fetchResult.uploadBytes,
                    downloadBytes = prepared.fetchResult.downloadBytes,
                    totalBytes = prepared.fetchResult.totalBytes,
                    expireTimestamp = prepared.fetchResult.expireTimestamp
                )
            )
        }
    }

    suspend fun updateSubscriptionDetails(
        subscription: Subscription,
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        subscriptionDao.update(
            subscription.copy(
                name = name,
                url = url,
                autoUpdate = autoUpdate,
                updateInterval = normalizeUpdateInterval(updateInterval)
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

    private suspend fun prepareSubscriptionNodes(url: String): PreparedSubscriptionData {
        val fetchResult = fetchSubscription(url)
        val nodes = SubscriptionParser.parseSubscription(fetchResult.content)
        if (nodes.isEmpty()) {
            throw IllegalStateException(NO_VALID_NODES_ERROR)
        }
        return PreparedSubscriptionData(
            fetchResult = fetchResult,
            nodes = nodes
        )
    }

    private suspend fun fetchSubscription(url: String): SubscriptionFetchResult =
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
                            val content = it.body?.string() ?: ""
                            val userInfo = parseSubscriptionUserInfo(
                                it.header("Subscription-Userinfo")
                            )
                            cont.resume(
                                SubscriptionFetchResult(
                                    content = content,
                                    uploadBytes = userInfo["upload"] ?: 0,
                                    downloadBytes = userInfo["download"] ?: 0,
                                    totalBytes = userInfo["total"] ?: 0,
                                    expireTimestamp = userInfo["expire"] ?: 0
                                )
                            )
                        }
                    }
                }
                override fun onFailure(call: Call, e: IOException) {
                    cont.resumeWithException(e)
                }
            })
        }

    private fun parseSubscriptionUserInfo(header: String?): Map<String, Long> {
        if (header.isNullOrBlank()) return emptyMap()
        return header.split(";")
            .mapNotNull { part ->
                val kv = part.trim().split("=", limit = 2)
                if (kv.size == 2) kv[0].trim() to (kv[1].trim().toLongOrNull() ?: 0L)
                else null
            }
            .toMap()
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

    private data class PreparedSubscriptionData(
        val fetchResult: SubscriptionFetchResult,
        val nodes: List<ProxyNode>
    )

    companion object {
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
    }
}
