package com.aerobox.data.repository

import android.content.Context
import androidx.room.withTransaction
import com.aerobox.AeroBoxApplication
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.SubscriptionInfo
import com.aerobox.data.model.withInfo
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
    val info: SubscriptionInfo = SubscriptionInfo()
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

    private data class ParsedSubscriptionUserInfo(
        val info: SubscriptionInfo = SubscriptionInfo()
    ) {
        fun merge(other: ParsedSubscriptionUserInfo): ParsedSubscriptionUserInfo {
            return ParsedSubscriptionUserInfo(
                info = SubscriptionInfo(
                    uploadBytes = info.uploadBytes.takeIf { it > 0 } ?: other.info.uploadBytes,
                    downloadBytes = info.downloadBytes.takeIf { it > 0 } ?: other.info.downloadBytes,
                    totalBytes = info.totalBytes.takeIf { it > 0 } ?: other.info.totalBytes,
                    expireTimestamp = info.expireTimestamp.takeIf { it > 0 } ?: other.info.expireTimestamp
                )
            )
        }

    }

    private val userInfoTokenPattern = Regex("""(?i)(?:^|[;,\s])(upload|download|total|expire)\s*=\s*(\d+)""")

    fun getAllSubscriptions(): Flow<List<Subscription>> = subscriptionDao.getAllSubscriptions()

    fun getNodesBySubscription(subscriptionId: Long): Flow<List<ProxyNode>> =
        proxyNodeDao.getNodesBySubscription(subscriptionId)

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
                        nodeCount = nodes.size
                    ).withInfo(prepared.fetchResult.info)
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


    suspend fun reorderSubscriptions(orderedSubscriptions: List<Subscription>) {
        val baseTimestamp = System.currentTimeMillis()
        database.withTransaction {
            orderedSubscriptions.forEachIndexed { index, subscription ->
                subscriptionDao.update(
                    subscription.copy(createdAt = baseTimestamp - index)
                )
            }
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
                    nodeCount = nodes.size
                ).withInfo(prepared.fetchResult.info)
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
                .header("User-Agent", SUBSCRIPTION_USER_AGENT)
                .header("Accept-Encoding", "identity")
                .header("Connection", "keep-alive")
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
                            val userInfo = extractSubscriptionUserInfo(it)
                            cont.resume(
                                SubscriptionFetchResult(
                                    content = content,
                                    info = userInfo.info
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

    private fun extractSubscriptionUserInfo(response: Response): ParsedSubscriptionUserInfo {
        val headerValues = collectSubscriptionInfoHeaderValues(response)
        return headerValues
            .map(::parseSubscriptionUserInfo)
            .fold(ParsedSubscriptionUserInfo()) { acc, item -> acc.merge(item) }
    }

    private fun collectSubscriptionInfoHeaderValues(response: Response): List<String> {
        val values = mutableListOf<String>()
        var hop: Response? = response
        var hopIndex = 0
        while (hop != null) {
            val currentHop = hop
            val headerNames = currentHop.headers.names().sorted()
            val explicitHeaders = mutableListOf<String>()
            val tokenHeaders = mutableListOf<String>()

            headerNames.forEach { name ->
                val headerValues = currentHop.headers(name)
                val matchesByName = name.contains("subscription", ignoreCase = true) ||
                    name.contains("profile", ignoreCase = true) ||
                    name.contains("userinfo", ignoreCase = true)
                val tokenValues = headerValues.filter { value ->
                    userInfoTokenPattern.containsMatchIn(value)
                }
                if (matchesByName) {
                    explicitHeaders += name
                    values += headerValues
                } else if (tokenValues.isNotEmpty()) {
                    tokenHeaders += name
                    values += tokenValues
                }
            }

            RuntimeLogBuffer.append(
                "debug",
                "Subscription fetch headers hop=$hopIndex: " +
                    "explicit=${explicitHeaders.distinct().joinToString(",").ifBlank { "none" }}, " +
                    "token=${tokenHeaders.distinct().joinToString(",").ifBlank { "none" }}"
            )
            hopIndex += 1
            hop = currentHop.priorResponse
        }

        if (values.isEmpty()) {
            values += response.headers("Subscription-Userinfo")
            values += response.headers("X-Subscription-Userinfo")
            values += response.headers("subscription-userinfo")
        }

        RuntimeLogBuffer.append(
            "debug",
            "Subscription userinfo candidates=${values.size}"
        )
        return values
    }

    private fun parseSubscriptionUserInfo(raw: String?): ParsedSubscriptionUserInfo {
        if (raw.isNullOrBlank()) return ParsedSubscriptionUserInfo()
        val values = mutableMapOf<String, Long>()
        userInfoTokenPattern.findAll(raw).forEach { match ->
            val key = match.groupValues[1].lowercase()
            val value = match.groupValues[2].toLongOrNull() ?: return@forEach
            values[key] = value
        }

        return ParsedSubscriptionUserInfo(
            info = SubscriptionInfo(
                uploadBytes = values["upload"] ?: 0L,
                downloadBytes = values["download"] ?: 0L,
                totalBytes = values["total"] ?: 0L,
                expireTimestamp = values["expire"] ?: 0L
            )
        )
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
        private const val SUBSCRIPTION_USER_AGENT = "Clash/1.9.0"
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
    }
}
