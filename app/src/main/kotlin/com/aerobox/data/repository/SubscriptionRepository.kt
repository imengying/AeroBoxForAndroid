package com.aerobox.data.repository

import android.content.Context
import androidx.room.withTransaction
import com.aerobox.AeroBoxApplication
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.connectionFingerprint
import com.aerobox.data.model.matchScore
import com.aerobox.data.model.normalizedDisplayName
import com.aerobox.utils.PreferenceManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.flow.first
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers
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
    val error: Throwable? = null,
    val metadataFromHeader: Boolean = false
)

class SubscriptionRepository(context: Context) {
    private val appContext = context.applicationContext
    private val database = AeroBoxApplication.database
    private val subscriptionDao = database.subscriptionDao()
    private val proxyNodeDao = database.proxyNodeDao()

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private data class SubscriptionFetchResult(
        val content: String,
        val headers: Headers
    )

    private data class PreparedSubscriptionImport(
        val nodes: List<ProxyNode>,
        val trafficBytes: Long,
        val expireTimestamp: Long,
        val metadataFromHeader: Boolean
    )

    private data class SubscriptionUserInfo(
        val uploadBytes: Long? = null,
        val downloadBytes: Long? = null,
        val totalBytes: Long? = null,
        val expireTimestamp: Long? = null
    ) {
        fun remainingBytes(): Long? {
            val total = totalBytes ?: return null
            val used = (uploadBytes ?: 0L) + (downloadBytes ?: 0L)
            return (total - used).coerceAtLeast(0L)
        }
    }

    fun getAllSubscriptions() = subscriptionDao.getAllSubscriptions()

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
            val prepared = prepareSubscriptionImport(url)
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
                        trafficBytes = prepared.trafficBytes,
                        expireTimestamp = prepared.expireTimestamp
                    )
                )
                insertedId
            }
            SubscriptionUpdateScheduler.reconfigure(appContext)
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = prepared.nodes.size,
                error = null,
                metadataFromHeader = prepared.metadataFromHeader
            )
        }.getOrElse { error ->
            SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = error,
                metadataFromHeader = false
            )
        }
    }

    suspend fun deleteSubscription(subscription: Subscription) {
        database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            subscriptionDao.deleteById(subscription.id)
        }
        SubscriptionUpdateScheduler.reconfigure(appContext)
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

    suspend fun updateSubscription(subscription: Subscription): SubscriptionUpdateResult {
        val result = updateSubscriptionInternal(subscription)
        SubscriptionUpdateScheduler.reconfigure(appContext)
        return result
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
        SubscriptionUpdateScheduler.reconfigure(appContext)
    }

    suspend fun refreshAllSubscriptions(subscriptions: List<Subscription>): List<Result<SubscriptionUpdateResult>> {
        val results = subscriptions.map { subscription ->
            runCatching { updateSubscriptionInternal(subscription) }
        }
        if (results.any { it.isSuccess }) {
            SubscriptionUpdateScheduler.reconfigure(appContext)
        }
        return results
    }

    suspend fun refreshDueSubscriptions(
        subscriptions: List<Subscription>,
        now: Long = System.currentTimeMillis(),
        reconfigureSchedule: Boolean = true
    ): List<Result<SubscriptionUpdateResult>> {
        val results = subscriptions.mapNotNull { subscription ->
            if (!shouldAutoUpdate(subscription, now)) return@mapNotNull null
            runCatching { updateSubscriptionInternal(subscription) }
        }
        if (reconfigureSchedule && results.any { it.isSuccess }) {
            SubscriptionUpdateScheduler.reconfigure(appContext)
        }
        return results
    }

    suspend fun updateNodeLatency(nodeId: Long, latency: Int) {
        proxyNodeDao.updateLatency(nodeId, latency)
    }

    suspend fun resolveNode(node: ProxyNode): ProxyNode? {
        proxyNodeDao.getNodeById(node.id)?.let { return it }
        if (node.subscriptionId <= 0L) return null

        val subscriptionNodes = proxyNodeDao.getNodesBySubscription(node.subscriptionId)
        return findBestMatchingNode(node, subscriptionNodes)
    }

    private suspend fun prepareSubscriptionImport(url: String): PreparedSubscriptionImport {
        val fetchResult = fetchSubscription(url)
        val parsed = SubscriptionParser.parseSubscriptionContent(fetchResult.content)
        if (parsed.nodes.isEmpty()) {
            throw IllegalStateException(NO_VALID_NODES_ERROR)
        }
        val userInfo = parseSubscriptionUserInfo(fetchResult.headers["Subscription-Userinfo"])
        val remainingBytes = userInfo?.remainingBytes()
        val expireTimestamp = userInfo?.expireTimestamp
        return PreparedSubscriptionImport(
            nodes = parsed.nodes,
            trafficBytes = remainingBytes ?: parsed.trafficBytes,
            expireTimestamp = expireTimestamp ?: parsed.expireTimestamp,
            metadataFromHeader = remainingBytes != null || expireTimestamp != null
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
                            cont.resume(
                                SubscriptionFetchResult(
                                    content = it.body.string(),
                                    headers = it.headers
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

    private fun shouldAutoUpdate(subscription: Subscription, now: Long): Boolean {
        if (!subscription.autoUpdate) return false
        val interval = normalizeUpdateInterval(subscription.updateInterval)
        if (subscription.updateTime <= 0L) return true
        return now - subscription.updateTime >= interval
    }

    private suspend fun updateSubscriptionInternal(subscription: Subscription): SubscriptionUpdateResult {
        val prepared = prepareSubscriptionImport(subscription.url)
        val updatedAt = System.currentTimeMillis()
        val existingNodes = proxyNodeDao.getNodesBySubscription(subscription.id)
        val selectedNodeId = PreferenceManager.lastSelectedNodeIdFlow(appContext).first()
        val stabilizedNodes = stabilizeSubscriptionNodes(
            existingNodes = existingNodes,
            freshNodes = prepared.nodes,
            subscriptionId = subscription.id
        )
        val summary = calculateUpdateSummary(existingNodes, stabilizedNodes)

        database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            proxyNodeDao.insertAll(stabilizedNodes)
            subscriptionDao.update(
                subscription.copy(
                    updateTime = updatedAt,
                    nodeCount = stabilizedNodes.size,
                    trafficBytes = prepared.trafficBytes,
                    expireTimestamp = prepared.expireTimestamp
                )
            )
        }
        val persistedNodes = proxyNodeDao.getNodesBySubscription(subscription.id)

        maybeUpdateSelectedNode(
            selectedNodeId = selectedNodeId,
            existingNodes = existingNodes,
            refreshedNodes = persistedNodes
        )

        return SubscriptionUpdateResult(
            subscriptionId = subscription.id,
            nodeCount = persistedNodes.size,
            trafficBytes = prepared.trafficBytes,
            expireTimestamp = prepared.expireTimestamp,
            summary = summary,
            metadataFromHeader = prepared.metadataFromHeader
        )
    }

    private suspend fun maybeUpdateSelectedNode(
        selectedNodeId: Long,
        existingNodes: List<ProxyNode>,
        refreshedNodes: List<ProxyNode>
    ) {
        val previouslySelected = existingNodes.firstOrNull { it.id == selectedNodeId } ?: return
        val replacement = refreshedNodes.firstOrNull { it.id == selectedNodeId }
            ?: findBestMatchingNode(previouslySelected, refreshedNodes)
            ?: refreshedNodes.firstOrNull()
            ?: return
        if (replacement.id != selectedNodeId) {
            PreferenceManager.setLastSelectedNodeId(appContext, replacement.id)
        }
    }

    private fun stabilizeSubscriptionNodes(
        existingNodes: List<ProxyNode>,
        freshNodes: List<ProxyNode>,
        subscriptionId: Long
    ): List<ProxyNode> {
        val remainingExisting = existingNodes.toMutableList()
        return freshNodes.map { freshNode ->
            val matchedNode = takeBestMatchingNode(freshNode, remainingExisting)
            freshNode.copy(
                id = matchedNode?.id ?: 0L,
                subscriptionId = subscriptionId,
                latency = matchedNode?.latency ?: freshNode.latency,
                createdAt = matchedNode?.createdAt ?: freshNode.createdAt
            )
        }
    }

    private fun takeBestMatchingNode(
        targetNode: ProxyNode,
        remainingExisting: MutableList<ProxyNode>
    ): ProxyNode? {
        takeUniqueNameMatch(targetNode, remainingExisting)?.let { return it }

        val exactMatchIndex = remainingExisting.indexOfFirst {
            it.connectionFingerprint(includeName = false) == targetNode.connectionFingerprint(includeName = false)
        }
        if (exactMatchIndex >= 0) {
            return remainingExisting.removeAt(exactMatchIndex)
        }

        val bestMatch = remainingExisting
            .withIndex()
            .map { indexedValue ->
                indexedValue.index to targetNode.matchScore(indexedValue.value)
            }
            .filter { (_, score) -> score >= NODE_MATCH_THRESHOLD }
            .maxWithOrNull(compareBy<Pair<Int, Int>>({ it.second }, { -it.first }))
            ?.first
            ?.let { remainingExisting.removeAt(it) }

        return bestMatch
    }

    private fun findBestMatchingNode(
        targetNode: ProxyNode,
        candidates: List<ProxyNode>
    ): ProxyNode? {
        takeUniqueNameMatch(targetNode, candidates.toMutableList())?.let { return it }

        return candidates.firstOrNull {
            it.connectionFingerprint(includeName = false) == targetNode.connectionFingerprint(includeName = false)
        } ?: candidates
            .map { candidate -> candidate to targetNode.matchScore(candidate) }
            .filter { (_, score) -> score >= NODE_MATCH_THRESHOLD }
            .maxByOrNull { (_, score) -> score }
            ?.first
    }

    private fun takeUniqueNameMatch(
        targetNode: ProxyNode,
        candidates: MutableList<ProxyNode>
    ): ProxyNode? {
        val normalizedName = targetNode.normalizedDisplayName()
        if (normalizedName.isBlank()) return null

        val matchingIndices = candidates.withIndex()
            .filter { (_, candidate) ->
                candidate.type == targetNode.type &&
                    candidate.normalizedDisplayName() == normalizedName
            }
            .map { it.index }

        return if (matchingIndices.size == 1) {
            candidates.removeAt(matchingIndices.first())
        } else {
            null
        }
    }

    private fun calculateUpdateSummary(
        existingNodes: List<ProxyNode>,
        refreshedNodes: List<ProxyNode>
    ): SubscriptionUpdateSummary {
        val existingById = existingNodes.associateBy { it.id }
        val matchedIds = mutableSetOf<Long>()
        var addedCount = 0
        var updatedCount = 0
        var unchangedCount = 0

        refreshedNodes.forEach { node ->
            val existingNode = node.id.takeIf { it > 0L }?.let { existingById[it] }
            if (existingNode == null) {
                addedCount++
            } else {
                matchedIds += existingNode.id
                if (existingNode.connectionFingerprint() == node.connectionFingerprint()) {
                    unchangedCount++
                } else {
                    updatedCount++
                }
            }
        }

        val deletedCount = existingNodes.count { it.id !in matchedIds }
        return SubscriptionUpdateSummary(
            addedCount = addedCount,
            updatedCount = updatedCount,
            deletedCount = deletedCount,
            unchangedCount = unchangedCount
        )
    }

    private fun parseSubscriptionUserInfo(value: String?): SubscriptionUserInfo? {
        if (value.isNullOrBlank()) return null
        val pairs = value.split(";")
            .mapNotNull { entry ->
                val separator = entry.indexOf('=')
                if (separator <= 0 || separator >= entry.lastIndex) return@mapNotNull null
                val key = entry.substring(0, separator).trim().lowercase()
                val rawValue = entry.substring(separator + 1).trim()
                key to rawValue
            }
            .toMap()

        if (pairs.isEmpty()) return null

        return SubscriptionUserInfo(
            uploadBytes = pairs["upload"]?.toLongOrNull(),
            downloadBytes = pairs["download"]?.toLongOrNull(),
            totalBytes = pairs["total"]?.toLongOrNull(),
            expireTimestamp = pairs["expire"]?.toLongOrNull()?.let(::normalizeExpireTimestamp)
        )
    }

    private fun normalizeExpireTimestamp(timestamp: Long): Long {
        return if (timestamp >= 1_000_000_000_000L) timestamp else timestamp * 1000L
    }

    private fun normalizeUpdateInterval(interval: Long): Long {
        return interval.coerceAtLeast(MIN_UPDATE_INTERVAL_MS)
    }

    companion object {
        private const val NODE_MATCH_THRESHOLD = 50
        private const val SUBSCRIPTION_USER_AGENT = "clash-verge/v1.3.8"
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
    }
}
