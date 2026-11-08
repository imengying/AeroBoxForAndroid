package com.aerobox.data.repository

import android.content.Context
import androidx.room.withTransaction
import com.aerobox.R
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.subscription.ParseDiagnostics
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.core.subscription.SubscriptionMetadataParser
import com.aerobox.data.model.NodeLatencyState
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyNodeMatcher
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.connectionFingerprint
import com.aerobox.data.model.isLocalGroup
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit


data class SubscriptionImportResult(
    val subscriptionId: Long,
    val nodeCount: Int,
    val error: Throwable? = null,
    val metadataFromHeader: Boolean = false,
    val diagnostics: ParseDiagnostics = ParseDiagnostics()
)

enum class NodeUpdateResult { SAVED, NOT_FOUND, CONFLICT }

// Result of parsing inline content (local file / pasted text / single-node QR).
// Nodes are not yet assigned to a group — callers pair this with an
// [ImportGroupTarget] and call [SubscriptionRepository.commitLocalImport].
data class PreparedLocalImport(
    val nodes: List<ProxyNode>,
    val resolvedName: String?,
    val metadataFromHeader: Boolean,
    val diagnostics: ParseDiagnostics
)

// Picker result used by local file / paste / single-node QR import flows.
// Subscription-backed groups are not valid targets here (they are refreshed
// from their remote URL, which would drop user-imported nodes).
sealed class ImportGroupTarget {
    data object Ungrouped : ImportGroupTarget()
    data class Existing(val subscriptionId: Long) : ImportGroupTarget()
    data class New(val name: String) : ImportGroupTarget()
}

internal class NoValidNodesException(
    val diagnostics: ParseDiagnostics
) : IllegalStateException(SubscriptionRepository.NO_VALID_NODES_ERROR)

class SubscriptionRepository(
    context: Context,
    private val database: com.aerobox.data.database.AppDatabase,
    private val downloader: SubscriptionDownloader,
    private val selectedNodeStore: SelectedNodeStore,
    private val rescheduleUpdates: suspend () -> Unit
) {
    private val appContext = context.applicationContext
    private val subscriptionDao = database.subscriptionDao()
    private val proxyNodeDao = database.proxyNodeDao()
    private val subscriptionMutationLocks = Array(SUBSCRIPTION_LOCK_COUNT) { Mutex() }
    private val subscriptionRefreshLocks = Array(SUBSCRIPTION_LOCK_COUNT) { Mutex() }

    companion object {
        private const val MAX_CONCURRENT_SUBSCRIPTION_REFRESHES = 4
        private const val MAX_REFRESH_SNAPSHOT_RETRIES = 3
        private const val SUBSCRIPTION_LOCK_COUNT = 32
        private const val NODE_QUERY_BATCH_SIZE = 500
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
        const val LOCAL_GROUP_TARGET_INVALID_ERROR = "LOCAL_GROUP_TARGET_INVALID"
        const val INVALID_SUBSCRIPTION_URL_ERROR = "INVALID_SUBSCRIPTION_URL"
        const val SUBSCRIPTION_RESPONSE_TOO_LARGE_ERROR = HttpSubscriptionDownloader.RESPONSE_TOO_LARGE

    }

    private sealed interface RefreshCommitOutcome {
        data class Retry(val subscription: Subscription) : RefreshCommitOutcome

        data class Success(
            val subscription: Subscription,
            val existingNodes: List<ProxyNode>,
            val persistedNodes: List<ProxyNode>,
            val summary: SubscriptionUpdateSummary
        ) : RefreshCommitOutcome

        data object Deleted : RefreshCommitOutcome
    }

    private data class PreparedSubscriptionImport(
        val nodes: List<ProxyNode>,
        val trafficBytes: Long,
        val expireTimestamp: Long,
        val metadataFromHeader: Boolean,
        val diagnostics: ParseDiagnostics,
        val resolvedName: String? = null,
        val resolvedUrl: String? = null,
        val resolvedUpdateInterval: Long? = null
    )

    fun getAllSubscriptions() = subscriptionDao.getAllSubscriptions()

    fun getLocalGroups() = subscriptionDao.getLocalGroups()

    fun observeUngroupedNodeCount() = proxyNodeDao.observeUngroupedNodeCount()

    fun observeSubscriptionById(id: Long) = subscriptionDao.observeById(id)

    fun observeNodesInGroup(subscriptionId: Long) =
        proxyNodeDao.observeNodesBySubscription(subscriptionId)

    suspend fun updateNode(node: ProxyNode, original: ProxyNode): NodeUpdateResult {
        require(node.id == original.id)
        val config = com.aerobox.core.config.ConfigGenerator.generateUrlTestConfig(node)
        com.aerobox.core.native.SingBoxNative.checkConfig(config)?.let { error ->
            throw IllegalArgumentException(error)
        }
        val existing = proxyNodeDao.getNodeById(node.id) ?: return NodeUpdateResult.NOT_FOUND
        return subscriptionMutationLock(existing.subscriptionId).withLock {
            database.withTransaction {
                val latest = proxyNodeDao.getNodeById(node.id)
                    ?: return@withTransaction NodeUpdateResult.NOT_FOUND
                // Sorting, group moves and latency updates do not invalidate an edit.
                if (latest.copy(
                        subscriptionId = original.subscriptionId,
                        latency = original.latency,
                        createdAt = original.createdAt
                    ) != original
                ) {
                    return@withTransaction NodeUpdateResult.CONFLICT
                }
                val connectionChanged = latest.connectionFingerprint(includeName = false) !=
                    node.connectionFingerprint(includeName = false)
                val updated = node.copy(
                    subscriptionId = latest.subscriptionId,
                    latency = if (connectionChanged) NodeLatencyState.UNTESTED else latest.latency,
                    createdAt = latest.createdAt
                )
                if (updated != latest) proxyNodeDao.update(updated)
                NodeUpdateResult.SAVED
            }
        }
    }

    suspend fun deleteNodes(nodeIds: List<Long>) {
        val ids = nodeIds.toSet()
        if (ids.isEmpty()) return
        val selectedId = selectedNodeStore.read()
        withMutationLocks(0) {
            database.withTransaction {
                val nodes = ids.toList().chunked(500).flatMap { proxyNodeDao.getNodesByIds(it) }
                proxyNodeDao.deleteAll(nodes)
                nodes.map { it.subscriptionId }.distinct().filter { it > 0 }.forEach { recomputeLocalGroupCount(it) }
            }
        }
        if (selectedId in ids) selectedNodeStore.replace(selectedId, 0L)
    }

    // Batch deletion spans groups; acquire stripes in a fixed order before opening the transaction.
    private suspend fun <T> withMutationLocks(index: Int, action: suspend () -> T): T {
        if (index == subscriptionMutationLocks.size) return action()
        return subscriptionMutationLocks[index].withLock { withMutationLocks(index + 1, action) }
    }

    suspend fun copyNodes(nodeIds: List<Long>, target: ImportGroupTarget): SubscriptionImportResult {
        val nodes = nodeIds.distinct().chunked(500).flatMap { proxyNodeDao.getNodesByIds(it) }
        return commitLocalImport(
            PreparedLocalImport(
                nodes = nodes.map { it.copy(id = 0L, subscriptionId = 0L) },
                resolvedName = null,
                metadataFromHeader = false,
                diagnostics = ParseDiagnostics()
            ), target
        )
    }

    suspend fun addSubscription(
        name: String,
        url: String,
        autoUpdate: Boolean = false,
        updateInterval: Long = DEFAULT_UPDATE_INTERVAL_MS
    ): SubscriptionImportResult {
        val normalizedInterval = normalizeUpdateInterval(updateInterval)
        val trimmedUrl = url.trim()
        if (!isValidRemoteSubscriptionUrl(trimmedUrl)) {
            return SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = IllegalArgumentException(INVALID_SUBSCRIPTION_URL_ERROR),
                metadataFromHeader = false,
                diagnostics = ParseDiagnostics()
            )
        }

        return runCatching {
            val prepared = prepareSubscriptionImport(trimmedUrl)
            val effectiveUrl = prepared.resolvedUrl ?: trimmedUrl
            val effectiveName = name.ifBlank { prepared.resolvedName ?: SubscriptionMetadataParser.deriveSubscriptionName(effectiveUrl) }
                ?: appContext.getString(R.string.import_subscription_default_name)
            val effectiveInterval = if (autoUpdate) {
                prepared.resolvedUpdateInterval ?: normalizedInterval
            } else {
                normalizedInterval
            }
            val subscription = Subscription(
                name = effectiveName,
                url = effectiveUrl,
                autoUpdate = autoUpdate,
                updateInterval = effectiveInterval,
                createdAt = System.currentTimeMillis()
            )
            val updatedAt = System.currentTimeMillis()
            val subscriptionId = database.withTransaction {
                val insertedId = subscriptionDao.insert(subscription)
                val nodes = assignFetchedNodeOrder(
                    nodes = prepared.nodes,
                    subscriptionId = insertedId
                )
                proxyNodeDao.insertAll(nodes)
                subscriptionDao.update(
                    subscription.copy(
                        id = insertedId,
                        updateTime = updatedAt,
                        nodeCount = nodes.size,
                        trafficBytes = prepared.trafficBytes,
                        expireTimestamp = prepared.expireTimestamp,
                        updateInterval = effectiveInterval
                    )
                )
                insertedId
            }
            rescheduleUpdates()
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = prepared.nodes.size,
                error = null,
                metadataFromHeader = prepared.metadataFromHeader,
                diagnostics = prepared.diagnostics
            )
        }.getOrElse { error ->
            val diagnostics = (error as? NoValidNodesException)?.diagnostics ?: ParseDiagnostics()
            SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = error,
                metadataFromHeader = false,
                diagnostics = diagnostics
            )
        }
    }

    suspend fun deleteSubscription(subscription: Subscription) {
        val selectedNodeId = selectedNodeStore.read()
        val selectedNode = selectedNodeId
            .takeIf { it > 0L }
            ?.let { proxyNodeDao.getNodeById(it) }
        var replacementSelectedNodeId: Long? = null
        var shouldMoveSelection = false

        subscriptionMutationLock(subscription.id).withLock {
            database.withTransaction {
                val current = subscriptionDao.getById(subscription.id) ?: return@withTransaction
                shouldMoveSelection = !current.isLocalGroup() &&
                    selectedNode?.subscriptionId == current.id
                if (current.isLocalGroup()) {
                    // Preserve user-imported nodes by moving them back to the default bucket.
                    proxyNodeDao.reassignBySubscription(
                        fromSubscriptionId = current.id,
                        targetSubscriptionId = 0L
                    )
                } else {
                    proxyNodeDao.deleteBySubscription(current.id)
                }
                subscriptionDao.deleteById(current.id)
                if (shouldMoveSelection) {
                    replacementSelectedNodeId = proxyNodeDao.getFirstNode()?.id ?: 0L
                }
            }
        }
        if (shouldMoveSelection) {
            selectedNodeStore.write(replacementSelectedNodeId ?: 0L)
        }
        rescheduleUpdates()
    }


    suspend fun reorderSubscriptions(orderedSubscriptions: List<Subscription>) {
        val baseTimestamp = System.currentTimeMillis()
        database.withTransaction {
            orderedSubscriptions.forEachIndexed { index, subscription ->
                subscriptionDao.updateCreatedAt(subscription.id, baseTimestamp - index)
            }
        }
    }

    suspend fun updateSubscription(subscription: Subscription): SubscriptionUpdateResult {
        if (subscription.isLocalGroup()) {
            throw IllegalStateException(appContext.getString(R.string.error_local_group_no_remote_refresh))
        }
        val result = updateSubscriptionInternal(subscription)
        rescheduleUpdates()
        return result
    }

    suspend fun updateSubscriptionDetails(
        subscription: Subscription,
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ) {
        subscriptionMutationLock(subscription.id).withLock {
            val current = subscriptionDao.getById(subscription.id) ?: return@withLock
            val wasLocal = current.isLocalGroup()
            val trimmedUrl = url.trim()
            // Local groups keep the empty URL marker. Invalid remote URLs leave
            // the currently persisted URL untouched.
            val resolvedUrl = when {
                wasLocal -> current.url
                isValidRemoteSubscriptionUrl(trimmedUrl) -> trimmedUrl
                else -> current.url
            }
            subscriptionDao.updateDetails(
                id = current.id,
                name = name,
                url = resolvedUrl,
                autoUpdate = if (wasLocal) false else autoUpdate,
                updateInterval = normalizeUpdateInterval(updateInterval)
            )
        }
        rescheduleUpdates()
    }

    suspend fun renameLocalGroup(subscription: Subscription, name: String) {
        val trimmed = name.trim()
        if (trimmed.isBlank()) return
        subscriptionMutationLock(subscription.id).withLock {
            val current = subscriptionDao.getById(subscription.id) ?: return@withLock
            if (!current.isLocalGroup()) return@withLock
            subscriptionDao.updateName(current.id, trimmed)
        }
    }

    suspend fun refreshAllSubscriptions(subscriptions: List<Subscription>): List<Result<SubscriptionUpdateResult>> {
        val refreshable = subscriptions.filterNot { it.isLocalGroup() }
        val results = refreshSubscriptions(refreshable)
        if (results.any { it.isSuccess }) {
            rescheduleUpdates()
        }
        return results
    }

    suspend fun refreshDueSubscriptions(
        subscriptions: List<Subscription>,
        now: Long = System.currentTimeMillis(),
        reconfigureSchedule: Boolean = true
    ): List<Result<SubscriptionUpdateResult>> {
        val dueSubscriptions = subscriptions.filter { subscription ->
            shouldAutoUpdate(subscription, now)
        }
        val results = refreshSubscriptions(dueSubscriptions)
        if (reconfigureSchedule && results.any { it.isSuccess }) {
            rescheduleUpdates()
        }
        return results
    }

    private suspend fun refreshSubscriptions(
        subscriptions: List<Subscription>
    ): List<Result<SubscriptionUpdateResult>> {
        if (subscriptions.isEmpty()) return emptyList()
        val semaphore = Semaphore(MAX_CONCURRENT_SUBSCRIPTION_REFRESHES)
        return coroutineScope {
            subscriptions.map { subscription ->
                async {
                    semaphore.withPermit {
                        runCatching { updateSubscriptionInternal(subscription) }
                    }
                }
            }.map { it.await() }
        }
    }

    suspend fun updateNodeLatency(node: ProxyNode, latency: Int) {
        updateNodeLatencies(listOf(node), mapOf(node.id to latency))
    }

    suspend fun updateNodeLatencies(testedNodes: List<ProxyNode>, latencies: Map<Long, Int>) {
        if (latencies.isEmpty()) return
        database.withTransaction {
            val currentNodes = latencies.keys.chunked(NODE_QUERY_BATCH_SIZE)
                .flatMap { proxyNodeDao.getNodesByIds(it) }
                .associateBy { it.id }
            for (tested in testedNodes) {
                val latency = latencies[tested.id] ?: continue
                val current = currentNodes[tested.id] ?: continue
                if (current.latency != latency &&
                    current.connectionFingerprint(includeName = false) == tested.connectionFingerprint(includeName = false)
                ) {
                    proxyNodeDao.updateLatency(current.id, latency)
                }
            }
        }
    }

    suspend fun resolveNode(node: ProxyNode): ProxyNode? {
        proxyNodeDao.getNodeById(node.id)?.let { return it }
        if (node.subscriptionId <= 0L) return null

        val subscriptionNodes = proxyNodeDao.getNodesBySubscription(node.subscriptionId)
        return ProxyNodeMatcher(subscriptionNodes).takeBestMatch(node)
    }

    // Parse inline content without touching the database. Pair the result with
    // an [ImportGroupTarget] and call [commitLocalImport] to finalise.
    suspend fun prepareLocalImport(
        source: String,
        nameHint: String = ""
    ): PreparedLocalImport {
        val prepared = prepareInlineImport(source, nameHint)
        return PreparedLocalImport(
            nodes = prepared.nodes,
            resolvedName = prepared.resolvedName,
            metadataFromHeader = prepared.metadataFromHeader,
            diagnostics = prepared.diagnostics
        )
    }

    suspend fun commitLocalImport(
        prepared: PreparedLocalImport,
        target: ImportGroupTarget
    ): SubscriptionImportResult {
        return runCatching {
            when (target) {
                is ImportGroupTarget.Ungrouped -> subscriptionMutationLock(0L).withLock { commitToUngrouped(prepared) }
                is ImportGroupTarget.Existing -> commitToExistingLocalGroup(prepared, target.subscriptionId)
                is ImportGroupTarget.New -> commitToNewLocalGroup(prepared, target.name)
            }
        }.getOrElse { error ->
            SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = error,
                metadataFromHeader = prepared.metadataFromHeader,
                diagnostics = prepared.diagnostics
            )
        }
    }

    private suspend fun commitToUngrouped(
        prepared: PreparedLocalImport
    ): SubscriptionImportResult {
        val existingFingerprints = proxyNodeDao.getNodesBySubscription(0L)
            .asSequence()
            .map { it.connectionFingerprint() }
            .toSet()
        val nodes = prepareNodesForLocalGroup(
            prepared = prepared,
            subscriptionId = 0L,
            existingFingerprints = existingFingerprints
        )
        return persistLocalImportNodes(
            subscriptionId = 0L,
            nodes = nodes,
            prepared = prepared
        )
    }

    private suspend fun commitToExistingLocalGroup(
        prepared: PreparedLocalImport,
        subscriptionId: Long
    ): SubscriptionImportResult {
        return subscriptionMutationLock(subscriptionId).withLock {
            val subscription = subscriptionDao.getById(subscriptionId)
                ?: throw IllegalStateException(appContext.getString(R.string.error_target_group_not_found))
            if (!subscription.isLocalGroup()) {
                throw IllegalStateException(LOCAL_GROUP_TARGET_INVALID_ERROR)
            }

            val existingFingerprints = proxyNodeDao.getNodesBySubscription(subscription.id)
                .asSequence()
                .map { it.connectionFingerprint() }
                .toSet()
            val nodes = prepareNodesForLocalGroup(
                prepared = prepared,
                subscriptionId = subscription.id,
                existingFingerprints = existingFingerprints
            )
            persistLocalImportNodes(
                subscriptionId = subscription.id,
                nodes = nodes,
                prepared = prepared
            )
        }
    }

    private suspend fun commitToNewLocalGroup(
        prepared: PreparedLocalImport,
        name: String
    ): SubscriptionImportResult {
        val trimmedName = name.trim().ifBlank { prepared.resolvedName?.trim().orEmpty() }
            .ifBlank { appContext.getString(R.string.local_group_label) }
        if (prepared.nodes.isEmpty()) {
            return persistLocalImportNodes(
                subscriptionId = 0L,
                nodes = emptyList(),
                prepared = prepared
            )
        }

        val (subscriptionId, nodes) = database.withTransaction {
            val insertedId = subscriptionDao.insert(buildLocalGroup(trimmedName))
            val preparedNodes = prepareNodesForLocalGroup(
                prepared = prepared,
                subscriptionId = insertedId,
                existingFingerprints = emptySet()
            )
            proxyNodeDao.insertAll(preparedNodes)
            recomputeLocalGroupCount(insertedId)
            insertedId to preparedNodes
        }

        return SubscriptionImportResult(
            subscriptionId = subscriptionId,
            nodeCount = nodes.size,
            metadataFromHeader = prepared.metadataFromHeader,
            diagnostics = prepared.diagnostics
        )
    }

    private fun buildLocalGroup(name: String): Subscription {
        val trimmed = name.trim().ifBlank { appContext.getString(R.string.local_group_label) }
        return Subscription(
            name = trimmed,
            url = "",
            autoUpdate = false,
            updateInterval = DEFAULT_UPDATE_INTERVAL_MS,
            createdAt = System.currentTimeMillis()
        )
    }

    private fun prepareNodesForLocalGroup(
        prepared: PreparedLocalImport,
        subscriptionId: Long,
        existingFingerprints: Set<String>
    ): List<ProxyNode> {
        val nameHint = prepared.resolvedName
        val total = prepared.nodes.size
        val filtered = prepared.nodes
            .filterNot { it.connectionFingerprint() in existingFingerprints }
            .mapIndexed { index, node ->
                val fallbackName = nameHint
                    ?.takeIf { total == 1 }
                    ?: appContext.getString(R.string.imported_node_default_name_format, index + 1)
                node.copy(
                    name = node.name.ifBlank { fallbackName },
                    subscriptionId = subscriptionId
                )
            }
        return assignFetchedNodeOrder(filtered, subscriptionId)
    }

    private suspend fun persistLocalImportNodes(
        subscriptionId: Long,
        nodes: List<ProxyNode>,
        prepared: PreparedLocalImport
    ): SubscriptionImportResult {
        if (nodes.isEmpty()) {
            return SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = 0,
                error = LocalizedException.of(R.string.error_no_new_nodes_imported),
                metadataFromHeader = prepared.metadataFromHeader,
                diagnostics = prepared.diagnostics
            )
        }

        database.withTransaction {
            proxyNodeDao.insertAll(nodes)
            if (subscriptionId > 0L) {
                recomputeLocalGroupCount(subscriptionId)
            }
        }
        return SubscriptionImportResult(
            subscriptionId = subscriptionId,
            nodeCount = nodes.size,
            metadataFromHeader = prepared.metadataFromHeader,
            diagnostics = prepared.diagnostics
        )
    }

    private suspend fun recomputeLocalGroupCount(subscriptionId: Long) {
        if (subscriptionId <= 0L) return
        val count = proxyNodeDao.countBySubscription(subscriptionId)
        subscriptionDao.updateNodeCount(subscriptionId, count)
    }

    private suspend fun prepareSubscriptionImport(url: String): PreparedSubscriptionImport {
        val trimmedUrl = url.trim()
        if (!isValidRemoteSubscriptionUrl(trimmedUrl)) {
            throw IllegalArgumentException(INVALID_SUBSCRIPTION_URL_ERROR)
        }
        val fetchResult = downloader.fetch(trimmedUrl)
        val metadata = SubscriptionMetadataParser.parse(
            source = fetchResult.content,
            sourceUrl = trimmedUrl,
            headers = fetchResult.headers
        )
        val parsed = SubscriptionParser.parseSubscriptionContent(metadata.sanitizedContent)
        if (parsed.nodes.isEmpty()) {
            throw NoValidNodesException(parsed.diagnostics)
        }
        val userInfo = metadata.userInfo
        val remainingBytes = userInfo?.remainingBytes()
        val expireTimestamp = userInfo?.expireTimestamp
        return PreparedSubscriptionImport(
            nodes = parsed.nodes,
            trafficBytes = remainingBytes ?: parsed.trafficBytes,
            expireTimestamp = expireTimestamp ?: parsed.expireTimestamp,
            metadataFromHeader = remainingBytes != null || expireTimestamp != null,
            diagnostics = parsed.diagnostics,
            resolvedName = metadata.profileTitle,
            resolvedUrl = metadata.canonicalUrl,
            resolvedUpdateInterval = metadata.updateIntervalMs
        )
    }

    private suspend fun prepareInlineImport(
        source: String,
        nameHint: String
    ): PreparedSubscriptionImport {
        val metadata = SubscriptionMetadataParser.parse(
            source = source,
            sourceUrl = null,
            headers = null
        )
        val parsed = SubscriptionParser.parseSubscriptionContent(metadata.sanitizedContent)
        if (parsed.nodes.isEmpty()) {
            throw NoValidNodesException(parsed.diagnostics)
        }
        val userInfo = metadata.userInfo
        return PreparedSubscriptionImport(
            nodes = parsed.nodes,
            trafficBytes = userInfo?.remainingBytes() ?: parsed.trafficBytes,
            expireTimestamp = userInfo?.expireTimestamp ?: parsed.expireTimestamp,
            metadataFromHeader = userInfo != null,
            diagnostics = parsed.diagnostics,
            resolvedName = metadata.profileTitle ?: nameHint.takeIf { it.isNotBlank() }
        )
    }

    private fun shouldAutoUpdate(subscription: Subscription, now: Long): Boolean {
        if (subscription.isLocalGroup()) return false
        if (!subscription.autoUpdate) return false
        val interval = normalizeUpdateInterval(subscription.updateInterval)
        if (subscription.updateTime <= 0L) return true
        return now - subscription.updateTime >= interval
    }

    private suspend fun updateSubscriptionInternal(subscription: Subscription): SubscriptionUpdateResult {
        return subscriptionRefreshLock(subscription.id).withLock {
            var snapshot = subscriptionMutationLock(subscription.id).withLock {
                subscriptionDao.getById(subscription.id)
            } ?: throw IllegalStateException("Subscription no longer exists")

            repeat(MAX_REFRESH_SNAPSHOT_RETRIES) {
                if (snapshot.isLocalGroup()) {
                    throw IllegalStateException(appContext.getString(R.string.error_local_group_no_remote_refresh))
                }

                val prepared = prepareSubscriptionImport(snapshot.url)
                val selectedNodeId = selectedNodeStore.read()
                val outcome = subscriptionMutationLock(snapshot.id).withLock {
                    val committed = database.withTransaction {
                        val current = subscriptionDao.getById(snapshot.id)
                            ?: return@withTransaction RefreshCommitOutcome.Deleted
                        if (current.url != snapshot.url) {
                            return@withTransaction RefreshCommitOutcome.Retry(current)
                        }

                        val existingNodes = proxyNodeDao.getNodesBySubscription(current.id)
                        val plan = SubscriptionUpdatePlanner.plan(existingNodes, prepared.nodes, current.id, System.currentTimeMillis())
                        if (plan.removed.isNotEmpty()) proxyNodeDao.deleteAll(plan.removed)
                        if (plan.changed.isNotEmpty()) proxyNodeDao.updateAll(plan.changed)
                        if (plan.added.isNotEmpty()) proxyNodeDao.insertAll(plan.added)
                        val updatedRows = subscriptionDao.updateRefreshState(
                            id = current.id,
                            url = prepared.resolvedUrl ?: current.url,
                            updateTime = System.currentTimeMillis(),
                            nodeCount = plan.nodes.size,
                            trafficBytes = prepared.trafficBytes,
                            expireTimestamp = prepared.expireTimestamp,
                            updateInterval = prepared.resolvedUpdateInterval
                                ?.takeIf { current.autoUpdate }
                                ?: normalizeUpdateInterval(current.updateInterval)
                        )
                        if (updatedRows != 1) {
                            throw IllegalStateException("Subscription disappeared during refresh commit")
                        }
                        RefreshCommitOutcome.Success(
                            subscription = current,
                            existingNodes = existingNodes,
                            persistedNodes = if (plan.added.isEmpty()) plan.nodes else {
                                proxyNodeDao.getNodesBySubscription(current.id)
                            },
                            summary = plan.summary
                        )
                    }
                    if (committed is RefreshCommitOutcome.Success) {
                        maybeUpdateSelectedNode(
                            selectedNodeId = selectedNodeId,
                            existingNodes = committed.existingNodes,
                            refreshedNodes = committed.persistedNodes
                        )
                    }
                    committed
                }

                when (outcome) {
                    RefreshCommitOutcome.Deleted -> {
                        throw IllegalStateException("Subscription was deleted during refresh")
                    }

                    is RefreshCommitOutcome.Retry -> {
                        snapshot = outcome.subscription
                    }

                    is RefreshCommitOutcome.Success -> {
                        return@withLock SubscriptionUpdateResult(
                            subscriptionId = outcome.subscription.id,
                            summary = outcome.summary,
                            metadataFromHeader = prepared.metadataFromHeader
                        )
                    }
                }
            }

            throw IllegalStateException("Subscription changed repeatedly during refresh")
        }
    }

    private fun subscriptionMutationLock(subscriptionId: Long): Mutex {
        return subscriptionMutationLocks[(subscriptionId and (SUBSCRIPTION_LOCK_COUNT - 1).toLong()).toInt()]
    }

    private fun subscriptionRefreshLock(subscriptionId: Long): Mutex {
        return subscriptionRefreshLocks[(subscriptionId and (SUBSCRIPTION_LOCK_COUNT - 1).toLong()).toInt()]
    }

    private suspend fun maybeUpdateSelectedNode(
        selectedNodeId: Long,
        existingNodes: List<ProxyNode>,
        refreshedNodes: List<ProxyNode>
    ) {
        val previouslySelected = existingNodes.firstOrNull { it.id == selectedNodeId } ?: return
        val replacement = refreshedNodes.firstOrNull { it.id == selectedNodeId }
            ?: ProxyNodeMatcher(refreshedNodes).takeBestMatch(previouslySelected)
            ?: return
        if (replacement.id != selectedNodeId) {
            selectedNodeStore.write(replacement.id)
        }
    }

    private fun assignFetchedNodeOrder(
        nodes: List<ProxyNode>,
        subscriptionId: Long
    ): List<ProxyNode> {
        val baseTimestamp = System.currentTimeMillis()
        return nodes.mapIndexed { index, node ->
            node.copy(
                subscriptionId = subscriptionId,
                createdAt = baseTimestamp + index
            )
        }
    }

    fun isValidRemoteSubscriptionUrl(url: String): Boolean =
        SubscriptionMetadataParser.isValidRemoteSubscriptionUrl(url)

    private fun normalizeUpdateInterval(interval: Long): Long {
        return interval.coerceAtLeast(MIN_UPDATE_INTERVAL_MS)
    }

}
