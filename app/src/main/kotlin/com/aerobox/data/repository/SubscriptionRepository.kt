package com.aerobox.data.repository

import android.content.Context
import android.net.Uri
import androidx.room.withTransaction
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.core.errors.LocalizedException
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.subscription.ParseDiagnostics
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.SubscriptionType
import com.aerobox.data.model.connectionFingerprint
import com.aerobox.data.model.isLocalGroup
import com.aerobox.data.model.matchScore
import com.aerobox.data.model.normalizedDisplayName
import com.aerobox.utils.PreferenceManager
import com.aerobox.work.SubscriptionUpdateScheduler
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers
import okhttp3.Request
import com.aerobox.core.network.SharedHttpClient
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import java.io.IOException
import java.util.Base64

import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class SubscriptionImportResult(
    val subscriptionId: Long,
    val nodeCount: Int,
    val error: Throwable? = null,
    val metadataFromHeader: Boolean = false,
    val diagnostics: ParseDiagnostics = ParseDiagnostics(),
    // Number of imported nodes with TLS certificate verification disabled
    // (allowInsecure / skip-cert-verify). Surfaces a security warning in the UI.
    val insecureNodeCount: Int = 0
)

// Result of parsing inline content (local file / pasted text / single-node QR).
// Nodes are not yet assigned to a group — callers pair this with an
// [ImportGroupTarget] and call [SubscriptionRepository.commitLocalImport].
data class PreparedLocalImport(
    val nodes: List<ProxyNode>,
    val resolvedName: String?,
    val sourceType: SubscriptionType,
    val trafficBytes: Long,
    val expireTimestamp: Long,
    val metadataFromHeader: Boolean,
    val diagnostics: ParseDiagnostics
) {
    val insecureNodeCount: Int get() = nodes.count { it.allowInsecure }
}

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

class SubscriptionRepository(context: Context) {
    private val appContext = context.applicationContext
    private val database = AeroBoxApplication.database
    private val subscriptionDao = database.subscriptionDao()
    private val proxyNodeDao = database.proxyNodeDao()

    companion object {
        private const val NODE_MATCH_THRESHOLD = 50
        private const val MAX_CONCURRENT_SUBSCRIPTION_REFRESHES = 4
        private const val SUBSCRIPTION_USER_AGENT = "clash-verge/v1.3.8"
        // Hard cap on subscription response body size. Aligned with Clash YAML
        // codePointLimit so a malicious server cannot OOM the app by streaming
        // an unbounded response into memory before parsing.
        private const val MAX_SUBSCRIPTION_BYTES = 8L * 1024L * 1024L
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
        const val LOCAL_GROUP_TARGET_INVALID_ERROR = "LOCAL_GROUP_TARGET_INVALID"
        const val INVALID_SUBSCRIPTION_URL_ERROR = "INVALID_SUBSCRIPTION_URL"
        const val SUBSCRIPTION_RESPONSE_TOO_LARGE_ERROR = "SUBSCRIPTION_RESPONSE_TOO_LARGE"
        private val COMMENT_METADATA_REGEX =
            Regex("""^\s*(#|//|;)\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$""")
        private val SUPPORTED_COMMENT_METADATA_KEYS = setOf(
            "profile-title",
            "profile-update-interval",
            "subscription-userinfo",
            "moved-permanently-to"
        )
        private val CONTENT_DISPOSITION_UTF8_REGEX =
            Regex("""filename\*\s*=\s*UTF-8''([^;]+)""", RegexOption.IGNORE_CASE)
        private val CONTENT_DISPOSITION_FILENAME_REGEX =
            Regex("""filename\s*=\s*"?([^";]+)"?""", RegexOption.IGNORE_CASE)

        internal val sharedClient get() = SharedHttpClient.base
    }

    private data class SubscriptionFetchResult(
        val content: String,
        val headers: Headers,
        val resolvedUrl: String
    )

    private data class PreparedSubscriptionImport(
        val nodes: List<ProxyNode>,
        val trafficBytes: Long,
        val expireTimestamp: Long,
        val metadataFromHeader: Boolean,
        val sourceType: SubscriptionType,
        val diagnostics: ParseDiagnostics,
        val resolvedName: String? = null,
        val resolvedUrl: String? = null,
        val resolvedUpdateInterval: Long? = null
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

    private data class ImportMetadata(
        val sanitizedContent: String,
        val profileTitle: String? = null,
        val canonicalUrl: String? = null,
        val updateIntervalMs: Long? = null,
        val userInfo: SubscriptionUserInfo? = null
    )

    private data class CommentMetadata(
        val sanitizedContent: String,
        val values: Map<String, String>
    )

    fun getAllSubscriptions() = subscriptionDao.getAllSubscriptions()

    fun getLocalGroups() = subscriptionDao.getLocalGroups()

    fun observeUngroupedNodeCount() = proxyNodeDao.observeUngroupedNodeCount()

    fun observeSubscriptionById(id: Long) = subscriptionDao.observeById(id)

    fun observeNodesInGroup(subscriptionId: Long) =
        proxyNodeDao.observeNodesBySubscription(subscriptionId)

    suspend fun deleteNode(nodeId: Long) {
        val node = proxyNodeDao.getNodeById(nodeId) ?: return
        val selectedNodeId = PreferenceManager.lastSelectedNodeIdFlow(appContext).first()
        database.withTransaction {
            proxyNodeDao.deleteById(nodeId)
            if (node.subscriptionId > 0L) {
                recomputeLocalGroupCount(node.subscriptionId)
            }
        }
        if (selectedNodeId == nodeId) {
            PreferenceManager.setLastSelectedNodeId(appContext, 0L)
        }
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
            val effectiveName = name.ifBlank { prepared.resolvedName ?: deriveSubscriptionName(effectiveUrl) }
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
                        // Note: Subscription.type is intentionally not written
                        // here. The column is preserved in the schema for
                        // forward compatibility but no consumer reads it, so
                        // we leave it at its default value to avoid pretending
                        // it carries meaning.
                        trafficBytes = prepared.trafficBytes,
                        expireTimestamp = prepared.expireTimestamp,
                        updateInterval = effectiveInterval
                    )
                )
                insertedId
            }
            SubscriptionUpdateScheduler.reconfigure(appContext)
            logImportDiagnostics(
                action = "import",
                subscriptionName = effectiveName,
                diagnostics = prepared.diagnostics
            )
            SubscriptionImportResult(
                subscriptionId = subscriptionId,
                nodeCount = prepared.nodes.size,
                error = null,
                metadataFromHeader = prepared.metadataFromHeader,
                diagnostics = prepared.diagnostics,
                insecureNodeCount = prepared.nodes.count { it.allowInsecure }
            )
        }.getOrElse { error ->
            val diagnostics = (error as? NoValidNodesException)?.diagnostics ?: ParseDiagnostics()
            logImportDiagnostics(
                action = "import",
                subscriptionName = name,
                diagnostics = diagnostics
            )
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
        database.withTransaction {
            if (subscription.isLocalGroup()) {
                // Preserve user-imported nodes by moving them back to the default bucket.
                proxyNodeDao.reassignBySubscription(
                    fromSubscriptionId = subscription.id,
                    targetSubscriptionId = 0L
                )
            } else {
                proxyNodeDao.deleteBySubscription(subscription.id)
            }
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
        if (subscription.isLocalGroup()) {
            throw IllegalStateException(appContext.getString(R.string.error_local_group_no_remote_refresh))
        }
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
        val wasLocal = subscription.isLocalGroup()
        val trimmedUrl = url.trim()
        // Local groups have no remote URL — preserve the empty marker so they
        // never accidentally become refreshable subscriptions. For real
        // subscriptions we require a valid HTTPS URL; if the caller passed an
        // invalid one we keep the existing url to avoid breaking refresh.
        val resolvedUrl = when {
            wasLocal -> subscription.url
            isValidRemoteSubscriptionUrl(trimmedUrl) -> trimmedUrl
            else -> subscription.url
        }
        subscriptionDao.update(
            subscription.copy(
                name = name,
                url = resolvedUrl,
                autoUpdate = if (wasLocal) false else autoUpdate,
                updateInterval = normalizeUpdateInterval(updateInterval)
            )
        )
        SubscriptionUpdateScheduler.reconfigure(appContext)
    }

    suspend fun renameLocalGroup(subscription: Subscription, name: String) {
        val trimmed = name.trim()
        if (!subscription.isLocalGroup() || trimmed.isBlank()) return
        subscriptionDao.update(subscription.copy(name = trimmed))
    }

    suspend fun createLocalGroup(name: String): Long {
        val trimmed = name.trim().ifBlank { appContext.getString(R.string.local_group_label) }
        val subscription = Subscription(
            name = trimmed,
            url = "",
            autoUpdate = false,
            updateInterval = DEFAULT_UPDATE_INTERVAL_MS,
            createdAt = System.currentTimeMillis()
        )
        return subscriptionDao.insert(subscription)
    }

    suspend fun refreshAllSubscriptions(subscriptions: List<Subscription>): List<Result<SubscriptionUpdateResult>> {
        val refreshable = subscriptions.filterNot { it.isLocalGroup() }
        val results = refreshSubscriptions(refreshable)
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
        val dueSubscriptions = subscriptions.filter { subscription ->
            shouldAutoUpdate(subscription, now)
        }
        val results = refreshSubscriptions(dueSubscriptions)
        if (reconfigureSchedule && results.any { it.isSuccess }) {
            SubscriptionUpdateScheduler.reconfigure(appContext)
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

    suspend fun updateNodeLatency(nodeId: Long, latency: Int) {
        proxyNodeDao.updateLatency(nodeId, latency)
    }

    suspend fun updateNodeLatencies(latencies: Map<Long, Int>) {
        if (latencies.isEmpty()) return
        database.withTransaction {
            latencies.forEach { (nodeId, latency) ->
                proxyNodeDao.updateLatency(nodeId, latency)
            }
        }
    }

    suspend fun resolveNode(node: ProxyNode): ProxyNode? {
        proxyNodeDao.getNodeById(node.id)?.let { return it }
        if (node.subscriptionId <= 0L) return null

        val subscriptionNodes = proxyNodeDao.getNodesBySubscription(node.subscriptionId)
        return findBestMatchingNode(node, subscriptionNodes)
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
            sourceType = prepared.sourceType,
            trafficBytes = prepared.trafficBytes,
            expireTimestamp = prepared.expireTimestamp,
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
                is ImportGroupTarget.Ungrouped -> commitToUngrouped(prepared)
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

    suspend fun moveNodesToGroup(
        nodeIds: List<Long>,
        target: ImportGroupTarget
    ): Result<Long> {
        if (nodeIds.isEmpty()) return Result.success(0L)
        return runCatching {
            val targetId = when (target) {
                is ImportGroupTarget.Ungrouped -> 0L
                is ImportGroupTarget.Existing -> {
                    val existing = subscriptionDao.getById(target.subscriptionId)
                        ?: throw IllegalStateException(appContext.getString(R.string.error_target_group_not_found))
                    if (!existing.isLocalGroup()) {
                        throw IllegalStateException(LOCAL_GROUP_TARGET_INVALID_ERROR)
                    }
                    existing.id
                }
                is ImportGroupTarget.New -> createLocalGroup(target.name)
            }

            val affectedSourceIds = nodeIds
                .mapNotNull { proxyNodeDao.getNodeById(it)?.subscriptionId }
                .toSet()

            database.withTransaction {
                proxyNodeDao.moveNodesToSubscription(nodeIds, targetId)
                recomputeLocalGroupCount(targetId)
                affectedSourceIds.forEach { sourceId ->
                    if (sourceId != targetId) recomputeLocalGroupCount(sourceId)
                }
            }
            targetId
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
            subscriptionName = prepared.resolvedName.orEmpty(),
            nodes = nodes,
            prepared = prepared
        )
    }

    private suspend fun commitToExistingLocalGroup(
        prepared: PreparedLocalImport,
        subscriptionId: Long
    ): SubscriptionImportResult {
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
        return persistLocalImportNodes(
            subscriptionId = subscription.id,
            subscriptionName = subscription.name,
            nodes = nodes,
            prepared = prepared
        )
    }

    private suspend fun commitToNewLocalGroup(
        prepared: PreparedLocalImport,
        name: String
    ): SubscriptionImportResult {
        val trimmedName = name.trim().ifBlank { prepared.resolvedName?.trim().orEmpty() }
            .ifBlank { appContext.getString(R.string.local_group_label) }
        val subscriptionId = createLocalGroup(trimmedName)
        val nodes = prepareNodesForLocalGroup(
            prepared = prepared,
            subscriptionId = subscriptionId,
            existingFingerprints = emptySet()
        )
        if (nodes.isEmpty()) {
            // Dedup yielded nothing — roll back the just-created group so we
            // don't leave an empty ghost. (Only safe here because we created
            // the group in this call; other paths must never delete.)
            subscriptionDao.deleteById(subscriptionId)
        }
        return persistLocalImportNodes(
            subscriptionId = subscriptionId.takeIf { nodes.isNotEmpty() } ?: 0L,
            subscriptionName = trimmedName,
            nodes = nodes,
            prepared = prepared
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
        subscriptionName: String,
        nodes: List<ProxyNode>,
        prepared: PreparedLocalImport
    ): SubscriptionImportResult {
        if (nodes.isEmpty()) {
            logImportDiagnostics(
                action = "import",
                subscriptionName = subscriptionName.ifBlank { "inline-import" },
                diagnostics = prepared.diagnostics
            )
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
        logImportDiagnostics(
            action = "import",
            subscriptionName = subscriptionName.ifBlank { "inline-import" },
            diagnostics = prepared.diagnostics
        )
        return SubscriptionImportResult(
            subscriptionId = subscriptionId,
            nodeCount = nodes.size,
            metadataFromHeader = prepared.metadataFromHeader,
            diagnostics = prepared.diagnostics,
            insecureNodeCount = nodes.count { it.allowInsecure }
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
        val fetchResult = fetchSubscription(trimmedUrl)
        val metadata = parseImportMetadata(
            source = fetchResult.content,
            sourceUrl = fetchResult.resolvedUrl.ifBlank { trimmedUrl },
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
            sourceType = parsed.sourceType,
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
        val metadata = parseImportMetadata(
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
            sourceType = parsed.sourceType,
            diagnostics = parsed.diagnostics,
            resolvedName = metadata.profileTitle ?: nameHint.takeIf { it.isNotBlank() }
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
            val call = sharedClient.newCall(request)
            cont.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!cont.isActive) return
                        val result = runCatching {
                            if (!it.isSuccessful) {
                                throw IOException("HTTP ${it.code}")
                            }
                            SubscriptionFetchResult(
                                content = readBoundedBody(it.body, MAX_SUBSCRIPTION_BYTES),
                                headers = it.headers,
                                resolvedUrl = it.request.url.toString()
                            )
                        }
                        if (!cont.isActive) return
                        result
                            .onSuccess { fetchResult ->
                                cont.resume(fetchResult)
                            }
                            .onFailure { error ->
                                cont.resumeWithException(error)
                            }
                    }
                }
                override fun onFailure(call: Call, e: IOException) {
                    if (cont.isActive) {
                        cont.resumeWithException(e)
                    }
                }
            })
        }

    /**
     * Read a [ResponseBody] into a UTF-8 string while enforcing an upper bound.
     *
     * Uses Okio to consume up to [maxBytes] from the source, then peeks one
     * additional byte. If any data remains the body exceeded the limit and we
     * abort instead of buffering the rest. This keeps memory usage bounded on
     * a hostile server even when `Content-Length` is missing or lies.
     */
    private fun readBoundedBody(body: ResponseBody, maxBytes: Long): String {
        val source = body.source()
        val buffer = Buffer()
        var remaining = maxBytes
        while (remaining > 0) {
            val read = source.read(buffer, remaining)
            if (read == -1L) break
            remaining -= read
        }
        if (source.request(1)) {
            throw IOException(SUBSCRIPTION_RESPONSE_TOO_LARGE_ERROR)
        }
        return buffer.readString(Charsets.UTF_8)
    }

    private fun shouldAutoUpdate(subscription: Subscription, now: Long): Boolean {
        if (subscription.isLocalGroup()) return false
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

        val persistedNodes = database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            proxyNodeDao.insertAll(stabilizedNodes)
            subscriptionDao.update(
                subscription.copy(
                    url = prepared.resolvedUrl ?: subscription.url,
                    updateTime = updatedAt,
                    nodeCount = stabilizedNodes.size,
                    // type intentionally not written — see addSubscription
                    trafficBytes = prepared.trafficBytes,
                    expireTimestamp = prepared.expireTimestamp,
                    updateInterval = prepared.resolvedUpdateInterval
                        ?.takeIf { subscription.autoUpdate }
                        ?: normalizeUpdateInterval(subscription.updateInterval)
                )
            )
            proxyNodeDao.getNodesBySubscription(subscription.id)
        }

        maybeUpdateSelectedNode(
            selectedNodeId = selectedNodeId,
            existingNodes = existingNodes,
            refreshedNodes = persistedNodes
        )

        logImportDiagnostics(
            action = "update",
            subscriptionName = subscription.name,
            diagnostics = prepared.diagnostics
        )

        return SubscriptionUpdateResult(
            subscriptionId = subscription.id,
            nodeCount = persistedNodes.size,
            trafficBytes = prepared.trafficBytes,
            expireTimestamp = prepared.expireTimestamp,
            summary = summary,
            metadataFromHeader = prepared.metadataFromHeader,
            diagnostics = prepared.diagnostics,
            insecureNodeCount = persistedNodes.count { it.allowInsecure }
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
        val baseTimestamp = System.currentTimeMillis()
        return freshNodes.mapIndexed { index, freshNode ->
            val matchedNode = takeBestMatchingNode(freshNode, remainingExisting)
            freshNode.copy(
                id = matchedNode?.id ?: 0L,
                subscriptionId = subscriptionId,
                latency = matchedNode?.latency ?: freshNode.latency,
                createdAt = baseTimestamp + index
            )
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
            totalBytes = pairs["total"]?.toLongOrNull() ?: pairs["totl"]?.toLongOrNull(),
            expireTimestamp = pairs["expire"]?.toLongOrNull()?.let(::normalizeExpireTimestamp)
        )
    }

    private fun parseImportMetadata(
        source: String,
        sourceUrl: String?,
        headers: Headers?
    ): ImportMetadata {
        val commentMetadata = parseLeadingCommentMetadata(source)
        val headerTitle = headers?.valueByName("Profile-Title")?.let(::decodeMetadataValue)
        val commentTitle = commentMetadata.values["profile-title"]?.let(::decodeMetadataValue)
        val contentDispositionTitle = headers?.valueByName("Content-Disposition")
            ?.let(::extractFilenameFromContentDisposition)
        val profileTitle = firstNonBlank(
            headerTitle,
            commentTitle,
            contentDispositionTitle,
            sourceUrl?.let(::deriveSubscriptionName)
        )
        val updateIntervalMs = headers?.valueByName("profile-update-interval")
            ?.let(::parseProfileUpdateInterval)
            ?: commentMetadata.values["profile-update-interval"]?.let(::parseProfileUpdateInterval)
        val canonicalUrl = firstNonBlank(
            headers?.valueByName("moved-permanently-to"),
            commentMetadata.values["moved-permanently-to"],
            sourceUrl
        )?.takeIf(::isValidRemoteSubscriptionUrl)
        val userInfo = parseSubscriptionUserInfo(
            headers?.valueByName("Subscription-Userinfo")
                ?: commentMetadata.values["subscription-userinfo"]
        )
        return ImportMetadata(
            sanitizedContent = commentMetadata.sanitizedContent,
            profileTitle = profileTitle,
            canonicalUrl = canonicalUrl,
            updateIntervalMs = updateIntervalMs,
            userInfo = userInfo
        )
    }

    private fun parseLeadingCommentMetadata(source: String): CommentMetadata {
        val lines = source.lines()
        if (lines.isEmpty()) {
            return CommentMetadata(source, emptyMap())
        }

        val metadata = linkedMapOf<String, String>()
        val sanitizedLines = lines.toMutableList()
        val maxLines = minOf(lines.size, 10)
        repeat(maxLines) { index ->
            val line = lines[index]
            val match = COMMENT_METADATA_REGEX.matchEntire(line) ?: return@repeat
            val key = match.groupValues[2].trim().lowercase()
            val value = match.groupValues[3].trim()
            if (key in SUPPORTED_COMMENT_METADATA_KEYS && value.isNotBlank()) {
                metadata[key] = value
                sanitizedLines[index] = ""
            }
        }
        return CommentMetadata(
            sanitizedContent = sanitizedLines.joinToString("\n"),
            values = metadata
        )
    }

    private fun Headers.valueByName(name: String): String? {
        return names()
            .firstOrNull { it.equals(name, ignoreCase = true) }
            ?.let { headerName -> get(headerName) }
            ?.trim()
            ?.takeIf { it.isNotBlank() }
    }

    private fun decodeMetadataValue(value: String): String {
        val trimmed = value.trim()
        val encodedValue = trimmed.substringAfter("base64:", "")
        if (!trimmed.startsWith("base64:", ignoreCase = true) || encodedValue.isBlank()) {
            return trimmed
        }
        return runCatching {
            String(Base64.getDecoder().decode(encodedValue))
        }.getOrDefault(trimmed)
    }

    private fun extractFilenameFromContentDisposition(value: String): String? {
        CONTENT_DISPOSITION_UTF8_REGEX.find(value)?.let { match ->
            return sanitizeProfileFileName(Uri.decode(match.groupValues[1]))
        }
        CONTENT_DISPOSITION_FILENAME_REGEX.find(value)?.let { match ->
            return sanitizeProfileFileName(match.groupValues[1])
        }
        return null
    }

    private fun sanitizeProfileFileName(value: String): String? {
        val trimmed = value.trim().trim('"').trim('\'')
        if (trimmed.isBlank()) return null
        return trimmed.substringBeforeLast('.').ifBlank { trimmed }
    }

    private fun deriveSubscriptionName(url: String): String? {
        return runCatching {
            val uri = Uri.parse(url)
            uri.fragment?.trim()?.takeIf { it.isNotBlank() }
                ?: sanitizeProfileFileName(uri.lastPathSegment ?: uri.host.orEmpty())
        }.getOrNull()
    }

    private fun parseProfileUpdateInterval(value: String): Long? {
        val hours = value.trim().toLongOrNull() ?: return null
        if (hours <= 0L) return null
        return normalizeUpdateInterval(hours * 60L * 60L * 1000L)
    }

    fun isValidRemoteSubscriptionUrl(url: String): Boolean {
        return runCatching {
            val parsed = Uri.parse(url.trim())
            parsed.scheme.equals("https", ignoreCase = true) && !parsed.host.isNullOrBlank()
        }.getOrDefault(false)
    }

    private fun firstNonBlank(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() }?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun normalizeExpireTimestamp(timestamp: Long): Long {
        return if (timestamp >= 1_000_000_000_000L) timestamp else timestamp * 1000L
    }

    private fun normalizeUpdateInterval(interval: Long): Long {
        return interval.coerceAtLeast(MIN_UPDATE_INTERVAL_MS)
    }

    private fun logImportDiagnostics(
        action: String,
        subscriptionName: String,
        diagnostics: ParseDiagnostics
    ) {
        if (diagnostics.ignoredEntryCount <= 0) return
        val summary = diagnostics.reasonCounts.entries
            .sortedByDescending { it.value }
            .joinToString(", ") { (reason, count) -> "$reason=$count" }
        RuntimeLogBuffer.append(
            "warn",
            "Subscription $action ignored ${diagnostics.ignoredEntryCount} entries for ${subscriptionName.ifBlank { "unnamed" }}: $summary"
        )
    }

}
