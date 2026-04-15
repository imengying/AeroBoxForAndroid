package com.aerobox.data.repository

import android.content.Context
import android.net.Uri
import androidx.room.withTransaction
import com.aerobox.AeroBoxApplication
import com.aerobox.core.logging.RuntimeLogBuffer
import com.aerobox.core.subscription.ParseDiagnostics
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.Subscription
import com.aerobox.data.model.SubscriptionType
import com.aerobox.data.model.connectionFingerprint
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
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class SubscriptionImportResult(
    val subscriptionId: Long,
    val nodeCount: Int,
    val error: Throwable? = null,
    val metadataFromHeader: Boolean = false,
    val diagnostics: ParseDiagnostics = ParseDiagnostics()
)

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
        const val MIN_UPDATE_INTERVAL_MS = 15 * 60 * 1000L
        const val DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val NO_VALID_NODES_ERROR = "NO_VALID_NODES"
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

        internal val sharedClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build()
        }
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

    suspend fun importExternalSource(
        nameHint: String,
        source: String,
        autoUpdate: Boolean = false,
        updateInterval: Long = DEFAULT_UPDATE_INTERVAL_MS
    ): SubscriptionImportResult {
        val trimmedSource = source.trim()
        return if (isValidRemoteSubscriptionUrl(trimmedSource)) {
            addSubscription(
                name = nameHint,
                url = trimmedSource,
                autoUpdate = autoUpdate,
                updateInterval = updateInterval
            )
        } else {
            importLocalContent(nameHint, trimmedSource)
        }
    }

    suspend fun addSubscription(
        name: String,
        url: String,
        autoUpdate: Boolean = false,
        updateInterval: Long = DEFAULT_UPDATE_INTERVAL_MS
    ): SubscriptionImportResult {
        val normalizedInterval = normalizeUpdateInterval(updateInterval)

        return runCatching {
            val prepared = prepareSubscriptionImport(url)
            val effectiveUrl = prepared.resolvedUrl ?: url
            val effectiveName = name.ifBlank { prepared.resolvedName ?: deriveSubscriptionName(effectiveUrl) }
                ?: "导入订阅"
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
                        type = prepared.sourceType,
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
                diagnostics = prepared.diagnostics
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
        val results = refreshSubscriptions(subscriptions)
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

    private suspend fun importLocalContent(
        nameHint: String,
        source: String
    ): SubscriptionImportResult {
        return runCatching {
            val prepared = prepareInlineImport(source, nameHint)
            val existingStandaloneFingerprints = proxyNodeDao.getNodesBySubscription(0L)
                .asSequence()
                .map { it.connectionFingerprint() }
                .toSet()
            val nodesToInsert = prepared.nodes
                .filterNot { it.connectionFingerprint() in existingStandaloneFingerprints }
                .mapIndexed { index, node ->
                    val fallbackName = prepared.resolvedName
                        ?.takeIf { prepared.nodes.size == 1 }
                        ?: nameHint.takeIf { nameHint.isNotBlank() && prepared.nodes.size == 1 }
                        ?: "导入节点 ${index + 1}"
                    node.copy(
                        name = node.name.ifBlank { fallbackName },
                        subscriptionId = 0L
                    )
                }
                .let { nodes -> assignFetchedNodeOrder(nodes, subscriptionId = 0L) }

            if (nodesToInsert.isEmpty()) {
                SubscriptionImportResult(
                    subscriptionId = 0,
                    nodeCount = 0,
                    error = IllegalStateException("未导入新节点，可能已存在相同配置"),
                    diagnostics = prepared.diagnostics
                )
            } else {
                proxyNodeDao.insertAll(nodesToInsert)
                logImportDiagnostics(
                    action = "import",
                    subscriptionName = nameHint.ifBlank { prepared.resolvedName ?: "inline-import" },
                    diagnostics = prepared.diagnostics
                )
                SubscriptionImportResult(
                    subscriptionId = 0,
                    nodeCount = nodesToInsert.size,
                    diagnostics = prepared.diagnostics
                )
            }
        }.getOrElse { error ->
            val diagnostics = (error as? NoValidNodesException)?.diagnostics ?: ParseDiagnostics()
            logImportDiagnostics(
                action = "import",
                subscriptionName = nameHint.ifBlank { "inline-import" },
                diagnostics = diagnostics
            )
            SubscriptionImportResult(
                subscriptionId = 0,
                nodeCount = 0,
                error = error,
                diagnostics = diagnostics
            )
        }
    }

    private suspend fun prepareSubscriptionImport(url: String): PreparedSubscriptionImport {
        val fetchResult = fetchSubscription(url)
        val metadata = parseImportMetadata(
            source = fetchResult.content,
            sourceUrl = fetchResult.resolvedUrl.ifBlank { url },
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
                        if (!it.isSuccessful) {
                            cont.resumeWithException(IOException("HTTP ${it.code}"))
                        } else {
                            cont.resume(
                                SubscriptionFetchResult(
                                    content = it.body.string(),
                                    headers = it.headers,
                                    resolvedUrl = it.request.url.toString()
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

        val persistedNodes = database.withTransaction {
            proxyNodeDao.deleteBySubscription(subscription.id)
            proxyNodeDao.insertAll(stabilizedNodes)
            subscriptionDao.update(
                subscription.copy(
                    url = prepared.resolvedUrl ?: subscription.url,
                    updateTime = updatedAt,
                    nodeCount = stabilizedNodes.size,
                    type = prepared.sourceType,
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
            diagnostics = prepared.diagnostics
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

    private fun isValidRemoteSubscriptionUrl(url: String): Boolean {
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
