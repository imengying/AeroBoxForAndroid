package com.aerobox.core.subscription

import com.aerobox.data.model.ProxyNode
import org.json.JSONArray

internal data class NodeParseBatch(
    val nodes: List<ProxyNode>,
    val diagnostics: ParseDiagnostics = ParseDiagnostics()
)

/**
 * Shared extension functions used by both [UriNodeParser] and [JsonNodeParser].
 */
internal fun JSONArray.toCommaSeparatedString(): String? {
    val values = buildList {
        for (i in 0 until length()) {
            optString(i).trim().takeIf { it.isNotEmpty() }?.let { add(it) }
        }
    }
    return values.takeIf { it.isNotEmpty() }?.joinToString(",")
}
