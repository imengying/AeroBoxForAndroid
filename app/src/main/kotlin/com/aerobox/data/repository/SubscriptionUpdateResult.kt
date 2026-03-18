package com.aerobox.data.repository

import com.aerobox.core.subscription.ParseDiagnostics

data class SubscriptionUpdateSummary(
    val addedCount: Int = 0,
    val updatedCount: Int = 0,
    val deletedCount: Int = 0,
    val unchangedCount: Int = 0
) {
    val changedCount: Int
        get() = addedCount + updatedCount + deletedCount
}

data class SubscriptionUpdateResult(
    val subscriptionId: Long,
    val nodeCount: Int,
    val trafficBytes: Long,
    val expireTimestamp: Long,
    val summary: SubscriptionUpdateSummary,
    val metadataFromHeader: Boolean,
    val diagnostics: ParseDiagnostics = ParseDiagnostics()
)
