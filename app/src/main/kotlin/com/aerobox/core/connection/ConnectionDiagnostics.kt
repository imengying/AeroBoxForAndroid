package com.aerobox.core.connection

import androidx.annotation.StringRes
import com.aerobox.R
import com.aerobox.data.repository.VpnConnectionResult

/**
 * Suggested remediation action presented next to a [ConnectionIssue]. The
 * label is supplied as a string resource so the UI layer can render it in
 * the user's locale.
 */
enum class ConnectionFixAction(@StringRes val labelResId: Int) {
    UPDATE_GEO(R.string.connection_fix_update_geo),
    SWITCH_GLOBAL_MODE(R.string.connection_fix_switch_global),
    REFRESH_SUBSCRIPTIONS(R.string.connection_fix_refresh_subscriptions)
}

/**
 * Structured representation of a connection failure. Both [titleResId] and
 * [messageResId] are string resources; the UI consumes them via
 * `stringResource(...)` so that translations follow the active locale.
 *
 * [rawError] is intentionally kept un-translated — it's the underlying
 * sing-box error string used for diagnostics / logs.
 */
data class ConnectionIssue(
    @StringRes val titleResId: Int,
    @StringRes val messageResId: Int,
    val rawError: String,
    val fixAction: ConnectionFixAction? = null
)

object ConnectionDiagnostics {
    fun classify(rawError: String): ConnectionIssue {
        val msg = rawError.lowercase()

        return when {
            msg.contains("reality") && msg.contains("sni") -> {
                ConnectionIssue(
                    titleResId = R.string.connection_issue_reality_title,
                    messageResId = R.string.connection_issue_reality_message,
                    rawError = rawError
                )
            }

            msg.contains("geosite") ||
                msg.contains("geoip") ||
                msg.contains("rule_set") ||
                msg.contains("rule-set") ||
                msg.contains(".srs") ||
                (msg.contains("router") && msg.contains("database")) -> {
                ConnectionIssue(
                    titleResId = R.string.connection_issue_geo_title,
                    messageResId = R.string.connection_issue_geo_message,
                    rawError = rawError,
                    fixAction = ConnectionFixAction.UPDATE_GEO
                )
            }

            msg.contains("rule") ||
                (msg.contains("router") && msg.contains("parse")) -> {
                ConnectionIssue(
                    titleResId = R.string.connection_issue_rule_title,
                    messageResId = R.string.connection_issue_rule_message,
                    rawError = rawError,
                    fixAction = ConnectionFixAction.SWITCH_GLOBAL_MODE
                )
            }

            msg.contains("outbound") ||
                msg.contains("node") ||
                msg.contains("subscription") ||
                msg.contains("proxy") -> {
                ConnectionIssue(
                    titleResId = R.string.connection_issue_node_title,
                    messageResId = R.string.connection_issue_node_message,
                    rawError = rawError,
                    fixAction = ConnectionFixAction.REFRESH_SUBSCRIPTIONS
                )
            }

            else -> {
                ConnectionIssue(
                    titleResId = R.string.connection_issue_generic_title,
                    messageResId = R.string.connection_issue_generic_message,
                    rawError = rawError
                )
            }
        }
    }

    fun issueFromResult(result: VpnConnectionResult): ConnectionIssue? {
        return when (result) {
            is VpnConnectionResult.InvalidConfig -> classify(result.error)
            is VpnConnectionResult.Failure -> {
                val rawError = result.throwable.message?.takeIf { it.isNotBlank() }
                    ?: result.throwable.toString()
                classify(rawError)
            }
            VpnConnectionResult.NoNodeAvailable,
            is VpnConnectionResult.Success -> null
        }
    }

    /**
     * Compose a snackbar-style failure message. Prefer the un-translated raw
     * core error because it is more useful for diagnostics and should not vary
     * with the device/app language.
     */
    fun userFacingFailureMessage(
        result: VpnConnectionResult,
        operationFailedText: String
    ): String {
        val issue = issueFromResult(result) ?: return operationFailedText
        return issue.rawError.takeIf { it.isNotBlank() } ?: operationFailedText
    }

    /**
     * Build a developer-facing log line using the raw core error. Logs should
     * stay language-neutral so they are easy to search and compare.
     */
    fun logFailureMessage(
        result: VpnConnectionResult,
        fallback: String
    ): String {
        val issue = issueFromResult(result)
        return when {
            issue?.rawError?.isNotBlank() == true -> issue.rawError
            result is VpnConnectionResult.Failure -> result.throwable.message ?: fallback
            else -> fallback
        }
    }
}
