package com.aerobox.core.connection

import com.aerobox.data.repository.VpnConnectionResult

enum class ConnectionFixAction(val label: String) {
    UPDATE_GEO("更新路由资源"),
    SWITCH_GLOBAL_MODE("切换为全局模式"),
    REFRESH_SUBSCRIPTIONS("重新拉取订阅")
}

data class ConnectionIssue(
    val title: String,
    val message: String,
    val rawError: String,
    val fixAction: ConnectionFixAction? = null
)

object ConnectionDiagnostics {
    fun classify(rawError: String): ConnectionIssue {
        val msg = rawError.lowercase()

        return when {
            msg.contains("geosite") ||
                msg.contains("geoip") ||
                msg.contains("rule_set") ||
                msg.contains("rule-set") ||
                msg.contains(".srs") ||
                (msg.contains("router") && msg.contains("database")) -> {
                ConnectionIssue(
                    title = "路由资源异常",
                    message = "检测到官方路由规则集不可用或格式不兼容。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.UPDATE_GEO
                )
            }

            msg.contains("rule") ||
                (msg.contains("router") && msg.contains("parse")) -> {
                ConnectionIssue(
                    title = "路由规则异常",
                    message = "当前规则模式可能与节点配置不兼容，建议先切换到全局模式。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.SWITCH_GLOBAL_MODE
                )
            }

            msg.contains("outbound") ||
                msg.contains("node") ||
                msg.contains("subscription") ||
                msg.contains("proxy") -> {
                ConnectionIssue(
                    title = "节点或订阅可能失效",
                    message = "节点参数可能已过期，建议重新拉取订阅后再连接。",
                    rawError = rawError,
                    fixAction = ConnectionFixAction.REFRESH_SUBSCRIPTIONS
                )
            }

            else -> {
                ConnectionIssue(
                    title = "连接配置异常",
                    message = "请检查节点、DNS、分流设置，必要时更新订阅后重试。",
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

    fun userFacingFailureMessage(result: VpnConnectionResult, operationFailedText: String): String {
        val issue = issueFromResult(result) ?: return operationFailedText
        return "$operationFailedText: ${issue.title}"
    }

    fun logFailureMessage(result: VpnConnectionResult, fallback: String): String {
        val issue = issueFromResult(result)
        return when {
            issue != null -> "${issue.title}: ${issue.rawError}"
            result is VpnConnectionResult.Failure -> result.throwable.message ?: fallback
            else -> fallback
        }
    }
}
