package com.aerobox.data.model

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

data class CustomRuleSet(
    val id: Long,
    val name: String,
    val url: String,
    val format: RuleSetFormat,
    val action: RuleSetAction,
    val enabled: Boolean
) {
    val tag: String get() = "custom-rule-$id"
}

fun isValidCustomRuleSetUrl(url: String): Boolean {
    val uri = runCatching { URI(url.trim()) }.getOrNull() ?: return false
    return uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()
}

enum class RuleSetFormat(val configValue: String) {
    BINARY("binary"),
    SOURCE("source");

    companion object {
        fun from(value: String?): RuleSetFormat? {
            return entries.firstOrNull { it.name == value }
        }
    }
}

enum class RuleSetAction {
    DIRECT,
    PROXY,
    REJECT;

    companion object {
        fun from(value: String?): RuleSetAction? {
            return entries.firstOrNull { it.name == value }
        }
    }
}

object CustomRuleSetCodec {
    fun encode(ruleSets: List<CustomRuleSet>): String {
        val array = JSONArray()
        ruleSets.filter { isValidCustomRuleSetUrl(it.url) }.forEach { ruleSet ->
            array.put(
                JSONObject()
                    .put("id", ruleSet.id)
                    .put("name", ruleSet.name)
                    .put("url", ruleSet.url)
                    .put("format", ruleSet.format.name)
                    .put("action", ruleSet.action.name)
                    .put("enabled", ruleSet.enabled)
            )
        }
        return array.toString()
    }

    fun decode(raw: String?): List<CustomRuleSet> {
        if (raw.isNullOrBlank()) return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            buildList {
                for (index in 0 until array.length()) {
                    val obj = array.optJSONObject(index) ?: continue
                    val id = obj.optLong("id", 0L).takeIf { it > 0L } ?: continue
                    val name = obj.optString("name").trim()
                    val url = obj.optString("url").trim()
                    if (name.isBlank() || !isValidCustomRuleSetUrl(url)) continue
                    val format = RuleSetFormat.from(obj.optString("format")) ?: continue
                    val action = RuleSetAction.from(obj.optString("action")) ?: continue
                    if (!obj.has("enabled")) continue
                    add(
                        CustomRuleSet(
                            id = id,
                            name = name,
                            url = url,
                            format = format,
                            action = action,
                            enabled = obj.optBoolean("enabled", true)
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }
}
