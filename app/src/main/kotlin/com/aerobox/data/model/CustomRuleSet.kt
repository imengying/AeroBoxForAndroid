package com.aerobox.data.model

import org.json.JSONArray
import org.json.JSONObject

data class CustomRuleSet(
    val id: Long,
    val name: String,
    val url: String,
    val format: RuleSetFormat = RuleSetFormat.BINARY,
    val action: RuleSetAction = RuleSetAction.DIRECT,
    val enabled: Boolean = true
) {
    val tag: String get() = "custom-rule-$id"
}

enum class RuleSetFormat(val configValue: String) {
    BINARY("binary"),
    SOURCE("source");

    companion object {
        fun from(value: String?): RuleSetFormat {
            return entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
                ?: entries.firstOrNull { it.configValue.equals(value, ignoreCase = true) }
                ?: BINARY
        }
    }
}

enum class RuleSetAction {
    DIRECT,
    PROXY,
    REJECT;

    companion object {
        fun from(value: String?): RuleSetAction {
            return entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: DIRECT
        }
    }
}

object CustomRuleSetCodec {
    fun encode(ruleSets: List<CustomRuleSet>): String {
        val array = JSONArray()
        ruleSets.forEach { ruleSet ->
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
                    if (name.isBlank() || url.isBlank()) continue
                    add(
                        CustomRuleSet(
                            id = id,
                            name = name,
                            url = url,
                            format = RuleSetFormat.from(obj.optString("format")),
                            action = RuleSetAction.from(obj.optString("action")),
                            enabled = obj.optBoolean("enabled", true)
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }
}
