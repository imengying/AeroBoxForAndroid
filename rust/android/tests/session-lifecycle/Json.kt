package org.json
class JSONObject {
    fun getLong(name: String) = 0L
    fun getString(name: String) = ""
    fun optString(name: String) = ""
    fun getJSONObject(name: String) = JSONObject()
    fun getJSONArray(name: String) = JSONArray()
    fun optJSONArray(name: String): JSONArray? = null
    fun put(name: String, value: Any?): JSONObject = this
}
class JSONArray(val values: Collection<*> = emptyList<Any>()) {
    fun length() = 0
    fun getJSONObject(index: Int) = JSONObject()
    fun getString(index: Int) = ""
    fun put(value: Any?): JSONArray = this
    override fun toString() = values.joinToString(prefix = "[", postfix = "]", separator = ",") { "\"$it\"" }
}
