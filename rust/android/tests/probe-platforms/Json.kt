package org.json

class JSONArray(private val values: Collection<*>) {
    override fun toString() = values.joinToString(prefix = "[", postfix = "]") { "\"$it\"" }
}
