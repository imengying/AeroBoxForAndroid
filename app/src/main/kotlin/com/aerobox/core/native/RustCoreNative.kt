package com.aerobox.core.`native`

import org.json.JSONArray
import org.json.JSONObject

/** Run these blocking calls on a service worker, never the Android main thread. */
object RustCoreNative {
    init { System.loadLibrary("aerobox") }

    /** Callbacks can run on Rust workers. Only the one-way completeDnsQuery
     * completion below may reenter JNI; never call lifecycle methods here. */
    interface PlatformCallbacks {
        fun protect(fd: Int): Boolean
        /** JSON array of physical-network DNS IPs or IP:port endpoints. */
        fun dnsServers(): String
        fun supportsSystemDns(): Boolean = false
        fun startDnsQuery(id: Long, generation: Long, networkHandle: Long, message: ByteArray): Unit =
            throw UnsupportedOperationException("Platform DNS transport is unavailable")
        fun cancelDnsQuery(id: Long): Unit =
            throw UnsupportedOperationException("Platform DNS transport is unavailable")
        /** Original TUN tuple. Diagnostic JSON null or {uid, packages}; never resolve hostnames. */
        fun connectionOwner(ipProtocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int): String = "null"
        /** Coherent non-VPN inventory; u64 handles/generations are JSON integers. */
        fun physicalNetworks(): String = throw UnsupportedOperationException("Physical network inventory is unavailable")
        /** Long arguments carry the exact u64 bit pattern returned in the inventory. */
        fun protectOnNetwork(fd: Int, generation: Long, handle: Long): Boolean =
            throw UnsupportedOperationException("Physical network binding is unavailable")
        /** Private persistent storage for DNS mappings and downloaded rules. */
        fun storageDirectory(): String = ""
    }

    // One-way DNS completion is allowed from platform callback threads. It only
    // resolves the native query token and never acquires Host lifecycle locks.
    @JvmStatic private external fun nativeDnsQueryComplete(
        id: Long, answer: ByteArray?, rcode: Int, errno: Int, message: String?
    )
    internal fun completeDnsQuery(id: Long, answer: ByteArray?, rcode: Int, errno: Int, message: String?) =
        nativeDnsQueryComplete(id, answer, rcode, errno, message)

    @JvmStatic private external fun nativeInit(level: String): String
    @JvmStatic private external fun nativeCheck(config: String): String
    @JvmStatic private external fun nativeStart(config: String, tunFd: Int, platform: PlatformCallbacks): String
    @JvmStatic private external fun nativeStop(): String
    @JvmStatic private external fun nativeNetworkChanged(): String
    @JvmStatic private external fun nativeIsRunning(): String
    @JvmStatic private external fun nativeStats(): String
    @JvmStatic private external fun nativeConnections(): String
    @JvmStatic private external fun nativeCloseConnection(id: String): String
    @JvmStatic private external fun nativeUrlTestConfig(config: String, name: String, url: String, timeoutMs: Long, platform: PlatformCallbacks): String
    @JvmStatic private external fun nativeDrainLogs(): String

    private fun value(response: String): Any? {
        val json = JSONObject(response)
        check(json.getBoolean("ok")) { json.optString("error", "Native core failed") }
        return json.opt("value").takeUnless { it === JSONObject.NULL }
    }

    @Volatile private var storageDirectory: String = ""

    /** Match the App's error-only log policy; storage also allows offline configuration checks. */
    fun initialize(level: String = "error", storage: java.io.File? = null): JSONObject {
        if (storage != null) storageDirectory = storage.absolutePath
        return value(nativeInit(level)) as JSONObject
    }

    private fun prepareConfig(configJson: String, platform: PlatformCallbacks? = null): String {
        val config = JSONObject(configJson)
        val cache = config.optJSONObject("experimental")?.optJSONObject("cache_file")
        if (cache != null && cache.optBoolean("enabled") && !cache.has("path")) {
            val directory = platform?.storageDirectory()?.takeIf { it.isNotBlank() } ?: storageDirectory
            check(directory.isNotBlank()) { "A private storage directory is required for persistent DNS and rules" }
            val file = java.io.File(directory)
            check(file.isDirectory || file.mkdirs()) { "Cannot create core storage directory" }
            // Android's app mount namespace may expose /data/user/0 as an alias.
            // Resolve the default private directory before Rust's no-follow
            // traversal. Explicit cache paths never enter this branch.
            val canonicalDirectory = file.canonicalFile
            cache.put("path", java.io.File(canonicalDirectory, "cache").absolutePath)
        }
        return config.toString()
    }

    /** Reports deferredRemoteRules; their contents are checked during start. */
    fun checkConfig(configJson: String, platform: PlatformCallbacks? = null): JSONObject =
        value(nativeCheck(prepareConfig(configJson, platform))) as JSONObject
    /** tunFd is borrowed. Rust duplicates it; keep it open until this call returns. */
    fun start(configJson: String, tunFd: Int = -1, platform: PlatformCallbacks) {
        val prepared = prepareConfig(configJson, platform)
        value(nativeStart(prepared, tunFd, platform))
        storageDirectory = platform.storageDirectory()
    }
    fun stop() { value(nativeStop()) }
    fun networkChanged() { value(nativeNetworkChanged()) }
    fun isRunning() = value(nativeIsRunning()) as Boolean
    fun stats() = value(nativeStats()) as JSONObject
    fun connections() = value(nativeConnections()) as JSONObject
    fun closeConnection(id: String) { value(nativeCloseConnection(id)) }
    fun urlTestConfig(configJson: String, name: String, url: String, timeoutMs: Long, platform: PlatformCallbacks) =
        (value(nativeUrlTestConfig(prepareConfig(configJson, platform), name, url, timeoutMs, platform)) as Number).toInt()
    fun drainLogs() = value(nativeDrainLogs()) as JSONArray
}
