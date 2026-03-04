package com.aerobox.utils

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import com.aerobox.core.subscription.SubscriptionParser
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

object ImportExportUtils {

    // ── Import ───────────────────────────────────────────────────────

    /**
     * Read text from the system clipboard.
     */
    fun getClipboardText(context: Context): String? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0).text?.toString()
    }

    /**
     * Import nodes from clipboard content (URI list, JSON, Clash YAML, etc.)
     */
    suspend fun importFromClipboard(context: Context): List<ProxyNode> {
        val text = getClipboardText(context) ?: return emptyList()
        return SubscriptionParser.parseSubscription(text)
    }

    /**
     * Import nodes from a file URI (content:// from SAF).
     */
    suspend fun importFromFile(context: Context, uri: Uri): List<ProxyNode> = withContext(Dispatchers.IO) {
        val content = context.contentResolver.openInputStream(uri)?.use { inputStream ->
            BufferedReader(InputStreamReader(inputStream)).readText()
        } ?: return@withContext emptyList()

        SubscriptionParser.parseSubscription(content)
    }

    // ── Export ────────────────────────────────────────────────────────

    /**
     * Export a single node as a shareable URI string.
     */
    fun exportNodeAsUri(node: ProxyNode): String? {
        return when (node.type) {
            ProxyType.SHADOWSOCKS, ProxyType.SHADOWSOCKS_2022 -> {
                val method = node.method ?: "aes-128-gcm"
                val password = node.password ?: ""
                val userInfo = android.util.Base64.encodeToString(
                    "$method:$password".toByteArray(),
                    android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
                )
                "ss://$userInfo@${node.server}:${node.port}#${Uri.encode(node.name)}"
            }
            ProxyType.VMESS -> {
                val json = JSONObject()
                    .put("v", "2")
                    .put("ps", node.name)
                    .put("add", node.server)
                    .put("port", node.port.toString())
                    .put("id", node.uuid ?: "")
                    .put("aid", "0")
                    .put("scy", node.security ?: "auto")
                    .put("net", node.network ?: "tcp")
                    .put("tls", if (node.tls) "tls" else "")
                    .put("sni", node.sni ?: "")
                val encoded = android.util.Base64.encodeToString(
                    json.toString().toByteArray(),
                    android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
                )
                "vmess://$encoded"
            }
            ProxyType.VLESS -> {
                val params = buildString {
                    append("security=${node.security ?: "none"}")
                    node.network?.let { append("&type=$it") }
                    node.sni?.let { append("&sni=$it") }
                    node.fingerprint?.let { append("&fp=$it") }
                    node.flow?.let { append("&flow=$it") }
                    node.publicKey?.let { append("&pbk=$it") }
                    node.shortId?.let { append("&sid=$it") }
                }
                "vless://${node.uuid}@${node.server}:${node.port}?$params#${Uri.encode(node.name)}"
            }
            ProxyType.TROJAN -> {
                val params = node.sni?.let { "sni=$it" } ?: ""
                "trojan://${node.password}@${node.server}:${node.port}?$params#${Uri.encode(node.name)}"
            }
            ProxyType.HYSTERIA2 -> {
                val params = node.sni?.let { "sni=$it" } ?: ""
                "hy2://${node.password}@${node.server}:${node.port}?$params#${Uri.encode(node.name)}"
            }
            ProxyType.TUIC -> {
                "tuic://${node.uuid}:${node.password ?: ""}@${node.server}:${node.port}#${Uri.encode(node.name)}"
            }
            ProxyType.SOCKS -> {
                val auth = if (node.username != null) "${node.username}:${node.password ?: ""}@" else ""
                "socks://${auth}${node.server}:${node.port}#${Uri.encode(node.name)}"
            }
            ProxyType.HTTP -> {
                val auth = if (node.username != null) "${node.username}:${node.password ?: ""}@" else ""
                val scheme = if (node.tls) "https" else "http"
                "$scheme://${auth}${node.server}:${node.port}#${Uri.encode(node.name)}"
            }
            ProxyType.WIREGUARD -> null // WG configs are not typically shared as URIs
        }
    }

    /**
     * Export nodes as a sing-box JSON outbounds array.
     */
    fun exportNodesAsJson(nodes: List<ProxyNode>): String {
        val array = JSONArray()
        nodes.forEach { node ->
            val obj = JSONObject()
                .put("type", node.type.name.lowercase())
                .put("tag", node.name)
                .put("server", node.server)
                .put("server_port", node.port)
            node.uuid?.let { obj.put("uuid", it) }
            node.password?.let { obj.put("password", it) }
            node.method?.let { obj.put("method", it) }
            array.put(obj)
        }
        return array.toString(2)
    }

    /**
     * Create a share Intent with the exported content.
     */
    fun createShareIntent(content: String, title: String = "AeroBox 配置分享"): Intent {
        return Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, content)
            putExtra(Intent.EXTRA_TITLE, title)
        }
    }
}
