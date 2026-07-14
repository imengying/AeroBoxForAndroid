package com.aerobox.data.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

internal object DatabaseMigration1To2 : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        rebuildTable(db, "subscriptions", subscriptionColumns)
        rebuildTable(db, "proxy_nodes", proxyNodeColumns)
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_proxy_nodes_subscriptionId` " +
                "ON `proxy_nodes` (`subscriptionId`)"
        )
    }

    private fun rebuildTable(
        db: SupportSQLiteDatabase,
        tableName: String,
        columns: List<MigrationColumn>
    ) {
        val sourceColumns = tableColumns(db, tableName)
        val oldTableName = "${tableName}_v1"
        db.execSQL("ALTER TABLE `$tableName` RENAME TO `$oldTableName`")
        db.execSQL(
            columns.joinToString(
                prefix = "CREATE TABLE `$tableName` (",
                postfix = ")"
            ) { column -> "`${column.name}` ${column.definition}" }
        )

        val targetNames = columns.joinToString { "`${it.name}`" }
        val sourceValues = columns.joinToString { column ->
            column.sourceNames
                .firstOrNull(sourceColumns::contains)
                ?.let { "`$it`" }
                ?: column.fallback
        }
        db.execSQL(
            "INSERT INTO `$tableName` ($targetNames) " +
                "SELECT $sourceValues FROM `$oldTableName`"
        )
        db.execSQL("DROP TABLE `$oldTableName`")
    }

    private fun tableColumns(db: SupportSQLiteDatabase, tableName: String): Set<String> {
        return buildSet {
            db.query("PRAGMA table_info(`$tableName`)").use { cursor ->
                val nameIndex = cursor.getColumnIndexOrThrow("name")
                while (cursor.moveToNext()) add(cursor.getString(nameIndex))
            }
        }
    }

    private class MigrationColumn(
        val name: String,
        val definition: String,
        val fallback: String = "NULL",
        val aliases: List<String> = emptyList()
    ) {
        val sourceNames: List<String> = listOf(name) + aliases
    }

    private fun required(
        name: String,
        definition: String,
        fallback: String,
        vararg aliases: String
    ) = MigrationColumn(name, "$definition NOT NULL", fallback, aliases.toList())

    private fun optional(
        name: String,
        definition: String,
        vararg aliases: String
    ) = MigrationColumn(name, definition, aliases = aliases.toList())

    private val subscriptionColumns = listOf(
        required("id", "INTEGER PRIMARY KEY AUTOINCREMENT", "0"),
        required("name", "TEXT", "''"),
        required("url", "TEXT", "''"),
        required("updateTime", "INTEGER", "0"),
        required("nodeCount", "INTEGER", "0"),
        required("autoUpdate", "INTEGER", "0"),
        required("updateInterval", "INTEGER", "86400000"),
        required("createdAt", "INTEGER", "0"),
        required("trafficBytes", "INTEGER", "0"),
        required("expireTimestamp", "INTEGER", "0")
    )

    private val proxyNodeColumns = listOf(
        required("id", "INTEGER PRIMARY KEY AUTOINCREMENT", "0"),
        required("name", "TEXT", "''"),
        required("type", "TEXT", "'SHADOWSOCKS'"),
        required("server", "TEXT", "''"),
        required("port", "INTEGER", "0"),
        optional("bindInterface", "TEXT"),
        optional("connectTimeout", "TEXT"),
        optional("tcpFastOpen", "INTEGER"),
        optional("tcpMultiPath", "INTEGER"),
        optional("udpFragment", "INTEGER"),
        optional("networkStrategy", "TEXT"),
        optional("networkType", "TEXT"),
        optional("fallbackNetworkType", "TEXT"),
        optional("fallbackDelay", "TEXT"),
        optional("uuid", "TEXT"),
        required("alterId", "INTEGER", "0"),
        optional("globalPadding", "INTEGER"),
        optional("authenticatedLength", "INTEGER"),
        optional("password", "TEXT"),
        optional("method", "TEXT"),
        optional("flow", "TEXT"),
        optional("security", "TEXT"),
        optional("network", "TEXT"),
        optional("transportType", "TEXT"),
        required("tls", "INTEGER", "0"),
        optional("sni", "TEXT"),
        optional("transportHost", "TEXT"),
        optional("transportPath", "TEXT"),
        optional("transportMethod", "TEXT"),
        optional("transportHeaders", "TEXT", "httpHeaders"),
        optional("transportIdleTimeout", "TEXT"),
        optional("transportPingTimeout", "TEXT"),
        optional("grpcPermitWithoutStream", "INTEGER", "transportPermitWithoutStream"),
        optional("transportServiceName", "TEXT"),
        optional("wsMaxEarlyData", "INTEGER"),
        optional("wsEarlyDataHeaderName", "TEXT"),
        optional("alpn", "TEXT"),
        optional("tlsDisableSni", "INTEGER"),
        optional("tlsMinVersion", "TEXT"),
        optional("tlsMaxVersion", "TEXT"),
        optional("tlsCipherSuites", "TEXT"),
        optional("tlsCurvePreferences", "TEXT"),
        optional("tlsCertificatePublicKeySha256", "TEXT"),
        optional("tlsClientCertificate", "TEXT"),
        optional("tlsClientCertificatePath", "TEXT"),
        optional("tlsClientKey", "TEXT"),
        optional("tlsClientKeyPath", "TEXT"),
        optional("tlsFragment", "INTEGER"),
        optional("tlsFragmentFallbackDelay", "TEXT"),
        optional("tlsRecordFragment", "INTEGER"),
        optional("tlsKernelTx", "INTEGER"),
        optional("tlsKernelRx", "INTEGER"),
        optional("fingerprint", "TEXT"),
        optional("publicKey", "TEXT"),
        optional("shortId", "TEXT"),
        optional("packetEncoding", "TEXT"),
        required("subscriptionId", "INTEGER", "0"),
        required("latency", "INTEGER", "-1"),
        required("createdAt", "INTEGER", "0"),
        optional("username", "TEXT"),
        optional("socksVersion", "TEXT"),
        required("allowInsecure", "INTEGER", "0"),
        optional("plugin", "TEXT"),
        optional("pluginOpts", "TEXT"),
        optional("udpOverTcpEnabled", "INTEGER"),
        optional("udpOverTcpVersion", "INTEGER"),
        optional("obfsType", "TEXT"),
        optional("obfsPassword", "TEXT"),
        optional("serverPorts", "TEXT"),
        optional("hopInterval", "TEXT"),
        optional("upMbps", "INTEGER"),
        optional("downMbps", "INTEGER"),
        optional("brutalDebug", "INTEGER"),
        optional("muxEnabled", "INTEGER"),
        optional("muxProtocol", "TEXT"),
        optional("muxMaxConnections", "INTEGER"),
        optional("muxMinStreams", "INTEGER"),
        optional("muxMaxStreams", "INTEGER"),
        optional("muxPadding", "INTEGER"),
        optional("muxBrutalEnabled", "INTEGER"),
        optional("muxBrutalUpMbps", "INTEGER"),
        optional("muxBrutalDownMbps", "INTEGER"),
        optional("congestionControl", "TEXT"),
        optional("udpRelayMode", "TEXT"),
        optional("udpOverStream", "INTEGER"),
        optional("zeroRttHandshake", "INTEGER"),
        optional("heartbeat", "TEXT"),
        optional("naiveProtocol", "TEXT"),
        optional("naiveExtraHeaders", "TEXT"),
        optional("naiveInsecureConcurrency", "INTEGER"),
        optional("naiveStreamReceiveWindow", "TEXT"),
        optional("naiveQuicSessionReceiveWindow", "TEXT"),
        optional("tlsCertificate", "TEXT", "naiveCertificate"),
        optional("tlsCertificatePath", "TEXT", "naiveCertificatePath"),
        optional("echEnabled", "INTEGER", "naiveEchEnabled"),
        optional("echConfig", "TEXT", "naiveEchConfig"),
        optional("echConfigPath", "TEXT", "naiveEchConfigPath"),
        optional("echQueryServerName", "TEXT", "naiveEchQueryServerName"),
        optional("disableTcpKeepAlive", "INTEGER"),
        optional("tcpKeepAlive", "TEXT"),
        optional("tcpKeepAliveInterval", "TEXT")
    )
}
