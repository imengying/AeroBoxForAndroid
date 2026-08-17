package com.aerobox.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.aerobox.AeroBoxApplication
import com.aerobox.R
import com.aerobox.data.model.ProxyNode
import com.aerobox.data.model.ProxyType
import com.aerobox.data.model.supportedProxyTransports
import com.aerobox.ui.components.AppSnackbarHost
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

private val transportOptions = listOf("") + supportedProxyTransports
private val naiveProtocolOptions = listOf("https", "quic")

@Composable
fun NodeEditScreen(
    nodeId: Long,
    onNavigateBack: () -> Unit
) {
    val repository = AeroBoxApplication.subscriptionRepository
    var node by remember(nodeId) { mutableStateOf<ProxyNode?>(null) }

    LaunchedEffect(nodeId) {
        repository.observeNodeById(nodeId).collect { current ->
            if (current == null) {
                onNavigateBack()
            } else {
                node = current
            }
        }
    }

    val currentNode = node
    if (currentNode == null) {
        Scaffold(
            topBar = {
                NodeEditTopBar(
                    saveEnabled = false,
                    onSave = {},
                    onNavigateBack = onNavigateBack
                )
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        }
        return
    }

    NodeEditForm(
        node = currentNode,
        onSave = repository::updateNode,
        onNavigateBack = onNavigateBack
    )
}

@Composable
private fun NodeEditForm(
    node: ProxyNode,
    onSave: suspend (ProxyNode) -> Boolean,
    onNavigateBack: () -> Unit
) {
    var draft by remember(node.id) { mutableStateOf(node) }
    var portText by remember(node.id) { mutableStateOf(node.port.toString()) }
    var alterIdText by remember(node.id) { mutableStateOf(node.alterId.toString()) }
    var saving by remember(node.id) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val saveError = stringResource(R.string.operation_failed)
    val port = portText.toIntOrNull()
    val isValid = draft.hasRequiredFields() && port != null && port in 1..65535

    Scaffold(
        topBar = {
            NodeEditTopBar(
                saveEnabled = isValid && !saving,
                onSave = {
                    val validPort = port
                    if (validPort != null) {
                        saving = true
                        scope.launch {
                            val saved = runCatching {
                                onSave(draft.normalizedForSave(validPort, alterIdText))
                            }.getOrDefault(false)
                            saving = false
                            if (saved) {
                                onNavigateBack()
                            } else {
                                snackbarHostState.showSnackbar(saveError)
                            }
                        }
                    }
                },
                onNavigateBack = onNavigateBack
            )
        },
        snackbarHost = { AppSnackbarHost(hostState = snackbarHostState) }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { NodeEditorSection(R.string.node_edit_section_general) }
            item {
                NodeTextField(
                    value = draft.name,
                    onValueChange = { draft = draft.copy(name = it) },
                    label = R.string.node_edit_name,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.type.displayName(),
                    onValueChange = {},
                    label = R.string.node_edit_protocol,
                    readOnly = true
                )
            }
            item {
                NodeTextField(
                    value = draft.server,
                    onValueChange = { draft = draft.copy(server = it) },
                    label = R.string.node_edit_server,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = R.string.node_edit_port,
                    required = true,
                    isError = port == null || port !in 1..65535,
                    keyboardType = KeyboardType.Number
                )
            }

            item { NodeEditorSection(R.string.node_edit_section_authentication) }
            authenticationFields(
                draft = draft,
                alterIdText = alterIdText,
                onDraftChange = { draft = it },
                onAlterIdChange = { alterIdText = it }
            )

            if (draft.type.supportsTransportEditor()) {
                item { NodeEditorSection(R.string.node_edit_section_transport) }
                transportFields(draft = draft, onDraftChange = { draft = it })
            } else if (draft.type == ProxyType.HTTP) {
                item { NodeEditorSection(R.string.node_edit_section_transport) }
                httpFields(draft = draft, onDraftChange = { draft = it })
            }

            when (draft.type) {
                ProxyType.HYSTERIA2 -> {
                    item { NodeEditorSection(R.string.node_edit_section_protocol_options) }
                    hysteria2Fields(draft = draft, onDraftChange = { draft = it })
                }

                ProxyType.TUIC -> {
                    item { NodeEditorSection(R.string.node_edit_section_protocol_options) }
                    tuicFields(draft = draft, onDraftChange = { draft = it })
                }

                ProxyType.NAIVE -> {
                    item { NodeEditorSection(R.string.node_edit_section_protocol_options) }
                    naiveFields(draft = draft, onDraftChange = { draft = it })
                }

                else -> Unit
            }

            if (draft.type.supportsTlsEditor()) {
                item { NodeEditorSection(R.string.node_edit_section_tls) }
                tlsFields(draft = draft, onDraftChange = { draft = it })
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NodeEditTopBar(
    saveEnabled: Boolean,
    onSave: () -> Unit,
    onNavigateBack: () -> Unit
) {
    TopAppBar(
        title = { Text(stringResource(R.string.edit_node)) },
        navigationIcon = {
            IconButton(onClick = onNavigateBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
            }
        },
        actions = {
            TextButton(onClick = onSave, enabled = saveEnabled) {
                Text(stringResource(R.string.save))
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    )
}

private fun androidx.compose.foundation.lazy.LazyListScope.authenticationFields(
    draft: ProxyNode,
    alterIdText: String,
    onDraftChange: (ProxyNode) -> Unit,
    onAlterIdChange: (String) -> Unit
) {
    when (draft.type) {
        ProxyType.SHADOWSOCKS,
        ProxyType.SHADOWSOCKS_2022 -> {
            item {
                NodeTextField(
                    value = draft.method.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(method = it)) },
                    label = R.string.node_edit_method,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.password.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(password = it)) },
                    label = R.string.node_edit_password,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.plugin.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(plugin = it)) },
                    label = R.string.node_edit_plugin
                )
            }
            item {
                NodeTextField(
                    value = draft.pluginOpts.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(pluginOpts = it)) },
                    label = R.string.node_edit_plugin_options
                )
            }
        }

        ProxyType.VMESS -> {
            item {
                NodeTextField(
                    value = draft.uuid.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(uuid = it)) },
                    label = R.string.node_edit_uuid,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.security.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(security = it)) },
                    label = R.string.node_edit_security
                )
            }
            item {
                NodeTextField(
                    value = alterIdText,
                    onValueChange = { onAlterIdChange(it.filter(Char::isDigit).take(10)) },
                    label = R.string.node_edit_alter_id,
                    keyboardType = KeyboardType.Number
                )
            }
            item {
                NodeTextField(
                    value = draft.packetEncoding.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(packetEncoding = it)) },
                    label = R.string.node_edit_packet_encoding
                )
            }
        }

        ProxyType.VLESS -> {
            item {
                NodeTextField(
                    value = draft.uuid.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(uuid = it)) },
                    label = R.string.node_edit_uuid,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.flow.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(flow = it)) },
                    label = R.string.node_edit_flow
                )
            }
            item {
                NodeTextField(
                    value = draft.packetEncoding.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(packetEncoding = it)) },
                    label = R.string.node_edit_packet_encoding
                )
            }
        }

        ProxyType.TROJAN,
        ProxyType.ANYTLS,
        ProxyType.HYSTERIA2 -> item {
            NodeTextField(
                value = draft.password.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(password = it)) },
                label = R.string.node_edit_password,
                required = true
            )
        }

        ProxyType.TUIC -> {
            item {
                NodeTextField(
                    value = draft.uuid.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(uuid = it)) },
                    label = R.string.node_edit_uuid,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.password.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(password = it)) },
                    label = R.string.node_edit_password,
                    required = true
                )
            }
        }

        ProxyType.NAIVE -> {
            item {
                NodeTextField(
                    value = draft.username.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(username = it)) },
                    label = R.string.node_edit_username,
                    required = true
                )
            }
            item {
                NodeTextField(
                    value = draft.password.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(password = it)) },
                    label = R.string.node_edit_password,
                    required = true
                )
            }
        }

        ProxyType.SOCKS,
        ProxyType.HTTP -> {
            item {
                NodeTextField(
                    value = draft.username.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(username = it)) },
                    label = R.string.node_edit_username
                )
            }
            item {
                NodeTextField(
                    value = draft.password.orEmpty(),
                    onValueChange = { onDraftChange(draft.copy(password = it)) },
                    label = R.string.node_edit_password
                )
            }
            if (draft.type == ProxyType.SOCKS) {
                item {
                    NodeTextField(
                        value = draft.socksVersion.orEmpty(),
                        onValueChange = { onDraftChange(draft.copy(socksVersion = it)) },
                        label = R.string.node_edit_socks_version
                    )
                }
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.transportFields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    val transport = draft.transportType.orEmpty().lowercase()
    item {
        NodeDropdownField(
            value = transport,
            options = if (transport in transportOptions) transportOptions else transportOptions + transport,
            label = R.string.node_edit_transport_type,
            emptyLabel = R.string.node_edit_transport_none,
            onValueChange = { onDraftChange(draft.copy(transportType = it.ifEmpty { null })) }
        )
    }
    if (transport == "grpc") {
        item {
            NodeTextField(
                value = draft.transportServiceName.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(transportServiceName = it)) },
                label = R.string.node_edit_grpc_service
            )
        }
    } else if (transport.isNotEmpty()) {
        item {
            NodeTextField(
                value = draft.transportHost.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(transportHost = it)) },
                label = R.string.node_edit_host
            )
        }
        item {
            NodeTextField(
                value = draft.transportPath.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(transportPath = it)) },
                label = R.string.node_edit_path
            )
        }
        item {
            NodeTextField(
                value = draft.transportHeaders.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(transportHeaders = it)) },
                label = R.string.node_edit_headers,
                singleLine = false
            )
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.httpFields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    item {
        NodeTextField(
            value = draft.transportPath.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(transportPath = it)) },
            label = R.string.node_edit_path
        )
    }
    item {
        NodeTextField(
            value = draft.transportHost.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(transportHost = it)) },
            label = R.string.node_edit_host
        )
    }
    item {
        NodeTextField(
            value = draft.transportHeaders.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(transportHeaders = it)) },
            label = R.string.node_edit_headers,
            singleLine = false
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.hysteria2Fields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    item {
        NodeTextField(
            value = draft.obfsType.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(obfsType = it)) },
            label = R.string.node_edit_obfs_type
        )
    }
    item {
        NodeTextField(
            value = draft.obfsPassword.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(obfsPassword = it)) },
            label = R.string.node_edit_obfs_password
        )
    }
    item {
        NodeTextField(
            value = draft.serverPorts.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(serverPorts = it)) },
            label = R.string.node_edit_server_ports
        )
    }
    item {
        NodeTextField(
            value = draft.hopInterval.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(hopInterval = it)) },
            label = R.string.node_edit_hop_interval
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.tuicFields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    item {
        NodeTextField(
            value = draft.congestionControl.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(congestionControl = it)) },
            label = R.string.node_edit_congestion_control
        )
    }
    item {
        NodeTextField(
            value = draft.udpRelayMode.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(udpRelayMode = it)) },
            label = R.string.node_edit_udp_relay_mode
        )
    }
    item {
        NodeTextField(
            value = draft.heartbeat.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(heartbeat = it)) },
            label = R.string.node_edit_heartbeat
        )
    }
    item {
        NodeSwitchRow(
            label = R.string.node_edit_udp_over_stream,
            checked = draft.udpOverStream == true,
            onCheckedChange = { onDraftChange(draft.copy(udpOverStream = it)) }
        )
    }
    item {
        NodeSwitchRow(
            label = R.string.node_edit_zero_rtt,
            checked = draft.zeroRttHandshake == true,
            onCheckedChange = { onDraftChange(draft.copy(zeroRttHandshake = it)) }
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.naiveFields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    val protocol = draft.naiveProtocol?.lowercase()
        ?: if (draft.transportType.equals("quic", ignoreCase = true)) "quic" else "https"
    item {
        NodeDropdownField(
            value = protocol,
            options = naiveProtocolOptions,
            label = R.string.node_edit_naive_protocol,
            onValueChange = {
                onDraftChange(
                    draft.copy(
                        naiveProtocol = it,
                        transportType = if (it == "quic") "quic" else null
                    )
                )
            }
        )
    }
    if (protocol == "quic") {
        item {
            NodeTextField(
                value = draft.congestionControl.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(congestionControl = it)) },
                label = R.string.node_edit_congestion_control
            )
        }
    }
    item {
        NodeTextField(
            value = draft.naiveExtraHeaders.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(naiveExtraHeaders = it)) },
            label = R.string.node_edit_extra_headers,
            singleLine = false
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.tlsFields(
    draft: ProxyNode,
    onDraftChange: (ProxyNode) -> Unit
) {
    val forced = draft.type.forcesTls()
    val enabled = forced || draft.tls
    item {
        NodeSwitchRow(
            label = R.string.node_edit_tls_enabled,
            checked = enabled,
            enabled = !forced,
            onCheckedChange = { onDraftChange(draft.copy(tls = it)) }
        )
    }
    if (!enabled) return
    item {
        NodeTextField(
            value = draft.sni.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(sni = it)) },
            label = R.string.node_edit_sni
        )
    }
    item {
        NodeSwitchRow(
            label = R.string.node_edit_allow_insecure,
            checked = draft.allowInsecure,
            onCheckedChange = { onDraftChange(draft.copy(allowInsecure = it)) }
        )
    }
    item {
        NodeTextField(
            value = draft.alpn.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(alpn = it)) },
            label = R.string.node_edit_alpn
        )
    }
    item {
        NodeTextField(
            value = draft.fingerprint.orEmpty(),
            onValueChange = { onDraftChange(draft.copy(fingerprint = it)) },
            label = R.string.node_edit_fingerprint
        )
    }
    if (draft.type == ProxyType.VLESS || draft.type == ProxyType.TROJAN) {
        item {
            NodeTextField(
                value = draft.publicKey.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(publicKey = it)) },
                label = R.string.node_edit_reality_public_key
            )
        }
        item {
            NodeTextField(
                value = draft.shortId.orEmpty(),
                onValueChange = { onDraftChange(draft.copy(shortId = it)) },
                label = R.string.node_edit_reality_short_id
            )
        }
    }
}

@Composable
private fun NodeEditorSection(title: Int) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = stringResource(title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold
        )
        HorizontalDivider()
    }
}

@Composable
private fun NodeTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: Int,
    required: Boolean = false,
    isError: Boolean = required && value.isBlank(),
    readOnly: Boolean = false,
    singleLine: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Text
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(label)) },
        supportingText = if (isError) {
            { Text(stringResource(R.string.node_edit_required)) }
        } else {
            null
        },
        isError = isError,
        readOnly = readOnly,
        singleLine = singleLine,
        minLines = if (singleLine) 1 else 3,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = Modifier.fillMaxWidth()
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NodeDropdownField(
    value: String,
    options: List<String>,
    label: Int,
    emptyLabel: Int? = null,
    onValueChange: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val emptyText = emptyLabel?.let { stringResource(it) }.orEmpty()
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = value.ifEmpty { emptyText },
            onValueChange = {},
            label = { Text(stringResource(label)) },
            readOnly = true,
            singleLine = true,
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option.ifEmpty { emptyText }) },
                    onClick = {
                        onValueChange(option)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun NodeSwitchRow(
    label: Int,
    checked: Boolean,
    enabled: Boolean = true,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(label),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked,
            enabled = enabled,
            onCheckedChange = onCheckedChange
        )
    }
}

private fun ProxyNode.hasRequiredFields(): Boolean {
    if (name.isBlank() || server.isBlank()) return false
    return when (type) {
        ProxyType.SHADOWSOCKS,
        ProxyType.SHADOWSOCKS_2022 -> !method.isNullOrBlank() && !password.isNullOrEmpty()
        ProxyType.VMESS,
        ProxyType.VLESS -> !uuid.isNullOrBlank()
        ProxyType.TROJAN,
        ProxyType.ANYTLS,
        ProxyType.HYSTERIA2 -> !password.isNullOrEmpty()
        ProxyType.TUIC -> !uuid.isNullOrBlank() && !password.isNullOrEmpty()
        ProxyType.NAIVE -> !username.isNullOrEmpty() && !password.isNullOrEmpty()
        ProxyType.SOCKS,
        ProxyType.HTTP -> true
    }
}

private fun ProxyNode.normalizedForSave(port: Int, alterIdText: String): ProxyNode {
    return copy(
        name = name.trim(),
        server = server.trim(),
        port = port,
        uuid = uuid.trimmedOrNull(),
        alterId = alterIdText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
        password = password.emptyToNull(),
        method = method.trimmedOrNull(),
        flow = flow.trimmedOrNull(),
        security = security.trimmedOrNull(),
        transportType = transportType.trimmedOrNull(),
        sni = sni.trimmedOrNull(),
        transportHost = transportHost.emptyToNull(),
        transportPath = transportPath.emptyToNull(),
        transportHeaders = transportHeaders.emptyToNull(),
        transportServiceName = transportServiceName.emptyToNull(),
        alpn = alpn.emptyToNull(),
        fingerprint = fingerprint.trimmedOrNull(),
        publicKey = publicKey.emptyToNull(),
        shortId = shortId.emptyToNull(),
        packetEncoding = packetEncoding.trimmedOrNull(),
        username = username.emptyToNull(),
        socksVersion = socksVersion.trimmedOrNull(),
        plugin = plugin.trimmedOrNull(),
        pluginOpts = pluginOpts.emptyToNull(),
        obfsType = obfsType.trimmedOrNull(),
        obfsPassword = obfsPassword.emptyToNull(),
        serverPorts = serverPorts.trimmedOrNull(),
        hopInterval = hopInterval.trimmedOrNull(),
        congestionControl = congestionControl.trimmedOrNull(),
        udpRelayMode = udpRelayMode.trimmedOrNull(),
        heartbeat = heartbeat.trimmedOrNull(),
        naiveProtocol = naiveProtocol.trimmedOrNull(),
        naiveExtraHeaders = naiveExtraHeaders.emptyToNull(),
        tls = if (type.forcesTls()) true else tls
    )
}

private fun ProxyType.supportsTransportEditor(): Boolean {
    return this == ProxyType.VMESS || this == ProxyType.VLESS || this == ProxyType.TROJAN
}

private fun ProxyType.supportsTlsEditor(): Boolean {
    return this != ProxyType.SHADOWSOCKS &&
        this != ProxyType.SHADOWSOCKS_2022 &&
        this != ProxyType.SOCKS
}

private fun ProxyType.forcesTls(): Boolean {
    return this == ProxyType.TROJAN ||
        this == ProxyType.ANYTLS ||
        this == ProxyType.HYSTERIA2 ||
        this == ProxyType.TUIC ||
        this == ProxyType.NAIVE
}

private fun String?.trimmedOrNull(): String? = this?.trim()?.takeIf(String::isNotEmpty)

private fun String?.emptyToNull(): String? = this?.takeIf(String::isNotEmpty)
