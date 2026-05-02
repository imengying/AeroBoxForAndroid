package com.aerobox.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aerobox.R
import com.aerobox.data.model.Subscription
import com.aerobox.data.repository.ImportGroupTarget

// Option shown in the group picker. Subscription-backed groups are never
// offered — those are refreshed from their remote URL, which would drop any
// manually-imported nodes we place into them.
sealed class GroupPickerOption {
    data object Ungrouped : GroupPickerOption()
    data class Existing(val subscription: Subscription) : GroupPickerOption()
    data object New : GroupPickerOption()
}

data class GroupPickerState(
    val option: GroupPickerOption,
    val newGroupName: String
) {
    /**
     * @param fallbackName preferred fallback when [newGroupName] is blank
     *   (typically a suggested name derived from filename / subscription).
     * @param defaultName  ultimate fallback when both are blank — caller is
     *   expected to pass a localized string (e.g. R.string.local_group_label).
     */
    fun toTarget(fallbackName: String, defaultName: String): ImportGroupTarget {
        return when (val opt = option) {
            is GroupPickerOption.Ungrouped -> ImportGroupTarget.Ungrouped
            is GroupPickerOption.Existing -> ImportGroupTarget.Existing(opt.subscription.id)
            is GroupPickerOption.New -> {
                val name = newGroupName.trim()
                    .ifBlank { fallbackName.trim() }
                    .ifBlank { defaultName }
                ImportGroupTarget.New(name)
            }
        }
    }

    val isValid: Boolean
        get() = when (option) {
            is GroupPickerOption.New -> newGroupName.isNotBlank()
            else -> true
        }
}

@Composable
fun rememberGroupPickerState(
    suggestedName: String,
    localGroups: List<Subscription>,
    initialOption: GroupPickerOption? = null
): GroupPickerStateHolder {
    val defaultOption = remember(initialOption, suggestedName, localGroups) {
        initialOption ?: if (suggestedName.isNotBlank()) GroupPickerOption.New else GroupPickerOption.Ungrouped
    }
    var option by remember { mutableStateOf<GroupPickerOption>(defaultOption) }
    var newName by remember(suggestedName) { mutableStateOf(suggestedName) }
    return GroupPickerStateHolder(
        state = GroupPickerState(option, newName),
        onOptionChange = { option = it },
        onNewNameChange = { newName = it }
    )
}

data class GroupPickerStateHolder(
    val state: GroupPickerState,
    val onOptionChange: (GroupPickerOption) -> Unit,
    val onNewNameChange: (String) -> Unit
)

// Reusable section that lets the user pick where imported nodes should land.
// Used both by the standalone [GroupPickerDialog] (shown after local-file /
// QR / external import) and inline inside [NodeImportDialog].
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupPickerSection(
    holder: GroupPickerStateHolder,
    localGroups: List<Subscription>,
    modifier: Modifier = Modifier
) {
    val ungroupedLabel = stringResource(R.string.group_ungrouped)
    val newGroupLabel = stringResource(R.string.group_new)

    val displayText = when (val opt = holder.state.option) {
        is GroupPickerOption.Ungrouped -> ungroupedLabel
        is GroupPickerOption.Existing -> opt.subscription.name
        is GroupPickerOption.New -> newGroupLabel
    }

    var expanded by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = stringResource(R.string.import_choose_group),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(8.dp))

        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it }
        ) {
            OutlinedTextField(
                value = displayText,
                onValueChange = {},
                readOnly = true,
                singleLine = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                // "未分组"
                DropdownMenuItem(
                    text = { Text(ungroupedLabel) },
                    onClick = {
                        holder.onOptionChange(GroupPickerOption.Ungrouped)
                        expanded = false
                    }
                )
                // Existing local groups
                localGroups.forEach { group ->
                    DropdownMenuItem(
                        text = {
                            Text(
                                text = "${group.name}（${stringResource(R.string.group_node_count_suffix, group.nodeCount)}）",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        },
                        onClick = {
                            holder.onOptionChange(GroupPickerOption.Existing(group))
                            expanded = false
                        }
                    )
                }
                // "新建分组"
                DropdownMenuItem(
                    text = {
                        Text(
                            text = newGroupLabel,
                            color = MaterialTheme.colorScheme.primary
                        )
                    },
                    onClick = {
                        holder.onOptionChange(GroupPickerOption.New)
                        expanded = false
                    }
                )
            }
        }

        if (holder.state.option is GroupPickerOption.New) {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = holder.state.newGroupName,
                onValueChange = holder.onNewNameChange,
                label = { Text(stringResource(R.string.group_new_name_hint)) },
                singleLine = true,
                isError = holder.state.newGroupName.isBlank(),
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
fun GroupPickerDialog(
    nodeCount: Int,
    suggestedName: String,
    localGroups: List<Subscription>,
    onConfirm: (ImportGroupTarget) -> Unit,
    onDismiss: () -> Unit
) {
    val holder = rememberGroupPickerState(
        suggestedName = suggestedName,
        localGroups = localGroups
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.import_choose_group)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.import_node_count, nodeCount),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(12.dp))
                GroupPickerSection(
                    holder = holder,
                    localGroups = localGroups
                )
            }
        },
        confirmButton = {
            val defaultLocalGroupName = stringResource(R.string.local_group_label)
            TextButton(
                onClick = {
                    onConfirm(
                        holder.state.toTarget(
                            fallbackName = suggestedName,
                            defaultName = defaultLocalGroupName
                        )
                    )
                },
                enabled = holder.state.isValid
            ) {
                Text(stringResource(R.string.confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}
