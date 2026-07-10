package com.aerobox.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
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
    val chooseGroupText = stringResource(R.string.import_choose_group)
    val ungroupedText = stringResource(R.string.group_ungrouped)
    val newGroupText = stringResource(R.string.group_new)
    val newGroupNameHint = stringResource(R.string.group_new_name_hint)

    val displayText = when (val opt = holder.state.option) {
        is GroupPickerOption.Ungrouped -> ungroupedText
        is GroupPickerOption.Existing -> opt.subscription.name
        is GroupPickerOption.New -> newGroupText
    }

    var expanded by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = chooseGroupText,
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
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                DropdownMenuItem(
                    text = { Text(ungroupedText) },
                    onClick = {
                        holder.onOptionChange(GroupPickerOption.Ungrouped)
                        expanded = false
                    }
                )
                localGroups.forEach { group ->
                    DropdownMenuItem(
                        text = {
                            val suffix = pluralStringResource(
                                R.plurals.group_node_count_suffix,
                                group.nodeCount,
                                group.nodeCount
                            )
                            Text(
                                text = "${group.name}（$suffix）",
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
                DropdownMenuItem(
                    text = {
                        Text(
                            text = newGroupText,
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
                label = { Text(newGroupNameHint) },
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
    val importNodeCountText = pluralStringResource(
        R.plurals.import_node_count,
        nodeCount,
        nodeCount
    )
    val confirmText = stringResource(R.string.confirm)
    val cancelText = stringResource(R.string.cancel)
    val defaultLocalGroupName = stringResource(R.string.local_group_label)
    val holder = rememberGroupPickerState(
        suggestedName = suggestedName,
        localGroups = localGroups
    )

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            modifier = Modifier.width(320.dp),
            shape = RoundedCornerShape(24.dp),
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 6.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = importNodeCountText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                GroupPickerSection(
                    holder = holder,
                    localGroups = localGroups
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(cancelText)
                    }
                    Spacer(Modifier.width(4.dp))
                    TextButton(
                        onClick = {
                            onConfirm(
                                holder.state.toTarget(
                                    fallbackName = suggestedName,
                                    defaultName = defaultLocalGroupName
                                )
                            )
                        }
                    ) {
                        Text(confirmText)
                    }
                }
            }
        }
    }
}
