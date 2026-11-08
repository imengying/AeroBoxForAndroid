package com.aerobox.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import com.aerobox.ui.icons.AppIcons
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import com.aerobox.R

/**
 * SFA-style connection card with a large circular tap-to-connect button.
 */
@Composable
fun ConnectionCard(
    state: com.aerobox.data.model.VpnState,
    connectionDuration: String,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier,
    buttonSize: Dp = 160.dp
) {
    val isConnected = state.isConnected
    val isConnecting = state.phase == com.aerobox.data.model.VpnPhase.STARTING
    val isStopping = state.phase == com.aerobox.data.model.VpnPhase.STOPPING ||
        (state.phase == com.aerobox.data.model.VpnPhase.FAILED && state.serviceActive)
    val isActive = isConnected || isConnecting

    // Pulse animation only when connected / connecting to save CPU
    val pulseScale = if (isActive) {
        val infiniteTransition = rememberInfiniteTransition(label = "pulse")
        val scale by infiniteTransition.animateFloat(
            initialValue = 1f,
            targetValue = if (isConnected) 1.06f else 1.03f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1500),
                repeatMode = RepeatMode.Reverse
            ),
            label = "pulse_scale"
        )
        scale
    } else {
        1f
    }

    val buttonColor by animateColorAsState(
        targetValue = when {
            isConnected -> MaterialTheme.colorScheme.primaryContainer
            isConnecting -> MaterialTheme.colorScheme.secondaryContainer
            else -> MaterialTheme.colorScheme.surface
        },
        label = "button_color"
    )

    val iconTint by animateColorAsState(
        targetValue = when {
            isConnected -> MaterialTheme.colorScheme.primary
            isConnecting -> MaterialTheme.colorScheme.secondary
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        },
        label = "icon_tint"
    )

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // ── Large circular connect button ──
        Box(
            modifier = Modifier.size(buttonSize + 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size(buttonSize)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(buttonColor)
                    .border(
                        width = 2.dp,
                        color = MaterialTheme.colorScheme.primary.copy(alpha = if (isActive) 0.5f else 0.2f),
                        shape = CircleShape
                    )
                    .clickable(enabled = !isStopping, onClick = onToggleConnection),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = AppIcons.Flight,
                    contentDescription = when {
                        isStopping -> stringResource(R.string.tile_status_stopping)
                        isActive -> stringResource(R.string.disconnect)
                        else -> stringResource(R.string.connect)
                    },
                    tint = iconTint,
                    modifier = Modifier.size(buttonSize * 0.45f)
                )
            }
        }

        Spacer(Modifier.size(16.dp))

        // ── Status text ──
        Text(
            text = when {
                isStopping -> stringResource(R.string.tile_status_stopping)
                isConnected -> stringResource(R.string.connected)
                isConnecting -> stringResource(R.string.connecting)
                else -> stringResource(R.string.disconnected)
            },
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = when {
                isConnected -> MaterialTheme.colorScheme.primary
                isConnecting -> MaterialTheme.colorScheme.secondary
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            }
        )

        Text(
            text = when {
                isConnected -> connectionDuration
                isConnecting -> stringResource(R.string.notification_connecting)
                else -> " "
            },
            style = MaterialTheme.typography.bodyMedium,
            color = if (isActive) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0f)
            },
            modifier = Modifier
                .padding(top = 2.dp)
                .heightIn(min = 20.dp)
        )

    }
}
