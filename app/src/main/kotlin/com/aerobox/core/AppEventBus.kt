package com.aerobox.core

import kotlinx.coroutines.flow.MutableSharedFlow

object AppEventBus {
    val showNodeSelector = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
}
