package com.aerobox.data.repository

import android.content.Context
import com.aerobox.utils.PreferenceManager
import kotlinx.coroutines.flow.first

interface SelectedNodeStore {
    suspend fun read(): Long
    suspend fun write(id: Long)
    suspend fun replace(expected: Long, replacement: Long)
}

class PreferenceSelectedNodeStore(private val context: Context) : SelectedNodeStore {
    override suspend fun read() = PreferenceManager.lastSelectedNodeIdFlow(context).first()
    override suspend fun write(id: Long) { PreferenceManager.setLastSelectedNodeId(context, id) }
    override suspend fun replace(expected: Long, replacement: Long) {
        PreferenceManager.replaceSelectedNode(context, expected, replacement)
    }
}
