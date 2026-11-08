package com.aerobox.data.repository

import android.content.Context
import android.net.Uri
import java.io.InputStream

internal object DocumentIo {
    fun <T> read(context: Context, uri: Uri, read: (InputStream) -> T): T =
        requireNotNull(context.contentResolver.openInputStream(uri)).use(read)

    fun write(context: Context, uri: Uri, content: ByteArray) {
        requireNotNull(context.contentResolver.openOutputStream(uri, "wt")).use { it.write(content) }
    }

    fun write(context: Context, uri: Uri, content: String) {
        requireNotNull(context.contentResolver.openOutputStream(uri, "wt"))
            .bufferedWriter(Charsets.UTF_8).use { it.write(content) }
    }
}
