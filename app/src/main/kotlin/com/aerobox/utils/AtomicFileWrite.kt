package com.aerobox.utils

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** The caller serializes writes and flushes any buffered wrapper before returning. */
internal fun File.writeAtomically(write: (FileOutputStream) -> Unit) {
    val directory = requireNotNull(parentFile)
    check(directory.isDirectory || directory.mkdirs()) { "Cannot create storage directory" }
    val temporary = File(directory, "$name.tmp")
    try {
        FileOutputStream(temporary).use { stream ->
            write(stream)
            stream.fd.sync()
        }
        Files.move(temporary.toPath(), toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } finally {
        temporary.delete()
    }
}
