package com.aerobox.viewmodel

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Shared version-1 format for selection snapshots and pending export requests. */
internal object NodeIdFile {
    private const val MAX_IDS = 1_000_000
    private const val FORMAT_VERSION = 1
    private const val MAX_AGE_MILLIS = 7 * 24 * 60 * 60 * 1000L
    private val TOKEN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    fun isValidToken(value: String): Boolean = TOKEN.matches(value)

    fun validate(ids: Collection<Long>, allowEmpty: Boolean = true) {
        require(ids.size in (if (allowEmpty) 0 else 1)..MAX_IDS && ids.all { it > 0 })
    }

    fun read(file: File, allowEmpty: Boolean = true): List<Long> =
        DataInputStream(file.inputStream().buffered()).use { input ->
            require(input.readInt() == FORMAT_VERSION)
            val count = input.readInt()
            require(count in (if (allowEmpty) 0 else 1)..MAX_IDS && file.length() == 8L + count * 8L)
            List(count) { input.readLong().also { require(it > 0) } }
        }

    fun write(file: File, ids: Collection<Long>) {
        validate(ids)
        val directory = requireNotNull(file.parentFile)
        check(directory.isDirectory || directory.mkdirs()) { "Cannot create node ID directory" }
        val temporary = File(directory, "${file.name}.tmp")
        try {
            FileOutputStream(temporary).use { stream ->
                val output = DataOutputStream(stream.buffered())
                output.writeInt(FORMAT_VERSION)
                output.writeInt(ids.size)
                ids.forEach(output::writeLong)
                output.flush()
                stream.fd.sync()
            }
            Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            temporary.delete()
        }
    }

    fun removeExpired(directory: File, retainedToken: String?) {
        val expiry = System.currentTimeMillis() - MAX_AGE_MILLIS
        directory.listFiles().orEmpty().filter {
            val token = it.name.removeSuffix(".tmp")
            token != retainedToken && isValidToken(token) && it.lastModified() < expiry
        }.forEach { it.delete() }
    }
}
