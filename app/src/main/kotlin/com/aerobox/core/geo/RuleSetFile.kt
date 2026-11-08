package com.aerobox.core.geo

import com.aerobox.utils.writeAtomically
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream

internal fun File.hasRuleSetHeader(): Boolean {
    if (!isFile || length() < 4L) return false
    return runCatching { inputStream().use(::readRuleSetHeader) }.isSuccess
}

/** Reject invalid input before replacing the last working rule set. The caller owns [input]. */
internal fun File.writeRuleSet(input: InputStream) {
    val header = readRuleSetHeader(input)
    writeAtomically { output ->
        output.write(header)
        input.copyTo(output)
    }
}

private fun readRuleSetHeader(input: InputStream): ByteArray {
    val header = ByteArray(4)
    DataInputStream(input).readFully(header)
    if (header[0] != 'S'.code.toByte() || header[1] != 'R'.code.toByte() || header[2] != 'S'.code.toByte()) {
        throw IOException("Invalid rule-set header")
    }
    return header
}
