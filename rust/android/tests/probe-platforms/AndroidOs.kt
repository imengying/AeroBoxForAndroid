package android.os

import java.io.FileDescriptor

class ParcelFileDescriptor : AutoCloseable {
    val fileDescriptor = FileDescriptor()
    override fun close() {}
    companion object { fun fromFd(fd: Int) = ParcelFileDescriptor() }
}
