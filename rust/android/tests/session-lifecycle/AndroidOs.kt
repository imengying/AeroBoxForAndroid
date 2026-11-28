package android.os
class ParcelFileDescriptor(val fd: Int = 9) : AutoCloseable {
    var closed = false
    val fileDescriptor = java.io.FileDescriptor()
    override fun close() { closed = true }
    companion object { fun fromFd(fd: Int) = ParcelFileDescriptor(fd) }
}
interface ParcelCreator<T> { fun createFromParcel(parcel: Parcel): T }
class Parcel private constructor() {
    var value: Any? = null
    fun setDataPosition(position: Int) {}
    fun recycle() { value = null }
    companion object { fun obtain() = Parcel() }
}
