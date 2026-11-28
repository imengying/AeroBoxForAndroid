package android.system
class ErrnoException(val errno: Int) : Exception()
object OsConstants { const val EIO = 5; const val ECANCELED = 125 }
