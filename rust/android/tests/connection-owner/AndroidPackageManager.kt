package android.content.pm

import java.util.concurrent.CopyOnWriteArrayList

open class PackageManager {
    val queries = CopyOnWriteArrayList<Int>()
    var lookup: (Int) -> Array<String?>? = { emptyArray() }
    open fun getPackagesForUid(uid: Int): Array<String?>? {
        queries.add(uid)
        return lookup(uid)
    }
}
