package com.aerobox.data.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query

/** Committed in the same Room transaction as the imported rows. Never included in backups. */
@Entity(tableName = "pending_restore")
data class PendingRestore(
    @PrimaryKey val id: Int = 1,
    val token: String,
    val settings: String,
    val selectedNodeId: Long
)

@Dao
interface PendingRestoreDao {
    @Query("SELECT * FROM pending_restore WHERE id = 1")
    suspend fun read(): PendingRestore?

    @Insert
    suspend fun insert(pending: PendingRestore)

    @Query("DELETE FROM pending_restore WHERE token = :token")
    suspend fun clear(token: String)
}
