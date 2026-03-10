package com.aerobox.data.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.aerobox.data.model.ProxyNode
import kotlinx.coroutines.flow.Flow

@Dao
interface ProxyNodeDao {
    @Query("SELECT * FROM proxy_nodes ORDER BY subscriptionId ASC, id ASC")
    fun getAllNodes(): Flow<List<ProxyNode>>

    @Query("SELECT * FROM proxy_nodes WHERE subscriptionId = :subscriptionId ORDER BY id ASC")
    suspend fun getNodesBySubscription(subscriptionId: Long): List<ProxyNode>

    @Query("SELECT * FROM proxy_nodes WHERE id = :id LIMIT 1")
    suspend fun getNodeById(id: Long): ProxyNode?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(nodes: List<ProxyNode>)

    @Query("UPDATE proxy_nodes SET latency = :latency WHERE id = :id")
    suspend fun updateLatency(id: Long, latency: Int)

    @Query("DELETE FROM proxy_nodes WHERE subscriptionId = :subscriptionId")
    suspend fun deleteBySubscription(subscriptionId: Long)
}
