package com.aerobox.data.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.aerobox.data.model.ProxyNode
import kotlinx.coroutines.flow.Flow

@Dao
interface ProxyNodeDao {
    @Query("SELECT * FROM proxy_nodes ORDER BY subscriptionId ASC, createdAt ASC, id ASC")
    fun getAllNodes(): Flow<List<ProxyNode>>

    @Query("SELECT * FROM proxy_nodes WHERE subscriptionId = :subscriptionId ORDER BY createdAt ASC, id ASC")
    suspend fun getNodesBySubscription(subscriptionId: Long): List<ProxyNode>

    @Query("SELECT * FROM proxy_nodes WHERE subscriptionId = :subscriptionId ORDER BY createdAt ASC, id ASC")
    fun observeNodesBySubscription(subscriptionId: Long): Flow<List<ProxyNode>>

    @Query("SELECT * FROM proxy_nodes WHERE id = :id LIMIT 1")
    suspend fun getNodeById(id: Long): ProxyNode?

    @Query("SELECT * FROM proxy_nodes ORDER BY subscriptionId ASC, createdAt ASC, id ASC LIMIT 1")
    suspend fun getFirstNode(): ProxyNode?

    @Query("SELECT COUNT(*) FROM proxy_nodes WHERE subscriptionId = :subscriptionId")
    suspend fun countBySubscription(subscriptionId: Long): Int

    @Query("SELECT COUNT(*) FROM proxy_nodes WHERE subscriptionId = 0")
    fun observeUngroupedNodeCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertAll(nodes: List<ProxyNode>)

    @Query("UPDATE proxy_nodes SET latency = :latency WHERE id = :id")
    suspend fun updateLatency(id: Long, latency: Int)

    @Query("UPDATE proxy_nodes SET subscriptionId = :targetSubscriptionId WHERE id IN (:ids)")
    suspend fun moveNodesToSubscription(ids: List<Long>, targetSubscriptionId: Long)

    @Query("UPDATE proxy_nodes SET subscriptionId = :targetSubscriptionId WHERE subscriptionId = :fromSubscriptionId")
    suspend fun reassignBySubscription(fromSubscriptionId: Long, targetSubscriptionId: Long)

    @Query("DELETE FROM proxy_nodes WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM proxy_nodes WHERE subscriptionId = :subscriptionId")
    suspend fun deleteBySubscription(subscriptionId: Long)
}
