package com.aerobox.data.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.aerobox.data.model.Subscription
import kotlinx.coroutines.flow.Flow

@Dao
interface SubscriptionDao {
    @Query("SELECT * FROM subscriptions ORDER BY createdAt DESC")
    fun getAllSubscriptions(): Flow<List<Subscription>>

    @Query("SELECT * FROM subscriptions WHERE url = '' ORDER BY createdAt DESC")
    fun getLocalGroups(): Flow<List<Subscription>>

    @Query("SELECT * FROM subscriptions WHERE id = :id LIMIT 1")
    suspend fun getById(id: Long): Subscription?

    @Query("SELECT * FROM subscriptions WHERE id = :id LIMIT 1")
    fun observeById(id: Long): Flow<Subscription?>

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(subscription: Subscription): Long

    @Update
    suspend fun update(subscription: Subscription)

    @Query("UPDATE subscriptions SET nodeCount = :nodeCount WHERE id = :id")
    suspend fun updateNodeCount(id: Long, nodeCount: Int)

    @Query(
        """
        UPDATE subscriptions SET
            url = :url,
            updateTime = :updateTime,
            nodeCount = :nodeCount,
            trafficBytes = :trafficBytes,
            expireTimestamp = :expireTimestamp,
            updateInterval = :updateInterval
        WHERE id = :id
        """
    )
    suspend fun updateRefreshState(
        id: Long,
        url: String,
        updateTime: Long,
        nodeCount: Int,
        trafficBytes: Long,
        expireTimestamp: Long,
        updateInterval: Long
    ): Int

    @Query(
        """
        UPDATE subscriptions SET
            name = :name,
            url = :url,
            autoUpdate = :autoUpdate,
            updateInterval = :updateInterval
        WHERE id = :id
        """
    )
    suspend fun updateDetails(
        id: Long,
        name: String,
        url: String,
        autoUpdate: Boolean,
        updateInterval: Long
    ): Int

    @Query("UPDATE subscriptions SET name = :name WHERE id = :id")
    suspend fun updateName(id: Long, name: String): Int

    @Query("UPDATE subscriptions SET createdAt = :createdAt WHERE id = :id")
    suspend fun updateCreatedAt(id: Long, createdAt: Long): Int

    @Query("DELETE FROM subscriptions WHERE id = :id")
    suspend fun deleteById(id: Long)
}
