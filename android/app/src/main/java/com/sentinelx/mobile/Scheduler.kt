package com.sentinelx.mobile

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Background monitoring with WorkManager.
 *  - Periodic: every 15 min (the WorkManager minimum), only while a network is connected. Android may defer it further
 *    under Doze / battery optimisation - that is a platform rule, which is why the dashboard scales its "offline" limit
 *    from the sync interval the device declares in its heartbeat.
 *  - Retry: on network/server errors the worker returns retry() -> exponential backoff, and the durable outbox keeps the data.
 */
class SyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result = when (Sync.runOnce(applicationContext)) {
        Outcome.OK, Outcome.NOT_ENROLLED -> Result.success()
        Outcome.RETRY -> Result.retry()
        Outcome.AUTH_ERROR -> Result.failure()   // retrying with a rejected key is pointless; the UI asks the user to reconnect
    }
}

object Scheduler {
    private const val PERIODIC = "sentinelx-periodic"
    private const val NOW = "sentinelx-now"
    private val online = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    fun schedulePeriodic(ctx: Context) {
        val req = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(online)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.UPDATE, req)
    }

    /** Immediate one-off sync (runs as soon as a network is available). */
    fun syncNow(ctx: Context) {
        val req = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(online)
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(ctx).enqueueUniqueWork(NOW, ExistingWorkPolicy.REPLACE, req)
    }

    fun cancelAll(ctx: Context) {
        WorkManager.getInstance(ctx).cancelUniqueWork(PERIODIC)
        WorkManager.getInstance(ctx).cancelUniqueWork(NOW)
    }
}
