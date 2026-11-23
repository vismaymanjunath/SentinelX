package com.sentinelx.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Optional "Live demo mode": a visible foreground service (data sync) that syncs every few seconds, so the dashboard shows
 * near-real-time data. Android requires the persistent notification. Default monitoring remains the 15-minute WorkManager job.
 * A network-available callback triggers an immediate sync, i.e. automatic reconnection.
 */
class LiveService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    private val kick = Channel<Unit>(Channel.CONFLATED)
    private var cb: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Prefs.init(this)
        startForegroundCompat()
        Prefs.liveMode = true
        Prefs.intervalS = Prefs.LIVE_INTERVAL_S
        if (job == null) {
            registerNetworkCallback()
            job = scope.launch {
                while (isActive) {
                    Sync.runOnce(applicationContext)
                    (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, notification())
                    withTimeoutOrNull((Prefs.LIVE_INTERVAL_S * 1000).toLong()) { kick.receive() }
                }
            }
        }
        return START_STICKY
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val c = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { kick.trySend(Unit) }   // reconnect -> flush the outbox now
        }
        cm.registerDefaultNetworkCallback(c)
        cb = c
    }

    private fun notification(): Notification {
        val ch = "sentinelx_live"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(ch, "Live monitoring", NotificationManager.IMPORTANCE_LOW))
        val state = when (Prefs.state) { "connected" -> "connected"; "auth_error" -> "needs reconnect"; "retrying" -> "retrying"; else -> "starting" }
        return NotificationCompat.Builder(this, ch)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("SentinelX Mobile - live monitoring")
            .setContentText("Syncing every ${Prefs.LIVE_INTERVAL_S.toInt()} s - $state")
            .setOngoing(true)
            .build()
    }

    private fun startForegroundCompat() {
        val n = notification()
        if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) else startForeground(NOTIF_ID, n)
    }

    override fun onDestroy() {
        job?.cancel()
        scope.cancel()
        cb?.let { (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it) }
        Prefs.liveMode = false
        Prefs.intervalS = Prefs.PERIODIC_INTERVAL_S
        if (Prefs.enrolled) Scheduler.syncNow(this)   // tell the server immediately that the sync interval is back to 15 min
        super.onDestroy()
    }

    companion object { const val NOTIF_ID = 4242 }
}
