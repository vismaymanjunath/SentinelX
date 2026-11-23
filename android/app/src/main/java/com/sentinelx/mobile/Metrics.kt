package com.sentinelx.mobile

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.TrafficStats
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import java.security.MessageDigest
import java.util.TimeZone

/**
 * What Android actually lets a normal app read (no special permissions):
 *  - RAM:      ActivityManager.MemoryInfo (system-wide total/available; "available" includes reclaimable cache)
 *  - Storage:  StatFs on the user-data partition (system-wide)
 *  - Battery:  sticky ACTION_BATTERY_CHANGED (level, charging)
 *  - Network:  TrafficStats device totals (bytes since boot) -> average Mbps between two samples; may be unsupported on some devices
 *  - Latency:  round-trip of our own request to the server (real, measured by the sync)
 * NOT available: system-wide CPU usage. Since Android 8 apps cannot read /proc/stat, so cpu_percent is deliberately not reported.
 */
object Metrics {
    fun collect(ctx: Context, nowMs: Long = System.currentTimeMillis()): Snapshot {
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)
        val mem = if (mi.totalMem > 0) (mi.totalMem - mi.availMem) * 100.0 / mi.totalMem else null

        val disk = try {
            val st = StatFs(Environment.getDataDirectory().path)
            val total = st.blockCountLong * st.blockSizeLong
            val avail = st.availableBlocksLong * st.blockSizeLong
            if (total > 0) (total - avail) * 100.0 / total else null
        } catch (e: Exception) { null }

        val bi: Intent? = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        var pct: Double? = null
        var charging: Boolean? = null
        if (bi != null) {
            val level = bi.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = bi.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            if (level >= 0 && scale > 0) pct = level * 100.0 / scale
            val status = bi.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            if (status != -1) charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        }

        var mbps: Double? = null
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        if (rx != TrafficStats.UNSUPPORTED.toLong() && tx != TrafficStats.UNSUPPORTED.toLong()) {
            val total = rx + tx
            val pb = Prefs.lastNetBytes
            val pt = Prefs.lastNetMs
            if (pb >= 0 && pt > 0 && nowMs > pt && total >= pb) {   // total < pb means the counters reset (reboot): skip one sample
                mbps = (total - pb) * 8.0 / ((nowMs - pt) / 1000.0) / 1e6
            }
            Prefs.setLastNet(total, nowMs)
        }
        val rtt = Prefs.lastRttMs.takeIf { it >= 0 }
        return Snapshot(nowMs, mem, disk, pct, charging, mbps, rtt)
    }

    fun deviceInfo(): DeviceInfo {
        val maker = Build.MANUFACTURER.orEmpty().replaceFirstChar { it.uppercase() }
        val model = if (Build.MODEL.orEmpty().startsWith(maker, ignoreCase = true)) Build.MODEL else "$maker ${Build.MODEL}"
        val os = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        val install = Prefs.installId
        val h = MessageDigest.getInstance("SHA-256").digest(install.toByteArray()).joinToString("") { "%02x".format(it) }.take(8)
        return DeviceInfo(model.trim(), os, TimeZone.getDefault().id, "phone-$h")
    }
}
