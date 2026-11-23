package com.sentinelx.mobile

import android.content.Context
import android.content.SharedPreferences
import java.util.UUID

/** Small persisted state. The join code is never stored; the API key is stored encrypted (see Secrets). */
object Prefs {
    const val APP_VERSION = "1.0.0"
    const val LIVE_INTERVAL_S = 5.0
    const val PERIODIC_INTERVAL_S = 900.0   // WorkManager's minimum periodic interval is 15 minutes

    private lateinit var sp: SharedPreferences

    fun init(ctx: Context) {
        if (!::sp.isInitialized) sp = ctx.applicationContext.getSharedPreferences("sentinelx", Context.MODE_PRIVATE)
    }

    private fun s(k: String, d: String = "") = sp.getString(k, d) ?: d
    private fun put(k: String, v: String) = sp.edit().putString(k, v).apply()

    var serverUrl: String get() = s("url"); set(v) = put("url", v)
    var deviceName: String get() = s("name"); set(v) = put("name", v)
    var collectorId: String get() = s("cid"); set(v) = put("cid", v)
    var slug: String get() = s("slug"); set(v) = put("slug", v)
    var lastError: String get() = s("err"); set(v) = put("err", v)
    /** connected | retrying | auth_error | idle */
    var state: String get() = s("state", "idle"); set(v) = put("state", v)
    var lastSyncMs: Long get() = sp.getLong("lastSync", 0); set(v) = sp.edit().putLong("lastSync", v).apply()
    var lastRttMs: Double get() = sp.getFloat("rtt", -1f).toDouble(); set(v) = sp.edit().putFloat("rtt", v.toFloat()).apply()
    var liveMode: Boolean get() = sp.getBoolean("live", false); set(v) = sp.edit().putBoolean("live", v).apply()
    var intervalS: Double get() = sp.getFloat("interval", PERIODIC_INTERVAL_S.toFloat()).toDouble(); set(v) = sp.edit().putFloat("interval", v.toFloat()).apply()
    var lastSnapshot: String get() = s("snap", "{}"); set(v) = put("snap", v)

    var apiKey: String?
        get() = s("key").takeIf { it.isNotEmpty() }?.let { Secrets.decrypt(it) }
        set(v) = put("key", if (v == null) "" else Secrets.encrypt(v))

    val enrolled: Boolean get() = collectorId.isNotEmpty() && serverUrl.isNotEmpty() && apiKey != null

    /** Stable random id of this installation (lets the server tell "same phone reconnecting" from "name taken"). */
    val installId: String
        get() = s("install").ifEmpty { UUID.randomUUID().toString().also { put("install", it) } }

    /** Monotonic payload sequence, committed synchronously so a crash can never reuse a number. */
    @Synchronized fun nextSeq(): Long {
        val n = sp.getLong("seq", 0) + 1
        sp.edit().putLong("seq", n).commit()
        return n
    }
    val lastSeq: Long get() = sp.getLong("seq", 0)
    fun resetSeq() { sp.edit().putLong("seq", 0).commit() }

    var lastNetBytes: Long get() = sp.getLong("netB", -1); private set(v) { sp.edit().putLong("netB", v).apply() }
    var lastNetMs: Long get() = sp.getLong("netT", 0); private set(v) { sp.edit().putLong("netT", v).apply() }
    fun setLastNet(bytes: Long, ms: Long) { lastNetBytes = bytes; lastNetMs = ms }

    fun clearEnrollment() {
        sp.edit().remove("key").remove("cid").remove("slug").remove("err").putString("state", "idle").putBoolean("live", false)
            .putLong("lastSync", 0).putLong("netB", -1).commit()
    }
}
