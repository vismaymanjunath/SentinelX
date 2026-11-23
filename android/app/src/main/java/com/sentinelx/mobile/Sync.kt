package com.sentinelx.mobile

import android.content.Context
import org.json.JSONObject
import java.util.UUID

enum class Outcome { OK, RETRY, AUTH_ERROR, NOT_ENROLLED }

/**
 * One sync cycle, used by both WorkManager (periodic) and the live foreground service:
 *   1. read the device (real values) and enqueue a payload in the durable outbox
 *   2. deliver the outbox oldest-first (HTTPS + Bearer key); keep anything not acknowledged for the next cycle
 *   3. send the heartbeat (device descriptor, buffer depth, sync interval) - this is what keeps the device "online" in Collector Fleet
 */
object Sync {
    private const val MAX_PER_RUN = 200

    @Synchronized fun runOnce(ctx: Context): Outcome {
        Prefs.init(ctx)
        val key = Prefs.apiKey
        if (!Prefs.enrolled || key == null) return Outcome.NOT_ENROLLED
        val base = Prefs.serverUrl
        val cid = Prefs.collectorId
        val slug = Prefs.slug
        val box = Outbox.get(ctx)
        val dev = Metrics.deviceInfo()
        val now = System.currentTimeMillis()

        // 1. collect + enqueue (even when offline: this is the local buffer)
        val snap = Metrics.collect(ctx, now)
        val events = Payload.events(slug, snap, dev.timeZoneId)
        if (events.isNotEmpty()) {
            val pid = UUID.randomUUID().toString()
            val seq = Prefs.nextSeq()
            box.enqueue(seq, pid, Payload.payload(cid, seq, pid, now, events).toString(), now)
        }
        Prefs.lastSnapshot = JSONObject()
            .put("mem", snap.memUsedPct ?: JSONObject.NULL).put("disk", snap.diskUsedPct ?: JSONObject.NULL)
            .put("bat", snap.batteryPct ?: JSONObject.NULL).put("chg", snap.charging ?: JSONObject.NULL)
            .put("bw", snap.bandwidthMbps ?: JSONObject.NULL).put("rtt", snap.latencyMs ?: JSONObject.NULL).toString()

        // 2. drain the outbox
        var outcome = Outcome.OK
        var sent = 0
        while (sent < MAX_PER_RUN) {
            val row = box.oldest() ?: break
            val r = try {
                Api.post(base, "/api/ingest/v1/payload", key, row.body)
            } catch (e: NetworkError) {
                fail("retrying", "Network: ${e.message}")
                return Outcome.RETRY
            }
            when {
                r.code == 200 -> { box.delete(row.seq); markOk(); sent++ }                       // accepted or duplicate: both are final
                r.code == 401 || r.code == 403 -> { fail("auth_error", "Server rejected this device's credentials - reconnect."); return Outcome.AUTH_ERROR }
                r.code == 400 || r.code == 422 -> { box.delete(row.seq); Prefs.lastError = "Server rejected a payload (HTTP ${r.code}); dropped it."; sent++ }
                else -> { fail("retrying", "Server not ready (HTTP ${r.code}); will retry."); outcome = Outcome.RETRY; break }
            }
        }

        // 3. heartbeat
        val hb = Payload.heartbeat(cid, slug, Prefs.deviceName, dev, box.count(), box.oldestAgeS(now), if (outcome == Outcome.OK) "connected" else "buffering",
            Prefs.lastSeq, Prefs.intervalS, now, Prefs.APP_VERSION)
        val t0 = System.nanoTime()
        try {
            val r = Api.post(base, "/api/ingest/v1/heartbeat", key, hb.toString())
            val rtt = (System.nanoTime() - t0) / 1e6
            when {
                r.code == 200 -> { Prefs.lastRttMs = rtt; markOk() }
                r.code == 401 || r.code == 403 -> { fail("auth_error", "Server rejected this device's credentials - reconnect."); return Outcome.AUTH_ERROR }
                else -> { fail("retrying", "Heartbeat failed (HTTP ${r.code})"); outcome = Outcome.RETRY }
            }
        } catch (e: NetworkError) {
            fail("retrying", "Network: ${e.message}")
            outcome = Outcome.RETRY
        }
        if (outcome == Outcome.OK) { Prefs.state = "connected"; Prefs.lastError = "" }
        return outcome
    }

    private fun markOk() { Prefs.lastSyncMs = System.currentTimeMillis() }

    private fun fail(state: String, msg: String) { Prefs.state = state; Prefs.lastError = msg }
}
