package com.sentinelx.mobile

import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/** One reading of the device. A null field means "not available on this device / API" and is simply not sent. */
data class Snapshot(
    val tsMs: Long,
    val memUsedPct: Double?,
    val diskUsedPct: Double?,
    val batteryPct: Double?,
    val charging: Boolean?,
    val bandwidthMbps: Double?,
    val latencyMs: Double?,
)

data class DeviceInfo(val model: String, val osVersion: String, val timeZoneId: String, val hostPseudonym: String)

/**
 * Builds the exact wire format the SENTINEL X ingestion API accepts (common/schema.py allow-list):
 * metric events with only {event_id,type,source_id,category,severity,metric,value,unit,event_time,source_tz,context{origin}}.
 * Pure JVM (no Android classes) so it is unit-tested off-device and contract-tested against the Python schema.
 */
object Payload {
    const val SCHEMA_VERSION = "1.0"

    fun hostId(slug: String) = "host:$slug"
    fun netId(slug: String) = "net:$slug-link"

    fun isoUtc(ms: Long): String {
        val f = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return f.format(Date(ms))
    }

    private fun metric(
        slug: String, source: String, category: String, name: String, value: Double, unit: String,
        s: Snapshot, tz: String, newId: () -> String,
    ): JSONObject = JSONObject()
        .put("event_id", newId())
        .put("type", "metric")
        .put("source_id", source)
        .put("category", category)
        .put("severity", "info")
        .put("metric", name)
        .put("value", Math.round(value * 1000.0) / 1000.0)
        .put("unit", unit)
        .put("event_time", isoUtc(s.tsMs))
        .put("source_tz", tz)
        .put("context", JSONObject().put("origin", "real"))

    fun events(slug: String, s: Snapshot, tz: String, newId: () -> String = { UUID.randomUUID().toString() }): List<JSONObject> {
        val out = ArrayList<JSONObject>()
        fun add(src: String, cat: String, name: String, v: Double?, unit: String) {
            if (v != null && v.isFinite()) out.add(metric(slug, src, cat, name, v, unit, s, tz, newId))
        }
        val h = hostId(slug)
        val n = netId(slug)
        add(h, "infrastructure", "memory_percent", s.memUsedPct, "percent")
        add(h, "infrastructure", "disk_percent", s.diskUsedPct, "percent")
        add(h, "infrastructure", "battery_percent", s.batteryPct, "percent")
        add(h, "infrastructure", "battery_charging", s.charging?.let { if (it) 1.0 else 0.0 }, "bool")
        add(n, "network", "bandwidth_mbps", s.bandwidthMbps, "mbps")
        add(n, "network", "latency_ms", s.latencyMs, "ms")
        return out
    }

    fun payload(collectorId: String, seq: Long, payloadId: String, nowMs: Long, events: List<JSONObject>): JSONObject =
        JSONObject()
            .put("payload_id", payloadId)
            .put("collector_id", collectorId)
            .put("seq", seq)
            .put("sent_at", isoUtc(nowMs))
            .put("schema_version", SCHEMA_VERSION)
            .put("events", JSONArray(events))

    fun heartbeat(
        collectorId: String, slug: String, deviceName: String, dev: DeviceInfo, bufferDepth: Int, oldestPendingS: Double,
        linkState: String, lastSeq: Long, intervalS: Double, nowMs: Long, appVersion: String,
    ): JSONObject {
        val topology = JSONObject()
            .put("nodes", JSONArray()
                .put(JSONObject().put("id", hostId(slug)).put("type", "host").put("label", deviceName.take(48)))
                .put(JSONObject().put("id", netId(slug)).put("type", "network").put("label", (deviceName.take(36) + " link"))))
            .put("edges", JSONArray().put(JSONArray().put(hostId(slug)).put(netId(slug))))
        return JSONObject()
            .put("collector_id", collectorId)
            .put("version", appVersion)
            .put("config_version", 1)
            .put("source_tz", dev.timeZoneId)
            .put("host_id", dev.hostPseudonym)
            .put("buffer_depth", bufferDepth)
            .put("oldest_pending_s", Math.round(oldestPendingS * 10.0) / 10.0)
            .put("link_state", linkState)
            .put("last_seq", lastSeq)
            .put("sent_at", isoUtc(nowMs))
            .put("topology", topology)
            .put("platform", "android")
            .put("os_version", dev.osVersion.take(60))
            .put("device_model", dev.model.take(60))
            .put("interval_s", intervalS)
    }
}
