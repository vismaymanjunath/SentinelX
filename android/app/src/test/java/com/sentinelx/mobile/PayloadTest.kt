package com.sentinelx.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PayloadTest {
    private val snap = Snapshot(1_800_000_000_123L, 61.5, 72.25, 83.0, true, 1.234, 42.0)
    private val dev = DeviceInfo("Google Pixel 7", "Android 14 (API 34)", "Asia/Kolkata", "phone-1a2b3c4d")
    private val allowedTop = setOf("event_id", "type", "source_id", "category", "severity", "metric", "value", "unit", "event_time", "source_tz", "context")

    @Test fun eventsUseOnlyAllowListedFieldsAndUnits() {
        val ev = Payload.events("pixel-7", snap, dev.timeZoneId)
        assertEquals(6, ev.size)
        val units = setOf("percent", "ms", "mbps", "count", "bool", "ratio", "bytes", "none", "seconds")
        for (e in ev) {
            assertEquals(allowedTop, e.keys().asSequence().toSet())
            assertEquals("metric", e.getString("type"))
            assertTrue(e.getString("unit") in units)
            assertEquals(setOf("origin"), e.getJSONObject("context").keys().asSequence().toSet())
            assertTrue(e.getString("event_time").matches(Regex("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}Z")))
            assertEquals("Asia/Kolkata", e.getString("source_tz"))
        }
        assertEquals(ev.size, ev.map { it.getString("event_id") }.toSet().size)
        assertEquals("2027-01-15T08:00:00.123Z", ev[0].getString("event_time"))
    }

    @Test fun entitiesAreUniquePerDevice() {
        val ids = Payload.events("pixel-7", snap, "UTC").map { it.getString("source_id") }.toSet()
        assertEquals(setOf("host:pixel-7", "net:pixel-7-link"), ids)
    }

    @Test fun cpuIsNeverReportedBecauseAndroidDoesNotExposeIt() {
        val metrics = Payload.events("x", snap, "UTC").map { it.getString("metric") }
        assertFalse(metrics.any { it.contains("cpu") })
        assertEquals(setOf("memory_percent", "disk_percent", "battery_percent", "battery_charging", "bandwidth_mbps", "latency_ms"), metrics.toSet())
    }

    @Test fun unavailableMetricsAreOmittedNotFaked() {
        val s = Snapshot(1_800_000_000_000L, 50.0, null, null, null, null, null)
        assertEquals(listOf("memory_percent"), Payload.events("x", s, "UTC").map { it.getString("metric") })
        val nan = Snapshot(1_800_000_000_000L, Double.NaN, Double.POSITIVE_INFINITY, null, null, null, null)
        assertTrue(Payload.events("x", nan, "UTC").isEmpty())
    }

    @Test fun chargingIsBoolMetric() {
        val c = Payload.events("x", snap, "UTC").first { it.getString("metric") == "battery_charging" }
        assertEquals(1.0, c.getDouble("value"), 0.0)
        assertEquals("bool", c.getString("unit"))
        val d = Payload.events("x", snap.copy(charging = false), "UTC").first { it.getString("metric") == "battery_charging" }
        assertEquals(0.0, d.getDouble("value"), 0.0)
    }

    @Test fun heartbeatDescribesAndroidDevice() {
        val hb = Payload.heartbeat("col-r-pixel-7", "pixel-7", "Pixel 7", dev, 2, 12.34, "connected", 17, 900.0, 1_800_000_000_000L, "1.0.0")
        assertEquals("android", hb.getString("platform"))
        assertEquals("Google Pixel 7", hb.getString("device_model"))
        assertEquals("Android 14 (API 34)", hb.getString("os_version"))
        assertEquals(900.0, hb.getDouble("interval_s"), 0.0)
        assertEquals(2, hb.getJSONObject("topology").getJSONArray("nodes").length())
    }

    @Test fun writeContractSamplesForServerSchemaTest() {
        val ev = Payload.events("pixel-7", snap, dev.timeZoneId)
        val p = Payload.payload("col-r-pixel-7", 5, "11111111-2222-3333-4444-555555555555", snap.tsMs, ev)
        val hb = Payload.heartbeat("col-r-pixel-7", "pixel-7", "Pixel 7", dev, 0, 0.0, "connected", 5, 900.0, snap.tsMs, "1.0.0")
        val dir = File("../contract").apply { mkdirs() }
        File(dir, "payload-sample.json").writeText(p.toString(2))
        File(dir, "heartbeat-sample.json").writeText(hb.toString(2))
    }

    @Test fun urlNormalisation() {
        assertEquals("https://abcd.ngrok-free.app", Api.normalizeUrl(" abcd.ngrok-free.app/ "))
        assertEquals("https://h.example:8443", Api.normalizeUrl("https://h.example:8443"))
        for (bad in listOf("http://abcd.ngrok-free.app", "https://abcd.ngrok-free.app/api/login", "https://u:p@h.example", "https://h.example/?x=1")) {
            var failed = false
            try { Api.normalizeUrl(bad) } catch (e: IllegalArgumentException) { failed = true }
            assertTrue("should reject $bad", failed)
        }
    }
}
