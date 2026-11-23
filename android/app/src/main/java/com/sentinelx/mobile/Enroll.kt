package com.sentinelx.mobile

import android.content.Context
import org.json.JSONObject

/** Registration through the EXISTING endpoint POST /api/ingest/v1/register. Returns null on success, or a user-facing error. */
object Enroll {
    private val NAME = Regex("[A-Za-z0-9][A-Za-z0-9 _.\\-]{0,31}")

    fun register(ctx: Context, rawUrl: String, joinCode: String, deviceName: String): String? {
        Prefs.init(ctx)
        val url = try { Api.normalizeUrl(rawUrl) } catch (e: IllegalArgumentException) { return e.message }
        val name = deviceName.trim()
        if (!NAME.matches(name)) return "Device name: 1-32 letters, digits, space, . _ -"
        if (joinCode.isEmpty()) return "Enter the join code from the host"
        val body = JSONObject().put("device_name", name).put("join_code", joinCode).put("install_id", Prefs.installId).toString()
        val r = try {
            Api.post(url, "/api/ingest/v1/register", null, body)
        } catch (e: NetworkError) {
            return "Cannot connect to $url (${e.message}). Check the URL, your internet, and that the host's tunnel is running."
        }
        when (r.code) {
            200 -> Unit
            403 -> return "The server rejected the join code (or enrollment is disabled)."
            409 -> return "That device name is already used by another device. Choose a different name."
            429 -> return "Too many attempts - wait a minute and retry."
            404 -> return if (r.body.contains("ngrok", ignoreCase = true)) "ngrok says this tunnel is offline or the URL is wrong." else "Server does not support registration (HTTP 404)."
            else -> return "Registration failed (HTTP ${r.code}): " + r.body.take(120)
        }
        val j = try { JSONObject(r.body) } catch (e: Exception) { return "Unexpected server response" }
        val newId = j.getString("collector_id")
        if (Prefs.collectorId != newId) {   // payloads queued for another collector id would be rejected: start clean
            Outbox.get(ctx).clear()
            Prefs.resetSeq()
        }
        Prefs.serverUrl = url
        Prefs.deviceName = name
        Prefs.collectorId = newId
        Prefs.slug = j.getString("slug")
        Prefs.apiKey = j.getString("api_key")
        Prefs.state = "idle"
        Prefs.lastError = ""
        Prefs.intervalS = if (Prefs.liveMode) Prefs.LIVE_INTERVAL_S else Prefs.PERIODIC_INTERVAL_S
        Scheduler.schedulePeriodic(ctx)
        Scheduler.syncNow(ctx)
        return null
    }

    fun disconnect(ctx: Context) {
        Prefs.init(ctx)
        ctx.stopService(android.content.Intent(ctx, LiveService::class.java))
        Scheduler.cancelAll(ctx)
        Outbox.get(ctx).clear()
        Prefs.clearEnrollment()
    }
}
