package com.sentinelx.mobile

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Bg = Color(0xFF0B1220)
private val Panel = Color(0xFF111A2E)
private val Accent = Color(0xFF4F8CFF)
private val Good = Color(0xFF2ECC71)
private val Warn = Color(0xFFF5A524)
private val Bad = Color(0xFFEF4444)
private val Mut = Color(0xFF8DA0C4)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Prefs.init(this)
        if (Prefs.enrolled) Scheduler.schedulePeriodic(this)   // keeps the periodic job alive after app updates / reinstalls of the job store
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Accent, background = Bg, surface = Panel)) {
                Box(Modifier.fillMaxSize().background(Bg).statusBarsPadding()) { Root() }
            }
        }
    }
}

@Composable
private fun Root() {
    var enrolled by remember { mutableStateOf(Prefs.enrolled) }
    if (!enrolled) ConnectScreen { enrolled = true } else StatusScreen { enrolled = false }
}

@Composable
private fun Title(sub: String) {
    Text("SentinelX Mobile", fontSize = 26.sp, fontWeight = FontWeight.ExtraBold, color = Color.White)
    Text(sub, color = Mut, fontSize = 13.sp)
    Spacer(Modifier.height(16.dp))
}

@Composable
private fun ConnectScreen(onDone: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf(Prefs.serverUrl) }
    var code by remember { mutableStateOf("") }
    var name by remember { mutableStateOf(Prefs.deviceName) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {
        Title("Connect this phone to your SENTINEL X server")
        OutlinedTextField(url, { url = it }, label = { Text("Server URL (https://…)") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(code, { code = it }, label = { Text("Join code") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(name, { name = it }, label = { Text("Device name (unique)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(16.dp))
        Button(onClick = {
            busy = true; error = ""
            scope.launch {
                val err = withContext(Dispatchers.IO) { Enroll.register(ctx, url, code, name) }
                busy = false
                if (err == null) { code = ""; onDone() } else error = err
            }
        }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Connecting…" else "Connect") }
        if (error.isNotEmpty()) { Spacer(Modifier.height(12.dp)); Text(error, color = Bad) }
        Spacer(Modifier.height(20.dp))
        Text("Uses HTTPS with normal certificate validation. The join code is sent once to register and is never stored. " +
            "Only metadata is sent: RAM, storage, battery, network throughput, device model and Android version.", color = Mut, fontSize = 12.sp)
    }
}

private fun ago(ms: Long): String {
    if (ms <= 0) return "never"
    val s = (System.currentTimeMillis() - ms) / 1000
    return when { s < 5 -> "just now"; s < 90 -> "$s s ago"; s < 5400 -> "${s / 60} min ago"; else -> "${s / 3600} h ago" }
}

private fun fmt(ms: Long, utc: Boolean): String {
    val f = SimpleDateFormat("yyyy-MM-dd HH:mm:ss" + if (utc) "'Z'" else "", Locale.US)
    if (utc) f.timeZone = java.util.TimeZone.getTimeZone("UTC")
    return f.format(Date(ms))
}

@Composable
private fun StatusScreen(onDisconnect: () -> Unit) {
    val ctx = LocalContext.current
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(1000); tick++ } }
    var live by remember { mutableStateOf(Prefs.liveMode) }
    val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { _ ->
        ctx.startForegroundServiceCompat(); live = true   // the service works without the notification being shown; Android 13+ just hides it
    }
    @Suppress("UNUSED_EXPRESSION") tick   // recompose every second
    val state = Prefs.state
    val (label, color) = when (state) {
        "connected" -> "Connected" to Good
        "retrying" -> "Offline – retrying automatically" to Warn
        "auth_error" -> "Credentials rejected – reconnect" to Bad
        else -> "Waiting for first sync" to Mut
    }
    val snap = runCatching { JSONObject(Prefs.lastSnapshot) }.getOrDefault(JSONObject())
    fun d(k: String): Double? = if (snap.isNull(k) || !snap.has(k)) null else snap.getDouble(k)
    val queued = remember(tick) { Outbox.get(ctx).count() }
    val dev = remember { Metrics.deviceInfo() }

    Column(Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Title(Prefs.deviceName + " · " + Prefs.collectorId)
        Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(12.dp).background(color, CircleShape)); Spacer(Modifier.size(8.dp))
                    Text(label, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = color)
                }
                Spacer(Modifier.height(8.dp))
                Text("Last successful sync: ${ago(Prefs.lastSyncMs)}", color = Color.White)
                if (Prefs.lastSyncMs > 0) Text("${fmt(Prefs.lastSyncMs, false)} local · ${fmt(Prefs.lastSyncMs, true)}", color = Mut, fontSize = 12.sp)
                Text("Queued for delivery: $queued payload(s)" + if (queued > 0) " (kept safely until the server is reachable)" else "", color = Mut, fontSize = 13.sp)
                if (Prefs.lastError.isNotEmpty()) Text(Prefs.lastError, color = Warn, fontSize = 12.sp)
                Text("Server: ${Prefs.serverUrl}", color = Mut, fontSize = 12.sp)
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(12.dp)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("This device", fontWeight = FontWeight.Bold, color = Color.White)
                Text("${dev.model} · ${dev.osVersion}", color = Mut)
                Spacer(Modifier.height(6.dp))
                Row { Text("Battery ", color = Mut); Text(d("bat")?.let { "%.0f%%".format(it) + if (snap.optBoolean("chg")) " ⚡ charging" else " on battery" } ?: "n/a", color = Color.White) }
                Row { Text("RAM used ", color = Mut); Text(d("mem")?.let { "%.0f%%".format(it) } ?: "n/a", color = Color.White) }
                Row { Text("Storage used ", color = Mut); Text(d("disk")?.let { "%.0f%%".format(it) } ?: "n/a", color = Color.White) }
                Row { Text("Network traffic ", color = Mut); Text(d("bw")?.let { "%.3f Mbps (avg since last sync)".format(it) } ?: "n/a (first sample or unsupported)", color = Color.White) }
                Row { Text("Server latency ", color = Mut); Text(d("rtt")?.let { "%.0f ms".format(it) } ?: "n/a", color = Color.White) }
                Text("CPU: not available – Android does not expose system CPU usage to apps.", color = Mut, fontSize = 12.sp)
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(12.dp)) {
            Column(Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Live demo mode", fontWeight = FontWeight.Bold, color = Color.White)
                        Text("Sync every 5 s with a visible notification. Off = background sync every 15 min (WorkManager).", color = Mut, fontSize = 12.sp)
                    }
                    Switch(checked = live, onCheckedChange = { on ->
                        if (on) {
                            if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                                notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
                            else { ctx.startForegroundServiceCompat(); live = true }
                        } else { ctx.stopService(Intent(ctx, LiveService::class.java)); live = false }
                    })
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(onClick = { Scheduler.syncNow(ctx) }, modifier = Modifier.weight(1f)) { Text("Sync now") }
            OutlinedButton(onClick = { Enroll.disconnect(ctx); onDisconnect() }, modifier = Modifier.weight(1f)) { Text("Disconnect") }
        }
        if (state == "auth_error") Button(onClick = { Enroll.disconnect(ctx); onDisconnect() }, modifier = Modifier.fillMaxWidth()) { Text("Reconnect with a new join code") }
        Text("Background syncs may be delayed by Android battery optimisation (Doze). Metadata only – no files, contacts, location or app data are read.", color = Mut, fontSize = 11.sp)
    }
}

private fun android.content.Context.startForegroundServiceCompat() {
    ContextCompat.startForegroundService(this, Intent(this, LiveService::class.java))
}
