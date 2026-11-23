package com.sentinelx.mobile

import java.io.IOException
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection

data class Resp(val code: Int, val body: String)
class NetworkError(msg: String, cause: Throwable? = null) : Exception(msg, cause)

/**
 * HTTPS-only client built on HttpsURLConnection: default SSLSocketFactory and hostname verifier, i.e. normal certificate
 * validation against the platform trust store. No custom TrustManager, no pinning bypass. Cleartext is also disabled in the manifest.
 */
object Api {
    /** "abcd.ngrok-free.app" or "https://abcd.ngrok-free.app/" -> "https://abcd.ngrok-free.app". Rejects http and paths. */
    fun normalizeUrl(raw: String): String {
        var r = raw.trim()
        if (!r.contains("://")) r = "https://$r"
        val u = try { URI(r) } catch (e: Exception) { throw IllegalArgumentException("That is not a valid URL") }
        require(u.scheme == "https") { "The server URL must start with https://" }
        val host = u.host ?: throw IllegalArgumentException("Enter just the server address, e.g. https://abcd.ngrok-free.app")
        require(Regex("[A-Za-z0-9.\\-]{1,253}").matches(host) && (u.path.isNullOrEmpty() || u.path == "/") &&
            u.query == null && u.userInfo == null) { "Enter just the server address, e.g. https://abcd.ngrok-free.app" }
        return "https://$host" + if (u.port != -1 && u.port != 443) ":${u.port}" else ""
    }

    fun post(base: String, path: String, bearer: String?, json: String): Resp {
        require(base.startsWith("https://")) { "https only" }
        try {
            val c = URL(base + path).openConnection() as HttpsURLConnection
            try {
                c.requestMethod = "POST"
                c.connectTimeout = 8000
                c.readTimeout = 15000
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.setRequestProperty("ngrok-skip-browser-warning", "1")
                if (bearer != null) c.setRequestProperty("Authorization", "Bearer $bearer")
                c.outputStream.use { it.write(json.toByteArray(Charsets.UTF_8)) }
                val code = c.responseCode
                val stream = if (code < 400) c.inputStream else c.errorStream
                val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                return Resp(code, body)
            } finally {
                c.disconnect()
            }
        } catch (e: IOException) {   // includes SSLHandshakeException (untrusted cert), timeouts, DNS failures
            throw NetworkError(e.javaClass.simpleName + ": " + (e.message ?: "").take(120), e)
        }
    }
}
