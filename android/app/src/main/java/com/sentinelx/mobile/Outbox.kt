package com.sentinelx.mobile

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class OutboxRow(val seq: Long, val payloadId: String, val body: String, val createdMs: Long)

/**
 * Durable queue of payloads that have been built but not yet acknowledged by the server. Payloads keep their payload_id
 * across retries, so a retry after a lost response is de-duplicated by the server (idempotent delivery).
 * Bounded: when more than MAX_ROWS accumulate (very long offline period) the oldest are dropped.
 */
class Outbox private constructor(ctx: Context) : SQLiteOpenHelper(ctx.applicationContext, "outbox.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE outbox(seq INTEGER PRIMARY KEY, payload_id TEXT NOT NULL, body TEXT NOT NULL, created_ms INTEGER NOT NULL)")
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {}

    @Synchronized fun enqueue(seq: Long, payloadId: String, body: String, nowMs: Long) {
        val db = writableDatabase
        db.insertOrThrow("outbox", null, ContentValues().apply {
            put("seq", seq); put("payload_id", payloadId); put("body", body); put("created_ms", nowMs)
        })
        val n = count()
        if (n > MAX_ROWS) db.execSQL("DELETE FROM outbox WHERE seq IN (SELECT seq FROM outbox ORDER BY seq LIMIT ?)", arrayOf<Any>(n - MAX_ROWS))
    }

    @Synchronized fun oldest(): OutboxRow? =
        readableDatabase.rawQuery("SELECT seq,payload_id,body,created_ms FROM outbox ORDER BY seq LIMIT 1", null).use {
            if (it.moveToFirst()) OutboxRow(it.getLong(0), it.getString(1), it.getString(2), it.getLong(3)) else null
        }

    @Synchronized fun delete(seq: Long) { writableDatabase.delete("outbox", "seq=?", arrayOf(seq.toString())) }

    @Synchronized fun count(): Int = readableDatabase.rawQuery("SELECT COUNT(*) FROM outbox", null).use { if (it.moveToFirst()) it.getInt(0) else 0 }

    @Synchronized fun oldestAgeS(nowMs: Long): Double =
        readableDatabase.rawQuery("SELECT MIN(created_ms) FROM outbox", null).use {
            if (it.moveToFirst() && !it.isNull(0)) (nowMs - it.getLong(0)) / 1000.0 else 0.0
        }

    @Synchronized fun clear() { writableDatabase.delete("outbox", null, null) }

    companion object {
        const val MAX_ROWS = 1500
        @Volatile private var inst: Outbox? = null
        fun get(ctx: Context): Outbox = inst ?: synchronized(this) { inst ?: Outbox(ctx).also { inst = it } }
    }
}
