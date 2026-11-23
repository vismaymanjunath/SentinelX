import json
import sqlite3
import threading
import time

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, raw TEXT, redacted TEXT,
  secrets TEXT, pii INTEGER DEFAULT 0, level TEXT, service TEXT);
CREATE TABLE IF NOT EXISTS outbox(seq INTEGER PRIMARY KEY, payload_id TEXT UNIQUE, body TEXT, sha256 TEXT,
  status TEXT, created_ms REAL, attempts INTEGER DEFAULT 0, last_attempt_ms REAL, sent_ms REAL, ack TEXT,
  event_count INTEGER, first_event_ms REAL);
CREATE TABLE IF NOT EXISTS egress(payload_id TEXT PRIMARY KEY, seq INTEGER, created_ms REAL, status TEXT,
  original TEXT, redacted TEXT, final TEXT, blocked TEXT, redactions TEXT, attempts TEXT, sha256 TEXT,
  saas_sha256 TEXT, http_status INTEGER, event_count INTEGER, blocked_count INTEGER);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms REAL, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""


class DB:
    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, isolation_level=None, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    def exec(self, sql, p=()):
        with self.lock:
            return self.conn.execute(sql, p)

    def all(self, sql, p=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, p).fetchall()]

    def one(self, sql, p=()):
        with self.lock:
            r = self.conn.execute(sql, p).fetchone()
            return dict(r) if r else None

    def kv_get(self, k, default=None):
        r = self.one("SELECT v FROM kv WHERE k=?", (k,))
        return json.loads(r["v"]) if r else default

    def kv_set(self, k, v):
        self.exec("INSERT OR REPLACE INTO kv VALUES(?,?)", (k, json.dumps(v)))

    def next_seq(self):
        with self.lock:
            n = (self.kv_get("seq", 0) or 0) + 1
            self.kv_set("seq", n)
            return n

    def audit(self, kind, detail=""):
        self.exec("INSERT INTO audit(ts_ms,kind,detail) VALUES(?,?,?)", (time.time() * 1000, kind, str(detail)[:500]))


db = DB()
