import json
import sqlite3
import threading
from contextlib import contextmanager

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY, name TEXT, region TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, username TEXT UNIQUE,
  pw_hash TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, tenant_id TEXT, username TEXT,
  role TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS collectors(id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, key_hash TEXT, region TEXT,
  version TEXT, source_tz TEXT, host_id TEXT, last_seen_ms REAL, last_hb_ms REAL, status TEXT DEFAULT 'unknown',
  proc_cpu REAL, proc_mem_mb REAL, buffer_depth REAL, oldest_pending_s REAL, link_state TEXT, config_version REAL,
  retention_s REAL, last_seq REAL, offline_since_ms REAL, registered_ms REAL,
  platform TEXT, os_version TEXT, device_model TEXT, interval_s REAL, install_id TEXT);
CREATE TABLE IF NOT EXISTS payloads(payload_id TEXT PRIMARY KEY, tenant_id TEXT, collector_id TEXT, seq INTEGER,
  received_ms REAL, sent_at TEXT, event_count INTEGER, sha256 TEXT, dup_events INTEGER DEFAULT 0, attempt_hint INTEGER);
CREATE INDEX IF NOT EXISTS ix_payloads_c ON payloads(tenant_id, collector_id, seq);
CREATE TABLE IF NOT EXISTS rejected(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT,
  payload_id TEXT, reason TEXT, ts_ms REAL);
CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, tenant_id TEXT, collector_id TEXT, payload_id TEXT,
  type TEXT, source_id TEXT, metric TEXT, value REAL, unit TEXT, category TEXT, severity TEXT, event_time TEXT,
  event_ms REAL, received_ms REAL, source_tz TEXT, context TEXT, late INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_events_series ON events(tenant_id, source_id, metric, event_ms);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(tenant_id, event_ms);
CREATE INDEX IF NOT EXISTS ix_events_payload ON events(payload_id);
CREATE TABLE IF NOT EXISTS latest(tenant_id TEXT, source_id TEXT, metric TEXT, value REAL, event_ms REAL,
  received_ms REAL, collector_id TEXT, unit TEXT, PRIMARY KEY(tenant_id, source_id, metric));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT,
  source_id TEXT, metric TEXT, kinds TEXT, severity TEXT, category TEXT, title TEXT, message TEXT, evidence TEXT,
  created_ms REAL, created_at TEXT, event_ms REAL, last_event_ms REAL, cleared_ms REAL, incident_id INTEGER,
  detected_by TEXT, late INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alerts_t ON alerts(tenant_id, created_ms);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, title TEXT, status TEXT,
  severity TEXT, priority REAL, root_cause TEXT, root_entity TEXT, confidence REAL, analysis TEXT,
  opened_ms REAL, opened_at TEXT, updated_ms REAL, last_alert_ms REAL, resolved_ms REAL, alert_count INTEGER DEFAULT 0,
  entities TEXT);
CREATE TABLE IF NOT EXISTS incident_events(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, incident_id INTEGER,
  ts_ms REAL, event_ms REAL, kind TEXT, detail TEXT, snapshot TEXT);
CREATE TABLE IF NOT EXISTS health_state(tenant_id TEXT, entity_id TEXT, state TEXT, PRIMARY KEY(tenant_id, entity_id));
CREATE TABLE IF NOT EXISTS health_history(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, entity_id TEXT,
  old_state TEXT, new_state TEXT, reasons TEXT, ts_ms REAL, ts TEXT);
CREATE TABLE IF NOT EXISTS thresholds(tenant_id TEXT, metric TEXT, good_max REAL, warn REAL, crit REAL,
  PRIMARY KEY(tenant_id, metric));
CREATE TABLE IF NOT EXISTS settings(tenant_id TEXT, key TEXT, value REAL, PRIMARY KEY(tenant_id, key));
CREATE TABLE IF NOT EXISTS entities(tenant_id TEXT, id TEXT, type TEXT, label TEXT, PRIMARY KEY(tenant_id, id));
CREATE TABLE IF NOT EXISTS topology(tenant_id TEXT, src TEXT, dst TEXT, PRIMARY KEY(tenant_id, src, dst));
CREATE TABLE IF NOT EXISTS remediation(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, incident_id INTEGER,
  collector_id TEXT, action TEXT, target TEXT, title TEXT, rationale TEXT, status TEXT, policy TEXT, risk TEXT,
  proposed_by TEXT, proposed_ms REAL, approved_by TEXT, approved_ms REAL, executed_ms REAL, result TEXT,
  rollback_plan TEXT, before_state TEXT, rolled_back_ms REAL, outcome TEXT, command_id TEXT);
CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, tenant_id TEXT, collector_id TEXT, remediation_id INTEGER,
  kind TEXT, action TEXT, target TEXT, status TEXT, created_ms REAL, delivered_ms REAL, done_ms REAL, result TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, actor TEXT, action TEXT,
  detail TEXT, ts_ms REAL, ts TEXT);
CREATE TABLE IF NOT EXISTS deletion_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT, scope TEXT,
  reason TEXT, status TEXT, requested_by TEXT, requested_ms REAL, decided_by TEXT, decided_ms REAL, decision_note TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS perf_render(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, event_id TEXT,
  latency_ms REAL, ts_ms REAL);
CREATE TABLE IF NOT EXISTS sim_markers(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT,
  scenario TEXT, injected_ms REAL, injected_at TEXT, received_ms REAL, event_id TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS incident_ai(tenant_id TEXT, incident_id INTEGER, status TEXT, model TEXT, ctx_hash TEXT,
  requested_by TEXT, requested_ms REAL, finished_ms REAL, duration_ms REAL, result TEXT, error TEXT, context TEXT, pmap TEXT,
  PRIMARY KEY(tenant_id, incident_id));
CREATE TABLE IF NOT EXISTS policy_violations(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT, level TEXT,
  code TEXT, field TEXT, count INTEGER DEFAULT 1, first_ms REAL, last_ms REAL, UNIQUE(tenant_id, collector_id, level, code, field));
CREATE TABLE IF NOT EXISTS intel_sources(source TEXT PRIMARY KEY, category TEXT, name TEXT, url TEXT, interval_s REAL, last_attempt_ms REAL,
  last_success_ms REAL, last_error TEXT, state TEXT, items_last INTEGER DEFAULT 0, items_total INTEGER DEFAULT 0, etag TEXT, last_modified TEXT,
  cache_hits INTEGER DEFAULT 0, fetches INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, next_attempt_ms REAL, note TEXT, last_data_ms REAL);
CREATE TABLE IF NOT EXISTS intel_events(id TEXT PRIMARY KEY, source TEXT, category TEXT, kind TEXT, severity TEXT, title TEXT, summary TEXT,
  status TEXT, event_ms REAL, updated_ms REAL, first_seen_ms REAL, last_seen_ms REAL, source_url TEXT, country TEXT, region TEXT, provider TEXT,
  asn TEXT, prefix TEXT, vendor TEXT, product TEXT, cve TEXT, score REAL, exploited INTEGER DEFAULT 0, data TEXT, version INTEGER DEFAULT 1,
  digest TEXT);
CREATE INDEX IF NOT EXISTS ix_intel_cat ON intel_events(category, event_ms);
CREATE INDEX IF NOT EXISTS ix_intel_src ON intel_events(source, event_ms);
CREATE INDEX IF NOT EXISTS ix_intel_asn ON intel_events(asn);
CREATE INDEX IF NOT EXISTS ix_intel_cve ON intel_events(cve);
CREATE TABLE IF NOT EXISTS intel_history(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, version INTEGER, ts_ms REAL, status TEXT, severity TEXT,
  summary TEXT, updated_ms REAL);
CREATE INDEX IF NOT EXISTS ix_intel_hist ON intel_history(event_id);
CREATE TABLE IF NOT EXISTS intel_bgp(scope TEXT, minute_ms REAL, announcements INTEGER, withdrawals INTEGER, prefixes INTEGER, peers INTEGER, msgs INTEGER,
  path_changes INTEGER DEFAULT 0, PRIMARY KEY(scope, minute_ms));
CREATE TABLE IF NOT EXISTS intel_bgp_updates(id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms REAL, host TEXT, peer_asn TEXT, kind TEXT, prefix TEXT,
  origin_asn TEXT, path TEXT, scope_asn TEXT);
CREATE INDEX IF NOT EXISTS ix_bgpu ON intel_bgp_updates(scope_asn, ts_ms);
CREATE TABLE IF NOT EXISTS intel_watch(asn TEXT PRIMARY KEY, reason TEXT, added_ms REAL, tenant_id TEXT);
CREATE TABLE IF NOT EXISTS intel_asn(asn TEXT PRIMARY KEY, holder TEXT, country TEXT, prefixes TEXT, fetched_ms REAL);
CREATE TABLE IF NOT EXISTS intel_cache(key TEXT PRIMARY KEY, value TEXT, fetched_ms REAL);
CREATE TABLE IF NOT EXISTS device_context(tenant_id TEXT, collector_id TEXT, asn INTEGER, country TEXT, software TEXT, updated_ms REAL,
  PRIMARY KEY(tenant_id, collector_id));
CREATE TABLE IF NOT EXISTS intel_correlations(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, kind TEXT, event_id TEXT, collector_id TEXT,
  local_type TEXT, local_ref TEXT, status TEXT, score REAL, confidence TEXT, factors TEXT, evidence TEXT, created_ms REAL, updated_ms REAL,
  incident_id INTEGER, UNIQUE(tenant_id, event_id, collector_id, local_type, local_ref));
CREATE INDEX IF NOT EXISTS ix_corr_t ON intel_correlations(tenant_id, status, updated_ms);
CREATE TABLE IF NOT EXISTS intel_ai(tenant_id TEXT, subject TEXT, status TEXT, model TEXT, ctx_hash TEXT, requested_by TEXT, requested_ms REAL,
  finished_ms REAL, result TEXT, error TEXT, context TEXT, PRIMARY KEY(tenant_id, subject));
CREATE TABLE IF NOT EXISTS rem_plans(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, problem_id TEXT, incident_id INTEGER, target TEXT, collector_id TEXT,
  title TEXT, status TEXT, root_cause TEXT, solution TEXT, expected_outcome TEXT, risk TEXT, needs_confirm INTEGER DEFAULT 0, evidence TEXT, ai TEXT,
  created_by TEXT, created_ms REAL, decided_by TEXT, decided_ms REAL, decision_note TEXT, started_ms REAL, finished_ms REAL, before_metrics TEXT, after_metrics TEXT,
  verification TEXT, summary TEXT, rolled_back_ms REAL);
CREATE INDEX IF NOT EXISTS ix_rem_plans ON rem_plans(tenant_id, id);
CREATE TABLE IF NOT EXISTS rem_steps(id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER, tenant_id TEXT, n INTEGER, key TEXT, action TEXT, kind TEXT, scope TEXT, title TEXT,
  rationale TEXT, params TEXT, risk TEXT, destructive INTEGER DEFAULT 0, reversible INTEGER DEFAULT 0, status TEXT, result TEXT, before_state TEXT, after_state TEXT,
  command_id TEXT, started_ms REAL, finished_ms REAL, rollback_status TEXT, rollback_result TEXT, manual_text TEXT, manual_by TEXT, manual_ms REAL);
CREATE INDEX IF NOT EXISTS ix_rem_steps ON rem_steps(plan_id);
CREATE TABLE IF NOT EXISTS outages(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, collector_id TEXT,
  last_seen_ms REAL, detected_ms REAL, recovered_ms REAL);
"""


class DB:
    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            # additive migration for databases created before the device-platform columns existed
            for tbl, col, typ in (("collectors", "platform", "TEXT"), ("collectors", "os_version", "TEXT"),
                                  ("collectors", "device_model", "TEXT"), ("collectors", "interval_s", "REAL"),
                                  ("collectors", "install_id", "TEXT"), ("incidents", "priority_level", "TEXT"),
                                  ("incidents", "category", "TEXT"), ("collectors", "anon_enabled", "INTEGER"),
                                  ("collectors", "anon_policy", "TEXT"), ("collectors", "anon_records", "REAL"),
                                  ("collectors", "anon_removed", "REAL"), ("collectors", "anon_pseudo", "REAL"),
                                  ("collectors", "privacy", "TEXT"), ("collectors", "privacy_ms", "REAL"), ("collectors", "transport", "TEXT"),
                                  ("payloads", "body", "TEXT"), ("collectors", "actions", "TEXT"), ("commands", "plan_step_id", "INTEGER"),
                                  ("commands", "params", "TEXT")):
                try:
                    self.conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
                except sqlite3.OperationalError:
                    pass  # already present

    def exec(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params)

    def all(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        with self.lock:
            r = self.conn.execute(sql, params).fetchone()
            return dict(r) if r else None

    @contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise


db = DB()


def jd(o):
    return json.dumps(o, separators=(",", ":"), default=str)


def jl(s, default=None):
    if s is None or s == "":
        return default
    try:
        return json.loads(s)
    except Exception:
        return default
