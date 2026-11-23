"""Background supervision: collector liveness, event-alert expiry, incident resolution, health transitions."""
import threading
import time

from common.schema import utc_iso
from . import aiops, health, remediation
from .core import hub, now_ms, settings
from .db import db, jd

_stop = threading.Event()


def tick():
    ms = now_ms()
    for t in db.all("SELECT id FROM tenants"):
        tenant = t["id"]
        st = settings(tenant)
        # ---- collector liveness
        for c in db.all("SELECT * FROM collectors WHERE tenant_id=?", (tenant,)):
            if not c["last_seen_ms"]:
                continue
            age = (ms - c["last_seen_ms"]) / 1000.0
            key = (tenant, "collector:" + c["id"], "collector_offline")
            st = health.eff_settings(settings(tenant), c.get("interval_s"))   # scaled by the device's sync interval
            if age > st["offline_after_s"]:
                if c["status"] != "offline":
                    db.exec("UPDATE collectors SET status='offline', offline_since_ms=? WHERE id=?", (ms, c["id"]))
                    db.exec("INSERT INTO outages(tenant_id,collector_id,last_seen_ms,detected_ms) VALUES(?,?,?,?)",
                            (tenant, c["id"], c["last_seen_ms"], ms))
                    aiops.process_notice(tenant, c["id"], {"source_id": "collector:" + c["id"], "category": "collector"}, ms, ms,
                                         "collector_offline", f"Collector {c['name']} is offline",
                                         f"No heartbeat or telemetry for {int(age)}s (limit {int(st['offline_after_s'])}s). "
                                         f"Last seen {utc_iso(c['last_seen_ms']/1000)}.", "critical",
                                         {"last_seen": utc_iso(c["last_seen_ms"] / 1000), "silent_for_s": int(age)})
                    from .core import audit
                    audit(tenant, "system", "collector.offline", f"{c['id']} silent for {int(age)}s")
            elif c["status"] == "offline":
                db.exec("UPDATE collectors SET status='online', offline_since_ms=NULL WHERE id=?", (c["id"],))
                db.exec("UPDATE outages SET recovered_ms=? WHERE tenant_id=? AND collector_id=? AND recovered_ms IS NULL",
                        (ms, tenant, c["id"]))
                aid = aiops.ACTIVE.pop(key, None)
                if aid:
                    db.exec("UPDATE alerts SET cleared_ms=? WHERE id=?", (ms, aid))
        # ---- event-style alerts clear after a quiet period
        for a in db.all("SELECT id, source_id, metric, last_event_ms FROM alerts WHERE tenant_id=? AND cleared_ms IS NULL "
                        "AND metric IN ('secrets_detected')", (tenant,)):
            if ms - (a["last_event_ms"] or 0) > 45000:
                db.exec("UPDATE alerts SET cleared_ms=? WHERE id=?", (ms, a["id"]))
                aiops.ACTIVE.pop((tenant, a["source_id"], a["metric"]), None)
        # ---- resolve incidents whose alerts are all cleared for 20s
        for inc in db.all("SELECT id FROM incidents WHERE tenant_id=? AND status='open'", (tenant,)):
            r = db.one("SELECT COUNT(*) n, SUM(cleared_ms IS NULL) open_n, MAX(cleared_ms) last_clear FROM alerts WHERE incident_id=?",
                       (inc["id"],))
            if r["n"] and not r["open_n"] and ms - (r["last_clear"] or ms) > 20000:
                db.exec("UPDATE incidents SET status='resolved', resolved_ms=?, updated_ms=? WHERE id=?", (ms, ms, inc["id"]))
                db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail) VALUES(?,?,?,?,?,?)",
                        (tenant, inc["id"], ms, ms, "resolved", "All contributing alerts cleared; incident auto-resolved"))
        # ---- re-score open incidents: duration grows, alerts clear, so priority can escalate/de-escalate
        from . import triage
        changed = False
        for inc in db.all("SELECT id FROM incidents WHERE tenant_id=? AND status='open'", (tenant,)):
            changed |= triage.refresh(tenant, inc["id"])
        if changed:
            hub.broadcast(tenant, {"type": "incident"})
        from . import rem_engine
        rem_engine.tick(tenant)               # step/rollback timeouts + before/after verification of remediation plans
        remediation.evaluate_outcomes(tenant)
        health.record_transitions(tenant)
        hub.broadcast(tenant, {"type": "tick", "t": ms})


def retention():
    for t in db.all("SELECT id FROM tenants"):
        hours = settings(t["id"])["retention_hours"]
        cutoff = now_ms() - hours * 3600 * 1000
        db.exec("DELETE FROM events WHERE tenant_id=? AND event_ms<?", (t["id"], cutoff))
        db.exec("DELETE FROM perf_render WHERE tenant_id=? AND ts_ms<?", (t["id"], cutoff))


def loop():
    n = 0
    while not _stop.is_set():
        try:
            tick()
            n += 1
            if n % 300 == 0:
                retention()
        except Exception as e:  # never die
            print("monitor error", repr(e))
        _stop.wait(2.0)


def start():
    aiops.load_active()
    th = threading.Thread(target=loop, daemon=True, name="monitor")
    th.start()
    return th
