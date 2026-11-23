"""Authenticated metadata ingestion: server-side allow-list re-validation, idempotency, event-time ordering."""
import re
import sqlite3

from common import policy
from common.schema import filter_event, parse_iso, validate_heartbeat
from . import aiops, config, remediation
from .core import hub, now_ms, upsert_entity
from .db import db, jd

PAYLOAD_KEYS = {"payload_id", "collector_id", "seq", "sent_at", "schema_version", "events"}
RX_PID = re.compile(r"^[A-Za-z0-9-]{8,64}$")
PLATFORMS = {"windows", "macos", "linux", "android"}
TYPE_PRIORITY ={"sim_marker": 0, "metric": 1, "log_summary": 2, "privacy_summary": 3, "security_summary": 4, "alert": 5}


def record_violation(tenant, cid, level, code, field):
    """Codes and field NAMES only - never the offending value - so this table cannot itself leak an identifier."""
    ms = now_ms()
    db.exec("INSERT INTO policy_violations(tenant_id,collector_id,level,code,field,count,first_ms,last_ms) VALUES(?,?,?,?,?,1,?,?) "
            "ON CONFLICT(tenant_id,collector_id,level,code,field) DO UPDATE SET count=count+1, last_ms=excluded.last_ms",
            (tenant, cid, level, code, field, ms, ms))


def _enforce(coll, findings, what):
    """Reject on reject-level findings (records them); record flag-level ones and continue."""
    rej = [f for f in findings if f["level"] == "reject"]
    for f in findings:
        record_violation(coll["tenant_id"], coll["id"], f["level"], f["code"], f["field"])
    if rej:
        raise Rejected([f"outgoing-data policy violation in {what}: " + ", ".join(sorted({f"{f['code']}@{f['field']}" for f in rej}))])


class Rejected(Exception):
    def __init__(self, problems):
        self.problems = problems


def _guess_type(sid):
    if sid.startswith("host"):
        return "host"
    if sid.startswith("net"):
        return "network"
    return "service"


def validate_payload(coll, payload):
    probs = []
    if not isinstance(payload, dict):
        raise Rejected(["payload must be an object"])
    extra = set(payload) - PAYLOAD_KEYS
    if extra:
        probs.append("fields not allowed: " + ",".join(sorted(extra)))
    if not RX_PID.match(str(payload.get("payload_id", ""))):
        probs.append("invalid payload_id")
    if payload.get("collector_id") != coll["id"]:
        probs.append("collector_id does not match credential")
    if not isinstance(payload.get("seq"), int):
        probs.append("invalid seq")
    evs = payload.get("events")
    if not isinstance(evs, list) or len(evs) > 500:
        probs.append("events must be a list (max 500)")
        raise Rejected(probs)
    if config.REQUIRE_ANON and coll.get("anon_enabled") == 0:
        probs.append("host policy requires local anonymisation (collector has not declared it enabled)")
        record_violation(coll["tenant_id"], coll["id"], "reject", "anonymisation_required", "collector")
    for i, ev in enumerate(evs):
        r = filter_event(ev)
        if r["blocked_fields"] or r["redactions"] or r["violations"] or r["blocked"]:
            probs.append(f"event[{i}] violates allow-list: blocked={r['blocked_fields']} redactions={[x['label'] for x in r['redactions']]} "
                         f"violations={r['violations']}")
    if probs:
        raise Rejected(probs[:10])
    # outgoing-data policy (beyond the allow-list): identifiers must not be on the wire
    findings = [f for ev in evs if isinstance(ev, dict) for f in policy.check_event(ev)]
    if coll.get("anon_enabled") and str(coll["id"]).startswith("col-r-"):
        findings += policy.device_identity_findings([ev.get("source_id", "") for ev in evs if isinstance(ev, dict)])
    _enforce(coll, findings, "payload")


BODY_KEEP = 25     # exact received bodies retained per collector (older ones keep only their hash)


def process_payload(coll, payload, body_sha, attempt_hint=None, raw_body=None):
    tenant, cid = coll["tenant_id"], coll["id"]
    t0 = now_ms()
    try:
        validate_payload(coll, payload)
    except Rejected as r:
        db.exec("INSERT INTO rejected(tenant_id,collector_id,payload_id,reason,ts_ms) VALUES(?,?,?,?,?)",
                (tenant, cid, str(payload.get("payload_id"))[:64] if isinstance(payload, dict) else None,
                 "allow-list violation: " + " | ".join(r.problems), t0))
        raise
    pid = payload["payload_id"]
    evs = sorted(payload["events"], key=lambda e: (parse_iso(e["event_time"]), TYPE_PRIORITY.get(e["type"], 9)))
    accepted, dup_events, new_events = 0, 0, []
    try:
        with db.tx() as conn:
            conn.execute("INSERT INTO payloads(payload_id,tenant_id,collector_id,seq,received_ms,sent_at,event_count,sha256,attempt_hint,body)"
                         " VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (pid, tenant, cid, payload["seq"], t0, payload.get("sent_at"), len(evs), body_sha, attempt_hint, raw_body))
            for ev in evs:
                ems = parse_iso(ev["event_time"]) * 1000.0
                lat = conn.execute("SELECT event_ms FROM latest WHERE tenant_id=? AND source_id=? AND metric=?",
                                   (tenant, ev["source_id"], ev.get("metric") or "")).fetchone()
                late = 1 if (ev["type"] == "metric" and lat and ems < lat["event_ms"]) else 0
                try:
                    conn.execute("INSERT INTO events(event_id,tenant_id,collector_id,payload_id,type,source_id,metric,value,unit,"
                                 "category,severity,event_time,event_ms,received_ms,source_tz,context,late) "
                                 "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (ev["event_id"], tenant, cid, pid, ev["type"], ev["source_id"], ev.get("metric"), ev.get("value"),
                                  ev.get("unit"), ev["category"], ev["severity"], ev["event_time"], ems, t0, ev["source_tz"],
                                  jd(ev.get("context", {})), late))
                except sqlite3.IntegrityError:
                    dup_events += 1
                    continue
                accepted += 1
                new_events.append((ev, ems, late))
                if ev["type"] == "metric" and ev["metric"] not in aiops.NO_ANALYSIS:      # probe evidence stays out of the live entity/health model
                    conn.execute("INSERT INTO latest VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,source_id,metric) DO UPDATE SET "
                                 "value=excluded.value, event_ms=excluded.event_ms, received_ms=excluded.received_ms, "
                                 "collector_id=excluded.collector_id, unit=excluded.unit WHERE excluded.event_ms >= latest.event_ms",
                                 (tenant, ev["source_id"], ev["metric"], ev["value"], ems, t0, cid, ev.get("unit")))
            conn.execute("UPDATE payloads SET dup_events=? WHERE payload_id=?", (dup_events, pid))
            conn.execute("UPDATE collectors SET last_seen_ms=?, last_seq=MAX(COALESCE(last_seq,0),?) WHERE id=?", (t0, payload["seq"], cid))
    except sqlite3.IntegrityError:
        db.exec("INSERT INTO rejected(tenant_id,collector_id,payload_id,reason,ts_ms) VALUES(?,?,?,?,?)",
                (tenant, cid, pid, "duplicate payload ignored (idempotent)", t0))
        return {"status": "duplicate", "payload_id": pid, "accepted_events": 0, "duplicate_events": len(evs)}
    if raw_body is not None:     # bound storage: only the newest BODY_KEEP exact bodies per collector are kept
        db.exec("UPDATE payloads SET body=NULL WHERE tenant_id=? AND collector_id=? AND body IS NOT NULL AND payload_id NOT IN "
                "(SELECT payload_id FROM payloads WHERE tenant_id=? AND collector_id=? ORDER BY received_ms DESC LIMIT ?)",
                (tenant, cid, tenant, cid, BODY_KEEP))
    out_of_order = sum(1 for _, _, late in new_events if late)
    for ev, ems, late in new_events:
        sid = ev["source_id"]
        t = ev["type"]
        if t == "sim_marker":
            c = ev.get("context", {})
            db.exec("INSERT OR IGNORE INTO sim_markers(tenant_id,collector_id,scenario,injected_ms,injected_at,received_ms,event_id) VALUES(?,?,?,?,?,?,?)",
                    (tenant, cid, c.get("scenario"), parse_iso(c["injected_at"]) * 1000.0, c["injected_at"], t0, ev["event_id"]))
            continue
        if not sid.startswith("collector:") and not sid.startswith("probe:"):
            upsert_known(tenant, sid)           # cloud-reachability probes are evidence, not topology entities
        if t == "metric":
            aiops.process_metric(tenant, cid, ev, ems, t0, bool(late))
        elif t == "alert":
            aiops.process_local_alert(tenant, cid, ev, ems, t0)
        elif t == "security_summary":
            key = (tenant, sid, "failed_logins")
            aid = aiops.ACTIVE.get(key)
            if aid:
                a = db.one("SELECT evidence FROM alerts WHERE id=?", (aid,))
                from .db import jl
                evd = jl(a["evidence"], {})
                evd["security"] = ev.get("context", {})
                db.exec("UPDATE alerts SET evidence=? WHERE id=?", (jd(evd), aid))
        elif t == "privacy_summary":
            c = ev.get("context", {})
            if (c.get("secrets_redacted") or 0) > 0:
                aiops.process_notice(tenant, cid, {**ev, "source_id": "collector:" + cid, "category": "privacy"}, ems, t0,
                                     "secrets_detected", "Secrets detected in local logs - redacted at source",
                                     f"{int(c.get('secrets_redacted', 0))} secret(s) of type {', '.join(c.get('secret_types', []))} "
                                     "were redacted on the collector; raw values never left the customer environment.",
                                     "info", {"secrets_redacted": c.get("secrets_redacted"), "types": c.get("secret_types")})
    hub.broadcast(tenant, {"type": "events", "events": [
        {"event_id": ev["event_id"], "event_time": ev["event_time"], "source_id": ev["source_id"], "metric": ev.get("metric"),
         "value": ev.get("value")} for ev, _, _ in new_events if ev["type"] == "metric"][:40]})
    return {"status": "accepted", "payload_id": pid, "accepted_events": accepted, "duplicate_events": dup_events,
            "out_of_order_events": out_of_order, "processing_ms": round(now_ms() - t0, 1)}


def upsert_known(tenant, sid):
    r = db.one("SELECT 1 FROM entities WHERE tenant_id=? AND id=?", (tenant, sid))
    if not r:
        upsert_entity(tenant, sid, _guess_type(sid), sid)


def process_heartbeat(coll, hb, via=None):
    tenant, cid = coll["tenant_id"], coll["id"]
    probs = validate_heartbeat(hb)
    if probs:
        raise Rejected(probs)
    anon = hb.get("anon") if isinstance(hb.get("anon"), dict) else None
    if config.REQUIRE_ANON and not (anon and anon.get("enabled")):
        record_violation(tenant, cid, "reject", "anonymisation_required", "collector")
        raise Rejected(["host policy requires local anonymisation (collector has not declared it enabled)"])
    findings = policy.check_heartbeat(hb)
    if anon and anon.get("enabled") and cid.startswith("col-r-") and isinstance(hb.get("topology"), dict):
        findings += policy.device_identity_findings([n.get("id", "") for n in hb["topology"].get("nodes", [])],
                                                    [n.get("label", "") for n in hb["topology"].get("nodes", [])])
    _enforce(coll, findings, "heartbeat")
    ms = now_ms()
    plat = str(hb.get("platform") or "").strip().lower()
    plat = plat if plat in PLATFORMS else ("other" if plat else None)
    iv = hb.get("interval_s")
    iv = float(iv) if isinstance(iv, (int, float)) and 1 <= iv <= 86400 else None
    db.exec("UPDATE collectors SET last_seen_ms=?, last_hb_ms=?, version=?, source_tz=?, host_id=?, proc_cpu=?, proc_mem_mb=?,"
            " buffer_depth=?, oldest_pending_s=?, link_state=?, config_version=?, retention_s=?, status='online',"
            " platform=COALESCE(?,platform), os_version=COALESCE(?,os_version), device_model=COALESCE(?,device_model),"
            " interval_s=COALESCE(?,interval_s), anon_enabled=?, anon_policy=?, anon_records=?, anon_removed=?, anon_pseudo=?,"
            " privacy=COALESCE(?,privacy), privacy_ms=COALESCE(?,privacy_ms), transport=COALESCE(?,transport), actions=COALESCE(?,actions) WHERE id=?",
            (ms, ms, hb.get("version"), hb.get("source_tz"), hb.get("host_id"), hb.get("proc_cpu_percent"), hb.get("proc_mem_mb"),
             hb.get("buffer_depth"), hb.get("oldest_pending_s"), hb.get("link_state"), hb.get("config_version"),
             hb.get("retention_s"), plat, hb.get("os_version"), hb.get("device_model"), iv,
             (1 if anon.get("enabled") else 0) if anon else None, anon.get("policy") if anon else None,
             anon.get("records") if anon else None, anon.get("removed") if anon else None, anon.get("pseudonymised") if anon else None,
             jd(hb["privacy"]) if isinstance(hb.get("privacy"), dict) else None, ms if isinstance(hb.get("privacy"), dict) else None,
             via if via in ("direct_tls", "tunnel") else None, jd(hb["actions"]) if isinstance(hb.get("actions"), list) else None, cid))
    env = hb.get("environment") if isinstance(hb.get("environment"), dict) else None
    if env:                                      # coarse network + software facts, used only for correlation with public intelligence
        net = env.get("network") or {}
        db.exec("INSERT INTO device_context(tenant_id,collector_id,asn,country,software,updated_ms) VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,collector_id) DO UPDATE SET "
                "asn=COALESCE(excluded.asn,asn), country=COALESCE(excluded.country,country), software=COALESCE(excluded.software,software), updated_ms=excluded.updated_ms",
                (tenant, cid, net.get("asn"), net.get("country"), jd(env["software"]) if env.get("software") else None, ms))
        if net.get("asn"):
            db.exec("INSERT OR IGNORE INTO intel_watch(asn,reason,added_ms,tenant_id) VALUES(?,?,?,?)", (str(net["asn"]), "connected device network", ms, tenant))
    topo = hb.get("topology")
    if topo:
        for n in topo.get("nodes", []):
            upsert_entity(tenant, n["id"], n["type"], n.get("label"))
        for s, d in topo.get("edges", []):
            db.exec("INSERT OR IGNORE INTO topology VALUES(?,?,?)", (tenant, s, d))
    upsert_entity(tenant, "collector:" + cid, "collector", coll["name"])
    return {"status": "ok", "server_time_ms": ms, "commands": remediation.pending_commands(tenant, cid)}
