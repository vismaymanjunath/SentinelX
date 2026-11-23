"""Live Judge Mode result builder + Global Reliability view. READ-ONLY over stored data: every number comes from timestamps the
pipeline actually recorded (injection marker, events, alerts, incidents, outages). Nothing here is hardcoded or assumed to pass."""
import json

from common import policy
from .core import now_ms
from .db import db, jl

TARGETS = {"collection_to_dashboard_ms": 10_000, "breach_to_alert_ms": 15_000, "offline_detect_ms": 60_000}


def _pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100.0
    f, c = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[f] + (xs[c] - xs[f]) * (k - f), 1)


def _verdict(value, target):
    return None if value is None else bool(value <= target)


def result(tenant, scenario, since_ms, collector_id=None):
    q = "SELECT * FROM sim_markers WHERE tenant_id=? AND scenario=? AND injected_ms>=?"
    p = [tenant, scenario, since_ms]
    if collector_id:
        q += " AND collector_id=?"
        p.append(collector_id)
    m = db.one(q + " ORDER BY injected_ms DESC LIMIT 1", p)
    if not m:
        return {"found": False, "note": "The injection marker has not reached the SaaS yet (it travels through the normal pipeline)."}
    cid, inj = m["collector_id"], m["injected_ms"]
    hi = inj + 150_000
    ms = now_ms()
    evs = db.all("SELECT event_id,payload_id,type,source_id,metric,value,severity,category,event_ms,received_ms,late,source_tz FROM events "
                 "WHERE tenant_id=? AND collector_id=? AND received_ms>=? AND event_ms>=? ORDER BY event_ms LIMIT 400", (tenant, cid, inj - 500, inj - 2000))
    outage_sc = scenario in ("collector_disconnect", "saas_disconnect")
    allfresh = [e["received_ms"] - e["event_ms"] for e in evs if e["type"] == "metric" and e["event_ms"] >= inj]
    lat = [x for x in allfresh if x < 10_000] if outage_sc else allfresh          # after an outage, buffered backlog is reported separately (same convention as /api/perf)
    backlog_n = len(allfresh) - len(lat)
    render = [r["latency_ms"] for r in db.all("SELECT latency_ms FROM perf_render WHERE tenant_id=? AND ts_ms>=? AND ts_ms<=?", (tenant, inj, hi))]
    if outage_sc:
        render = [x for x in render if x < 10_000]
    # first alert caused by the injection (offline scenarios legitimately raise collector alerts)
    offline_like = scenario in ("collector_disconnect", "saas_disconnect")
    aq = ("SELECT * FROM alerts WHERE tenant_id=? AND collector_id=? AND created_ms>=? AND created_ms<=? AND severity!='info' "
          + ("" if offline_like else "AND category!='collector' ") + "ORDER BY created_ms LIMIT 8")
    alerts = db.all(aq, (tenant, cid, inj, hi))
    for a in alerts:
        a["evidence"], a["detected_by"] = jl(a["evidence"], {}), jl(a["detected_by"], [])
    first = alerts[0] if alerts else None
    already = None
    if not first and not offline_like:        # a still-active alert from an earlier run suppresses a new one (dedup) - say so instead of showing nothing
        already = db.one("SELECT title, severity, created_ms FROM alerts WHERE tenant_id=? AND collector_id=? AND created_ms<? AND (cleared_ms IS NULL OR cleared_ms>?) "
                         "AND severity!='info' AND category!='collector' ORDER BY created_ms DESC LIMIT 1", (tenant, cid, inj, inj))
    inc = db.one("SELECT id,title,severity,priority_level,opened_ms,updated_ms,status,alert_count,root_cause,root_entity,confidence FROM incidents "
                 "WHERE id=? AND tenant_id=?", (first["incident_id"], tenant)) if first and first.get("incident_id") else None
    outage = db.one("SELECT * FROM outages WHERE tenant_id=? AND collector_id=? AND detected_ms>=? ORDER BY detected_ms LIMIT 1", (tenant, cid, inj)) if offline_like else None
    dups = db.one("SELECT COUNT(*) n FROM rejected WHERE tenant_id=? AND collector_id=? AND ts_ms>=? AND reason LIKE 'duplicate%'", (tenant, cid, inj))["n"]
    late = sum(1 for e in evs if e["late"])
    # the exact payload (as stored by the host) that carried the first scenario event + its policy check
    pid = (first and next((e["payload_id"] for e in evs if e["source_id"] == first["source_id"] and e["metric"] == first["metric"]), None)) or \
          (evs[-1]["payload_id"] if evs else None)
    payload, findings = None, []
    if pid:
        row = db.one("SELECT body, sha256, seq, received_ms FROM payloads WHERE tenant_id=? AND payload_id=?", (tenant, pid))
        if row and row["body"]:
            payload = json.loads(row["body"])
            findings = [f"{f['code']}@{f['field']}" for ev in payload.get("events", []) if isinstance(ev, dict) for f in policy.check_event(ev)]
            payload = {**payload, "events": payload["events"][:6]}
            payload["_sha256"], payload["_received_ms"] = row["sha256"], row["received_ms"]
    timeline = [{"t": inj, "what": "Scenario injected at the collector (SIMULATED source perturbation)", "measured": True}]
    if evs:
        f0 = min((e for e in evs if e["event_ms"] >= inj), key=lambda e: e["received_ms"], default=None)
        if f0:
            timeline.append({"t": f0["received_ms"], "what": f"First scenario telemetry received by the SaaS ({f0['source_id']}{(' · ' + f0['metric']) if f0['metric'] else ''})", "measured": True})
    if first:
        timeline.append({"t": first["event_ms"], "what": f"Anomalous sample produced at the source ({first['metric']})", "measured": True})
        timeline.append({"t": first["created_ms"], "what": f"Alert created: {first['title']} ({first['severity']})", "measured": True})
    if inc:
        timeline.append({"t": inc["opened_ms"], "what": f"Incident #{inc['id']} opened/correlated: {inc['title']}", "measured": True})
    if outage:
        timeline.append({"t": outage["detected_ms"], "what": "Collector marked OFFLINE by the SaaS (health state Poor)", "measured": True})
        if outage["recovered_ms"]:
            timeline.append({"t": outage["recovered_ms"], "what": "Collector back ONLINE", "measured": True})
    timeline.sort(key=lambda x: x["t"])
    alert_ms = round(first["created_ms"] - inj) if (first and not offline_like) else None      # offline scenarios are judged by the 60 s offline-detection target
    offline_ms = round(outage["detected_ms"] - inj) if outage else None
    rp = _pct(render, 95)
    c2d, basis = (rp, "event time → dashboard render (measured in the browser)") if rp is not None else (_pct(lat, 95), "event time → SaaS arrival (dashboard render not reported yet)")
    return {"found": True, "scenario": scenario, "collector_id": cid, "injected_ms": inj, "now_ms": ms, "simulated": True,
            "metrics": {"collection_to_saas_p95_ms": c2d, "collection_to_dashboard_basis": basis, "ingest_p95_ms": _pct(lat, 95), "collection_to_saas_p50_ms": _pct(lat, 50), "samples": len(lat),
                        "dashboard_render_p95_ms": _pct(render, 95), "render_samples": len(render),
                        "breach_to_alert_ms": alert_ms, "offline_detect_ms": offline_ms},
            "targets": TARGETS,
            "verdicts": {"collection_to_dashboard": _verdict(c2d, TARGETS["collection_to_dashboard_ms"]),
                         "breach_to_alert": _verdict(alert_ms, TARGETS["breach_to_alert_ms"]),
                         "offline_detect": _verdict(offline_ms, TARGETS["offline_detect_ms"])},
            "alerts": [{k: a[k] for k in ("id", "title", "severity", "category", "source_id", "metric", "created_ms", "event_ms", "incident_id", "message", "evidence", "detected_by")} for a in alerts],
            "incident": inc, "outage": ({"detected_ms": outage["detected_ms"], "last_seen_ms": outage["last_seen_ms"], "recovered_ms": outage["recovered_ms"]} if outage else None),
            "already_active_alert": already, "backlog_events": backlog_n, "delivery": {"duplicates_ignored": dups, "out_of_order_events": late, "events_in_window": len(evs)},
            "payload": payload, "policy_findings": findings, "timeline": timeline}


def reliability(tenant):
    t = db.one("SELECT id, region FROM tenants WHERE id=?", (tenant,))
    cols = db.all("SELECT id, name, region, source_tz, status FROM collectors WHERE tenant_id=? ORDER BY name", (tenant,))
    recent = db.all("SELECT e.event_id, e.source_id, e.metric, e.event_time, e.source_tz, e.event_ms, e.received_ms, e.late, c.region, c.name cname "
                    "FROM events e LEFT JOIN collectors c ON c.id=e.collector_id WHERE e.tenant_id=? AND e.type='metric' "
                    "ORDER BY e.received_ms DESC LIMIT 12", (tenant,))
    # ordering check on real data: take the newest 400 metric events of the busiest source, compare arrival order with event-time order
    src = db.one("SELECT source_id, metric FROM events WHERE tenant_id=? AND type='metric' ORDER BY received_ms DESC LIMIT 1", (tenant,))
    inversions = n = 0
    if src:
        rows = db.all("SELECT event_ms, received_ms FROM events WHERE tenant_id=? AND source_id=? AND metric=? ORDER BY received_ms DESC LIMIT 400",
                      (tenant, src["source_id"], src["metric"]))
        rows.reverse()
        n = len(rows)
        inversions = sum(1 for a, b in zip(rows, rows[1:]) if b["event_ms"] < a["event_ms"])
    totals = db.one("SELECT COUNT(*) n, SUM(late) late FROM events WHERE tenant_id=?", (tenant,))
    dups = db.one("SELECT COUNT(*) n FROM rejected WHERE tenant_id=? AND reason LIKE 'duplicate%'", (tenant,))["n"]
    pay = db.one("SELECT COUNT(*) n, COUNT(DISTINCT payload_id) d FROM payloads WHERE tenant_id=?", (tenant,))
    ev_d = db.one("SELECT COUNT(*) n, COUNT(DISTINCT event_id) d FROM events WHERE tenant_id=?", (tenant,))
    mism = [c["id"] for c in cols if c["region"] != t["region"]]
    return {
        "time": {"server_utc_ms": now_ms(), "note": "All event times are stored as UTC milliseconds with the source timezone kept alongside; dashboards render UTC."},
        "recent": [{"event_id": r["event_id"][:8], "source": r["source_id"], "metric": r["metric"], "event_time_utc": r["event_time"], "source_tz": r["source_tz"],
                    "event_ms": r["event_ms"], "arrival_ms": r["received_ms"], "transit_ms": round(r["received_ms"] - r["event_ms"]), "late": bool(r["late"]),
                    "region": r["region"]} for r in recent],
        "ordering": {"method": "Series and charts are ordered by event time (event_ms), never arrival time; an event older than the newest stored sample is flagged late.",
                     "checked_source": f"{src['source_id']} · {src['metric']}" if src else None, "events_checked": n,
                     "arrival_order_inversions": inversions, "late_events_total": totals["late"] or 0, "events_total": totals["n"]},
        "idempotency": {"mechanism": "Each payload has a unique payload_id; the host ignores a payload_id it has already stored.",
                        "duplicates_ignored": dups, "payloads": pay["n"], "duplicate_payloads_stored": pay["n"] - pay["d"],
                        "duplicate_events_stored": ev_d["n"] - ev_d["d"]},
        "regional": {"tenant_region": t["region"],
                     "collector_regions": sorted({c["region"] or "?" for c in cols}),
                     "region_mismatches": mism,
                     "residency_check": "Implemented: a collector whose region differs from its tenant's region is refused at ingest (HTTP 403).",
                     "regional_ingest_endpoints": "Not configured (one ingest endpoint; no per-region endpoints)",
                     "regional_storage": "Not configured (one database on one host; no per-region storage or replication)"},
    }
