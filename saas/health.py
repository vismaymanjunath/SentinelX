"""Four-state health model (Excellent / Good / Fair / Poor) with explicit reasons, stale-data downgrade
and a UTC-stamped transition history."""
from common.schema import utc_iso
from .config import LOWER_IS_WORSE
from .core import STATE_ORDER, entity_info, now_ms, settings, thresholds
from .db import db, jl

STATES = ["Excellent", "Good", "Fair", "Poor"]


def worse(a, b):
    return a if STATE_ORDER[a] >= STATE_ORDER[b] else b


def eff_settings(st, interval_s):
    """Stale/offline limits scale with a device's declared sync interval (e.g. a phone syncing every 15 min must not look
    offline after 30 s). Collectors that declare no interval, or a short one (<= 12 s), keep the configured limits."""
    iv = float(interval_s or 0)
    return {**st, "stale_after_s": max(st["stale_after_s"], 2.5 * iv), "offline_after_s": max(st["offline_after_s"], 4.0 * iv)}


def metric_state(metric, v, thr, alert_sev, age_s, st):
    """-> (state, reason or None)"""
    state, reason = "Excellent", None
    if metric == "availability":
        if v < 0.5:
            state, reason = "Poor", "service unavailable"
    elif metric in LOWER_IS_WORSE and thr:
        if v <= thr["crit"]:
            state, reason = "Poor", f"{metric}={v:.0f} ≤ critical {thr['crit']}"
        elif v <= thr["warn"]:
            state, reason = "Fair", f"{metric}={v:.0f} ≤ warning {thr['warn']}"
        elif v <= thr["good_max"]:
            state, reason = "Good", f"{metric}={v:.0f} below 'excellent' limit {thr['good_max']}"
    elif thr:
        if v >= thr["crit"]:
            state, reason = "Poor", f"{metric}={v:.1f} ≥ critical {thr['crit']}"
        elif v >= thr["warn"]:
            state, reason = "Fair", f"{metric}={v:.1f} ≥ warning {thr['warn']}"
        elif v >= thr["good_max"]:
            state, reason = "Good", f"{metric}={v:.1f} above 'excellent' limit {thr['good_max']}"
    if alert_sev == "critical" and STATE_ORDER[state] < 3:
        state, reason = "Poor", f"critical anomaly on {metric}"
    elif alert_sev == "warning" and STATE_ORDER[state] < 2:
        state, reason = "Fair", f"anomaly vs baseline on {metric}"
    if age_s > st["offline_after_s"]:
        return "Poor", f"telemetry stale: nothing received for {int(age_s)}s (> {int(st['offline_after_s'])}s)"
    if age_s > st["stale_after_s"] and STATE_ORDER[state] < 2:
        return "Fair", f"telemetry stale: last data {int(age_s)}s ago (> {int(st['stale_after_s'])}s)"
    return state, reason


def collector_state(c, st):
    st = eff_settings(st, c.get("interval_s"))
    age = (now_ms() - (c["last_seen_ms"] or 0)) / 1000.0 if c["last_seen_ms"] else 1e9
    if age > st["offline_after_s"]:
        return "Poor", "offline", [f"collector offline: no heartbeat for {int(min(age, 99999))}s (> {int(st['offline_after_s'])}s)"]
    if age > st["stale_after_s"]:
        return "Fair", "stale", [f"heartbeat delayed {int(age)}s (> {int(st['stale_after_s'])}s)"]
    reasons, state = [], "Excellent"
    if (c["buffer_depth"] or 0) > 3:
        state = "Good"
        reasons.append(f"{int(c['buffer_depth'])} payloads buffered locally (delivery backlog)")
    if c["link_state"] and c["link_state"] != "connected":
        state = worse(state, "Fair")
        reasons.append(f"link state: {c['link_state']}")
    return state, "online", reasons


def compute(tenant):
    st, thr = settings(tenant), thresholds(tenant)
    ms = now_ms()
    info = entity_info(tenant)
    active = {}
    for a in db.all("SELECT source_id, metric, severity FROM alerts WHERE tenant_id=? AND cleared_ms IS NULL AND metric IS NOT NULL", (tenant,)):
        k = (a["source_id"], a["metric"])
        if k not in active or a["severity"] == "critical":
            active[k] = a["severity"]
    ents = {}
    interval = {c["id"]: c["interval_s"] for c in db.all("SELECT id, interval_s FROM collectors WHERE tenant_id=?", (tenant,))}
    for r in db.all("SELECT * FROM latest WHERE tenant_id=?", (tenant,)):
        e = ents.setdefault(r["source_id"], {"id": r["source_id"], "type": (info.get(r["source_id"]) or {}).get("type", "service"),
                                             "label": (info.get(r["source_id"]) or {}).get("label", r["source_id"]),
                                             "state": "Excellent", "reasons": [], "metrics": {}, "collector_id": r["collector_id"]})
        age = (ms - r["received_ms"]) / 1000.0
        s, why = metric_state(r["metric"], r["value"], thr.get(r["metric"]), active.get((r["source_id"], r["metric"])), age,
                              eff_settings(st, interval.get(r["collector_id"])))
        e["metrics"][r["metric"]] = {"value": r["value"], "state": s, "event_ms": r["event_ms"], "age_s": round(age, 1),
                                     "unit": r["unit"], "reason": why}
        if STATE_ORDER[s] > STATE_ORDER[e["state"]]:
            e["state"] = s
        if why and STATE_ORDER[s] >= 2:
            e["reasons"].append(why)
    # a charging device is not penalised for a low battery level
    for e in ents.values():
        bp, ch = e["metrics"].get("battery_percent"), e["metrics"].get("battery_charging")
        if bp and ch and ch["value"] >= 0.5 and bp["reason"] and "stale" not in bp["reason"]:
            bp["state"], bp["reason"] = "Excellent", None
            worst = max((m["state"] for m in e["metrics"].values()), key=lambda x: STATE_ORDER[x])
            e["state"] = worst
            e["reasons"] = [m["reason"] for m in e["metrics"].values() if m["reason"] and STATE_ORDER[m["state"]] >= 2]
    # entities without any telemetry yet
    for eid, i in info.items():
        if eid not in ents and not eid.startswith("collector:"):
            ents[eid] = {"id": eid, "type": i["type"], "label": i["label"], "state": "Good", "reasons": ["no telemetry yet"],
                         "metrics": {}, "collector_id": None}
    colls = []
    offline_cids = set()
    for c in db.all("SELECT * FROM collectors WHERE tenant_id=?", (tenant,)):
        s, status, reasons = collector_state(c, st)
        if status == "offline":
            offline_cids.add(c["id"])
        colls.append({**{k: c[k] for k in ("id", "name", "region", "version", "source_tz", "host_id", "last_seen_ms",
                                           "proc_cpu", "proc_mem_mb", "buffer_depth", "oldest_pending_s", "link_state",
                                           "config_version", "retention_s", "last_seq", "registered_ms", "platform",
                                           "os_version", "device_model", "interval_s")},
                      "state": s, "status": status, "reasons": reasons,
                      "age_s": round((ms - c["last_seen_ms"]) / 1000.0, 1) if c["last_seen_ms"] else None})
    tenant_state, reasons = "Excellent", []
    for e in ents.values():
        if STATE_ORDER[e["state"]] > STATE_ORDER[tenant_state]:
            tenant_state = e["state"]
        if STATE_ORDER[e["state"]] >= 2:
            reasons.append({"entity": e["label"], "state": e["state"], "why": (e["reasons"] or [""])[0]})
    for c in colls:
        if STATE_ORDER[c["state"]] > STATE_ORDER[tenant_state]:
            tenant_state = c["state"]
        if STATE_ORDER[c["state"]] >= 2:
            reasons.append({"entity": "collector " + c["name"], "state": c["state"], "why": c["reasons"][0]})
    reasons.sort(key=lambda r: -STATE_ORDER[r["state"]])
    return {"state": tenant_state, "reasons": reasons[:8], "entities": ents, "collectors": colls}


def record_transitions(tenant, h=None):
    h = h or compute(tenant)
    ms = now_ms()
    cur = {r["entity_id"]: r["state"] for r in db.all("SELECT * FROM health_state WHERE tenant_id=?", (tenant,))}
    items = [("tenant", h["state"], [r["why"] for r in h["reasons"][:3]])]
    items += [(e["id"], e["state"], e["reasons"][:3]) for e in h["entities"].values()]
    items += [("collector:" + c["id"], c["state"], c["reasons"]) for c in h["collectors"]]
    for eid, state, reasons in items:
        old = cur.get(eid)
        if old != state:
            db.exec("INSERT OR REPLACE INTO health_state VALUES(?,?,?)", (tenant, eid, state))
            if old is not None or state != "Excellent":
                db.exec("INSERT INTO health_history(tenant_id,entity_id,old_state,new_state,reasons,ts_ms,ts) VALUES(?,?,?,?,?,?,?)",
                        (tenant, eid, old or "unknown", state, "; ".join(reasons) if reasons else "all signals within baseline",
                         ms, utc_iso(ms / 1000)))
