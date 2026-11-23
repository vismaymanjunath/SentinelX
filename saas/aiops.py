"""AIOps detection: rolling robust baselines (median/MAD), z-score deviation, rate-of-change, static thresholds.

Baselines are computed from *stored telemetry ordered by event time* (never arrival order) and exclude
samples that fall inside an existing anomaly interval, so a sustained anomaly cannot become the "new normal".
"""
import statistics

from common.schema import utc_iso
from .config import LOWER_IS_WORSE, METRIC_META
from .core import SEV_ORDER, hub, now_ms, thresholds
from .db import db, jd, jl

ACTIVE: dict = {}   # (tenant, source, metric) -> alert id
NORMAL: dict = {}   # consecutive normal samples while an alert is active
MIN_HISTORY = 15    # ~30 s warm-up; static thresholds still apply during warm-up (8 samples caused false alarms)

HISTORY_SQL = """SELECT e.value, e.event_ms FROM events e
 WHERE e.tenant_id=? AND e.source_id=? AND e.metric=? AND e.type='metric' AND e.event_ms < ?
 AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.tenant_id=e.tenant_id AND a.source_id=e.source_id
   AND a.metric=e.metric AND e.event_ms >= a.event_ms - 8000
   AND e.event_ms <= COALESCE(a.last_event_ms, a.event_ms))
 ORDER BY e.event_ms DESC LIMIT 60"""


def load_active():
    ACTIVE.clear()
    for a in db.all("SELECT id, tenant_id, source_id, metric FROM alerts WHERE cleared_ms IS NULL AND metric IS NOT NULL"):
        ACTIVE[(a["tenant_id"], a["source_id"], a["metric"])] = a["id"]


def baseline(tenant, source, metric, before_ms):
    rows = db.all(HISTORY_SQL, (tenant, source, metric, before_ms))
    if len(rows) < MIN_HISTORY:
        return None
    meta = METRIC_META.get(metric, dict(floor=1, min_delta=1, up_only=True))
    vals = [r["value"] for r in rows]
    med = statistics.median(vals)
    mad = statistics.median([abs(x - med) for x in vals]) * 1.4826
    sigma = max(mad, meta["floor"], 0.03 * abs(med))
    diffs = [abs(vals[i] - vals[i + 1]) for i in range(min(len(vals) - 1, 30))]
    typ = max((statistics.median(diffs) * 1.4826) if diffs else 0, meta["floor"])
    return {"median": med, "sigma": sigma, "typ_step": typ, "n": len(vals), "last": vals[0], "last_ms": rows[0]["event_ms"]}


def evaluate(tenant, source, metric, v, event_ms):
    """Pure evaluation -> dict(kinds, severity, evidence, dev)."""
    meta = METRIC_META.get(metric, dict(floor=1, min_delta=1, up_only=True))
    thr = thresholds(tenant).get(metric)
    kinds, sev, ev = [], None, {"value": round(v, 3)}

    def bump(s):
        nonlocal sev
        if sev is None or SEV_ORDER[s] > SEV_ORDER[sev]:
            sev = s

    if metric == "availability":
        if v < 0.5:
            kinds.append("availability")
            bump("critical")
        return {"kinds": kinds, "severity": sev, "evidence": ev, "dev": 0.0}
    if metric == "battery_charging":   # a state signal, never an alert on its own
        return {"kinds": [], "severity": None, "evidence": ev, "dev": 0.0}
    if metric in LOWER_IS_WORSE:       # threshold-only, lower is worse, ignored while the device is charging
        if thr:
            ev["threshold_warn"], ev["threshold_crit"] = thr["warn"], thr["crit"]
            ch = db.one("SELECT value FROM latest WHERE tenant_id=? AND source_id=? AND metric='battery_charging'", (tenant, source))
            if not (ch and ch["value"] >= 0.5):
                if v <= thr["crit"]:
                    kinds.append("threshold")
                    bump("critical")
                elif v <= thr["warn"]:
                    kinds.append("threshold")
                    bump("warning")
        return {"kinds": kinds, "severity": sev, "evidence": ev, "dev": 0.0}
    if thr:
        ev["threshold_warn"], ev["threshold_crit"] = thr["warn"], thr["crit"]
        if v >= thr["crit"]:
            kinds.append("threshold")
            bump("critical")
        elif v >= thr["warn"]:
            kinds.append("threshold")
            bump("warning")
    b = baseline(tenant, source, metric, event_ms)
    dev = 0.0
    if b:
        up = meta["up_only"]
        z = (v - b["median"]) / b["sigma"]
        dev = z if up else abs(z)
        delta = (v - b["median"]) if up else abs(v - b["median"])
        zprev = (b["last"] - b["median"]) / b["sigma"]
        persist = (zprev if up else abs(zprev)) >= 3
        ev.update(baseline_median=round(b["median"], 3), baseline_sigma=round(b["sigma"], 3), z_score=round(z, 2),
                  window_n=b["n"])
        if dev >= 4 and delta >= meta["min_delta"] and (persist or dev >= 8):
            kinds.append("baseline_deviation")
            bump("critical" if dev >= 12 else "warning")
        jump = v - b["last"]
        jump = jump if up else abs(jump)
        roc = jump / b["typ_step"]
        ev["rate_of_change"] = round(roc, 2)
        if roc >= 8 and jump >= meta["min_delta"] * 0.6 and dev >= 3:
            kinds.append("rate_of_change")
            bump("warning")
    return {"kinds": kinds, "severity": sev, "evidence": ev, "dev": dev}


def _title(source, metric, kinds):
    human = {"cpu_percent": "CPU", "memory_percent": "memory", "disk_percent": "disk", "latency_ms": "network latency",
             "packet_loss_pct": "packet loss", "bandwidth_mbps": "bandwidth", "response_ms": "response time",
             "error_rate_pct": "error rate", "availability": "availability", "failed_logins": "failed logins",
             "battery_percent": "battery level"}.get(metric, metric)
    if "availability" in kinds:
        return f"{source}: service unavailable"
    if "baseline_deviation" in kinds or "rate_of_change" in kinds:
        return f"{source}: {human} anomaly"
    return f"{source}: {human} threshold breach"


def _message(source, metric, kinds, ev):
    parts = [f"{metric}={ev['value']}"]
    if "baseline_median" in ev:
        parts.append(f"baseline {ev['baseline_median']} (σ≈{ev['baseline_sigma']}, z={ev['z_score']})")
    if "threshold" in kinds:
        parts.append(f"limits warn {ev.get('threshold_warn')}/crit {ev.get('threshold_crit')}")
    if "rate_of_change" in kinds:
        parts.append(f"rate-of-change {ev.get('rate_of_change')}× typical step")
    return "; ".join(parts)


def _create_alert(tenant, collector, source, metric, kinds, sev, ev, event_ms, received_ms, detected_by, late):
    meta = METRIC_META.get(metric, {})
    ms = now_ms()
    lateness = received_ms - event_ms
    cur = db.exec(
        "INSERT INTO alerts(tenant_id,collector_id,source_id,metric,kinds,severity,category,title,message,evidence,"
        "created_ms,created_at,event_ms,last_event_ms,detected_by,late) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (tenant, collector, source, metric, jd(kinds), sev, meta.get("category", "service"),
         _title(source, metric, kinds), _message(source, metric, kinds, ev), jd(ev), ms, utc_iso(ms / 1000),
         event_ms, event_ms, jd(detected_by), 1 if (late or lateness > 10000) else 0))
    return cur.lastrowid


NO_ANALYSIS = {"probe_ok", "probe_rtt_ms"}    # raw reachability evidence for the global-intelligence correlation: stored, never alerted on


def process_metric(tenant, collector, ev, event_ms, received_ms, is_late):
    from .correlation import correlate
    source, metric, v = ev["source_id"], ev["metric"], float(ev["value"])
    if metric in NO_ANALYSIS:
        return
    key = (tenant, source, metric)
    r = evaluate(tenant, source, metric, v, event_ms)
    kinds, sev, evid = r["kinds"], r["severity"], r["evidence"]
    aid = ACTIVE.get(key)
    if kinds:
        NORMAL[key] = 0
        if aid:
            if is_late:
                return
            a = db.one("SELECT kinds, severity, evidence, detected_by FROM alerts WHERE id=?", (aid,))
            nk = sorted(set(jl(a["kinds"], [])) | set(kinds))
            nsev = sev if SEV_ORDER[sev] > SEV_ORDER[a["severity"]] else a["severity"]
            old_ev = jl(a["evidence"], {})
            peak = max(float(old_ev.get("peak", old_ev.get("value", v))), v)
            evid = {**old_ev, **{k: x for k, x in evid.items() if k in ("value", "z_score", "rate_of_change")}, "peak": round(peak, 3)}
            if "baseline_median" not in old_ev:
                evid.update({k: x for k, x in r["evidence"].items()})
            db.exec("UPDATE alerts SET kinds=?, severity=?, evidence=?, last_event_ms=MAX(COALESCE(last_event_ms,0),?),"
                    " message=? WHERE id=?",
                    (jd(nk), nsev, jd(evid), event_ms, _message(source, metric, nk, evid), aid))
            if nsev != a["severity"]:
                correlate(tenant, aid, escalated=True)
            return
        # covering historical alert (late events)?
        if is_late:
            cov = db.one("SELECT id FROM alerts WHERE tenant_id=? AND source_id=? AND metric=? AND event_ms-8000<=? "
                         "AND COALESCE(last_event_ms,event_ms)>=?", (tenant, source, metric, event_ms, event_ms))
            if cov:
                return
        detected_by = ["central"]
        evid["peak"] = round(v, 3)
        aid = _create_alert(tenant, collector, source, metric, kinds, sev, evid, event_ms, received_ms, detected_by, is_late)
        if is_late:
            db.exec("UPDATE alerts SET cleared_ms=? WHERE id=?", (now_ms(), aid))
        else:
            ACTIVE[key] = aid
            NORMAL[key] = 0
        correlate(tenant, aid)
        hub.broadcast(tenant, {"type": "alert", "id": aid})
        return
    # no anomaly
    if aid and not is_late:
        thr = thresholds(tenant).get(metric)
        over_warn = bool(thr) and ((v <= thr["warn"]) if metric in LOWER_IS_WORSE else (v >= thr["warn"]))
        normal = (r["dev"] < 2.5) and not over_warn and (metric != "availability" or v >= 0.5)
        if metric in LOWER_IS_WORSE and not r["kinds"]:   # recovered or started charging
            normal = True
        if normal:
            NORMAL[key] = NORMAL.get(key, 0) + 1
            if NORMAL[key] >= 4:
                db.exec("UPDATE alerts SET cleared_ms=?, last_event_ms=? WHERE id=?", (now_ms(), event_ms, aid))
                ACTIVE.pop(key, None)
                hub.broadcast(tenant, {"type": "alert_cleared", "id": aid})
        else:
            NORMAL[key] = 0
            db.exec("UPDATE alerts SET last_event_ms=MAX(COALESCE(last_event_ms,0),?) WHERE id=?", (event_ms, aid))


def process_local_alert(tenant, collector, ev, event_ms, received_ms):
    """Alert computed on the collector (local AIOps). Merge with the central view of the same series."""
    from .correlation import correlate
    ctx = ev.get("context", {})
    source, metric = ev["source_id"], ev.get("metric")
    sev = ev["severity"]
    if not metric:
        return
    key = (tenant, source, metric)
    aid = ACTIVE.get(key)
    kind = "local_" + ctx.get("kind", "anomaly")
    if aid:
        a = db.one("SELECT detected_by, kinds, evidence FROM alerts WHERE id=?", (aid,))
        by = sorted(set(jl(a["detected_by"], [])) | {"local"})
        kinds = sorted(set(jl(a["kinds"], [])) | {kind})
        evd = jl(a["evidence"], {})
        evd["local"] = {k: ctx.get(k) for k in ("z_score", "baseline_mean", "baseline_std", "rate_of_change", "message") if k in ctx}
        db.exec("UPDATE alerts SET detected_by=?, kinds=?, evidence=? WHERE id=?", (jd(by), jd(kinds), jd(evd), aid))
        return
    evd = {"value": ev.get("value"), "local": {k: ctx.get(k) for k in ctx}}
    if "z_score" in ctx:
        evd["z_score"] = ctx["z_score"]
    aid = _create_alert(tenant, collector, source, metric, [kind], sev, evd, event_ms, received_ms, ["local"], False)
    db.exec("UPDATE alerts SET message=? WHERE id=?", (ctx.get("message") or f"local detector flagged {metric}", aid))
    ACTIVE[key] = aid
    NORMAL[key] = 0
    correlate(tenant, aid)
    hub.broadcast(tenant, {"type": "alert", "id": aid})


def process_notice(tenant, collector, ev, event_ms, received_ms, kind, title, message, sev, evidence):
    """Event-style alerts (security summary, secrets found) auto-clear after quiet period (monitor)."""
    from .correlation import correlate
    key = (tenant, ev["source_id"], kind)
    aid = ACTIVE.get(key)
    if aid:
        db.exec("UPDATE alerts SET last_event_ms=?, evidence=?, message=? WHERE id=?", (event_ms, jd(evidence), message, aid))
        return aid
    ms = now_ms()
    cur = db.exec(
        "INSERT INTO alerts(tenant_id,collector_id,source_id,metric,kinds,severity,category,title,message,evidence,"
        "created_ms,created_at,event_ms,last_event_ms,detected_by,late) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
        (tenant, collector, ev["source_id"], kind, jd([kind]), sev, ev.get("category", "security"), title, message,
         jd(evidence), ms, utc_iso(ms / 1000), event_ms, event_ms, jd(["local"])))
    aid = cur.lastrowid
    ACTIVE[key] = aid
    correlate(tenant, aid)
    hub.broadcast(tenant, {"type": "alert", "id": aid})
    return aid
