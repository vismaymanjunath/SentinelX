"""Issue classification and deterministic priority (P1-P4) for incidents.

Everything here is a pure function of data SENTINEL X already stored (alerts, topology, collectors): no randomness, no
network, no model. Each result carries the exact factors and points behind it so the dashboard can show *why*.

The optional local AI (saas/ai.py) only reads these results; it never writes category or priority.
"""
from .core import SEV_ORDER, entity_info, now_ms
from .db import db, jd, jl

CATEGORIES = ("Infrastructure", "Network", "Security", "Collector Health")

NETWORK_METRICS = {"latency_ms", "packet_loss_pct", "bandwidth_mbps", "jitter_ms", "link_errors"}
SECURITY_METRICS = {"failed_logins", "secrets_detected", "auth_failures", "port_scan"}
COLLECTOR_METRICS = {"collector_offline", "buffer_depth", "link_down"}

# priority thresholds (score >= value -> level); documented in README and returned with every result
LEVELS = (("P1", 75, "Critical - respond immediately"), ("P2", 55, "High - respond now"),
          ("P3", 35, "Medium - investigate soon"), ("P4", 0, "Low - monitor"))
SEVERITY_POINTS = {"critical": 40, "warning": 20, "info": 5}
DURATION_STEPS = ((900, 20), (300, 15), (120, 10), (60, 5))       # (seconds, points)


def rank_key(level, score):
    """The single ordering rule used by every screen: P1 before P2 ... then higher score first.
    Missing triage data (legacy rows) sorts last. Use as `sorted(items, key=...)`."""
    order = {lvl: i for i, (lvl, _, _) in enumerate(LEVELS)}
    return (order.get(level, len(order)), -(score or 0))


# ------------------------------------------------------------------------------------------- classification
def classify_signal(source_id, metric, alert_category="", entity_type=""):
    """-> (category, rule). First matching rule wins; the rule text is shown to the operator."""
    if source_id.startswith("collector:") or alert_category == "collector" or metric in COLLECTOR_METRICS:
        return "Collector Health", "telemetry pipeline signal (collector liveness/buffering)"
    if alert_category == "security" or metric in SECURITY_METRICS:
        return "Security", f"security signal ({metric})"
    if entity_type == "network" or metric in NETWORK_METRICS:
        return "Network", f"network metric ({metric}) on a link/network entity" if entity_type == "network" else f"network metric ({metric})"
    return "Infrastructure", f"compute/storage/service metric ({metric})"


def classify_incident(signals):
    """Category of the incident = category of its root-cause signal; the rest are reported as secondary."""
    if not signals:
        return "Infrastructure", [], "no signals"
    root = next((s for s in signals if s.get("is_root")), signals[0])
    primary = root["category"]
    counts = {}
    for s in signals:
        counts[s["category"]] = counts.get(s["category"], 0) + 1
    secondary = sorted(c for c in counts if c != primary)
    why = f"root-cause signal '{root['metric']}' on {root['entity']} is a {primary} signal ({root['rule']})"
    if secondary:
        why += "; also contains " + ", ".join(f"{counts[c]} {c}" for c in secondary) + " signal(s)"
    return primary, secondary, why


# ------------------------------------------------------------------------------------------- prioritisation
def level_for(score):
    for lvl, floor, meaning in LEVELS:
        if score >= floor:
            return lvl, meaning
    return "P4", LEVELS[-1][2]


def prioritize(signals, category, n_affected=0, n_at_risk=0, now=None):
    """Deterministic score from severity + duration + affected devices + impact (+ corroboration, category).
    signals: dicts with severity, start_ms, end_ms (None = still active), collector_id, n_detectors."""
    now = now_ms() if now is None else now
    reasons = []

    def add(factor, points, detail):
        reasons.append({"factor": factor, "points": points, "detail": detail})

    sev = max((s["severity"] for s in signals), key=lambda x: SEV_ORDER.get(x, 0), default="info")
    n_sev = sum(1 for s in signals if s["severity"] == sev)
    add("severity", SEVERITY_POINTS.get(sev, 0), f"highest severity is {sev} ({n_sev} signal(s))")

    start = min(s["start_ms"] for s in signals)
    active = any(s["end_ms"] is None for s in signals)
    end = max(now if s["end_ms"] is None else s["end_ms"] for s in signals)
    dur = max(0.0, (end - start) / 1000.0)
    pts = next((p for sec, p in DURATION_STEPS if dur >= sec), 0)
    add("duration", pts, f"{int(dur)}s from first anomaly" + (" and still active" if active else " (all signals cleared)"))

    devices = sorted({s["collector_id"] for s in signals if s.get("collector_id")})
    pts = 15 if len(devices) >= 3 else 10 if len(devices) == 2 else 0
    add("affected_devices", pts, f"{len(devices)} device(s) report signals" + ("" if pts else " (no multi-device bonus)"))

    pts = min(15, n_affected * 5) + min(5, n_at_risk * 2)
    add("impact", pts, f"{n_affected} dependent service(s) already alerting, {n_at_risk} more downstream at risk")

    corroborated = sum(1 for s in signals if s.get("n_detectors", 1) > 1)
    pts = 5 if (corroborated or len(signals) >= 3) else 0
    add("corroboration", pts, f"{len(signals)} signal(s), {corroborated} confirmed by more than one detector"
        + ("" if pts else " (single uncorroborated signal)"))

    pts = (10 if sev == "critical" else 5) if category == "Security" else 0
    add("category", pts, "security incidents carry extra weight" if pts else f"{category}: no category weight")

    score = sum(r["points"] for r in reasons)
    level, meaning = level_for(score)
    return {"level": level, "score": score, "meaning": meaning, "reasons": reasons, "severity": sev,
            "duration_s": int(dur), "active": active, "devices": devices,
            "thresholds": {lvl: floor for lvl, floor, _ in LEVELS}}


# ------------------------------------------------------------------------------------------- integration
def _signals(tenant, alerts, info, root_entity=None, root_metric=None):
    out = []
    for a in alerts:
        e = a["source_id"]
        et = "collector" if e.startswith("collector:") else (info.get(e) or {}).get("type", "")
        cat, rule = classify_signal(e, a["metric"], a.get("category") or "", et)
        out.append({"alert_id": a["id"], "entity": e, "metric": a["metric"], "category": cat, "rule": rule,
                    "severity": a["severity"], "start_ms": a["event_ms"], "end_ms": a["cleared_ms"],
                    "collector_id": a["collector_id"], "n_detectors": len(jl(a["detected_by"], [])) or 1,
                    "is_root": e == root_entity and a["metric"] == root_metric})
    return out


def assess(tenant, alerts, root_entity, root_metric, n_affected, n_at_risk, now=None):
    info = entity_info(tenant)
    sigs = _signals(tenant, alerts, info, root_entity, root_metric)
    category, secondary, why = classify_incident(sigs)
    pr = prioritize(sigs, category, n_affected, n_at_risk, now)
    names = {c["id"]: c for c in db.all("SELECT id, name, platform FROM collectors WHERE tenant_id=?", (tenant,))}
    pr["devices"] = [{"id": d, "name": (names.get(d) or {}).get("name", d), "platform": (names.get(d) or {}).get("platform")}
                     for d in pr["devices"]]
    return {"category": category, "secondary_categories": secondary, "category_reason": why,
            "priority": {k: v for k, v in pr.items()},
            "signal_categories": {str(s["alert_id"]): s["category"] for s in sigs}}


def refresh(tenant, incident_id):
    """Re-score an open incident from its stored analysis + current alert state (duration grows, alerts clear).
    Cheap; called by the monitor loop. Returns True when the level changed."""
    inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant))
    if not inc or inc["status"] != "open":
        return False
    an = jl(inc["analysis"], {})
    alerts = db.all("SELECT * FROM alerts WHERE incident_id=?", (incident_id,))
    if not alerts or "root" not in an:
        return False
    t = assess(tenant, alerts, an["root"]["entity"], an["root"]["metric"], len(set(an.get("affected", []))),
               len(an.get("blast_radius", [])))
    old = an.get("triage", {}).get("priority", {})
    an["triage"] = {**an.get("triage", {}), **t}
    new = t["priority"]
    if old.get("score") == new["score"] and old.get("level") == new["level"]:
        return False
    db.exec("UPDATE incidents SET analysis=?, priority=?, priority_level=?, category=? WHERE id=?",
            (jd(an), new["score"], new["level"], t["category"], incident_id))
    if old.get("level") and old["level"] != new["level"]:
        ms = now_ms()
        db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail) VALUES(?,?,?,?,?,?)",
                (tenant, incident_id, ms, ms, "priority_changed",
                 f"Priority {old['level']} -> {new['level']} (score {old['score']} -> {new['score']}; "
                 f"{new['duration_s']}s elapsed)"))
        return True
    return False
