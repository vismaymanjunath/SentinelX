"""Causal incident intelligence: group related alerts (time + dependency graph + category) into incidents and
rank probable root causes with an explicit, inspectable score breakdown."""
from common.schema import utc_iso
from . import triage
from .core import SEV_ORDER, dependents, entity_info, graph, hop_distance, hub, now_ms, settings
from .db import db, jd, jl

CAUSE = {
    ("host", "cpu_percent"): "CPU saturation on {label}",
    ("host", "memory_percent"): "Memory exhaustion / leak on {label}",
    ("host", "disk_percent"): "Disk pressure on {label}",
    ("host", "battery_percent"): "Low battery on {label}",
    ("network", "latency_ms"): "Network latency degradation on {label}",
    ("network", "packet_loss_pct"): "Packet loss on {label}",
    ("network", "bandwidth_mbps"): "Abnormal bandwidth on {label}",
    ("service", "failed_logins"): "Brute-force / credential-stuffing activity against {label}",
    ("service", "response_ms"): "Performance degradation of {label}",
    ("service", "error_rate_pct"): "Elevated error rate in {label}",
    ("service", "availability"): "{label} is unavailable",
    ("collector", "collector_offline"): "Collector {label} offline",
}

RECOMMEND = {
    # (entity type, metric): [(action_id, title, why-template, advisory?)]
    ("host", "cpu_percent"): [("scale_up_host", "Scale out / shed load on {label}",
                               "CPU {value}% vs baseline {baseline}% is the earliest anomaly and every dependent service "
                               "slowed afterwards; adding capacity addresses the cause rather than the symptoms")],
    ("host", "memory_percent"): [("recycle_process", "Recycle the leaking process on {label}",
                                  "Memory {value}% vs baseline {baseline}% rose steadily (rate-of-change flagged); "
                                  "recycling reclaims memory before OOM-kill")],
    ("network", "latency_ms"): [("failover_wan_link", "Fail over {label} to the secondary path",
                                 "Latency {value} ms vs baseline {baseline} ms precedes the service slowdowns on "
                                 "everything that depends on this link")],
    ("network", "packet_loss_pct"): [("failover_wan_link", "Fail over {label} to the secondary path",
                                      "Packet loss {value}% vs baseline {baseline}% on the link that dependent services use")],
    ("service", "failed_logins"): [("block_login_sources", "Temporarily block offending login sources at {label}",
                                    "{value} failed logins/min vs baseline {baseline}; locally-detected burst from few sources")],
    ("service", "response_ms"): [("restart_service", "Restart {label}",
                                  "{label} response {value} ms vs baseline {baseline} ms with no upstream anomaly explaining it")],
    ("service", "error_rate_pct"): [("restart_service", "Restart {label}", "error rate {value}% vs baseline {baseline}%")],
    ("service", "availability"): [("restart_service", "Restart {label}", "{label} reports unavailable")],
}

ADVISORY = {
    ("host", "cpu_percent"): "Inspect top CPU consumers on the host (runs locally; no process data leaves the collector).",
    ("host", "memory_percent"): "Capture a heap profile locally before recycling.",
    ("host", "battery_percent"): "Connect the device to a charger; it will stop reporting if the battery is depleted.",
    ("network", "latency_ms"): "Check ISP / peering status and recent route changes.",
    ("network", "packet_loss_pct"): "Check physical link / interface error counters.",
    ("service", "failed_logins"): "Enforce MFA and rotate credentials for targeted accounts.",
    ("collector", "collector_offline"): "Check the collector host / service and its network path to the regional ingest endpoint; "
                                        "buffered metadata will be delivered after it reconnects.",
}


def _sev_w(s):
    return {"critical": 1.0, "warning": 0.6, "info": 0.2}.get(s, 0.3)


def _related(tenant, alert, inc_entities, inc_alerts, hops):
    e = alert["source_id"]
    # several collectors going silent together is one telemetry-pipeline incident, not N separate ones
    if e.startswith("collector:") and inc_alerts and all(a["source_id"].startswith("collector:") for a in inc_alerts):
        return True
    sec = alert["category"] == "security"
    if sec:  # security alerts only join incidents that already have security signals or the same entity
        if any(a["category"] == "security" for a in inc_alerts) or e in inc_entities:
            return min(hop_distance(tenant, e, x, hops) for x in inc_entities) <= hops if inc_entities else False
        return False
    if any(a["category"] == "security" for a in inc_alerts) and not any(a["category"] != "security" for a in inc_alerts):
        return False
    return any(hop_distance(tenant, e, x, hops) <= hops for x in inc_entities)


def correlate(tenant, alert_id, escalated=False):
    a = db.one("SELECT * FROM alerts WHERE id=? AND tenant_id=?", (alert_id, tenant))
    if not a or a["severity"] == "info":
        return
    st = settings(tenant)
    window = st["correlation_window_s"] * 1000
    hops = int(st["graph_hops"])
    ms = now_ms()
    if a["incident_id"]:
        analyze(tenant, a["incident_id"], reason="alert_escalated" if escalated else "update", alert_id=alert_id)
        return
    best = None
    for inc in db.all("SELECT * FROM incidents WHERE tenant_id=? AND status='open'", (tenant,)):
        alerts = db.all("SELECT * FROM alerts WHERE incident_id=?", (inc["id"],))
        active = any(x["cleared_ms"] is None for x in alerts)
        # event-time proximity so late/replayed events still group correctly
        near = active or abs((a["event_ms"] or 0) - (inc["last_alert_ms"] or 0)) <= window
        if not near:
            continue
        ents = set(jl(inc["entities"], []))
        if _related(tenant, a, ents, alerts, hops):
            best = inc
            break
    if best:
        db.exec("UPDATE alerts SET incident_id=? WHERE id=?", (best["id"], alert_id))
        analyze(tenant, best["id"], reason="alert_added", alert_id=alert_id)
    else:
        cur = db.exec("INSERT INTO incidents(tenant_id,title,status,severity,opened_ms,opened_at,updated_ms,last_alert_ms,"
                      "entities,alert_count,priority,confidence) VALUES(?,?,?,?,?,?,?,?,?,0,0,0)",
                      (tenant, a["title"], "open", a["severity"], ms, utc_iso(ms / 1000), ms, a["event_ms"], jd([a["source_id"]])))
        iid = cur.lastrowid
        db.exec("UPDATE alerts SET incident_id=? WHERE id=?", (iid, alert_id))
        db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail) VALUES(?,?,?,?,?,?)",
                (tenant, iid, ms, a["event_ms"], "opened", f"Incident opened by alert #{alert_id}: {a['title']}"))
        analyze(tenant, iid, reason="opened", alert_id=alert_id)
    hub.broadcast(tenant, {"type": "incident"})


def analyze(tenant, incident_id, reason="update", alert_id=None):
    alerts = db.all("SELECT * FROM alerts WHERE incident_id=? ORDER BY event_ms", (incident_id,))
    if not alerts:
        return
    info = entity_info(tenant)
    t0 = min(x["event_ms"] for x in alerts)
    by_ent = {}
    for x in alerts:
        by_ent.setdefault(x["source_id"], []).append(x)
    ents = list(by_ent)
    first_t = {e: min(x["event_ms"] for x in lst) for e, lst in by_ent.items()}
    tmin, tmax = min(first_t.values()), max(first_t.values())

    def label(e):
        return (info.get(e) or {}).get("label") or e

    def etype(e):
        if e.startswith("collector:"):
            return "collector"
        return (info.get(e) or {}).get("type", "service")

    def top_alert(lst):
        # most severe first; among equals prefer metrics with a known cause/remediation, then earliest
        return sorted(lst, key=lambda x: (-SEV_ORDER[x["severity"]],
                                          0 if (etype(x["source_id"]), x["metric"]) in RECOMMEND else 1, x["event_ms"]))[0]

    ranking = []
    for e in ents:
        lst = by_ent[e]
        deps_of = dependents(tenant, e)
        downstream_hit = [o for o in ents if o != e and o in deps_of]
        upstream_alerting = [o for o in ents if o != e and e in dependents(tenant, o)]
        t = 1.0 if tmax == tmin else 1.0 - (first_t[e] - tmin) / (tmax - tmin)
        d = (len(downstream_hit) / max(1, len(ents) - 1)) if len(ents) > 1 else 0.5
        u = 0.0 if upstream_alerting else 1.0
        ta = top_alert(lst)
        ev = jl(ta["evidence"], {})
        z = abs(float(ev.get("z_score", 0) or 0))
        s = _sev_w(ta["severity"]) * 0.7 + min(1.0, z / 12.0) * 0.3
        total = 0.30 * t + 0.30 * d + 0.25 * u + 0.15 * s
        ranking.append({"entity": e, "label": label(e), "score": round(total, 3),
                        "breakdown": {"temporal_precedence": round(t, 2), "downstream_coverage": round(d, 2),
                                      "no_alerting_upstream": u, "signal_strength": round(s, 2)},
                        "downstream_alerting": downstream_hit, "upstream_alerting": upstream_alerts_names(upstream_alerting),
                        "metric": ta["metric"], "alert_id": ta["id"]})
    ranking.sort(key=lambda r: -r["score"])
    top = ranking[0]
    second = ranking[1]["score"] if len(ranking) > 1 else 0.0
    margin = (top["score"] - second) / top["score"] if top["score"] else 0
    signals_n = len(alerts)
    coverage = min(1.0, signals_n / 4.0)
    local_corro = sum(1 for x in by_ent[top["entity"]] if len(jl(x["detected_by"], [])) > 1)
    conf = 0.40 * top["score"] + 0.35 * (margin if len(ranking) > 1 else 0.4) + 0.20 * coverage + 0.05 * min(1, local_corro)
    conf = round(min(0.97, max(0.2, conf)), 2)

    root_e, root_m = top["entity"], top["metric"]
    rtype = etype(root_e)
    cause = CAUSE.get((rtype, root_m), "Anomaly on {label}").format(label=label(root_e))
    rev = jl(next(x for x in alerts if x["id"] == top["alert_id"])["evidence"], {})
    base = rev.get("baseline_median", (rev.get("local") or {}).get("baseline_mean", "n/a"))
    value = rev.get("peak", rev.get("value"))

    signals = []
    for x in alerts:
        ev = jl(x["evidence"], {})
        signals.append({"alert_id": x["id"], "entity": x["source_id"], "label": label(x["source_id"]),
                        "metric": x["metric"], "kinds": jl(x["kinds"], []), "severity": x["severity"],
                        "value": ev.get("peak", ev.get("value")), "baseline": ev.get("baseline_median"),
                        "z_score": ev.get("z_score"), "t_offset_s": round((x["event_ms"] - t0) / 1000.0, 1),
                        "detected_by": jl(x["detected_by"], []), "cleared": x["cleared_ms"] is not None})
    deps_of_root = dependents(tenant, root_e)
    affected = [e for e in ents if e != root_e and e in deps_of_root]
    unrelated = [e for e in ents if e != root_e and e not in deps_of_root]
    blast = sorted(deps_of_root - set(ents))

    reasoning = []
    order = sorted(ents, key=lambda e: first_t[e])
    reasoning.append(f"{len(alerts)} alert(s) across {len(ents)} entit{'y' if len(ents)==1 else 'ies'} were grouped into one incident "
                     f"because they fall within {int(settings(tenant)['correlation_window_s'])}s of each other and are connected in the dependency graph.")
    if len(ents) > 1:
        reasoning.append("Order of first anomaly: " + " → ".join(f"{label(e)} (+{(first_t[e]-tmin)/1000:.0f}s)" for e in order) + ".")
    reasoning.append(f"{label(root_e)} ranks first (score {top['score']}): temporal precedence {top['breakdown']['temporal_precedence']}, "
                     f"downstream coverage {top['breakdown']['downstream_coverage']} "
                     f"({len(top['downstream_alerting'])} alerting dependent(s)), "
                     f"{'no alerting upstream dependency' if top['breakdown']['no_alerting_upstream'] else 'but an upstream dependency is also alerting'}.")
    if affected:
        reasoning.append("Dependency edges link the root cause to affected services: " + ", ".join(label(e) for e in affected) + ".")
    if unrelated:
        reasoning.append("Also alerting but not downstream of the root (separate contributing signals): " + ", ".join(label(e) for e in unrelated) + ".")
    if len(ranking) > 1:
        reasoning.append(f"Next hypothesis: {ranking[1]['label']} (score {ranking[1]['score']}); margin {margin:.0%}.")
    if blast:
        reasoning.append("Not alerting yet but at risk (downstream blast radius): " + ", ".join(label(e) for e in blast) + ".")

    recs = []
    for aid_, ttl, why in RECOMMEND.get((rtype, root_m), []):
        recs.append({"action": aid_, "title": ttl.format(label=label(root_e)), "target": root_e,
                     "rationale": why.format(label=label(root_e), value=value, baseline=base),
                     "risk": "low", "reversible": True, "executable": True})
    adv = ADVISORY.get((rtype, root_m))
    if adv:
        recs.append({"action": None, "title": "Operator investigation", "target": root_e, "rationale": adv,
                     "risk": "none", "reversible": True, "executable": False})
    if rtype == "service" and root_m == "response_ms" and top["downstream_alerting"] == [] and affected == []:
        pass
    sev = max((x["severity"] for x in alerts), key=lambda s: SEV_ORDER[s])
    n_aff = len(set(affected) | set(blast))
    tri = triage.assess(tenant, alerts, root_e, root_m, len(set(affected)), len(blast))
    priority = tri["priority"]["score"]
    title = f"{cause}" + (f" — {len(set(affected))} service(s) affected" if affected else "")
    coll = [e for e in ents if e.startswith("collector:")]
    if len(coll) > 1 and len(coll) == len(ents):
        title = f"{len(coll)} collectors offline"
    analysis = {"root": {"entity": root_e, "label": label(root_e), "metric": root_m, "cause": cause, "confidence": conf,
                         "score": top["score"]},
                "ranking": ranking[:5], "signals": signals, "affected": affected, "unrelated_alerting": unrelated,
                "blast_radius": blast, "reasoning": reasoning, "recommendations": recs,
                "noise_reduction": {"raw_alerts": len(alerts), "incidents": 1}, "triage": tri}
    prev = db.one("SELECT root_entity, confidence, alert_count, priority_level FROM incidents WHERE id=?", (incident_id,))
    ms = now_ms()
    last_alert_ms = max(x["event_ms"] for x in alerts)
    db.exec("UPDATE incidents SET title=?, severity=?, priority=?, priority_level=?, category=?, root_cause=?, root_entity=?,"
            " confidence=?, analysis=?, updated_ms=?, last_alert_ms=?, alert_count=?, entities=? WHERE id=?",
            (title, sev, priority, tri["priority"]["level"], tri["category"], cause, root_e, conf, jd(analysis), ms,
             last_alert_ms, len(alerts), jd(ents), incident_id))
    if prev and prev["priority_level"] and prev["priority_level"] != tri["priority"]["level"]:
        db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail) VALUES(?,?,?,?,?,?)",
                (tenant, incident_id, ms, ms, "priority_changed",
                 f"Priority {prev['priority_level']} -> {tri['priority']['level']} (score {tri['priority']['score']})"))
    if reason in ("alert_added", "alert_escalated") or (prev and prev["root_entity"] and prev["root_entity"] != root_e):
        ev_ms = next((x["event_ms"] for x in alerts if x["id"] == alert_id), t0) if alert_id else t0
        kind = "root_cause_changed" if (prev and prev["root_entity"] and prev["root_entity"] != root_e) else reason
        detail = {"alert_added": f"Alert #{alert_id} correlated into incident",
                  "alert_escalated": f"Alert #{alert_id} escalated to critical",
                  "root_cause_changed": f"Root-cause hypothesis revised to {cause} (confidence {conf})"}.get(kind, kind)
        db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail,snapshot) VALUES(?,?,?,?,?,?,?)",
                (tenant, incident_id, ms, ev_ms, kind, detail,
                 jd({"root": analysis["root"], "affected": affected, "n_alerts": len(alerts)})))
    elif reason == "opened":
        db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail,snapshot) VALUES(?,?,?,?,?,?,?)",
                (tenant, incident_id, ms, t0, "hypothesis", f"Initial hypothesis: {cause} (confidence {conf})",
                 jd({"root": analysis["root"], "affected": affected, "n_alerts": len(alerts)})))
    hub.broadcast(tenant, {"type": "incident", "id": incident_id})


def upstream_alerts_names(lst):
    return list(lst)
