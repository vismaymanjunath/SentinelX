"""Links Scenario Lab injections to the incidents they actually produced, and orders them with the triage engine.

No priority is computed or invented here: a scenario's priority is the stored triage result (priority_level, score,
category) of the incident that its alerts were correlated into. A scenario with no matching alert yet is 'pending'."""
from .db import db
from .triage import rank_key

# which alert metrics each scenario perturbs at the source (used only to attribute alerts to the right injection when
# several scenarios run together). Scenarios that raise no alert by design are absent and stay 'pending'.
SIGNALS = {
    "cpu_spike": {"cpu_percent"},
    "memory_anomaly": {"memory_percent"},
    "latency_increase": {"latency_ms"},
    "packet_loss": {"packet_loss_pct"},
    "failed_logins": {"failed_logins"},
    "secret_logs": {"secrets_detected"},
    "collector_disconnect": {"collector_offline"},
    "correlated": {"cpu_percent", "memory_percent", "response_ms", "error_rate_pct"},
    "service_outage": {"availability", "response_ms", "error_rate_pct"},
}


def _match(tenant, marker):
    metrics = SIGNALS.get(marker["scenario"])
    if not metrics:
        return None
    ph = ",".join("?" * len(metrics))
    rows = db.all(f"SELECT DISTINCT incident_id FROM alerts WHERE tenant_id=? AND collector_id=? AND metric IN ({ph}) "
                  "AND incident_id IS NOT NULL AND severity!='info' AND created_ms>=? AND (cleared_ms IS NULL OR cleared_ms>=?)",
                  (tenant, marker["collector_id"], *sorted(metrics), marker["injected_ms"] - 2000, marker["injected_ms"]))
    best = None
    for r in rows:
        inc = db.one("SELECT id, status, priority, priority_level, category, title FROM incidents WHERE id=? AND tenant_id=?",
                     (r["incident_id"], tenant))
        if inc and (best is None or (inc["status"] != "open", rank_key(inc["priority_level"], inc["priority"])) <
                    (best["status"] != "open", rank_key(best["priority_level"], best["priority"]))):
            best = inc
    return best


def priority_view(tenant, names):
    """Ordered view of the given (active) scenario names: incident-backed first by triage rank, pending last."""
    out = []
    for i, name in enumerate(dict.fromkeys(names)):
        m = db.one("SELECT scenario, collector_id, injected_ms FROM sim_markers WHERE tenant_id=? AND scenario=? "
                   "ORDER BY injected_ms DESC LIMIT 1", (tenant, name))
        inc = _match(tenant, m) if m else None
        out.append({"name": name, "state": "incident" if inc else "pending", "incident_id": inc["id"] if inc else None,
                    "priority_level": inc["priority_level"] if inc else None,
                    "priority_score": inc["priority"] if inc else None, "category": inc["category"] if inc else None,
                    "incident_status": inc["status"] if inc else None, "incident_title": inc["title"] if inc else None,
                    "injected_ms": m["injected_ms"] if m else None, "_i": i})
    by_inc = {}
    for o in out:
        if o["incident_id"]:
            by_inc.setdefault(o["incident_id"], []).append(o["name"])
    for o in out:   # several scenarios feeding one correlated incident are flagged, not double-counted as separate incidents
        o["shared_with"] = [n for n in by_inc.get(o["incident_id"], []) if n != o["name"]]
    out.sort(key=lambda o: (o["state"] == "pending", rank_key(o["priority_level"], o["priority_score"]), -(o["injected_ms"] or 0), o["_i"]))
    for o in out:
        o.pop("_i")
    return out
