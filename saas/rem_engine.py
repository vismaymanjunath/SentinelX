"""AI-assisted remediation engine.

  catalogue of problems  ->  real telemetry evidence  ->  grounded plan  ->  human approval  ->  controlled execution  ->  verification  ->  rollback

Hard rules enforced here (server side):
  * every executable step comes from the predefined ACTIONS table; parameters are range-checked; there is no code path that executes text
    written by a model or a user. The model may only EXPLAIN (root cause, rationale, expected outcome) and may only mention steps Python proposed.
  * nothing executes before an admin approves; destructive/high-risk plans need a second, typed confirmation.
  * every step is labelled REAL (a real change/measurement), SIMULATED (the collector's test environment) or MANUAL (instructions for a human);
    a MANUAL step is never reported as executed - a human can only acknowledge it.
  * before/after values are measured by the machine that ran the action; results, failures and rollbacks are audited."""
import json
import os
import re
import statistics
import threading
import time

from . import ai as base_ai, config
from .config import LOWER_IS_WORSE
from .core import audit, entity_info, now_ms, thresholds
from .db import db, jd, jl

PLAN_TTL_MS = 30 * 60_000
STEP_TIMEOUT_MS = float(os.environ.get("SENTINEL_REM_STEP_TIMEOUT_S", 90)) * 1000     # a step nobody acknowledges is failed, never assumed done
VERIFY_DELAY_MS = float(os.environ.get("SENTINEL_REM_VERIFY_DELAY_S", 25)) * 1000
COOLDOWN_MS = float(os.environ.get("SENTINEL_REM_COOLDOWN_S", 30)) * 1000
RISK_ORDER = {"low": 0, "medium": 1, "high": 2}

# ----------------------------------------------------------------------------------------------- the ONLY things that can ever run
ACTIONS = {
    # REAL, collector-side (collector/actions.py): measured before/after on the device itself
    "reconnect_link": dict(kind="real", scope="collector", title="Reconnect the collector's secure link", risk="low", destructive=False, reversible=False,
                           what="Opens a fresh certificate-verified TLS connection from the device to the host and measures it.", params={}),
    "flush_dns_cache": dict(kind="real", scope="collector", title="Flush the device's DNS resolver cache", risk="low", destructive=False, reversible=False,
                            what="Runs the operating system's own DNS-cache flush on the device (may need an elevated session) and re-measures DNS lookup time.", params={}),
    "reprobe_connectivity": dict(kind="real", scope="collector", title="Re-measure cloud reachability from the device", risk="low", destructive=False, reversible=False,
                                 what="Diagnostic: performs real TCP+TLS handshakes to the cloud endpoints and reports which are unreachable. Changes nothing.", params={}),
    "lower_collector_footprint": dict(kind="real", scope="collector", title="Lower the collector's own resource footprint", risk="low", destructive=False, reversible=True,
                                      what="Slows the agent's collection interval and pauses cloud probes to cut its CPU use; reversible from the recorded settings.",
                                      params={"tick_s": 5.0, "probes_off": True}),
    "reduce_local_retention": dict(kind="real", scope="collector", title="Shrink the collector's local log retention", risk="medium", destructive=True, reversible=True,
                                   what="Deletes the collector's OWN old raw-log/egress rows and compacts its database to free disk. Settings can be rolled back; deleted rows cannot.",
                                   params={"retention_s": 600, "egress_retention_s": 1800}),
    # REAL, host-side (executed by this server)
    "refresh_intel_source": dict(kind="real", scope="host", title="Re-fetch a global-intelligence source now", risk="low", destructive=False, reversible=False,
                                 what="Immediately re-fetches one public feed and reports how fresh it is afterwards.", params={"source": None}),
    "rerun_correlation": dict(kind="real", scope="host", title="Re-run local-to-global correlation", risk="low", destructive=False, reversible=False,
                              what="Re-evaluates this tenant's devices against the current intelligence (use after patching to verify).", params={}),
    "check_tls_status": dict(kind="real", scope="host", title="Check the host TLS certificate", risk="low", destructive=False, reversible=False,
                             what="Reads the host certificate/CA validity (diagnostic). Renewal itself is manual because it needs a host restart.", params={}),
    # SIMULATED: the collector's sandbox/test environment (these never touch a real system)
    "scale_up_host": dict(kind="simulated", scope="collector", title="Scale out / shed load (simulated environment)", risk="low", destructive=False, reversible=True, what="", params={}),
    "recycle_process": dict(kind="simulated", scope="collector", title="Recycle leaking process (simulated environment)", risk="medium", destructive=False, reversible=True, what="", params={}),
    "failover_wan_link": dict(kind="simulated", scope="collector", title="Fail over WAN link (simulated environment)", risk="medium", destructive=False, reversible=True, what="", params={}),
    "block_login_sources": dict(kind="simulated", scope="collector", title="Block offending login sources (simulated environment)", risk="medium", destructive=False, reversible=True, what="", params={}),
    "restart_service": dict(kind="simulated", scope="collector", title="Restart service (simulated environment)", risk="medium", destructive=False, reversible=True, what="", params={}),
}
for _a in ("scale_up_host", "recycle_process", "failover_wan_link", "block_login_sources", "restart_service"):
    ACTIONS[_a]["what"] = "Runs against the collector's SIMULATED test environment. No real system is changed; the simulated telemetry reacts."
PARAM_RULES = {"lower_collector_footprint": {"tick_s": (2.0, 30.0), "probes_off": bool}, "reduce_local_retention": {"retention_s": (60, 86400), "egress_retention_s": (120, 86400)},
               "refresh_intel_source": {"source": str}}


def validate_params(action, params):
    spec = ACTIONS.get(action)
    if not spec:
        raise ValueError(f"unknown action '{action}'")
    params = params or {}
    rules = PARAM_RULES.get(action, {})
    if set(params) - set(rules):
        raise ValueError(f"unexpected parameter(s) for {action}")
    out = {}
    for k, rule in rules.items():
        if k not in params:
            continue
        v = params[k]
        if rule is bool:
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be true/false")
        elif rule is str:
            from .intel import core as ic, registry  # noqa: F401  (registers every source)
            if not isinstance(v, str) or v not in ic.SOURCES or ic.SOURCES[v].stream:
                raise ValueError(f"{k} must be one of the polled intelligence sources (live streams reconnect by themselves)")
        else:
            lo, hi = rule
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
        out[k] = v
    return out


# ----------------------------------------------------------------------------------------------- the problem catalogue
def M(text):                                                                  # manual step helper
    return {"action": None, "manual": text}


CATALOGUE = [
    {"id": "high_cpu", "title": "High CPU usage", "category": "Infrastructure", "icon": "CPU", "metrics": ["cpu_percent"], "types": ["host"],
     "description": "A host's CPU is above its warning threshold for a sustained period.",
     "steps": [M("On {device}, find the process using the CPU: Task Manager (Windows), Activity Monitor (macOS) or `top` (Linux), sorted by CPU. Do not end processes you do not recognise."),
               {"action": "scale_up_host", "when": "sandbox"}, {"action": "lower_collector_footprint", "when": "agent_busy"},
               M("If load stays high after the offending process is handled, check for runaway scheduled tasks or malware scans and consider adding capacity.")]},
    {"id": "high_memory", "title": "High memory usage / leak", "category": "Infrastructure", "icon": "RAM", "metrics": ["memory_percent"], "types": ["host"],
     "description": "Memory use is above its warning threshold and may be climbing.",
     "steps": [M("On {device}, sort processes by memory and note any that keep growing. Restart the leaking application (save work first)."),
               {"action": "recycle_process", "when": "sandbox"}, {"action": "lower_collector_footprint", "when": "agent_heavy"},
               M("If memory stays high with no single culprit, add RAM or reduce startup applications.")]},
    {"id": "disk_pressure", "title": "Disk pressure", "category": "Infrastructure", "icon": "DISK", "metrics": ["disk_percent"], "types": ["host"],
     "description": "Disk usage is above its warning threshold.",
     "steps": [{"action": "reduce_local_retention", "when": "cap:reduce_local_retention"},
               M("On {device}, free space yourself: run Disk Cleanup / Storage Sense, empty the recycle bin, and review the largest folders. The collector can only clean its own data."),
               M("Do not delete system files or folders you do not recognise.")]},
    {"id": "service_failure", "title": "Service failure / degradation", "category": "Service", "icon": "SVC", "metrics": ["response_ms", "error_rate_pct", "availability"], "types": ["service"],
     "description": "A service is slow, erroring or unavailable.",
     "steps": [M("Read {device}'s recent logs for the failing time window and confirm whether an upstream dependency is the cause (see the incident's dependency graph)."),
               {"action": "restart_service", "when": "sandbox"},
               M("If the service is still failing after a restart, roll back the most recent deployment and escalate.")]},
    {"id": "network_latency", "title": "Network latency", "category": "Network", "icon": "LAT", "metrics": ["latency_ms"], "types": ["network"],
     "description": "Round-trip latency on a link is above its warning threshold.",
     "steps": [{"action": "reprobe_connectivity", "when": "cap:reprobe_connectivity"}, {"action": "reconnect_link", "when": "cap:reconnect_link"},
               {"action": "flush_dns_cache", "when": "cap:flush_dns_cache"}, {"action": "failover_wan_link", "when": "sandbox"},
               M("Check {device}'s Wi-Fi signal or cable, restart the router if safe, and compare with another device on the same network.")]},
    {"id": "packet_loss", "title": "Packet loss", "category": "Network", "icon": "LOSS", "metrics": ["packet_loss_pct"], "types": ["network"],
     "description": "A link is dropping packets.",
     "steps": [{"action": "reprobe_connectivity", "when": "cap:reprobe_connectivity"}, {"action": "reconnect_link", "when": "cap:reconnect_link"}, {"action": "failover_wan_link", "when": "sandbox"},
               M("Move {device} closer to the access point or use a cable; if loss persists across devices, contact the ISP with the time window shown in the evidence.")]},
    {"id": "brute_force", "title": "Repeated failed logins", "category": "Security", "icon": "SEC", "metrics": ["failed_logins"], "types": ["host", "service"],
     "description": "Failed-login rate is far above normal, consistent with password guessing.",
     "steps": [{"action": "block_login_sources", "when": "sandbox"},
               M("Enforce multi-factor authentication on the targeted accounts and rotate their passwords from a trusted device."),
               M("Review whether any login succeeded after the failures in the same window.")]},
    {"id": "tls_expiry", "title": "TLS certificate expiry / validity", "category": "Security", "icon": "TLS", "metrics": [], "types": [],
     "description": "The host's TLS certificate or CA is close to expiry (collectors refuse to send over an expired certificate).",
     "steps": [{"action": "check_tls_status", "when": "always"},
               M("Restart the host (python run_host.py): it renews the server certificate automatically when fewer than 30 days remain."),
               M("If the CA itself is replaced, give each direct-TLS collector the new CA and its new SHA-256 fingerprint through a separate channel.")]},
    {"id": "vulnerable_software", "title": "Vulnerable software installed", "category": "Security", "icon": "VULN", "metrics": [], "types": [],
     "description": "A device reports installed software whose version is inside a known advisory's affected range.",
     "steps": [M("On {device}, update the affected software: {vuln_fix}"), {"action": "rerun_correlation", "when": "always"},
               M("After updating, restart the application so the new version is the one reported, then re-run the correlation to confirm the exposure is gone.")]},
    {"id": "collector_offline", "title": "Collector offline", "category": "Collector", "icon": "OFF", "metrics": [], "types": [],
     "description": "A device has stopped sending heartbeats or telemetry.",
     "steps": [M("Check that {device} is powered on, awake and online."), M("Restart the collector on that device; it buffers locally and re-sends missed data on reconnect."),
               M("If it was enrolled with a rotated key, re-enrol it from the setup page.")]},
    {"id": "collector_overloaded", "title": "Collector using too many resources", "category": "Collector", "icon": "AGT", "metrics": [], "types": [],
     "description": "The monitoring agent itself uses noticeable CPU or memory.",
     "steps": [{"action": "lower_collector_footprint", "when": "cap:lower_collector_footprint"}, {"action": "reduce_local_retention", "when": "cap:reduce_local_retention"},
               M("If it stays high, set COLLECTOR_PROBES=0 or COLLECTOR_INVENTORY=0 in the collector's environment and restart it.")]},
    {"id": "stale_global_data", "title": "Stale global-intelligence data", "category": "Intelligence", "icon": "FEED", "metrics": [], "types": [],
     "description": "A public intelligence feed is cached, stale, rate-limited or unavailable.",
     "steps": [{"action": "refresh_intel_source", "when": "always"}, M("If the source stays unavailable, check this host's internet access; some feeds rate-limit and will recover on their own.")]},
    {"id": "cloud_provider_incident", "title": "Cloud provider incident affecting a device", "category": "Cloud", "icon": "CLD", "metrics": [], "types": [],
     "description": "A provider incident matches failures the device itself observed.",
     "steps": [{"action": "refresh_intel_source", "when": "always"}, {"action": "reprobe_connectivity", "when": "cap:reprobe_connectivity"},
               M("Check the provider's status page for the affected region and, if you operate there, fail over to another region; there is nothing to fix on the device itself.")]},
    {"id": "low_battery", "title": "Low battery on a mobile device", "category": "Infrastructure", "icon": "BAT", "metrics": ["battery_percent"], "types": ["host"],
     "description": "A phone's battery is low and not charging.",
     "steps": [M("Connect {device} to a charger. It stops reporting if the battery is depleted.")]},
    {"id": "secrets_in_logs", "title": "Secrets detected in logs", "category": "Security", "icon": "KEY", "metrics": ["secrets_detected"], "types": [],
     "description": "The collector found credentials in local logs (they were redacted before leaving the device).",
     "steps": [M("Treat the exposed credential types as compromised: rotate them at their source."), M("Fix the application that writes secrets into its logs; the redacted copy never left the device.")]},
]
BYID = {p["id"]: p for p in CATALOGUE}


# ----------------------------------------------------------------------------------------------- real-telemetry evidence
def _series(tenant, source, metric, since_ms):
    return db.all("SELECT value, event_ms FROM events WHERE tenant_id=? AND source_id=? AND metric=? AND type='metric' AND event_ms>=? ORDER BY event_ms", (tenant, source, metric, since_ms))


def metric_snapshot(tenant, source, metrics, window_s=120, end_ms=None):
    """Median/last/max of each metric over a recent window - real stored telemetry only."""
    end_ms = end_ms or now_ms()
    out = {}
    for m in metrics:
        rows = [r for r in _series(tenant, source, m, end_ms - window_s * 1000) if r["event_ms"] <= end_ms]
        if rows:
            vals = [r["value"] for r in rows]
            out[m] = {"median": round(statistics.median(vals), 2), "last": round(vals[-1], 2), "max": round(max(vals), 2), "n": len(vals), "from_ms": rows[0]["event_ms"], "to_ms": rows[-1]["event_ms"]}
    return out


def _worse(metric, v, thr):
    if not thr:
        return False
    return v <= thr["warn"] if metric in LOWER_IS_WORSE else v >= thr["warn"]


def _owner(tenant, target):
    r = db.one("SELECT collector_id FROM latest WHERE tenant_id=? AND source_id=? ORDER BY event_ms DESC LIMIT 1", (tenant, target))
    if r:
        return r["collector_id"]
    a = db.one("SELECT collector_id FROM alerts WHERE tenant_id=? AND source_id=? ORDER BY event_ms DESC LIMIT 1", (tenant, target))
    return a["collector_id"] if a else None


def _collector(tenant, cid):
    c = db.one("SELECT * FROM collectors WHERE id=? AND tenant_id=?", (cid, tenant)) if cid else None
    if c:
        c["caps"] = jl(c.get("actions"), [])
        c["online"] = bool(c["last_seen_ms"] and now_ms() - c["last_seen_ms"] < 30_000)
    return c


def observed(tenant):
    """For each catalogue problem: where it is happening RIGHT NOW according to real telemetry (never invented)."""
    thr = thresholds(tenant)
    info = entity_info(tenant)
    out = {p["id"]: [] for p in CATALOGUE}
    for r in db.all("SELECT source_id, metric, value, event_ms FROM latest WHERE tenant_id=?", (tenant,)):
        for p in CATALOGUE:
            if r["metric"] in p["metrics"] and _worse(r["metric"], r["value"], thr.get(r["metric"])):
                e = info.get(r["source_id"]) or {}
                if p["types"] and e.get("type") not in p["types"]:
                    continue
                out[p["id"]].append({"target": r["source_id"], "label": e.get("label") or r["source_id"], "metric": r["metric"], "value": round(r["value"], 2), "since_ms": r["event_ms"]})
    for a in db.all("SELECT source_id, metric, severity, event_ms FROM alerts WHERE tenant_id=? AND cleared_ms IS NULL AND metric IN ('secrets_detected')", (tenant,)):
        out["secrets_in_logs"].append({"target": a["source_id"], "label": (info.get(a["source_id"]) or {}).get("label") or a["source_id"], "metric": a["metric"], "value": None, "since_ms": a["event_ms"]})
    for c in db.all("SELECT id, name, status, last_seen_ms, proc_cpu, proc_mem_mb FROM collectors WHERE tenant_id=?", (tenant,)):
        if c["status"] == "offline" and c["last_seen_ms"]:
            out["collector_offline"].append({"target": "collector:" + c["id"], "label": c["name"], "metric": "heartbeat", "value": None, "since_ms": c["last_seen_ms"]})
        elif c["status"] == "online" and ((c["proc_cpu"] or 0) >= 15 or (c["proc_mem_mb"] or 0) >= 300):
            out["collector_overloaded"].append({"target": "collector:" + c["id"], "label": c["name"], "metric": "agent_cpu_percent", "value": round(c["proc_cpu"] or 0, 1), "since_ms": c["last_seen_ms"]})
    try:
        from . import security
        t = security.tls_info()
        if (t.get("server_days_left") is not None and t["server_days_left"] < 60) or (t.get("ca_days_left") is not None and t["ca_days_left"] < 60):
            out["tls_expiry"].append({"target": "host:tls", "label": "host TLS certificate", "metric": "days_left", "value": min(x for x in (t["server_days_left"], t["ca_days_left"]) if x is not None), "since_ms": now_ms()})
    except Exception:
        pass
    seen = {}
    for c in db.all("SELECT collector_id, COUNT(*) n FROM intel_correlations WHERE tenant_id=? AND kind='vuln' AND status='confirmed' GROUP BY collector_id", (tenant,)):
        col = _collector(tenant, c["collector_id"])
        out["vulnerable_software"].append({"target": "collector:" + c["collector_id"], "label": (col or {}).get("name", c["collector_id"]), "metric": "confirmed exposures", "value": c["n"], "since_ms": now_ms()})
    for c in db.all("SELECT DISTINCT collector_id FROM intel_correlations WHERE tenant_id=? AND kind='cloud' AND status IN ('confirmed','possible')", (tenant,)):
        col = _collector(tenant, c["collector_id"])
        out["cloud_provider_incident"].append({"target": "collector:" + c["collector_id"], "label": (col or {}).get("name", c["collector_id"]), "metric": "cloud correlation", "value": None, "since_ms": now_ms()})
    try:
        from .intel import core as ic
        for s in ic.source_view():
            if s["freshness"] in ("cached", "stale", "unavailable", "rate_limited", "delayed"):
                out["stale_global_data"].append({"target": "intel:" + s["source"], "label": s["name"], "metric": "freshness", "value": s["freshness"], "since_ms": s["last_success_ms"] or now_ms()})
    except Exception:
        pass
    return out


def catalogue_view(tenant):
    obs = observed(tenant)
    return [{"id": p["id"], "title": p["title"], "category": p["category"], "icon": p["icon"], "description": p["description"], "metrics": p["metrics"],
             "observed": obs[p["id"]][:12], "observed_count": len(obs[p["id"]]),
             "steps_preview": [(ACTIONS[s["action"]]["title"], ACTIONS[s["action"]]["kind"]) if s.get("action") else ("manual instructions", "manual") for s in p["steps"]]} for p in CATALOGUE]


def incident_problem(inc):
    """Map an incident's root cause to a catalogue problem (deterministic)."""
    a = jl(inc["analysis"], {})
    root = a.get("root") or {}
    m = root.get("metric")
    for p in CATALOGUE:
        if m and m in p["metrics"]:
            return p["id"]
    return {"collector_offline": "collector_offline", "secrets_detected": "secrets_in_logs"}.get(m)


def gather(tenant, problem, target, incident_id):
    """Evidence items (E1..) built from stored telemetry, incident analysis, collector state and intelligence. Each item carries real numbers."""
    ev = []

    def add(kind, text, **vals):
        ev.append({"id": f"E{len(ev) + 1}", "kind": kind, "text": text, **vals})
    info = entity_info(tenant)
    label = (info.get(target) or {}).get("label") or target
    cid = None
    if target.startswith("collector:"):
        cid = target.split(":", 1)[1]
    elif target not in ("host:tls",) and not target.startswith("intel:"):
        cid = _owner(tenant, target)
    col = _collector(tenant, cid)
    thr = thresholds(tenant)
    for m in problem["metrics"]:
        snap = metric_snapshot(tenant, target, [m], window_s=900).get(m)
        if snap:
            t = thr.get(m) or {}
            add("metric", f"{m} on {label}: median {snap['median']}, last {snap['last']}, peak {snap['max']} over the last 15 min ({snap['n']} samples); warning threshold {t.get('warn')}, critical {t.get('crit')}",
                metric=m, **{k: snap[k] for k in ("median", "last", "max", "n")})
    for a in db.all("SELECT metric, severity, event_ms, title FROM alerts WHERE tenant_id=? AND source_id=? AND cleared_ms IS NULL ORDER BY event_ms DESC LIMIT 4", (tenant, target)):
        add("alert", f"active {a['severity']} alert on {a['metric']} since {int((now_ms() - a['event_ms']) / 60000)} min ago", metric=a["metric"], severity=a["severity"])
    if incident_id:
        inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant))
        if inc:
            an = jl(inc["analysis"], {})
            r = an.get("root") or {}
            tri = (an.get("triage") or {}).get("priority") or {}
            add("incident", f"incident #{incident_id}: priority {tri.get('level')} (score {tri.get('score')}), engine root-cause confidence {r.get('confidence')}, {inc['alert_count']} correlated alerts, "
                            f"{len(an.get('affected', []))} affected and {len(an.get('blast_radius', []))} at-risk downstream entities", priority=tri.get("level"))
            for s in (an.get("signals") or [])[:3]:
                add("signal", f"signal {s['metric']}: value {s.get('value')} vs baseline {s.get('baseline')} (z {s.get('z_score')})", metric=s["metric"], value=s.get("value"))
    if col:
        def f(v, unit=""):
            return "not reported" if v is None else f"{v}{unit}"
        add("collector", f"collector {'online' if col['online'] else 'OFFLINE'}; platform {col.get('platform') or 'unknown'}; agent CPU {f(col.get('proc_cpu'), '%')}, agent memory {f(col.get('proc_mem_mb'), ' MB')}, "
                         f"buffer depth {f(col.get('buffer_depth'))}, link {f(col.get('link_state'))}", online=col["online"])
    if problem["id"] == "vulnerable_software" and cid:
        rows = db.all("SELECT * FROM intel_correlations WHERE tenant_id=? AND collector_id=? AND kind='vuln' AND status='confirmed' ORDER BY score DESC LIMIT 6", (tenant, cid))
        for r in rows[:4]:
            e = jl(r["evidence"], {})
            sw, g = e.get("software", {}), e.get("global", {})
            add("vuln", f"{sw.get('vendor')}/{sw.get('product')} {sw.get('version')} is inside the affected range of {g.get('cve') or g.get('id')} (score {r['score']:.0f}, severity {g.get('severity')})",
                product=sw.get("product"), version=sw.get("version"))
    if problem["id"] == "tls_expiry":
        from . import security
        t = security.tls_info()
        add("tls", f"host server certificate valid for {t.get('server_days_left')} more days; CA valid for {t.get('ca_days_left')} days", server_days=t.get("server_days_left"), ca_days=t.get("ca_days_left"))
    if problem["id"] in ("network_latency", "packet_loss", "cloud_provider_incident") and cid:
        for r in db.all("SELECT * FROM intel_correlations WHERE tenant_id=? AND collector_id=? AND kind IN ('cloud','network') ORDER BY score DESC LIMIT 2", (tenant, cid)):
            g = jl(r["evidence"], {}).get("global", {})
            add("correlation", f"{r['status']} match (score {r['score']:.0f}) with global event '{g.get('title', '')[:90]}' from {g.get('source')} - not a statement of cause", status=r["status"])
    if problem["id"] == "stale_global_data" and target.startswith("intel:"):
        from .intel import core as ic
        s = next((x for x in ic.source_view() if x["source"] == target[6:]), None)
        if s:
            add("source", f"source {s['name']} is {s['freshness']}; last success {int((s['age_s'] or 0) / 60)} min ago; last error: {s['last_error']}", freshness=s["freshness"])
    return ev, cid, col, label


# ----------------------------------------------------------------------------------------------- candidate steps (deterministic)
def _applicable(cond, ctx):
    if cond in (None, "always"):
        return True
    col = ctx["col"]
    if cond == "sandbox":                                   # the simulated environment exists only on non-remote (simulated) collectors
        return bool(col and col["online"] and not str(col["id"]).startswith("col-r-"))
    if cond.startswith("cap:"):
        return bool(col and col["online"] and cond[4:] in col["caps"])
    if cond == "agent_busy":
        return bool(col and col["online"] and "lower_collector_footprint" in col["caps"] and (col.get("proc_cpu") or 0) >= 3)
    if cond == "agent_heavy":
        return bool(col and col["online"] and "lower_collector_footprint" in col["caps"] and (col.get("proc_mem_mb") or 0) >= 100)
    return False


def _fix_text(tenant, cid):
    if not cid:
        return "apply the vendor's latest update."
    parts = []
    for r in db.all("SELECT evidence FROM intel_correlations WHERE tenant_id=? AND collector_id=? AND kind='vuln' AND status='confirmed' ORDER BY score DESC LIMIT 40", (tenant, cid)):
        e = jl(r["evidence"], {})
        sw = e.get("software", {})
        key = f"{sw.get('vendor')}/{sw.get('product')} {sw.get('version')}"
        if key not in parts:
            parts.append(key)
    return ("update " + ", ".join(parts[:5]) + " to the latest release from the vendor") if parts else "apply the vendor's latest update."


def candidate_steps(tenant, problem, target, cid, col, label):
    ctx = {"col": col}
    steps = []
    n = 0
    for s in problem["steps"]:
        if s.get("action"):
            if not _applicable(s.get("when"), ctx):
                continue
            a = ACTIONS[s["action"]]
            params = dict(a["params"])
            if s["action"] == "refresh_intel_source":
                params["source"] = target[6:] if target.startswith("intel:") else ("aws" if problem["id"] == "cloud_provider_incident" else "cisa_kev")
                from .intel import core as _ic, registry as _reg  # noqa: F401
                if params["source"] not in _ic.SOURCES or _ic.SOURCES[params["source"]].stream:
                    continue                                    # a live stream (e.g. RIS) has nothing to re-fetch; it reconnects automatically
            n += 1
            steps.append({"n": n, "key": f"S{n}", "action": s["action"], "kind": a["kind"], "scope": a["scope"], "title": a["title"], "params": params, "risk": a["risk"],
                          "destructive": a["destructive"], "reversible": a["reversible"], "what": a["what"], "manual_text": None})
        else:
            n += 1
            text = s["manual"].format(device=label, vuln_fix=_fix_text(tenant, cid))
            steps.append({"n": n, "key": f"S{n}", "action": None, "kind": "manual", "scope": "human", "title": "Manual step", "params": {}, "risk": "low",
                          "destructive": False, "reversible": False, "what": "", "manual_text": text})
    return steps


def plan_risk(steps):
    exe = [s for s in steps if s["action"]]
    risk = max((s["risk"] for s in exe), key=lambda r: RISK_ORDER[r], default="low")
    needs = any(s["destructive"] or s["risk"] == "high" for s in exe)
    return risk, needs


# ----------------------------------------------------------------------------------------------- AI: explanation only
SYSTEM = ("You are an SRE assistant writing a remediation plan EXPLANATION for a human to approve. You receive evidence items (E1, E2 ...) measured from real telemetry "
          "and a fixed list of candidate steps (S1, S2 ...) already chosen by deterministic rules. You must NOT add, remove, reorder or change steps, parameters or risk, and must "
          "never write commands. Using ONLY the evidence: state the most likely root cause (cite evidence ids; if the evidence is insufficient, say so and keep it tentative), "
          "explain in one sentence per step why it helps or what it measures, and describe the expected outcome without promising results. Entities are named device-1 etc.")
SCHEMA = {"type": "object", "properties": {
    "root_cause": {"type": "string"}, "root_cause_evidence": {"type": "array", "items": {"type": "string"}}, "solution": {"type": "string"}, "expected_outcome": {"type": "string"},
    "steps": {"type": "array", "items": {"type": "object", "properties": {"key": {"type": "string"}, "rationale": {"type": "string"}}, "required": ["key", "rationale"]}},
    "caveats": {"type": "array", "items": {"type": "string"}}}, "required": ["root_cause", "root_cause_evidence", "solution", "expected_outcome", "steps"]}


def _deterministic_text(problem, ev, steps, label):
    metric_ev = [e for e in ev if e["kind"] in ("metric", "alert", "vuln", "tls", "source", "correlation", "incident")]

    # Build a richer root-cause sentence that surfaces specific evidence values
    if metric_ev:
        first = metric_ev[0]
        if first["kind"] == "metric":
            m_name = first.get("metric", "the metric")
            median = first.get("median")
            peak = first.get("max")
            vals = f"median {median}" + (f", peak {peak}" if peak and peak != median else "")
            cause = (f"{label} is showing elevated {m_name} ({vals}). "
                     "This exceeds the configured warning threshold and indicates the system is under stress. "
                     "The steps below diagnose the likely contributors and apply targeted corrective actions.")
        elif first["kind"] == "vuln":
            product = first.get("product", "a package")
            cause = (f"{label} has {product} installed at a version inside a known advisory's affected range. "
                     "The vulnerability was matched against current intelligence feeds. "
                     "The steps below re-run correlation after you apply the update to confirm the exposure is cleared.")
        elif first["kind"] == "tls":
            days = first.get("server_days")
            cause = (f"The host TLS certificate is valid for {days} more days. "
                     "Collectors refuse to send data over an expired or untrusted certificate, so this will cause collector loss if not renewed. "
                     "The diagnostic step below reads the current certificate validity; renewal itself requires a host restart.")
        elif first["kind"] == "source":
            freshness = first.get("freshness", "stale")
            cause = (f"An intelligence feed is currently {freshness}. "
                     "Stale feeds reduce detection accuracy and may miss recent advisories. "
                     "The steps below re-fetch the feed and report the new freshness status.")
        elif first["kind"] == "correlation":
            status = first.get("status", "possible")
            cause = (f"A {status} correlation was found between this device's observed failures and a cloud provider incident. "
                     "If confirmed, the issue originates outside your infrastructure and there may be nothing to fix on the device itself. "
                     "The steps below re-fetch the latest provider status and re-probe connectivity.")
        elif first["kind"] == "alert":
            severity = first.get("severity", "")
            m_name = first.get("metric", "a metric")
            cause = (f"{label} has an active {severity} alert on {m_name}. "
                     "The alert has not cleared, indicating the problem is ongoing. "
                     "The steps below take corrective action and verify that the alert resolves afterwards.")
        elif first["kind"] == "incident":
            priority = first.get("priority", "")
            pfx = f"An open {priority} incident" if priority else "An open incident"
            cause = (f"{pfx} is linked to {label}. "
                     "The incident analysis identified this as the most likely root cause entity. "
                     "The steps below address the underlying problem and verify that the incident's alerts clear.")
        else:
            cause = (f"Observed: {first['text']}. "
                     "The exact cause cannot be proven from telemetry alone; the steps below test and address the likely contributors.")
    else:
        cause = (f"No stored telemetry currently shows {problem['title'].lower()} on {label}. "
                 "This may be a recent or intermittent condition. "
                 "The steps below are still applicable and will measure the current state before and after.")

    exe = [s for s in steps if s["action"]]
    manual_count = sum(1 for s in steps if not s["action"])
    if exe:
        automated_titles = ", ".join(s["title"] for s in exe)
        sol = (f"{len(exe)} automated action(s) will run in sequence: {automated_titles}. "
               + (f"{manual_count} step(s) require a human operator." if manual_count else "")).strip()
    else:
        sol = ("No automated action is available for this target's current configuration. "
               "Follow the manual steps below; they describe exactly what to do and what to verify.")

    if problem["metrics"]:
        outcome = (f"{', '.join(problem['metrics'])} on {label} should return below its warning threshold. "
                   "The system measures this before and after execution and reports the result regardless of outcome.")
    else:
        outcome = ("No continuous metric tracks this specific condition. "
                   "Each executed step reports its own before/after measured values, "
                   "and manual steps must be confirmed by an operator.")

    return {"root_cause": cause, "root_cause_evidence": [e["id"] for e in metric_ev[:3]], "solution": sol,
            "expected_outcome": outcome,
            "rationale": {s["key"]: s["what"] or "Manual step for a human operator." for s in steps}, "caveats": []}




def ai_refine(tenant, problem, ev, steps, label, lang=None):
    """-> (text dict, ai info). Falls back to deterministic text if Ollama is down, slow or returns anything that fails validation."""
    base = _deterministic_text(problem, ev, steps, label)
    info = {"used": False, "model": config.OLLAMA_MODEL, "status": "not_used", "error": None}
    ctx = {"problem": problem["title"], "evidence": [{"id": e["id"], "text": e["text"].replace(label, "device-1")} for e in ev],
           "candidate_steps": [{"key": s["key"], "kind": s["kind"], "title": s["title"], "does": s["what"] or (s["manual_text"] or "")[:200].replace(label, "device-1"), "risk": s["risk"]} for s in steps]}
    body = "Plan inputs (JSON):\n" + json.dumps(ctx, separators=(",", ":"))
    sysmsg = SYSTEM + base_ai.sys_for(lang)[len(base_ai.SYSTEM):]
    try:
        from common.secrets import scan
        if scan(body, include_pii=True) or scan(SYSTEM, include_pii=True):
            raise base_ai.AIError("blocked", "privacy filter: the prompt matched a secret/PII pattern; nothing was sent to the model")
        av = base_ai.availability()
        if not av["available"]:
            raise base_ai.AIError("unavailable", av["reason"])
        if not base_ai._gate.acquire(blocking=False):
            raise base_ai.AIError("busy", "the local model is busy with another request")
        try:
            with base_ai._client(min(config.OLLAMA_TIMEOUT_S, 120)) as c:
                r = c.post("/api/chat", json={"model": config.OLLAMA_MODEL, "stream": False, "format": SCHEMA, "options": {"temperature": 0.1, "num_ctx": 4096},
                                              "messages": [{"role": "system", "content": sysmsg}, {"role": "user", "content": body + base_ai.lang_tail(lang)}]})
        finally:
            base_ai._gate.release()
        if r.status_code != 200:
            raise base_ai.AIError("error", f"Ollama returned HTTP {r.status_code}")
        d = json.loads(r.json()["message"]["content"])
        if not isinstance(d, dict) or not isinstance(d.get("root_cause"), str) or not d["root_cause"].strip() or not isinstance(d.get("solution"), str):
            raise base_ai.AIError("malformed", "model JSON is missing required fields")
        ids = {e["id"] for e in ev}
        cited = [x for x in (d.get("root_cause_evidence") or []) if isinstance(x, str) and x in ids]
        rc = base_ai._clean(d["root_cause"], 600)
        if sum(ch.isalpha() for ch in re.sub(r"\bE\d+\b", "", rc)) < 20:      # e.g. the model answered just "E1, E2": not an explanation
            raise base_ai.AIError("malformed", "the model's root-cause text was not an explanation; using the deterministic text")
        if not cited:
            rc = "Hypothesis (no supporting evidence cited): " + rc
        keys = {s["key"] for s in steps}
        rat = {x["key"]: base_ai._clean(x["rationale"], 280) for x in (d.get("steps") or []) if isinstance(x, dict) and x.get("key") in keys and isinstance(x.get("rationale"), str)}
        text = {"root_cause": re.sub(r"\bdevice-1\b", label, rc, flags=re.I), "root_cause_evidence": cited, "solution": re.sub(r"\bdevice-1\b", label, base_ai._clean(d["solution"], 600), flags=re.I),
                "expected_outcome": re.sub(r"\bdevice-1\b", label, base_ai._clean(d.get("expected_outcome") or base["expected_outcome"], 500), flags=re.I),
                "rationale": {**base["rationale"], **{k: re.sub(r"\bdevice-1\b", label, v, flags=re.I) for k, v in rat.items()}},
                "caveats": [base_ai._clean(x, 240) for x in (d.get("caveats") or []) if isinstance(x, str)][:4]}
        info.update(used=True, status="ready")
        return text, info
    except base_ai.AIError as e:
        info.update(status=e.status, error=e.msg)
    except (ValueError, KeyError, TypeError):
        info.update(status="malformed", error="the model's reply was not the expected JSON; using the deterministic plan")
    except Exception as e:
        info.update(status="error", error=f"{type(e).__name__}")
    return base, info


# ----------------------------------------------------------------------------------------------- plans
def _row(tenant, pid):
    return db.one("SELECT * FROM rem_plans WHERE id=? AND tenant_id=?", (pid, tenant))


def view(tenant, pid):
    p = _row(tenant, pid)
    if not p:
        return None
    for k in ("evidence", "ai", "before_metrics", "after_metrics", "verification", "summary"):
        p[k] = jl(p[k], None)
    p["needs_confirm"] = bool(p["needs_confirm"])
    steps = db.all("SELECT * FROM rem_steps WHERE plan_id=? ORDER BY n", (pid,))
    for s in steps:
        for k in ("params", "result", "before_state", "after_state", "rollback_result"):
            s[k] = jl(s[k], None)
        s["destructive"], s["reversible"] = bool(s["destructive"]), bool(s["reversible"])
    p["steps"] = steps
    p["expired"] = p["status"] == "proposed" and now_ms() - p["created_ms"] > PLAN_TTL_MS
    p["audit"] = db.all("SELECT ts_ms, actor, action, detail FROM audit WHERE tenant_id=? AND detail LIKE ? ORDER BY id", (tenant, f"plan#{pid} %"))
    # One-line diagnosis summary for UI card headers
    ev_items = (p["evidence"] or {}).get("items") or []
    metric_item = next((e for e in ev_items if e.get("kind") == "metric"), None)
    if metric_item:
        m = metric_item.get("metric", "")
        last = metric_item.get("last")
        p["diagnosis_summary"] = f"{m} at {last}" if last is not None else m
    elif ev_items:
        p["diagnosis_summary"] = ev_items[0].get("text", "")[:100]
    else:
        p["diagnosis_summary"] = ""
    return p




def list_plans(tenant, limit=60):
    return [view(tenant, r["id"]) for r in db.all("SELECT id FROM rem_plans WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (tenant, limit))]


def generate(tenant, user, role, problem_id, target=None, incident_id=None, lang=None):
    if role != "admin":
        raise PermissionError("generating a remediation plan requires the admin role")
    if incident_id and not problem_id:
        inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant))
        if not inc:
            raise LookupError("incident not found")
        problem_id = incident_problem(inc)
        target = target or inc["root_entity"]
        if not problem_id:
            raise ValueError("this incident does not map to a catalogue problem; pick a problem from the catalogue")
    problem = BYID.get(problem_id or "")
    if not problem:
        raise ValueError("unknown problem")
    if incident_id and not db.one("SELECT 1 FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant)):
        raise LookupError("incident not found")
    if not target:
        obs = observed(tenant)[problem["id"]]
        if not obs:
            raise ValueError("this problem is not currently observed in your telemetry; choose a target explicitly")
        target = obs[0]["target"]
    if not isinstance(target, str) or len(target) > 80:
        raise ValueError("invalid target")
    known = set(entity_info(tenant)) | {f"collector:{c['id']}" for c in db.all("SELECT id FROM collectors WHERE tenant_id=?", (tenant,))} | {"host:tls"}
    if target not in known and not target.startswith("intel:"):
        raise LookupError("target not found in this tenant")
    ev, cid, col, label = gather(tenant, problem, target, incident_id)
    steps = candidate_steps(tenant, problem, target, cid, col, label)
    if not steps:
        raise ValueError("no applicable action or instruction for this target")
    risk, needs = plan_risk(steps)
    sync_ai = os.environ.get("SENTINEL_REM_AI_SYNC") == "1"
    if sync_ai:
        text, ai_info = ai_refine(tenant, problem, ev, steps, label)
    else:                                   # show the evidence-based plan at once; the local model refines the wording in the background
        text = _deterministic_text(problem, ev, steps, label)
        ai_info = {"used": False, "model": config.OLLAMA_MODEL, "status": "pending", "error": None}
    ms = now_ms()
    cur = db.exec("INSERT INTO rem_plans(tenant_id,problem_id,incident_id,target,collector_id,title,status,root_cause,solution,expected_outcome,risk,needs_confirm,evidence,ai,created_by,created_ms) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (tenant, problem["id"], incident_id, target, cid, f"{problem['title']} — {label}", "proposed", text["root_cause"], text["solution"], text["expected_outcome"], risk, 1 if needs else 0,
                   jd({"items": ev, "cited": text["root_cause_evidence"], "caveats": text["caveats"]}), jd(ai_info), user, ms))
    pid = cur.lastrowid
    for s in steps:
        db.exec("INSERT INTO rem_steps(plan_id,tenant_id,n,key,action,kind,scope,title,rationale,params,risk,destructive,reversible,status,manual_text) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, tenant, s["n"], s["key"], s["action"], s["kind"], s["scope"], s["title"], text["rationale"].get(s["key"], s["what"]), jd(s["params"]), s["risk"], int(s["destructive"]),
                 int(s["reversible"]), "manual_pending" if s["kind"] == "manual" else "pending", s["manual_text"]))
    audit(tenant, user, "rem.plan.generated", f"plan#{pid} problem={problem['id']} target={target} steps={len(steps)} risk={risk} ai={ai_info['status']}")
    if not sync_ai:
        threading.Thread(target=_refine_bg, args=(tenant, pid, problem, ev, steps, label, lang), daemon=True, name=f"rem-ai-{pid}").start()
    return view(tenant, pid)


def _refine_bg(tenant, pid, problem, ev, steps, label, lang=None):
    try:
        text, info = ai_refine(tenant, problem, ev, steps, label, lang)
    except Exception as e:
        text, info = None, {"used": False, "model": config.OLLAMA_MODEL, "status": "error", "error": type(e).__name__}
    try:
        with db.lock:
            row = db.one("SELECT status FROM rem_plans WHERE id=?", (pid,))
            if row and row["status"] == "proposed" and text and info.get("used"):
                db.exec("UPDATE rem_plans SET root_cause=?, solution=?, expected_outcome=? WHERE id=?", (text["root_cause"], text["solution"], text["expected_outcome"], pid))
                for k, v in text["rationale"].items():
                    db.exec("UPDATE rem_steps SET rationale=? WHERE plan_id=? AND key=?", (v, pid, k))
                cur = jl(db.one("SELECT evidence FROM rem_plans WHERE id=?", (pid,))["evidence"], {})
                cur["cited"], cur["caveats"] = text["root_cause_evidence"], text["caveats"]
                db.exec("UPDATE rem_plans SET evidence=? WHERE id=?", (jd(cur), pid))
            db.exec("UPDATE rem_plans SET ai=? WHERE id=?", (jd(info), pid))
    except Exception:
        pass


def reject(tenant, user, role, pid, note=""):
    if role != "admin":
        raise PermissionError("rejection requires the admin role")
    p = _row(tenant, pid)
    if not p:
        raise LookupError("plan not found")
    if p["status"] != "proposed":
        raise ValueError(f"cannot reject a plan in status '{p['status']}'")
    db.exec("UPDATE rem_plans SET status='rejected', decided_by=?, decided_ms=?, decision_note=? WHERE id=?", (user, now_ms(), str(note)[:200], pid))
    db.exec("UPDATE rem_steps SET status='not_executed' WHERE plan_id=? AND status IN ('pending','manual_pending')", (pid,))
    audit(tenant, user, "rem.plan.rejected", f"plan#{pid} nothing was executed note={str(note)[:80]}")
    return view(tenant, pid)


def _policy(tenant, plan, steps):
    col = _collector(tenant, plan["collector_id"])
    for s in steps:
        if not s["action"]:
            continue
        if s["action"] not in ACTIONS:
            raise ValueError(f"step {s['key']}: action is not on the predefined catalogue")
        validate_params(s["action"], jl(s["params"], {}))
        if s["scope"] == "collector":
            if not col or not col["online"]:
                raise ValueError(f"step {s['key']}: the owning collector is offline, so it cannot execute or acknowledge")
            if s["kind"] == "real" and s["action"] not in col["caps"]:
                raise ValueError(f"step {s['key']}: this collector build does not support {s['action']}")
            if s["kind"] == "simulated" and str(col["id"]).startswith("col-r-"):
                raise ValueError(f"step {s['key']}: simulated actions are not available on real devices")
        recent = db.one("SELECT 1 FROM rem_steps WHERE tenant_id=? AND action=? AND plan_id!=? AND status IN ('running','succeeded') AND finished_ms>? AND plan_id IN "
                        "(SELECT id FROM rem_plans WHERE collector_id=?)", (tenant, s["action"], plan["id"], now_ms() - COOLDOWN_MS, plan["collector_id"]))
        if recent:
            raise ValueError(f"step {s['key']}: the same action ran on this collector in the last {int(COOLDOWN_MS // 1000)}s (cooldown)")


def approve(tenant, user, role, pid, confirm_text=None, note=""):
    if role != "admin":
        raise PermissionError("approval requires the admin role")
    p = _row(tenant, pid)
    if not p:
        raise LookupError("plan not found")
    if p["status"] != "proposed":
        raise ValueError(f"cannot approve a plan in status '{p['status']}'")
    if now_ms() - p["created_ms"] > PLAN_TTL_MS:
        db.exec("UPDATE rem_plans SET status='expired' WHERE id=?", (pid,))
        audit(tenant, user, "rem.plan.expired", f"plan#{pid} older than {PLAN_TTL_MS // 60000} min: generate a fresh plan from current telemetry")
        raise ValueError("this plan is older than 30 minutes; generate a new one from current telemetry")
    steps = db.all("SELECT * FROM rem_steps WHERE plan_id=? ORDER BY n", (pid,))
    if p["needs_confirm"] and (confirm_text or "").strip() != "CONFIRM":
        destructive = [s["title"] for s in steps if s["destructive"] or s["risk"] == "high"]
        raise ValueError("additional confirmation required: this plan contains destructive or high-risk step(s) (" + "; ".join(destructive) + "). Type CONFIRM to proceed.")
    _policy(tenant, p, steps)
    target = p["target"]
    before = {m: v for m, v in metric_snapshot(tenant, target, BYID[p["problem_id"]]["metrics"], window_s=90).items()} if BYID[p["problem_id"]]["metrics"] else {}
    ms = now_ms()
    db.exec("UPDATE rem_plans SET status='running', decided_by=?, decided_ms=?, decision_note=?, started_ms=?, before_metrics=? WHERE id=?", (user, ms, str(note)[:200], ms, jd(before), pid))
    audit(tenant, user, "rem.plan.approved", f"plan#{pid} approved{' with typed confirmation' if p['needs_confirm'] else ''} steps={len(steps)} risk={p['risk']}")
    _advance(tenant, pid)
    return view(tenant, pid)


def _set_step(sid, **kw):
    sets = ",".join(f"{k}=?" for k in kw)
    db.exec(f"UPDATE rem_steps SET {sets} WHERE id=?", (*[jd(v) if isinstance(v, (dict, list)) else v for v in kw.values()], sid))


def _advance(tenant, pid):
    """Start the next pending executable step (steps run strictly one after another; manual steps never block or count as executed)."""
    p = _row(tenant, pid)
    if not p or p["status"] != "running":
        return
    steps = db.all("SELECT * FROM rem_steps WHERE plan_id=? ORDER BY n", (pid,))
    if any(s["status"] == "running" for s in steps):
        return
    nxt = next((s for s in steps if s["status"] == "pending"), None)
    if nxt is None:
        _finish(tenant, p, steps)
        return
    ms = now_ms()
    if nxt["scope"] == "host":
        _set_step(nxt["id"], status="running", started_ms=ms)
        audit(tenant, p["decided_by"], "rem.step.started", f"plan#{pid} {nxt['key']} {nxt['action']} (host-side, real)")
        threading.Thread(target=_run_host_step, args=(tenant, pid, nxt["id"], nxt["action"], jl(nxt["params"], {})), daemon=True, name="rem-host").start()
        return
    import uuid
    cmd = str(uuid.uuid4())
    db.exec("INSERT INTO commands(id,tenant_id,collector_id,remediation_id,kind,action,target,status,created_ms,plan_step_id,params) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (cmd, tenant, p["collector_id"], 0, "execute", nxt["action"], p["target"], "queued", ms, nxt["id"], nxt["params"]))
    _set_step(nxt["id"], status="running", started_ms=ms, command_id=cmd)
    audit(tenant, p["decided_by"], "rem.step.started", f"plan#{pid} {nxt['key']} {nxt['action']} ({nxt['kind']}) queued for collector {p['collector_id']}")


def _run_host_step(tenant, pid, sid, action, params):
    from .intel import core as ic, correlate
    ok, detail, before, after = False, "", None, None
    try:
        if action == "refresh_intel_source":
            src = ic.SOURCES[params["source"]]
            b = next(x for x in ic.source_view() if x["source"] == src.id)
            r = ic.run_once(src)
            a = next(x for x in ic.source_view() if x["source"] == src.id)
            ok = bool(r.get("ok"))
            before, after = {"freshness": b["freshness"], "events_stored": b["events_stored"], "age_s": b["age_s"]}, {"freshness": a["freshness"], "events_stored": a["events_stored"], "age_s": a["age_s"]}
            detail = f"re-fetched {src.name}: {b['freshness']} -> {a['freshness']}" if ok else f"the fetch failed: {r.get('error')}"
        elif action == "rerun_correlation":
            b = db.one("SELECT COUNT(*) n FROM intel_correlations WHERE tenant_id=? AND status='confirmed'", (tenant,))["n"]
            r = correlate.run(tenant, enrich=True)
            a = db.one("SELECT COUNT(*) n FROM intel_correlations WHERE tenant_id=? AND status='confirmed'", (tenant,))["n"]
            ok, before, after = True, {"confirmed_matches": b}, {"confirmed_matches": a}
            detail = f"re-evaluated devices against current intelligence: confirmed matches {b} -> {a}"
        elif action == "check_tls_status":
            from . import security
            t = security.tls_info()
            ok, before, after = True, None, {"server_days_left": t.get("server_days_left"), "ca_days_left": t.get("ca_days_left")}
            detail = f"host server certificate valid {t.get('server_days_left')} more days, CA {t.get('ca_days_left')} days (diagnostic only)"
        else:
            detail = "unknown host action"
    except Exception as e:
        detail = f"error: {type(e).__name__}: {str(e)[:120]}"
    step_result(tenant, None, {"plan_step_id": sid, "kind": "execute"}, ok, detail, before, after)


def step_result(tenant, collector_id, cmd, ok, detail, before, after):
    """Called when a collector acknowledges a command or a host step ends. Records the outcome, then continues, fails, or finishes the plan."""
    s = db.one("SELECT * FROM rem_steps WHERE id=? AND tenant_id=?", (cmd["plan_step_id"], tenant))
    if not s:
        return
    p = _row(tenant, s["plan_id"])
    ms = now_ms()
    actor = f"collector:{collector_id}" if collector_id else "system"
    detail = str(detail)[:400]
    if cmd["kind"] == "rollback":
        _set_step(s["id"], rollback_status="rolled_back" if ok else "rollback_failed", rollback_result={"ok": ok, "detail": detail, "after": after})
        audit(tenant, actor, "rem.step.rolled_back" if ok else "rem.step.rollback_failed", f"plan#{p['id']} {s['key']} {s['action']}: {detail}")
        _advance_rollback(tenant, p["id"])
        return
    if s["status"] != "running":
        return                                           # late/duplicate acknowledgement (e.g. after a timeout): ignored
    _set_step(s["id"], status="succeeded" if ok else "failed", finished_ms=ms, result={"ok": ok, "detail": detail}, before_state=before, after_state=after)
    audit(tenant, actor, "rem.step.succeeded" if ok else "rem.step.failed", f"plan#{p['id']} {s['key']} {s['action']}: {detail}")
    if ok:
        _advance(tenant, p["id"])
    else:
        db.exec("UPDATE rem_steps SET status='skipped' WHERE plan_id=? AND status='pending'", (p["id"],))
        db.exec("UPDATE rem_plans SET status='failed', finished_ms=? WHERE id=?", (ms, p["id"]))
        audit(tenant, "system", "rem.plan.failed", f"plan#{p['id']} stopped at {s['key']}; remaining steps skipped; earlier reversible steps can be rolled back")


def _finish(tenant, p, steps):
    ms = now_ms()
    done = [s for s in steps if s["status"] == "succeeded"]
    manual = [s for s in steps if s["kind"] == "manual" and s["status"] == "manual_pending"]
    db.exec("UPDATE rem_plans SET status='executed', finished_ms=?, summary=? WHERE id=?",
            (ms, jd({"executed_steps": len(done), "manual_pending": len(manual),
                     "note": "manual steps are instructions for a human; they are never recorded as executed by the system"}), p["id"]))
    audit(tenant, "system", "rem.plan.executed", f"plan#{p['id']} {len(done)} step(s) executed, {len(manual)} manual step(s) still need a human")


def manual_done(tenant, user, role, pid, sid, note=""):
    if role != "admin":
        raise PermissionError("acknowledging a manual step requires the admin role")
    s = db.one("SELECT * FROM rem_steps WHERE id=? AND plan_id=? AND tenant_id=?", (sid, pid, tenant))
    if not s or s["kind"] != "manual":
        raise LookupError("manual step not found")
    p = _row(tenant, pid)
    if p["status"] not in ("running", "executed", "failed"):
        raise ValueError("a manual step can only be acknowledged after the plan was approved")
    if s["status"] != "manual_pending":
        raise ValueError("already acknowledged")
    _set_step(sid, status="manual_done", manual_by=user, manual_ms=now_ms(), result={"ok": None, "detail": f"acknowledged by {user}; performed by a human, not verified by the system. {str(note)[:120]}"})
    audit(tenant, user, "rem.step.manual_acknowledged", f"plan#{pid} {s['key']} acknowledged by a human (not executed by the system)")
    return view(tenant, pid)


# ----------------------------------------------------------------------------------------------- rollback
def rollback(tenant, user, role, pid):
    if role != "admin":
        raise PermissionError("rollback requires the admin role")
    p = _row(tenant, pid)
    if not p:
        raise LookupError("plan not found")
    if p["status"] not in ("executed", "failed"):
        raise ValueError(f"cannot roll back a plan in status '{p['status']}'")
    steps = db.all("SELECT * FROM rem_steps WHERE plan_id=? ORDER BY n DESC", (pid,))
    todo = [s for s in steps if s["status"] == "succeeded" and s["reversible"] and not s["rollback_status"]]
    if not todo:
        raise ValueError("nothing can be rolled back: no executed step is reversible")
    col = _collector(tenant, p["collector_id"])
    if not col or not col["online"]:
        raise ValueError("the owning collector is offline; it must be online to roll back")
    db.exec("UPDATE rem_plans SET status='rolling_back' WHERE id=?", (pid,))
    audit(tenant, user, "rem.plan.rollback_requested", f"plan#{pid} reversing {len(todo)} step(s); irreversible: {[s['key'] for s in steps if s['status'] == 'succeeded' and not s['reversible']]}")
    _advance_rollback(tenant, pid)
    return view(tenant, pid)


def _advance_rollback(tenant, pid):
    p = _row(tenant, pid)
    if not p or p["status"] != "rolling_back":
        return
    steps = db.all("SELECT * FROM rem_steps WHERE plan_id=? ORDER BY n DESC", (pid,))
    if any(s["rollback_status"] == "running" for s in steps):
        return
    failed = [s for s in steps if s["rollback_status"] == "rollback_failed"]
    nxt = next((s for s in steps if s["status"] == "succeeded" and s["reversible"] and not s["rollback_status"]), None)
    if failed:
        db.exec("UPDATE rem_plans SET status='rollback_failed' WHERE id=?", (pid,))
        audit(tenant, "system", "rem.plan.rollback_failed", f"plan#{pid} a step could not be reversed: follow the manual guidance")
        return
    if nxt is None:
        db.exec("UPDATE rem_plans SET status='rolled_back', rolled_back_ms=? WHERE id=?", (now_ms(), pid))
        audit(tenant, "system", "rem.plan.rolled_back", f"plan#{pid} every reversible step was restored")
        return
    import uuid
    cmd = str(uuid.uuid4())
    db.exec("INSERT INTO commands(id,tenant_id,collector_id,remediation_id,kind,action,target,status,created_ms,plan_step_id,params) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (cmd, tenant, p["collector_id"], 0, "rollback", nxt["action"], p["target"], "queued", now_ms(), nxt["id"], "{}"))
    _set_step(nxt["id"], rollback_status="running", command_id=cmd)
    audit(tenant, "system", "rem.step.rollback_started", f"plan#{pid} {nxt['key']} {nxt['action']}")


# ----------------------------------------------------------------------------------------------- supervision: timeouts + verification
def tick(tenant):
    ms = now_ms()
    for s in db.all("SELECT s.*, p.status pstatus FROM rem_steps s JOIN rem_plans p ON p.id=s.plan_id WHERE s.tenant_id=? AND ((s.status='running' AND p.status='running') OR s.rollback_status='running')", (tenant,)):
        if s["started_ms"] and s["status"] == "running" and ms - s["started_ms"] > STEP_TIMEOUT_MS:
            if s["command_id"]:
                db.exec("UPDATE commands SET status='cancelled' WHERE id=? AND status IN ('queued','delivered')", (s["command_id"],))
            step_result(tenant, None, {"plan_step_id": s["id"], "kind": "execute"}, False, "no acknowledgement within the step timeout: the step was cancelled and NOT assumed to have run", None, None)
    for s in db.all("SELECT s.id, s.plan_id, s.command_id FROM rem_steps s WHERE s.tenant_id=? AND s.rollback_status='running'", (tenant,)):
        c = db.one("SELECT created_ms FROM commands WHERE id=?", (s["command_id"],))
        if c and ms - c["created_ms"] > STEP_TIMEOUT_MS:                     # a rollback that is never acknowledged is reported as failed, not assumed done
            db.exec("UPDATE commands SET status='cancelled' WHERE id=? AND status IN ('queued','delivered')", (s["command_id"],))
            step_result(tenant, None, {"plan_step_id": s["id"], "kind": "rollback"}, False, "no acknowledgement within the timeout: the rollback was cancelled and NOT assumed to have run", None, None)
    for p in db.all("SELECT id, finished_ms, rolled_back_ms, status, target, problem_id, before_metrics, verification FROM rem_plans WHERE tenant_id=? AND status IN ('executed','rolled_back','failed') AND verification IS NULL", (tenant,)):
        t0 = p["rolled_back_ms"] or p["finished_ms"]
        if not t0 or ms - t0 < VERIFY_DELAY_MS:
            continue
        verify(tenant, p, t0)
    for p in db.all("SELECT id FROM rem_plans WHERE tenant_id=? AND status='proposed' AND created_ms<?", (tenant, ms - PLAN_TTL_MS)):
        db.exec("UPDATE rem_plans SET status='expired' WHERE id=?", (p["id"],))
        audit(tenant, "system", "rem.plan.expired", f"plan#{p['id']} was never approved")


def verify(tenant, p, t0):
    """Compare the target's real telemetry before the plan with telemetry after it finished (median over fresh samples)."""
    problem = BYID.get(p["problem_id"])
    metrics = problem["metrics"] if problem else []
    before = jl(p["before_metrics"], {}) or {}
    after = {m: v for m, v in metric_snapshot(tenant, p["target"], metrics, window_s=int((now_ms() - t0 - 5000) / 1000) or 30).items()} if metrics else {}
    if metrics and (not after or all(v["n"] < 3 for v in after.values())) and now_ms() - t0 < 150_000:
        return                                            # wait for enough fresh samples
    thr = thresholds(tenant)
    rows, verdicts = [], []
    for m in metrics:
        b, a = before.get(m), after.get(m)
        if not b or not a:
            continue
        lower_worse = m in LOWER_IS_WORSE
        delta = round(a["median"] - b["median"], 2)
        improved = delta > 0 if lower_worse else delta < 0
        t = thr.get(m) or {}
        goal = (a["median"] > t.get("warn", 0)) if lower_worse else (a["median"] < t.get("warn", 1e18))
        small = abs(delta) < max(1.0, 0.03 * abs(b["median"]))
        verdicts.append("no_change" if small else ("improved" if improved else "worse"))
        rows.append({"metric": m, "before_median": b["median"], "after_median": a["median"], "delta": delta, "samples_after": a["n"], "below_warning_threshold": bool(goal)})
    overall = ("improved" if "improved" in verdicts and "worse" not in verdicts else "worse" if "worse" in verdicts else "no_change") if verdicts else "not_measurable"
    steps = db.all("SELECT action, kind, status FROM rem_steps WHERE plan_id=?", (p["id"],))
    caveats = []
    if any(s["kind"] == "simulated" and s["status"] == "succeeded" for s in steps):
        caveats.append("Simulated-environment steps change only the simulated test telemetry, not a real system.")
    if not any(s["status"] == "succeeded" for s in steps):
        caveats.append("No step executed, so any metric change is not attributable to this plan.")
    if not metrics:
        caveats.append("This problem has no continuous metric; see each step's own measured before/after values.")
    ver = {"overall": overall, "metrics": rows, "measured_ms": now_ms(), "caveats": caveats,
           "method": "median of stored telemetry before approval vs. fresh samples after completion; correlation with the action is not proof of cause"}
    db.exec("UPDATE rem_plans SET verification=?, after_metrics=? WHERE id=?", (jd(ver), jd(after), p["id"]))
    audit(tenant, "system", "rem.plan.verified", f"plan#{p['id']} verification={overall} " + "; ".join(f"{r['metric']} {r['before_median']}->{r['after_median']}" for r in rows))
