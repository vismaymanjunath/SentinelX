"""Issue classification, deterministic priority (P1-P4) with explainable reasons, and alert->incident correlation.
Runs the real saas modules against a throw-away SQLite database in a subprocess (so the project's data is never touched)."""
import json
import subprocess
import sys
import tempfile

import pytest

from .conftest import BASE

PRELUDE = r'''
import json, time
from saas import triage, correlation, monitor
from saas.core import now_ms
from saas.db import db, jd

def ent(t, eid, typ): db.exec("INSERT OR REPLACE INTO entities VALUES(?,?,?,?)", (t, eid, typ, eid))
def edge(t, a, b): db.exec("INSERT OR REPLACE INTO topology VALUES(?,?,?)", (t, a, b))
def coll(t, cid, name, plat): db.exec("INSERT OR REPLACE INTO collectors(id,tenant_id,name,platform) VALUES(?,?,?,?)", (cid, t, name, plat))
def alert(t, cid, src, metric, sev, cat, t_off_s=0, cleared=None, detectors=("local","saas"), title=None, base=None):
    base = base or NOW
    ev = (base + t_off_s * 1000)
    c = db.exec("INSERT INTO alerts(tenant_id,collector_id,source_id,metric,kinds,severity,category,title,message,evidence,created_ms,"
                "created_at,event_ms,last_event_ms,cleared_ms,detected_by,late) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (t, cid, src, metric, jd(["threshold"]), sev, cat, title or f"{metric} on {src}", "SECRET raw log text 10.1.2.3",
                 jd({"peak": 91, "baseline_median": 20, "z_score": 9}), ev, "", ev, ev, cleared, jd(list(detectors))))
    return c.lastrowid
NOW = now_ms()
def out(o): print("@@" + json.dumps(o, default=str))
'''


def run(body):
    tmp = tempfile.mkdtemp(prefix="sx-triage-")
    env = {"SENTINEL_DATA_DIR": tmp, "PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")}
    r = subprocess.run([sys.executable, "-c", PRELUDE + body], cwd=BASE, env={**__import__("os").environ, **env},
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.split("@@")[-1])


# --------------------------------------------------------------------------------------------- classification
def test_classification_of_each_signal_type():
    res = run('''
cases = [("host:app","cpu_percent","service","host"), ("host:app","disk_percent","service","host"),
         ("svc:api","response_ms","service","service"), ("net:wan","latency_ms","network","network"),
         ("net:wan","packet_loss_pct","network","network"), ("host:app","bandwidth_mbps","service","host"),
         ("svc:auth","failed_logins","security","service"), ("host:app","secrets_detected","security","host"),
         ("collector:col-1","collector_offline","collector",""), ("host:phone","battery_percent","service","host")]
out([triage.classify_signal(s, m, c, e)[0] for s, m, c, e in cases])
''')
    assert res == ["Infrastructure", "Infrastructure", "Infrastructure", "Network", "Network", "Network",
                   "Security", "Security", "Collector Health", "Infrastructure"]


def test_incident_category_follows_root_cause_and_lists_secondary():
    res = run('''
sig = lambda e, m, c, root: {"entity": e, "metric": m, "category": c, "rule": "r", "is_root": root}
out(triage.classify_incident([sig("svc:api","response_ms","Infrastructure",False), sig("net:wan","latency_ms","Network",True)]))
''')
    assert res[0] == "Network" and res[1] == ["Infrastructure"] and "latency_ms" in res[2]


# --------------------------------------------------------------------------------------------- prioritisation
def test_priority_is_deterministic_explainable_and_monotonic():
    res = run('''
def sig(sev="critical", dur=0, dev="c1", cleared=False, det=1):
    return {"severity": sev, "start_ms": NOW, "end_ms": None if not cleared else NOW + dur * 1000, "collector_id": dev, "n_detectors": det}
def P(sigs, cat="Infrastructure", aff=0, risk=0, at=0):
    return triage.prioritize(sigs, cat, aff, risk, NOW + at * 1000)
a = P([sig()], at=10); b = P([sig()], at=10)
o = {"same": a == b, "sum": a["score"] == sum(r["points"] for r in a["reasons"]), "factors": [r["factor"] for r in a["reasons"]]}
o["warn_short"] = P([sig("warning")], at=10)["level"]                       # 20 -> P4
o["crit_short"] = P([sig()], at=10)["level"]                                # 40 -> P3
o["crit_long"] = P([sig()], at=400)["score"] - P([sig()], at=10)["score"]    # duration adds 15
o["crit_impact"] = P([sig(), sig("warning", dev="c1")], aff=3, risk=2, at=200)["level"]
o["multi_dev"] = P([sig(dev="c1"), sig(dev="c2"), sig(dev="c3")], aff=3, risk=2, at=400)["level"]
o["multi_dev_score"] = P([sig(dev="c1"), sig(dev="c2"), sig(dev="c3")], aff=3, risk=2, at=400)["score"]
o["sec_bonus"] = P([sig()], "Security", at=10)["score"] - P([sig()], "Infrastructure", at=10)["score"]
o["cleared_not_growing"] = P([sig(cleared=True, dur=30)], at=9999)["duration_s"]
o["ordered"] = [triage.level_for(s)[0] for s in (0, 34, 35, 54, 55, 74, 75, 110)]
out(o)
''')
    assert res["same"] and res["sum"]
    assert res["factors"] == ["severity", "duration", "affected_devices", "impact", "corroboration", "category"]
    assert res["warn_short"] == "P4" and res["crit_short"] == "P3"
    assert res["crit_long"] == 15
    assert res["crit_impact"] == "P2"
    assert res["multi_dev"] == "P1" and res["multi_dev_score"] >= 75
    assert res["sec_bonus"] == 10
    assert res["cleared_not_growing"] == 30
    assert res["ordered"] == ["P4", "P4", "P3", "P3", "P2", "P2", "P1", "P1"]


# --------------------------------------------------------------------------------------------- correlation (real tables)
def test_related_alerts_group_into_one_incident_with_category_priority_devices():
    res = run('''
T = "acme"
coll(T, "c-app", "App Laptop", "windows"); coll(T, "c-db", "DB Server", "linux")
for e, ty in (("host:app","host"),("svc:api","service"),("svc:web","service"),("host:db","host")): ent(T, e, ty)
edge(T, "svc:api", "host:app"); edge(T, "svc:web", "svc:api")
ids = [alert(T, "c-app", "host:app", "cpu_percent", "critical", "service", 0),
       alert(T, "c-app", "svc:api", "response_ms", "warning", "service", 20),
       alert(T, "c-db", "svc:web", "error_rate_pct", "warning", "service", 40)]
for i in ids: correlation.correlate(T, i)
incs = db.all("SELECT * FROM incidents WHERE tenant_id=?", (T,))
an = json.loads(incs[0]["analysis"])
out({"n": len(incs), "alert_count": incs[0]["alert_count"], "cat": incs[0]["category"], "lvl": incs[0]["priority_level"],
     "score": incs[0]["priority"], "devices": sorted(d["name"] for d in an["triage"]["priority"]["devices"]),
     "reasons": [r["factor"] for r in an["triage"]["priority"]["reasons"]], "root": an["root"]["entity"]})
''')
    assert res["n"] == 1 and res["alert_count"] == 3, "three related alerts -> ONE incident"
    assert res["cat"] == "Infrastructure" and res["root"] == "host:app"
    assert res["devices"] == ["App Laptop", "DB Server"]
    assert res["lvl"] in ("P1", "P2", "P3", "P4") and res["score"] > 0 and "impact" in res["reasons"]


def test_unrelated_security_network_and_collector_signals_get_their_own_incident_and_category():
    res = run('''
T = "acme"
coll(T, "c1", "Laptop 1", "windows"); coll(T, "c2", "Laptop 2", "macos"); coll(T, "c3", "Phone", "android")
for e, ty in (("host:app","host"),("svc:auth","service"),("net:wan","network"),("svc:shop","service")): ent(T, e, ty)
edge(T, "svc:shop", "net:wan")
ids = [alert(T, "c1", "host:app", "cpu_percent", "warning", "service", 0),
       alert(T, "c1", "svc:auth", "failed_logins", "critical", "security", 5, title="Brute force"),
       alert(T, "c1", "net:wan", "latency_ms", "critical", "network", 10),
       alert(T, "c2", "svc:shop", "response_ms", "warning", "service", 20),
       alert(T, "c2", "collector:c2", "collector_offline", "critical", "collector", 30),
       alert(T, "c3", "collector:c3", "collector_offline", "critical", "collector", 35)]
for i in ids: correlation.correlate(T, i)
rows = db.all("SELECT id, title, category, alert_count FROM incidents WHERE tenant_id=?", (T,))
out({"by_cat": sorted((r["category"], r["alert_count"], r["title"]) for r in rows)})
''')
    cats = {(c, n): t for c, n, t in res["by_cat"]}
    assert ("Security", 1) in cats and ("Network", 2) in cats, res
    assert ("Infrastructure", 1) in cats
    assert ("Collector Health", 2) in cats and cats[("Collector Health", 2)] == "2 collectors offline", "multiple offline collectors = one incident"
    assert len(res["by_cat"]) == 4


def test_priority_escalates_as_incident_ages_and_records_timeline():
    res = run('''
T = "acme"
coll(T, "c1", "Laptop", "windows"); ent(T, "host:app", "host")
i = alert(T, "c1", "host:app", "cpu_percent", "critical", "service", -600, base=now_ms())   # first anomaly 10 min ago, still active
correlation.correlate(T, i)
before = db.one("SELECT priority_level, priority FROM incidents WHERE tenant_id=?", (T,))
# pretend the incident was previously scored when it was brand new, then let the monitor-style refresh re-score it
inc = db.one("SELECT * FROM incidents WHERE tenant_id=?", (T,))
an = json.loads(inc["analysis"]); an["triage"]["priority"].update(level="P4", score=1)
db.exec("UPDATE incidents SET analysis=? WHERE id=?", (jd(an), inc["id"]))
changed = triage.refresh(T, inc["id"])
after = db.one("SELECT priority_level, priority FROM incidents WHERE tenant_id=?", (T,))
ev = [r["detail"] for r in db.all("SELECT detail FROM incident_events WHERE kind='priority_changed'")]
out({"changed": changed, "before": before, "after": after, "ev": ev, "again": triage.refresh(T, inc["id"]),
     "wrong_tenant": triage.refresh("globex", inc["id"])})
''')
    assert res["changed"] and res["after"]["priority_level"] == res["before"]["priority_level"]
    assert res["ev"] and "P4 ->" in res["ev"][0]
    assert res["again"] is False, "refresh is idempotent when nothing changed"
    assert res["wrong_tenant"] is False


def test_tenant_isolation_in_correlation_and_priority():
    res = run('''
for T, cid in (("acme", "ca"), ("globex", "cg")):
    coll(T, cid, T + " laptop", "windows"); ent(T, "host:app", "host"); ent(T, "svc:api", "service"); edge(T, "svc:api", "host:app")
    for i in (alert(T, cid, "host:app", "cpu_percent", "critical", "service", 0), alert(T, cid, "svc:api", "response_ms", "warning", "service", 5)):
        correlation.correlate(T, i)
rows = db.all("SELECT tenant_id, alert_count, analysis FROM incidents ORDER BY tenant_id")
out([(r["tenant_id"], r["alert_count"], [d["id"] for d in json.loads(r["analysis"])["triage"]["priority"]["devices"]]) for r in rows])
''')
    assert res == [["acme", 2, ["ca"]], ["globex", 2, ["cg"]]], "same entity names in two tenants never merge or share devices"


def test_api_exposes_triage_fields_and_dashboard_bundle(stack, admin):
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for needle in ("Classification & priority", "Affected devices", "priority_level"):
        assert needle in js, needle
    for i in stack.saas.get("/api/incidents", headers=admin).json():   # backward compatible: old fields still there
        assert {"id", "title", "status", "severity", "priority", "alert_count", "confidence", "affected", "root"} <= set(i)
        assert i["priority_level"] in ("P1", "P2", "P3", "P4") and i["category"] in (
            "Infrastructure", "Network", "Security", "Collector Health")
        assert isinstance(i["priority_reasons"], list) and "devices" in i


# --------------------------------------------------------------------------------------------- Scenario Lab ordering
SCN = r'''
from saas import scenarios
def marker(t, cid, name, off_s=0):
    db.exec("INSERT INTO sim_markers(tenant_id,collector_id,scenario,injected_ms,injected_at,received_ms,event_id) VALUES(?,?,?,?,?,?,?)",
            (t, cid, name, NOW + off_s * 1000, "", NOW, f"{name}-{off_s}-{t}"))
T = "acme"
coll(T, "c1", "Laptop", "windows")
for e, ty in (("host:app","host"),("svc:api","service"),("net:wan","network"),("svc:auth","service")): ent(T, e, ty)
edge(T, "svc:api", "host:app")
def mk(src, metric, sev, cat, off=1, **kw):
    i = alert(T, "c1", src, metric, sev, cat, off, **kw); correlation.correlate(T, i); return i
'''


def test_scenarios_ordered_by_incident_priority_then_score_with_pending_last():
    res = run(SCN + '''
# click order: failed_logins (low), latency (mid), cpu (high), saas_disconnect (never raises an alert), packet_loss (no alert yet)
for n in ("failed_logins", "latency_increase", "cpu_spike", "saas_disconnect", "packet_loss"):
    marker(T, "c1", n)
mk("svc:auth", "failed_logins", "warning", "security")
mk("net:wan", "latency_ms", "critical", "network")
mk("host:app", "cpu_percent", "critical", "service", 2)
mk("svc:api", "response_ms", "critical", "service", 3)
# force clearly different stored triage results (the engine's own columns), to check ordering only
rows = {r["category"]: r for r in db.all("SELECT * FROM incidents")}
db.exec("UPDATE incidents SET priority_level='P3', priority=40 WHERE category='Network'")
db.exec("UPDATE incidents SET priority_level='P1', priority=80 WHERE category='Infrastructure'")
db.exec("UPDATE incidents SET priority_level='P3', priority=44 WHERE category='Security'")
v = scenarios.priority_view(T, ["failed_logins", "latency_increase", "cpu_spike", "saas_disconnect", "packet_loss"])
out([(o["name"], o["state"], o["priority_level"], o["priority_score"], o["category"]) for o in v])
''')
    assert res == [["cpu_spike", "incident", "P1", 80.0, "Infrastructure"],
                   ["failed_logins", "incident", "P3", 44.0, "Security"],      # same level as latency, higher score first
                   ["latency_increase", "incident", "P3", 40.0, "Network"],
                   ["saas_disconnect", "pending", None, None, None],
                   ["packet_loss", "pending", None, None, None]], res


def test_scenario_order_follows_incident_priority_changes():
    res = run(SCN + '''
marker(T, "c1", "failed_logins"); marker(T, "c1", "latency_increase")
mk("svc:auth", "failed_logins", "warning", "security"); mk("net:wan", "latency_ms", "warning", "network")
names = ["failed_logins", "latency_increase"]
db.exec("UPDATE incidents SET priority_level='P3', priority=40 WHERE category='Security'")
db.exec("UPDATE incidents SET priority_level='P4', priority=20 WHERE category='Network'")
first = [o["name"] for o in scenarios.priority_view(T, names)]
# the network incident ages/escalates: same columns the monitor's triage.refresh writes
db.exec("UPDATE incidents SET priority_level='P2', priority=60 WHERE category='Network'")
second = [o["name"] for o in scenarios.priority_view(T, names)]
out([first, second])
''')
    assert res == [["failed_logins", "latency_increase"], ["latency_increase", "failed_logins"]]


def test_scenarios_sharing_one_incident_and_tenant_isolation():
    res = run(SCN + '''
marker(T, "c1", "cpu_spike"); marker(T, "c1", "correlated")
mk("host:app", "cpu_percent", "critical", "service", 1); mk("svc:api", "response_ms", "warning", "service", 2)
v = scenarios.priority_view(T, ["cpu_spike", "correlated"])
other = scenarios.priority_view("globex", ["cpu_spike", "correlated"])
out({"n_incidents": db.one("SELECT COUNT(*) n FROM incidents")["n"], "ids": [o["incident_id"] for o in v],
     "shared": [o["shared_with"] for o in v], "other": [o["state"] for o in other]})
''')
    assert res["n_incidents"] == 1 and res["ids"][0] == res["ids"][1] and res["ids"][0] is not None
    assert sorted(sum(res["shared"], [])) == ["correlated", "cpu_spike"]
    assert res["other"] == ["pending", "pending"], "another tenant never sees these incidents"


def test_incidents_and_scenarios_use_the_same_rank_key():
    res = run('''
rows = [("P3", 44), ("P1", 76), (None, 0), ("P3", 40), ("P2", 60), ("P1", 90), ("P4", 10)]
out([list(r) for r in sorted(rows, key=lambda r: triage.rank_key(*r))])
''')
    assert res == [["P1", 90], ["P1", 76], ["P2", 60], ["P3", 44], ["P3", 40], ["P4", 10], [None, 0]]


def test_api_incident_list_is_priority_ordered_and_scenario_endpoint_works(stack, admin):
    rows = stack.saas.get("/api/incidents", headers=admin).json()
    keys = [(r["status"] != "open", {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(r["priority_level"], 9), -r["priority"]) for r in rows]
    assert keys == sorted(keys), "open first, then P1..P4, then higher score first"
    r = stack.saas.get("/api/scenarios/priority?active=cpu_spike,nonexistent", headers=admin)
    assert r.status_code == 200 and {o["name"] for o in r.json()} == {"cpu_spike", "nonexistent"}
    assert all(o["state"] in ("incident", "pending") for o in r.json())
    assert stack.saas.get("/api/scenarios/priority?active=cpu_spike").status_code == 401
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    assert "/api/scenarios/priority" in js and "no incident yet" in js
