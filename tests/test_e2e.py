"""End-to-end workflow tests: real collector -> real SaaS over TLS, scenarios injected through the same API the UI uses."""
import json
import sqlite3
import time

import httpx
import pytest

from common.schema import CONTEXT_ALLOW, TOP_FIELDS
from .conftest import wait_until

SECRETS = ["S3cr3tP@ss", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE", "Hunter2!Prod",
           "sk_live_51HxExampleKey99", "4111 1111 1111 1111", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
           "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun", "jane.doe@corp.com"]


def saas_db(stack):
    c = sqlite3.connect(str(stack.tmp / "saas.db"))
    c.row_factory = sqlite3.Row
    return c


def dump_saas_text(stack):
    c = saas_db(stack)
    parts = []
    for t in ("events", "alerts", "incidents", "payloads", "rejected", "incident_events", "audit", "collectors", "entities"):
        for r in c.execute(f"SELECT * FROM {t}"):
            parts.append(json.dumps(dict(r), default=str))
    return "\n".join(parts)


def clear_all(stack):
    stack.ca.post("/api/sim/clear")
    stack.cb.post("/api/sim/clear")


def test_00_auth_and_tls_required(stack):
    cfg = stack.cfg["acme"]
    plain = httpx.post(f"http://127.0.0.1:18080/api/ingest/v1/payload", content=b"{}", headers={"Authorization": "Bearer " + cfg["api_key"]})
    assert plain.status_code == 426, "ingest over plain HTTP must be refused"
    tls = httpx.Client(verify=cfg["ca_cert"], base_url="https://localhost:18443")
    assert tls.post("/api/ingest/v1/payload", content=b"{}").status_code == 401
    assert tls.post("/api/ingest/v1/payload", content=b"{}", headers={"Authorization": "Bearer sx_wrong"}).status_code == 401
    assert stack.saas.get("/api/overview").status_code == 401


def test_01_telemetry_flows_and_is_quiet(stack, admin):
    wait_until(lambda: stack.saas.get("/api/overview", headers=admin).json()["kpis"]["events_per_min"] > 50, 40, msg="events flowing")
    time.sleep(45)  # baseline warm-up
    o = stack.saas.get("/api/overview", headers=admin).json()
    assert o["collectors"][0]["status"] == "online"
    assert o["kpis"]["active_alerts"] == 0, f"false alarms on a quiet system: {stack.saas.get('/api/alerts', headers=admin).json()[:3]}"
    assert o["health"]["state"] in ("Excellent", "Good")
    assert {e["id"] for e in o["entities"]} >= {"host:app-node", "net:wan-link", "db-primary", "api-gateway"}


def test_02_secrets_stay_local_and_only_allowlisted_fields_leave(stack, admin):
    stack.ca.post("/api/sim/secret_logs")
    stack.ca.post("/api/logs/inject", json={"line": "WARN custom password=MyCustomPw!42 token=ghp_abcdefghijklmnopqrstuvwxyz123456"})
    # local side keeps the raw secrets...
    local = wait_until(lambda: [l for l in stack.ca.get("/api/logs?limit=200&only_secrets=true").json()], 15, msg="local secret logs")
    raws = " ".join(l["raw"] for l in local)
    assert "S3cr3tP@ss" in raws and "AKIAIOSFODNN7EXAMPLE" in raws
    redacted = " ".join(l["redacted"] for l in local)
    assert "S3cr3tP@ss" not in redacted and "[REDACTED:" in redacted
    # ...while SaaS gets a privacy summary only
    wait_until(lambda: any(e["type"] == "privacy_summary" for e in stack.saas.get("/api/events?types=privacy_summary", headers=admin).json()), 20, msg="privacy_summary at saas")
    time.sleep(4)
    text = dump_saas_text(stack) + json.dumps(stack.saas.get("/api/events?limit=300", headers=admin).json())
    for s in SECRETS + ["MyCustomPw!42", "ghp_abcdefghijklmnopqrstuvwxyz123456", "203.0.113.9", "alice@corp.com"]:
        assert s not in text, f"secret leaked to SaaS: {s}"
    # strict allow-list on everything stored
    c = saas_db(stack)
    for r in c.execute("SELECT type, context FROM events"):
        assert set(json.loads(r["context"])) <= set(CONTEXT_ALLOW[r["type"]]), (r["type"], r["context"])
    # egress proof: original had the secrets + extra fields, final does not
    eg = [p for p in stack.ca.get("/api/egress?limit=40").json() if p["blocked_count"]]
    one = stack.ca.get(f"/api/egress/{eg[0]['payload_id']}").json()
    assert one["final"] and one["blocked"]["fields"]
    assert any("S3cr3tP@ss" in json.dumps(p["original"]) for p in
               [stack.ca.get(f"/api/egress/{x['payload_id']}").json() for x in stack.ca.get("/api/egress?limit=30").json()]), "original (local) event should show the raw secret"
    for x in stack.ca.get("/api/egress?limit=60").json():
        d = stack.ca.get(f"/api/egress/{x['payload_id']}").json()
        if d["final"]:
            body = json.dumps(d["final"])
            assert not any(s in body for s in SECRETS)
    clear_all(stack)


def test_03_firewall_selftest_redacts_and_blocks(stack):
    stack.ca.post("/api/firewall/selftest")
    time.sleep(3)
    rows = [stack.ca.get(f"/api/egress/{x['payload_id']}").json() for x in stack.ca.get("/api/egress?limit=10").json()]
    st = [r for r in rows if r["blocked"] and any(e["reason"].startswith("last-line guard") for e in r["blocked"]["events"])]
    assert st, "canary token in an allowed field must be blocked by the last-line guard"
    # layered defence: the local anonymiser strips identifying fields (username) BEFORE the firewall; the firewall still drops api_token etc.
    assert any("api_token" in f["fields"] and "raw_payload" in f["fields"] for r in st for f in r["blocked"]["fields"])
    assert "bob" not in json.dumps([r["final"] for r in rows]) and '"username"' not in json.dumps([r["final"] for r in rows])
    assert any(x["label"] == "aws_access_key" for r in st for x in r["redactions"])
    assert "Sup3rS3cretToken99" not in json.dumps([r["final"] for r in rows])


def test_04_saas_rejects_non_allowlisted_payload(stack):
    cfg = stack.cfg["acme"]
    tls = httpx.Client(verify=cfg["ca_cert"], base_url="https://localhost:18443", headers={"Authorization": "Bearer " + cfg["api_key"]})
    bad = {"payload_id": "11111111-aaaa-bbbb-cccc-000000000001", "collector_id": cfg["collector_id"], "seq": 99999, "sent_at": "2026-01-01T00:00:00.000Z",
           "schema_version": "1.0", "events": [{"event_id": "22222222-aaaa-bbbb-cccc-000000000002", "type": "metric", "source_id": "api-gateway",
                                                "category": "service", "severity": "info", "metric": "response_ms", "value": 1.0, "unit": "ms",
                                                "event_time": "2026-01-01T00:00:00.000Z", "source_tz": "UTC", "raw_log": "password=abc"}]}
    r = tls.post("/api/ingest/v1/payload", json=bad)
    assert r.status_code == 422 and "allow-list" in json.dumps(r.json())
    bad["events"][0].pop("raw_log")
    bad["events"][0]["context"] = {"origin": "password=hunter2"}
    assert tls.post("/api/ingest/v1/payload", json=bad).status_code == 422
    other = {**bad, "collector_id": "col-globex-01"}
    assert tls.post("/api/ingest/v1/payload", json=other).status_code == 422, "payload may not claim another collector"


def test_05_tenant_isolation(stack, admin, gadmin):
    a = stack.saas.get("/api/overview", headers=admin).json()
    g = stack.saas.get("/api/overview", headers=gadmin).json()
    assert {c["id"] for c in a["collectors"]} == {"col-acme-01"}
    assert {c["id"] for c in g["collectors"]} == {"col-globex-01"}
    ap = stack.saas.get("/api/ledger", headers=admin).json()
    assert ap and all(p["collector_id"] == "col-acme-01" for p in ap)
    assert stack.saas.get(f"/api/ledger/{ap[0]['payload_id']}", headers=gadmin).status_code == 404
    gp = stack.saas.get("/api/ledger", headers=gadmin).json()
    assert gp and all(p["collector_id"] == "col-globex-01" for p in gp)
    for ev in stack.saas.get("/api/events?limit=300", headers=gadmin).json():
        assert ev["event_id"] not in {x["event_id"] for x in stack.saas.get("/api/events?limit=300", headers=admin).json()}
    a_ids = {e["event_id"] for e in stack.saas.get("/api/events?limit=300", headers=admin).json()}
    assert not a_ids & {e["event_id"] for e in stack.saas.get("/api/events?limit=300", headers=gadmin).json()}


def test_06_cpu_spike_detected_correlated_explained(stack, admin):
    t0 = time.time()
    stack.ca.post("/api/sim/cpu_spike")
    inc = wait_until(lambda: next((i for i in stack.saas.get("/api/incidents?status=open", headers=admin).json() if i["alert_count"] >= 3), None),
                     45, msg="correlated incident")
    d = stack.saas.get(f"/api/incidents/{inc['id']}", headers=admin).json()
    an = d["analysis"]
    assert an["root"]["entity"] == "host:app-node", an["root"]
    assert an["root"]["confidence"] >= 0.5
    assert len(an["affected"]) >= 2 and len(d["alerts"]) >= 3
    assert any(s["z_score"] for s in an["signals"]) and an["reasoning"] and an["ranking"][0]["breakdown"]
    assert any(r["action"] == "scale_up_host" for r in an["recommendations"])
    # alert-latency target: injected spike -> alert within 15 s
    perf = stack.saas.get("/api/perf", headers=admin).json()
    cpu = next(x for x in perf["alert_latency"] if x["scenario"] == "cpu_spike")
    assert cpu["alert_after_ms"] is not None and cpu["alert_after_ms"] < 15000, cpu
    # noise reduction: many raw alerts -> a single incident
    assert len(stack.saas.get("/api/incidents?status=open", headers=admin).json()) == 1
    # keep for remediation test
    stack.inc_id = inc["id"]


def test_07_remediation_requires_approval_and_is_audited(stack, admin, viewer):
    iid = stack.inc_id
    r = stack.saas.post(f"/api/incidents/{iid}/remediation", headers=admin, json={"action": "scale_up_host", "target": "host:app-node"})
    assert r.status_code == 200 and r.json()["status"] == "proposed"
    rid = r.json()["id"]
    assert all(c["passed"] for c in r.json()["policy"])
    # nothing executes without approval
    assert stack.saas.post(f"/api/remediation/{rid}/execute", headers=admin).status_code == 409
    time.sleep(7)
    assert stack.saas.get("/api/remediation", headers=admin).json()[0]["status"] == "proposed"
    assert stack.ca.get("/api/status").json()["sim"]["mitigations"]["scaled_up"] is False
    # viewers cannot approve
    assert stack.saas.post(f"/api/remediation/{rid}/approve", headers=viewer, json={}).status_code == 403
    # policy blocks out-of-scope / unknown actions
    bad = stack.saas.post(f"/api/incidents/{iid}/remediation", headers=admin, json={"action": "rm_rf", "target": "host:app-node"}).json()
    assert bad["status"] == "blocked_by_policy"
    assert stack.saas.post(f"/api/remediation/{bad['id']}/approve", headers=admin, json={}).status_code == 409
    # admin approval -> sandbox execution on the collector
    assert stack.saas.post(f"/api/remediation/{rid}/approve", headers=admin, json={"note": "ok"}).json()["status"] == "approved"
    def get_rem():
        return next(x for x in stack.saas.get("/api/remediation", headers=admin).json() if x["id"] == rid)
    done = wait_until(lambda: get_rem() if get_rem()["status"] == "executed" else None, 25, msg="executed")
    assert done["before_state"] is not None and "SANDBOX" in done["result"]["detail"]
    assert stack.ca.get("/api/status").json()["sim"]["mitigations"]["scaled_up"] is True
    # effect is real: CPU recovers, incident resolves on its own
    wait_until(lambda: next(i for i in stack.saas.get("/api/incidents", headers=admin).json() if i["id"] == iid)["status"] == "resolved", 90, msg="incident resolved")
    # rollback restores the previous sandbox state
    assert stack.saas.post(f"/api/remediation/{rid}/rollback", headers=admin).json()["status"] == "rollback_pending"
    wait_until(lambda: next(x for x in stack.saas.get("/api/remediation", headers=admin).json() if x["id"] == rid)["status"] == "rolled_back", 25, msg="rolled back")
    assert stack.ca.get("/api/status").json()["sim"]["mitigations"]["scaled_up"] is False
    actions = [a["action"] for a in stack.saas.get("/api/audit?limit=100", headers=admin).json()]
    for need in ("remediation.proposed", "remediation.approved", "remediation.executed", "remediation.rollback_requested", "remediation.rolled_back"):
        assert need in actions, need
    clear_all(stack)


def test_08_failed_logins_security_signal_without_raw_auth_records(stack, admin):
    time.sleep(20)  # let previous incident settle
    stack.ca.post("/api/sim/failed_logins")
    al = wait_until(lambda: next((a for a in stack.saas.get("/api/alerts?limit=50", headers=admin).json()
                                  if a["metric"] == "failed_logins" and a["cleared_ms"] is None), None), 30, msg="failed login alert")
    assert al["category"] == "security"
    sec = wait_until(lambda: [e for e in stack.saas.get("/api/events?types=security_summary", headers=admin).json()], 20, msg="security summary")
    ctx = sec[0]["context"]
    assert ctx["failed_attempts"] >= 5 and ctx["unique_sources"] >= 1 and ctx["top_sources"][0].startswith("src-")
    text = dump_saas_text(stack)
    for raw in ("203.0.113.9", "198.51.100.23", "192.0.2.77", "bob@corp.com", "Winter2026!"):
        assert raw not in text
    clear_all(stack)


def test_09_network_latency_and_packet_loss(stack, admin):
    time.sleep(35)
    stack.ca.post("/api/sim/latency_increase")
    wait_until(lambda: any(a["source_id"] == "net:wan-link" and a["metric"] == "latency_ms" for a in stack.saas.get("/api/alerts?limit=40", headers=admin).json()), 25, msg="latency alert")
    inc = wait_until(lambda: next((i for i in stack.saas.get("/api/incidents?status=open", headers=admin).json() if i["alert_count"] >= 2), None), 40, msg="latency incident")
    an = stack.saas.get(f"/api/incidents/{inc['id']}", headers=admin).json()["analysis"]
    assert an["root"]["entity"] == "net:wan-link", an["root"]
    assert "failover_wan_link" in [r["action"] for r in an["recommendations"]]
    topo = stack.saas.get(f"/api/topology?incident_id={inc['id']}", headers=admin).json()
    roles = {n["id"]: n["role"] for n in topo["nodes"]}
    assert roles["net:wan-link"] == "root" and "affected" in roles.values()
    clear_all(stack)


def test_10_saas_outage_buffers_then_delivers_without_loss_or_duplicates(stack, admin):
    time.sleep(40)
    before = stack.ca.post("/api/reconcile").json()
    stack.ca.post("/api/sim/saas_disconnect", json={"duration_s": 20})
    time.sleep(12)
    st = stack.ca.get("/api/status").json()
    assert st["outbox"]["pending"] >= 4 and "partitioned" in st["link"]["state"]
    eg = stack.ca.get("/api/egress?limit=5").json()
    assert any(x["status"] == "buffered" for x in eg)
    wait_until(lambda: stack.ca.get("/api/status").json()["outbox"]["pending"] <= 1, 50, msg="backlog drained")
    time.sleep(3)
    rec = stack.ca.post("/api/reconcile").json()
    assert rec["zero_loss"] and rec["zero_duplicates"], rec
    assert rec["saas_received"] >= before["saas_received"] + 8
    perf = stack.saas.get("/api/perf", headers=admin).json()
    d = perf["delivery"][0]
    assert d["missing_seq"] == [] and d["seq_gaps"] == 0
    clear_all(stack)


def test_11_duplicate_and_out_of_order_delivery(stack, admin):
    base = stack.saas.get("/api/perf", headers=admin).json()["delivery"][0]
    stack.ca.post("/api/sim/duplicate_ooo")
    time.sleep(14)
    d = stack.saas.get("/api/perf", headers=admin).json()["delivery"][0]
    assert d["duplicates_ignored"] > base["duplicates_ignored"], "duplicates must be detected by payload id"
    assert d["out_of_order_events"] > base["out_of_order_events"], "reordered payloads must be placed by event time"
    c = saas_db(stack)
    assert c.execute("SELECT COUNT(*) - COUNT(DISTINCT event_id) FROM events").fetchone()[0] == 0
    rows = stack.saas.get("/api/series?source_id=api-gateway&metric=response_ms&seconds=120", headers=admin).json()["points"]
    ts = [p[0] for p in rows]
    assert ts == sorted(ts), "series is ordered by event time"
    rec = stack.ca.post("/api/reconcile").json()
    assert rec["zero_loss"] and rec["zero_duplicates"]


def test_12_collector_offline_detected_within_60s_and_recovers(stack, admin):
    time.sleep(10)
    t0 = time.time()
    stack.ca.post("/api/sim/collector_disconnect", json={"duration_s": 40})

    def poor():
        c = stack.saas.get("/api/collectors", headers=admin).json()[0]
        return c if c["state"] == "Poor" and c["status"] == "offline" else None
    wait_until(poor, 60, 1, msg="collector Poor/offline")
    assert time.time() - t0 < 60
    o = stack.saas.get("/api/overview", headers=admin).json()
    assert o["health"]["state"] == "Poor"
    perf = wait_until(lambda: (lambda p: p if p["offline_detection"] else None)(stack.saas.get("/api/perf", headers=admin).json()),
                      10, 0.5, msg="outage record")
    assert perf["offline_detection"][0]["since_last_heartbeat_ms"] < 60000
    wait_until(lambda: stack.saas.get("/api/collectors", headers=admin).json()[0]["status"] == "online", 60, 1, msg="collector back")
    hist = stack.saas.get("/api/history?limit=50", headers=admin).json()
    assert any(h["entity_id"] == "collector:col-acme-01" and h["new_state"] == "Poor" for h in hist)
    assert all(h["ts"].endswith("Z") for h in hist)


def test_13_health_states_thresholds_configurable(stack, admin, viewer):
    clear_all(stack)
    time.sleep(30)
    r = stack.saas.put("/api/thresholds", headers=viewer, json={"thresholds": {"disk_percent": {"good_max": 1, "warn": 2, "crit": 3}}})
    assert r.status_code == 403
    r = stack.saas.put("/api/thresholds", headers=admin, json={"thresholds": {"disk_percent": {"good_max": 1, "warn": 2, "crit": 3}}})
    assert r.status_code == 200
    ent = next(e for e in stack.saas.get("/api/overview", headers=admin).json()["entities"] if e["id"] == "host:app-node")
    assert ent["metrics"]["disk_percent"]["state"] == "Poor" and "critical" in ent["metrics"]["disk_percent"]["reason"]
    stack.saas.put("/api/thresholds", headers=admin, json={"thresholds": {"disk_percent": {"good_max": 85, "warn": 93, "crit": 98}}})


def test_14_replay_uses_stored_telemetry(stack, admin):
    incs = stack.saas.get("/api/incidents", headers=admin).json()
    iid = next(i["id"] for i in incs if i["alert_count"] >= 3)
    rp = stack.saas.get(f"/api/incidents/{iid}/replay", headers=admin).json()
    assert rp["series"] and rp["alerts"] and rp["timeline"]
    ts = [t["event_ms"] for t in rp["timeline"]]
    assert ts == sorted(ts)
    assert any("host:app-node|cpu_percent" == k for k in rp["series"])


def test_15_performance_targets_measured(stack, admin):
    p = stack.saas.get("/api/perf", headers=admin).json()
    assert p["ingest"]["p95"] is not None and p["ingest"]["p95"] < 10000
    assert p["delivery"][0]["missing_seq"] == []
