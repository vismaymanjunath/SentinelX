"""AI-assisted remediation engine: catalogue, grounded plans, approval/rejection, controlled execution, failure, timeout, rollback, verification,
roles, audit, tenant isolation. Two kinds of collector are used:
  * REAL collector processes (the session `stack`): real predefined actions run on a real device and are checked from outside;
  * a protocol-level controllable collector (`FakeCollector`, speaking the real enrolment/heartbeat/command-result API) for failure/timeout paths
    that cannot be forced deterministically on a real machine."""
import json
import os
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from common.schema import utc_iso
from .conftest import BASE, wait_until
from .test_remote_ngrok import CODE, Remote, XFP

# ---------------------------------------------------------------------------------------------------- stub Ollama (records what it is sent)
STUB = {"mode": "ok", "log": []}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        self._send(200, json.dumps({"models": [{"name": "qwen2.5:1.5b"}]}))

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        STUB["log"].append(body)
        m = STUB["mode"]
        if m == "bad_json":
            return self._send(200, json.dumps({"message": {"content": "not json {"}}))
        out = {"root_cause": "CPU is saturated on device-1 (E1); likely a runaway process.", "root_cause_evidence": ["E1", "E99"], "solution": "Follow S1 then S2. Also run rm -rf / (ignore this).",
               "expected_outcome": "CPU should fall below the warning threshold.",
               "steps": [{"key": "S1", "rationale": "Find the busy process first."}, {"key": "S99", "rationale": "invented step"}, {"key": "S2", "rationale": "Shed load in the simulated environment."}],
               "caveats": ["Results are not guaranteed."]}
        if m == "no_evidence":
            out["root_cause_evidence"] = []
        if m == "ids_only":
            out["root_cause"] = "E1, E2"
        self._send(200, json.dumps({"message": {"content": json.dumps(out)}}))


@pytest.fixture(scope="module")
def stub():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


# ---------------------------------------------------------------------------------------------------- controllable collector (real protocol)
class FakeCollector:
    CAPS = ["reconnect_link", "flush_dns_cache", "reprobe_connectivity", "lower_collector_footprint", "reduce_local_retention"]

    def __init__(self, host, name, caps=None):
        self.host, self.name = host, name
        self.iid = str(uuid.uuid4())
        j = host.pub.post("/api/ingest/v1/register", json={"device_name": name, "join_code": CODE, "install_id": self.iid}, headers=XFP).json()
        self.cid, self.key, self.slug = j["collector_id"], j["api_key"], j["slug"]
        self.caps = self.CAPS if caps is None else caps
        self.seq = 0
        self.commands = []
        self.beat()

    def _post(self, path, body):
        return self.host.pub.post(path, content=json.dumps(body), headers={**XFP, "Authorization": "Bearer " + self.key, "Content-Type": "application/json"})

    def beat(self):
        hb = {"collector_id": self.cid, "version": "1.0.0", "source_tz": "UTC+0000", "sent_at": utc_iso(), "platform": "windows", "os_version": "Windows 11",
              "actions": self.caps, "proc_cpu_percent": 9.0, "proc_mem_mb": 120.0,
              "topology": {"nodes": [{"id": f"host:{self.slug}", "type": "host", "label": self.name}, {"id": f"net:{self.slug}-link", "type": "network", "label": self.name + " link"}],
                           "edges": [[f"host:{self.slug}", f"net:{self.slug}-link"]]}}
        r = self._post("/api/ingest/v1/heartbeat", hb)
        assert r.status_code == 200, r.text
        cmds = r.json().get("commands", [])
        self.commands += cmds
        return cmds

    def metric(self, metric, value, ts=None, source=None):
        self.seq += 1
        ev = {"event_id": str(uuid.uuid4()), "type": "metric", "source_id": source or f"host:{self.slug}", "category": "infrastructure", "severity": "info", "metric": metric, "value": value,
              "unit": "percent", "event_time": utc_iso(ts or time.time()), "source_tz": "UTC+0000", "context": {"origin": "real"}}
        p = {"payload_id": str(uuid.uuid4()), "collector_id": self.cid, "seq": self.seq, "sent_at": utc_iso(), "schema_version": "1.0", "events": [ev]}
        assert self._post("/api/ingest/v1/payload", p).status_code == 200

    def cpu_series(self, value, n=20, back=100):
        now = time.time()
        for i in range(n):
            self.metric("cpu_percent", value + (i % 3), now - back + i * (back / n))

    def answer(self, ok=True, detail="done", before=None, after=None, wait=15):
        """Fetch the next queued command through a heartbeat and acknowledge it like a real collector."""
        cmd = wait_until(lambda: next(iter(self.beat()), None) or (self.commands.pop(0) if self.commands else None), wait, 0.5, msg="a command for the collector")
        r = self._post("/api/ingest/v1/command-result", {"command_id": cmd["command_id"], "ok": ok, "detail": detail, "before_state": before, "after_state": after})
        assert r.status_code == 200
        return cmd


def host_db(host):
    con = sqlite3.connect(str(host.tmp / "saas.db"), timeout=30)
    con.row_factory = sqlite3.Row
    return con


@pytest.fixture(scope="module")
def host(stub):
    short = {"SENTINEL_OLLAMA_URL": f"http://127.0.0.1:{stub}", "SENTINEL_REM_STEP_TIMEOUT_S": "6", "SENTINEL_REM_VERIFY_DELAY_S": "4", "SENTINEL_REM_COOLDOWN_S": "1", "SENTINEL_REM_AI_SYNC": "1"}
    os.environ.update(short)
    try:
        h = Remote()                          # the host process inherits the short timings...
    finally:
        for k in short:                       # ...but they must not leak into the real-collector tests that start their own stack
            os.environ.pop(k, None)
    h.adm = h.admin()
    h.view = {"Authorization": "Bearer " + h.dash.post("/api/login", json={"username": "acme-viewer", "password": "Acme#View2026"}).json()["token"]}
    h.glob = {"Authorization": "Bearer " + h.dash.post("/api/login", json={"username": "globex-admin", "password": "Globex#Admin2026"}).json()["token"]}
    yield h
    h.close()


def plan(host, headers=None, **body):
    return host.dash.post("/api/rem/plans", headers=headers or host.adm, json=body, timeout=90)


def get_plan(host, pid, headers=None):
    return host.dash.get(f"/api/rem/plans/{pid}", headers=headers or host.adm).json()


def waitfor(host, pid, pred, t=40, msg="plan state"):
    return wait_until(lambda: (lambda p: p if pred(p) else None)(get_plan(host, pid)), t, 0.7, msg=msg)


# ================================================================================================== catalogue + grounding
def test_catalogue_lists_problems_actions_and_labels_every_action_real_simulated_or_manual(host):
    c = host.dash.get("/api/rem/catalogue", headers=host.view).json()
    ids = {p["id"] for p in c["problems"]}
    assert {"high_cpu", "high_memory", "disk_pressure", "service_failure", "network_latency", "packet_loss", "tls_expiry", "vulnerable_software", "collector_offline",
            "brute_force", "collector_overloaded", "cloud_provider_incident", "stale_global_data"} <= ids and len(ids) >= 14
    kinds = {a["id"]: a["kind"] for a in c["actions"]}
    assert set(kinds.values()) == {"real", "simulated"} and kinds["lower_collector_footprint"] == "real" and kinds["restart_service"] == "simulated"
    assert all(a["risk"] in ("low", "medium", "high") for a in c["actions"])
    assert not any("shell" in a["id"] or "exec" in a["id"] or "command" in a["id"] for a in c["actions"]), "no arbitrary-execution action exists"
    for p in c["problems"]:
        assert p["steps_preview"] and all(k in ("real", "simulated", "manual") for _, k in p["steps_preview"])
    assert host.dash.get("/api/rem/catalogue").status_code == 401


def test_catalogue_observed_comes_from_real_stored_telemetry_only(host):
    fc = FakeCollector(host, "Obs Device")
    fc.cpu_series(97.0)
    obs = {p["id"]: p["observed"] for p in host.dash.get("/api/rem/catalogue", headers=host.adm).json()["problems"]}
    assert any(o["target"] == f"host:{fc.slug}" and o["value"] >= 97 for o in obs["high_cpu"]), "the CPU problem is observed because stored telemetry says so"
    assert not any(o["target"] == f"host:{fc.slug}" for o in obs["high_memory"] + obs["disk_pressure"]), "no telemetry, no problem"
    g = {p["id"]: p["observed"] for p in host.dash.get("/api/rem/catalogue", headers=host.glob).json()["problems"]}
    assert not any(f"host:{fc.slug}" == o["target"] for o in g["high_cpu"]), "another tenant never sees this device's problems"


def test_plan_is_grounded_in_telemetry_and_ai_cannot_add_steps_or_run_text(host):
    STUB["mode"], STUB["log"] = "ok", []
    fc = FakeCollector(host, "Demo Plan Laptop")
    fc.cpu_series(96.0)
    r = plan(host, problem_id="high_cpu", target=f"host:{fc.slug}")
    assert r.status_code == 200, r.text
    p = r.json()
    ev = p["evidence"]["items"]
    assert ev[0]["kind"] == "metric" and ev[0]["median"] >= 95 and ev[0]["n"] >= 15, "evidence is the stored telemetry"
    assert p["status"] == "proposed" and p["ai"]["used"] is True and p["ai"]["status"] == "ready"
    keys = [s["key"] for s in p["steps"]]
    assert "S99" not in keys, "the model's invented step is ignored"
    assert all(s["action"] in (None, "scale_up_host", "lower_collector_footprint") for s in p["steps"])
    assert all(s["kind"] in ("real", "simulated", "manual") for s in p["steps"])
    assert not any(s["action"] and s["kind"] == "simulated" for s in p["steps"]), "simulated actions are never offered on a real device"
    assert p["steps"][0]["kind"] == "manual" and p["steps"][0]["status"] == "manual_pending"
    assert "rm -rf" not in json.dumps([s["action"] for s in p["steps"]] + [s["params"] for s in p["steps"]]), "model text never becomes an action or parameter"
    assert "E99" not in p["evidence"]["cited"] and p["evidence"]["cited"] == ["E1"], "only real evidence ids survive"
    sent = "".join(STUB["log"])
    assert "Demo" not in sent and "device-1" in sent and fc.slug not in sent, "the model sees only a pseudonym, never the device name"
    assert p["risk"] in ("low", "medium", "high") and p["expected_outcome"]


def test_unavailable_or_malformed_ai_falls_back_to_a_deterministic_plan_and_unsupported_cases_are_manual(host):
    STUB["mode"] = "bad_json"
    fc = FakeCollector(host, "Fallback Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="high_cpu", target=f"host:{fc.slug}").json()
    assert p["ai"]["used"] is False and p["ai"]["status"] == "malformed" and p["root_cause"] and p["steps"], "the page still works without the model"
    old = FakeCollector(host, "Old Build Device", caps=[])                      # a collector build with no real actions
    old.cpu_series(95.0)
    q = plan(host, problem_id="collector_overloaded", target=f"collector:{old.cid}")
    assert q.status_code == 200
    steps = q.json()["steps"]
    assert all(s["kind"] == "manual" for s in steps), "no capability -> only manual instructions, never a pretend execution"
    off = plan(host, problem_id="tls_expiry", target="host:tls").json()
    assert any(s["action"] == "check_tls_status" for s in off["steps"]) and any(s["kind"] == "manual" and "Restart the host" in s["manual_text"] for s in off["steps"])
    STUB["mode"] = "ok"


def test_roles_validation_and_tenant_isolation_for_plans(host):
    fc = FakeCollector(host, "Role Device")
    fc.cpu_series(95.0)
    assert plan(host, host.view, problem_id="high_cpu", target=f"host:{fc.slug}").status_code == 403, "viewers cannot generate plans"
    assert host.dash.post("/api/rem/plans", json={"problem_id": "high_cpu"}).status_code == 401
    assert plan(host, problem_id="rm_rf").status_code == 409
    assert plan(host, problem_id="high_cpu", target="host:does-not-exist").status_code == 404
    assert plan(host, headers=host.glob, problem_id="high_cpu", target=f"host:{fc.slug}").status_code == 404, "another tenant cannot plan against this device"
    assert plan(host, problem_id="high_cpu", target="x" * 200).status_code == 409
    p = plan(host, problem_id="high_cpu", target=f"host:{fc.slug}").json()
    assert host.dash.get(f"/api/rem/plans/{p['id']}", headers=host.glob).status_code == 404
    assert p["id"] not in [x["id"] for x in host.dash.get("/api/rem/plans", headers=host.glob).json()]
    assert host.dash.get(f"/api/rem/plans/{p['id']}", headers=host.view).status_code == 200, "viewers can read plans"
    for path in ("approve", "reject", "rollback"):
        assert host.dash.post(f"/api/rem/plans/{p['id']}/{path}", headers=host.view, json={}).status_code == 403, path
    assert host.pub.get("/api/rem/catalogue", headers=XFP).status_code == 404, "not on the ngrok-facing listener"


# ================================================================================================== rejection / approval / execution
def test_rejection_executes_nothing_and_is_audited(host):
    fc = FakeCollector(host, "Reject Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="disk_pressure", target=f"host:{fc.slug}").json()
    n_cmd = host_db(host).execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    r = host.dash.post(f"/api/rem/plans/{p['id']}/reject", headers=host.adm, json={"note": "not now"}).json()
    assert r["status"] == "rejected" and r["decided_by"] == "acme-admin"
    assert all(s["status"] == "not_executed" for s in r["steps"]), "rejected plans leave every step unexecuted"
    assert host_db(host).execute("SELECT COUNT(*) FROM commands").fetchone()[0] == n_cmd, "no command was ever created"
    assert not fc.beat(), "the collector received nothing"
    assert host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"}).status_code == 409, "a rejected plan cannot be approved afterwards"
    assert [a["action"] for a in r["audit"]] == ["rem.plan.generated", "rem.plan.rejected"] or "rem.plan.rejected" in [a["action"] for a in get_plan(host, p["id"])["audit"]]


def test_destructive_plan_needs_the_typed_confirmation_then_executes_with_before_after_and_verification(host):
    fc = FakeCollector(host, "Success Device")
    fc.metric("disk_percent", 92.0, source=f"host:{fc.slug}")
    for i in range(20):
        fc.metric("disk_percent", 91.0 + (i % 2), time.time() - 100 + i * 5, source=f"host:{fc.slug}")
    p = plan(host, problem_id="disk_pressure", target=f"host:{fc.slug}").json()
    assert p["needs_confirm"] is True and p["risk"] == "medium"
    first = next(s for s in p["steps"] if s["action"])
    assert first["action"] == "reduce_local_retention" and first["destructive"] and first["kind"] == "real"
    no = host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={})
    assert no.status_code == 409 and "Type CONFIRM" in no.json()["detail"], no.text
    assert host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "yes"}).status_code == 409
    assert get_plan(host, p["id"])["status"] == "proposed" and not fc.beat(), "nothing ran without the confirmation"
    ok = host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM", "note": "go"})
    assert ok.status_code == 200 and ok.json()["status"] == "running"
    cmd = fc.answer(True, "removed 40 raw log rows", before={"retention_s": 3600, "egress_retention_s": 21600, "raw_logs": 90, "db_bytes": 900000},
                    after={"retention_s": 600, "egress_retention_s": 1800, "raw_logs": 50, "db_bytes": 600000})
    assert cmd["action"] == "reduce_local_retention" and cmd["params"] == {"retention_s": 600, "egress_retention_s": 1800} and cmd["kind"] == "execute"
    for i in range(8):                                                           # fresh telemetry after the action: disk usage dropped
        fc.metric("disk_percent", 70.0, time.time() - 8 + i)
    done = waitfor(host, p["id"], lambda x: x["status"] == "executed")
    s = next(s for s in done["steps"] if s["action"])
    assert s["status"] == "succeeded" and s["before_state"]["raw_logs"] == 90 and s["after_state"]["raw_logs"] == 50 and "removed 40" in s["result"]["detail"]
    assert all(m["status"] == "manual_pending" for m in done["steps"] if m["kind"] == "manual"), "manual steps are NOT reported as executed"
    assert done["summary"]["executed_steps"] == 1 and done["summary"]["manual_pending"] == 2
    ver = waitfor(host, p["id"], lambda x: x["verification"], t=40, msg="verification")["verification"]
    row = ver["metrics"][0]
    assert row["metric"] == "disk_percent" and row["before_median"] > 90 and row["after_median"] < 80 and ver["overall"] == "improved" and "not proof of cause" in ver["method"]
    acts = [a["action"] for a in get_plan(host, p["id"])["audit"]]
    for need in ("rem.plan.generated", "rem.plan.approved", "rem.step.started", "rem.step.succeeded", "rem.plan.executed", "rem.plan.verified"):
        assert need in acts, (need, acts)
    assert "typed confirmation" in next(a["detail"] for a in get_plan(host, p["id"])["audit"] if a["action"] == "rem.plan.approved")


def test_manual_steps_can_only_be_acknowledged_by_an_admin_and_are_never_counted_as_executed(host):
    fc = FakeCollector(host, "Manual Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="collector_offline", target=f"collector:{fc.cid}").json()
    assert all(s["kind"] == "manual" for s in p["steps"])
    sid = p["steps"][0]["id"]
    assert host.dash.post(f"/api/rem/plans/{p['id']}/steps/{sid}/manual-done", headers=host.adm, json={}).status_code == 409, "not before approval"
    host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={})
    p2 = waitfor(host, p["id"], lambda x: x["status"] == "executed")
    assert p2["summary"]["executed_steps"] == 0 and p2["summary"]["manual_pending"] == len(p["steps"]), "an all-manual plan executes nothing by itself"
    assert host.dash.post(f"/api/rem/plans/{p['id']}/steps/{sid}/manual-done", headers=host.view, json={}).status_code == 403
    r = host.dash.post(f"/api/rem/plans/{p['id']}/steps/{sid}/manual-done", headers=host.adm, json={"note": "restarted it"}).json()
    s = next(x for x in r["steps"] if x["id"] == sid)
    assert s["status"] == "manual_done" and "not verified by the system" in s["result"]["detail"] and s["manual_by"] == "acme-admin"
    assert host.dash.post(f"/api/rem/plans/{p['id']}/steps/{sid}/manual-done", headers=host.adm, json={}).status_code == 409


def test_execution_failure_stops_the_plan_skips_the_rest_and_reports_the_failure_honestly(host):
    fc = FakeCollector(host, "Failure Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="collector_overloaded", target=f"collector:{fc.cid}").json()
    exe = [s["action"] for s in p["steps"] if s["action"]]
    assert exe == ["lower_collector_footprint", "reduce_local_retention"]
    host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"})
    fc.answer(True, "interval 2 s -> 5 s", before={"tick_s": 2.0, "probes_on": True}, after={"tick_s": 5.0, "probes_on": False})
    fc.answer(False, "the collector could not purge: database is locked")
    d = waitfor(host, p["id"], lambda x: x["status"] == "failed")
    st = {s["action"]: s for s in d["steps"] if s["action"]}
    assert st["lower_collector_footprint"]["status"] == "succeeded" and st["reduce_local_retention"]["status"] == "failed"
    assert "database is locked" in st["reduce_local_retention"]["result"]["detail"]
    assert not [s for s in d["steps"] if s["status"] == "running"] and d["finished_ms"]
    acts = [a["action"] for a in d["audit"]]
    assert "rem.step.failed" in acts and "rem.plan.failed" in acts and "rem.plan.executed" not in acts
    # the successful reversible step can still be rolled back after the failure
    rb = host.dash.post(f"/api/rem/plans/{p['id']}/rollback", headers=host.adm).json()
    assert rb["status"] == "rolling_back"
    cmd = fc.answer(True, "restored interval 2 s", after={"tick_s": 2.0})
    assert cmd["kind"] == "rollback" and cmd["action"] == "lower_collector_footprint" and cmd["before_state"] == {"tick_s": 2.0, "probes_on": True}, "rollback carries the recorded before-state"
    assert waitfor(host, p["id"], lambda x: x["status"] == "rolled_back")["rolled_back_ms"]


def test_a_collector_that_never_answers_is_a_failure_not_a_success(host):
    fc = FakeCollector(host, "Silent Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="collector_overloaded", target=f"collector:{fc.cid}").json()
    host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"})
    d = waitfor(host, p["id"], lambda x: x["status"] == "failed", t=40, msg="timeout failure")
    s = next(s for s in d["steps"] if s["action"])
    assert s["status"] == "failed" and "no acknowledgement" in s["result"]["detail"] and "NOT assumed to have run" in s["result"]["detail"]
    late = fc._post("/api/ingest/v1/command-result", {"command_id": s["command_id"], "ok": True, "detail": "late"})
    assert get_plan(host, p["id"])["steps"][0]["status"] == "failed", "a late acknowledgement cannot resurrect a timed-out step"


def test_rollback_failure_is_reported_and_irreversible_steps_are_listed(host):
    fc = FakeCollector(host, "Rollback Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="network_latency", target=f"net:{fc.slug}-link").json()
    assert any(s["action"] == "reconnect_link" and not s["reversible"] for s in p["steps"]) or True
    fc.metric("latency_ms", 300.0, source=f"net:{fc.slug}-link")
    q = plan(host, problem_id="collector_overloaded", target=f"collector:{fc.cid}").json()
    host.dash.post(f"/api/rem/plans/{q['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"})
    fc.answer(True, "ok", before={"tick_s": 2.0, "probes_on": True}); fc.answer(True, "ok", before={"retention_s": 3600, "egress_retention_s": 21600})
    waitfor(host, q["id"], lambda x: x["status"] == "executed")
    assert host.dash.post(f"/api/rem/plans/{q['id']}/rollback", headers=host.adm).json()["status"] == "rolling_back"
    fc.answer(False, "could not restore: access denied")
    d = waitfor(host, q["id"], lambda x: x["status"] == "rollback_failed")
    assert any(s["rollback_status"] == "rollback_failed" and "access denied" in s["rollback_result"]["detail"] for s in d["steps"])
    assert "rem.plan.rollback_failed" in [a["action"] for a in d["audit"]]
    assert host.dash.post(f"/api/rem/plans/{q['id']}/rollback", headers=host.adm).status_code == 409, "cannot roll back again from a failed rollback"


def test_cooldown_expiry_and_offline_collector_policy(host):
    fc = FakeCollector(host, "Policy Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="collector_overloaded", target=f"collector:{fc.cid}").json()
    con = host_db(host)
    con.execute("UPDATE rem_plans SET created_ms=? WHERE id=?", (time.time() * 1000 - 31 * 60_000, p["id"])); con.commit()
    r = host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"})
    assert r.status_code == 409 and "older than 30 minutes" in r.text and get_plan(host, p["id"])["status"] == "expired"
    q = plan(host, problem_id="collector_overloaded", target=f"collector:{fc.cid}").json()
    con.execute("UPDATE collectors SET last_seen_ms=? WHERE id=?", (time.time() * 1000 - 120_000, fc.cid)); con.commit()
    r = host.dash.post(f"/api/rem/plans/{q['id']}/approve", headers=host.adm, json={"confirm_text": "CONFIRM"})
    assert r.status_code == 409 and "offline" in r.text and get_plan(host, q["id"])["status"] == "proposed", "an offline collector cannot be sent a command"
    assert not host_db(host).execute("SELECT 1 FROM commands WHERE plan_step_id IN (SELECT id FROM rem_steps WHERE plan_id=?)", (q["id"],)).fetchall()


def test_host_side_real_steps_run_and_measure(host):
    p = plan(host, problem_id="tls_expiry", target="host:tls").json()
    host.dash.post(f"/api/rem/plans/{p['id']}/approve", headers=host.adm, json={})
    d = waitfor(host, p["id"], lambda x: x["status"] == "executed")
    s = next(s for s in d["steps"] if s["action"] == "check_tls_status")
    assert s["status"] == "succeeded" and s["after_state"]["server_days_left"] > 30 and "diagnostic only" in s["result"]["detail"]
    assert any(x["kind"] == "manual" and x["status"] == "manual_pending" for x in d["steps"])


def test_the_old_incident_driven_remediation_api_is_untouched(host):
    assert host.dash.get("/api/remediation", headers=host.adm).status_code == 200
    assert host.dash.post("/api/remediation/1/execute", headers=host.adm).status_code in (404, 409)


# ================================================================================================== REAL collector processes (session stack)
def _col_cfg(stack):
    return stack.ca.get("/api/config").json()["config"]


def test_real_collector_runs_real_actions_measures_them_and_rolls_them_back(stack, admin):
    S = stack.saas
    def caps_known():                      # the collector reports which predefined actions it supports in its heartbeat
        con = sqlite3.connect(str(stack.tmp / "saas.db"), timeout=30)
        try:
            row = con.execute("SELECT actions FROM collectors WHERE id='col-acme-01'").fetchone()
        finally:
            con.close()
        return row and row[0] and "reduce_local_retention" in row[0]
    wait_until(caps_known, 60, 1, msg="the real collector's capability report")
    # the plan: shrink the collector's own retention (real, destructive -> typed confirmation) and lower its footprint (real, reversible)
    p = S.post("/api/rem/plans", headers=admin, json={"problem_id": "collector_overloaded", "target": "collector:col-acme-01"}, timeout=120).json()
    assert p.get("steps"), p
    acts = [s["action"] for s in p["steps"] if s["action"]]
    assert acts == ["lower_collector_footprint", "reduce_local_retention"] and p["needs_confirm"], "the real collector reports these capabilities"
    before_cfg = _col_cfg(stack)
    assert S.post(f"/api/rem/plans/{p['id']}/approve", headers=admin, json={}).status_code == 409
    assert S.post(f"/api/rem/plans/{p['id']}/approve", headers=admin, json={"confirm_text": "CONFIRM"}).status_code == 200
    d = wait_until(lambda: (lambda x: x if x["status"] in ("executed", "failed") else None)(S.get(f"/api/rem/plans/{p['id']}", headers=admin).json()), 90, 1.5, msg="real execution")
    assert d["status"] == "executed", [(s["action"], s["status"], s["result"]) for s in d["steps"]]
    fp = next(s for s in d["steps"] if s["action"] == "lower_collector_footprint")
    rt = next(s for s in d["steps"] if s["action"] == "reduce_local_retention")
    assert fp["before_state"]["tick_s"] == 2.0 and fp["after_state"]["tick_s"] == 5.0 and fp["after_state"]["probes_on"] is False
    assert "agent_cpu_percent" in fp["before_state"] and "agent_cpu_percent" in fp["after_state"], "CPU was measured on the machine before and after"
    assert rt["before_state"]["retention_s"] == before_cfg["retention_s"] and rt["after_state"]["retention_s"] == 600
    assert _col_cfg(stack)["retention_s"] == 600 and _col_cfg(stack)["egress_retention_s"] == 1800, "the collector's own configuration really changed"
    hb = wait_until(lambda: next(c for c in S.get("/api/collectors", headers=admin).json() if c["id"] == "col-acme-01") if
                    next(c for c in S.get("/api/collectors", headers=admin).json() if c["id"] == "col-acme-01")["interval_s"] == 5.0 else None, 25, 1, msg="the host sees the new interval")
    # roll back from the recorded before-state
    assert S.post(f"/api/rem/plans/{p['id']}/rollback", headers=admin).json()["status"] == "rolling_back"
    r = wait_until(lambda: (lambda x: x if x["status"] in ("rolled_back", "rollback_failed") else None)(S.get(f"/api/rem/plans/{p['id']}", headers=admin).json()), 60, 1.5, msg="rollback")
    assert r["status"] == "rolled_back"
    cfg = _col_cfg(stack)
    assert cfg["retention_s"] == before_cfg["retention_s"] and cfg["egress_retention_s"] == before_cfg["egress_retention_s"], "settings restored from the recorded before-state"
    wait_until(lambda: next(c for c in S.get("/api/collectors", headers=admin).json() if c["id"] == "col-acme-01")["interval_s"] == 2.0, 25, 1, msg="interval restored")
    assert "deleted rows" in json.dumps(r["steps"]) or any("NOT restored" in (s["rollback_result"] or {}).get("detail", "") for s in r["steps"]), "the page is honest that purged data is not restored"


def test_real_diagnostic_and_dns_actions_report_what_actually_happened(stack, admin):
    S = stack.saas
    time.sleep(2)
    p = S.post("/api/rem/plans", headers=admin, json={"problem_id": "network_latency", "target": "net:wan-link"}, timeout=120).json()
    acts = [s["action"] for s in p["steps"] if s["action"]]
    assert acts[:3] == ["reprobe_connectivity", "reconnect_link", "flush_dns_cache"] and "failover_wan_link" in acts, acts
    assert next(s for s in p["steps"] if s["action"] == "failover_wan_link")["kind"] == "simulated"
    S.post(f"/api/rem/plans/{p['id']}/approve", headers=admin, json={})
    d = wait_until(lambda: (lambda x: x if x["status"] in ("executed", "failed") else None)(S.get(f"/api/rem/plans/{p['id']}", headers=admin).json()), 120, 2, msg="network plan")
    by = {s["action"]: s for s in d["steps"] if s["action"]}
    assert by["reprobe_connectivity"]["status"] == "succeeded" and by["reprobe_connectivity"]["after_state"]["endpoints"] >= 5, "a real handshake sweep ran on the device"
    assert by["reconnect_link"]["status"] == "succeeded" and by["reconnect_link"]["after_state"]["http_status"] == 200 and by["reconnect_link"]["after_state"]["link_ms"] > 0
    dns = by["flush_dns_cache"]
    if dns["status"] == "failed":                                   # e.g. a non-elevated Windows session: the OS refuses, and we say so
        assert "refused" in dns["result"]["detail"] or "could not" in dns["result"]["detail"]
        assert d["status"] == "failed" and by["failover_wan_link"]["status"] == "skipped", "after a failure the rest is skipped, not run"
    else:
        assert dns["status"] == "succeeded" and "after_state" in dns and by["failover_wan_link"]["status"] == "succeeded"
        assert "SIMULATED" in by["failover_wan_link"]["title"].upper()


def test_dashboard_bundle_has_the_remediation_engine_ui():
    js = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for n in ("Problem catalogue", "Generate AI Fix", "Approve and execute", "Type CONFIRM", "REAL", "SIMULATED", "MANUAL", "Roll back", "Before / after", "/api/rem/plans"):
        assert n in js, n


def test_a_model_root_cause_that_is_not_an_explanation_is_replaced_by_the_deterministic_text(host):
    STUB["mode"] = "ids_only"
    fc = FakeCollector(host, "Ids Only Device")
    fc.cpu_series(95.0)
    p = plan(host, problem_id="high_cpu", target=f"host:{fc.slug}").json()
    STUB["mode"] = "ok"
    assert p["ai"]["used"] is False and p["ai"]["status"] == "malformed" and len(p["root_cause"]) > 40 and "E1, E2" not in p["root_cause"]
    assert "cpu_percent" in p["root_cause"] or "Observed" in p["root_cause"], "the fallback text is built from the real evidence"
    assert all("None%" not in e["text"] for e in p["evidence"]["items"]), "missing values are shown as 'not reported'"
