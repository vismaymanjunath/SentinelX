"""Ask-SENTINEL-X Q&A: routing to real tenant data, privacy (names/secrets never reach the model), failures, malformed output,
tenant isolation, auth, public-listener exclusion, plus a LIVE check against the real local Ollama model."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
import pytest

from .conftest import BASE
from .test_ai import LIVE_MODEL, LIVE_URL, _live_ok
from .test_remote_ngrok import Remote, XFP
from .test_triage import PRELUDE

STUB = r'''
import threading, json, time, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from saas import ai, config, qa
MODE = {"m": "ok", "delay": 0}
LOG = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body):
        b = body.encode(); self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self._send(200, json.dumps({"models": [{"name": config.OLLAMA_MODEL}]}))
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode(); LOG.append(body)
        time.sleep(MODE["delay"]); m = MODE["m"]
        if m == "500": return self._send(500, "boom")
        user = json.loads(body)["messages"][1]["content"]
        ids = re.findall(r"^\[([^\]]+)\]", user, re.M)
        dev = (re.findall(r"device-\d+|host-\d+|service-\d+", user) or ["device-1"])[0]
        out = {"ok": {"answer": f"{dev} is the main concern.", "enough_data": True, "sources": ids[:2] + ["not a real source"]},
               "evil": {"answer": "<script>alert(1)</script> password=hunter2 mail bob@example.com", "enough_data": True, "sources": ids[:1]},
               "empty": {"answer": "  ", "enough_data": True, "sources": []}}.get(m)
        if m == "bad_json": return self._send(200, json.dumps({"message": {"content": "nope {"}}))
        if m == "wrong_shape": return self._send(200, json.dumps({"x": 1}))
        self._send(200, json.dumps({"message": {"content": json.dumps(out)}}))
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
config.OLLAMA_URL = f"http://127.0.0.1:{srv.server_address[1]}"; config.OLLAMA_TIMEOUT_S = 3
T = "acme"
def world(tenant=T):
    coll(tenant, "c-pri", "Demo-Laptop", "windows"); coll(tenant, "c-pix", "Pixel Nine", "android"); coll(tenant, "c-off", "Quiet Server", "linux")
    db.exec("UPDATE collectors SET status='online' WHERE id IN ('c-pri','c-pix')"); db.exec("UPDATE collectors SET status='offline' WHERE id='c-off'")
    ent(tenant, "host:demo", "host"); ent(tenant, "svc:payments", "service"); ent(tenant, "net:wan", "network")
    db.exec("UPDATE entities SET label='Demo-Laptop' WHERE id='host:demo'"); db.exec("UPDATE entities SET label='Payments Gateway' WHERE id='svc:payments'")
    edge(tenant, "svc:payments", "host:demo")
    db.exec("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?,?)", (tenant, "host:demo", "cpu_percent", 93.2, NOW, NOW, "c-pri", "%"))
    db.exec("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?,?)", (tenant, "host:pixel", "battery_percent", 9.0, NOW, NOW, "c-pix", "%"))
    ids = [alert(tenant, "c-pri", "host:demo", "cpu_percent", "critical", "service", 0), alert(tenant, "c-pri", "svc:payments", "response_ms", "warning", "service", 5),
           alert(tenant, "c-off", "collector:c-off", "collector_offline", "critical", "collector", 8),
           alert(tenant, "c-pix", "svc:auth", "failed_logins", "warning", "security", 9, title="Brute force")]
    for i in ids: correlation.correlate(tenant, i)
'''


def run_qa(body, timeout=90):
    tmp = tempfile.mkdtemp(prefix="sx-qa-")
    r = subprocess.run([sys.executable, "-c", PRELUDE + STUB + body], cwd=BASE, env={**os.environ, "SENTINEL_DATA_DIR": tmp},
                       capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, r.stdout[-1500:] + r.stderr[-2500:]
    return json.loads(r.stdout.split("@@")[-1])


# ------------------------------------------------------------------------------------------------ routing uses real data
def test_questions_route_to_the_right_real_data_and_filters_work():
    res = run_qa('''
world()
def ask(q): return qa.ask(T, "u", q)
a = ask("What are the highest priority incidents?"); b = ask("which devices are offline?")
c = ask("how is Demo doing"); d = ask("show incident #1"); e = ask("any security problems?"); f = ask("tell me something random")
out({"a": [x["id"] for x in a["facts"]], "a_t": a["topics"], "b": b["facts"], "c": [x["text"] for x in c["facts"]], "d": [x["id"] for x in d["facts"]],
     "e": [json.loads(x["text"]).get("category") for x in e["facts"] if x["id"].startswith("incident ") and x["id"] != "incident list"], "f_topics": f["topics"],
     "answer": a["answer"], "status": a["status"]})
''')
    assert res["status"] == "ready" and res["answer"].endswith("is the main concern.")
    assert res["a"][0] == "incident list" and all(i.startswith("incident") or i == "incident list" for i in res["a"])
    texts = " ".join(f["text"] for f in res["b"])
    assert "Quiet Server" in texts and '"status": "offline"' in texts, "real names are restored for display"
    assert any("Demo-Laptop" in t and "93.2" in t for t in res["c"]), "partial name 'Demo' resolved; real metric value used"
    assert any(i.startswith("incident 1") for i in res["d"]) and "incident 1 priority factors" in res["d"]
    assert set(res["e"]) == {"Security"}
    assert res["f_topics"] == ["overview"]


# ------------------------------------------------------------------------------------------------ privacy
def test_model_never_receives_names_logs_or_secrets_and_typed_secrets_are_redacted():
    res = run_qa('''
world()
db.exec("UPDATE alerts SET message='login failed password=hunter2 from 203.0.113.9 bob@corp.com', evidence=?", (jd({"raw": "AKIAIOSFODNN7EXAMPLE"}),))
ok = qa.ask(T, "u", "Why is Demo-Laptop slow and is Payments Gateway affected on c-pri / host:demo?")
redacted = qa.ask(T, "u", "check Demo-Laptop, my password=hunter2 and key AKIAIOSFODNN7EXAMPLE")
mail = qa.ask(T, "u", "email bob@corp.com about Pixel Nine from 203.0.113.9")
try:
    qa._ask_model("q", [{"id": "x", "text": "AKIAIOSFODNN7EXAMPLE"}]); gate = False
except ai.AIError as e:
    gate = e.status == "blocked"
out({"sent": "\\n".join(LOG), "ok": ok["status"], "redacted": [redacted["status"], redacted["question_sent"]], "mail": [mail["status"], mail["question_sent"]],
     "gate": gate, "q_sent": ok["question_sent"], "display_has_names": "Demo-Laptop" in json.dumps(ok["facts"])})
''')
    sent = res["sent"]
    for bad in ("Demo", "demo", "Payments", "payments", "Pixel", "Quiet", "c-pri", "c-off", "hunter2", "203.0.113.9", "bob@corp.com", "AKIA", "Brute force", "acme"):
        assert bad not in sent, bad
    assert "device-1" in sent and "host-" in sent or "service-" in sent
    assert res["ok"] == "ready" and res["display_has_names"], "names come back only in what the operator sees"
    assert res["redacted"][0] == "ready" and "hunter2" not in res["redacted"][1] and "AKIA" not in res["redacted"][1], "secrets typed into a question are redacted before sending"
    assert "bob@corp.com" not in res["mail"][1] and "203.0.113.9" not in res["mail"][1]
    assert res["gate"], "the final scan still blocks the call if a secret reaches the prompt by any other route"
    assert "Demo" not in res["q_sent"]


# ------------------------------------------------------------------------------------------------ failures and untrusted output
@pytest.mark.parametrize("mode,status", [("500", "error"), ("bad_json", "malformed"), ("wrong_shape", "malformed"), ("empty", "malformed")])
def test_ollama_failures_and_malformed_output_return_the_facts_and_never_raise(mode, status):
    res = run_qa(f'''
world(); MODE["m"] = "{mode}"
r = qa.ask(T, "u", "which devices are offline?")
out({{"status": r["status"], "answer": r["answer"], "facts": len(r["facts"]), "err": r["error"]}})
''')
    assert res["status"] == status and res["answer"] is None and res["facts"] >= 1 and res["err"]


def test_timeout_ollama_down_remote_url_and_unknown_sources():
    res = run_qa('''
world(); MODE["delay"] = 5
slow = qa.ask(T, "u", "which devices are offline?"); MODE["delay"] = 0
good = config.OLLAMA_URL
config.OLLAMA_URL = "http://127.0.0.1:1"; ai._avail["t"] = 0
down = qa.ask(T, "u", "which devices are offline?")
config.OLLAMA_URL = "http://example.com:11434"; ai._avail["t"] = 0
remote = qa.ask(T, "u", "which devices are offline?")
config.OLLAMA_URL = good; ai._avail["t"] = 0
ok = qa.ask(T, "u", "which devices are offline?")
out({"slow": [slow["status"], slow["error"]], "down": down["status"], "remote": [remote["status"], remote["error"]], "src": ok["sources"],
     "facts_even_when_down": len(down["facts"])})
''')
    assert res["slow"][0] == "error" and "in time" in res["slow"][1]
    assert res["down"] == "unavailable" and res["facts_even_when_down"] >= 1
    assert res["remote"][0] == "unavailable" and "loopback" in res["remote"][1]
    assert res["src"] and "not a real source" not in res["src"], "sources must be ids that were actually in the facts"


def test_output_is_untrusted_redacted_plain_text_and_changes_nothing():
    res = run_qa('''
world(); MODE["m"] = "evil"
before = [db.one("SELECT priority, priority_level, category FROM incidents ORDER BY id"), db.one("SELECT COUNT(*) n FROM remediation")["n"], db.one("SELECT COUNT(*) n FROM commands")["n"]]
r = qa.ask(T, "u", "any problems?")
after = [db.one("SELECT priority, priority_level, category FROM incidents ORDER BY id"), db.one("SELECT COUNT(*) n FROM remediation")["n"], db.one("SELECT COUNT(*) n FROM commands")["n"]]
out({"a": r["answer"], "same": before == after, "audit": [x["detail"] for x in db.all("SELECT detail FROM audit WHERE action='ai.ask'")]})
''')
    assert "hunter2" not in res["a"] and "bob@example.com" not in res["a"]
    assert res["same"], "Q&A is read-only"
    assert res["audit"] and "any problems" not in res["audit"][0], "the question text is not written to the audit log"


def test_no_matching_data_skips_the_model_and_one_request_at_a_time():
    res = run_qa('''
coll(T, "c1", "Solo", "windows")
empty = qa.ask("globex", "u", "what are the P1 incidents?")
world(); MODE["delay"] = 1.5
import threading
box = {}
t = threading.Thread(target=lambda: box.setdefault("first", qa.ask(T, "u1", "which devices are offline?"))); t.start()
time.sleep(0.4)
second = qa.ask(T, "u2", "which devices are offline?")
t.join()
out({"empty": [empty["status"], empty["answer"], len(LOG) if False else None], "first": box["first"]["status"], "second": [second["status"], second["error"], len(second["facts"])]})
''')
    assert res["empty"][0] == "nodata" and res["empty"][1] is None
    assert res["first"] == "ready"
    assert res["second"][0] == "busy" and res["second"][2] >= 1, "busy -> still returns the observed data"


def test_tenant_isolation_names_and_data_never_leak():
    res = run_qa('''
world("acme")
coll("globex", "g1", "Globex Box", "linux"); ent("globex", "host:gbx", "host")
r = qa.ask("globex", "g-user", "tell me about Demo-Laptop and Payments Gateway and incidents")
body = json.dumps(r["facts"]) + "\\n".join(x.split("FACTS:")[-1] for x in LOG)   # data part only: the user's own typed words are theirs
out({"leak": any(w in body for w in ("Demo", "Payments", "Pixel", "Quiet", "c-pri")), "q": r["question_sent"], "status": r["status"]})
''')
    assert res["leak"] is False


# ------------------------------------------------------------------------------------------------ API / bundle
@pytest.fixture(scope="module")
def srv():
    r = Remote()
    yield r
    r.close()


def test_api_auth_validation_and_public_listener(srv):
    adm = srv.admin()
    t = srv.dash.post("/api/login", json={"username": "acme-viewer", "password": "Acme#View2026"}).json()["token"]
    view = {"Authorization": "Bearer " + t}
    assert srv.dash.post("/api/ask", json={"question": "hi"}).status_code == 401
    assert srv.dash.post("/api/ask", headers=adm, json={"question": "   "}).status_code == 400
    assert srv.dash.post("/api/ask", headers=adm, json={"question": "x" * 301}).status_code == 400
    r = srv.dash.post("/api/ask", headers=view, json={"question": "which devices are online?"}, timeout=150)   # viewers may ask (read-only)
    assert r.status_code == 200 and {"facts", "status", "topics"} <= set(r.json())
    assert any("Acme Site-01" in f["text"] for f in r.json()["facts"]), "real tenant data in the facts"
    g = srv.dash.post("/api/login", json={"username": "globex-admin", "password": "Globex#Admin2026"}).json()["token"]
    rg = srv.dash.post("/api/ask", headers={"Authorization": "Bearer " + g}, json={"question": "which devices are online?"}, timeout=150).json()
    assert not any("Acme" in f["text"] for f in rg["facts"])
    assert srv.pub.post("/api/ask", headers={**XFP, "Authorization": adm["Authorization"]}, json={"question": "x"}).status_code == 404


def test_dashboard_bundle_has_ask_page():
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for n in ("Ask SENTINEL X", "Observed data used", "AI answer", "/api/ask", "Nothing is executed"):
        assert n in js, n


# ------------------------------------------------------------------------------------------------ LIVE
@pytest.mark.skipif(not _live_ok(), reason="local Ollama with qwen2.5:1.5b not available")
def test_live_real_model_answers_questions_from_real_data():
    body = '''
config.OLLAMA_URL = "http://127.0.0.1:11434"; config.OLLAMA_TIMEOUT_S = 200; ai._avail["t"] = 0
world(); res = []
for q in ("What are the highest priority incidents right now?", "Which devices are offline?", "Which device has the lowest battery?"):
    r = qa.ask(T, "u", q); res.append({"q": q, "status": r["status"], "answer": r["answer"], "sources": r["sources"], "enough": r["enough_data"], "topics": r["topics"], "s": round(r["duration_ms"]/1000, 1), "sent_q": r["question_sent"]})
out(res)
'''
    res = run_qa(body, timeout=600)
    if os.environ.get("QA_LIVE_OUT"):
        Path(os.environ["QA_LIVE_OUT"]).write_text(json.dumps(res, indent=2))
    assert all(r["status"] == "ready" and r["answer"] for r in res), res


def test_comparisons_are_computed_in_python_not_left_to_the_model():
    res = run_qa('''
world()
r = qa.ask(T, "u", "Which device has the lowest battery?")
ex = next(f for f in r["facts"] if f["id"] == "extremes battery_percent")
out({"ex": json.loads(ex["text"]), "sent_has_pixel": "Pixel" in "".join(LOG)})
''')
    assert res["ex"]["lowest"] == {"device": "Pixel Nine", "value": 9.0}, "restored for display from the real latest-value table"
    assert res["sent_has_pixel"] is False


def test_live_answer_to_lowest_battery_names_the_right_device():
    if not _live_ok():
        pytest.skip("local Ollama not available")
    res = run_qa('''
config.OLLAMA_URL = "http://127.0.0.1:11434"; config.OLLAMA_TIMEOUT_S = 200; ai._avail["t"] = 0
world(); r = qa.ask(T, "u", "Which device has the lowest battery?")
out({"status": r["status"], "answer": r["answer"]})
''', timeout=300)
    assert res["status"] == "ready" and "Pixel Nine" in res["answer"], res


def test_capitalised_placeholders_are_restored_and_named_device_pulls_in_its_incidents():
    res = run_qa('''
world()
r = qa.ask(T, "u", "Why is Demo-Laptop in trouble?")
ps = qa.Pseudo(T); ps.collector("c-pri")
out({"ids": [f["id"] for f in r["facts"]], "topics": r["topics"], "restored": ps.restore("Device-1 is slow and DEVICE-1 too, service-9 unknown")})
''')
    assert res["restored"] == "Demo-Laptop is slow and Demo-Laptop too, service-9 unknown"
    assert "open incidents" in " ".join(res["topics"]) and any(i.startswith("incident ") for i in res["ids"])
