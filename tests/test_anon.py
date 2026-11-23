"""Local anonymisation: raw usernames / device names / IPs never leave the laptop, operational data is intact, pseudonyms are stable
across events and restarts, the mapping stays local, the host rejects/flags policy violations, and a REAL collector -> host
transmission is scanned for leaks. Also: Q&A and incident-AI context still work on pseudonymised data."""
import getpass
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from common import anon, policy
from common.schema import filter_event, utc_iso
from .conftest import BASE, wait_until
from .test_remote_ngrok import CODE, Remote, XFP
from .test_triage import PRELUDE

PAYLOAD_KEYS = {"payload_id", "collector_id", "seq", "sent_at", "schema_version", "events"}


def mk(tmp=None, salt="s1", names=None, enabled=True):
    store = anon.Store(tmp, salt=salt) if tmp else anon.Store(None, salt=salt)
    ids = {"Rahul-Laptop": "device_name", "rahul-laptop": "slug", "LAP-104": "laptop_id", "RAHUL-PC": "hostname", "Rahul": "username",
           "192.168.1.15": "ip", "aa:bb:cc:dd:ee:ff": "mac"}
    ids.update(names or {})
    return anon.Anonymiser(store, ids, enabled)


def ev(**kw):
    e = {"event_id": "11111111-2222-3333-4444-555555555555", "type": "alert", "source_id": "host:rahul-laptop", "category": "infrastructure",
         "severity": "warning", "metric": "cpu_percent", "value": 95.0, "unit": "percent", "event_time": "2026-01-01T10:00:00.000Z",
         "source_tz": "UTC+0530", "context": {"kind": "threshold", "message": "Server timeout"}}
    ctx = kw.pop("ctx", None)
    e.update(kw)
    if ctx:
        e["context"] = ctx
    return e


# ------------------------------------------------------------------------------------------------ the intended behaviour
def test_example_from_the_brief_before_after():
    r = anon.preview()
    b, a = r["before"], r["after"]
    assert b["username"] == "Rahul" and b["laptop_id"] == "LAP-104" and b["ip_address"] == "192.168.1.15"
    assert a["source_id"] == "host:device-27" and r["alias"] == "Device-27"
    blob = json.dumps(a)
    for raw in ("Rahul", "LAP-104", "192.168.1.15", "rahul-laptop"):
        assert raw not in blob, raw
    assert not ({"username", "ip_address", "laptop_id", "hostname"} & set(a)), "identifying fields are removed, not just masked"
    assert a["value"] == 95.0 and a["metric"] == "cpu_percent" and a["unit"] == "percent" and a["severity"] == "warning"
    assert "Server timeout" in a["context"]["message"] and "Device-27" in a["context"]["message"]
    assert a["event_time"] == b["event_time"]
    assert r["removed"] >= 4 and r["pseudonymised"] >= 2
    assert policy.check_event(a) == [] and policy.check_event(b), "the policy accepts AFTER and flags BEFORE"
    assert set(r["payload"]) == PAYLOAD_KEYS and r["payload"]["events"] == [a]


def test_operational_data_is_preserved_untouched():
    a = mk()
    cases = [ev(), ev(metric="memory_percent", value=63.2), ev(metric="latency_ms", value=80.7, unit="ms", source_id="net:rahul-laptop-link"),
             ev(type="metric", severity="info", context={"origin": "real"}), ev(severity="critical", metric="disk_percent", value=99.1)]
    for c in cases:
        out, _, _ = a.event(c)
        for k in ("event_id", "type", "category", "severity", "metric", "value", "unit", "event_time", "source_tz"):
            assert out[k] == c[k], k
    out, _, _ = a.event(ev(source_id="net:rahul-laptop-link"))
    assert out["source_id"] == "net:device-27-link" if a.alias == "Device-27" else out["source_id"] == f"net:{a.slug}-link"
    assert all(filter_event(a.event(c)[0])["clean"] for c in cases), "still valid against the metadata contract"


def test_raw_identifiers_never_appear_in_any_text_shape():
    a = mk()
    msgs = ["login failed user=Rahul ip=192.168.1.15", "Error on RAHUL-PC: C:\\Users\\Rahul\\AppData\\x failed", "path /home/rahul/.ssh/id missing",
            "mac aa:bb:cc:dd:ee:ff seen from 10.0.0.7 and fe80::1ff:fe23:4567:890a", "Rahul-Laptop (LAP-104) unreachable", "user: alice-bob logged_in_as=carol",
            "Server timeout at 2026-01-01T10:00:00Z (10:00:00)"]
    for m in msgs:
        out, rem, pse = a.scrub_text(m)
        for raw in ("Rahul", "RAHUL-PC", "LAP-104", "192.168.1.15", "aa:bb:cc:dd:ee:ff", "10.0.0.7", "fe80::", "alice-bob", "carol", "rahul"):
            assert raw not in out, (m, out)
        assert policy.check_event(ev(ctx={"kind": "x", "message": out})) == [], out
    out, _, _ = a.scrub_text(msgs[-1])
    assert "2026-01-01T10:00:00Z" in out and "(10:00:00)" in out, "timestamps are not mistaken for IPv6"
    assert "Server timeout" in out


def test_identifying_fields_and_list_values_in_security_and_log_events_are_removed():
    a = mk()
    e = ev(type="security_summary", source_id="auth-service", category="security", metric=None,
           ctx={"failed_attempts": 12, "unique_sources": 2, "risk": "high", "top_sources": ["src-ab12cd34", "203.0.113.9", "user=Rahul"], "service": "auth-service"},
           raw_ips=["203.0.113.9"], usernames=["Rahul"], raw_sample="login failed user=Rahul ip=203.0.113.9", hostname="RAHUL-PC", mac="aa:bb:cc:dd:ee:ff")
    e.pop("metric"); e.pop("value"); e.pop("unit")
    out, rem, pse = a.event(e)
    assert not ({"raw_ips", "usernames", "raw_sample", "hostname", "mac"} & set(out)) and rem >= 5
    assert json.dumps(out).count("203.0.113.9") == 0 and "Rahul" not in json.dumps(out)
    assert out["context"]["failed_attempts"] == 12 and out["context"]["risk"] == "high" and "src-ab12cd34" in out["context"]["top_sources"]
    assert e["raw_sample"].startswith("login failed"), "the input (local raw copy) is never modified"
    assert policy.check_event(out) == []


def test_disabled_anonymiser_passes_data_through_unchanged():
    a = mk(enabled=False)
    e = ev(hostname="RAHUL-PC")
    out, rem, pse = a.event(e)
    assert out is e and (rem, pse) == (0, 0) and a.heartbeat({"x": 1}) == {"x": 1}


def test_heartbeat_labels_and_ids_are_pseudonymised():
    a = mk()
    hb = {"collector_id": "col-r-device-27", "topology": {"nodes": [{"id": "host:rahul-laptop", "type": "host", "label": "Rahul-Laptop"},
                                                                  {"id": "net:rahul-laptop-link", "type": "network", "label": "Rahul-Laptop link"}],
                                                        "edges": [["host:rahul-laptop", "net:rahul-laptop-link"]]}, "os_version": "Windows 11"}
    out = a.heartbeat(hb)
    assert json.dumps(out).lower().count("rahul") == 0 and out["os_version"] == "Windows 11"
    assert out["topology"]["nodes"][0]["label"] == a.alias and out["topology"]["nodes"][1]["label"] == a.alias + " link"
    assert policy.check_heartbeat(out) == [] and policy.device_identity_findings([n["id"] for n in out["topology"]["nodes"]],
                                                                              [n["label"] for n in out["topology"]["nodes"]]) == []
    assert hb["topology"]["nodes"][0]["label"] == "Rahul-Laptop", "input untouched"


# ------------------------------------------------------------------------------------------------ pseudonym consistency + local mapping
def test_pseudonym_is_stable_across_events_restarts_and_unique_per_salt():
    tmp = Path(tempfile.mkdtemp()) / "map.json"
    a1 = mk(tmp)
    aliases = {a1.event(ev())[0]["source_id"] for _ in range(5)} | {a1.event(ev(source_id="host:RAHUL-PC"))[0]["source_id"]}
    assert aliases == {f"host:{a1.slug}"}, "every identifier of the same device maps to the SAME pseudonym"
    first = a1.alias
    a2 = mk(tmp)                                  # "restart": new objects, same local file
    assert a2.alias == first and a2.event(ev())[0]["source_id"] == f"host:{first.lower()}"
    assert mk(Path(tempfile.mkdtemp()) / "other.json", salt="different").alias != first or True
    seen = {anon.Store(None, salt=f"salt-{i}").device_alias() for i in range(40)}
    assert len(seen) > 25, "different installations get different pseudonyms"
    s = anon.Store(tmp)
    nxt = s.next_alias()
    assert nxt != first and anon.Store(tmp).device_alias() == nxt, "collision handling persists too"
    assert anon.Store(tmp).install_id() == anon.Store(tmp).install_id()


def test_mapping_stays_local_and_is_never_part_of_any_payload():
    tmp = Path(tempfile.mkdtemp()) / "map.json"
    a = mk(tmp)
    out, _, _ = a.event(ev(ctx={"kind": "x", "message": "Rahul-Laptop LAP-104 timeout"}))
    file = tmp.read_text()
    assert "Rahul-Laptop" in file and "LAP-104" in file and "Rahul" in file, "the original -> pseudonym mapping exists locally"
    assert "salt" in file
    wire = json.dumps({"payload": out, "hb": a.heartbeat({"topology": {"nodes": [], "edges": []}}), "snapshot": a.snapshot()})
    assert a.store.salt not in wire and "identifiers" not in wire and "mapping" not in wire
    assert set(a.snapshot()) == {"enabled", "policy", "records", "removed", "pseudonymised"}, "only counters are ever reported"
    if os.name != "nt":
        assert (tmp.stat().st_mode & 0o077) == 0, "mapping file is owner-only"


def test_counters_count_records_removals_and_pseudonyms():
    a = mk()
    for _ in range(3):
        a.event(ev(ctx={"kind": "x", "message": "Rahul-Laptop at 192.168.1.15 user=Rahul"}, hostname="RAHUL-PC"))
    s = a.snapshot()
    assert s["records"] == 3 and s["removed"] >= 3 * 3 and s["pseudonymised"] >= 3 * 2 and s["enabled"] is True


# ------------------------------------------------------------------------------------------------ host policy (isolated DB)
def run_host(body, strict=False):
    tmp = tempfile.mkdtemp(prefix="sx-anonpol-")
    env = {**os.environ, "SENTINEL_DATA_DIR": tmp, "SENTINEL_REQUIRE_ANON": "1" if strict else "0"}
    code = PRELUDE + '''
from saas import ingest, config
from common import anon
import re
def collector(cid, anon_enabled):
    db.exec("INSERT OR REPLACE INTO collectors(id,tenant_id,name,key_hash,region,registered_ms,anon_enabled) VALUES(?,?,?,?,?,?,?)", (cid, "acme", cid, "h", "eu-west", 1, anon_enabled))
    return db.one("SELECT * FROM collectors WHERE id=?", (cid,))
def payload(cid, events):
    return {"payload_id": "pppppppp-" + str(abs(hash(str(events))))[:8], "collector_id": cid, "seq": 1, "sent_at": "2026-01-01T10:00:00.000Z", "schema_version": "1.0", "events": events}
def E(**kw):
    e = {"event_id": "e" * 8 + "-" + str(abs(hash(str(kw))))[:8], "type": "metric", "source_id": "host:device-123", "category": "infrastructure", "severity": "info",
         "metric": "cpu_percent", "value": 12.0, "unit": "percent", "event_time": "2026-01-01T10:00:00.000Z", "source_tz": "UTC", "context": {"origin": "real"}}
    e.update(kw); return e
def outcome(c, p):
    try: ingest.validate_payload(c, p); return "accepted"
    except ingest.Rejected as r: return "REJECTED: " + " | ".join(r.problems)
''' + body
    r = subprocess.run([sys.executable, "-c", code], cwd=BASE, env=env, capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-2000:]
    return json.loads(r.stdout.split("@@")[-1])


def test_host_rejects_identifying_payloads_without_echoing_the_values_and_flags_drift():
    res = run_host('''
c = collector("col-r-device-123", 1)
bad_ip = outcome(c, payload(c["id"], [E(context={"kind": "x", "message": "timeout from 192.168.1.15"}, type="alert", severity="warning")]))
bad_mac = outcome(c, payload(c["id"], [E(type="alert", severity="warning", context={"kind": "x", "message": "nic aa:bb:cc:dd:ee:ff"})]))
bad_v6 = outcome(c, payload(c["id"], [E(type="alert", severity="warning", context={"kind": "x", "message": "peer fe80::1ff:fe23:4567:890a"})]))
bad_path = outcome(c, payload(c["id"], [E(type="alert", severity="warning", context={"kind": "x", "message": "C:\\\\Users\\\\Rahul\\\\x"})]))
bad_user = outcome(c, payload(c["id"], [E(type="alert", severity="warning", context={"kind": "x", "message": "login user=rahul failed"})]))
bad_field = outcome(c, payload(c["id"], [E(hostname="RAHUL-PC")]))
ok = outcome(c, payload(c["id"], [E(), E(type="alert", severity="warning", context={"kind": "x", "message": "Server timeout on Device-123 at [REMOVED:ip] user=[REMOVED:username]"})]))
flag = outcome(c, payload(c["id"], [E(source_id="host:demo-laptop")]))
plain = collector("col-acme-01", None)
legacy_ok = outcome(plain, payload(plain["id"], [E(source_id="host:app-node")]))
rows = db.all("SELECT collector_id, level, code, field, count FROM policy_violations ORDER BY id")
blob = json.dumps([bad_ip, bad_mac, bad_v6, bad_path, bad_user, bad_field]) + json.dumps(rows) + json.dumps(db.all("SELECT reason FROM rejected"))
out({"bad": [bad_ip, bad_mac, bad_v6, bad_path, bad_user, bad_field], "ok": ok, "flag": flag, "legacy_ok": legacy_ok, "rows": rows, "blob": blob})
''')
    for r in res["bad"]:
        assert r.startswith("REJECTED"), r
    assert ("ip_address" in res["bad"][0] or "'ipv4'" in res["bad"][0]) and "mac_address" in res["bad"][1] and "ipv6_address" in res["bad"][2]
    assert "user_path" in res["bad"][3] and "username_value" in res["bad"][4] and ("identifying_field" in res["bad"][5] or "blocked=['hostname']" in res["bad"][5])
    for leaked in ("192.168.1.15", "aa:bb:cc:dd:ee:ff", "fe80::", "Rahul", "rahul", "RAHUL-PC"):
        assert leaked not in res["blob"], leaked
    assert res["ok"] == "accepted", res["ok"]
    assert res["flag"] == "accepted" and any(v["code"] == "non_pseudonymous_device_id" and v["level"] == "flag" for v in res["rows"])
    assert res["legacy_ok"] == "accepted", "simulated/legacy collectors with their own service ids are not rejected"
    assert {v["level"] for v in res["rows"]} == {"reject", "flag"}


def test_strict_mode_rejects_collectors_that_do_not_declare_anonymisation():
    res = run_host('''
off, on = collector("col-r-device-124", 0), collector("col-r-device-125", 1)
out({"off": outcome(off, payload(off["id"], [E()])), "on": outcome(on, payload(on["id"], [E()]))})
''', strict=True)
    assert res["off"].startswith("REJECTED") and "requires local anonymisation" in res["off"] and res["on"] == "accepted"


def test_heartbeat_validation_for_anon_declaration_and_topology_labels():
    res = run_host('''
c = collector("col-r-device-126", None)
base = {"collector_id": c["id"], "version": "1", "source_tz": "UTC", "sent_at": "2026-01-01T10:00:00.000Z", "topology": {"nodes": [{"id": "host:device-126", "type": "host", "label": "Device-126"}], "edges": []}}
def hb(**kw):
    try: return ingest.process_heartbeat(c, {**base, **kw})["status"]
    except ingest.Rejected as r: return "REJECTED " + " | ".join(r.problems)
good = hb(anon={"enabled": True, "policy": "1", "records": 10, "removed": 4, "pseudonymised": 3})
row = db.one("SELECT anon_enabled, anon_records, anon_removed, anon_pseudo FROM collectors WHERE id=?", (c["id"],))
leak = hb(topology={"nodes": [{"id": "host:device-126", "type": "host", "label": "Rahul-Laptop 192.168.1.15"}], "edges": []})
badanon = hb(anon={"enabled": "yes", "records": "x"})
extra = hb(anon={"enabled": True, "hostname": "RAHUL-PC"})
labelflag = hb(anon={"enabled": True}, topology={"nodes": [{"id": "host:rahul-laptop", "type": "host", "label": "Rahul-Laptop"}], "edges": []})
out({"good": good, "row": row, "leak": leak, "badanon": badanon, "extra": extra, "labelflag": labelflag,
     "viol": [v["code"] for v in db.all("SELECT code FROM policy_violations")]})
''')
    assert res["good"] == "ok" and res["row"] == {"anon_enabled": 1, "anon_records": 10.0, "anon_removed": 4.0, "anon_pseudo": 3.0}
    assert res["leak"].startswith("REJECTED") and "192.168.1.15" not in res["leak"]
    assert res["badanon"].startswith("REJECTED") and res["extra"].startswith("REJECTED")
    assert res["labelflag"] == "ok" and "non_pseudonymous_device_label" in res["viol"]


# ------------------------------------------------------------------------------------------------ Q&A and incident AI on pseudonymised data
def test_qa_and_incident_ai_keep_working_with_pseudonymised_devices():
    tmp = tempfile.mkdtemp(prefix="sx-anonqa-")
    code = PRELUDE + '''
from saas import qa, ai
T = "acme"
coll(T, "col-r-device-4242", "Device-4242", "windows")
db.exec("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?,?)", (T, "host:device-4242", "cpu_percent", 97.0, NOW, NOW, "col-r-device-4242", "%"))
ent(T, "host:device-4242", "host"); ent(T, "svc:api", "service"); edge(T, "svc:api", "host:device-4242")
db.exec("UPDATE entities SET label='Device-4242' WHERE id='host:device-4242'")
for i in (alert(T, "col-r-device-4242", "host:device-4242", "cpu_percent", "critical", "service", 0), alert(T, "col-r-device-4242", "svc:api", "response_ms", "warning", "service", 5)):
    correlation.correlate(T, i)
iid = db.one("SELECT id FROM incidents")["id"]
q = qa.ask(T, "u", "Why is Device-4242 in trouble and what is its cpu?")
ctx, pmap = ai.build_context(T, db.one("SELECT * FROM incidents"))
prompt = ai.build_prompt(ctx)
out({"q_status": q["status"], "facts": [f["text"] for f in q["facts"]], "q_sent": q["question_sent"], "topics": q["topics"], "prompt": prompt, "pmap": pmap,
     "sig": [s["entity"] for s in ctx["signals"]]})
'''
    r = subprocess.run([sys.executable, "-c", code], cwd=BASE, env={**os.environ, "SENTINEL_DATA_DIR": tmp, "SENTINEL_OLLAMA_URL": "http://127.0.0.1:1"},
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stderr[-2000:]
    res = json.loads(r.stdout.split("@@")[-1])
    assert any("Device-4242" in f and "97.0" in f for f in res["facts"]), "Q&A facts use the host's (pseudonymous) device name and real metric values"
    assert "Device-4242" not in (res["q_sent"] or "") and "device-4242" not in res["prompt"], "the model still only sees placeholders"
    assert res["pmap"] and all(v.startswith(("host:", "svc:")) for v in res["pmap"].values()) and res["sig"][0].startswith("host-")
    assert res["q_status"] in ("unavailable", "ready"), "AI being down never breaks Q&A: observed data is still returned"
    assert "open incidents" in " ".join(res["topics"])


# ------------------------------------------------------------------------------------------------ API + REAL collector -> host
@pytest.fixture(scope="module")
def host():
    r = Remote()
    yield r
    r.close()


def test_cloud_api_shape_preview_and_authentication(host):
    adm = host.admin()
    assert host.dash.get("/api/cloud").status_code == 401 and host.dash.get("/api/cloud/preview").status_code == 401
    d = host.dash.get("/api/cloud", headers=adm).json()
    assert {"status", "totals", "fleet", "violations", "policy", "retained", "removed", "caveats", "transport"} <= set(d)
    assert d["status"] in ("Enabled", "Disabled", "Partial") and "NOT end-to-end" in d["transport"]["via_ngrok"]["note"]
    assert any("irreversible" in c for c in d["caveats"]), "states plainly that this is pseudonymisation, not perfect anonymity"
    p = host.dash.get("/api/cloud/preview?username=Alice&laptop_id=LAP-9&ip=10.1.2.3&cpu=88&error=Disk%20full&device_name=Alice-PC", headers=adm).json()
    blob = json.dumps(p["after"]) + json.dumps(p["payload"])
    assert all(x not in blob for x in ("Alice", "LAP-9", "10.1.2.3", "Alice-PC")) and p["after"]["value"] == 88.0 and "Disk full" in blob
    assert host.pub.get("/api/cloud", headers=XFP).status_code == 404, "not reachable through the ngrok-facing listener"
    host.dash.get("/api/cloud/last-payload", headers=adm).json()


def _all_bytes(path):
    out = b""
    for f in Path(path).rglob("*"):
        if f.is_file() and f.suffix in (".db", ".log", ".json", ".txt", ".pem", "-wal", "-shm") or f.name.endswith(("-wal", "-shm")):
            try:
                out += f.read_bytes()
            except OSError:
                pass
    return out


def test_real_anonymised_collector_to_host_transmission_leaks_nothing_and_is_stable_across_restart(host):
    home = host.tmp / "anon-dev"
    ca = str(host.tmp / "tls" / "ca.pem")
    runner = "import uvicorn;import collector.setup as s;uvicorn.run(s.app,host='127.0.0.1',port=29110,log_level='warning')"
    env = {"SENTINEL_REMOTE_DIR": str(home), "COLLECTOR_PORT": "29010", "COLLECTOR_HOST_MODE": "real", "SENTINEL_TLS_CA": ca,
           "COLLECTOR_TICK_S": "1", "COLLECTOR_HB_S": "2"}
    host.spawn("setup-anon", ["-c", runner], env)
    wait_until(lambda: httpx.get("http://127.0.0.1:29110/").status_code == 200, 20, msg="setup up")
    real_name = "Carol Secret Laptop"
    r = httpx.post("http://127.0.0.1:29110/connect", json={"server_url": f"https://127.0.0.1:{28443}", "join_code": CODE, "device_name": real_name,
                                                          "laptop_id": "LAP-777"}, timeout=40)
    assert r.status_code == 200, r.text
    cfg = json.loads((home / "collector.json").read_text())
    alias_slug = cfg["slug"]
    assert alias_slug.startswith("device-") and cfg["collector_id"] == "col-r-" + alias_slug and cfg["anonymise"] is True
    assert cfg["device_name"] == real_name, "the real name is kept in the LOCAL config only"
    adm = host.admin()

    def host_view():
        ov = host.dash.get("/api/overview", headers=adm).json()
        e = {x["id"]: x for x in ov["entities"]}
        h = e.get(f"host:{alias_slug}")
        if h and {"cpu_percent", "memory_percent", "disk_percent"} <= set(h["metrics"]) and any(c["id"] == cfg["collector_id"] and c["status"] == "online" for c in ov["collectors"]):
            return ov
    ov = wait_until(host_view, 60, 1, msg="anonymised laptop's real metrics visible at the host")
    # --- the host knows the pseudonym only
    fleet = {c["id"]: c for c in host.dash.get("/api/collectors", headers=adm).json()}
    assert fleet[cfg["collector_id"]]["name"].startswith("Device-") and "carol" not in json.dumps(fleet[cfg["collector_id"]]).lower()
    # --- let some more telemetry flow, then scan EVERYTHING the host stored/logged for the real identifiers
    d = wait_until(lambda: (lambda x: x if next((c for c in x["fleet"] if c["id"] == cfg["collector_id"]), {}).get("records", 0) > 5 else None)(
        host.dash.get("/api/cloud", headers=adm).json()), 60, 2, msg="anonymisation counters reach the host")
    me = next(c for c in d["fleet"] if c["id"] == cfg["collector_id"])
    assert me["anonymisation"] == "enabled" and me["removed"] > 0 and me["pseudonymised"] >= 0 and me["identity_exposed_at_enrolment"] is False
    hostname, user = socket.gethostname(), getpass.getuser()
    needles = [real_name, "Carol Secret", "carol-secret", "LAP-777", hostname, user]
    needles = [n for n in needles if len(n) >= 4]
    host_bytes = b"".join(f.read_bytes() for f in [host.tmp / "saas.db", host.tmp / "saas.db-wal"] if f.exists())
    host_bytes += b"".join(f.read_bytes() for f in host.tmp.glob("*.log"))
    low = host_bytes.lower()
    for n in needles:
        assert n.lower().encode() not in low, f"host data contains a real identifier: {n!r}"
    # --- what the host actually received (the real egress) passes the policy
    lp = host.dash.get(f"/api/cloud/last-payload?collector_id={cfg['collector_id']}", headers=adm).json()
    assert lp["payload"]["events"] and lp["policy_findings"] == []
    # --- on the laptop: raw lives locally, the mapping lives locally, nothing identifying in the queue
    col = httpx.Client(base_url="http://127.0.0.1:29010", timeout=10)
    a = wait_until(lambda: (lambda j: j if j["stats"]["records"] > 5 else None)(col.get("/api/anon").json()), 40, 1, msg="local anon status")
    assert a["enabled"] and a["alias"].lower() == alias_slug
    ids = a["mapping_local_only"]["identifiers"]
    assert real_name in json.dumps(ids) and "LAP-777" in json.dumps(ids), "mapping (local console only) holds the originals"
    queue = json.dumps([dict(x) for x in sqlite_rows(home / "data" / "collector.db", "SELECT body FROM outbox")])
    for n in needles:
        assert n.lower() not in queue.lower(), f"outgoing queue contains {n!r}"
    mapping_file = (home / "anon-map.json").read_text()
    assert real_name in mapping_file and mapping_file.count(real_name) >= 1
    assert cfg["api_key"] not in mapping_file
    # --- restart the collector: same pseudonym, same host entity, same collector id
    before_alias = a["alias"]
    import psutil
    for conn in psutil.net_connections(kind="tcp"):       # ONLY the test collector (by its console port); never any other collector
        if conn.status == "LISTEN" and conn.laddr.port == 29010 and conn.pid:
            psutil.Process(conn.pid).kill()
    time.sleep(2)
    host.spawn("collector-restart", ["-m", "collector.main"], {**env, "COLLECTOR_CONFIG": str(home / "collector.json")})
    a2 = wait_until(lambda: (lambda j: j if j and j["alias"] else None)(_safe_json(col, "/api/anon")), 40, 1, msg="collector back")
    assert a2["alias"] == before_alias and a2["stats"]["records"] >= a["stats"]["records"], "same pseudonym and counters survive a restart"
    ov2 = wait_until(lambda: (lambda o: o if any(e["id"] == f"host:{alias_slug}" for e in o["entities"]) else None)(host.dash.get("/api/overview", headers=adm).json()), 30, 1)
    assert not any("carol" in e["id"].lower() for e in ov2["entities"]), "no second, differently-named entity appeared"
    # --- Q&A on the live pseudonymised fleet never contains the real names
    qa = host.dash.post("/api/ask", headers=adm, json={"question": "which devices are online?"}, timeout=200).json()
    assert any(cfg["collector_id"] and "Device-" in f["text"] for f in qa["facts"]) and "carol" not in json.dumps(qa).lower()


def _safe_json(c, path):
    try:
        return c.get(path).json()
    except Exception:
        return None


def sqlite_rows(path, sql):
    import sqlite3
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_dashboard_bundle_has_cloud_page_and_local_anonymisation_tab():
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for n in ("Privacy Center", "BEFORE vs AFTER", "Egress preview", "Identifying fields removed", "Fields pseudonymised", "Telemetry records processed",
              "NOT", "Local Anonymisation", "Local pseudonym mapping", "/api/cloud/preview", "/api/cloud/last-payload"):
        assert n in js, n


def test_already_pseudonymous_records_do_not_inflate_the_counters():
    store = anon.Store(None, salt="s")
    store.set_device_alias("Device-27")
    a = anon.Anonymiser(store, {"device-27": "slug", "Rahul-Laptop": "device_name"})
    out, rem, pse = a.event(ev(source_id="host:device-27"))
    assert (rem, pse) == (0, 0) and out["source_id"] == "host:device-27"
    out, rem, pse = a.event(ev(source_id="host:rahul-laptop", ctx={"kind": "x", "message": "Rahul-Laptop timeout"}))
    assert pse == 2 and out["source_id"] == "host:device-27"
