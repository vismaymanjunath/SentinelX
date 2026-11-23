"""Central Privacy & Security view: built ONLY from data the host already holds. Checks the heartbeat privacy block (closed-world
validation), per-device/fleet endpoints, exact received payloads + hashes, firewall events, TLS/route facts, tenant isolation,
auth, public-listener exclusion, that no raw identifier can reach the dashboard, and a REAL anonymising collector end to end
(including that its local console keeps working)."""
import getpass
import hashlib
import json
import socket
import time
import uuid
from pathlib import Path

import httpx
import pytest

from common.schema import utc_iso, valid_privacy, validate_heartbeat
from .conftest import BASE, wait_until
from .test_remote_ngrok import CODE, Remote, XFP

PRIV = {"breakdown": {"username": 3, "ip": 2, "identifying_field": 7},
        "firewall": {"blocked_events": 1, "blocked_fields": 4, "redactions": 2, "policy_blocked": 0, "redaction_labels": {"aws_access_key": 1, "email": 1}},
        "egress": {"payloads_sent": 5, "events_sent": 40},
        "tls": {"verified": True, "trust": "pinned_ca", "min_tls": "1.2", "error": None}}


# ------------------------------------------------------------------------------------------------ closed-world validation
def test_privacy_block_is_closed_world_so_it_cannot_carry_raw_data():
    ok = json.loads(json.dumps(PRIV))
    ok["egress"].update(payload_id="abcdefgh-1234", sha256="a" * 64)
    assert valid_privacy(ok)
    bad = {
        "unknown key": {**ok, "hostname": "RAHUL-PC"},
        "raw value as breakdown key": {**ok, "breakdown": {"Rahul": 1}},
        "string instead of number": {**ok, "breakdown": {"ip": "192.168.1.15"}},
        "IP as a redaction label": {**ok, "firewall": {"redaction_labels": {"192.168.1.15": 1}}},
        "free text in firewall": {**ok, "firewall": {"blocked_events": "RAHUL-PC"}},
        "mapping smuggled in egress": {**ok, "egress": {"mapping": {"Rahul": "Device-27"}}},
        "bad sha": {**ok, "egress": {"sha256": "RAHUL"}},
        "free-text tls error": {**ok, "tls": {"error": "cert for RAHUL-PC invalid"}},
        "tls trust free text": {**ok, "tls": {"trust": "C:\\Users\\Rahul\\ca.pem"}},
        "too many labels": {**ok, "firewall": {"redaction_labels": {f"label_{i}": 1 for i in range(40)}}},
        "not a dict": "x",
    }
    for name, v in bad.items():
        assert not valid_privacy(v), name
        assert any("bad privacy" in p for p in validate_heartbeat({"collector_id": "col-r-device-1234", "privacy": v})), name


# ------------------------------------------------------------------------------------------------ host endpoints with posted data
@pytest.fixture(scope="module")
def host():
    r = Remote()
    yield r
    r.close()


class Dev:
    """A device enrolled through the real register API that posts heartbeats/payloads like an anonymising collector would."""

    def __init__(self, host, name, via="tunnel"):
        self.host, self.via = host, via
        self.iid = str(uuid.uuid4())
        j = host.pub.post("/api/ingest/v1/register", json={"device_name": name, "join_code": CODE, "install_id": self.iid}, headers=XFP).json()
        self.cid, self.key, self.slug, self.name = j["collector_id"], j["api_key"], j["slug"], name
        self.seq = 0
        self.direct = httpx.Client(base_url=f"https://127.0.0.1:28443", verify=str(host.tmp / "tls" / "ca.pem"), timeout=10)

    def _post(self, path, body, raw=None, via=None):
        h = {"Authorization": "Bearer " + self.key, "Content-Type": "application/json"}
        if (via or self.via) == "tunnel":
            return self.host.pub.post(path, content=raw if raw is not None else json.dumps(body), headers={**XFP, **h})
        return self.direct.post(path, content=raw if raw is not None else json.dumps(body), headers=h)

    def heartbeat(self, privacy=None, anon=True, via=None, **over):
        hb = {"collector_id": self.cid, "version": "1.0.0", "source_tz": "UTC+0000", "sent_at": utc_iso(), "platform": "windows", "os_version": "Windows 11",
              "topology": {"nodes": [{"id": f"host:{self.slug}", "type": "host", "label": self.name}, {"id": f"net:{self.slug}-link", "type": "network", "label": self.name + " link"}],
                           "edges": [[f"host:{self.slug}", f"net:{self.slug}-link"]]}}
        if anon:
            hb["anon"] = {"enabled": True, "policy": "1", "records": 120, "removed": 33, "pseudonymised": 9}
        if privacy is not None:
            hb["privacy"] = privacy
        hb.update(over)
        return self._post("/api/ingest/v1/heartbeat", hb, via=via)

    def payload(self, cpu=12.5, msg=None, via=None):
        self.seq += 1
        ev = [{"event_id": str(uuid.uuid4()), "type": "metric", "source_id": f"host:{self.slug}", "category": "infrastructure", "severity": "info",
               "metric": "cpu_percent", "value": cpu, "unit": "percent", "event_time": utc_iso(), "source_tz": "UTC+0000", "context": {"origin": "real"}}]
        if msg:
            ev.append({"event_id": str(uuid.uuid4()), "type": "alert", "source_id": f"host:{self.slug}", "category": "infrastructure", "severity": "warning",
                       "metric": "cpu_percent", "value": cpu, "unit": "percent", "event_time": utc_iso(), "source_tz": "UTC+0000",
                       "context": {"kind": "threshold", "message": msg}})
        p = {"payload_id": str(uuid.uuid4()), "collector_id": self.cid, "seq": self.seq, "sent_at": utc_iso(), "schema_version": "1.0", "events": ev}
        raw = json.dumps(p, separators=(",", ":"), sort_keys=True)
        return p, raw, self._post("/api/ingest/v1/payload", None, raw=raw, via=via)


def hdr(t):
    return {"Authorization": "Bearer " + t}


def test_overview_device_detail_and_exact_payload_with_hash_proof(host):
    adm = host.admin()
    d = Dev(host, "Device-4101")
    p, raw, r = d.payload(cpu=77.7)
    assert r.status_code == 200
    sha = hashlib.sha256(raw.encode()).hexdigest()
    priv = json.loads(json.dumps(PRIV))
    priv["egress"].update(payload_id=p["payload_id"], sha256=sha)
    assert d.heartbeat(privacy=priv).status_code == 200
    ov = host.dash.get("/api/privacy/overview", headers=adm).json()
    me = next(x for x in ov["devices"] if x["id"] == d.cid)
    assert me["device_id"] == "Device-4101" and me["pseudonymous"] is True and me["anonymisation"] == "enabled"
    assert (me["records"], me["removed"], me["pseudonymised"]) == (120, 33, 9)
    assert me["firewall"]["blocked_fields"] == 4 and me["firewall"]["redaction_labels"] == {"aws_access_key": 1, "email": 1}
    assert me["breakdown"]["username"] == 3 and me["tls"]["verified"] is True and me["tls"]["trust"] == "pinned_ca"
    assert me["tls"]["via"] == "tunnel" and me["tls"]["end_to_end_tls"] is False
    assert me["egress_proof"]["match"] is True and me["last_transmission"]["payload_id"] == p["payload_id"]
    assert ov["tls_totals"]["tunnel"] >= 1 and ov["egress_totals"]["verified_match"] >= 1 and {"devices", "totals", "firewall_totals", "transport"} <= set(ov)
    # device detail
    dd = host.dash.get(f"/api/privacy/devices/{d.cid}", headers=adm).json()
    assert dd["payloads"][0]["payload_id"] == p["payload_id"] and dd["payloads"][0]["exact"]
    # the payload exactly as received: same JSON, same hash, integrity verified, matches what the collector reported
    got = host.dash.get(f"/api/privacy/devices/{d.cid}/payloads/{p['payload_id']}", headers=adm).json()
    assert got["exact"] and got["payload"] == p and got["sha256_host"] == sha and got["integrity_ok"] is True
    assert got["collector_reported_match"] is True and got["policy_findings"] == []
    # a collector reporting the WRONG hash is shown as a mismatch (tamper / transit-corruption signal)
    priv["egress"]["sha256"] = "b" * 64
    d.heartbeat(privacy=priv)
    assert next(x for x in host.dash.get("/api/privacy/overview", headers=adm).json()["devices"] if x["id"] == d.cid)["egress_proof"]["match"] is False
    assert host.dash.get(f"/api/privacy/devices/{d.cid}/payloads/{p['payload_id']}", headers=adm).json()["collector_reported_match"] is False


def test_direct_tls_route_is_observed_and_old_collectors_degrade_gracefully(host):
    adm = host.admin()
    d = Dev(host, "Device-4102")
    assert d.heartbeat(privacy=PRIV, via="direct").status_code == 200
    me = next(x for x in host.dash.get("/api/privacy/overview", headers=adm).json()["devices"] if x["id"] == d.cid)
    assert me["tls"]["via"] == "direct_tls" and me["tls"]["end_to_end_tls"] is True and "TLS endpoint" in me["tls"]["host_observed"]
    old = Dev(host, "Device-4103")                          # a collector build that predates the privacy block
    assert old.heartbeat(privacy=None, anon=True).status_code == 200
    me = next(x for x in host.dash.get("/api/privacy/overview", headers=adm).json()["devices"] if x["id"] == old.cid)
    assert me["privacy_reported"] is False and me["tls"]["reported_by_collector"] is False and me["egress_proof"] == {"reported": False, "match": None}
    assert me["anonymisation"] == "enabled" and me["records"] == 120, "the existing counters still work for older builds"


def test_only_the_newest_exact_bodies_are_kept_older_ones_fall_back_to_stored_events(host):
    from saas.ingest import BODY_KEEP
    adm = host.admin()
    d = Dev(host, "Device-4104")
    first = d.payload(cpu=1.0)
    for i in range(BODY_KEEP + 3):
        assert d.payload(cpu=2.0 + i)[2].status_code == 200
    old = host.dash.get(f"/api/privacy/devices/{d.cid}/payloads/{first[0]['payload_id']}", headers=adm).json()
    assert old["exact"] is False and old["payload"]["events"][0]["value"] == 1.0 and "no longer retained" in old["note"]
    new = host.dash.get(f"/api/privacy/devices/{d.cid}", headers=adm).json()["payloads"]
    assert len(new) == 25 and new[0]["exact"] is True and sum(1 for x in new if x["exact"]) == BODY_KEEP


def test_bad_privacy_blocks_and_identifying_payloads_are_rejected_without_echoing_values(host):
    adm = host.admin()
    d = Dev(host, "Device-4105")
    for bad in ({**PRIV, "hostname": "RAHUL-PC"}, {**PRIV, "firewall": {"redaction_labels": {"192.168.1.15": 1}}}, {**PRIV, "tls": {"error": "RAHUL-PC"}}):
        r = d.heartbeat(privacy=bad)
        assert r.status_code == 422 and "RAHUL" not in r.text and "192.168" not in r.text
    p, raw, r = d.payload(msg="timeout talking to 192.168.1.15 as user=rahul on RAHUL-PC")
    assert r.status_code == 422 and "192.168.1.15" not in r.text and "RAHUL" not in r.text
    fw = host.dash.get("/api/privacy/firewall", headers=adm).json()
    blob = json.dumps(fw)
    assert any(x["collector_id"] == d.cid for x in fw["host_rejections"])
    for leaked in ("192.168.1.15", "RAHUL-PC", "rahul"):
        assert leaked not in blob, leaked
    dd = json.dumps(host.dash.get(f"/api/privacy/devices/{d.cid}", headers=adm).json())
    assert "192.168.1.15" not in dd and "RAHUL" not in dd
    ok = d.payload(msg="timeout on Device-4105 at [REMOVED:ip] user=[REMOVED:username]")
    assert ok[2].status_code == 200


def test_firewall_endpoint_shows_laptop_counters_host_rejections_and_violations(host):
    adm = host.admin()
    d = Dev(host, "Device-4106")
    d.heartbeat(privacy=PRIV)
    d.payload(msg="x at 10.9.8.7")                           # rejected (IP)
    d.payload()                                               # accepted
    fw = host.dash.get("/api/privacy/firewall", headers=adm).json()
    me = next(x for x in fw["devices"] if x["id"] == d.cid)
    assert me["firewall"]["redactions"] == 2 and me["breakdown"]["ip"] == 2
    assert fw["redaction_labels"].get("aws_access_key", 0) >= 1
    assert fw["host_rejections"] and all("10.9.8.7" not in r["reason"] for r in fw["host_rejections"])


# ------------------------------------------------------------------------------------------------ auth, isolation, public listener
def test_auth_tenant_isolation_and_public_listener(host):
    adm = host.admin()
    d = Dev(host, "Device-4107")
    d.heartbeat(privacy=PRIV)
    d.payload()
    paths = ["/api/privacy/overview", f"/api/privacy/devices/{d.cid}", "/api/privacy/firewall", "/api/privacy/contract"]
    for p in paths:
        assert host.dash.get(p).status_code == 401, p
        assert host.pub.get(p, headers=XFP).status_code == 404, p
    v = host.dash.post("/api/login", json={"username": "acme-viewer", "password": "Acme#View2026"}).json()["token"]
    for p in paths:
        assert host.dash.get(p, headers=hdr(v)).status_code == 200, "viewers may read (read-only, host data only)"
    g = hdr(host.dash.post("/api/login", json={"username": "globex-admin", "password": "Globex#Admin2026"}).json()["token"])
    assert host.dash.get(f"/api/privacy/devices/{d.cid}", headers=g).status_code == 404
    pid = host.dash.get(f"/api/privacy/devices/{d.cid}", headers=adm).json()["payloads"][0]["payload_id"]
    assert host.dash.get(f"/api/privacy/devices/{d.cid}/payloads/{pid}", headers=g).status_code == 404
    assert d.cid not in json.dumps(host.dash.get("/api/privacy/overview", headers=g).json())
    assert host.dash.get(f"/api/privacy/devices/{d.cid}/payloads/nope", headers=adm).status_code == 404
    c = host.dash.get("/api/privacy/contract", headers=adm).json()
    assert "hostname" in c["identifying_fields_removed_locally"] and "event_id" in c["top_fields"] and "alert" in c["context_allow"]


def test_dashboard_bundle_has_the_unified_privacy_security_section():
    js = "".join(p.read_text(errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    for n in ("Privacy & Security", "Fleet overview", "Device privacy details", "Egress proof", "Privacy firewall events", "TLS & transport",
              "Pseudonymous device ID", "Actual anonymised payload received by the host", "Exact final payload received by the host",
              "stay on the laptop", "/api/privacy/overview", "/api/privacy/devices/", "never tunnelled and never contacted"):
        assert n in js, n


# ------------------------------------------------------------------------------------------------ REAL anonymising collector
def test_real_collector_appears_in_the_central_privacy_view_with_real_counters_and_exact_payload(host):
    home = host.tmp / "priv-dev"
    ca = str(host.tmp / "tls" / "ca.pem")
    runner = "import uvicorn;import collector.setup as s;uvicorn.run(s.app,host='127.0.0.1',port=29120,log_level='warning')"
    env = {"SENTINEL_REMOTE_DIR": str(home), "COLLECTOR_PORT": "29020", "COLLECTOR_HOST_MODE": "real", "SENTINEL_TLS_CA": ca, "COLLECTOR_TICK_S": "1", "COLLECTOR_HB_S": "2"}
    host.spawn("setup-priv", ["-c", runner], env)
    wait_until(lambda: httpx.get("http://127.0.0.1:29120/").status_code == 200, 20, msg="setup up")
    real = "Test User Laptop"
    r = httpx.post("http://127.0.0.1:29120/connect", json={"server_url": "https://127.0.0.1:28443", "join_code": CODE, "device_name": real, "laptop_id": "LAP-555"}, timeout=40)
    assert r.status_code == 200, r.text
    cid = r.json()["collector_id"]
    adm = host.admin()

    def ready():
        x = next((d for d in host.dash.get("/api/privacy/overview", headers=adm).json()["devices"] if d["id"] == cid), None)
        return x if x and x["privacy_reported"] and x["records"] > 5 and x["egress_proof"]["match"] is True else None
    me = wait_until(ready, 90, 2, msg="real collector reports privacy block and a verified egress hash")
    assert me["pseudonymous"] and me["device_id"].startswith("Device-") and me["anonymisation"] == "enabled" and me["status"] == "online"
    assert me["tls"]["verified"] is True and me["tls"]["trust"] == "pinned_ca" and me["tls"]["min_tls"] == "1.2" and me["tls"]["via"] == "direct_tls"
    assert me["removed"] > 0 and me["breakdown"].get("identifying_field", 0) > 0 and me["last_transmission"]
    # counters at the host never exceed what the laptop itself reports locally (heartbeat lag only)
    col = httpx.Client(base_url="http://127.0.0.1:29020", timeout=10)
    local = col.get("/api/anon").json()
    assert local["stats"]["records"] >= me["records"] > 0 and local["stats"]["removed"] >= me["removed"]
    # the exact payload the host received is the one the collector hashed
    dd = host.dash.get(f"/api/privacy/devices/{cid}", headers=adm).json()
    pid = me["egress_proof"]["payload_id"]
    got = host.dash.get(f"/api/privacy/devices/{cid}/payloads/{pid}", headers=adm).json()
    assert got["exact"] and got["integrity_ok"] and got["collector_reported_match"] is True and got["policy_findings"] == []
    assert hashlib.sha256(json.dumps(got["payload"], separators=(",", ":"), sort_keys=True).encode()).hexdigest() == got["sha256_host"]
    # nothing the privacy endpoints return contains anything raw: this machine's hostname/user, the real device name, the laptop id
    blob = "".join(json.dumps(host.dash.get(p, headers=adm).json()) for p in ("/api/privacy/overview", f"/api/privacy/devices/{cid}", "/api/privacy/firewall",
                                                                                f"/api/privacy/devices/{cid}/payloads/{pid}", "/api/cloud", "/api/privacy/contract")).lower()
    for n in (real, "test user", "lap-555", socket.gethostname(), getpass.getuser()):
        if len(n) >= 4:
            assert n.lower() not in blob, f"central dashboard data contains {n!r}"
    # the LOCAL console is preserved and still has the raw BEFORE/AFTER view (local only)
    assert col.get("/api/status").status_code == 200 and col.get("/api/egress").status_code == 200
    assert real in json.dumps(local["mapping_local_only"]), "the mapping exists only on the laptop's own console"
    assert not any(real in json.dumps(host.dash.get(p, headers=adm).json()) for p in ("/api/privacy/overview", "/api/collectors"))


def test_central_privacy_views_never_contact_a_collector_console():
    src = (BASE / "web" / "src" / "Saas.jsx").read_text(encoding="utf-8")
    region = src[src.index("function PrivacySecurity"):src.index("function Lab(")] + src[src.index("function Cloud("):src.index("function PrivacySecurity")]
    import re
    calls = re.findall(r"api\(([^)]*)\)", region)
    assert calls and all("/api/privacy/" in c or "/api/cloud" in c for c in calls), calls
    assert not any("base" in c for c in calls), "no call may target another origin (collector console)"
    assert "fetch(" not in region and "127.0.0.1:9" not in region and "localhost:9" not in region


def test_preserved_local_console_endpoints_still_exist():
    import ast
    src = (BASE / "collector" / "main.py").read_text(encoding="utf-8")
    for route in ("/api/anon", "/api/egress", "/api/egress/{payload_id}", "/api/status", "/api/firewall/rules", "/api/logs", "/api/sim/{name}"):
        assert f'"{route}"' in src, route
    ast.parse(src)
