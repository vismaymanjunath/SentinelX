"""ngrok remote-collector path: join code, ingest-only public listener, forwarded-header trust, registration and
authenticated telemetry. The public listener is exercised exactly as ngrok would use it (plain HTTP from loopback with
X-Forwarded-Proto: https). A real ngrok tunnel / separate laptop is NOT part of these tests."""
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import psutil
import pytest

from saas.public import ALLOWED, PublicIngest
from .conftest import BASE, wait_until

HTTP, HTTPS, PUB = 28080, 28443, 28090
SETUP_OK, SETUP_NOCA, CONSOLE = 29100, 29101, 29001
CODE = "test-join-code-7f3a91"
XFP = {"X-Forwarded-Proto": "https"}


class Remote:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sx-ngrok-"))
        self.env = {**os.environ, "SENTINEL_DATA_DIR": str(self.tmp), "SAAS_HTTP_PORT": str(HTTP), "SAAS_HTTPS_PORT": str(HTTPS),
                    "SAAS_PUBLIC_PORT": str(PUB), "SENTINEL_JOIN_CODE": CODE}
        self.procs = []
        subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, env=self.env, check=True, capture_output=True)
        self.saas_proc = self.spawn("saas", ["-m", "saas.main"])
        self.pub = httpx.Client(base_url=f"http://127.0.0.1:{PUB}", timeout=10)
        self.dash = httpx.Client(base_url=f"http://127.0.0.1:{HTTP}", timeout=10)
        wait_until(lambda: self.dash.get("/api/whoami").status_code == 200, 30, msg="saas up")
        wait_until(lambda: self.pub.get("/nope").status_code == 404, 30, msg="public listener up")

    def spawn(self, name, args, extra=None):
        f = open(self.tmp / f"{name}.log", "w")
        p = subprocess.Popen([sys.executable] + args, cwd=BASE, stdout=f, stderr=subprocess.STDOUT, env={**self.env, **(extra or {})})
        self.procs.append(p)
        return p

    def register(self, name, code=CODE, headers=XFP, body=None):
        return self.pub.post("/api/ingest/v1/register", json=body if body is not None else {"device_name": name, "join_code": code}, headers=headers)

    def admin(self):
        t = self.dash.post("/api/login", json={"username": "acme-admin", "password": "Acme#Admin2026"}).json()["token"]
        return {"Authorization": "Bearer " + t}

    def close(self):
        for p in self.procs:   # kill whole trees: collector.setup spawns a collector child that would otherwise outlive the test
            try:
                for ch in psutil.Process(p.pid).children(recursive=True):
                    ch.kill()
            except psutil.Error:
                pass
            p.terminate()


@pytest.fixture(scope="module")
def remote():
    r = Remote()
    yield r
    r.close()


# ----------------------------------------------------------------------------- proxy-header trust (unit, no network)
def _run_wrapper(peer, headers, path="/api/ingest/v1/heartbeat", method="POST"):
    seen = {}

    async def inner(scope, receive, send):
        seen["scheme"], seen["client"] = scope["scheme"], scope.get("client")
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    scope = {"type": "http", "method": method, "path": path, "scheme": "http", "client": (peer, 5555),
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    asyncio.run(PublicIngest(inner)(scope, receive, send))
    return seen, out[0]["status"]


def test_forwarded_headers_trusted_only_from_loopback():
    seen, st = _run_wrapper("127.0.0.1", {"X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.7, 10.0.0.1"})
    assert st == 204 and seen["scheme"] == "https" and seen["client"][0] == "198.51.100.7"
    for peer in ("203.0.113.9", "10.1.2.3"):   # a non-local peer can never assert https or a client address
        seen, st = _run_wrapper(peer, {"X-Forwarded-Proto": "https", "X-Forwarded-For": "1.2.3.4"})
        assert st == 204 and seen["scheme"] == "http" and seen["client"][0] == peer
    seen, _ = _run_wrapper("127.0.0.1", {"X-Forwarded-Proto": "http"})
    assert seen["scheme"] == "http"
    seen, _ = _run_wrapper("127.0.0.1", {})
    assert seen["scheme"] == "http"


def test_wrapper_allows_exactly_the_ingest_routes():
    for method, path in ALLOWED:
        assert _run_wrapper("127.0.0.1", {}, path, method)[1] == 204
    for method, path in [("GET", "/"), ("GET", "/api/overview"), ("POST", "/api/login"), ("GET", "/api/ingest/v1/register"),
                         ("POST", "/api/ingest/v1/ledger"), ("GET", "/api/ingest/v1/payload"), ("POST", "/api/ingest/v1/payload/"),
                         ("POST", "/api/ingest/v1/payload/../login"), ("GET", "/docs")]:
        assert _run_wrapper("127.0.0.1", {}, path, method)[1] == 404, (method, path)


# ----------------------------------------------------------------------------- live public listener
def test_public_listener_exposes_only_ingestion_routes(remote):
    for path in ["/", "/index.html", "/assets/index.js", "/api/login", "/api/me", "/api/overview", "/api/incidents", "/api/alerts",
                 "/api/whoami", "/api/thresholds", "/api/audit", "/api/perf", "/api/ledger", "/api/events", "/api/topology",
                 "/docs", "/openapi.json", "/ws", "/api/ingest/v1/unknown", "/api/ingest/v1/payload/x"]:
        r = remote.pub.get(path, headers=XFP)
        assert r.status_code == 404, f"{path} leaked through the public listener ({r.status_code})"
    assert remote.pub.post("/api/login", json={"username": "acme-admin", "password": "Acme#Admin2026"}, headers=XFP).status_code == 404
    assert remote.pub.get("/api/ingest/v1/register", headers=XFP).status_code == 404       # wrong method
    # websocket upgrade is refused
    import websockets.sync.client as wsc
    with pytest.raises(Exception):
        with wsc.connect(f"ws://127.0.0.1:{PUB}/ws?token=x", open_timeout=5):
            pass


def test_dashboard_and_ingest_listeners_bound_to_loopback_only(remote):
    p = psutil.Process(remote.saas_proc.pid)
    conns = p.net_connections(kind="tcp") if hasattr(p, "net_connections") else p.connections(kind="tcp")
    listen = {c.laddr.port: c.laddr.ip for c in conns if c.status == "LISTEN"}
    for port in (HTTP, HTTPS, PUB):
        assert listen.get(port) in ("127.0.0.1", "::1"), f"port {port} is not loopback-only: {listen}"


def test_ingest_requires_https_signal_on_public_listener(remote):
    for h in ({}, {"X-Forwarded-Proto": "http"}):
        assert remote.register("x1", headers=h).status_code == 426
        assert remote.pub.post("/api/ingest/v1/heartbeat", json={}, headers={**h, "Authorization": "Bearer sx_nope"}).status_code == 426
    # with the forwarded https signal the request proceeds to the normal checks
    assert remote.pub.post("/api/ingest/v1/heartbeat", json={}, headers={**XFP, "Authorization": "Bearer sx_nope"}).status_code == 401


def test_enrollment_disabled_without_join_code_configured(stack):
    cfg = stack.cfg["acme"]       # the main test stack runs WITHOUT SENTINEL_JOIN_CODE
    c = httpx.Client(verify=cfg["ca_cert"], base_url=f"https://localhost:18443")
    r = c.post("/api/ingest/v1/register", json={"device_name": "x", "join_code": ""})
    assert r.status_code == 403 and "disabled" in r.text


def test_join_code_validation_and_registration(remote):
    for bad in ({"device_name": "A1"}, {"device_name": "A1", "join_code": ""}, {"device_name": "A1", "join_code": "wrong"},
                {"device_name": "A1", "join_code": 12345}, {"device_name": "A1", "join_code": [CODE]}, {"device_name": "A1", "join_code": CODE + "x"}):
        r = remote.register("A1", body=bad)
        assert r.status_code == 403, bad
        assert CODE not in r.text
    assert remote.register("A1", body=["not", "an", "object"]).status_code == 400
    assert remote.register("bad/name!").status_code == 400
    ok = remote.register("Alice Laptop")
    assert ok.status_code == 200
    j = ok.json()
    assert j["collector_id"] == "col-r-alice-laptop" and j["api_key"].startswith("sx_") and CODE not in ok.text
    # reconnecting the same device keeps one fleet entry and rotates the key
    j2 = remote.register("Alice Laptop").json()
    assert j2["collector_id"] == j["collector_id"] and j2["api_key"] != j["api_key"]
    remote.keys = {"old": j["api_key"], "new": j2["api_key"]}


def test_registration_then_bearer_authenticated_telemetry(remote):
    hb = {"collector_id": "col-r-alice-laptop", "version": "1.0.0", "config_version": 1, "source_tz": "UTC+0000", "host_id": "host-abc12345",
          "buffer_depth": 0, "link_state": "connected", "sent_at": "2026-01-01T00:00:00.000Z",
          "topology": {"nodes": [{"id": "host:alice-laptop", "type": "host", "label": "Alice Laptop"}], "edges": []}}
    h = {**XFP, "Authorization": "Bearer " + remote.keys["new"]}
    assert remote.pub.post("/api/ingest/v1/heartbeat", json=hb, headers=h).status_code == 200
    assert remote.pub.post("/api/ingest/v1/heartbeat", json=hb, headers={**XFP, "Authorization": "Bearer " + remote.keys["old"]}).status_code == 401, "rotated key must stop working"
    assert remote.pub.post("/api/ingest/v1/heartbeat", json=hb, headers=XFP).status_code == 401
    assert remote.pub.post("/api/ingest/v1/heartbeat", json={**hb, "hostname": "LAPTOP-X"}, headers=h).status_code == 422, "allow-list still enforced"
    fleet = remote.dash.get("/api/collectors", headers=remote.admin()).json()
    me = next(c for c in fleet if c["id"] == "col-r-alice-laptop")
    assert me["name"] == "Alice Laptop" and me["status"] == "online"
    # payload ingest + ledger work through the tunnel path as well
    assert remote.pub.get("/api/ingest/v1/ledger", headers=h).status_code == 200


def test_secrets_not_stored_or_logged(remote):
    time.sleep(1)
    c = sqlite3.connect(str(remote.tmp / "saas.db"))
    dump = []
    for t in ("audit", "collectors", "rejected", "events", "alerts"):
        dump += [json.dumps(dict(zip([d[0] for d in cur.description], r)), default=str) for cur in [c.execute(f"SELECT * FROM {t}")] for r in cur]
    text = "\n".join(dump) + (remote.tmp / "saas.log").read_text(errors="ignore")
    assert CODE not in text, "join code leaked into DB/logs"
    for k in remote.keys.values():
        assert k not in text, "collector API key stored/logged in plaintext (only its hash may be stored)"


# ----------------------------------------------------------------------------- collector side
def test_setup_url_normalisation_and_validation():
    from fastapi import HTTPException
    from collector.setup import normalize_url
    assert normalize_url("abcd.ngrok-free.app") == "https://abcd.ngrok-free.app"
    assert normalize_url(" https://abcd.ngrok-free.app/ ") == "https://abcd.ngrok-free.app"
    assert normalize_url("https://abcd.ngrok-free.app:8443") == "https://abcd.ngrok-free.app:8443"
    for bad in ("http://abcd.ngrok-free.app", "https://abcd.ngrok-free.app/api/login", "https://user:pw@abcd.ngrok-free.app",
                "https://abcd.ngrok-free.app/?x=1", "ftp://x.y", "https://"):
        with pytest.raises(HTTPException):
            normalize_url(bad)


def test_latency_probe_defaults_to_443_for_https_urls():
    cfg = Path(tempfile.mkdtemp()) / "c.json"
    cfg.write_text(json.dumps({"collector_id": "col-x-1111", "tenant": "t", "api_key": "sx_k", "region": "eu-west", "source_tz": "UTC",
                               "saas_url": "https://abcd.ngrok-free.app", "ca_cert": None, "data_dir": str(cfg.parent / "d"), "remote": True,
                               "slug": "x", "device_name": "x"}))
    code = ("from urllib.parse import urlparse;import collector.sources as s;from collector import config;"
            "print(s._port(urlparse(config.SAAS_URL)), s._port(urlparse('https://h:8443')), s._port(urlparse('http://h')), config.CA_CERT)")
    out = subprocess.run([sys.executable, "-c", code], cwd=BASE, env={**os.environ, "COLLECTOR_CONFIG": str(cfg)}, capture_output=True, text=True)
    assert out.stdout.split() == ["443", "8443", "80", "None"], out.stdout + out.stderr


def test_setup_connect_streams_real_metrics_and_keeps_tls_verification(remote):
    ca = str(remote.tmp / "tls" / "ca.pem")
    runner = "import uvicorn;import collector.setup as s;uvicorn.run(s.app,host='127.0.0.1',port={p},log_level='warning')"
    common = {"SENTINEL_REMOTE_DIR": str(remote.tmp / "dev"), "COLLECTOR_PORT": str(CONSOLE), "COLLECTOR_HOST_MODE": "real"}
    remote.spawn("setup-ca", ["-c", runner.format(p=SETUP_OK)], {**common, "SENTINEL_TLS_CA": ca})
    remote.spawn("setup-noca", ["-c", runner.format(p=SETUP_NOCA)], {**common, "SENTINEL_REMOTE_DIR": str(remote.tmp / "dev2"), "COLLECTOR_PORT": "29002"})
    wait_until(lambda: httpx.get(f"http://127.0.0.1:{SETUP_OK}/").status_code == 200, 20, msg="setup up")
    wait_until(lambda: httpx.get(f"http://127.0.0.1:{SETUP_NOCA}/").status_code == 200, 20, msg="setup2 up")
    url = f"https://127.0.0.1:{HTTPS}"
    # no private CA configured -> system trust store is used -> our self-signed local server is rejected (verification really on)
    r = httpx.post(f"http://127.0.0.1:{SETUP_NOCA}/connect", json={"server_url": url, "join_code": CODE, "device_name": "NoCA"}, timeout=30)
    assert r.status_code == 495 and "Nothing was sent" in r.text and ("not issued by a trusted authority" in r.text or "self-signed" in r.text)
    # wrong code / bad inputs
    s = f"http://127.0.0.1:{SETUP_OK}/connect"
    assert httpx.post(s, json={"server_url": url, "join_code": "nope", "device_name": "Bob Laptop"}, timeout=30).status_code == 403
    assert httpx.post(s, json={"server_url": "http://x.y", "join_code": CODE, "device_name": "Bob"}, timeout=30).status_code == 400
    assert httpx.post(s, json={"server_url": url, "join_code": "", "device_name": "Bob"}, timeout=30).status_code == 400
    # happy path
    # (legacy path: anonymise=False keeps the real device name visible at the host; the anonymised path is covered in test_anon.py)
    r = httpx.post(s, json={"server_url": url, "join_code": CODE, "device_name": "Bob Laptop", "anonymise": False}, timeout=30)
    assert r.status_code == 200, r.text
    cfg = json.loads((remote.tmp / "dev" / "collector.json").read_text())
    assert CODE not in json.dumps(cfg) and cfg["api_key"].startswith("sx_") and cfg["remote"] is True
    h = remote.admin()

    def entities():
        ov = remote.dash.get("/api/overview", headers=h).json()
        e = {x["id"]: x for x in ov["entities"]}
        host, net = e.get("host:bob-laptop"), e.get("net:bob-laptop-link")
        if host and net and {"cpu_percent", "memory_percent", "disk_percent"} <= set(host["metrics"]) \
                and {"latency_ms", "packet_loss_pct", "bandwidth_mbps"} <= set(net["metrics"]):
            return ov
    ov = wait_until(entities, 60, 1, msg="bob's real metrics at the SaaS")
    bob = next(c for c in ov["collectors"] if c["id"] == "col-r-bob-laptop")
    assert bob["status"] == "online" and bob["age_s"] < 15
    ev = remote.dash.get("/api/events?limit=300", headers=h).json()
    real = {"cpu_percent", "memory_percent", "disk_percent", "latency_ms", "packet_loss_pct", "bandwidth_mbps"}
    origins = {x["context"].get("origin") for x in ev if x["type"] == "metric" and x["metric"] in real and "bob" in x["source_id"]}
    assert origins == {"real"}, origins


def test_zz_join_code_bruteforce_lockout(remote):
    codes = [remote.register("Brute", code=f"guess{i}").status_code for i in range(10)]
    # failures from earlier tests in the same 60 s window count too, so the lockout may start early
    first_429 = codes.index(429)
    assert codes[:first_429] == [403] * first_429 and set(codes[first_429:]) == {429}, codes
    assert remote.register("Brute", code=CODE).status_code == 429, "lockout applies even to the right code until the window passes"
