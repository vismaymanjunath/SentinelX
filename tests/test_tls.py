"""TLS for laptop->host: HTTPS only, certificate + host-name verification always on, private CA accepted only by fingerprint,
understandable errors for expired / wrong-host / untrusted / self-signed certificates, and a collector that refuses to send."""
import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from collector import tlsutil
from .conftest import BASE, wait_until
from .test_remote_ngrok import CODE, Remote

NOW = dt.datetime.now(dt.timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca(name="Test CA", days=365, start=None):
    k, start = _key(), start or NOW - dt.timedelta(minutes=5)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False).sign(k, hashes.SHA256()))
    return k, c


def make_leaf(ca, names=("127.0.0.1", "localhost"), not_before=None, not_after=None, self_signed=False):
    ca_key, ca_cert = ca
    k = _key()
    nb = not_before or NOW - dt.timedelta(minutes=5)
    na = not_after or NOW + dt.timedelta(days=30)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    san = [x509.IPAddress(ipaddress.ip_address(n)) if n.replace(".", "").isdigit() else x509.DNSName(n) for n in names]
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj if self_signed else ca_cert.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName(san), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False))
    if not self_signed:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    return k, b.sign(k if self_signed else ca_key, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


class TLSServer:
    """A real HTTPS server counting the requests that reach it (a rejected handshake never gets this far)."""

    def __init__(self, leaf_key, leaf_cert):
        self.dir = Path(tempfile.mkdtemp(prefix="sx-tls-"))
        (self.dir / "c.pem").write_bytes(pem(leaf_cert))
        (self.dir / "k.pem").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                                 serialization.NoEncryption()))
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _ok(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.requests.append((self.path, self.rfile.read(n) if n else b""))
                b = json.dumps({"status": "ok", "commands": []}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
            do_POST = do_GET = _ok

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.dir / "c.pem", self.dir / "k.pem")
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture(scope="module")
def pki():
    ca1, ca2 = make_ca("Host CA"), make_ca("Someone Elses CA")
    d = Path(tempfile.mkdtemp(prefix="sx-pki-"))
    (d / "ca1.pem").write_bytes(pem(ca1[1]))
    (d / "ca2.pem").write_bytes(pem(ca2[1]))
    servers = {
        "valid": TLSServer(*make_leaf(ca1)),
        "expired": TLSServer(*make_leaf(ca1, not_before=NOW - dt.timedelta(days=60), not_after=NOW - dt.timedelta(days=1))),
        "wrong_host": TLSServer(*make_leaf(ca1, names=("not-this-host.example",))),
        "untrusted": TLSServer(*make_leaf(ca2)),
        "self_signed": TLSServer(*make_leaf(ca1, self_signed=True)),
    }
    yield {"dir": d, "ca1": ca1, "ca2": ca2, "servers": servers}
    for s in servers.values():
        s.close()


def attempt(url, ca=None):
    with tlsutil.build_client(ca, timeout=5) as c:
        return c.post(url + "/api/ingest/v1/payload", content=b"{}")


# ------------------------------------------------------------------------------------------------ successful encrypted connection
def test_valid_certificate_with_pinned_ca_connects_over_tls_12_or_newer(pki):
    s = pki["servers"]["valid"]
    r = attempt(s.url, pki["dir"] / "ca1.pem")
    assert r.status_code == 200 and len(s.requests) == 1
    ctx = tlsutil.make_context(pki["dir"] / "ca1.pem")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True and ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


# ------------------------------------------------------------------------------------------------ rejection of bad certificates
@pytest.mark.parametrize("which,needle", [("expired", "EXPIRED"), ("wrong_host", "different server name"),
                                          ("untrusted", "not issued by a trusted authority"), ("self_signed", "self-signed")])
def test_invalid_certificates_are_rejected_with_a_clear_message_and_nothing_is_sent(pki, which, needle):
    s = pki["servers"][which]
    with pytest.raises(Exception) as ei:
        attempt(s.url, pki["dir"] / "ca1.pem")
    assert tlsutil.is_tls_error(ei.value)
    msg = tlsutil.explain_tls_error(ei.value)
    assert needle in msg and "Nothing was sent" in msg, msg
    assert s.requests == [], "the request must never be transmitted over an unverified connection"


def test_without_the_private_ca_the_system_trust_store_rejects_the_host(pki):
    s = pki["servers"]["valid"]
    n = len(s.requests)
    with pytest.raises(Exception) as ei:
        attempt(s.url, None)
    assert "not issued by a trusted authority" in tlsutil.explain_tls_error(ei.value) or "self-signed" in tlsutil.explain_tls_error(ei.value)
    assert len(s.requests) == n


def test_non_tls_errors_are_not_mislabelled_as_certificate_problems():
    with pytest.raises(Exception) as ei:
        attempt("https://127.0.0.1:1")
    assert not tlsutil.is_tls_error(ei.value) and "Cannot reach" in tlsutil.explain_tls_error(ei.value)


# ------------------------------------------------------------------------------------------------ https only
def test_http_urls_are_refused_by_the_collector_helpers_and_setup():
    for bad in ("http://host.example", "ftp://x", "host.example", ""):
        with pytest.raises(tlsutil.TLSProblem):
            tlsutil.require_https(bad)
    assert tlsutil.require_https("https://abcd.ngrok-free.app/") == "https://abcd.ngrok-free.app"


def test_collector_refuses_to_start_with_an_unencrypted_server_url():
    cfg = Path(tempfile.mkdtemp()) / "c.json"
    cfg.write_text(json.dumps({"collector_id": "col-x-1", "tenant": "t", "api_key": "sx_k", "region": "eu-west", "source_tz": "UTC",
                               "saas_url": "http://insecure.example:8080", "data_dir": str(cfg.parent / "d")}))
    r = subprocess.run([sys.executable, "-c", "import collector.config"], cwd=BASE, env={**os.environ, "COLLECTOR_CONFIG": str(cfg)},
                       capture_output=True, text=True)
    assert r.returncode != 0 and "unencrypted collector connections are refused" in (r.stderr + r.stdout)


# ------------------------------------------------------------------------------------------------ CA pinning by fingerprint
def test_private_ca_is_accepted_only_with_the_matching_fingerprint_and_only_if_valid(pki):
    good_pem = pem(pki["ca1"][1]).decode()
    fp = tlsutil.fingerprint(good_pem)
    assert tlsutil.check_ca(good_pem, fp)["fingerprint"] == fp
    assert tlsutil.check_ca(good_pem, fp.replace(":", "").lower())["fingerprint"] == fp, "format-insensitive"
    with pytest.raises(tlsutil.TLSProblem, match="does NOT match"):
        tlsutil.check_ca(good_pem, tlsutil.fingerprint(pem(pki["ca2"][1]).decode()))
    with pytest.raises(tlsutil.TLSProblem, match="64 hex"):
        tlsutil.check_ca(good_pem, "abc")
    with pytest.raises(tlsutil.TLSProblem, match="valid PEM"):
        tlsutil.check_ca("not a cert", fp)
    leaf = pem(make_leaf(pki["ca1"])[1]).decode()
    with pytest.raises(tlsutil.TLSProblem, match="not a certificate authority"):
        tlsutil.check_ca(leaf, tlsutil.fingerprint(leaf))
    old = pem(make_ca("Old CA", days=10, start=NOW - dt.timedelta(days=60))[1]).decode()
    with pytest.raises(tlsutil.TLSProblem, match="expired"):
        tlsutil.check_ca(old, tlsutil.fingerprint(old))


def test_setup_page_pins_a_private_ca_only_when_the_fingerprint_matches(pki):
    from fastapi.testclient import TestClient
    import collector.setup as setup
    c = TestClient(setup.app)
    body = {"server_url": pki["servers"]["valid"].url, "join_code": "x", "device_name": "Pin Laptop", "ca_pem": pem(pki["ca1"][1]).decode(),
            "ca_fingerprint": tlsutil.fingerprint(pem(pki["ca2"][1]).decode())}
    r = c.post("/connect", json=body)
    assert r.status_code == 400 and "does NOT match" in r.json()["detail"]
    r = c.post("/connect", json={**body, "ca_fingerprint": "", "ca_pem": "junk"})
    assert r.status_code == 400
    # a certificate the host presents that does not chain to the pinned CA is reported as a certificate problem (495), not a generic error
    r = c.post("/connect", json={**body, "server_url": pki["servers"]["untrusted"].url, "ca_fingerprint": tlsutil.fingerprint(pem(pki["ca1"][1]).decode())})
    assert r.status_code == 495 and "not issued by a trusted authority" in r.json()["detail"] and "Nothing was sent" in r.json()["detail"]
    assert pki["servers"]["untrusted"].requests == []
    r = c.post("/connect", json={**body, "server_url": "http://insecure.example"})
    assert r.status_code == 400


# ------------------------------------------------------------------------------------------------ a real collector against bad certs
def _run_collector(url, ca_path, tmp, port):
    cfg = tmp / "c.json"
    cfg.write_text(json.dumps({"collector_id": "col-r-device-4242", "tenant": "remote", "api_key": "sx_fake", "region": "eu-west", "source_tz": "UTC+0000",
                               "saas_url": url, "ca_cert": str(ca_path), "ui_port": port, "data_dir": str(tmp / "d"), "remote": True,
                               "device_name": "Dana Laptop", "slug": "device-4242", "anonymise": True, "anon_map": str(tmp / "map.json")}))
    f = open(tmp / "collector.log", "w")
    return subprocess.Popen([sys.executable, "-m", "collector.main"], cwd=BASE, stdout=f, stderr=subprocess.STDOUT,
                            env={**os.environ, "COLLECTOR_CONFIG": str(cfg), "COLLECTOR_PORT": str(port), "COLLECTOR_HB_S": "1", "COLLECTOR_TICK_S": "1"})


@pytest.mark.parametrize("which,needle,port", [("expired", "EXPIRED", 29201), ("wrong_host", "different server name", 29202)])
def test_real_collector_refuses_to_send_over_a_bad_certificate_and_says_why(pki, which, needle, port):
    s = pki["servers"][which]
    tmp = Path(tempfile.mkdtemp(prefix="sx-col-"))
    p = _run_collector(s.url, pki["dir"] / "ca1.pem", tmp, port)
    try:
        def status():
            try:
                j = httpx.get(f"http://127.0.0.1:{port}/api/anon", timeout=3).json()
                return j if j["transport"]["last_error"] else None
            except Exception:
                return None
        j = wait_until(status, 40, 1, msg="collector reports the TLS problem")
        assert needle in j["transport"]["last_error"] and "Nothing was sent" in j["transport"]["last_error"]
        st = httpx.get(f"http://127.0.0.1:{port}/api/status", timeout=3).json()
        assert st["link"]["state"] == "buffering" and st["outbox"]["pending"] >= 1, "data is buffered locally, not sent insecurely"
        assert s.requests == [], "no byte of application data reached a server whose certificate failed verification"
    finally:
        p.kill()


def test_real_collector_delivers_over_a_valid_pinned_certificate(pki):
    s = pki["servers"]["valid"]
    n0 = len(s.requests)
    tmp = Path(tempfile.mkdtemp(prefix="sx-col-"))
    p = _run_collector(s.url, pki["dir"] / "ca1.pem", tmp, 29203)
    try:
        wait_until(lambda: any(r[0].endswith("/payload") for r in s.requests[n0:]), 40, 1, msg="payload delivered over verified TLS")
        assert httpx.get("http://127.0.0.1:29203/api/anon", timeout=3).json()["transport"]["last_error"] is None
    finally:
        p.kill()


# ------------------------------------------------------------------------------------------------ the host side
@pytest.fixture(scope="module")
def host():
    r = Remote()
    yield r
    r.close()


def test_host_refuses_unencrypted_ingest_and_enrolment_and_keeps_dashboard_and_ollama_private(host):
    hdr = {"Authorization": "Bearer sx_anything"}
    for path in ("/api/ingest/v1/payload", "/api/ingest/v1/heartbeat", "/api/ingest/v1/register"):
        r = host.dash.post(path, json={}, headers=hdr)           # plain-HTTP listener
        assert r.status_code == 426, (path, r.status_code)
    r = host.pub.post("/api/ingest/v1/register", json={"device_name": "x", "join_code": CODE})   # public listener without a TLS-terminating proxy
    assert r.status_code == 426
    # only the ingest routes exist on the tunnel-facing listener
    for p in ("/", "/api/cloud", "/api/ask", "/api/tls/status", "/api/tls/ca", "/api/incidents/1/ai"):
        assert host.pub.get(p, headers={"X-Forwarded-Proto": "https"}).status_code == 404, p
    # nothing in the project binds the dashboard/Ollama to a non-loopback address by default
    import saas.config as cfg
    assert cfg.HOST == "127.0.0.1" and cfg.OLLAMA_URL.startswith("http://127.0.0.1")


def test_host_reports_tls_facts_and_hands_out_the_ca_fingerprint_to_admins_only(host):
    adm = host.admin()
    t = host.dash.get("/api/tls/status", headers=adm).json()
    assert t["server_days_left"] > 30 and t["ca_days_left"] > 30 and "127.0.0.1" in t["server_names"]
    assert t["transport"]["via_ngrok"]["end_to_end_tls"] is False and "NOT end-to-end" in t["transport"]["via_ngrok"]["note"]
    ca = host.dash.get("/api/tls/ca", headers=adm).json()
    assert ca["fingerprint_sha256"] == t["ca_fingerprint_sha256"] and "BEGIN CERTIFICATE" in ca["pem"] and "PRIVATE" not in ca["pem"]
    assert tlsutil.check_ca(ca["pem"], ca["fingerprint_sha256"])["fingerprint"] == ca["fingerprint_sha256"]
    v = host.dash.post("/api/login", json={"username": "acme-viewer", "password": "Acme#View2026"}).json()["token"]
    assert host.dash.get("/api/tls/ca", headers={"Authorization": "Bearer " + v}).status_code == 403
    assert host.dash.get("/api/tls/ca").status_code == 401


def test_host_certificates_are_renewed_before_they_expire():
    code = (
        "import os, tempfile; os.environ['SENTINEL_DATA_DIR']=tempfile.mkdtemp()\n"
        "from saas import security\n"
        "ca, srv, key = security.ensure_tls(); a = (ca.read_bytes(), srv.read_bytes())\n"
        "security.ensure_tls(); b = (ca.read_bytes(), srv.read_bytes())\n"
        "orig = security._days_left\n"
        "security._days_left = lambda p: 5 if p.name == 'server.pem' else orig(p)\n"      # server cert 'about to expire'
        "security.ensure_tls(); c = (ca.read_bytes(), srv.read_bytes())\n"
        "security._days_left = lambda p: 5 if p.name == 'ca.pem' else orig(p)\n"          # CA 'about to expire'
        "security.ensure_tls(); d = (ca.read_bytes(), srv.read_bytes())\n"
        "print(json.dumps({'stable': a == b, 'server_renewed_same_ca': c[0] == a[0] and c[1] != a[1], 'ca_replaced': d[0] != c[0]})) if False else None\n"
        "import json; print(json.dumps({'stable': a == b, 'server_renewed_same_ca': c[0] == a[0] and c[1] != a[1], 'ca_replaced': d[0] != c[0]}))\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=BASE, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-1500:]
    assert json.loads(r.stdout.strip().splitlines()[-1]) == {"stable": True, "server_renewed_same_ca": True, "ca_replaced": True}
