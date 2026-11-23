"""Local environment facts the host can correlate with global intelligence. All of it is coarse, public-identifier data:
  * network: this laptop's public ASN + country (from RIPEstat, looked up by the laptop itself; the IP address is never reported)
  * software: vendor/product/version of the OS, Python runtime, this agent's own PyPI dependencies and a few browsers (closed vocabulary)
  * cloud reachability probes: TCP+TLS handshake timing to well-known provider endpoints (real measurements, once a minute)
Disable with COLLECTOR_INVENTORY=0 (network+software) and/or COLLECTOR_PROBES=0 (probes)."""
import os
import platform
import re
import socket
import ssl
import threading
import time
import uuid
from importlib import metadata

import httpx

from common.schema import utc_iso

INVENTORY = os.environ.get("COLLECTOR_INVENTORY", "1").strip().lower() not in ("0", "false", "no", "off")
PROBES_ON = os.environ.get("COLLECTOR_PROBES", "1").strip().lower() not in ("0", "false", "no", "off")
STAT = "https://stat.ripe.net/data"
PYPI = ["fastapi", "uvicorn", "httpx", "httpcore", "h11", "anyio", "starlette", "pydantic", "psutil", "cryptography", "certifi", "idna", "websockets"]
PROBE_TARGETS = [("aws-us-east-1", "ec2.us-east-1.amazonaws.com"), ("aws-eu-west-1", "ec2.eu-west-1.amazonaws.com"),
                 ("aws-ap-south-1", "ec2.ap-south-1.amazonaws.com"), ("aws-me-central-1", "ec2.me-central-1.amazonaws.com"),
                 ("aws-me-south-1", "ec2.me-south-1.amazonaws.com"), ("azure", "management.azure.com"), ("cloudflare", "www.cloudflare.com"),
                 ("gcp", "storage.googleapis.com"), ("github", "github.com")]
RX_VER = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+\-]{0,39}$")
_state = {"network": None, "software": [], "probes": [], "probe_seq": 0, "net_ms": 0, "sw_ms": 0}


def _norm(s):
    return re.sub(r"[^a-z0-9._\-]+", "-", str(s).lower()).strip("-")[:40]


def _entry(eco, vendor, product, version):
    v = str(version or "").strip()
    return {"eco": eco, "vendor": _norm(vendor), "product": _norm(product), "version": v} if v and RX_VER.match(v) else None


def _windows_app(path, name="version"):
    try:
        import winreg
        hive, sub = path
        with winreg.OpenKey(hive, sub) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return None


def software():
    out = []
    s = platform.system()
    if s == "Windows":
        build = platform.version()                                      # e.g. 10.0.26300
        try:
            major = "windows_11" if int(build.split(".")[2]) >= 22000 else "windows_10"
        except (IndexError, ValueError):
            major = "windows"
        out.append(_entry("os", "microsoft", major, build))
        try:
            import winreg
            out.append(_entry("app", "google", "chrome", _windows_app((winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon"))))
            out.append(_entry("app", "microsoft", "edge_chromium", _windows_app((winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Edge\BLBeacon"))))
            out.append(_entry("app", "mozilla", "firefox", _windows_app((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Mozilla\Mozilla Firefox"), "CurrentVersion")))
        except Exception:
            pass
    elif s == "Darwin":
        out.append(_entry("os", "apple", "macos", platform.mac_ver()[0]))
    elif s == "Linux":
        out.append(_entry("os", "linux", "linux_kernel", platform.release().split("-")[0]))
    out.append(_entry("runtime", "python", "python", platform.python_version()))
    for name in PYPI:
        try:
            out.append(_entry("pypi", "pypi", name, metadata.version(name)))
        except metadata.PackageNotFoundError:
            pass
    return [e for e in out if e][:40]


def lookup_network():
    """Own public ASN + country via RIPEstat. The IP is used for the lookup only and is never stored or reported."""
    with httpx.Client(timeout=20, trust_env=False) as c:
        ip = c.get(f"{STAT}/whats-my-ip/data.json").json()["data"]["ip"]
        ni = c.get(f"{STAT}/network-info/data.json", params={"resource": ip}).json()["data"]
        asn = int(ni["asns"][0]) if ni.get("asns") else None
        geo = c.get(f"{STAT}/rir-geo/data.json", params={"resource": ni["prefix"]}).json()["data"]["located_resources"]
        cc = geo[0]["location"] if geo else None
    return {"asn": asn, "country": cc.upper() if isinstance(cc, str) and len(cc) == 2 else None} if asn else None


def probe_once(host, timeout=4.0, ctx=None):
    """Real TCP + TLS handshake (certificate verified). -> (ok, ms)."""
    ctx = ctx or ssl.create_default_context()
    t = time.perf_counter()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                pass
        return True, round((time.perf_counter() - t) * 1000, 1)
    except Exception:
        return False, None


def _loop(stop):
    last_probe = 0
    while not stop.is_set():
        now = time.time()
        try:
            if INVENTORY and now - _state["sw_ms"] > 6 * 3600:
                _state["software"] = software()
                _state["sw_ms"] = now
            if INVENTORY and (_state["network"] is None and now - _state["net_ms"] > 300 or now - _state["net_ms"] > 6 * 3600):
                _state["net_ms"] = now
                _state["network"] = lookup_network() or _state["network"]
        except Exception:
            pass
        if PROBES_ON and now - last_probe >= 60:
            last_probe = now
            ctx = ssl.create_default_context()
            res = [(label, *probe_once(host, ctx=ctx)) for label, host in PROBE_TARGETS]
            _state["probes"], _state["probe_seq"] = res, _state["probe_seq"] + 1
        stop.wait(5)


_started = False


def start(stop):
    global _started
    if not _started and (INVENTORY or PROBES_ON):
        _started = True
        threading.Thread(target=_loop, args=(stop,), daemon=True, name="envinfo").start()


def environment():
    """The heartbeat's `environment` block (closed vocabulary), or None while nothing has been learned yet."""
    env = {}
    if _state["network"]:
        env["network"] = {k: v for k, v in _state["network"].items() if v}
    if _state["software"]:
        env["software"] = _state["software"]
    return env or None


_emitted_seq = [0]


def probe_events(now, slug, tz):
    """Metric events for the newest probe batch (emitted once per batch, i.e. about once a minute). Real handshakes only."""
    if _state["probe_seq"] == _emitted_seq[0]:
        return []
    _emitted_seq[0] = _state["probe_seq"]
    ev = []
    for label, ok, ms in _state["probes"]:
        sid = f"probe:{label}:{slug}"[:64]
        base = {"type": "metric", "source_id": sid, "category": "network", "severity": "info", "event_time": utc_iso(now), "source_tz": tz, "context": {"origin": "real"}}
        ev.append({**base, "event_id": str(uuid.uuid4()), "metric": "probe_ok", "value": 1.0 if ok else 0.0, "unit": "bool"})
        if ok and ms is not None:
            ev.append({**base, "event_id": str(uuid.uuid4()), "metric": "probe_rtt_ms", "value": ms, "unit": "ms"})
    return ev
