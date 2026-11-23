"""Telemetry sources. Host CPU / memory / disk / network-throughput are REAL (psutil); WAN-link latency uses a REAL TCP
probe plus a simulated base path; services are a simulated dependency-coupled fleet so cascades are realistic."""
import hashlib
import hmac
import math
import random
import socket
import time
import uuid
from urllib.parse import urlparse

import psutil

from common.schema import utc_iso
from . import config
from . import anonymise as anon
from .simstate import sim

HOST = f"host:{anon.PUBLIC_SLUG}" if config.REMOTE else "host:app-node"     # PUBLIC_SLUG = pseudonym when anonymising
NET = f"net:{anon.PUBLIC_SLUG}-link" if config.REMOTE else "net:wan-link"
AUTH_SRC = HOST if config.REMOTE else "auth-service"   # where log-derived failed-login signals are attributed
SERVICES = {  # base response ms, dependencies (service -> what it depends on)
    "web-frontend": (90, ["api-gateway"]),
    "api-gateway": (40, ["auth-service", "payment-service", "cache", NET]),
    "auth-service": (35, ["db-primary"]),
    "payment-service": (60, ["db-primary", NET]),
    "cache": (5, [HOST]),
    "db-primary": (12, [HOST]),
}
if config.REMOTE:
    TOPOLOGY = {"nodes": [{"id": HOST, "type": "host", "label": anon.PUBLIC_LABEL[:48]},
                          {"id": NET, "type": "network", "label": (anon.PUBLIC_LABEL[:36] + " link")}],
                "edges": [[HOST, NET]]}   # the laptop depends on its link to the server
else:
    TOPOLOGY = {
        "nodes": [{"id": HOST, "type": "host", "label": "app-node"}, {"id": NET, "type": "network", "label": "wan-link"}] +
                 [{"id": s, "type": "service", "label": s} for s in SERVICES],
        "edges": [[s, d] for s, (_, deps) in SERVICES.items() for d in deps],
    }
_probe_hist = []  # remote mode: rolling success/failure of real probes to the server (-> real packet-loss estimate)

_rng = random.Random(config.SIM_SEED)
_state = {"resp": {s: v[0] for s, v in SERVICES.items()}, "net_prev": None, "sim_t": 0}
psutil.cpu_percent(None)


def host_pseudonym():
    h = socket.gethostname()
    return "host-" + hmac.new(anon.store.salt.encode(), h.encode(), hashlib.sha256).hexdigest()[:8]   # salt never leaves this laptop


def pseudonym(value: str) -> str:
    return "src-" + hmac.new(anon.store.salt.encode(), value.encode(), hashlib.sha256).hexdigest()[:8]


def _port(u):
    """Explicit port, else the scheme default (443 for https) - urlparse().port is None for https://host/."""
    return u.port or (443 if u.scheme == "https" else 80)


def _tcp_probe_ms():
    u = urlparse(config.SAAS_URL)
    t0 = time.perf_counter()
    try:
        with socket.create_connection((u.hostname, _port(u)), timeout=0.4):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def _ev(now, source, category, metric, value, unit, origin, extra=None):
    e = {"event_id": str(uuid.uuid4()), "type": "metric", "source_id": source, "category": category, "severity": "info",
         "metric": metric, "value": round(float(value), 3), "unit": unit, "event_time": utc_iso(now),
         "source_tz": config.SOURCE_TZ, "context": {"origin": origin}}
    if extra:
        e.update(extra)  # local-only fields (hostname, pid...) -> will be stripped by the privacy firewall
    return e


def collect(now: float):
    ev = []
    local = {"hostname": socket.gethostname(), "collector_pid": psutil.Process().pid}
    # ---- host (real by default)
    if config.HOST_MODE == "real":
        cpu = psutil.cpu_percent(None)
        mem = psutil.virtual_memory().percent
        try:
            disk = psutil.disk_usage("C:\\" if psutil.WINDOWS else "/").percent
        except Exception:
            disk = 50.0
        origin = "real"
    else:
        _state["sim_t"] += 1
        cpu = 14 + 3 * math.sin(_state["sim_t"] / 9) + _rng.gauss(0, 1.2)
        mem = 52 + 1.5 * math.sin(_state["sim_t"] / 21) + _rng.gauss(0, 0.3)
        disk = 61.0 + _rng.gauss(0, 0.05)
        origin = "simulated"
    cpu_v = min(99.5, max(0.0, cpu + sim.cpu_extra()))
    mem_v = min(99.5, mem + sim.mem_extra())
    ev.append(_ev(now, HOST, "infrastructure", "cpu_percent", cpu_v, "percent", origin, local))
    ev.append(_ev(now, HOST, "infrastructure", "memory_percent", mem_v, "percent", origin, local))
    ev.append(_ev(now, HOST, "infrastructure", "disk_percent", disk, "percent", origin, local))
    if config.REMOTE:
        return ev + _remote_net(now, sim)
    # ---- network link: real probe + simulated WAN base
    probe = _tcp_probe_ms()
    # the loopback probe is real but not WAN-representative: it contributes at most 15 ms to the simulated WAN path
    base_lat = 24 + _rng.gauss(0, 2.0) + min(probe if probe is not None else 0.5, 15.0)
    lat = base_lat + sim.latency_extra() * (1 + _rng.gauss(0, 0.05))
    loss = max(0.0, abs(_rng.gauss(0.05, 0.05)) + sim.loss_extra() * (1 + _rng.gauss(0, 0.1)))
    io = psutil.net_io_counters()
    prev = _state["net_prev"]
    bw = 38 + _rng.gauss(0, 3)
    if prev:
        dt = max(0.2, now - prev[0])
        bw += ((io.bytes_sent + io.bytes_recv) - prev[1]) * 8 / dt / 1e6
    _state["net_prev"] = (now, io.bytes_sent + io.bytes_recv)
    ev.append(_ev(now, NET, "network", "latency_ms", lat, "ms", "hybrid"))
    ev.append(_ev(now, NET, "network", "packet_loss_pct", min(loss, 60), "percent", "simulated"))
    ev.append(_ev(now, NET, "network", "bandwidth_mbps", max(0.0, bw), "mbps", "hybrid"))
    # ---- services: dependency-coupled response model with lag (EWMA) so effects propagate over a few ticks
    cpu_stress = max(0.0, min(1.0, (cpu_v - 45) / 50))
    mem_stress = max(0.0, min(1.0, sim.mem_extra() / 30.0))  # driven by memory pressure on top of the real baseline
    wan_lat_extra = max(0.0, lat - 40)
    delta = {}
    order = ["cache", "db-primary", "auth-service", "payment-service", "api-gateway", "web-frontend"]
    for s in order:
        base, deps = SERVICES[s]
        own = 0.0
        if s == "db-primary":
            own = base * (9 * cpu_stress + 4 * mem_stress)
        elif s == "cache":
            own = base * (10 * cpu_stress + 12 * mem_stress)
        elif s == "payment-service":
            own = 0.9 * wan_lat_extra + 8 * min(loss, 30)
        elif s == "api-gateway":
            own = 0.8 * wan_lat_extra + 6 * min(loss, 30)
        up = 0.0
        for d in deps:
            if d in delta:
                up = max(up, 0.8 * delta[d] if s not in ("web-frontend",) else 0.7 * delta[d])
        target = base + own + up
        if sim.service_down(s):
            target = base * 40
        cur = _state["resp"][s]
        cur += 0.55 * (target - cur)
        _state["resp"][s] = cur
        resp = cur * (1 + _rng.gauss(0, 0.04))
        delta[s] = max(0.0, cur - base)
        ratio = resp / base
        err = 0.2 + abs(_rng.gauss(0, 0.05)) + min(40.0, 3.0 * max(0.0, ratio - 1.6)) + (1.5 * min(loss, 30) if s in ("payment-service", "api-gateway") else 0)
        down = sim.service_down(s)
        ev.append(_ev(now, s, "service", "response_ms", resp, "ms", "simulated"))
        ev.append(_ev(now, s, "service", "error_rate_pct", min(100.0, 100.0 if down else err), "percent", "simulated"))
        ev.append(_ev(now, s, "service", "availability", 0.0 if down else 1.0, "bool", "simulated"))
    return ev


def _remote_net(now, sim_):
    """REAL link metrics for a remote laptop: TCP RTT to the server endpoint (the ngrok edge when tunnelled), loss = failed-probe ratio
    over the last 30 probes, bandwidth = this machine's actual NIC throughput. Scenario injections still add on top."""
    probe = _tcp_probe_ms_slow()
    _probe_hist.append(probe is not None)
    del _probe_hist[:-30]
    out = []
    if probe is not None:
        out.append(_ev(now, NET, "network", "latency_ms", probe + sim_.latency_extra(), "ms", "real"))
    elif sim_.latency_extra():
        out.append(_ev(now, NET, "network", "latency_ms", sim_.latency_extra(), "ms", "real"))
    loss = 100.0 * (1 - sum(_probe_hist) / len(_probe_hist)) + sim_.loss_extra()
    out.append(_ev(now, NET, "network", "packet_loss_pct", min(loss, 100), "percent", "real"))
    io = psutil.net_io_counters()
    prev = _state["net_prev"]
    _state["net_prev"] = (now, io.bytes_sent + io.bytes_recv)
    if prev:
        dt = max(0.2, now - prev[0])
        out.append(_ev(now, NET, "network", "bandwidth_mbps", ((io.bytes_sent + io.bytes_recv) - prev[1]) * 8 / dt / 1e6, "mbps", "real"))
    return out


def _tcp_probe_ms_slow():
    """Like _tcp_probe_ms but with a timeout suited to a real WAN path."""
    u = urlparse(config.SAAS_URL)
    t0 = time.perf_counter()
    try:
        with socket.create_connection((u.hostname, _port(u)), timeout=1.5):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def reset_service(s):
    if s not in _state["resp"]:
        return
    _state["resp"][s] = SERVICES[s][0]
