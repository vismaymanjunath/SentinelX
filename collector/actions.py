"""Predefined remediation actions executed ON THE COLLECTOR. Nothing here accepts a command string: each action is a Python function with
range-checked parameters. The only subprocess is a fixed, hard-coded argv per OS (DNS cache flush). Every action returns measured
before/after values taken from the machine itself, and reversible ones can be rolled back from their recorded before-state."""
import os
import platform
import socket
import statistics
import subprocess
import time
from urllib.parse import urlparse

import psutil

from . import config, envinfo, tlsutil
from .db import db

CAPABILITIES = ["reconnect_link", "flush_dns_cache", "reprobe_connectivity", "lower_collector_footprint", "reduce_local_retention"]
PARAMS = {"lower_collector_footprint": {"tick_s": (2.0, 30.0), "probes_off": bool}, "reduce_local_retention": {"retention_s": (60, 86400), "egress_retention_s": (120, 86400)}}


def validate(action, params):
    """Bounded, typed parameters only. Unknown keys are rejected rather than ignored."""
    params = params or {}
    spec = PARAMS.get(action, {})
    if set(params) - set(spec):
        raise ValueError(f"unexpected parameter(s) for {action}: {sorted(set(params) - set(spec))}")
    out = {}
    for k, rule in spec.items():
        if k not in params:
            continue
        v = params[k]
        if rule is bool:
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be true/false")
            out[k] = v
        else:
            lo, hi = rule
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
                raise ValueError(f"{k} must be a number between {lo} and {hi}")
            out[k] = float(v) if isinstance(lo, float) else int(v)
    if action == "lower_collector_footprint" and not out:
        raise ValueError("nothing to change")
    return out


def _dns_ms():
    host = urlparse(config.SAAS_URL).hostname
    ts = []
    for _ in range(3):
        t = time.perf_counter()
        try:
            socket.getaddrinfo(host, 443)
            ts.append((time.perf_counter() - t) * 1000)
        except OSError:
            return None
    return round(statistics.median(ts), 2)


def _db_bytes():
    try:
        return os.path.getsize(config.DB_PATH)
    except OSError:
        return None


def run(engine, action, params, rollback=False, before_state=None):
    """-> (ok, detail, before, after). Raises ValueError only for invalid parameters."""
    if action not in CAPABILITIES:
        return False, "action not supported by this collector build", None, None
    params = validate(action, params) if not rollback else (params or {})
    return globals()["_" + action](engine, params, rollback, before_state)


def _reconnect_link(engine, p, rollback, before_state):
    if rollback:
        return True, "nothing to roll back: reconnecting changes no persistent state", None, None
    before = {"link_state": engine.link.get("state"), "fail_streak": engine.link.get("fail_streak"), "last_error": engine.link.get("last_error")}
    try:
        engine.client.close()
    except Exception:
        pass
    engine.client = tlsutil.build_client(config.CA_CERT, timeout=5.0 if config.REMOTE else 3.0,
                                         headers={"Authorization": f"Bearer {config.API_KEY}", "ngrok-skip-browser-warning": "1"})
    t = time.perf_counter()
    try:
        r = engine.client.get(f"{config.SAAS_URL}/api/ingest/v1/ledger")
        ms = round((time.perf_counter() - t) * 1000, 1)
        ok = r.status_code == 200
        if ok:
            engine.link.update(state="connected", last_error=None, fail_streak=0, tls_error=False)
        return ok, f"opened a fresh verified TLS connection to the host (HTTP {r.status_code}, {ms} ms)", before, {"link_ms": ms, "http_status": r.status_code}
    except Exception as e:
        why = tlsutil.explain_tls_error(e) if tlsutil.is_tls_error(e) else f"{type(e).__name__}"
        return False, f"could not reconnect: {why}", before, {"link_ms": None}


def _flush_dns_cache(engine, p, rollback, before_state):
    if rollback:
        return True, "nothing to roll back: a flushed DNS cache simply refills", None, None
    argv = {"Windows": ["ipconfig", "/flushdns"], "Darwin": ["dscacheutil", "-flushcache"], "Linux": ["resolvectl", "flush-caches"]}.get(platform.system())
    if not argv:
        return False, f"no supported DNS flush command for {platform.system()}", None, None
    before = {"dns_lookup_ms": _dns_ms()}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15, shell=False)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"could not run the OS DNS flush ({type(e).__name__})", before, None
    after = {"dns_lookup_ms": _dns_ms()}
    if r.returncode != 0:
        return False, f"the OS refused the flush (exit {r.returncode}; this usually needs an elevated/administrator session)", before, after
    return True, "flushed the operating system DNS resolver cache", before, after


def _reprobe_connectivity(engine, p, rollback, before_state):
    if rollback:
        return True, "diagnostic only: nothing to roll back", None, None
    before = {"last_probe_batch": {l: bool(ok) for l, ok, _ in envinfo._state.get("probes", [])}}
    res = [(l, *envinfo.probe_once(h)) for l, h in envinfo.PROBE_TARGETS]
    failed = [l for l, ok, _ in res if not ok]
    rtts = [ms for _, ok, ms in res if ok and ms]
    after = {"endpoints": len(res), "reachable": len(res) - len(failed), "failed": failed, "median_handshake_ms": round(statistics.median(rtts), 1) if rtts else None}
    return True, f"re-measured {len(res)} cloud endpoints from this device: {len(failed)} unreachable" + (f" ({', '.join(failed)})" if failed else ""), before, after


def _cpu_sample():
    return round(psutil.Process().cpu_percent(interval=3.0), 1)


def _lower_collector_footprint(engine, p, rollback, before_state):
    if rollback:
        bs = before_state or {}
        if "tick_s" not in bs:
            return False, "no recorded before-state to restore", None, None
        cur = {"tick_s": engine.tick_s, "probes_on": envinfo.PROBES_ON}
        engine.tick_s = float(bs["tick_s"])
        envinfo.PROBES_ON = bool(bs.get("probes_on", True))
        return True, f"restored the collection interval to {engine.tick_s:g} s and probes to {'on' if envinfo.PROBES_ON else 'off'}", cur, {"tick_s": engine.tick_s, "probes_on": envinfo.PROBES_ON}
    before = {"tick_s": engine.tick_s, "probes_on": envinfo.PROBES_ON, "agent_cpu_percent": _cpu_sample(), "agent_mem_mb": round(psutil.Process().memory_info().rss / 1e6, 1)}
    if "tick_s" in p:
        engine.tick_s = float(p["tick_s"])
    if p.get("probes_off"):
        envinfo.PROBES_ON = False
    time.sleep(max(2.0, engine.tick_s))             # let one new cycle run so the measurement reflects the change
    after = {"tick_s": engine.tick_s, "probes_on": envinfo.PROBES_ON, "agent_cpu_percent": _cpu_sample(), "agent_mem_mb": round(psutil.Process().memory_info().rss / 1e6, 1)}
    return True, f"collection interval {before['tick_s']:g} s -> {after['tick_s']:g} s, cloud probes {'off' if not after['probes_on'] else 'on'}; collector CPU {before['agent_cpu_percent']}% -> {after['agent_cpu_percent']}%", before, after


def _reduce_local_retention(engine, p, rollback, before_state):
    if rollback:
        bs = before_state or {}
        if "retention_s" not in bs:
            return False, "no recorded before-state to restore", None, None
        cur = dict(engine.cfg)
        engine.set_config({"retention_s": bs["retention_s"], "egress_retention_s": bs["egress_retention_s"]})
        return True, "restored the previous retention settings (data already purged is NOT restored)", {k: cur.get(k) for k in ("retention_s", "egress_retention_s")}, \
            {k: engine.cfg.get(k) for k in ("retention_s", "egress_retention_s")}

    def counts():
        return {"raw_logs": db.one("SELECT COUNT(*) n FROM raw_logs")["n"], "egress_rows": db.one("SELECT COUNT(*) n FROM egress")["n"], "db_bytes": _db_bytes()}
    before = {"retention_s": engine.cfg["retention_s"], "egress_retention_s": engine.cfg["egress_retention_s"], **counts()}
    engine.set_config({k: p[k] for k in ("retention_s", "egress_retention_s") if k in p})
    engine.purge()
    try:
        db.exec("VACUUM")
    except Exception:
        pass
    after = {"retention_s": engine.cfg["retention_s"], "egress_retention_s": engine.cfg["egress_retention_s"], **counts()}
    freed = (before["db_bytes"] or 0) - (after["db_bytes"] or 0)
    return True, (f"local retention now {after['retention_s']} s (raw logs) / {after['egress_retention_s']} s (egress): removed {before['raw_logs'] - after['raw_logs']} raw log "
                  f"rows and {before['egress_rows'] - after['egress_rows']} egress rows; database {before['db_bytes']} -> {after['db_bytes']} bytes"), before, {**after, "bytes_freed": freed}
