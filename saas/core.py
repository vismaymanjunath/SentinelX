"""Shared SaaS helpers: settings, thresholds, topology graph, audit, hub (websocket fan-out)."""
import asyncio
import time

from common.schema import utc_iso
from .config import DEFAULT_SETTINGS, DEFAULT_THRESHOLDS
from .db import db, jd

STATE_ORDER = {"Excellent": 0, "Good": 1, "Fair": 2, "Poor": 3}
SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}


def now_ms() -> float:
    return time.time() * 1000.0


# ---------------------------------------------------------------- thresholds & settings
_thr_cache: dict = {}
_set_cache: dict = {}


def thresholds(tenant: str) -> dict:
    t = _thr_cache.get(tenant)
    if t is None:
        t = {m: {"good_max": g, "warn": w, "crit": c} for m, (g, w, c) in DEFAULT_THRESHOLDS.items()}
        for r in db.all("SELECT * FROM thresholds WHERE tenant_id=?", (tenant,)):
            t[r["metric"]] = {"good_max": r["good_max"], "warn": r["warn"], "crit": r["crit"]}
        _thr_cache[tenant] = t
    return t


def set_threshold(tenant, metric, good_max, warn, crit):
    db.exec("INSERT OR REPLACE INTO thresholds VALUES(?,?,?,?,?)", (tenant, metric, good_max, warn, crit))
    _thr_cache.pop(tenant, None)


def settings(tenant: str) -> dict:
    s = _set_cache.get(tenant)
    if s is None:
        s = dict(DEFAULT_SETTINGS)
        for r in db.all("SELECT key, value FROM settings WHERE tenant_id=?", (tenant,)):
            s[r["key"]] = r["value"]
        _set_cache[tenant] = s
    return s


def set_setting(tenant, key, value):
    if key not in DEFAULT_SETTINGS:
        raise ValueError("unknown setting")
    db.exec("INSERT OR REPLACE INTO settings VALUES(?,?,?)", (tenant, key, float(value)))
    _set_cache.pop(tenant, None)


# ---------------------------------------------------------------- topology
def graph(tenant: str):
    deps, rdeps = {}, {}
    for r in db.all("SELECT src, dst FROM topology WHERE tenant_id=?", (tenant,)):
        deps.setdefault(r["src"], set()).add(r["dst"])
        rdeps.setdefault(r["dst"], set()).add(r["src"])
    return deps, rdeps


def _reach(start, adj):
    seen, stack = set(), [start]
    while stack:
        n = stack.pop()
        for m in adj.get(n, ()):
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return seen


def dependents(tenant, node):
    """Everything that (transitively) depends on `node` = its downstream blast radius."""
    return _reach(node, graph(tenant)[1])


def dependencies(tenant, node):
    return _reach(node, graph(tenant)[0])


def hop_distance(tenant, a, b, limit=4):
    if a == b:
        return 0
    deps, rdeps = graph(tenant)
    frontier, seen, d = {a}, {a}, 0
    while frontier and d < limit:
        d += 1
        nxt = set()
        for n in frontier:
            for m in deps.get(n, set()) | rdeps.get(n, set()):
                if m not in seen:
                    if m == b:
                        return d
                    seen.add(m)
                    nxt.add(m)
        frontier = nxt
    return 99


def entity_info(tenant):
    return {r["id"]: r for r in db.all("SELECT * FROM entities WHERE tenant_id=?", (tenant,))}


def upsert_entity(tenant, eid, etype, label=None):
    db.exec("INSERT INTO entities VALUES(?,?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET "
            "type=excluded.type, label=COALESCE(excluded.label, entities.label)", (tenant, eid, etype, label or eid))


# ---------------------------------------------------------------- audit
def audit(tenant, actor, action, detail=""):
    ms = now_ms()
    db.exec("INSERT INTO audit(tenant_id,actor,action,detail,ts_ms,ts) VALUES(?,?,?,?,?,?)",
            (tenant, actor, action, detail if isinstance(detail, str) else jd(detail), ms, utc_iso(ms / 1000)))


# ---------------------------------------------------------------- hub
class Hub:
    def __init__(self):
        self.clients: dict = {}  # ws -> tenant
        self.loop = None

    def broadcast(self, tenant: str, msg: dict):
        if not self.loop or not self.clients:
            return
        for ws, t in list(self.clients.items()):
            if t == tenant:
                try:
                    asyncio.run_coroutine_threadsafe(ws.send_json(msg), self.loop)
                except Exception:
                    pass


hub = Hub()
