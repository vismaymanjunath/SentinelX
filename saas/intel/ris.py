"""B. Global network intelligence: RIPE RIS Live (BGP) over its real WebSocket stream.

One general vantage (rrc00) gives global rollups; targeted `path`/`prefix` subscriptions follow the ASNs we care about (this host's
network + connected devices' networks). Raw updates are NOT stored in bulk: per-minute rollups are, plus compact update rows for
watched ASNs, plus *notable* events. A notable event is only emitted when the data shows it (a rate far above this stream's own
baseline, several peers agreeing on an origin change, several peers losing a watched prefix). Routing changes are normal; nothing
here is called an attack."""
import asyncio
import collections
import json
import threading
import time
from collections import OrderedDict, deque

import httpx

from ..core import now_ms
from ..db import db, jd, jl
from . import core

RIS_URL = "wss://ris-live.ripe.net/v1/ws/?client=SentinelX-AIOps"
GLOBAL_SUB = {"type": "UPDATE", "host": "rrc00"}
STAT = "https://stat.ripe.net/data"
ORIGIN_CAP = 250_000
MAX_PREFIX_SUBS = 60
RING = deque(maxlen=60)                    # last real messages (memory only) for the live view
STATE = {"connected": False, "since_ms": None, "msgs": 0, "last_msg_ms": None, "rate": 0.0, "subs": 0, "error": None, "watched": []}


class Detector:
    """All state lives in memory + the rollup tables; handle() is a pure function of the real messages it is fed."""

    def __init__(self):
        self.origin = OrderedDict()                                    # prefix -> last seen origin ASN
        self.changes = {}                                              # (prefix, old, new) -> {"peers": set, "first": ts, "hosts": set, "path": [...]}
        self.pending = {}                                              # prefix -> (old, new) of the open change, so later peers can agree with it
        self.seen_ids = OrderedDict()
        self.minute = {}                                               # scope -> counters for the current minute
        self.minute_ms = None
        self.baseline = {"wd": None, "n": 0}                           # EWMA of global withdrawals / minute (+ samples)
        self.watched = set()                                           # ASNs (str)
        self.watch_prefixes = {}                                       # prefix -> asn
        self.last_path = OrderedDict()                                 # (peer, prefix) -> path (watched prefixes only)
        self.wd_peers = {}                                             # (asn, prefix) -> {"peers": set, "ts": first}
        self.emitted = {}                                              # event id -> ts (rate limiting)

    # ---- helpers
    def _bucket(self, scope):
        m = self.minute.get(scope)
        if m is None:
            m = self.minute[scope] = {"a": 0, "w": 0, "pfx": set(), "peers": set(), "msgs": 0, "pc": 0}
        return m

    def handle(self, d, now=None):
        """d = one RIS 'ris_message' payload. Returns a list of events (possibly empty)."""
        mid = d.get("id")
        if mid:
            if mid in self.seen_ids:
                return []
            self.seen_ids[mid] = 1
            if len(self.seen_ids) > 4000:
                self.seen_ids.popitem(last=False)
        ts = d.get("timestamp") or time.time()
        now = now or ts
        host, peer, peer_asn, path = (d.get("host") or "").split(".")[0], d.get("peer"), str(d.get("peer_asn")), d.get("path") or []
        flat = [a for a in path if isinstance(a, int)]
        origin = str(flat[-1]) if flat else None
        events = []
        scopes = set()
        if host == "rrc00":
            scopes.add("global")
        for a in flat:
            if str(a) in self.watched:
                scopes.add(f"AS{a}")
        wd = d.get("withdrawals") or []
        for w in wd:
            asn = self.watch_prefixes.get(w)
            if asn:
                scopes.add(f"AS{asn}")
        for sc in scopes:
            b = self._bucket(sc)
            b["msgs"] += 1
            b["peers"].add(peer)
            b["w"] += len(wd)
        for ann in d.get("announcements") or []:
            for pfx in ann.get("prefixes", []):
                for sc in scopes:
                    b = self._bucket(sc)
                    b["a"] += 1
                    b["pfx"].add(pfx)
                if origin:
                    ev = self._origin_check(pfx, origin, f"{host}/{peer}", host, flat, ts)
                    if ev:
                        events.append(ev)
                if pfx in self.watch_prefixes or any(str(a) in self.watched for a in flat):
                    key = (peer, pfx)
                    prev = self.last_path.get(key)
                    if prev is not None and prev != flat:
                        for sc in scopes:
                            self._bucket(sc)["pc"] += 1
                    self.last_path[key] = flat
                    if len(self.last_path) > 60_000:
                        self.last_path.popitem(last=False)
                    self.wd_peers.pop((self.watch_prefixes.get(pfx), pfx), None)        # re-announced: not a loss
        for pfx in wd:
            asn = self.watch_prefixes.get(pfx)
            if asn:
                rec = self.wd_peers.setdefault((asn, pfx), {"peers": set(), "ts": ts, "hosts": set()})
                rec["peers"].add(peer)
                rec["hosts"].add(host)
        # keep a compact, genuine record for watched ASNs; the live ring is a view of the real stream (memory only)
        RING.appendleft({"ts_ms": ts * 1000, "host": host, "peer_asn": peer_asn, "path": flat[:10], "origin": origin,
                         "announced": [p for a in d.get("announcements") or [] for p in a.get("prefixes", [])][:4], "withdrawn": wd[:4]})
        return events

    def _origin_check(self, pfx, origin, peer_asn, host, flat, ts):
        pend = self.pending.get(pfx)
        if pend and pend[1] == origin:                                  # another peer now announces the same NEW origin: that is agreement
            ch = self.changes.get((pfx, pend[0], origin))
            if ch is not None:
                ch["peers"].add(peer_asn)
                ch["hosts"].add(host)
                self.origin[pfx] = origin
                return None
        prev = self.origin.get(pfx)
        self.origin[pfx] = origin
        self.origin.move_to_end(pfx)
        if len(self.origin) > ORIGIN_CAP:
            self.origin.popitem(last=False)
        if prev is None or prev == origin:
            return None
        ch = self.changes.setdefault((pfx, prev, origin), {"peers": set(), "first": ts, "hosts": set(), "path": flat[:12]})
        self.pending[pfx] = (prev, origin)
        ch["peers"].add(peer_asn)
        ch["hosts"].add(host)
        if len(self.changes) > 20_000:
            self.changes.pop(next(iter(self.changes)))
        return None                                                     # evaluated in flush(): needs several peers to agree

    # ---- once a minute: persist rollups, evaluate detectors
    def flush(self, now=None):
        now = now or time.time()
        events = []
        minute_ms = int(now // 60 * 60) * 1000
        for sc, b in self.minute.items():
            db.exec("INSERT OR REPLACE INTO intel_bgp(scope,minute_ms,announcements,withdrawals,prefixes,peers,msgs,path_changes) VALUES(?,?,?,?,?,?,?,?)",
                    (sc, minute_ms, b["a"], b["w"], len(b["pfx"]), len(b["peers"]), b["msgs"], b["pc"]))
        g = self.minute.get("global")
        if g:
            ev = self._global_surge(g, minute_ms, now)
            if ev:
                events.append(ev)
        self.minute = {}
        confirmed = {}
        for (pfx, old, new), ch in list(self.changes.items()):
            if now - ch["first"] > 600:                                 # window closed without enough agreement
                del self.changes[(pfx, old, new)]
                if self.pending.get(pfx) == (old, new):
                    del self.pending[pfx]
            elif len(ch["peers"]) >= 3:
                confirmed.setdefault(frozenset((old, new)), []).append((pfx, old, new, ch))
                del self.changes[(pfx, old, new)]
                if self.pending.get(pfx) == (old, new):
                    del self.pending[pfx]
        for pair, items in confirmed.items():                           # ONE observation per AS pair per hour, not one per prefix
            eid = f"ris:origin:{'-'.join(sorted(pair))}:{int(now // 3600)}"
            if eid in self.emitted or sum(1 for t in self.emitted.values() if now - t < 3600) >= 40:
                continue
            self.emitted[eid] = now
            events.append(self._origin_event(eid, items))
        events += self._watched_withdrawals(now)
        for k in [k for k, t in self.emitted.items() if now - t > 7200]:
            del self.emitted[k]
        return events

    def _global_surge(self, g, minute_ms, now):
        wd = g["w"]
        b = self.baseline
        ev = None
        if b["wd"] is not None and b["n"] >= 30 and wd > max(3.0 * b["wd"], b["wd"] + 4000):          # needs 30 min of history first
            eid = f"ris:surge:global:{int(now // 900)}"
            if eid not in self.emitted:
                self.emitted[eid] = now
                ev = {"id": eid, "source": "ris", "category": "routing", "kind": "withdrawal_surge", "severity": "low", "status": "observed",
                      "title": f"Withdrawal rate {wd / max(b['wd'], 1):.1f}x above this stream's baseline (rrc00)",
                      "summary": (f"{wd} prefix withdrawals in one minute observed at RIS collector rrc00 versus a rolling baseline of {b['wd']:.0f}/min "
                                  f"({g['a']} announcements, {len(g['peers'])} peers). A rate change alone does not identify a cause: leaks, maintenance, "
                                  f"session resets and large re-convergence events all look like this."),
                      "event_ms": minute_ms, "updated_ms": minute_ms, "source_url": "https://ris-live.ripe.net/",
                      "data": {"withdrawals": wd, "baseline_per_min": round(b["wd"], 1), "announcements": g["a"], "peers": len(g["peers"]), "collector": "rrc00",
                               "classification": "rate anomaly (informational)"}}
        b["wd"] = wd if b["wd"] is None else 0.9 * b["wd"] + 0.1 * wd
        b["n"] += 1
        return ev

    def _origin_event(self, eid, items):
        dirs = {(old, new) for _, old, new, _ in items}
        flapping = any((b, a) in dirs for a, b in dirs) or len(dirs) > 1
        pfxs = sorted({p for p, *_ in items})
        peers = set().union(*(ch["peers"] for *_, ch in items))
        hosts = set().union(*(ch["hosts"] for *_, ch in items))
        pfx, old, new, ch = items[0]
        a, b = sorted({old, new})
        first = min(ch["first"] for *_, ch in items)
        if flapping:
            title, cls = f"Origin AS flapping between AS{a} and AS{b} ({len(pfxs)} prefix(es))", "origin flapping (informational)"
            why = "Both ASes alternated as the visible origin, which is the usual signature of multi-homing, failover or anycast."
        else:
            title, cls = f"Origin AS change AS{old} → AS{new} ({len(pfxs)} prefix(es))", "origin change (informational)"
            why = "Origin changes are routine (multi-homing, anycast, DDoS mitigation, migrations)."
        return {"id": eid, "source": "ris", "category": "routing", "kind": "origin_flapping" if flapping else "origin_change",
                "severity": "medium" if (len(peers) >= 8 and not flapping) else "low", "status": "observed", "title": title, "asn": new, "prefix": pfx,
                "summary": (f"{len(peers)} distinct RIS peers observed the change on {len(pfxs)} prefix(es), e.g. {pfx}. {why} This is NOT evidence of a hijack "
                            f"without further validation (e.g. RPKI/ROA checks)."),
                "event_ms": first * 1000, "updated_ms": time.time() * 1000, "source_url": f"https://stat.ripe.net/app/launchpad/{pfx}",
                "data": {"asns": [a, b], "prefixes": pfxs[:12], "peers_observing": len(peers), "collectors": sorted(hosts), "example_path": ch["path"],
                         "classification": cls, "rpki_validated": None}}

    def _watched_withdrawals(self, now):
        out = []
        by_asn = {}
        for (asn, pfx), rec in list(self.wd_peers.items()):
            if now - rec["ts"] > 180:
                del self.wd_peers[(asn, pfx)]
                continue
            if asn:
                by_asn.setdefault(asn, []).append((pfx, rec))
        for asn, items in by_asn.items():
            peers = set().union(*(r["peers"] for _, r in items))
            if len(items) >= 1 and len(peers) >= 5:                                    # several peers lost the prefix and none saw it re-announced
                eid = f"ris:loss:AS{asn}:{int(now // 600)}"
                if eid in self.emitted:
                    continue
                self.emitted[eid] = now
                out.append({"id": eid, "source": "ris", "category": "routing", "kind": "prefix_withdrawn", "severity": "medium", "status": "observed",
                            "title": f"AS{asn}: {len(items)} prefix(es) withdrawn, seen by {len(peers)} peers", "asn": asn, "prefix": items[0][0],
                            "summary": (f"{len(peers)} RIS peers withdrew {len(items)} prefix(es) originated by AS{asn} and have not re-announced them within the observation "
                                        f"window. This indicates loss of reachability to those prefixes from those vantage points; it does not by itself explain why."),
                            "event_ms": min(r["ts"] for _, r in items) * 1000, "updated_ms": now * 1000, "source_url": f"https://stat.ripe.net/app/launchpad/AS{asn}",
                            "data": {"prefixes": [p for p, _ in items][:12], "peers_observing": len(peers), "collectors": sorted(set().union(*(r["hosts"] for _, r in items))),
                                     "classification": "reachability loss observed (informational)"}})
        return out


DET = Detector()


# ------------------------------------------------------------------------------------------------ real reference data (RIPEstat)
def asn_info(asn, client=None):
    """Holder name + announced prefixes for an ASN from RIPEstat (cached 24 h in intel_asn)."""
    row = db.one("SELECT * FROM intel_asn WHERE asn=?", (str(asn),))
    if row and now_ms() - row["fetched_ms"] < 86400_000:
        return {"asn": row["asn"], "holder": row["holder"], "prefixes": jl(row["prefixes"], [])}
    own = client is None
    client = client or httpx.Client(trust_env=False, timeout=25)
    try:
        h = client.get(f"{STAT}/as-overview/data.json", params={"resource": f"AS{asn}"}).json()["data"]
        pf = client.get(f"{STAT}/announced-prefixes/data.json", params={"resource": f"AS{asn}"}).json()["data"]["prefixes"]
        prefixes = [p["prefix"] for p in pf if ":" not in p["prefix"]][:MAX_PREFIX_SUBS // 2]       # IPv4 first; bounded
        db.exec("INSERT OR REPLACE INTO intel_asn(asn,holder,country,prefixes,fetched_ms) VALUES(?,?,?,?,?)", (str(asn), h.get("holder"), None, jd(prefixes), now_ms()))
        return {"asn": str(asn), "holder": h.get("holder"), "prefixes": prefixes}
    except Exception:
        return {"asn": str(asn), "holder": row["holder"] if row else None, "prefixes": jl(row["prefixes"], []) if row else []}
    finally:
        if own:
            client.close()


def add_watch(asn, reason, tenant_id=None):
    db.exec("INSERT OR IGNORE INTO intel_watch(asn,reason,added_ms,tenant_id) VALUES(?,?,?,?)", (str(asn), reason, now_ms(), tenant_id))


def host_network():
    """This SaaS host's own public ASN (real lookup): its network is always worth watching."""
    with httpx.Client(trust_env=False, timeout=20) as c:
        ip = c.get(f"{STAT}/whats-my-ip/data.json").json()["data"]["ip"]
        ni = c.get(f"{STAT}/network-info/data.json", params={"resource": ip}).json()["data"]
    return (ni["asns"][0] if ni.get("asns") else None)


# ------------------------------------------------------------------------------------------------ the stream
async def _session(stop):
    import websockets
    async with websockets.connect(RIS_URL, open_timeout=25, max_size=2 ** 22, ping_interval=30) as ws:
        STATE.update(connected=True, since_ms=now_ms(), last_msg_ms=None, error=None)
        subs = []

        async def sub(data):
            await ws.send(json.dumps({"type": "ris_subscribe", "data": data}))
            subs.append(data)

        await sub(GLOBAL_SUB)
        applied = set()
        last_flush = last_sync = last_rec = time.time()
        n_window = 0
        t_window = time.time()
        while not stop.is_set():
            try:
                raw = await asyncio.wait_for(ws.recv(), 20)
            except asyncio.TimeoutError:
                raw = None
            now = time.time()
            quiet_since = (STATE["last_msg_ms"] or STATE["since_ms"] or now * 1000) / 1000
            if now - quiet_since > 40:          # a live BGP stream is never silent for 40 s: treat it as stalled and reconnect
                core.record("ris", False, err="stream stalled (no BGP messages for 40 s); reconnecting", state="delayed", retry_s=10)
                raise RuntimeError("RIS stream stalled (no messages for 40 s); reconnecting")
            if raw is not None:
                m = json.loads(raw)
                if m.get("type") == "ris_message":
                    STATE["msgs"] += 1
                    STATE["last_msg_ms"] = now * 1000
                    n_window += 1
                    evs = DET.handle(m["data"])
                    if evs:
                        core.upsert(evs)
                elif m.get("type") == "ris_error":
                    raise RuntimeError("RIS error: " + str(m.get("data", {}).get("message", ""))[:120])
            if now - last_sync > 30:                                         # follow the watch list
                last_sync = now
                want = {r["asn"] for r in db.all("SELECT asn FROM intel_watch")}
                DET.watched = want
                for asn in sorted(want - applied):
                    await sub({"path": asn, "type": "UPDATE"})
                    info = await asyncio.get_running_loop().run_in_executor(None, asn_info, asn)
                    for pfx in info["prefixes"]:
                        if len(DET.watch_prefixes) < MAX_PREFIX_SUBS:
                            DET.watch_prefixes[pfx] = asn
                            await sub({"prefix": pfx, "type": "UPDATE", "moreSpecific": True, "lessSpecific": False})
                    applied.add(asn)
                STATE.update(subs=len(subs), watched=sorted(want))
            if now - last_flush >= 60:
                last_flush = now
                evs = DET.flush(now)
                if evs:
                    core.upsert(evs)
                db.exec("DELETE FROM intel_bgp_updates WHERE ts_ms < ?", (now_ms() - 48 * 3600_000,))
            if now - last_rec >= 30:
                STATE["rate"] = n_window / max(now - t_window, 1)
                n_window, t_window, last_rec = 0, now, now
                stale = STATE["last_msg_ms"] is None or now * 1000 - STATE["last_msg_ms"] > 60_000
                core.record("ris", True, STATE["msgs"], state="delayed" if stale else "ok", data_ms=STATE["last_msg_ms"],
                            note=f"{STATE['rate']:.0f} msg/s from rrc00 + {len(subs) - 1} targeted subscription(s); watching {', '.join('AS' + a for a in sorted(applied)) or 'no ASN yet'}")


def _thread_main(stop):
    backoff = 5
    while not stop.is_set():
        try:
            asyncio.run(_session(stop))
            backoff = 5
        except Exception as e:
            STATE.update(connected=False, error=f"{type(e).__name__}: {str(e)[:120]}")
            core.record("ris", False, err=STATE["error"], retry_s=backoff)
            stop.wait(backoff)
            backoff = min(backoff * 2, 300)


_thread = None


def start():
    global _thread
    from .. import config
    if not config.INTEL_ENABLED or _thread:
        return
    core.ensure_source(core.SOURCES["ris"])
    try:                                           # watch this host's own network (a real lookup); device networks are added from heartbeats
        a = host_network()
        if a:
            add_watch(a, "this SENTINEL X host's network")
    except Exception:
        pass
    _thread = threading.Thread(target=_thread_main, args=(core._stop,), daemon=True, name="intel-ris")
    _thread.start()


core.register(core.Source("ris", "routing", "RIPE RIS Live (BGP)", "wss://ris-live.ripe.net/v1/ws/", 60, None, doc_url="https://ris-live.ripe.net/", stream=True))
