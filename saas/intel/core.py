"""Ingestion engine: sources, polling, conditional GET + caching, rate-limit/backoff, dedup + history, freshness reporting.
Nothing here fabricates data: an event exists only if a feed returned it; a failing source keeps its last real data and is
labelled cached / stale / unavailable instead."""
import hashlib
import json
import threading
import time
from datetime import datetime, timezone

import httpx

from .. import config
from ..core import now_ms
from ..db import db, jd, jl

SEVERITIES = ("critical", "high", "medium", "low", "unrated")
SOURCES: dict = {}


class RateLimited(Exception):
    def __init__(self, retry_after_s=300):
        super().__init__(f"rate limited; retry after {retry_after_s}s")
        self.retry_after_s = retry_after_s


class Source:
    def __init__(self, id, category, name, url, interval_s, fetch, doc_url=None, timeout=45, stream=False):
        self.id, self.category, self.name, self.url, self.interval_s = id, category, name, url, interval_s
        self.fetch, self.doc_url, self.timeout, self.stream = fetch, doc_url or url, timeout, stream


def register(src):
    SOURCES[src.id] = src
    return src


def sev_from_cvss(score):
    if score is None:
        return "unrated"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "unrated"


def parse_ts(s):
    """ISO-8601 / 'YYYY-MM-DD' -> epoch ms (UTC) or None."""
    if not s:
        return None
    try:
        s = str(s).replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.timestamp() * 1000.0
    except ValueError:
        return None


def iso_ms(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


# ------------------------------------------------------------------------------------------------ source state
def _row(sid):
    return db.one("SELECT * FROM intel_sources WHERE source=?", (sid,))


def ensure_source(src):
    if not _row(src.id):
        db.exec("INSERT INTO intel_sources(source,category,name,url,interval_s,state) VALUES(?,?,?,?,?,?)",
                (src.id, src.category, src.name, src.doc_url, src.interval_s, "pending"))
    else:
        db.exec("UPDATE intel_sources SET category=?, name=?, url=?, interval_s=? WHERE source=?", (src.category, src.name, src.doc_url, src.interval_s, src.id))


def record(sid, ok, items=0, err=None, state=None, cache_hit=False, retry_s=None, note=None, data_ms=None):
    ms = now_ms()
    r = _row(sid) or {}
    nxt = ms + (retry_s * 1000 if retry_s else (SOURCES[sid].interval_s * 1000 if sid in SOURCES else 600_000))
    if ok:
        db.exec("UPDATE intel_sources SET last_attempt_ms=?, last_success_ms=?, last_error=NULL, state=?, items_last=?, items_total=COALESCE(items_total,0)+?, "
                "cache_hits=COALESCE(cache_hits,0)+?, fetches=COALESCE(fetches,0)+1, next_attempt_ms=?, note=COALESCE(?,note), "
                "last_data_ms=COALESCE(?,last_data_ms) WHERE source=?", (ms, ms, state or "ok", items, items, 1 if cache_hit else 0, nxt, note, data_ms, sid))
    else:
        db.exec("UPDATE intel_sources SET last_attempt_ms=?, last_error=?, state=?, failures=COALESCE(failures,0)+1, fetches=COALESCE(fetches,0)+1, "
                "next_attempt_ms=? WHERE source=?", (ms, str(err)[:240], state or "error", nxt, sid))


def freshness(row, now=None):
    """Honest label for a source: live | cached | stale | delayed | rate_limited | unavailable | pending. Never hides an outage."""
    now = now or now_ms()
    iv = (row.get("interval_s") or 600) * 1000
    ok_ms = row.get("last_success_ms")
    age = (now - ok_ms) / 1000 if ok_ms else None
    st = row.get("state")
    if st == "pending":
        label = "pending"
    elif not ok_ms:
        label = "rate_limited" if st == "rate_limited" else "unavailable"
    elif st == "rate_limited":
        label = "rate_limited"
    elif st == "error":
        label = "cached" if (now - ok_ms) < 2.5 * iv else "stale"
    elif (now - ok_ms) > 2.5 * iv:
        label = "stale"
    elif st == "delayed":
        label = "delayed"
    else:
        label = "live"
    return {"label": label, "age_s": round(age) if age is not None else None}


def source_view(now=None):
    now = now or now_ms()
    out = []
    for r in db.all("SELECT * FROM intel_sources ORDER BY category, source"):
        f = freshness(r, now)
        cnt = db.one("SELECT COUNT(*) n, MAX(event_ms) newest FROM intel_events WHERE source=?", (r["source"],))
        out.append({"source": r["source"], "category": r["category"], "name": r["name"], "url": r["url"], "interval_s": r["interval_s"],
                    "freshness": f["label"], "age_s": f["age_s"], "last_success_ms": r["last_success_ms"], "last_attempt_ms": r["last_attempt_ms"],
                    "last_error": r["last_error"], "events_stored": cnt["n"], "newest_event_ms": cnt["newest"], "items_last_fetch": r["items_last"],
                    "cache_hits": r["cache_hits"], "failures": r["failures"], "note": r["note"], "last_data_ms": r["last_data_ms"]})
    return out


# ------------------------------------------------------------------------------------------------ dedup + history
EVENT_COLS = ("source", "category", "kind", "severity", "title", "summary", "status", "event_ms", "updated_ms", "source_url", "country", "region",
              "provider", "asn", "prefix", "vendor", "product", "cve", "score", "exploited")


def _digest(e):
    mat = {k: e.get(k) for k in ("severity", "title", "summary", "status", "updated_ms", "score", "exploited")}
    mat["data"] = e.get("data")
    return hashlib.sha256(json.dumps(mat, sort_keys=True, default=str).encode()).hexdigest()[:24]


def upsert(events):
    """-> {'new','updated','unchanged'}. Same id never duplicates; a changed event keeps its history."""
    new = upd = same = 0
    ms = now_ms()
    with db.tx() as c:
        for e in events:
            eid, dg = e["id"], _digest(e)
            if e.get("severity") not in SEVERITIES:
                e["severity"] = "unrated"
            row = c.execute("SELECT digest, version FROM intel_events WHERE id=?", (eid,)).fetchone()
            if row is None:
                c.execute(f"INSERT INTO intel_events(id,{','.join(EVENT_COLS)},first_seen_ms,last_seen_ms,data,version,digest) VALUES(?,{','.join('?' * len(EVENT_COLS))},?,?,?,1,?)",
                          (eid, *[e.get(k) for k in EVENT_COLS], ms, ms, jd(e.get("data") or {}), dg))
                c.execute("INSERT INTO intel_history(event_id,version,ts_ms,status,severity,summary,updated_ms) VALUES(?,?,?,?,?,?,?)",
                          (eid, 1, ms, e.get("status"), e.get("severity"), (e.get("summary") or "")[:300], e.get("updated_ms")))
                new += 1
            elif row["digest"] != dg:
                v = row["version"] + 1
                sets = ",".join(f"{k}=?" for k in EVENT_COLS)
                c.execute(f"UPDATE intel_events SET {sets}, last_seen_ms=?, data=?, version=?, digest=? WHERE id=?",
                          (*[e.get(k) for k in EVENT_COLS], ms, jd(e.get("data") or {}), v, dg, eid))
                c.execute("INSERT INTO intel_history(event_id,version,ts_ms,status,severity,summary,updated_ms) VALUES(?,?,?,?,?,?,?)",
                          (eid, v, ms, e.get("status"), e.get("severity"), (e.get("summary") or "")[:300], e.get("updated_ms")))
                upd += 1
            else:
                c.execute("UPDATE intel_events SET last_seen_ms=? WHERE id=?", (ms, eid))
                same += 1
    return {"new": new, "updated": upd, "unchanged": same}


# ------------------------------------------------------------------------------------------------ fetching
class Ctx:
    """What a source's fetch() gets: a cached/conditional HTTP getter and the time of its last success."""

    def __init__(self, src, client):
        self.src, self.client = src, client
        r = _row(src.id) or {}
        self.last_success_ms = r.get("last_success_ms")

    def get(self, url, *, params=None, headers=None, conditional=False, key=None):
        """GET with real error handling. conditional=True uses ETag/Last-Modified and returns None on 304 (cached data still valid)."""
        h = {"User-Agent": config.INTEL_UA, "Accept": "application/json, */*;q=0.5", **(headers or {})}
        if conditional:
            r = _row(self.src.id) or {}
            if r.get("etag"):
                h["If-None-Match"] = r["etag"]
            elif r.get("last_modified"):
                h["If-Modified-Since"] = r["last_modified"]
        resp = self.client.get(url, params=params, headers=h, timeout=self.src.timeout, follow_redirects=True)
        if resp.status_code == 304:
            return None
        if resp.status_code in (403, 429, 503) and (resp.headers.get("retry-after") or resp.status_code == 429):
            try:
                ra = int(resp.headers.get("retry-after", "300"))
            except ValueError:
                ra = 300
            raise RateLimited(min(max(ra, 30), 3600))
        resp.raise_for_status()
        if conditional:
            db.exec("UPDATE intel_sources SET etag=?, last_modified=? WHERE source=?", (resp.headers.get("etag"), resp.headers.get("last-modified"), self.src.id))
        return resp


def run_once(src, client=None):
    """One real fetch of one source: fetch -> upsert -> record. Returns a result dict; never raises."""
    ensure_source(src)
    own = client is None
    client = client or httpx.Client(trust_env=False)
    try:
        ctx = Ctx(src, client)
        out = src.fetch(ctx)
        if out is None:                                     # HTTP 304: our cached copy is still current
            record(src.id, True, 0, cache_hit=True)
            return {"ok": True, "cache_hit": True}
        events, meta = (out if isinstance(out, tuple) else (out, {}))
        res = upsert(events)
        n = meta.get("items", len(events))
        record(src.id, True, n, state=meta.get("state"), note=meta.get("note"), data_ms=meta.get("data_ms"))
        return {"ok": True, "fetched": n, **{k: v + meta.get("upserted", {}).get(k, 0) for k, v in res.items()}}
    except RateLimited as e:
        record(src.id, False, err=str(e), state="rate_limited", retry_s=e.retry_after_s)
        return {"ok": False, "error": str(e), "state": "rate_limited"}
    except Exception as e:      # timeouts, DNS failures, HTTP errors, malformed payloads: recorded, data kept, never fabricated
        record(src.id, False, err=f"{type(e).__name__}: {e}", retry_s=min(src.interval_s, 300))
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}
    finally:
        if own:
            client.close()


_threads: list = []
_stop = threading.Event()


def _loop(src):
    ensure_source(src)
    _stop.wait(min(30, 2 + (hash(src.id) % 20)))           # stagger start-up
    with httpx.Client(trust_env=False) as client:
        while not _stop.is_set():
            r = _row(src.id) or {}
            due = r.get("next_attempt_ms") or 0
            if now_ms() >= due:
                run_once(src, client)
            _stop.wait(5)


def start(only=None):
    """Start one polling thread per source (streams are started by their own module). Safe to call once at SaaS start-up."""
    if not config.INTEL_ENABLED:
        return []
    from . import ris
    ris.start()
    for sid, src in SOURCES.items():
        if only and sid not in only:
            continue
        if src.stream:
            continue
        t = threading.Thread(target=_loop, args=(src,), daemon=True, name=f"intel-{sid}")
        t.start()
        _threads.append(t)
    if not only or "correlation" in only:
        c = threading.Thread(target=_correlation_loop, daemon=True, name="intel-correlation")
        c.start()
        _threads.append(c)
    return _threads


def _correlation_loop():
    from . import correlate
    _stop.wait(45)
    while not _stop.is_set():
        try:
            correlate.run_all()
        except Exception:
            pass
        _stop.wait(120)


def stop():
    _stop.set()
