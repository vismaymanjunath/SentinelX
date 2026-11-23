"""C. Global internet outages: IODA (Georgia Tech) public API v2 - detected outage events by country, region and ASN, per data source
(BGP visibility, active probing, Google traffic, network telescope)."""
import time

from ..core import now_ms
from ..db import db
from . import core

BASE = "https://api.ioda.inetintel.cc.gatech.edu/v2"
UI = "https://ioda.inetintel.cc.gatech.edu"
DS_NAME = {"bgp": "BGP visibility", "ping-slash24": "active probing (ping /24 blocks)", "gtr": "Google traffic", "merit-nt": "network telescope (Merit)",
           "ucsd-nt": "network telescope (UCSD)"}
WINDOW_S = 48 * 3600


def _entities():
    """Extra entities worth querying individually: watched ASNs and the countries of connected devices (when known)."""
    out = [("asn", r["asn"]) for r in db.all("SELECT asn FROM intel_watch")]
    try:
        out += [("country", r["country"]) for r in db.all("SELECT DISTINCT country FROM device_context WHERE country IS NOT NULL AND country!=''")]
    except Exception:
        pass
    return out[:30]


def _normalise(rows, etype, until):
    """One event per (entity, data source, start); severity comes from how many independent signals agree (stated in the data)."""
    by_entity = {}
    for e in rows:
        by_entity.setdefault(e["location"], []).append(e)
    out = []
    for loc, evs in by_entity.items():
        for e in evs:
            end = e["start"] + e["duration"]
            overlap = {o["datasource"] for o in evs if o["start"] < end and o["start"] + o["duration"] > e["start"]}
            ongoing = end >= until - 7200
            kind, _, code = loc.partition("/")
            sev = "high" if len(overlap) >= 2 else ("medium" if kind == "country" else "low")
            dur_h = e["duration"] / 3600
            qd = int(e["duration"] // 1800) * 1800                       # quantised so an ongoing event does not create a new version every poll
            name = e.get("location_name") or loc
            out.append({"id": f"ioda:{loc}:{e['datasource']}:{e['start']}", "source": "ioda", "category": "outage", "kind": f"{kind}_outage", "severity": sev,
                        "title": f"{name}: {DS_NAME.get(e['datasource'], e['datasource'])} outage signal", "status": "ongoing" if ongoing else "ended",
                        "summary": (f"IODA detected a drop in {DS_NAME.get(e['datasource'], e['datasource'])} for {name} starting "
                                    f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(e['start']))}, observed for about {dur_h:.0f} h"
                                    f"{' and still ongoing' if ongoing else ''}. Confirmed by {len(overlap)} independent signal(s): {', '.join(sorted(overlap))}."),
                        "event_ms": e["start"] * 1000.0, "updated_ms": (e["start"] + qd) * 1000.0, "source_url": f"{UI}/{kind}/{code}",
                        "country": code if kind == "country" else None, "asn": code if kind == "asn" else None, "region": name if kind == "region" else None,
                        "score": e.get("score"),
                        "data": {"datasource": e["datasource"], "entity_type": kind, "entity_code": code, "location_name": name, "score": e.get("score"),
                                 "duration_s": qd, "ongoing": ongoing, "method": e.get("method"), "fraction": e.get("fraction"), "corroborating_datasources": sorted(overlap),
                                 "severity_basis": "number of independent IODA signals that overlap in time (>=2: high; single: medium for countries, low for regions/ASNs)"}})
    return out


def fetch_ioda(ctx):
    until = int(time.time())
    frm = until - WINDOW_S
    events, meta_n = [], {}
    plan = [("country", None, 400), ("region", None, 200), ("asn", None, 200)] + [(t, c, 100) for t, c in _entities()]
    for et, code, lim in plan:
        params = {"entityType": et, "from": frm, "until": until, "limit": lim}
        if code:
            params["entityCode"] = code
        j = ctx.get(f"{BASE}/outages/events", params=params).json()
        if j.get("error"):
            raise RuntimeError(f"IODA error: {str(j['error'])[:120]}")
        rows = j.get("data") or []
        meta_n[et] = meta_n.get(et, 0) + len(rows)
        events += _normalise(rows, et, until)
    seen, uniq = set(), []
    for e in events:                                                       # targeted queries can overlap the general ones
        if e["id"] not in seen:
            seen.add(e["id"])
            uniq.append(e)
    ongoing = sum(1 for e in uniq if e["status"] == "ongoing")
    return uniq, {"note": f"{ongoing} ongoing / {len(uniq)} outage signals in the last 48 h ({', '.join(f'{k}: {v}' for k, v in meta_n.items())})", "data_ms": until * 1000.0}


core.register(core.Source("ioda", "outage", "IODA internet outage detection", BASE + "/outages/events", 600, fetch_ioda, doc_url="https://ioda.inetintel.cc.gatech.edu/", timeout=90))
