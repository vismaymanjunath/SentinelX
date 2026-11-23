"""E. Global internet measurements: RIPE Atlas public built-in measurements (no API key, results are public).
ping msm 1001 / traceroute msm 5001 / DNS msm 10001 all target k.root-servers.net from thousands of volunteer probes. We read the latest
results of a handful of connected probes per country and publish per-country statistics only (probe addresses are never stored).
Severity is 'medium' only when the numbers show degradation (loss, failures, or RTT far above that country's own recent median)."""
import statistics
import time

from ..core import now_ms
from ..db import db, jd, jl
from . import core

A = "https://atlas.ripe.net/api/v2"
BASELINE_COUNTRIES = ["US", "DE", "GB", "IN", "BR", "JP", "ZA", "AU", "SG"]
MSM = {"ping": (1001, 900), "dns": (10001, 3000), "traceroute": (5001, 3000)}      # (measurement id, lookback seconds)
MAX_COUNTRIES = 14
PROBES_PER_COUNTRY = 12
BUCKET_S = 900


def countries_of_interest():
    cs = list(BASELINE_COUNTRIES)
    try:
        cs += [r["country"] for r in db.all("SELECT DISTINCT country FROM device_context WHERE country IS NOT NULL AND country!=''")]
    except Exception:
        pass
    cs += [r["country"] for r in db.all("SELECT country FROM intel_events WHERE source='ioda' AND kind='country_outage' AND status='ongoing' "
                                         "ORDER BY score DESC LIMIT 5") if r["country"]]
    return list(dict.fromkeys(c for c in cs if c and len(c) == 2))[:MAX_COUNTRIES]


def probes_for(ctx, cc):
    key = f"atlas:probes:{cc}"
    row = db.one("SELECT value, fetched_ms FROM intel_cache WHERE key=?", (key,))
    if row and now_ms() - row["fetched_ms"] < 86400_000:
        return jl(row["value"], [])
    j = ctx.get(f"{A}/probes/", params={"country_code": cc, "status": 1, "page_size": PROBES_PER_COUNTRY, "fields": "id,country_code,asn_v4"}).json()
    ids = [p["id"] for p in j.get("results", [])]
    db.exec("INSERT OR REPLACE INTO intel_cache(key,value,fetched_ms) VALUES(?,?,?)", (key, jd(ids), now_ms()))
    return ids


def summarise(kind, results):
    """Pure aggregation of real Atlas result entries. Returns None when there is nothing to summarise (never a made-up value)."""
    if not results:
        return None
    probes = {r.get("prb_id") for r in results}
    if kind == "ping":
        ok = [r for r in results if (r.get("rcvd") or 0) > 0 and (r.get("avg") or 0) > 0]
        sent = sum(r.get("sent") or 0 for r in results)
        rcvd = sum(r.get("rcvd") or 0 for r in results)
        return {"probes": len(probes), "samples": len(results), "median_rtt_ms": round(statistics.median(r["avg"] for r in ok), 1) if ok else None,
                "loss_pct": round(100 * (1 - rcvd / sent), 1) if sent else None}
    if kind == "dns":
        good = [r for r in results if isinstance(r.get("result"), dict) and r["result"].get("rt") is not None]
        return {"probes": len(probes), "samples": len(results), "success_pct": round(100 * len(good) / len(results), 1),
                "median_resolution_ms": round(statistics.median(r["result"]["rt"] for r in good), 1) if good else None}
    if kind == "traceroute":
        reached, hops, rtts = 0, [], []
        for r in results:
            path = r.get("result") or []
            last = path[-1]["result"] if path and isinstance(path[-1], dict) and isinstance(path[-1].get("result"), list) else []
            hit = [x for x in last if x.get("from") == r.get("dst_addr") and x.get("rtt") is not None]
            if hit:
                reached += 1
                hops.append(path[-1]["hop"])
                rtts.append(min(x["rtt"] for x in hit))
        return {"probes": len(probes), "samples": len(results), "reached_pct": round(100 * reached / len(results), 1),
                "median_hops": statistics.median(hops) if hops else None, "median_final_rtt_ms": round(statistics.median(rtts), 1) if rtts else None}
    return None


def _trailing_median(cc, kind, field, now):
    rows = db.all("SELECT data FROM intel_events WHERE source='atlas' AND kind=? AND country=? AND event_ms>? ORDER BY event_ms DESC LIMIT 30",
                  (kind, cc, (now - 24 * 3600) * 1000))
    vals = [jl(r["data"], {}).get(field) for r in rows]
    vals = [v for v in vals if v]
    return statistics.median(vals) if len(vals) >= 6 else None


def _severity(kind, s, cc, now):
    if kind == "ping":
        base = _trailing_median(cc, "ping", "median_rtt_ms", now)
        if (s["loss_pct"] or 0) >= 25:
            return "medium", f"packet loss {s['loss_pct']}%"
        if base and s["median_rtt_ms"] and s["median_rtt_ms"] >= 2.5 * base and s["median_rtt_ms"] - base > 40:
            return "medium", f"median RTT {s['median_rtt_ms']} ms vs {base:.0f} ms recent median for {cc}"
    elif kind == "dns" and s["success_pct"] < 70:
        return "medium", f"only {s['success_pct']}% of DNS queries answered"
    elif kind == "traceroute" and s["reached_pct"] < 70:
        return "medium", f"destination reached in only {s['reached_pct']}% of traceroutes"
    return "low", None


def fetch_atlas(ctx):
    now = int(time.time())
    bucket = now // BUCKET_S * BUCKET_S
    events, noted = [], []
    for cc in countries_of_interest():
        ids = probes_for(ctx, cc)
        if not ids:
            continue
        for kind, (msm, win) in MSM.items():
            res = ctx.get(f"{A}/measurements/{msm}/results/", params={"start": now - win, "stop": now, "probe_ids": ",".join(map(str, ids)), "format": "json"}).json()
            s = summarise(kind, res)
            if s is None:
                continue
            sev, why = _severity(kind, s, cc, now)
            head = {"ping": f"median RTT {s.get('median_rtt_ms')} ms, loss {s.get('loss_pct')}%", "dns": f"{s.get('success_pct')}% answered, median {s.get('median_resolution_ms')} ms",
                    "traceroute": f"{s.get('reached_pct')}% reached the target, median {s.get('median_hops')} hops"}[kind]
            events.append({"id": f"atlas:{kind}:{cc}:{bucket}", "source": "atlas", "category": "measurement", "kind": kind, "severity": sev, "country": cc,
                           "title": f"{kind.upper()} to k.root-servers.net from {cc}: {head}", "status": "degraded" if why else "normal",
                           "summary": (f"{s['samples']} real RIPE Atlas {kind} results from {s['probes']} probe(s) in {cc} over the last {win // 60} min. "
                                       f"{'Degradation: ' + why + '.' if why else 'Within normal range for this country.'}"),
                           "event_ms": bucket * 1000.0, "updated_ms": bucket * 1000.0, "source_url": f"https://atlas.ripe.net/measurements/{msm}/",
                           "data": {**s, "measurement_id": msm, "target": "k.root-servers.net", "window_s": win, "country": cc, "degradation": why}})
    return events, {"note": f"{len(events)} regional summaries across {len(set(e['country'] for e in events))} countries (built-in measurements 1001 ping / 5001 traceroute / 10001 DNS)",
                    "data_ms": now * 1000.0}


core.register(core.Source("atlas", "measurement", "RIPE Atlas measurements", A + "/measurements/", 900, fetch_atlas, doc_url="https://atlas.ripe.net/", timeout=60))
