"""Stage 5 - RIPE Atlas: REAL measurement results (ping / traceroute / DNS) aggregated per country."""
import time

import pytest

from .intel_helpers import needs_internet, run_intel

pytestmark = needs_internet


def test_real_atlas_measurements_are_aggregated_per_country_without_probe_addresses():
    r = run_intel('''
a = core.run_once(core.SOURCES["atlas"]); b = core.run_once(core.SOURCES["atlas"])
rows = db.all("SELECT * FROM intel_events WHERE source='atlas'")
sv = [s for s in core.source_view() if s["source"] == "atlas"][0]
out({"a": a, "b": b, "n": len(rows), "rows": [dict(x) | {"data": json.loads(x["data"])} for x in rows], "sv": sv, "now": time.time() * 1000,
     "dump": json.dumps([dict(x) for x in rows])})
''', timeout=400)
    assert r["a"]["ok"] and r["a"]["new"] >= 20, r["a"]
    buckets = {e["event_ms"] for e in r["rows"]}
    if len(buckets) == 1:                      # both fetches fell in the same 15-minute bucket (the second can legitimately cross a boundary)
        assert r["b"]["new"] == 0, "same 15-minute bucket -> deduplicated"
    else:
        assert r["b"]["new"] > 0 and len(buckets) == 2
    kinds = {e["kind"] for e in r["rows"]}
    countries = {e["country"] for e in r["rows"]}
    assert kinds == {"ping", "dns", "traceroute"} and len(countries) >= 6, (kinds, countries)
    for e in r["rows"]:
        d = e["data"]
        assert d["measurement_id"] in (1001, 5001, 10001) and d["target"] == "k.root-servers.net" and d["probes"] >= 1 and d["samples"] >= 1
        assert e["source_url"].startswith("https://atlas.ripe.net/measurements/") and abs(e["event_ms"] - r["now"]) < 1_000_000
        if e["kind"] == "ping":
            assert d["median_rtt_ms"] is None or 0 < d["median_rtt_ms"] < 2000, d
            assert d["loss_pct"] is None or 0 <= d["loss_pct"] <= 100
        if e["kind"] == "dns":
            assert 0 <= d["success_pct"] <= 100
        if e["kind"] == "traceroute":
            assert 0 <= d["reached_pct"] <= 100
        if e["severity"] == "medium":
            assert e["status"] == "degraded" and d["degradation"], "'medium' always carries the numeric reason"
    import re
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", r["dump"].replace("193.0.14.129", "")), "no probe/IP addresses are stored"
    assert r["sv"]["freshness"] == "live" and "regional summaries" in r["sv"]["note"]


def test_atlas_ping_latency_is_physically_plausible_against_an_independent_measurement():
    """Independent check: our India ping median should be in the same ballpark as the raw Atlas results fetched separately."""
    import httpx, statistics
    r = run_intel('''
core.run_once(core.SOURCES["atlas"])
row = db.one("SELECT data FROM intel_events WHERE source='atlas' AND kind='ping' AND country='IN'")
out({"d": json.loads(row["data"])} if row else {"d": None})
''', timeout=400)
    assert r["d"], "India is a baseline country and must have a ping summary"
    now = int(time.time())
    pr = httpx.get("https://atlas.ripe.net/api/v2/probes/", params={"country_code": "IN", "status": 1, "page_size": 12, "fields": "id"}, timeout=40).json()["results"]
    raw = httpx.get("https://atlas.ripe.net/api/v2/measurements/1001/results/", params={"start": now - 900, "stop": now, "probe_ids": ",".join(str(p["id"]) for p in pr), "format": "json"}, timeout=60).json()
    avg = [x["avg"] for x in raw if x.get("avg", -1) > 0]
    assert avg and abs(statistics.median(avg) - r["d"]["median_rtt_ms"]) <= max(25, 0.6 * statistics.median(avg)), (statistics.median(avg), r["d"])


def test_summaries_are_pure_and_never_invent_values():
    from saas.intel.atlas import summarise
    assert summarise("ping", []) is None and summarise("dns", []) is None and summarise("traceroute", []) is None
    s = summarise("ping", [{"prb_id": 1, "avg": 40.0, "rcvd": 3, "sent": 3}, {"prb_id": 2, "avg": -1, "rcvd": 0, "sent": 3}])
    assert s["median_rtt_ms"] == 40.0 and s["loss_pct"] == 50.0 and s["probes"] == 2
    d = summarise("dns", [{"prb_id": 1, "result": {"rt": 12.0}}, {"prb_id": 2, "error": {"timeout": 5000}}])
    assert d["success_pct"] == 50.0 and d["median_resolution_ms"] == 12.0
    t = summarise("traceroute", [{"prb_id": 1, "dst_addr": "9.9.9.9", "result": [{"hop": 1, "result": [{"from": "10.0.0.1", "rtt": 1.0}]}, {"hop": 2, "result": [{"from": "9.9.9.9", "rtt": 8.0}]}]},
                                 {"prb_id": 2, "dst_addr": "9.9.9.9", "result": [{"hop": 1, "result": [{"x": "*"}]}]}])
    assert t["reached_pct"] == 50.0 and t["median_final_rtt_ms"] == 8.0 and t["median_hops"] == 2
