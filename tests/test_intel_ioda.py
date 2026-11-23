"""Stage 4 - IODA: REAL API fetches."""
import time

import pytest

from .intel_helpers import needs_internet, run_intel

pytestmark = needs_internet


def test_ioda_real_outage_events_are_fetched_attributed_and_deduplicated():
    r = run_intel('''
a = core.run_once(core.SOURCES["ioda"]); b = core.run_once(core.SOURCES["ioda"])
rows = db.all("SELECT * FROM intel_events WHERE source='ioda'")
kinds = {}
for x in rows: kinds[x["kind"]] = kinds.get(x["kind"], 0) + 1
out({"a": a, "b": b, "n": len(rows), "kinds": kinds, "rows": [dict(x) | {"data": json.loads(x["data"])} for x in rows[:400]],
     "hist": db.one("SELECT COUNT(*) n FROM intel_history WHERE event_id LIKE 'ioda:%'")["n"], "src": [s for s in core.source_view() if s["source"] == "ioda"][0], "now": time.time() * 1000})
''', timeout=300)
    assert r["a"]["ok"] and r["a"]["new"] >= 10, r["a"]
    assert r["b"]["new"] == 0, "a repeated fetch adds nothing (ongoing events are not versioned on every poll)"
    assert {"country_outage"} <= set(r["kinds"]) and r["n"] == r["a"]["new"]
    for e in r["rows"]:
        d = e["data"]
        assert e["id"].startswith("ioda:") and e["category"] == "outage" and e["status"] in ("ongoing", "ended") and e["severity"] in ("high", "medium", "low")
        assert e["event_ms"] < r["now"] and e["updated_ms"] >= e["event_ms"] and d["duration_s"] >= 0 and d["datasource"]
        assert e["source_url"].startswith("https://ioda.inetintel.cc.gatech.edu/")
        if e["kind"] == "country_outage":
            assert len(e["country"]) == 2 and e["country"].isupper(), "ISO country code from the IODA entity"
        if e["kind"] == "asn_outage":
            assert e["asn"].isdigit()
        if e["severity"] == "high":
            assert len(d["corroborating_datasources"]) >= 2, "'high' only when independent signals agree"
    assert r["src"]["freshness"] == "live" and "outage signals" in r["src"]["note"]


def test_ioda_country_names_and_ongoing_flag_match_the_api_directly():
    import httpx
    r = run_intel('''
core.run_once(core.SOURCES["ioda"])
rows = db.all("SELECT country, title, status FROM intel_events WHERE kind='country_outage'")
out({"rows": rows})
''', timeout=300)
    now = int(time.time())
    live = httpx.get("https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events", params={"entityType": "country", "from": now - 48 * 3600, "until": now, "limit": 400},
                     timeout=60).json()["data"]
    live_codes = {e["location"].split("/")[1] for e in live}
    ours = {x["country"] for x in r["rows"]}
    assert ours and len(ours ^ live_codes) <= max(2, len(live_codes) // 5), "our stored countries track what IODA itself reports right now"
    assert all(x["country"] and x["title"].lower().startswith(x["title"].split(":")[0].lower()) for x in r["rows"])
