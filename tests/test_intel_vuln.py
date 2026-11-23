"""Stage 1 - CISA KEV, NIST NVD, OSV: REAL fetches from the actual external sources (no mocked responses)."""
import re
import time

import pytest

from .intel_helpers import needs_internet, run_intel

pytestmark = needs_internet
NOW_MS = lambda: time.time() * 1000


def test_cisa_kev_real_feed_is_fetched_normalised_attributed_and_deduplicated():
    r = run_intel('''
a = core.run_once(core.SOURCES["cisa_kev"]); b = core.run_once(core.SOURCES["cisa_kev"])
rows = db.all("SELECT * FROM intel_events WHERE source='cisa_kev' ORDER BY event_ms DESC")
src = core.source_view()[0]
out({"a": a, "b": b, "n": len(rows), "newest": rows[0], "sample": rows[len(rows)//2], "ids": len({x["id"] for x in rows}), "src": src,
     "hist": db.one("SELECT COUNT(*) n FROM intel_history")["n"]})
''')
    assert r["a"]["ok"] and r["a"]["new"] >= 1000, r["a"]
    assert r["b"] == {"ok": True, "fetched": r["a"]["fetched"], "new": 0, "updated": 0, "unchanged": r["a"]["fetched"]}, "second fetch must not duplicate anything"
    assert r["n"] == r["ids"] == r["a"]["new"] and r["hist"] == r["n"]
    for e in (r["newest"], r["sample"]):
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", e["cve"]) and e["id"] == f"kev:{e['cve']}" and e["exploited"] == 1 and e["status"] == "exploited_in_the_wild"
        assert e["vendor"] and e["product"] and e["summary"] and e["source_url"] == f"https://nvd.nist.gov/vuln/detail/{e['cve']}"
        assert 0 < e["event_ms"] <= NOW_MS() + 86400_000, "dateAdded is a real, non-future date"
    assert r["src"]["freshness"] == "live" and r["src"]["events_stored"] == r["n"] and r["src"]["last_success_ms"] > NOW_MS() - 120_000


def test_nvd_real_api_returns_cves_with_cvss_vendors_and_correct_severity_mapping():
    r = run_intel('''
res = core.run_once(core.SOURCES["nvd"])
rows = db.all("SELECT * FROM intel_events WHERE source='nvd'")
scored = [x for x in rows if x["score"] is not None]
cfg = [x for x in rows if json.loads(x["data"]).get("cpe")]
bad = [(x["id"], x["score"], x["severity"]) for x in scored if x["severity"] != core.sev_from_cvss(x["score"])]
out({"res": res, "n": len(rows), "scored": len(scored), "with_cpe": len(cfg), "bad_sev": bad[:3], "sample": cfg[0] if cfg else rows[0],
     "published_ok": all(0 < x["event_ms"] <= time.time()*1000 + 86400000 for x in rows), "newest_update": max(x["updated_ms"] for x in rows),
     "src": [s for s in core.source_view() if s["source"] == "nvd"][0]})
''')
    assert r["res"]["ok"] and r["n"] >= 50, r["res"]
    assert r["scored"] >= 0.5 * r["n"], "most CVEs carry a real CVSS score"
    assert r["bad_sev"] == [] and r["published_ok"] and r["with_cpe"] > 0
    e = r["sample"]
    assert re.fullmatch(r"CVE-\d{4}-\d{4,}", e["cve"]) and e["source_url"] == f"https://nvd.nist.gov/vuln/detail/{e['cve']}" and e["summary"]
    assert e["vendor"], "affected vendor present for a CVE with CPE data"
    assert r["newest_update"] > NOW_MS() - 3 * 86400_000, "NVD data is current (modified within days)"
    assert r["src"]["freshness"] == "live"


def test_osv_real_advisories_carry_packages_ranges_aliases_and_sources():
    r = run_intel('''
res = core.run_once(core.SOURCES["osv"]); res2 = core.run_once(core.SOURCES["osv"])
rows = db.all("SELECT * FROM intel_events WHERE source='osv'")
pk = [json.loads(x["data"]) for x in rows if x["kind"] == "package-vuln"]
out({"res": res, "res2": res2, "n": len(rows), "kinds": sorted({x["kind"] for x in rows}), "eco": sorted({json.loads(x["data"])["ecosystem"] for x in rows}),
     "with_ranges": sum(1 for d in pk if any(a["ranges"] or a["versions"] for a in d["affected"])), "pk": len(pk), "sample": rows[0],
     "bad_url": [x["id"] for x in rows if x["source_url"] != "https://osv.dev/vulnerability/" + x["id"].split(":", 1)[1]]})
''')
    assert r["res"]["ok"] and r["n"] > 10 and r["res2"]["new"] == 0, (r["res"], r["res2"])
    assert set(r["eco"]) <= {"PyPI", "npm", "Go"} and r["bad_url"] == []
    assert r["pk"] and r["with_ranges"] >= 0.8 * r["pk"], "package advisories carry version ranges/lists usable for matching"
    assert r["sample"]["event_ms"] and r["sample"]["updated_ms"]


def test_unavailable_source_keeps_last_real_data_and_is_labelled_cached_then_never_invented():
    r = run_intel('''
src = core.SOURCES["cisa_kev"]
first = core.run_once(src); n1 = db.one("SELECT COUNT(*) n FROM intel_events")["n"]
dead = core.Source("cisa_kev", "cyber", src.name, "http://127.0.0.1:1/none.json", 3600, lambda ctx: (_ for _ in ()).throw(ctx.client.get("http://127.0.0.1:1/none.json")), doc_url=src.doc_url)
core.SOURCES["cisa_kev"] = dead
bad = core.run_once(dead)
n2 = db.one("SELECT COUNT(*) n FROM intel_events")["n"]
v = core.source_view()[0]
db.exec("UPDATE intel_sources SET last_success_ms=? WHERE source='cisa_kev'", (time.time()*1000 - 5*3600_000,))
stale = core.source_view()[0]
never = core.Source("ghost", "cyber", "Never reachable", "http://127.0.0.1:1/", 600, lambda ctx: ctx.get("http://127.0.0.1:1/x"))
bad2 = core.run_once(never); gv = [s for s in core.source_view() if s["source"] == "ghost"][0]
out({"first": first["ok"], "bad": bad, "n1": n1, "n2": n2, "cached": [v["freshness"], v["last_error"]], "stale": stale["freshness"], "ghost": [gv["freshness"], gv["events_stored"], gv["last_error"]]})
''')
    assert r["first"] and not r["bad"]["ok"] and r["n1"] == r["n2"] > 1000, "a failing source never deletes or fabricates events"
    assert r["cached"][0] == "cached" and r["cached"][1], "recent real data + current failure = 'cached', with the error shown"
    assert r["stale"] == "stale"
    assert r["ghost"][0] == "unavailable" and r["ghost"][1] == 0 and r["ghost"][2]


def test_rate_limit_responses_are_recorded_and_backed_off():
    r = run_intel('''
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(429); self.send_header("Retry-After", "120"); self.end_headers()
srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}/"
s = core.Source("limited", "cyber", "Limited", url, 600, lambda ctx: ctx.get(url))
res = core.run_once(s); row = db.one("SELECT state, next_attempt_ms, last_attempt_ms FROM intel_sources WHERE source='limited'")
out({"res": res, "state": row["state"], "backoff_s": round((row["next_attempt_ms"] - row["last_attempt_ms"]) / 1000), "label": [x for x in core.source_view() if x["source"] == "limited"][0]["freshness"]})
''')
    assert r["res"]["state"] == "rate_limited" and r["state"] == "rate_limited" and r["backoff_s"] == 120 and r["label"] == "rate_limited"
