"""Stage 3 - RIPE RIS Live. Part 1 runs the REAL WebSocket stream; part 2 checks the detector's logic (synthetic messages in the real
RIS format) so that ordinary routing activity is never reported as unusual."""
import ipaddress
import time

import pytest

from .intel_helpers import needs_internet, run_intel


@needs_internet
def test_real_ris_live_stream_is_ingested_rolled_up_and_attributed():
    r = run_intel('''
import threading
from saas.intel import ris
core.ensure_source(core.SOURCES["ris"])
ris.add_watch("13335", "test: Cloudflare"); ris.add_watch(ris.host_network(), "host network")
stop = threading.Event(); t = threading.Thread(target=ris._thread_main, args=(stop,), daemon=True); t.start()
time.sleep(70); stop.set()
roll = {r["scope"]: r for r in db.all("SELECT scope, COUNT(*) minutes, SUM(announcements) ann, SUM(withdrawals) wd, MAX(peers) peers FROM intel_bgp GROUP BY scope")}
sv = [s for s in core.source_view() if s["source"] == "ris"][0]
evs = db.all("SELECT kind, severity, title, summary, source_url, data FROM intel_events WHERE source='ris'")
info = ris.asn_info("13335")
out({"state": {k: v for k, v in ris.STATE.items() if k != "watched"}, "watched": ris.STATE["watched"], "roll": roll, "sv": sv, "ring": list(ris.RING)[:25], "n_ring": len(ris.RING),
     "events": evs, "info": info, "now": time.time() * 1000})
''', timeout=200)
    st = r["state"]
    assert st["connected"] and st["msgs"] > 5000 and st["rate"] > 50 and st["error"] is None, st
    assert "13335" in r["watched"] and st["subs"] > 2, "targeted ASN/prefix subscriptions were really sent"
    assert r["roll"]["global"]["ann"] > 5000 and r["roll"]["global"]["wd"] > 0 and r["roll"]["global"]["peers"] > 10, r["roll"]["global"]
    assert r["roll"]["AS13335"]["ann"] > 0 and r["roll"]["AS13335"]["peers"] > 5, "a watched ASN accumulates its own genuine announcements"
    assert r["sv"]["freshness"] == "live" and r["sv"]["last_data_ms"] > r["now"] - 120_000 and "msg/s" in r["sv"]["note"]
    assert r["n_ring"] >= 25
    for m in r["ring"]:
        assert m["host"].startswith("rrc") and m["peer_asn"].isdigit() and abs(m["ts_ms"] - r["now"]) < 180_000, m
        assert all(isinstance(a, int) for a in m["path"]) and (m["announced"] or m["withdrawn"])
        for pfx in m["announced"] + m["withdrawn"]:
            ipaddress.ip_network(pfx)                                    # real, parseable prefixes
    assert "CLOUDFLARE" in (r["info"]["holder"] or "").upper() and r["info"]["prefixes"], "AS info comes from RIPEstat"
    for e in r["events"]:                                                # any notable event must be conservative and attributed
        assert e["kind"] in ("origin_change", "origin_flapping", "withdrawal_surge", "prefix_withdrawn") and e["source_url"].startswith("https://")
        low = (e["title"] + e["summary"]).lower()
        assert "attack" not in low and ("not evidence" in low or "does not" in low or "alone" in low), "no unsupported attack claims"


# ---------------------------------------------------------------------------------------------------- detector logic (no network)
MSG = lambda i, peer, path, ann=(), wd=(), host="rrc00", ts=None: {"id": f"{peer}-{i}", "host": host + ".ripe.net", "type": "UPDATE", "timestamp": ts or time.time(),
                                                                  "peer": peer, "peer_asn": str(path[0]) if path else "64500", "path": list(path),
                                                                  "announcements": [{"next_hop": peer, "prefixes": list(ann)}] if ann else [], "withdrawals": list(wd)}


def test_normal_routing_activity_produces_no_unusual_event_and_duplicates_are_dropped():
    from saas.intel.ris import Detector
    d = Detector()
    t0 = time.time()
    for i in range(200):                                              # steady announcements, one peer at a time, stable origins
        assert d.handle(MSG(i, f"10.0.0.{i % 5}", [65001 + i % 5, 3356, 64496], ann=[f"198.51.{i % 50}.0/24"], ts=t0)) == []
    assert d.flush(t0 + 61) == [], "ordinary announcements are not 'events'"
    dup = MSG(999, "10.0.0.1", [65001, 64496], ann=["203.0.113.0/24"])
    d.handle(dup)
    n = d.minute["global"]["a"]
    d.handle(dup)
    assert d.minute["global"]["a"] == n, "the same RIS message id is counted once even if two subscriptions deliver it"


def test_origin_change_needs_several_peers_and_is_labelled_informational_not_an_attack():
    from saas.intel.ris import Detector
    d = Detector()
    t0 = time.time()
    d.handle(MSG(1, "10.0.0.1", [65001, 64496], ann=["203.0.113.0/24"], ts=t0))                       # origin AS64496 established
    d.handle(MSG(2, "10.0.0.2", [65002, 64999], ann=["203.0.113.0/24"], ts=t0 + 1))                   # ONE peer sees a different origin
    assert d.flush(t0 + 61) == [], "a single peer is not enough evidence"
    d = Detector()
    d.handle(MSG(1, "10.0.0.1", [65001, 64496], ann=["203.0.113.0/24"], ts=t0))
    for i, peer in enumerate(("10.0.0.2", "10.0.0.3", "10.0.0.4")):
        d.handle(MSG(10 + i, peer, [65002 + i, 64999], ann=["203.0.113.0/24"], ts=t0 + 2 + i))
    ev = d.flush(t0 + 61)
    assert len(ev) == 1 and ev[0]["kind"] == "origin_change" and ev[0]["severity"] == "low" and ev[0]["prefix"] == "203.0.113.0/24"
    assert "NOT evidence of a hijack" in ev[0]["summary"] and ev[0]["data"]["rpki_validated"] is None and ev[0]["data"]["peers_observing"] >= 3
    assert d.flush(t0 + 122) == [], "the same change is not re-reported"


def test_flapping_between_two_origins_is_one_aggregated_observation():
    from saas.intel.ris import Detector
    d = Detector()
    t0 = time.time()
    pfxs = [f"198.18.{i}.0/24" for i in range(6)]
    for p in pfxs:
        d.handle(MSG(hash(p) % 10**6, "10.0.0.1", [65001, 64496], ann=[p], ts=t0))
    k = 100
    for flip in range(2):                                              # A->B then B->A, seen by 3 peers each time
        origin = 64999 if flip == 0 else 64496
        for peer in ("10.0.0.2", "10.0.0.3", "10.0.0.4"):
            for p in pfxs:
                k += 1
                d.handle(MSG(k, peer, [65002, origin], ann=[p], ts=t0 + 5 + flip))
    ev = d.flush(t0 + 61)
    assert len(ev) == 1 and ev[0]["kind"] == "origin_flapping" and len(ev[0]["data"]["prefixes"]) == 6 and "multi-homing" in ev[0]["summary"]


def test_withdrawal_surge_requires_a_baseline_and_a_large_multiple():
    from saas.intel.ris import Detector
    d = Detector()
    t0 = time.time()
    for minute in range(35):                                           # 35 minutes of a steady ~1000 withdrawals/minute baseline
        d.handle(MSG(minute, "10.0.0.1", [], wd=[f"192.0.{minute % 200}.{j}/32" for j in range(250)] * 4, ts=t0 + minute * 60))
        assert d.flush(t0 + minute * 60 + 59) == [], "no event while behaviour is normal"
    d.handle(MSG(900, "10.0.0.1", [], wd=[f"100.64.{j % 250}.{j // 250}/32" for j in range(9000)], ts=t0 + 36 * 60))
    ev = d.flush(t0 + 36 * 60 + 59)
    assert len(ev) == 1 and ev[0]["kind"] == "withdrawal_surge" and ev[0]["severity"] == "low" and "does not identify a cause" in ev[0]["summary"]
    cold = Detector()
    cold.handle(MSG(1, "10.0.0.1", [], wd=[f"100.64.{j % 250}.{j // 250}/32" for j in range(9000)], ts=t0))
    assert cold.flush(t0 + 59) == [], "no baseline yet -> no claim (not enough evidence)"


def test_watched_prefix_loss_needs_several_peers_and_is_cancelled_by_reannouncement():
    from saas.intel.ris import Detector
    d = Detector()
    d.watched, d.watch_prefixes = {"64496"}, {"203.0.113.0/24": "64496"}
    t0 = time.time()
    for i in range(3):
        d.handle(MSG(i, f"10.0.0.{i}", [], wd=["203.0.113.0/24"], ts=t0))
    assert d.flush(t0 + 61) == [], "3 peers are not enough"
    d = Detector()
    d.watched, d.watch_prefixes = {"64496"}, {"203.0.113.0/24": "64496"}
    for i in range(6):
        d.handle(MSG(i, f"10.0.0.{i}", [], wd=["203.0.113.0/24"], ts=t0))
    ev = d.flush(t0 + 61)
    assert len(ev) == 1 and ev[0]["kind"] == "prefix_withdrawn" and ev[0]["asn"] == "64496" and "does not by itself explain why" in ev[0]["summary"]
    d = Detector()
    d.watched, d.watch_prefixes = {"64496"}, {"203.0.113.0/24": "64496"}
    for i in range(6):
        d.handle(MSG(i, f"10.0.0.{i}", [], wd=["203.0.113.0/24"], ts=t0))
    d.handle(MSG(50, "10.0.0.9", [65001, 64496], ann=["203.0.113.0/24"], ts=t0 + 5))                 # prefix re-announced: not a loss
    assert d.flush(t0 + 61) == []
