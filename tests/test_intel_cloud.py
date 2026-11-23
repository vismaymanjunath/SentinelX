"""Stage 2 - AWS, Azure, Cloudflare, Google Cloud, GitHub status feeds: REAL fetches from the official sources."""
import time

import pytest

from .intel_helpers import needs_internet, run_intel

pytestmark = needs_internet
OFFICIAL = {"aws": ("status.aws.amazon.com", "health.aws.amazon.com"), "azure": ("azure.status.microsoft", "status.azure.com"), "cloudflare": ("cloudflarestatus.com", "stspg.io"),
            "gcp": ("status.cloud.google.com",), "github": ("githubstatus.com", "stspg.io")}


def test_all_five_real_provider_feeds_are_fetched_attributed_and_normalised():
    r = run_intel('''
res = {sid: core.run_once(core.SOURCES[sid]) for sid in ("aws", "azure", "cloudflare", "gcp", "github")}
rows = db.all("SELECT * FROM intel_events WHERE category='cloud'")
again = {sid: core.run_once(core.SOURCES[sid]) for sid in ("aws", "azure", "cloudflare", "gcp", "github")}
out({"res": res, "again": again, "rows": [{k: x[k] for k in ("id", "source", "provider", "severity", "status", "title", "event_ms", "updated_ms", "source_url", "region", "summary")}
                                           | {"data": json.loads(x["data"])} for x in rows],
     "src": {s["source"]: s for s in core.source_view()}})
''')
    for sid, res in r["res"].items():
        assert res["ok"], (sid, res)
    for sid, res in r["again"].items():
        assert res["new"] == 0, (sid, "second fetch must not duplicate", res)
    by = {}
    for e in r["rows"]:
        by.setdefault(e["source"], []).append(e)
    assert len(by["cloudflare"]) > 5 and len(by["github"]) > 5 and len(by["gcp"]) >= 1 and len(by["aws"]) >= 1, {k: len(v) for k, v in by.items()}
    for e in r["rows"]:
        assert e["provider"] == e["source"] and e["status"] and e["title"] and e["severity"] in ("critical", "high", "medium", "low", "unrated")
        assert any(h in e["source_url"] for h in OFFICIAL[e["source"]]), (e["source"], e["source_url"])
        assert e["event_ms"] and e["event_ms"] < time.time() * 1000 + 3600_000 and (e["updated_ms"] or 0) >= (e["event_ms"] or 0) - 1
        assert isinstance(e["data"].get("updates"), list) and "services" in e["data"]
        assert "<" not in e["summary"] and "<script" not in e["title"].lower(), "external markup is stripped"
    assert any(e["status"] == "resolved" and e["data"]["updates"] for e in by["github"] + by["cloudflare"]), "resolution updates are preserved"
    # Azure may legitimately have NO incidents: the source must still be reported as live, with an honest note, and nothing invented
    assert r["src"]["azure"]["freshness"] == "live" and (r["src"]["azure"]["events_stored"] == 0) == ("no active" in (r["src"]["azure"]["note"] or ""))
    for sid in ("aws", "cloudflare", "gcp", "github", "azure"):
        assert r["src"][sid]["freshness"] == "live" and r["src"][sid]["last_success_ms"] > time.time() * 1000 - 300_000


def test_active_incident_counts_match_what_the_provider_itself_reports():
    """Cross-check our normalisation against the provider's own live summary (fetched independently here)."""
    import httpx
    r = run_intel('''
core.run_once(core.SOURCES["cloudflare"]); core.run_once(core.SOURCES["github"])
n = lambda sid: db.one("SELECT COUNT(*) n FROM intel_events WHERE source=? AND status!='resolved' AND status!='postmortem'", (sid,))["n"]
out({"cloudflare": n("cloudflare"), "github": n("github")})
''')
    for sid, base in (("cloudflare", "https://www.cloudflarestatus.com"), ("github", "https://www.githubstatus.com")):
        live = httpx.get(f"{base}/api/v2/summary.json", timeout=30).json()
        assert abs(len(live["incidents"]) - r[sid]) <= 1, (sid, len(live["incidents"]), r[sid])


def test_aws_overlapping_feeds_are_deduplicated_per_region():
    r = run_intel('''
core.run_once(core.SOURCES["aws"])
rows = db.all("SELECT id, region, status FROM intel_events WHERE source='aws'")
active = [x for x in rows if x["status"] == "active"]
out({"active_regions": [x["region"] for x in active], "n": len(rows)})
''')
    assert len(r["active_regions"]) == len(set(r["active_regions"])), "one active AWS incident per region (RSS + Health feeds merged)"
