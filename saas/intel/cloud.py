"""D. Cloud infrastructure health: official machine-readable status feeds for AWS, Azure, Cloudflare, Google Cloud and GitHub."""
import html
import json
import re
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

from . import core

CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TAG = re.compile(r"<[^>]+>")
REGION = re.compile(r"((?:us|eu|ap|sa|ca|me|af|il|mx)-(?:gov-)?[a-z]+-\d)$")
IMPACT_SEV = {"critical": "critical", "major": "high", "minor": "medium", "none": "low", "maintenance": "low"}


def clean(s, n=600):
    """External text is untrusted data: strip markup/control characters and bound its length. (It is never executed or rendered as HTML.)"""
    s = html.unescape(TAG.sub(" ", s or ""))
    return re.sub(r"\s+", " ", CTRL.sub("", s)).strip()[:n]


# ------------------------------------------------------------------------------------------------ Atlassian Statuspage (Cloudflare, GitHub)
def _statuspage(provider, base, page_url):
    def fetch(ctx):
        inc = ctx.get(f"{base}/api/v2/incidents.json").json()
        try:
            summ = ctx.get(f"{base}/api/v2/summary.json").json()
            note = f"{summ['status']['description']} (provider indicator: {summ['status']['indicator']}); {len(summ.get('incidents', []))} unresolved incident(s)"
        except Exception:
            note = None
        events = []
        for i in inc.get("incidents", []):
            comps = [c["name"] for c in i.get("components", []) if c.get("name")]
            ups = [{"status": u.get("status"), "at": u.get("created_at"), "body": clean(u.get("body"), 500)} for u in i.get("incident_updates", [])][:12]
            latest = ups[0]["body"] if ups else ""
            events.append({"id": f"{provider}:{i['id']}", "source": provider, "category": "cloud", "kind": "incident", "provider": provider,
                           "severity": IMPACT_SEV.get(i.get("impact"), "unrated"), "title": clean(i.get("name"), 200), "summary": latest,
                           "status": i.get("status"), "event_ms": core.parse_ts(i.get("started_at") or i.get("created_at")), "updated_ms": core.parse_ts(i.get("updated_at")),
                           "source_url": i.get("shortlink") or page_url, "region": ", ".join(comps[:6])[:200] or None,
                           "data": {"impact": i.get("impact"), "services": comps[:40], "updates": ups, "resolved_at": i.get("resolved_at"), "page": page_url}})
        return events, {"note": note}
    return fetch


# ------------------------------------------------------------------------------------------------ Google Cloud
def fetch_gcp(ctx):
    j = ctx.get("https://status.cloud.google.com/incidents.json").json()
    events = []
    for i in j:
        ended = i.get("end")
        impact = i.get("status_impact")
        locs = [x.get("title") for x in (i.get("currently_affected_locations") or i.get("previously_affected_locations") or []) if x.get("title")]
        prods = [x.get("title") for x in i.get("affected_products") or [] if x.get("title")]
        ups = [{"status": u.get("status"), "at": u.get("when") or u.get("created"), "body": clean(u.get("text"), 500)} for u in i.get("updates", [])][-12:][::-1]
        events.append({"id": f"gcp:{i['id']}", "source": "gcp", "category": "cloud", "kind": "incident", "provider": "gcp",
                       "severity": {"SERVICE_OUTAGE": "critical", "SERVICE_DISRUPTION": "high", "SERVICE_INFORMATION": "low"}.get(impact, "unrated"),
                       "title": clean(i.get("external_desc") or i.get("service_name"), 200), "summary": ups[0]["body"] if ups else "",
                       "status": "resolved" if ended else "active", "event_ms": core.parse_ts(i.get("begin")), "updated_ms": core.parse_ts(i.get("modified")),
                       "source_url": "https://status.cloud.google.com" + (i.get("uri") or "/"), "region": ", ".join(locs[:8])[:200] or None,
                       "data": {"impact": impact, "severity_reported": i.get("severity"), "services": prods[:40], "locations": locs[:30], "updates": ups, "resolved_at": ended,
                                "service": i.get("service_name")}})
    return events, {"note": f"{sum(1 for e in events if e['status'] == 'active')} active incident(s) in the official feed"}


# ------------------------------------------------------------------------------------------------ AWS
AWS_RSS = "https://status.aws.amazon.com/rss/all.rss"
AWS_CURRENT = "https://health.aws.amazon.com/public/currentevents"


def _parse_rss(text):
    if "<!DOCTYPE" in text[:2000] or "<!ENTITY" in text:
        raise ValueError("refusing XML with DTD/entities")
    if len(text) > 3_000_000:
        raise ValueError("feed unexpectedly large")
    root = ET.fromstring(text.encode("utf-8", "replace"))
    out = []
    for it in root.iter("item"):
        d = {c.tag: (c.text or "") for c in it}
        out.append(d)
    return out


def _aws_kind(title):
    t = (title or "").lower()
    if t.startswith("service is operating normally") or "resolved" in t[:40]:
        return "resolved", "low"
    if t.startswith("service disruption") or t.startswith("service impact"):
        return "active", "high"
    if t.startswith("performance issues") or t.startswith("service degradation"):
        return "active", "medium"
    if t.startswith("informational"):
        return "active", "low"
    return "active", "unrated"


def fetch_aws(ctx):
    items = _parse_rss(ctx.get(AWS_RSS, headers={"Accept": "application/rss+xml"}).text)
    parsed = []
    for it in items:
        m = re.search(r"#(.+)_(\d{9,})$", it.get("guid", ""))
        if not m:
            continue
        svc_key, ep = m.group(1), int(m.group(2))
        rm = REGION.search(svc_key)
        parsed.append({"svc": svc_key, "region": rm.group(1) if rm else None, "service": svc_key[:rm.start() - 1] if rm else svc_key, "ep": ep,
                       "title": clean(it.get("title"), 200), "body": clean(it.get("description"), 700), "link": it.get("link") or "https://health.aws.amazon.com/health/status"})
    parsed.sort(key=lambda x: x["ep"])
    chains, open_ = [], {}
    for p in parsed:                                    # group successive updates of one service/region into one incident
        st, sev = _aws_kind(p["title"])
        ch = open_.get(p["svc"])
        if ch is None:
            ch = {"svc": p["svc"], "region": p["region"], "service": p["service"], "start": p["ep"], "updates": [], "sev": "low"}
            chains.append(ch)
            open_[p["svc"]] = ch
        ch["updates"].append({"status": st, "at": p["ep"], "title": p["title"], "body": p["body"]})
        if core.SEVERITIES.index(sev) < core.SEVERITIES.index(ch["sev"]) if sev in core.SEVERITIES and ch["sev"] in core.SEVERITIES else False:
            ch["sev"] = sev
        ch["last"] = p
        if st == "resolved":
            open_.pop(p["svc"], None)
    events = []
    for ch in chains:
        last = ch["updates"][-1]
        resolved = last["status"] == "resolved"
        peak = min((_aws_kind(u["title"])[1] for u in ch["updates"]), key=lambda s: core.SEVERITIES.index(s) if s in core.SEVERITIES else 9)
        events.append({"id": f"aws:{ch['svc']}:{ch['start']}", "source": "aws", "category": "cloud", "kind": "incident", "provider": "aws", "severity": peak,
                       "title": f"{ch['service']} — {ch['updates'][0]['title']}"[:200], "summary": last["body"], "status": "resolved" if resolved else "active",
                       "event_ms": ch["start"] * 1000.0, "updated_ms": last["at"] * 1000.0, "source_url": ch["last"]["link"], "region": ch["region"],
                       "data": {"services": [ch["service"]], "region": ch["region"], "updates": [{"status": u["status"], "at": u["at"] * 1000, "body": u["body"], "title": u["title"]} for u in ch["updates"][::-1]][:12]}})
    cur_note = ""
    rss_events = events
    events = []
    try:                                                # AWS Health public dashboard: events AWS itself lists as current
        raw = ctx.get(AWS_CURRENT).content
        txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")
        cur = json.loads(txt) if txt.strip() else []
        for e in cur:
            log = e.get("event_log") or []
            last = log[-1] if log else {}
            msg = clean(last.get("message"), 700)
            resolved = msg.lower().startswith("[resolved]") or (last.get("summary") or "").lower().startswith("resolved")
            rm = REGION.search(e.get("service", ""))
            events.append({"id": f"aws-current:{e.get('arn')}", "source": "aws", "category": "cloud", "kind": "incident", "provider": "aws",
                           "severity": "high" if "disruption" in (e.get("summary", "") + msg).lower() or "unavailab" in msg.lower() else "medium",
                           "title": clean(f"{e.get('service_name')} ({e.get('region_name')}) — {e.get('summary')}", 200), "summary": msg,
                           "status": "resolved" if resolved else "active", "event_ms": float(e.get("date", 0)) * 1000 or None,
                           "updated_ms": (last.get("timestamp") or 0) * 1000.0 or None, "source_url": "https://health.aws.amazon.com/health/status",
                           "region": rm.group(1) if rm else e.get("region_name"),
                           "data": {"services": [e.get("service_name")], "region_name": e.get("region_name"), "arn": e.get("arn"), "raw_status": e.get("status"),
                                    "updates": [{"status": u.get("status"), "at": (u.get("timestamp") or 0) * 1000, "body": clean(u.get("message"), 500), "title": clean(u.get("summary"), 120)} for u in log[::-1]][:12]}})
        cur_note = f"; AWS Health lists {len(cur)} current event(s)"
    except Exception as ex:
        cur_note = f"; AWS Health currentevents unavailable ({type(ex).__name__})"
    # the same live incident appears in both feeds: keep AWS Health's own current event and drop the overlapping ACTIVE RSS chain of that region
    live_regions = {e["region"] for e in events if e["status"] == "active" and e.get("region")}
    events = events + [e for e in rss_events if not (e["status"] == "active" and e.get("region") in live_regions)]
    return events, {"note": f"{sum(1 for e in events if e['status'] == 'active')} active incident(s){cur_note}"}


# ------------------------------------------------------------------------------------------------ Azure
AZURE_RSS = "https://rssfeed.azure.status.microsoft/en-us/status/feed/"


def fetch_azure(ctx):
    items = _parse_rss(ctx.get(AZURE_RSS, headers={"Accept": "application/rss+xml"}).text)
    events = []
    for it in items:
        title, link, guid = clean(it.get("title"), 200), it.get("link") or "https://azure.status.microsoft/en-us/status/", it.get("guid") or it.get("link") or title
        try:
            ts = parsedate_to_datetime(it["pubDate"]).timestamp() * 1000 if it.get("pubDate") else None
        except (TypeError, ValueError):
            ts = None
        body = clean(it.get("description"), 700)
        resolved = "resolved" in title.lower() or "resolved" in body.lower()[:80]
        events.append({"id": f"azure:{guid}", "source": "azure", "category": "cloud", "kind": "incident", "provider": "azure", "severity": "unrated" if not resolved else "low",
                       "title": title, "summary": body, "status": "resolved" if resolved else "active", "event_ms": ts, "updated_ms": ts, "source_url": link,
                       "data": {"services": [], "updates": [{"status": "resolved" if resolved else "active", "at": ts, "body": body}]}})
    return events, {"note": "feed healthy; Azure currently lists no active incidents" if not events else f"{len(events)} item(s) in the official feed"}


core.register(core.Source("aws", "cloud", "AWS Service Health", AWS_RSS, 300, fetch_aws, doc_url="https://health.aws.amazon.com/health/status"))
core.register(core.Source("azure", "cloud", "Microsoft Azure Status", AZURE_RSS, 300, fetch_azure, doc_url="https://azure.status.microsoft/en-us/status/"))
core.register(core.Source("cloudflare", "cloud", "Cloudflare Status", "https://www.cloudflarestatus.com/api/v2/incidents.json", 300,
                          _statuspage("cloudflare", "https://www.cloudflarestatus.com", "https://www.cloudflarestatus.com"), doc_url="https://www.cloudflarestatus.com"))
core.register(core.Source("gcp", "cloud", "Google Cloud Status", "https://status.cloud.google.com/incidents.json", 300, fetch_gcp, doc_url="https://status.cloud.google.com"))
core.register(core.Source("github", "cloud", "GitHub Status", "https://www.githubstatus.com/api/v2/incidents.json", 300,
                          _statuspage("github", "https://www.githubstatus.com", "https://www.githubstatus.com"), doc_url="https://www.githubstatus.com"))
