"""A. Cybersecurity intelligence: CISA KEV (official JSON feed), NIST NVD (REST 2.0), OSV (GCS index + api.osv.dev)."""
import math
import time
from concurrent.futures import ThreadPoolExecutor

from ..core import now_ms
from . import core

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_INDEX = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/modified_id.csv"
OSV_DOC = "https://api.osv.dev/v1/vulns/{id}"
OSV_ECOSYSTEMS = ("PyPI", "npm", "Go")


def _clip(s, n):
    return (s or "").strip()[:n]


# ------------------------------------------------------------------------------------------------ CISA KEV
def fetch_kev(ctx):
    r = ctx.get(KEV_URL, conditional=True)
    if r is None:
        return None
    j = r.json()
    released = core.parse_ts(j.get("dateReleased"))
    events = []
    for v in j.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        ransom = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
        events.append({
            "id": f"kev:{cve}", "source": "cisa_kev", "category": "cyber", "kind": "kev", "severity": "critical" if ransom else "high",
            "title": _clip(v.get("vulnerabilityName") or cve, 200), "summary": _clip(v.get("shortDescription"), 900), "status": "exploited_in_the_wild",
            "event_ms": core.parse_ts(v.get("dateAdded")), "updated_ms": released, "source_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "vendor": _clip(v.get("vendorProject"), 80), "product": _clip(v.get("product"), 120), "cve": cve, "exploited": 1,
            "data": {"required_action": _clip(v.get("requiredAction"), 400), "due_date": v.get("dueDate"), "ransomware_use": v.get("knownRansomwareCampaignUse"),
                     "notes": _clip(v.get("notes"), 300), "cwes": v.get("cwes") or [], "catalog_version": j.get("catalogVersion"),
                     "catalog_url": KEV_PAGE}})
    return events, {"data_ms": released}


# ------------------------------------------------------------------------------------------------ NIST NVD
def _parse_cpe(c):
    p = c.split(":")
    return (p[2], p[3], p[4], p[5]) if len(p) > 5 and p[0] == "cpe" else None      # part, vendor, product, version


def nvd_event(cve):
    cid = cve["id"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    best = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ms = cve.get("metrics", {}).get(key) or []
        if ms:
            best = sorted(ms, key=lambda m: 0 if m.get("type") == "Primary" else 1)[0]
            break
    score = sev = ver = vec = None
    if best:
        d = best["cvssData"]
        score, ver, vec = d.get("baseScore"), d.get("version"), d.get("vectorString")
        sev = core.sev_from_cvss(score)
    cpes, pairs = [], []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                pc = _parse_cpe(m.get("criteria", ""))
                if not pc:
                    continue
                pairs.append((pc[1], pc[2]))
                if len(cpes) < 40:
                    cpes.append({"part": pc[0], "vendor": pc[1], "product": pc[2], "version": pc[3], "vsi": m.get("versionStartIncluding"),
                                 "vse": m.get("versionStartExcluding"), "vei": m.get("versionEndIncluding"), "vee": m.get("versionEndExcluding")})
    if not pairs:   # freshly published CVEs are often not yet analysed: fall back to the CNA's own 'affected' statement
        for a in cve.get("affected") or []:
            for ad in a.get("affectedData", []):
                pairs.append((str(ad.get("vendor", "")).lower(), str(ad.get("product", "")).lower()))
    uniq = list(dict.fromkeys(pairs))
    exploited = 1 if cve.get("cisaExploitAdd") else 0
    return {"id": f"nvd:{cid}", "source": "nvd", "category": "cyber", "kind": "cve", "severity": sev or "unrated", "title": cid,
            "summary": _clip(desc, 900), "status": cve.get("vulnStatus"), "event_ms": core.parse_ts(cve.get("published")),
            "updated_ms": core.parse_ts(cve.get("lastModified")), "source_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "vendor": ", ".join(dict.fromkeys(v for v, _ in uniq))[:160] or None, "product": ", ".join(dict.fromkeys(p for _, p in uniq))[:200] or None,
            "cve": cid, "score": score, "exploited": exploited,
            "data": {"cvss_version": ver, "cvss_vector": vec, "cpe": cpes, "weaknesses": [w["description"][0]["value"] for w in cve.get("weaknesses", []) if w.get("description")][:4],
                     "references": [r["url"] for r in cve.get("references", [])][:6], "cisa_action_due": cve.get("cisaActionDue"),
                     "source_identifier": cve.get("sourceIdentifier")}}


def fetch_nvd(ctx, max_pages=6, page_size=2000, pause_s=6.5):
    """Incremental by lastModified. NVD allows 5 requests / 30 s without an API key, so pages are spaced out; each page is stored as it
    arrives so a later failure never throws away what was already fetched."""
    now = now_ms()
    since = ctx.last_success_ms or (now - 2 * 86400_000)
    start, end = core.iso_ms(max(since - 300_000, now - 100 * 86400_000)), core.iso_ms(now)
    idx = total_seen = 0
    up = {"new": 0, "updated": 0, "unchanged": 0}
    for page in range(max_pages):
        r = ctx.get(NVD_URL, params={"lastModStartDate": start, "lastModEndDate": end, "resultsPerPage": page_size, "startIndex": idx})
        j = r.json()
        evs = [nvd_event(v["cve"]) for v in j.get("vulnerabilities", [])]
        for k, v in core.upsert(evs).items():
            up[k] += v
        total_seen += len(evs)
        idx += len(evs)
        if not evs or idx >= j.get("totalResults", 0):
            break
        time.sleep(pause_s)
    return [], {"items": total_seen, "upserted": up, "data_ms": now}


# ------------------------------------------------------------------------------------------------ OSV
def cvss3_score(vec):
    """CVSS v3.x base score from the vector string (deterministic formula from the specification)."""
    try:
        m = dict(p.split(":") for p in vec.split("/")[1:])
        S = m["S"]
        AV = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        AC = {"L": .77, "H": .44}[m["AC"]]
        PR = {"N": .85, "L": .68 if S == "C" else .62, "H": .5 if S == "C" else .27}[m["PR"]]
        UI = {"N": .85, "R": .62}[m["UI"]]
        C, I, A = [{"H": .56, "L": .22, "N": 0}[m[k]] for k in "CIA"]
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - C) * (1 - I) * (1 - A)
    imp = 6.42 * iss if S == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
    if imp <= 0:
        return 0.0
    base = min(imp + 8.22 * AV * AC * PR * UI, 10) if S == "U" else min(1.08 * (imp + 8.22 * AV * AC * PR * UI), 10)
    return math.ceil(base * 10 - 1e-9) / 10


def osv_event(d, eco):
    vid = d["id"]
    score = None
    for sv in d.get("severity") or []:
        if str(sv.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_score(sv.get("score", ""))
    ds = str((d.get("database_specific") or {}).get("severity", "")).upper()
    sev = core.sev_from_cvss(score) if score is not None else {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(ds, "unrated")
    aff = []
    for a in d.get("affected") or []:
        pk = a.get("package") or {}
        if not pk.get("name"):
            continue
        aff.append({"ecosystem": pk.get("ecosystem", eco), "name": pk["name"], "ranges": [{"type": r.get("type"), "events": r.get("events", [])} for r in a.get("ranges", [])],
                    "versions": (a.get("versions") or [])[:300]})
    cves = [x for x in d.get("aliases", []) if x.startswith("CVE-")]
    summ = d.get("summary") or (d.get("details") or "")[:200]
    return {"id": f"osv:{vid}", "source": "osv", "category": "cyber", "kind": "malicious-package" if vid.startswith("MAL-") else "package-vuln", "severity": sev,
            "title": _clip(f"{vid}: {summ}" if summ else vid, 200), "summary": _clip(d.get("details") or summ, 900), "status": "withdrawn" if d.get("withdrawn") else "published",
            "event_ms": core.parse_ts(d.get("published")), "updated_ms": core.parse_ts(d.get("modified")), "source_url": f"https://osv.dev/vulnerability/{vid}",
            "vendor": aff[0]["ecosystem"] if aff else eco, "product": ", ".join(dict.fromkeys(a["name"] for a in aff))[:200] or None, "cve": cves[0] if cves else None,
            "score": score, "exploited": 0, "data": {"aliases": d.get("aliases", [])[:8], "affected": aff[:6], "references": [r["url"] for r in d.get("references", [])][:5],
                                                     "ecosystem": eco, "cvss_vector": next((s.get("score") for s in d.get("severity") or []), None)}}


def fetch_osv(ctx, per_eco=30, mal_cap=8):
    now = now_ms()
    cutoff = ctx.last_success_ms or (now - 2 * 86400_000)
    wanted = []
    for eco in OSV_ECOSYSTEMS:
        txt = ctx.get(OSV_INDEX.format(eco=eco), headers={"Accept": "text/csv"}).text
        n = mal = 0
        for line in txt.splitlines():
            ts, _, vid = line.partition(",")
            t = core.parse_ts(ts)
            if not vid or t is None or t < cutoff or n >= per_eco:
                if t is not None and t < cutoff:
                    break
                continue
            if vid.startswith("MAL-"):
                if mal >= mal_cap:
                    continue
                mal += 1
            wanted.append((eco, vid))
            n += 1

    def one(item):
        eco, vid = item
        try:
            r = ctx.get(OSV_DOC.format(id=vid))
            return osv_event(r.json(), eco)
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=6) as ex:
        events = [e for e in ex.map(one, wanted) if e]
    if wanted and not events:
        raise RuntimeError("OSV index listed advisories but none could be fetched")
    return events, {"data_ms": now}


core.register(core.Source("cisa_kev", "cyber", "CISA Known Exploited Vulnerabilities", KEV_URL, 3600, fetch_kev, doc_url=KEV_PAGE))
core.register(core.Source("nvd", "cyber", "NIST National Vulnerability Database", NVD_URL, 7200, fetch_nvd, doc_url="https://nvd.nist.gov/developers/vulnerabilities", timeout=60))
core.register(core.Source("osv", "cyber", "Open Source Vulnerabilities (OSV)", "https://api.osv.dev/", 7200, fetch_osv, doc_url="https://osv.dev/", timeout=45))
