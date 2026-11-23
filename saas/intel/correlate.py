"""Local-to-global correlation: compares public intelligence with what connected devices actually report.

Principles
  * evidence only: every point of a score comes from a named factor computed from data present in BOTH sides; no factor, no points
  * Python decides (scoring, matching, status); the optional local LLM may only explain the stored result
  * three outcomes: confirmed (shared identifier + overlapping time/verified version + local evidence), possible, and unrelated
    (not stored: it is simply a worldwide event). Nothing is ever described as a cause.
  * nothing here changes an incident's priority; relevant incidents only gain a timeline note and an evidence panel
  * every row is tenant-scoped; global events themselves are public and shared."""
import re
import statistics
import time

import httpx

from ..core import hub, now_ms
from ..db import db, jd, jl
from . import core

NET_METRICS = {"latency_ms": 1.0, "packet_loss_pct": 1.0, "collector_offline": 1.0, "bandwidth_mbps": 0.6}
SEV_PTS = {"critical": 20, "warning": 12, "info": 5}
GLOBAL_PTS = {"critical": 15, "high": 15, "medium": 10, "low": 5, "unrated": 3}
CLOUD_PROVIDERS = {"aws", "azure", "cloudflare", "gcp", "github"}
NVD_CPE = {("python", "python"), ("google", "chrome"), ("microsoft", "edge_chromium"), ("mozilla", "firefox")}
OSV_ECO = {"pypi": "PyPI"}


def band(score):
    return "high" if score >= 80 else "medium" if score >= 60 else "low"


# ------------------------------------------------------------------------------------------------ version logic (we never trust a feed's own matching)
def _ver(v):
    from packaging.version import InvalidVersion, Version
    try:
        return Version(str(v))
    except InvalidVersion:
        return None


def cpe_affects(version, c):
    """NVD cpeMatch entry (vendor/product already matched) vs installed version. -> (affected: bool|None, reason)."""
    v = _ver(version)
    if v is None:
        return None, "installed version is not comparable"
    cv = c.get("version")
    if cv and cv not in ("*", "-"):
        cvv = _ver(cv)
        ok = cvv is not None and cvv == v
        return ok, f"CPE lists exactly {cv}" if ok else f"CPE lists exactly {cv} (installed {version})"
    lo_i, lo_e, hi_i, hi_e = (_ver(c.get(k)) if c.get(k) else None for k in ("vsi", "vse", "vei", "vee"))
    if not any((c.get("vsi"), c.get("vse"), c.get("vei"), c.get("vee"))):
        return True, "CPE applies to all versions"
    if (c.get("vsi") and lo_i is None) or (c.get("vse") and lo_e is None) or (c.get("vei") and hi_i is None) or (c.get("vee") and hi_e is None):
        return None, "range bounds are not comparable"
    ok = (lo_i is None or v >= lo_i) and (lo_e is None or v > lo_e) and (hi_i is None or v <= hi_i) and (hi_e is None or v < hi_e)
    lo = c.get("vsi") and f">= {c['vsi']}" or c.get("vse") and f"> {c['vse']}" or ""
    hi = c.get("vei") and f"<= {c['vei']}" or c.get("vee") and f"< {c['vee']}" or ""
    return ok, f"affected range {' and '.join(x for x in (lo, hi) if x)}"


def osv_affects(version, aff):
    """OSV 'affected' entry vs installed version using its events (introduced / fixed / last_affected) or explicit version list."""
    v = _ver(version)
    if v is None:
        return None, "installed version is not comparable"
    if str(version) in (aff.get("versions") or []):
        return True, f"version {version} is listed as affected"
    for r in aff.get("ranges", []):
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        start = None
        spans = []
        for e in r.get("events", []):
            if "introduced" in e:
                start = e["introduced"]
            elif "fixed" in e and start is not None:
                spans.append((start, "<", e["fixed"]))
                start = None
            elif "last_affected" in e and start is not None:
                spans.append((start, "<=", e["last_affected"]))
                start = None
        if start is not None:
            spans.append((start, None, None))
        for lo, op, hi in spans:
            lov = _ver(lo) if lo != "0" else _ver("0")
            hiv = _ver(hi) if hi else None
            if lov is None or (hi and hiv is None):
                continue
            if v >= lov and (hiv is None or (v < hiv if op == "<" else v <= hiv)):
                return True, f"installed {version} is inside the advisory range {lo} {'to ' + op + ' ' + hi if hi else 'and later (no fix listed)'}"
    return False, "installed version is outside the affected ranges"


def _norm(s):
    return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())


# ------------------------------------------------------------------------------------------------ store
def _store(tenant, kind, event_id, cid, ltype, lref, status, score, factors, evidence, incident_id=None):
    """Insert/update one correlation; returns (id, changed) where changed = new row or status/score-band change."""
    ms = now_ms()
    old = db.one("SELECT id, status, score FROM intel_correlations WHERE tenant_id=? AND event_id=? AND collector_id=? AND local_type=? AND local_ref=?",
                 (tenant, event_id, cid, ltype, str(lref)))
    if old:
        changed = old["status"] != status or band(old["score"]) != band(score)
        db.exec("UPDATE intel_correlations SET status=?, score=?, confidence=?, factors=?, evidence=?, updated_ms=?, incident_id=COALESCE(?,incident_id) WHERE id=?",
                (status, score, band(score), jd(factors), jd(evidence), ms, incident_id, old["id"]))
        return old["id"], changed
    cur = db.exec("INSERT INTO intel_correlations(tenant_id,kind,event_id,collector_id,local_type,local_ref,status,score,confidence,factors,evidence,created_ms,updated_ms,incident_id)"
                  " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (tenant, kind, event_id, cid, ltype, str(lref), status, score, band(score), jd(factors), jd(evidence), ms, ms, incident_id))
    return cur.lastrowid, True


def _timeline(tenant, incident_id, text):
    """A timeline note only: the incident's priority, category and scoring are never touched."""
    ms = now_ms()
    db.exec("INSERT INTO incident_events(tenant_id,incident_id,ts_ms,event_ms,kind,detail) VALUES(?,?,?,?,?,?)", (tenant, incident_id, ms, ms, "external_correlation", text[:400]))
    hub.broadcast(tenant, {"type": "incident", "id": incident_id})


def _factor(name, points, maxp, detail, matched=True):
    return {"factor": name, "points": points, "max": maxp, "detail": detail, "matched": matched}


def _devices(tenant):
    rows = db.all("SELECT d.collector_id cid, d.asn, d.country, d.software, c.name FROM device_context d JOIN collectors c ON c.id=d.collector_id AND c.tenant_id=d.tenant_id "
                  "WHERE d.tenant_id=?", (tenant,))
    for r in rows:
        r["software"] = jl(r["software"], [])
    return rows


def _gev(r):
    return {"id": r["id"], "source": r["source"], "title": r["title"], "severity": r["severity"], "status": r["status"], "event_ms": r["event_ms"], "updated_ms": r["updated_ms"],
            "source_url": r["source_url"], "category": r["category"], "kind": r["kind"]}


# ------------------------------------------------------------------------------------------------ 1. network: routing / outage / measurement <-> local network anomalies
def correlate_network(tenant, now):
    out = []
    devs = [d for d in _devices(tenant) if d["asn"] or d["country"]]
    if not devs:
        return out
    gl = db.all("SELECT * FROM intel_events WHERE category IN ('routing','outage','measurement') AND (COALESCE(updated_ms,event_ms) > ? OR status IN ('ongoing','active')) AND "
                "(category!='measurement' OR status='degraded')", (now - 12 * 3600_000,))
    for d in devs:
        alerts = db.all("SELECT * FROM alerts WHERE tenant_id=? AND collector_id=? AND metric IN ('latency_ms','packet_loss_pct','bandwidth_mbps','collector_offline') "
                        "AND severity!='info' AND COALESCE(last_event_ms,event_ms) > ?", (tenant, d["cid"], now - 12 * 3600_000))
        for g in gl:
            data = jl(g["data"], {})
            asn_hit = bool(d["asn"]) and (str(d["asn"]) == str(g["asn"] or "") or str(d["asn"]) in [str(a) for a in data.get("asns", [])])
            cty_hit = bool(d["country"]) and d["country"] == (g["country"] or "")
            if not (asn_hit or cty_hit):
                continue
            g_start = g["event_ms"] or 0
            g_end = (now if (g["status"] in ("ongoing", "observed", "active", "degraded")) else (g["updated_ms"] or g_start))
            g_end = max(g_end, g["updated_ms"] or 0)
            for a in alerts:
                a_start, a_end = a["event_ms"], a["cleared_ms"] or a["last_event_ms"] or a["event_ms"]
                if a["cleared_ms"] is None:
                    a_end = max(a_end, now)
                gap = max(0, max(a_start - (g_end + 30 * 60_000), (g_start - 10 * 60_000) - a_end))      # minutes between the two windows
                gap_min = gap / 60_000
                if gap_min > 60:
                    continue
                tp = round(30 * (1 - gap_min / 60), 1)
                idp = 35 if asn_hit else 20
                rel = NET_METRICS.get(a["metric"], 0.5)
                lp = round(SEV_PTS.get(a["severity"], 5) * rel, 1)
                gp = GLOBAL_PTS.get(g["severity"], 3)
                score = round(tp + idp + lp + gp, 1)
                factors = [
                    _factor("shared network identifier", idp, 35, f"device network AS{d['asn']} = global event AS{g['asn'] or data.get('asns')}" if asn_hit else
                            f"device country {d['country']} = event country {g['country']} (country-level only: weaker than an ASN match)"),
                    _factor("time overlap", tp, 30, "the local anomaly overlaps the global event window" if gap_min == 0 else f"windows are {gap_min:.0f} min apart"),
                    _factor("local anomaly", lp, 20, f"{a['severity']} {a['metric']} anomaly on the device"),
                    _factor("global event strength", gp, 15, f"{g['source']} severity '{g['severity']}', status '{g['status']}'")]
                status = "confirmed" if (asn_hit and tp >= 20 and score >= 80) else "possible" if score >= 45 else None
                if not status:
                    continue
                ev = {"global": _gev(g), "local": {"alert_id": a["id"], "metric": a["metric"], "severity": a["severity"], "start_ms": a_start, "end_ms": a_end,
                                                     "title": a["title"]}, "device": {"collector_id": d["cid"], "name": d["name"], "asn": d["asn"], "country": d["country"]},
                      "claim": "shared identifiers and overlapping time; this is not a statement of cause"}
                out.append(("network", g["id"], d["cid"], "alert", a["id"], status, score, factors, ev, a["incident_id"]))
    return out


# ------------------------------------------------------------------------------------------------ 2. cloud: provider incident <-> real reachability probes
def _probe_stats(tenant, cid, label, t0, t1):
    slug_like = f"probe:{label}:%"
    rows = db.all("SELECT metric, value, event_ms FROM events WHERE tenant_id=? AND collector_id=? AND source_id LIKE ? AND metric IN ('probe_ok','probe_rtt_ms') AND event_ms BETWEEN ? AND ?",
                  (tenant, cid, slug_like, t0, t1))
    ok = [r["value"] for r in rows if r["metric"] == "probe_ok"]
    rtt = [r["value"] for r in rows if r["metric"] == "probe_rtt_ms"]
    return {"n": len(ok), "fail": sum(1 for v in ok if v < 0.5), "rtt_median": statistics.median(rtt) if rtt else None}


def correlate_cloud(tenant, now):
    out = []
    devs = _devices(tenant)
    if not devs:
        return out
    # an incident that is still ACTIVE counts however long ago the provider last updated it (some outages last weeks)
    evs = db.all("SELECT * FROM intel_events WHERE category='cloud' AND (status NOT IN ('resolved','postmortem') OR COALESCE(updated_ms,event_ms) > ?)", (now - 6 * 3600_000,))
    for d in devs:
        labels = {r["l"] for r in db.all("SELECT DISTINCT substr(source_id, 7, instr(substr(source_id, 7), ':') - 1) l FROM events WHERE tenant_id=? AND collector_id=? AND source_id LIKE 'probe:%' "
                                         "AND event_ms > ?", (tenant, d["cid"], now - 6 * 3600_000))}
        if not labels:
            continue
        for g in evs:
            prov = g["provider"]
            if prov not in CLOUD_PROVIDERS:
                continue
            mine = {l for l in labels if l.split("-")[0] == prov}
            if not mine:
                continue
            region = g["region"] if prov == "aws" else None
            if prov == "aws":
                target = {l for l in mine if region and l == f"aws-{region}"}
                if not target:
                    continue                       # AWS region not probed from this device: no evidence either way
                region_pts, region_txt = 25, f"incident region {region} = probed endpoint ec2.{region}.amazonaws.com"
            else:
                target, region_pts, region_txt = mine, 10, f"{prov} incident is provider-wide/unspecified; device probes {', '.join(sorted(mine))}"
            active = g["status"] not in ("resolved", "postmortem")
            w0 = max((g["event_ms"] or 0) - 10 * 60_000, now - 6 * 3600_000)
            w1 = (now if active else (g["updated_ms"] or now)) + 15 * 60_000
            s = {"n": 0, "fail": 0, "rtts": []}
            for l in target:
                st = _probe_stats(tenant, d["cid"], l, w0, w1)
                s["n"] += st["n"]
                s["fail"] += st["fail"]
                if st["rtt_median"]:
                    s["rtts"].append(st["rtt_median"])
            if s["n"] < 3:
                continue
            ratio = s["fail"] / s["n"]
            base_rows = db.all("SELECT value FROM events WHERE tenant_id=? AND collector_id=? AND source_id LIKE ? AND metric='probe_rtt_ms' AND event_ms < ? AND event_ms > ?",
                               (tenant, d["cid"], f"probe:{sorted(target)[0]}:%", w0, w0 - 24 * 3600_000))
            base = statistics.median([r["value"] for r in base_rows]) if len(base_rows) >= 5 else None
            cur = statistics.median(s["rtts"]) if s["rtts"] else None
            lat_up = bool(base and cur and cur >= 3 * base and cur - base >= 150)
            fp = 35 if (ratio >= 0.5) else 20 if ratio >= 0.2 else (20 if lat_up else 0)
            if fp == 0:
                continue                           # the provider has an incident, but this device sees no problem reaching it: unrelated
            ctrl = [l for l in mine if l not in target]
            ctrl_stats = [_probe_stats(tenant, d["cid"], l, w0, w1) for l in ctrl]
            ctrl_fail = sum(c["fail"] for c in ctrl_stats)
            ctrl_n = sum(c["n"] for c in ctrl_stats)
            tp = 10 if s["n"] >= 5 else 5
            gp = {"critical": 10, "high": 10, "medium": 6}.get(g["severity"], 3)
            score = round(20 + region_pts + fp + tp + gp, 1)
            factors = [_factor("provider reachable-by-probe", 20, 20, f"device runs real handshake probes to {prov}"),
                       _factor("region/service match", region_pts, 25, region_txt),
                       _factor("device-observed failures" if ratio >= 0.2 else "device-observed latency increase", fp, 35,
                               f"{s['fail']}/{s['n']} probe handshakes failed ({ratio:.0%}) in the incident window" if ratio >= 0.2 else f"median handshake {cur:.0f} ms vs {base:.0f} ms baseline"),
                       _factor("sample size", tp, 10, f"{s['n']} probe samples in the window"),
                       _factor("provider incident strength", gp, 10, f"{prov} severity '{g['severity']}', status '{g['status']}'")]
            status = "confirmed" if (region_pts == 25 and ratio >= 0.5 and score >= 80) else "possible" if score >= 45 else None
            if not status:
                continue
            alert = db.one("SELECT id, incident_id FROM alerts WHERE tenant_id=? AND collector_id=? AND incident_id IS NOT NULL AND metric IN ('latency_ms','packet_loss_pct','collector_offline') "
                           "AND event_ms BETWEEN ? AND ? ORDER BY event_ms DESC LIMIT 1", (tenant, d["cid"], w0, w1))
            ev = {"global": _gev(g), "local": {"probe_labels": sorted(target), "samples": s["n"], "failures": s["fail"], "failure_ratio": round(ratio, 2),
                                                "median_rtt_ms": cur, "baseline_rtt_ms": base, "window_ms": [w0, w1]},
                  "controls": {"other_probed_endpoints_of_same_provider": sorted(ctrl), "their_failures": ctrl_fail, "their_samples": ctrl_n,
                               "note": "healthy controls make a device-side network problem less likely" if ctrl_n and ctrl_fail == 0 else None},
                  "device": {"collector_id": d["cid"], "name": d["name"]}, "claim": "device-observed failures coincide with the provider's reported incident; this is not a statement of cause"}
            out.append(("cloud", g["id"], d["cid"], "probe", ",".join(sorted(target)), status, score, factors, ev, alert["incident_id"] if alert else None))
    return out


# ------------------------------------------------------------------------------------------------ 3. vulnerabilities <-> installed software
def enrich_inventory(tenant, max_nvd=3):
    """Device-driven lookups with REAL data: OSV advisories for installed PyPI packages, NVD CVEs for runtime/browser CPEs (cached 24 h)."""
    from . import vuln
    seen_pypi, nvd_budget = {}, max_nvd
    for d in _devices(tenant):
        for e in d["software"]:
            if e["eco"] == "pypi":
                seen_pypi[(e["product"], e["version"])] = True
    todo = [k for k in seen_pypi if not db.one("SELECT 1 FROM intel_cache WHERE key=? AND ?-fetched_ms<86400000", (f"osv:q:{k[0]}@{k[1]}", now_ms()))]
    if todo:
        try:
            with httpx.Client(timeout=40, trust_env=False) as c:
                r = c.post("https://api.osv.dev/v1/querybatch", json={"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in todo]}).json()
                evs = []
                for (n, v), res in zip(todo, r.get("results", [])):
                    ids = [x["id"] for x in res.get("vulns", [])][:15]
                    for vid in ids:
                        try:
                            evs.append(vuln.osv_event(c.get(vuln.OSV_DOC.format(id=vid)).json(), "PyPI"))
                        except Exception:
                            pass
                    db.exec("INSERT OR REPLACE INTO intel_cache(key,value,fetched_ms) VALUES(?,?,?)", (f"osv:q:{n}@{v}", jd(ids), now_ms()))
                if evs:
                    core.upsert(evs)
        except Exception:
            pass
    cpes = {}
    for d in _devices(tenant):
        for e in d["software"]:
            if (e["vendor"], e["product"]) in NVD_CPE and e["eco"] in ("runtime", "app"):
                cpes[(e["vendor"], e["product"], e["version"])] = True
    for (ven, prod, ver) in cpes:
        if nvd_budget <= 0:
            break
        key = f"nvd:cpe:{ven}:{prod}@{ver}"
        if db.one("SELECT 1 FROM intel_cache WHERE key=? AND ?-fetched_ms<86400000", (key, now_ms())):
            continue
        nvd_budget -= 1
        try:
            with httpx.Client(timeout=60, trust_env=False, headers={"User-Agent": "SentinelX/1.0"}) as c:
                r = c.get(vuln.NVD_URL, params={"cpeName": f"cpe:2.3:a:{ven}:{prod}:{ver}:*:*:*:*:*:*:*", "resultsPerPage": 200})
                if r.status_code == 200:
                    core.upsert([vuln.nvd_event(v["cve"]) for v in r.json().get("vulnerabilities", [])])
                    db.exec("INSERT OR REPLACE INTO intel_cache(key,value,fetched_ms) VALUES(?,?,?)", (key, "ok", now_ms()))
            time.sleep(6.5)
        except Exception:
            pass


def _vuln_candidates(sw):
    """Yield (event row, verdict, reason, verified) for one installed software entry."""
    v_ = sw["version"]
    vend, prod = sw["vendor"], sw["product"]
    out = []
    if sw["eco"] == "pypi":
        want = re.sub(r"[-_.]+", "-", prod.lower())
        for g in db.all("SELECT * FROM intel_events WHERE source='osv' AND (product LIKE ?)", (f"%{prod}%",)):
            d = jl(g["data"], {})
            for a in d.get("affected", []):
                if a.get("ecosystem") == "PyPI" and re.sub(r"[-_.]+", "-", a["name"].lower()) == want:
                    ok, why = osv_affects(v_, a)
                    if ok:
                        out.append((g, "affected", why, True))
                    break
    for g in db.all("SELECT * FROM intel_events WHERE source='nvd' AND (vendor LIKE ? OR product LIKE ?)", (f"%{vend}%", f"%{prod}%")):
        d = jl(g["data"], {})
        hit, why, any_prod = False, "", False
        for c in d.get("cpe", []):
            if c["vendor"] == vend and c["product"] == prod:
                any_prod = True
                ok, w = cpe_affects(v_, c)
                if ok:
                    hit, why = True, w
                    break
        if hit:
            out.append((g, "affected", f"NVD configuration: {why}", True))
    if sw["eco"] in ("os", "app"):                           # KEV carries vendor/product only, so this is a family match unless NVD data verifies the version
        for g in db.all("SELECT * FROM intel_events WHERE source='cisa_kev'"):
            kv, kp = _norm(g["vendor"]), _norm(g["product"])
            fam = prod.replace("_", "").replace("edge_chromium", "edge")
            alias = {"chrome": ("chrome", "chromium"), "edgechromium": ("edge", "chromium")}.get(prod.replace("_", ""), (prod.replace("_", ""),))
            if kv.startswith(_norm(vend)) or _norm(vend).startswith(kv):
                if any(a in kp for a in alias) or (sw["eco"] == "os" and "windows" in kp and "windows" in prod):
                    nvd = db.one("SELECT data FROM intel_events WHERE id=?", ("nvd:" + (g["cve"] or ""),))
                    cp = [c for c in jl(nvd["data"], {}).get("cpe", []) if c["vendor"] == vend and c["product"] == prod] if nvd else []
                    if cp:
                        res = [cpe_affects(v_, c) for c in cp]
                        if any(r[0] for r in res):
                            out.append((g, "affected", "NVD configuration confirms the installed version: " + next(r[1] for r in res if r[0]), True))
                        continue                         # NVD data says the installed version is outside the ranges: not exposed
                    out.append((g, "family", f"CISA KEV lists {g['vendor']} {g['product']}; KEV has no version data, so the installed version cannot be verified", False))
    return out


def correlate_vulns(tenant, now):
    out = []
    for d in _devices(tenant):
        for sw in d["software"]:
            cands = _vuln_candidates(sw)
            cands.sort(key=lambda x: (not x[3], -(x[0]["exploited"] or 0), -(x[0]["score"] or 0)))
            kept_family = kept_verified = 0
            n_verified = sum(1 for c in cands if c[3])
            for g, verdict, why, verified in cands:
                if not verified:
                    kept_family += 1
                    if kept_family > 8:
                        continue
                else:
                    kept_verified += 1
                    if kept_verified > 25:                 # the strongest 25 are listed; the total is recorded, not hidden
                        continue
                sev = g["severity"]
                idp = 40
                vp = 40 if verified else 15
                xp = 10 if g["exploited"] else 0
                sp = {"critical": 10, "high": 8, "medium": 5}.get(sev, 2)
                score = idp + vp + xp + sp
                factors = [_factor("vendor/product match", idp, 40, f"installed {sw['vendor']}/{sw['product']} = advisory {g['vendor'] or ''} {g['product'] or ''}"[:160]),
                           _factor("version evidence", vp, 40, why, verified),
                           _factor("known exploitation", xp, 10, "listed in CISA KEV as exploited in the wild" if xp else "no known exploitation recorded", bool(xp)),
                           _factor("severity", sp, 10, f"{sev}" + (f" (CVSS {g['score']})" if g["score"] is not None else ""))]
                status = "confirmed" if verified else "possible"
                ev = {"global": _gev(g) | {"cve": g["cve"]}, "software": sw, "device": {"collector_id": d["cid"], "name": d["name"]},
                      "claim": "installed version is inside the advisory's affected range" if verified else "product family matches; installed version not verifiable from this source",
                      "note": "potential exposure only: this does not show the vulnerable code path is reachable or exploited",
                      "matches_for_this_software": n_verified if verified else None}
                out.append(("vuln", g["id"], d["cid"], "software", f"{sw['eco']}:{sw['vendor']}/{sw['product']}@{sw['version']}", status, float(score), factors, ev, None))
    return out


# ------------------------------------------------------------------------------------------------ run
def run(tenant, enrich=True):
    now = now_ms()
    if enrich:
        enrich_inventory(tenant)
    found = correlate_network(tenant, now) + correlate_cloud(tenant, now) + correlate_vulns(tenant, now)
    new = changed = 0
    keep = set()
    for kind, eid, cid, lt, lr, status, score, factors, ev, inc in found:
        cid_, ch = _store(tenant, kind, eid, cid, lt, lr, status, score, factors, ev, inc)
        keep.add(cid_)
        if ch and inc:
            g = ev["global"]
            _timeline(tenant, inc, f"External intelligence {'matched' if status == 'confirmed' else 'possibly related'}: {g['title']} [{g['source']}] "
                                   f"(correlation score {score:.0f}, {band(score)} confidence; device {ev['device']['name']}). Not a statement of cause; incident priority unchanged.")
        new += 1 if ch else 0
    # vulnerability rows are re-derived every run (a patched version must stop matching); network/cloud rows keep 48 h of history
    ids = ",".join(str(i) for i in keep) or "NULL"
    gone = db.exec(f"DELETE FROM intel_correlations WHERE tenant_id=? AND kind='vuln' AND id NOT IN ({ids})", (tenant,)).rowcount
    db.exec("DELETE FROM intel_correlations WHERE tenant_id=? AND kind IN ('network','cloud') AND updated_ms < ?", (tenant, now - 48 * 3600_000))
    return {"correlations": len(found), "new_or_changed": new, "stored": len(keep), "removed_vuln_rows": gone}


def run_all():
    out = {}
    for t in db.all("SELECT id FROM tenants"):
        out[t["id"]] = run(t["id"])
    return out


def incident_external(tenant, incident_id):
    """Correlations attached to one tenant incident, for the incident detail page (tenant-scoped)."""
    rows = db.all("SELECT * FROM intel_correlations WHERE tenant_id=? AND incident_id=? ORDER BY score DESC", (tenant, incident_id))
    return [out_row(r) for r in rows]


def out_row(r):
    ev = jl(r["evidence"], {})
    return {"id": r["id"], "kind": r["kind"], "status": r["status"], "score": r["score"], "confidence": r["confidence"], "factors": jl(r["factors"], []),
            "global_event": ev.get("global"), "local": ev.get("local") or ev.get("software"), "device": ev.get("device"), "controls": ev.get("controls"),
            "claim": ev.get("claim"), "note": ev.get("note"), "incident_id": r["incident_id"], "created_ms": r["created_ms"], "updated_ms": r["updated_ms"],
            "causation_claimed": False}
