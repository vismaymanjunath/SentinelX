"""Dashboard API for global intelligence. Read-only, public-feed data (not tenant data), login required. Served only on the dashboard
listener (127.0.0.1): never on the collector/ngrok ingest listener. The frontend never contacts an external source itself."""
from fastapi import APIRouter, Depends, HTTPException

from ..core import now_ms
from ..db import db, jl
from . import core, correlate
from . import ai as intel_ai
from .. import ai as base_ai


def _event_out(r, fresh, full=False):
    d = {k: r[k] for k in ("id", "source", "category", "kind", "severity", "title", "status", "event_ms", "updated_ms", "first_seen_ms", "last_seen_ms",
                           "source_url", "country", "region", "provider", "asn", "prefix", "vendor", "product", "cve", "score", "exploited", "version")}
    d["summary"] = r["summary"] if full else (r["summary"] or "")[:420]
    d["source_freshness"] = fresh.get(r["source"], {}).get("freshness")
    d["source_last_updated_ms"] = fresh.get(r["source"], {}).get("last_success_ms")
    d["source_name"] = fresh.get(r["source"], {}).get("name")
    if full:
        d["data"] = jl(r["data"], {})
    return d


def make_router(user_dep):
    r = APIRouter(prefix="/api/intel")

    @r.get("/sources")
    def sources(s=Depends(user_dep)):
        return core.source_view()

    def _relevance(tenant):
        """event id -> 'correlated' (tied to one of this tenant's incidents) | 'relevant' (matched to this tenant's devices). Everything else is worldwide."""
        rel = {}
        for x in db.all("SELECT event_id, MAX(incident_id IS NOT NULL) inc, MAX(status='confirmed') conf FROM intel_correlations WHERE tenant_id=? GROUP BY event_id", (tenant,)):
            rel[x["event_id"]] = ("correlated" if x["inc"] else "relevant", "confirmed" if x["conf"] else "possible")
        return rel

    @r.get("/events")
    def events(category: str = "", source: str = "", severity: str = "", country: str = "", kind: str = "", status: str = "", q: str = "",
               since_h: float = 0, exploited: int = 0, asn: str = "", provider: str = "", relevance: str = "", limit: int = 100, offset: int = 0,
               order: str = "event", s=Depends(user_dep)):
        rel = _relevance(s["tenant_id"])
        where, p = ["1=1"], []
        if relevance in ("relevant", "correlated"):
            ids = [k for k, v in rel.items() if v[0] == "correlated" or (relevance == "relevant")]
            where.append(f"id IN ({','.join('?' * len(ids)) or 'NULL'})")
            p += ids
        elif relevance == "worldwide":
            ids = list(rel)
            if ids:
                where.append(f"id NOT IN ({','.join('?' * len(ids))})")
                p += ids
        for col, val in (("category", category), ("source", source), ("severity", severity), ("country", country.upper()), ("kind", kind), ("status", status),
                         ("asn", asn), ("provider", provider)):
            if val:
                where.append(f"{col}=?")
                p.append(val)
        if exploited:
            where.append("exploited=1")
        if since_h > 0:
            where.append("COALESCE(event_ms,0) >= ?")
            p.append(now_ms() - since_h * 3600_000)
        if q:
            where.append("(title LIKE ? OR summary LIKE ? OR cve LIKE ? OR vendor LIKE ? OR product LIKE ?)")
            p += [f"%{q}%"] * 5
        col = "COALESCE(updated_ms, event_ms)" if order == "updated" else "event_ms"
        rows = db.all(f"SELECT * FROM intel_events WHERE {' AND '.join(where)} ORDER BY {col} DESC LIMIT ? OFFSET ?", (*p, min(limit, 500), max(offset, 0)))
        total = db.one(f"SELECT COUNT(*) n FROM intel_events WHERE {' AND '.join(where)}", p)["n"]
        fresh = {x["source"]: x for x in core.source_view()}
        outl = []
        for x in rows:
            e = _event_out(x, fresh)
            e["relevance"], e["correlation_status"] = rel.get(x["id"], ("worldwide", None))
            outl.append(e)
        return {"total": total, "events": outl}

    @r.get("/events/{eid:path}")
    def event(eid: str, s=Depends(user_dep)):
        row = db.one("SELECT * FROM intel_events WHERE id=?", (eid,))
        if not row:
            raise HTTPException(404, "event not found")
        fresh = {x["source"]: x for x in core.source_view()}
        out = _event_out(row, fresh, full=True)
        out["history"] = db.all("SELECT version, ts_ms, status, severity, summary, updated_ms FROM intel_history WHERE event_id=? ORDER BY version", (eid,))
        return out

    @r.get("/overview")
    def overview(hours: float = 24, s=Depends(user_dep)):
        since = now_ms() - hours * 3600_000
        by_cat = {x["category"]: x["n"] for x in db.all("SELECT category, COUNT(*) n FROM intel_events WHERE COALESCE(event_ms,0)>=? GROUP BY category", (since,))}
        by_sev = {x["severity"]: x["n"] for x in db.all("SELECT severity, COUNT(*) n FROM intel_events WHERE COALESCE(event_ms,0)>=? GROUP BY severity", (since,))}
        by_src = {x["source"]: x["n"] for x in db.all("SELECT source, COUNT(*) n FROM intel_events WHERE COALESCE(event_ms,0)>=? GROUP BY source", (since,))}
        totals = {x["category"]: x["n"] for x in db.all("SELECT category, COUNT(*) n FROM intel_events GROUP BY category")}
        rel = _relevance(s["tenant_id"])
        ids = [x["id"] for x in db.all("SELECT id FROM intel_events WHERE COALESCE(event_ms,0)>=?", (since,))]
        split = {"worldwide": 0, "relevant": 0, "correlated": 0}
        for i in ids:
            split[rel.get(i, ("worldwide",))[0]] += 1
        corr = {f"{x['kind']}/{x['status']}": x["n"] for x in db.all("SELECT kind, status, COUNT(*) n FROM intel_correlations WHERE tenant_id=? GROUP BY kind, status", (s["tenant_id"],))}
        return {"hours": hours, "relevance": split, "correlations": corr, "in_window": {"by_category": by_cat, "by_severity": by_sev, "by_source": by_src}, "stored_total": totals,
                "exploited_known": db.one("SELECT COUNT(*) n FROM intel_events WHERE exploited=1 AND source='cisa_kev'")["n"],
                "sources": core.source_view(), "now_ms": now_ms()}

    @r.get("/correlations")
    def correlations(kind: str = "", status: str = "", limit: int = 100, s=Depends(user_dep)):
        where, p = ["tenant_id=?"], [s["tenant_id"]]
        for col, val in (("kind", kind), ("status", status)):
            if val:
                where.append(f"{col}=?")
                p.append(val)
        rows = db.all(f"SELECT * FROM intel_correlations WHERE {' AND '.join(where)} ORDER BY (status='confirmed') DESC, score DESC, updated_ms DESC LIMIT ?", (*p, min(limit, 300)))
        return {"total": db.one(f"SELECT COUNT(*) n FROM intel_correlations WHERE {' AND '.join(where)}", p)["n"], "correlations": [correlate.out_row(x) for x in rows]}

    @r.get("/correlations/{cid}")
    def correlation(cid: int, s=Depends(user_dep)):
        row = db.one("SELECT * FROM intel_correlations WHERE id=? AND tenant_id=?", (cid, s["tenant_id"]))
        if not row:
            raise HTTPException(404, "correlation not found")
        return correlate.out_row(row)

    @r.get("/devices")
    def devices(s=Depends(user_dep)):
        """What each device has told the host for correlation: its network (ASN, country) and software inventory. Pseudonymous names."""
        return [{"collector_id": d["cid"], "name": d["name"], "asn": d["asn"], "country": d["country"], "software": d["software"]} for d in correlate._devices(s["tenant_id"])]

    @r.post("/correlate")
    def run_now(s=Depends(user_dep)):
        if s["role"] != "admin":
            raise HTTPException(403, "admin role required")
        return correlate.run(s["tenant_id"])

    @r.get("/ris/live")
    def ris_live(s=Depends(user_dep)):
        from . import ris
        return {"state": ris.STATE, "messages": list(ris.RING)[:40],
                "rollups": db.all("SELECT scope, minute_ms, announcements, withdrawals, prefixes, peers, path_changes FROM intel_bgp WHERE minute_ms > ? ORDER BY minute_ms DESC LIMIT 120",
                                  (now_ms() - 3600_000,))}

    def _ai(fn, *a):
        try:
            return fn(*a)
        except base_ai.AIError as e:
            raise HTTPException({"notfound": 404, "busy": 429}.get(e.status, 503), e.msg)

    @r.get("/correlations/{cid}/ai")
    def corr_ai_get(cid: int, s=Depends(user_dep)):
        if not db.one("SELECT 1 FROM intel_correlations WHERE id=? AND tenant_id=?", (cid, s["tenant_id"])):
            raise HTTPException(404, "correlation not found")
        return _ai(intel_ai.get, s["tenant_id"], f"corr:{cid}")

    @r.post("/correlations/{cid}/ai", status_code=202)
    def corr_ai_run(cid: int, s=Depends(user_dep)):
        if s["role"] != "admin":
            raise HTTPException(403, "admin role required to run AI analysis")
        return _ai(intel_ai.start, s["tenant_id"], f"corr:{cid}", s["username"])

    @r.get("/ai/overview")
    def ov_ai_get(s=Depends(user_dep)):
        return _ai(intel_ai.get, s["tenant_id"], "overview")

    @r.post("/ai/overview", status_code=202)
    def ov_ai_run(s=Depends(user_dep)):
        if s["role"] != "admin":
            raise HTTPException(403, "admin role required to run AI analysis")
        return _ai(intel_ai.start, s["tenant_id"], "overview", s["username"])

    return r
