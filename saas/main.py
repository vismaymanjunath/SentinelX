import asyncio
import hashlib
import json
import re
import statistics
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from common import anon as anon_lib
from common import policy as policy_lib
from common.schema import parse_iso, utc_iso
from .intel import core as intel_core, registry as _intel_registry  # noqa: F401  (registers every source)
from .intel.api import make_router as _intel_router
from . import ai, config, qa, rem_engine, health, ingest, monitor, remediation, scenarios, security, triage
from .config import LOWER_IS_WORSE, METRIC_META
from .core import (audit, dependents, entity_info, graph, hub, now_ms, set_setting, set_threshold, settings, thresholds)
from .db import db, jd, jl

_started = {"v": False}


@asynccontextmanager
async def lifespan(app):
    hub.loop = asyncio.get_running_loop()
    if not _started["v"]:
        _started["v"] = True
        monitor.start()
        intel_core.start()          # public-feed ingestion threads (separate from the collector ingest listener)
    yield


app = FastAPI(title="SENTINEL X — Central SaaS", lifespan=lifespan)


# ------------------------------------------------------------------ auth helpers
def user(request: Request):
    h = request.headers.get("authorization", "")
    token = h[7:] if h.lower().startswith("bearer ") else request.query_params.get("token")
    s = security.session_for(token)
    if not s:
        raise HTTPException(401, "authentication required")
    return s


app.include_router(_intel_router(user))


def collector_auth(request: Request):
    if request.url.scheme != "https":
        raise HTTPException(426, "TLS required: collectors must use the HTTPS ingest endpoint")
    h = request.headers.get("authorization", "")
    c = security.collector_for_key(h[7:] if h.lower().startswith("bearer ") else None)
    if not c:
        raise HTTPException(401, "invalid collector credentials")
    t = db.one("SELECT * FROM tenants WHERE id=?", (c["tenant_id"],))
    if t and t["region"] != c["region"]:
        raise HTTPException(403, f"data residency policy: collector region {c['region']} != tenant region {t['region']}")
    return c


_fail: dict = {}


@app.get("/api/whoami")
def whoami():
    return {"tier": "saas", "name": "SENTINEL X Central SaaS"}


@app.post("/api/login")
def login(body: dict):
    u = str(body.get("username", ""))
    f = _fail.get(u, (0, 0))
    if f[0] >= 5 and time.time() - f[1] < 30:
        raise HTTPException(429, "too many failed attempts; retry in 30s")
    s = security.login(u, str(body.get("password", "")))
    if not s:
        _fail[u] = (f[0] + 1, time.time())
        raise HTTPException(401, "invalid credentials")
    _fail.pop(u, None)
    t = db.one("SELECT * FROM tenants WHERE id=?", (s["tenant_id"],))
    audit(s["tenant_id"], u, "login", "")
    return {**s, "tenant_name": t["name"], "region": t["region"]}


@app.get("/api/me")
def me(s=Depends(user)):
    t = db.one("SELECT * FROM tenants WHERE id=?", (s["tenant_id"],))
    return {"username": s["username"], "role": s["role"], "tenant_id": s["tenant_id"], "tenant_name": t["name"], "region": t["region"]}


# ------------------------------------------------------------------ collector ingest (TLS + API key)
@app.post("/api/ingest/v1/payload")
async def ingest_payload(request: Request, c=Depends(collector_auth)):
    if config.REQUIRE_ANON and c.get("anon_enabled") is None:   # retryable: the collector must declare anonymisation first
        raise HTTPException(428, "host policy requires local anonymisation: send a heartbeat declaring it first")
    body = await request.body()
    sha = hashlib.sha256(body).hexdigest()
    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(400, "invalid JSON")
    try:
        res = await run_in_threadpool(ingest.process_payload, c, payload, sha, request.headers.get("x-attempt"), body.decode("utf-8", "replace"))
    except ingest.Rejected as r:
        return JSONResponse(status_code=422, content={"status": "rejected", "problems": r.problems, "sha256": sha})
    res["sha256"] = sha
    res["received_at"] = utc_iso()
    return res


def _via(request: Request):
    """How this request reached the host: the ingest-only tunnel listener (ngrok) or the host's own TLS endpoint."""
    port = (request.scope.get("server") or (None, None))[1]
    return "tunnel" if (config.PUBLIC_MODE or port == config.PUBLIC_PORT) else "direct_tls"


@app.post("/api/ingest/v1/heartbeat")
async def ingest_hb(request: Request, c=Depends(collector_auth)):
    try:
        hb = await request.json()
        return await run_in_threadpool(ingest.process_heartbeat, c, hb, _via(request))
    except ingest.Rejected as r:
        return JSONResponse(status_code=422, content={"status": "rejected", "problems": r.problems})


@app.post("/api/ingest/v1/command-result")
async def ingest_cmd(request: Request, c=Depends(collector_auth)):
    b = await request.json()
    ok = await run_in_threadpool(remediation.command_result, c["tenant_id"], c["id"], b.get("command_id"), bool(b.get("ok")),
                                 str(b.get("detail", ""))[:300], b.get("before_state"), b.get("after_state"))
    return {"status": "ok" if ok else "ignored"}


_enroll_log: list = []
_join_fail: list = []


@app.post("/api/ingest/v1/register")
async def ingest_register(request: Request):
    """Self-registration for remote laptops. TLS-only, and enabled only when SENTINEL_JOIN_CODE is set on the host.
    The join code is validated server-side (constant-time) and is never logged or stored. Creates/rotates a
    collector credential for a device name in the demo tenant; afterwards all traffic uses that Bearer key."""
    import hmac
    import re
    if request.url.scheme != "https":
        raise HTTPException(426, "TLS required")
    if not config.JOIN_CODE:
        raise HTTPException(403, "enrollment is disabled on this server")
    now = time.time()
    _enroll_log[:] = [t for t in _enroll_log if now - t < 60]
    _join_fail[:] = [t for t in _join_fail if now - t < 60]
    if len(_enroll_log) >= 20 or len(_join_fail) >= 8:
        raise HTTPException(429, "too many attempts; retry in a minute")
    _enroll_log.append(now)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "invalid body")
    code = body.get("join_code")
    if not isinstance(code, str) or not hmac.compare_digest(code.encode(), config.JOIN_CODE.encode()):
        _join_fail.append(now)
        raise HTTPException(403, "invalid join code")
    name = str(body.get("device_name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.\-]{0,31}", name):
        raise HTTPException(400, "device_name: 1-32 chars, letters/digits/space/._-")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "device"
    t = db.one("SELECT * FROM tenants WHERE id=?", (config.ENROLL_TENANT,))
    if not t:
        raise HTTPException(500, "enrollment tenant missing; run saas.seed")
    cid = "col-r-" + slug
    key = security.new_key()
    install_id = body.get("install_id")
    if install_id is not None and not (isinstance(install_id, str) and re.fullmatch(r"[A-Za-z0-9-]{8,64}", install_id)):
        raise HTTPException(400, "install_id: 8-64 letters/digits/-")
    existing = db.one("SELECT id, install_id FROM collectors WHERE id=?", (cid,))
    if existing:
        # Same device name: only the SAME installation may reconnect (rotates its key, keeps its fleet entry).
        # A different device (or a legacy laptop vs a phone) must pick another name instead of hijacking this one.
        if (existing["install_id"] or None) != (install_id or None):
            raise HTTPException(409, "device name already in use by another device; choose a different name")
        db.exec("UPDATE collectors SET key_hash=?, name=? WHERE id=?", (security.hash_key(key), name, cid))
    else:
        db.exec("INSERT INTO collectors(id,tenant_id,name,key_hash,region,registered_ms,install_id) VALUES(?,?,?,?,?,?,?)",
                (cid, t["id"], name, security.hash_key(key), t["region"], now_ms(), install_id))
    audit(t["id"], "enrollment", "collector.enrolled", f"{cid} name={name} from={request.client.host if request.client else '?'}")
    return {"collector_id": cid, "api_key": key, "region": t["region"], "slug": slug}


@app.get("/api/ingest/v1/ledger")
def ingest_ledger(c=Depends(collector_auth)):
    rows = db.all("SELECT payload_id FROM payloads WHERE collector_id=? AND tenant_id=?", (c["id"], c["tenant_id"]))
    dups = db.one("SELECT COUNT(*) n FROM rejected WHERE collector_id=? AND reason LIKE 'duplicate%'", (c["id"],))["n"]
    return {"payload_ids": [r["payload_id"] for r in rows], "duplicates_ignored": dups}


# ------------------------------------------------------------------ dashboard APIs (tenant-scoped)
def pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    k = (len(vals) - 1) * p / 100.0
    f, c = int(k), min(int(k) + 1, len(vals) - 1)
    return round(vals[f] + (vals[c] - vals[f]) * (k - f), 1)


@app.get("/api/overview")
def overview(s=Depends(user)):
    t = s["tenant_id"]
    h = health.compute(t)
    ms = now_ms()
    alerts_total = db.one("SELECT COUNT(*) n FROM alerts WHERE tenant_id=? AND created_ms>?", (t, ms - 3600_000))["n"]
    inc_total = db.one("SELECT COUNT(*) n FROM incidents WHERE tenant_id=? AND opened_ms>?", (t, ms - 3600_000))["n"]
    lat = [r["l"] for r in db.all("SELECT received_ms-event_ms l FROM events WHERE tenant_id=? AND type='metric' AND received_ms>? "
                                  "AND received_ms-event_ms<10000", (t, ms - 300_000))]
    rl = [r["latency_ms"] for r in db.all("SELECT latency_ms FROM perf_render WHERE tenant_id=? AND ts_ms>?", (t, ms - 300_000))]
    return {
        "health": {"state": h["state"], "reasons": h["reasons"]},
        "entities": list(h["entities"].values()),
        "collectors": h["collectors"],
        "kpis": {
            "collectors_online": sum(1 for c in h["collectors"] if c["status"] == "online"),
            "collectors_total": len(h["collectors"]),
            "open_incidents": db.one("SELECT COUNT(*) n FROM incidents WHERE tenant_id=? AND status='open'", (t,))["n"],
            "active_alerts": db.one("SELECT COUNT(*) n FROM alerts WHERE tenant_id=? AND cleared_ms IS NULL AND severity!='info'", (t,))["n"],
            "alerts_1h": alerts_total, "incidents_1h": inc_total,
            "ingest_p95_ms": pct(lat, 95), "render_p95_ms": pct(rl, 95),
            "events_per_min": db.one("SELECT COUNT(*) n FROM events WHERE tenant_id=? AND received_ms>?", (t, ms - 60_000))["n"],
            "rejected_payloads": db.one("SELECT COUNT(*) n FROM rejected WHERE tenant_id=? AND reason LIKE 'allow-list%'", (t,))["n"],
        },
        "server_time_ms": ms,
    }


@app.get("/api/series")
def series(source_id: str, metric: str, seconds: int = 300, s=Depends(user)):
    t = s["tenant_id"]
    since = now_ms() - seconds * 1000
    rows = db.all("SELECT event_ms, value, late FROM events WHERE tenant_id=? AND source_id=? AND metric=? AND type='metric' "
                  "AND event_ms>? ORDER BY event_ms", (t, source_id, metric, since))
    alerts = db.all("SELECT id, severity, event_ms, COALESCE(last_event_ms,event_ms) end_ms, cleared_ms, incident_id FROM alerts WHERE "
                    "tenant_id=? AND source_id=? AND metric=? AND COALESCE(last_event_ms,event_ms)>?", (t, source_id, metric, since - 60000))
    meta = METRIC_META.get(metric, dict(floor=1))
    normal = []
    pts, band = [], []
    for r in rows:
        inside = any(a["event_ms"] - 8000 <= r["event_ms"] <= a["end_ms"] for a in alerts)
        w = [x for x in normal[-40:]]
        if len(w) >= 10:
            med = statistics.median(w)
            sig = max(statistics.median([abs(x - med) for x in w]) * 1.4826, meta["floor"], 0.03 * abs(med))
            band.append([r["event_ms"], round(med - 4 * sig, 3), round(med + 4 * sig, 3)])
        else:
            band.append([r["event_ms"], None, None])
        if not inside:
            normal.append(r["value"])
        pts.append([r["event_ms"], r["value"], r["late"]])
    return {"points": pts, "band": band, "alerts": alerts, "threshold": thresholds(t).get(metric)}


@app.get("/api/collectors")
def collectors(s=Depends(user)):
    return health.compute(s["tenant_id"])["collectors"]


@app.get("/api/collectors/{cid}")
def collector_detail(cid: str, s=Depends(user)):
    """Device details: descriptor + the latest value of every metric this collector reports (tenant-scoped)."""
    t = s["tenant_id"]
    h = health.compute(t)
    c = next((x for x in h["collectors"] if x["id"] == cid), None)
    if not c:
        raise HTTPException(404, "collector not found")
    metrics = []
    for e in h["entities"].values():
        if e.get("collector_id") == cid:
            for m, v in e["metrics"].items():
                metrics.append({"source_id": e["id"], "entity": e["label"], "type": e["type"], "metric": m, **v})
    return {"collector": c, "metrics": sorted(metrics, key=lambda m: (m["source_id"], m["metric"]))}


@app.get("/api/alerts")
def alerts(limit: int = 100, s=Depends(user)):
    rows = db.all("SELECT * FROM alerts WHERE tenant_id=? ORDER BY created_ms DESC LIMIT ?", (s["tenant_id"], min(limit, 500)))
    for r in rows:
        r["kinds"], r["evidence"], r["detected_by"] = jl(r["kinds"], []), jl(r["evidence"], {}), jl(r["detected_by"], [])
    return rows


@app.get("/api/incidents")
def incidents(status: str | None = None, s=Depends(user)):
    q = "SELECT * FROM incidents WHERE tenant_id=?"
    p = [s["tenant_id"]]
    if status:
        q += " AND status=?"
        p.append(status)
    rows = db.all(q + " ORDER BY opened_ms DESC LIMIT 100", p)
    # one ordering rule for every screen (saas/triage.rank_key): open first, then P1..P4, then higher score, then newest
    rows.sort(key=lambda r: (r["status"] != "open", triage.rank_key(r["priority_level"], r["priority"])))
    for r in rows:
        r["entities"] = jl(r["entities"], [])
        a = jl(r["analysis"], {})
        r["affected"] = a.get("affected", [])
        r["root"] = a.get("root")
        tri = a.get("triage", {})
        r["priority_reasons"] = (tri.get("priority") or {}).get("reasons", [])
        r["devices"] = (tri.get("priority") or {}).get("devices", [])
        r["secondary_categories"] = tri.get("secondary_categories", [])
        r.pop("analysis", None)
    return rows


def _ai_call(fn, *a):
    try:
        return fn(*a)
    except ai.AIError as e:
        code = {"notfound": 404, "busy": 429, "nodata": 409}.get(e.status, 503)
        raise HTTPException(code, e.msg)


@app.get("/api/incidents/{iid}/ai")
def incident_ai_get(iid: int, s=Depends(user)):
    """Local-AI analysis state for an incident (any logged-in user of the tenant). Dashboard listener only."""
    return _ai_call(ai.get, s["tenant_id"], iid)


@app.post("/api/incidents/{iid}/ai", status_code=202)
def incident_ai_run(iid: int, s=Depends(user), ui_lang: str | None = Header(None, alias="X-UI-Lang")):
    if s["role"] != "admin":
        raise HTTPException(403, "admin role required to run AI analysis")
    return _ai_call(ai.start, s["tenant_id"], iid, s["username"], (ui_lang or "en")[:2])


# ------------------------------------------------------------------ Cloud: local anonymisation + transport security
PSEUDO_CID = re.compile(r"^col-r-device-\d{3,4}$")


def _anon_state(c):
    st = "enabled" if c["anon_enabled"] == 1 else "disabled" if c["anon_enabled"] == 0 else "not declared"
    legacy = st == "enabled" and c["id"].startswith("col-r-") and not PSEUDO_CID.match(c["id"])
    return st, legacy


@app.get("/api/cloud")
def cloud(s=Depends(user)):
    """Fleet-level view of local anonymisation, from what collectors DECLARE (counters only) and what the host's policy
    check observed. The host never holds raw identifiers or the pseudonym mapping."""
    t = s["tenant_id"]
    rows = db.all("SELECT id,name,platform,status,last_seen_ms,anon_enabled,anon_policy,anon_records,anon_removed,anon_pseudo "
                  "FROM collectors WHERE tenant_id=? ORDER BY name", (t,))
    fleet, tot = [], {"records": 0, "removed": 0, "pseudonymised": 0}
    for c in rows:
        st, legacy = _anon_state(c)
        tot["records"] += int(c["anon_records"] or 0)
        tot["removed"] += int(c["anon_removed"] or 0)
        tot["pseudonymised"] += int(c["anon_pseudo"] or 0)
        fleet.append({"id": c["id"], "name": c["name"], "platform": c["platform"], "status": c["status"], "anonymisation": st,
                      "identity_exposed_at_enrolment": legacy, "records": int(c["anon_records"] or 0),
                      "removed": int(c["anon_removed"] or 0), "pseudonymised": int(c["anon_pseudo"] or 0),
                      "policy": c["anon_policy"]})
    names = {c["id"]: c["name"] for c in rows}
    viol = [{**v, "collector": names.get(v["collector_id"], v["collector_id"])} for v in db.all(
        "SELECT collector_id, level, code, field, count, first_ms, last_ms FROM policy_violations WHERE tenant_id=? "
        "ORDER BY last_ms DESC LIMIT 30", (t,))]
    on = sum(1 for f in fleet if f["anonymisation"] == "enabled")
    return {"status": "Enabled" if fleet and on == len(fleet) else "Disabled" if not on else "Partial",
            "collectors_enabled": on, "collectors_total": len(fleet), "totals": tot, "fleet": fleet, "violations": viol,
            "policy": {"version": anon_lib.POLICY_VERSION, "mode": "strict (reject collectors without anonymisation)" if config.REQUIRE_ANON
                       else "flag (accept but flag collectors without anonymisation)",
                       "always_rejected": ["IP addresses", "MAC addresses", "e-mail addresses", "usernames", "user home paths",
                                           "identifying fields (hostname, username, laptop id, raw logs ...)"],
                       "flagged": ["device ids/labels that are not pseudonymous (collector declared anonymisation)",
                                   "collectors that do not declare anonymisation"]},
            "retained": ["CPU, RAM, disk and network metrics (values, units)", "event timestamps", "alert severity and category",
                         "error / alert descriptions (identifiers inside them removed)", "platform and OS version",
                         "collector health (buffer, link state)"],
            "removed": ["usernames and account names", "laptop / asset IDs", "hostnames and device names - replaced by a stable pseudonym such as Device-27",
                        "IP and MAC addresses (private and public)", "user home paths (C:\\Users\\<name>)", "raw log lines and samples"],
            "caveats": ["Pseudonymisation, not irreversible anonymisation: a device keeps the same pseudonym so it can be tracked over time.",
                        "The mapping from real names to pseudonyms exists only on each laptop; whoever has the laptop's local files can reverse it.",
                        "The source IP of the network connection is visible to ngrok and the host at the transport layer.",
                        "Collectors enrolled under their real name before this feature still have an identifying collector id at the host until they re-enrol."],
            "transport": _transport()}


def _transport():
    info = security.tls_info()
    if config.PUBLIC_MODE:      # honest description of the public deployment: TLS terminates at the platform edge, not at this process
        return {"collector_to_host": "HTTPS required: plain HTTP to the ingest API is refused (426). Collectors verify the platform's public certificate and host name.",
                "direct_local": {"description": "Not available in the public deployment (no private-CA endpoint is exposed).", "tls": info},
                "via_ngrok": {"collector_to_ngrok": "Encrypted: TLS with the hosting platform's public certificate, verified by the collector.",
                              "ngrok_to_host": "The platform's edge proxy terminates TLS and forwards plain HTTP to this service over the provider's private network.",
                              "end_to_end_tls": False,
                              "note": "TLS terminates at the hosting provider's edge, so the provider can see the (already anonymised) payload. This is NOT end-to-end TLS. "
                                      "Local anonymisation limits what the provider or anyone in the path can learn."},
                "dashboard": "Public over HTTPS (TLS ends at the provider edge); every dashboard API call requires a login token.",
                "ollama": "Not deployed on this host: AI features are unavailable here. Ollama is never exposed publicly.",
                "public_enrollment_enabled": bool(config.JOIN_CODE)}
    return {"collector_to_host": "HTTPS required: plain HTTP to the ingest API is refused (426). Collectors verify the server certificate and "
                                 "host name (TLS 1.2+) and never disable verification.",
            "direct_local": {"description": "Local collectors connect to the host's own TLS endpoint (private CA, pinned on the collector).",
                             "tls": info},
            "via_ngrok": {"collector_to_ngrok": "Encrypted: TLS with ngrok's public certificate, verified by the collector.",
                          "ngrok_to_host": "Carried over ngrok's own encrypted tunnel to the ngrok agent on the host; the agent then forwards PLAINTEXT HTTP "
                                           "to 127.0.0.1:8090 on the same machine.",
                          "end_to_end_tls": False,
                          "note": "ngrok terminates TLS at its edge, so ngrok can see the (already anonymised) payload. This is NOT end-to-end TLS. "
                                  "Local anonymisation limits what ngrok or anyone in the path can learn."},
            "dashboard": "Bound to 127.0.0.1 only; never tunnelled.", "ollama": "127.0.0.1 only; never tunnelled; not reachable by collectors.",
            "public_enrollment_enabled": bool(config.JOIN_CODE)}


@app.get("/api/cloud/preview")
def cloud_preview(username: str = "", laptop_id: str = "", ip: str = "", cpu: float = 95.0, error: str = "", device_name: str = "",
                  s=Depends(user)):
    """BEFORE/AFTER with sample data, produced by the SAME anonymiser the collectors run. Stateless: nothing is stored."""
    sample = {k: v for k, v in {"username": username[:32], "laptop_id": laptop_id[:32], "ip": ip[:45], "error": error[:80],
                                "device_name": device_name[:32]}.items() if v}
    sample["cpu"] = max(0.0, min(100.0, cpu))
    return anon_lib.preview(sample)


@app.get("/api/cloud/last-payload")
def cloud_last_payload(collector_id: str = "", s=Depends(user)):
    """The last payload this host actually RECEIVED, reconstructed from stored events: what really left the laptop."""
    t = s["tenant_id"]
    q = "SELECT payload_id, collector_id, seq, sent_at, received_ms FROM payloads WHERE tenant_id=?"
    p = [t]
    if collector_id:
        q += " AND collector_id=?"
        p.append(collector_id)
    last = db.one(q + " ORDER BY received_ms DESC LIMIT 1", p)
    if not last:
        return {"payload": None}
    evs = db.all("SELECT event_id,type,source_id,category,severity,metric,value,unit,event_time,source_tz,context FROM events "
                 "WHERE tenant_id=? AND payload_id=? ORDER BY event_ms", (t, last["payload_id"]))
    for e in evs:
        e["context"] = jl(e["context"], {})
        for k in [k for k, v in e.items() if v is None]:
            e.pop(k)
    findings = [f for e in evs for f in policy_lib.check_event(e)]
    return {"payload": {"payload_id": last["payload_id"], "collector_id": last["collector_id"], "seq": last["seq"],
                        "sent_at": last["sent_at"], "schema_version": "1.0", "events": evs},
            "policy_findings": [f"{f['code']}@{f['field']}" for f in findings]}


@app.get("/api/tls/status")
def tls_status(s=Depends(user)):
    return {**security.tls_info(), "transport": _transport()}


@app.get("/api/tls/ca")
def tls_ca(s=Depends(user)):
    """Public CA certificate + fingerprint, for enrolling collectors that connect directly (not via ngrok). Admin only;
    the fingerprint must be given to the collector's owner through a separate channel and checked there."""
    if s["role"] != "admin":
        raise HTTPException(403, "admin role required")
    info = security.tls_info()
    return {"fingerprint_sha256": info["ca_fingerprint_sha256"], "pem": (config.CERT_DIR / "ca.pem").read_text()}


# ------------------------------------------------------------------ Privacy & Security (central view)
# Everything below is built ONLY from data the host already holds: heartbeat counters/labels/hashes, accepted (already anonymised)
# payloads, policy-violation codes. Nothing is fetched from a collector, and raw originals / the pseudonym mapping never exist here.
PSEUDONYM_NAME = re.compile(r"^Device-\d{3,4}$")


def _priv_collector(t, cid):
    c = db.one("SELECT * FROM collectors WHERE id=? AND tenant_id=?", (cid, t))
    if not c:
        raise HTTPException(404, "device not found")
    return c


def _tls_summary(c, pr):
    tls = (pr or {}).get("tls")
    via = c.get("transport")
    return {"reported_by_collector": bool(tls), "verified": tls.get("verified") if tls else None, "trust": tls.get("trust") if tls else None,
            "min_tls": tls.get("min_tls") if tls else None, "last_error": tls.get("error") if tls else None,
            "host_observed": {"direct_tls": "host's own TLS endpoint (HTTPS)", "tunnel": "via the ingest-only tunnel listener (ngrok: TLS ends at ngrok, "
                                                                                  "then plain HTTP on 127.0.0.1)"}.get(via, "not observed yet"),
            "via": via, "end_to_end_tls": (False if via == "tunnel" else True if via == "direct_tls" else None)}


def _egress_proof(t, c, pr):
    """Collector-reported hash of its last acknowledged payload vs the hash the host computed on the bytes it received."""
    e = (pr or {}).get("egress") or {}
    if not e.get("payload_id"):
        return {"reported": False, "match": None}
    row = db.one("SELECT sha256, received_ms, seq FROM payloads WHERE tenant_id=? AND collector_id=? AND payload_id=?", (t, c["id"], e["payload_id"]))
    return {"reported": True, "payload_id": e["payload_id"], "collector_sha256": e.get("sha256"),
            "host_sha256": row["sha256"] if row else None, "match": (row["sha256"] == e.get("sha256")) if row else None,
            "payloads_sent": e.get("payloads_sent"), "events_sent": e.get("events_sent")}


def _priv_device(t, c, deep=False):
    st, legacy = _anon_state(c)
    pr = jl(c.get("privacy"), {})
    last = db.one("SELECT payload_id, seq, received_ms, event_count, sha256 FROM payloads WHERE tenant_id=? AND collector_id=? ORDER BY received_ms DESC LIMIT 1",
                  (t, c["id"]))
    vio = db.all("SELECT level, code, field, count, first_ms, last_ms FROM policy_violations WHERE tenant_id=? AND collector_id=? ORDER BY last_ms DESC LIMIT 30",
                 (t, c["id"]))
    fw = (pr.get("firewall") or {}) if pr else {}
    d = {"id": c["id"], "device_id": c["name"], "pseudonymous": bool(PSEUDONYM_NAME.match(c["name"] or "")),
         "platform": c["platform"], "status": c["status"], "last_seen_ms": c["last_seen_ms"], "anonymisation": st,
         "identity_exposed_at_enrolment": legacy, "records": int(c["anon_records"] or 0), "removed": int(c["anon_removed"] or 0),
         "pseudonymised": int(c["anon_pseudo"] or 0), "policy": c["anon_policy"], "privacy_reported": bool(pr),
         "firewall": {"blocked_events": int(fw.get("blocked_events", 0)), "blocked_fields": int(fw.get("blocked_fields", 0)),
                      "redactions": int(fw.get("redactions", 0)), "policy_blocked": int(fw.get("policy_blocked", 0)),
                      "redaction_labels": fw.get("redaction_labels", {})},
         "breakdown": (pr.get("breakdown") or {}) if pr else {}, "tls": _tls_summary(c, pr),
         "last_transmission": ({"received_ms": last["received_ms"], "payload_id": last["payload_id"], "seq": last["seq"],
                                "events": last["event_count"], "sha256": last["sha256"]} if last else None),
         "violations": {"rejected": sum(v["count"] for v in vio if v["level"] == "reject"), "flagged": sum(v["count"] for v in vio if v["level"] == "flag"),
                        "items": vio if deep else []},
         "egress_proof": _egress_proof(t, c, pr)}
    return d


@app.get("/api/privacy/overview")
def privacy_overview(s=Depends(user)):
    t = s["tenant_id"]
    base = cloud(s)
    rows = db.all("SELECT * FROM collectors WHERE tenant_id=? ORDER BY name", (t,))
    devs = [_priv_device(t, c) for c in rows]
    fw = {k: sum(d["firewall"][k] for d in devs) for k in ("blocked_events", "blocked_fields", "redactions", "policy_blocked")}
    tls = {"reporting": sum(1 for d in devs if d["tls"]["reported_by_collector"]), "verified": sum(1 for d in devs if d["tls"]["verified"]),
           "direct": sum(1 for d in devs if d["tls"]["via"] == "direct_tls"), "tunnel": sum(1 for d in devs if d["tls"]["via"] == "tunnel"),
           "errors": sum(1 for d in devs if d["tls"]["last_error"])}
    return {**base, "devices": devs, "firewall_totals": fw, "tls_totals": tls,
            "egress_totals": {"verified_match": sum(1 for d in devs if d["egress_proof"]["match"] is True),
                              "mismatch": sum(1 for d in devs if d["egress_proof"]["match"] is False)}}


@app.get("/api/privacy/devices/{cid}")
def privacy_device(cid: str, s=Depends(user)):
    t = s["tenant_id"]
    c = _priv_collector(t, cid)
    d = _priv_device(t, c, deep=True)
    d["payloads"] = db.all("SELECT payload_id, seq, received_ms, event_count, sha256, body IS NOT NULL AS exact FROM payloads WHERE tenant_id=? AND "
                           "collector_id=? ORDER BY received_ms DESC LIMIT 25", (t, cid))
    for x in d["payloads"]:
        x["exact"] = bool(x["exact"])
    return d


@app.get("/api/privacy/devices/{cid}/payloads/{pid}")
def privacy_payload(cid: str, pid: str, s=Depends(user)):
    """The payload exactly as the host received it (the stored request body), with integrity and policy checks."""
    t = s["tenant_id"]
    c = _priv_collector(t, cid)
    row = db.one("SELECT payload_id, seq, received_ms, sha256, body, event_count FROM payloads WHERE tenant_id=? AND collector_id=? AND payload_id=?", (t, cid, pid))
    if not row:
        raise HTTPException(404, "payload not found")
    pr = jl(c.get("privacy"), {})
    rep = (pr.get("egress") or {}) if pr else {}
    if row["body"] is not None:
        payload, exact = json.loads(row["body"]), True
        integrity = hashlib.sha256(row["body"].encode("utf-8")).hexdigest() == row["sha256"]
    else:      # older than the retention window for exact bodies: rebuilt from stored events (content equal, formatting not guaranteed)
        evs = db.all("SELECT event_id,type,source_id,category,severity,metric,value,unit,event_time,source_tz,context FROM events WHERE tenant_id=? AND payload_id=? ORDER BY event_ms", (t, pid))
        for e in evs:
            e["context"] = jl(e["context"], {})
            for k in [k for k, v in e.items() if v is None]:
                e.pop(k)
        payload = {"payload_id": pid, "collector_id": cid, "seq": row["seq"], "schema_version": "1.0", "events": evs}
        exact, integrity = False, None
    findings = [f for e in payload.get("events", []) if isinstance(e, dict) for f in policy_lib.check_event(e)]
    return {"payload_id": pid, "seq": row["seq"], "received_ms": row["received_ms"], "sha256_host": row["sha256"], "exact": exact,
            "integrity_ok": integrity, "events": row["event_count"], "payload": payload,
            "collector_reported_match": (rep.get("sha256") == row["sha256"]) if rep.get("payload_id") == pid else None,
            "policy_findings": [f"{f['code']}@{f['field']}" for f in findings],
            "note": None if exact else "Exact body no longer retained (only the newest bodies are kept); showing the stored events."}


@app.get("/api/privacy/firewall")
def privacy_firewall(s=Depends(user)):
    """Privacy-firewall activity: collector-reported counters (per device) + what the HOST rejected or flagged."""
    t = s["tenant_id"]
    names = {c["id"]: c["name"] for c in db.all("SELECT id, name FROM collectors WHERE tenant_id=?", (t,))}
    devs = [_priv_device(t, c) for c in db.all("SELECT * FROM collectors WHERE tenant_id=? ORDER BY name", (t,))]
    rej = db.all("SELECT collector_id, reason, ts_ms FROM rejected WHERE tenant_id=? AND (reason LIKE 'allow-list%' OR reason LIKE 'outgoing%' "
                 "OR reason LIKE '%anonymisation%') ORDER BY ts_ms DESC LIMIT 40", (t,))
    for r in rej:
        r["device"] = names.get(r["collector_id"], r["collector_id"])
        r["reason"] = r["reason"][:240]          # field names / labels / codes only - never values
    vio = [{**v, "device": names.get(v["collector_id"], v["collector_id"])} for v in db.all(
        "SELECT collector_id, level, code, field, count, first_ms, last_ms FROM policy_violations WHERE tenant_id=? ORDER BY last_ms DESC LIMIT 50", (t,))]
    labels = {}
    for d in devs:
        for k, v in d["firewall"]["redaction_labels"].items():
            labels[k] = labels.get(k, 0) + v
    return {"devices": [{k: d[k] for k in ("id", "device_id", "status", "privacy_reported", "firewall", "breakdown")} for d in devs],
            "redaction_labels": labels, "host_rejections": rej, "violations": vio}


@app.get("/api/privacy/deletions")
def deletion_list(s=Depends(user)):
    from . import deletion
    return deletion.listing(s["tenant_id"])


def _del(fn, *a, **k):
    try:
        return fn(*a, **k)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/privacy/deletions")
def deletion_create(body: dict, s=Depends(user)):
    from . import deletion
    return _del(deletion.create, s["tenant_id"], s["username"], str((body or {}).get("collector_id", "")), (body or {}).get("reason"))


@app.post("/api/privacy/deletions/{rid}/approve")
def deletion_approve(rid: int, body: dict, s=Depends(user)):
    from . import deletion
    return _del(deletion.approve, s["tenant_id"], s["username"], s["role"], rid, (body or {}).get("confirm_text"), (body or {}).get("note", ""))


@app.post("/api/privacy/deletions/{rid}/reject")
def deletion_reject(rid: int, body: dict, s=Depends(user)):
    from . import deletion
    return _del(deletion.reject, s["tenant_id"], s["username"], s["role"], rid, (body or {}).get("note", ""))


@app.get("/api/privacy/retention")
def privacy_retention(s=Depends(user)):
    """Actual retention configuration and what is currently stored for this tenant."""
    from .ingest import BODY_KEEP
    t = s["tenant_id"]
    ev = db.one("SELECT COUNT(*) n, MIN(event_ms) oldest FROM events WHERE tenant_id=?", (t,))
    pl = db.one("SELECT COUNT(*) n, SUM(body IS NOT NULL) bodies FROM payloads WHERE tenant_id=?", (t,))
    return {"telemetry_retention_hours": settings(t)["retention_hours"], "events_stored": ev["n"], "oldest_event_ms": ev["oldest"],
            "payload_records": pl["n"], "payload_bodies_kept": pl["bodies"] or 0, "payload_bodies_kept_per_device": BODY_KEEP,
            "audit_entries": db.one("SELECT COUNT(*) n FROM audit WHERE tenant_id=?", (t,))["n"],
            "notes": ["Telemetry older than the retention window is deleted automatically by the host (hourly sweep).",
                      "Only the newest exact payload bodies per device are kept (for the egress proof); older ones keep only the hash.",
                      "The audit log is append-only and is not covered by the telemetry retention window.",
                      "Raw logs and original identities are never sent to the host, so there is nothing to retain here; they remain on each device."]}


@app.get("/api/privacy/contract")
def privacy_contract(s=Depends(user)):
    """The allow-list (data contract) every outgoing event is filtered against on the laptop AND re-checked here."""
    from common.schema import CONTEXT_ALLOW, HEARTBEAT_FIELDS, TOP_FIELDS, TYPES
    return {"top_fields": sorted(TOP_FIELDS), "event_types": sorted(TYPES), "context_allow": {k: v for k, v in CONTEXT_ALLOW.items()},
            "heartbeat_fields": sorted(HEARTBEAT_FIELDS), "identifying_fields_removed_locally": sorted(anon_lib.IDENTIFYING_FIELDS)}


@app.post("/api/ask")
def ask_question(body: dict, s=Depends(user), accept_language: str | None = Header(None, alias="X-UI-Lang")):
    """Read-only Q&A over this tenant's data via the local model. Any logged-in user; dashboard listener only."""
    try:
        return qa.ask(s["tenant_id"], s["username"], str((body or {}).get("question", "")), (accept_language or "en")[:2])
    except ai.AIError as e:
        raise HTTPException({"badrequest": 400, "busy": 429}.get(e.status, 503), e.msg)


@app.get("/api/voice/status")
def voice_status(s=Depends(user)):
    from . import voice
    return voice.status()


@app.post("/api/voice/transcribe")
async def voice_transcribe(request: Request, s=Depends(user)):
    """Local Whisper speech-to-text. Body: raw 16 kHz mono int16 PCM. Audio is processed in memory and discarded; neither audio nor text is logged."""
    from starlette.concurrency import run_in_threadpool
    from . import voice
    st = voice.status()
    if not st["available"]:
        raise HTTPException(503, st["reason"])
    pcm = await request.body()
    try:
        text = await run_in_threadpool(voice.transcribe, pcm)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(500, "local transcription failed")
    return {"text": text, "model": st["model"], "processed": "locally on this PC; audio was not stored"}


@app.get("/api/judge/result")
def judge_result(scenario: str, since_ms: float, collector_id: str = "", s=Depends(user)):
    """Live Judge Mode: everything measured for one injected scenario, from stored timestamps (read-only)."""
    from . import judge
    return judge.result(s["tenant_id"], scenario, since_ms, collector_id or None)


@app.get("/api/reliability")
def reliability_view(s=Depends(user)):
    from . import judge
    return judge.reliability(s["tenant_id"])


@app.get("/api/scenarios/priority")
def scenario_priority(active: str = "", s=Depends(user)):
    """Active Scenario Lab entries ordered by the triage priority of the incidents they generated."""
    names = [n for n in active.split(",") if n][:30]
    return scenarios.priority_view(s["tenant_id"], names)


def _incident(t, iid):
    inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (iid, t))
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/incidents/{iid}")
def incident(iid: int, s=Depends(user)):
    t = s["tenant_id"]
    inc = _incident(t, iid)
    inc["analysis"] = jl(inc["analysis"], {})
    inc["entities"] = jl(inc["entities"], [])
    inc["alerts"] = db.all("SELECT * FROM alerts WHERE incident_id=? ORDER BY event_ms", (iid,))
    for a in inc["alerts"]:
        a["kinds"], a["evidence"], a["detected_by"] = jl(a["kinds"], []), jl(a["evidence"], {}), jl(a["detected_by"], [])
    inc["timeline"] = db.all("SELECT ts_ms,event_ms,kind,detail,snapshot FROM incident_events WHERE incident_id=? ORDER BY ts_ms", (iid,))
    for e in inc["timeline"]:
        e["snapshot"] = jl(e["snapshot"], None)
    from .intel import correlate as _corr
    inc["external"] = _corr.incident_external(t, iid)      # global intelligence tied to this incident (priority is never changed by it)
    inc["remediation"] = [remediation.get(t, r["id"]) for r in db.all("SELECT id FROM remediation WHERE incident_id=? AND tenant_id=? ORDER BY id", (iid, t))]
    return inc


@app.get("/api/incidents/{iid}/replay")
def replay(iid: int, s=Depends(user)):
    """Incident Time Machine: everything below comes from stored telemetry/alerts, ordered by EVENT time."""
    t = s["tenant_id"]
    inc = _incident(t, iid)
    a = jl(inc["analysis"], {})
    alerts_ = db.all("SELECT id,source_id,metric,severity,title,message,event_ms,COALESCE(last_event_ms,event_ms) end_ms,cleared_ms,kinds,evidence "
                     "FROM alerts WHERE incident_id=? ORDER BY event_ms", (iid,))
    start = min([x["event_ms"] for x in alerts_] + [inc["opened_ms"]]) - 60_000
    end_candidates = [x["end_ms"] for x in alerts_] + [inc["last_alert_ms"] or 0]
    end = max(end_candidates) + 30_000
    ents = sorted(set(jl(inc["entities"], [])) | set(a.get("blast_radius", [])))
    ser = {}
    for e in ents:
        for m in db.all("SELECT DISTINCT metric FROM events WHERE tenant_id=? AND source_id=? AND type='metric' AND event_ms BETWEEN ? AND ?", (t, e, start, end)):
            rows = db.all("SELECT event_ms, value FROM events WHERE tenant_id=? AND source_id=? AND metric=? AND type='metric' "
                          "AND event_ms BETWEEN ? AND ? ORDER BY event_ms", (t, e, m["metric"], start, end))
            step = max(1, len(rows) // 300)
            ser[f"{e}|{m['metric']}"] = [[r["event_ms"], r["value"]] for r in rows[::step]]
    for x in alerts_:
        x["kinds"], x["evidence"] = jl(x["kinds"], []), jl(x["evidence"], {})
        x["resolved"] = x["cleared_ms"] is not None
    tl = db.all("SELECT ts_ms,event_ms,kind,detail,snapshot FROM incident_events WHERE incident_id=? ORDER BY event_ms, ts_ms", (iid,))
    for e in tl:
        e["snapshot"] = jl(e["snapshot"], None)
    rem = [remediation.get(t, r["id"]) for r in db.all("SELECT id FROM remediation WHERE incident_id=?", (iid,))]
    rem_ev = []
    for r in rem:
        for k, label in (("proposed_ms", "proposed"), ("approved_ms", "approved"), ("executed_ms", "executed"), ("rolled_back_ms", "rolled back")):
            if r.get(k):
                rem_ev.append({"ts_ms": r[k], "event_ms": r[k], "kind": "remediation", "detail": f"Remediation #{r['id']} {label}: {r['title']}"})
    hh = db.all("SELECT entity_id, old_state, new_state, reasons, ts_ms FROM health_history WHERE tenant_id=? AND ts_ms BETWEEN ? AND ? ORDER BY ts_ms",
                (t, start, end + 120_000))
    hh = [x for x in hh if x["entity_id"] in ents or x["entity_id"] == "tenant"]
    return {"incident": {k: inc[k] for k in ("id", "title", "status", "opened_ms", "severity")}, "start_ms": start, "end_ms": end,
            "entities": ents, "series": ser, "alerts": alerts_, "timeline": sorted(tl + rem_ev, key=lambda e: e["event_ms"]),
            "health_transitions": hh, "analysis": {"root": a.get("root"), "affected": a.get("affected"), "blast_radius": a.get("blast_radius")},
            "edges": [[x, y] for x, ys in graph(t)[0].items() for y in ys if x in ents or y in ents]}


@app.get("/api/topology")
def topology(incident_id: int | None = None, s=Depends(user)):
    t = s["tenant_id"]
    h = health.compute(t)
    deps, _ = graph(t)
    info = entity_info(t)
    nodes = []
    roles = {}
    if incident_id:
        inc = _incident(t, incident_id)
        a = jl(inc["analysis"], {})
        roles[(a.get("root") or {}).get("entity")] = "root"
        for e in a.get("affected", []) + a.get("unrelated_alerting", []):
            roles.setdefault(e, "affected")
        for e in a.get("blast_radius", []):
            roles.setdefault(e, "blast")
    for eid, i in info.items():
        if eid.startswith("collector:"):
            continue
        e = h["entities"].get(eid, {})
        nodes.append({"id": eid, "type": i["type"], "label": i["label"], "state": e.get("state", "Good"), "reasons": e.get("reasons", []),
                      "metrics": {k: round(v["value"], 2) for k, v in (e.get("metrics") or {}).items()}, "role": roles.get(eid)})
    edges = [[a_, b_] for a_, bs in deps.items() for b_ in bs]
    return {"nodes": nodes, "edges": edges}


@app.get("/api/thresholds")
def get_thr(s=Depends(user)):
    return {"thresholds": thresholds(s["tenant_id"]), "settings": settings(s["tenant_id"])}


@app.put("/api/thresholds")
def put_thr(body: dict, s=Depends(user)):
    if s["role"] != "admin":
        raise HTTPException(403, "admin role required")
    t = s["tenant_id"]
    for m, v in (body.get("thresholds") or {}).items():
        try:
            g, w, c = float(v["good_max"]), float(v["warn"]), float(v["crit"])
        except Exception:
            raise HTTPException(400, f"bad threshold for {m}")
        ok_order = (g >= w >= c) if m in LOWER_IS_WORSE else (g <= w <= c)
        if not ok_order:
            raise HTTPException(400, f"{m}: require " + ("good_max >= warn >= crit (lower is worse)" if m in LOWER_IS_WORSE
                                                         else "good_max <= warn <= crit"))
        set_threshold(t, m, g, w, c)
    for k, v in (body.get("settings") or {}).items():
        try:
            set_setting(t, k, v)
        except Exception:
            raise HTTPException(400, f"bad setting {k}")
    audit(t, s["username"], "config.thresholds_changed", jd(body)[:300])
    return get_thr(s)


@app.get("/api/history")
def history(limit: int = 100, s=Depends(user)):
    return db.all("SELECT * FROM health_history WHERE tenant_id=? ORDER BY ts_ms DESC LIMIT ?", (s["tenant_id"], min(limit, 500)))


@app.get("/api/audit")
def audit_log(limit: int = 100, s=Depends(user)):
    return db.all("SELECT * FROM audit WHERE tenant_id=? ORDER BY ts_ms DESC LIMIT ?", (s["tenant_id"], min(limit, 500)))


# ---- remediation
@app.get("/api/remediation")
def rem_list(s=Depends(user)):
    t = s["tenant_id"]
    return [remediation.get(t, r["id"]) for r in db.all("SELECT id FROM remediation WHERE tenant_id=? ORDER BY id DESC LIMIT 100", (t,))]


def _wrap(fn, *a):
    try:
        return fn(*a)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/incidents/{iid}/remediation")
def rem_propose(iid: int, body: dict, s=Depends(user)):
    return _wrap(remediation.propose, s["tenant_id"], s["username"], iid, body.get("action"), body.get("target"))


@app.post("/api/remediation/{rid}/approve")
def rem_approve(rid: int, body: dict | None = None, s=Depends(user)):
    return _wrap(remediation.approve, s["tenant_id"], s["username"], s["role"], rid, (body or {}).get("note", ""))


@app.post("/api/remediation/{rid}/reject")
def rem_reject(rid: int, body: dict | None = None, s=Depends(user)):
    return _wrap(remediation.reject, s["tenant_id"], s["username"], s["role"], rid, (body or {}).get("note", ""))


@app.post("/api/remediation/{rid}/rollback")
def rem_rollback(rid: int, s=Depends(user)):
    return _wrap(remediation.request_rollback, s["tenant_id"], s["username"], s["role"], rid)


@app.post("/api/remediation/{rid}/execute")
def rem_execute(rid: int, s=Depends(user)):
    r = remediation.get(s["tenant_id"], rid)
    if not r:
        raise HTTPException(404, "not found")
    raise HTTPException(409, "direct execution is not permitted; execution is only triggered by an approval record")


# ---- AI-assisted remediation engine (catalogue -> evidence -> plan -> approval -> controlled execution -> verification -> rollback)
@app.get("/api/rem/catalogue")
def rem_catalogue(s=Depends(user)):
    return {"problems": rem_engine.catalogue_view(s["tenant_id"]),
            "actions": [{"id": k, "title": v["title"], "kind": v["kind"], "scope": v["scope"], "risk": v["risk"], "destructive": v["destructive"], "reversible": v["reversible"], "what": v["what"]}
                        for k, v in rem_engine.ACTIONS.items()]}


@app.get("/api/rem/plans")
def rem_plans(s=Depends(user)):
    return rem_engine.list_plans(s["tenant_id"])


@app.get("/api/rem/plans/{pid}")
def rem_plan(pid: int, s=Depends(user)):
    p = rem_engine.view(s["tenant_id"], pid)
    if not p:
        raise HTTPException(404, "plan not found")
    return p


@app.post("/api/rem/plans")
def rem_plan_create(body: dict, s=Depends(user), ui_lang: str | None = Header(None, alias="X-UI-Lang")):
    b = body or {}
    return _wrap(rem_engine.generate, s["tenant_id"], s["username"], s["role"], b.get("problem_id"), b.get("target"), b.get("incident_id"), (ui_lang or "en")[:2])


@app.post("/api/rem/plans/{pid}/approve")
def rem_plan_approve(pid: int, body: dict | None = None, s=Depends(user)):
    b = body or {}
    return _wrap(rem_engine.approve, s["tenant_id"], s["username"], s["role"], pid, b.get("confirm_text"), b.get("note", ""))


@app.post("/api/rem/plans/{pid}/reject")
def rem_plan_reject(pid: int, body: dict | None = None, s=Depends(user)):
    return _wrap(rem_engine.reject, s["tenant_id"], s["username"], s["role"], pid, (body or {}).get("note", ""))


@app.post("/api/rem/plans/{pid}/rollback")
def rem_plan_rollback(pid: int, s=Depends(user)):
    return _wrap(rem_engine.rollback, s["tenant_id"], s["username"], s["role"], pid)


@app.post("/api/rem/plans/{pid}/steps/{sid}/manual-done")
def rem_manual_done(pid: int, sid: int, body: dict | None = None, s=Depends(user)):
    return _wrap(rem_engine.manual_done, s["tenant_id"], s["username"], s["role"], pid, sid, (body or {}).get("note", ""))


# ---- data inspection: what the SaaS actually received (compare with collector Egress Proof)
@app.get("/api/ledger")
def ledger(limit: int = 60, s=Depends(user)):
    return db.all("SELECT payload_id, collector_id, seq, received_ms, event_count, sha256, dup_events FROM payloads WHERE tenant_id=? "
                  "ORDER BY received_ms DESC LIMIT ?", (s["tenant_id"], min(limit, 300)))


@app.get("/api/ledger/{payload_id}")
def ledger_one(payload_id: str, s=Depends(user)):
    t = s["tenant_id"]
    p = db.one("SELECT * FROM payloads WHERE payload_id=? AND tenant_id=?", (payload_id, t))
    if not p:
        raise HTTPException(404, "payload not found")
    evs = db.all("SELECT event_id,type,source_id,category,severity,metric,value,unit,event_time,source_tz,context FROM events "
                 "WHERE payload_id=? AND tenant_id=? ORDER BY event_ms", (payload_id, t))
    for e in evs:
        e["context"] = jl(e["context"], {})
    return {"payload": p, "events": evs}


@app.get("/api/rejections")
def rejections(s=Depends(user)):
    return db.all("SELECT * FROM rejected WHERE tenant_id=? ORDER BY ts_ms DESC LIMIT 50", (s["tenant_id"],))


@app.get("/api/events")
def events_feed(types: str = "", limit: int = 100, s=Depends(user)):
    q, p = "SELECT event_id,type,source_id,metric,value,severity,event_time,source_tz,context,late FROM events WHERE tenant_id=?", [s["tenant_id"]]
    if types:
        ts = [x for x in types.split(",") if x.isalnum() or "_" in x]
        q += " AND type IN (%s)" % ",".join("?" * len(ts))
        p += ts
    rows = db.all(q + " ORDER BY event_ms DESC LIMIT ?", p + [min(limit, 300)])
    for r in rows:
        r["context"] = jl(r["context"], {})
    return rows


# ---- performance (measured, not claimed)
@app.post("/api/perf/render")
def perf_render(body: dict, s=Depends(user)):
    now = now_ms()
    rows = []
    for x in (body.get("samples") or [])[:100]:
        try:
            l = float(x["rendered_ms"]) - parse_iso(x["event_time"]) * 1000.0
        except Exception:
            continue
        if -1000 < l < 600_000:
            rows.append((s["tenant_id"], str(x.get("event_id", ""))[:64], l, now))
    with db.lock:          # the connection is shared across threads: never bypass the lock (an ingestion transaction may be open)
        db.conn.executemany("INSERT INTO perf_render(tenant_id,event_id,latency_ms,ts_ms) VALUES(?,?,?,?)", rows)
    return {"stored": len(rows)}


@app.get("/api/perf")
def perf(s=Depends(user)):
    t = s["tenant_id"]
    ms = now_ms()
    ing = db.all("SELECT received_ms-event_ms l, event_ms FROM events WHERE tenant_id=? AND type='metric' AND received_ms>?", (t, ms - 600_000))
    live = [r["l"] for r in ing if r["l"] < 10_000]
    delayed = [r["l"] for r in ing if r["l"] >= 10_000]
    rend = [r["latency_ms"] for r in db.all("SELECT latency_ms FROM perf_render WHERE tenant_id=? AND ts_ms>?", (t, ms - 600_000))]
    markers = db.all("SELECT * FROM sim_markers WHERE tenant_id=? ORDER BY injected_ms DESC LIMIT 30", (t,))
    alert_lat = []
    for m in markers:
        a = db.one("SELECT created_ms, title, event_ms FROM alerts WHERE tenant_id=? AND created_ms>=? AND created_ms<=? AND severity!='info' "
                   "AND category!='collector' ORDER BY created_ms LIMIT 1", (t, m["injected_ms"], m["injected_ms"] + 90_000))
        alert_lat.append({"scenario": m["scenario"], "injected_at": m["injected_at"], "alert_after_ms": round(a["created_ms"] - m["injected_ms"]) if a else None,
                          "alert": a["title"] if a else None})
    outages = []
    for o in db.all("SELECT * FROM outages WHERE tenant_id=? ORDER BY detected_ms DESC LIMIT 10", (t,)):
        mk = db.one("SELECT injected_ms, scenario FROM sim_markers WHERE tenant_id=? AND collector_id=? AND scenario IN "
                    "('collector_disconnect') AND injected_ms<=? ORDER BY injected_ms DESC LIMIT 1", (t, o["collector_id"], o["detected_ms"]))
        outages.append({"collector_id": o["collector_id"], "since_last_heartbeat_ms": round(o["detected_ms"] - o["last_seen_ms"]),
                        "since_outage_start_ms": round(o["detected_ms"] - mk["injected_ms"]) if mk else None,
                        "detected_at": utc_iso(o["detected_ms"] / 1000), "recovered": o["recovered_ms"] is not None})
    delivery = []
    for c in db.all("SELECT id, name FROM collectors WHERE tenant_id=?", (t,)):
        r = db.one("SELECT COUNT(*) n, MIN(seq) lo, MAX(seq) hi, COUNT(DISTINCT seq) dseq FROM payloads WHERE tenant_id=? AND collector_id=?", (t, c["id"]))
        dups = db.one("SELECT COUNT(*) n FROM rejected WHERE tenant_id=? AND collector_id=? AND reason LIKE 'duplicate%'", (t, c["id"]))["n"]
        rej = db.one("SELECT COUNT(*) n FROM rejected WHERE tenant_id=? AND collector_id=? AND reason LIKE 'allow-list%'", (t, c["id"]))["n"]
        ev = db.one("SELECT COUNT(*) n, SUM(late) late FROM events WHERE tenant_id=? AND collector_id=?", (t, c["id"]))
        gaps = ((r["hi"] - r["lo"] + 1) - r["dseq"]) if r["n"] else 0
        # missing seq numbers (since first received)
        seqs = {x["seq"] for x in db.all("SELECT seq FROM payloads WHERE tenant_id=? AND collector_id=?", (t, c["id"]))}
        missing = [q for q in range(r["lo"], r["hi"] + 1) if q not in seqs][:20] if r["n"] else []
        delivery.append({"collector_id": c["id"], "name": c["name"], "payloads": r["n"], "first_seq": r["lo"], "last_seq": r["hi"],
                         "missing_seq": missing, "seq_gaps": gaps, "duplicates_ignored": dups, "rejected_by_allowlist": rej,
                         "events": ev["n"], "out_of_order_events": ev["late"] or 0})
    targets = {"collection_to_dashboard_p95_ms": 10_000, "alert_ms": 15_000, "offline_detect_ms": 60_000}
    return {"targets": targets,
            "ingest": {"live_n": len(live), "p50": pct(live, 50), "p95": pct(live, 95), "max": round(max(live), 1) if live else None,
                       "delayed_backlog_n": len(delayed)},
            "render": {"n": len(rend), "p50": pct(rend, 50), "p95": pct(rend, 95), "max": round(max(rend), 1) if rend else None},
            "alert_latency": alert_lat, "offline_detection": outages, "delivery": delivery}


# ------------------------------------------------------------------ websocket
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    s = security.session_for(websocket.query_params.get("token"))
    if not s:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    hub.clients[websocket] = s["tenant_id"]
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.pop(websocket, None)


# ------------------------------------------------------------------ static UI
if (config.WEB_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=config.WEB_DIST / "assets"), name="assets")


@app.get("/{path:path}")
def spa(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "not found")
    f = config.WEB_DIST / "index.html"
    if not f.exists():
        return JSONResponse({"detail": "UI not built: run `npm run build` in /web"}, status_code=503)
    return FileResponse(f)


async def serve_public():
    """Single public listener for a hosting platform (Render). Fails closed if admin credentials are not provided via environment."""
    from .seed import seed_public
    seed_public()
    srv = uvicorn.Server(uvicorn.Config(app, host=config.HOST, port=config.HTTP_PORT, log_level="warning",
                                        proxy_headers=True, forwarded_allow_ips="*"))     # the platform edge sets X-Forwarded-Proto/For
    srv.install_signal_handlers = lambda: None
    print(f"SENTINEL X public mode on port {config.HTTP_PORT} (remote enrollment {'ON' if config.JOIN_CODE else 'OFF'})", flush=True)
    await srv.serve()


async def serve():
    if config.PUBLIC_MODE:
        return await serve_public()
    ca, crt, key = security.ensure_tls()
    https = uvicorn.Server(uvicorn.Config(app, host=config.INGEST_HOST, port=config.HTTPS_PORT, ssl_certfile=str(crt),
                                          ssl_keyfile=str(key), log_level="warning"))
    http = uvicorn.Server(uvicorn.Config(app, host=config.HOST, port=config.HTTP_PORT, log_level="warning"))
    http.install_signal_handlers = lambda: None
    servers = [https.serve(), http.serve()]
    if config.JOIN_CODE:
        # ingest-only front for the ngrok tunnel: loopback ONLY, never bound to another interface
        from .public import PublicIngest
        pub = uvicorn.Server(uvicorn.Config(PublicIngest(app), host="127.0.0.1", port=config.PUBLIC_PORT, log_level="warning",
                                            proxy_headers=False, ws="none"))
        pub.install_signal_handlers = lambda: None
        servers.append(pub.serve())
    print(f"SENTINEL X SaaS  UI: http://{config.HOST}:{config.HTTP_PORT} (local only)   local TLS ingest: https://{config.INGEST_HOST}:{config.HTTPS_PORT}"
          + (f"   ngrok ingest-only listener: http://127.0.0.1:{config.PUBLIC_PORT}  (remote enrollment ON)" if config.JOIN_CODE else
             "   remote enrollment OFF (no SENTINEL_JOIN_CODE)"), flush=True)
    await asyncio.gather(*servers)


if __name__ == "__main__":
    asyncio.run(serve())
