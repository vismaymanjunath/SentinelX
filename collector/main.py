import json
import os
import threading
import time

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from common.secrets import redact
from . import config
from .db import db
from .engine import engine
from .simstate import SCENARIOS, sim

WEB_DIST = config.BASE / "web" / "dist"
app = FastAPI(title="SENTINEL X — Local Collector Console")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8080", "http://localhost:8080", *[o for o in os.environ.get("COLLECTOR_CORS_ORIGINS", "").split(",") if o.strip()]], allow_methods=["*"], allow_headers=["*"])
threading.Thread(target=engine.run, daemon=True, name="engine").start()


@app.get("/api/whoami")
def whoami():
    return {"tier": "collector", "collector_id": config.COLLECTOR_ID, "tenant": config.TENANT_LABEL, "region": config.REGION,
            "source_tz": config.SOURCE_TZ, "saas_url": config.SAAS_URL, "version": config.VERSION, "host_mode": config.HOST_MODE,
            "saas_ui": None if config.REMOTE else "http://127.0.0.1:8080", "device_name": config.DEVICE_NAME,
            "remote": config.REMOTE}


@app.get("/api/status")
def status():
    pend = db.one("SELECT COUNT(*) n, MIN(created_ms) m, MIN(seq) lo, MAX(seq) hi FROM outbox WHERE status='pending'")
    sent = db.one("SELECT COUNT(*) n FROM outbox WHERE status='sent'")["n"]
    rej = db.one("SELECT COUNT(*) n FROM outbox WHERE status='rejected'")["n"]
    now = time.time() * 1000
    link = dict(engine.link)
    if sim.saas_blocked():
        link["state"] = "partitioned (simulated)"
    if sim.collector_down():
        link["state"] = "collector stopped (simulated)"
    qb = db.one("SELECT COALESCE(SUM(LENGTH(body)),0) b FROM outbox WHERE status='pending'")["b"]
    online = link["state"] == "connected"
    sync = {"state": "ONLINE" if online else "OFFLINE", "pending": pend["n"], "pending_kib": round(qb / 1024),
            "last_successful_sync_ms": link.get("last_ack_ms"),
            "last_successful_sync": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(link["last_ack_ms"] / 1000)) if link.get("last_ack_ms") else None,
            "last_sync_error": link.get("last_error"), "queue_full": bool(link.get("queue_full")),
            "not_queued_payloads": engine.stats.get("queue_full_payloads", 0),
            "limits": {"max_pending": config.OUTBOX_MAX_PENDING, "max_mb": config.OUTBOX_MAX_MB,
                       "backoff_base_s": config.BACKOFF_BASE_S, "backoff_max_s": config.BACKOFF_MAX_S}}
    return {"sync": sync, "link": link, "outbox": {"pending": pend["n"], "sent": sent, "rejected": rej,
                                      "oldest_pending_s": round((now - pend["m"]) / 1000, 1) if pend["m"] else 0,
                                      "pending_seq_range": [pend["lo"], pend["hi"]]},
            "stats": engine.stats, "sim": sim.status(), "scenarios": SCENARIOS, "config": engine.cfg, "config_version": engine.cfg_version,
            "logproc": engine.logproc.stats, "last_seq": db.kv_get("seq", 0), "now_ms": now,
            "local_alerts": list(engine.local_alerts)[:15]}


@app.get("/api/logs")
def get_logs(limit: int = 60, only_secrets: bool = False):
    q = "SELECT id, ts, raw, redacted, secrets, pii, level, service FROM raw_logs"
    if only_secrets:
        q += " WHERE secrets!=''"
    return db.all(q + " ORDER BY id DESC LIMIT ?", (min(limit, 300),))


@app.post("/api/logs/inject")
def inject_log(body: dict):
    line = str(body.get("line", ""))[:600]
    if not line.strip():
        raise HTTPException(400, "empty line")
    with sim.lock:
        sim.log_queue.append(line)
    db.audit("log.injected", "custom raw log line injected via console")
    return {"queued": True}


@app.get("/api/anon")
def anon_status():
    """LOCAL console only (loopback): anonymisation status, counters, the local original->pseudonym mapping, real BEFORE/AFTER
    pairs from what was actually queued, and transport (TLS) facts. The mapping never leaves this laptop."""
    from common import policy
    from . import anonymise as an
    snap = an.anonymiser.snapshot()
    pairs = []
    for r in db.all("SELECT original, final FROM egress WHERE final IS NOT NULL ORDER BY created_ms DESC LIMIT 12"):
        try:
            orig = {e["event_id"]: e for e in json.loads(r["original"])}
            fin = json.loads(r["final"])["events"]
        except (ValueError, KeyError, TypeError):
            continue
        for ev in fin:
            b = orig.get(ev["event_id"])
            if b is not None and b != ev:
                pairs.append({"before": b, "after": ev, "violations_after": [f["code"] for f in policy.check_event(ev)]})
        if len(pairs) >= 3:
            break
    m = an.store.mapping()
    kinds = {}
    for real, kind in m["identifiers"].items():
        kinds.setdefault(kind, []).append(real)
    return {"enabled": snap["enabled"], "policy": snap["policy"], "alias": an.ALIAS, "public_label": an.PUBLIC_LABEL,
            "stats": {"records": snap["records"], "removed": snap["removed"], "pseudonymised": snap["pseudonymised"]},
            "mapping_local_only": {"alias": m["alias"], "identifiers": kinds},
            "legacy_identity_at_host": an.LEGACY_IDENTITY, "pairs": pairs,
            "transport": {"scheme": "https", "certificate_verification": "on",
                          "trust": "pinned private CA" if config.CA_CERT else "system trust store (public CA)",
                          "min_tls": "1.2", "last_error": engine.link.get("last_error") if engine.link.get("tls_error") else None,
                          "end_to_end": False if "ngrok" in config.SAAS_URL else None},
            "retained": ["CPU / RAM / disk / network metrics", "timestamps", "alert severity", "error descriptions (with identifiers removed)",
                         "platform and OS version", "collector buffer/link health"],
            "removed": ["usernames", "laptop / asset IDs", "hostnames and device names (replaced by the pseudonym)", "IP and MAC addresses",
                        "user home paths", "raw log lines and raw samples"]}


@app.get("/api/egress")
def egress_list(limit: int = 60):
    rows = db.all("SELECT payload_id, seq, created_ms, status, sha256, saas_sha256, http_status, event_count, blocked_count, attempts "
                  "FROM egress ORDER BY created_ms DESC LIMIT ?", (min(limit, 300),))
    for r in rows:
        r["attempts"] = json.loads(r["attempts"] or "[]")
    return rows


@app.get("/api/egress/{payload_id}")
def egress_one(payload_id: str):
    r = db.one("SELECT * FROM egress WHERE payload_id=?", (payload_id,))
    if not r:
        raise HTTPException(404, "payload not found (may have been purged by retention)")
    for k in ("original", "redacted", "final", "blocked", "redactions", "attempts"):
        r[k] = json.loads(r[k]) if r[k] else None
    return r


@app.get("/api/outbox")
def outbox(limit: int = 40):
    return db.all("SELECT seq, payload_id, status, attempts, created_ms, sent_ms, event_count, sha256 FROM outbox ORDER BY seq DESC LIMIT ?", (limit,))


@app.post("/api/sim/clear")
def sim_clear():
    sim.clear()
    db.audit("scenario.cleared", "all")
    return sim.status()


@app.post("/api/sim/{name}")
def sim_inject(name: str, body: dict | None = None):
    if name not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    dur = (body or {}).get("duration_s")
    return sim.inject(name, float(dur) if dur else None)


@app.post("/api/firewall/selftest")
def selftest():
    engine.selftest()
    return {"submitted": True}


@app.get("/api/firewall/rules")
def rules():
    from common.schema import CONTEXT_ALLOW, TOP_FIELDS, TYPES
    return {"top_fields": sorted(TOP_FIELDS), "types": sorted(TYPES), "context_allow": {k: v for k, v in CONTEXT_ALLOW.items()}}


@app.post("/api/redact-preview")
def preview(body: dict):
    red, f = redact(str(body.get("text", ""))[:2000])
    return {"redacted": red, "findings": [{"label": x["label"], "kind": x["kind"]} for x in f]}


@app.post("/api/reconcile")
def reconcile():
    """Sent IDs vs IDs the SaaS has: proves zero loss / zero duplicates after an outage."""
    try:
        r = engine.client.get(f"{config.SAAS_URL}/api/ingest/v1/ledger")
        r.raise_for_status()
    except Exception as e:
        raise HTTPException(502, f"SaaS unreachable: {e}")
    j = r.json()
    saas = j["payload_ids"]
    local_sent = {x["payload_id"] for x in db.all("SELECT payload_id FROM outbox WHERE status='sent'")}
    local_all = {x["payload_id"] for x in db.all("SELECT payload_id FROM outbox")}
    pending = {x["payload_id"] for x in db.all("SELECT payload_id FROM outbox WHERE status='pending'")}
    ss = set(saas)
    return {"local_payloads": len(local_all), "local_acked_sent": len(local_sent), "pending_in_buffer": len(pending),
            "saas_received": len(ss), "saas_ids_unique": len(ss) == len(saas),
            "missing_at_saas": sorted(local_sent - ss)[:20], "unknown_to_collector": sorted(ss - local_all)[:20],
            "duplicates_stored_at_saas": len(saas) - len(ss), "duplicates_ignored_by_saas": j["duplicates_ignored"],
            "zero_loss": not (local_sent - ss), "zero_duplicates": len(saas) == len(ss)}


@app.get("/api/config")
def get_cfg():
    return {"config": engine.cfg, "version": engine.cfg_version}


@app.put("/api/config")
def put_cfg(body: dict):
    engine.set_config(body)
    return get_cfg()


@app.get("/api/audit")
def audit(limit: int = 80):
    return db.all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))


@app.get("/api/live")
def live():
    return {f"{k[0]}|{k[1]}": list(v)[-60:] for k, v in engine.recent.items()}


if (WEB_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")


@app.get("/{path:path}")
def spa(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "not found")
    f = WEB_DIST / "index.html"
    if not f.exists():
        return JSONResponse({"detail": "UI not built"}, status_code=503)
    return FileResponse(f)


if __name__ == "__main__":
    print(f"SENTINEL X Collector {config.COLLECTOR_ID} console: http://127.0.0.1:{config.UI_PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=config.UI_PORT, log_level="warning")
