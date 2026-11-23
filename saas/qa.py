"""Ask-a-question over the tenant's own SENTINEL X data, answered by the local Ollama model.

Pipeline (all on the backend):
 1. deterministic router: keywords + known device/entity names pick which fixed, tenant-scoped lookups to run (no model, no SQL from the model)
 2. facts: numbers/enums only, every device/entity name replaced by a pseudonym (map stays server-side)
 3. the question itself is pseudonymised the same way, length-capped and scanned for secrets/PII; a hit blocks the call
 4. one Ollama request at a time (shares the gate with incident analysis); failures return the deterministic facts anyway
 5. the answer is validated, redacted, shown as plain text; sources must be ids that really were in the facts
Read-only: nothing here writes incidents/priority or triggers actions."""
import json
import re
import time

import httpx

from common.secrets import redact, scan
from . import ai, config
from .core import audit, entity_info, now_ms
from .db import db, jl

MAX_Q = 300
KIND = {"collector": "device", "host": "host", "service": "service", "network": "link"}
FACT_METRICS = ("cpu_percent", "memory_percent", "disk_percent", "battery_percent", "battery_charging", "latency_ms",
                "packet_loss_pct", "bandwidth_mbps", "response_ms", "error_rate_pct")
LEVEL_RE = re.compile(r"\bp([1-4])\b", re.I)
INC_RE = re.compile(r"(?:incident\s*#?|#)\s*(\d{1,7})", re.I)
_recent = {}     # user -> timestamps (simple per-user rate limit)

SCHEMA = {"type": "object", "properties": {
    "answer": {"type": "string"}, "enough_data": {"type": "boolean"},
    "sources": {"type": "array", "items": {"type": "string"}}}, "required": ["answer", "enough_data", "sources"]}

SYSTEM = ("You answer an operator's question about their own monitoring data. You are given FACTS as JSON lines, each with an id. "
          "Use ONLY those facts. Never invent devices, numbers, causes or times. Refer to things only by the given names "
          "(device-1, host-2, incident 22). If the facts do not contain the answer, set enough_data=false and say what is missing. "
          "Facts named \"extremes ...\" already contain the correct lowest/highest device; copy them, do not compare numbers yourself. Put the ids of the facts you relied on in sources. Priorities (P1-P4) and categories were computed by deterministic "
          "rules; report them, do not change or dispute them. Do not write commands. Be brief (max 5 sentences).")


class Pseudo:
    """Per-request, server-side name map."""
    def __init__(self, tenant):
        self.tenant, self.fwd, self.back, self.n = tenant, {}, {}, {}
        self.coll = {c["id"]: c for c in db.all("SELECT * FROM collectors WHERE tenant_id=?", (tenant,))}
        self.ents = entity_info(tenant)

    def name(self, kind, key, label):
        if (kind, key) not in self.fwd:
            self.n[kind] = self.n.get(kind, 0) + 1
            p = f"{KIND[kind]}-{self.n[kind]}"
            self.fwd[(kind, key)], self.back[p] = p, label or key
        return self.fwd[(kind, key)]

    def collector(self, cid):
        c = self.coll.get(cid)
        return self.name("collector", cid, c["name"] if c else cid)

    def entity(self, eid):
        if eid.startswith("collector:"):
            return self.collector(eid.split(":", 1)[1])
        e = self.ents.get(eid) or {}
        return self.name(e.get("type") if e.get("type") in KIND else "service", eid, e.get("label") or eid)

    def restore(self, text):
        return re.sub(r"\b(?:device|host|service|link)-\d{1,3}\b", lambda m: self.back.get(m.group(0).lower(), m.group(0)), text, flags=re.I)


# ------------------------------------------------------------------------------------------------ question -> mentions
def _tokens(name):
    return {t.lower() for t in re.split(r"[\s\-_:./]+", name) if len(t) >= 4}


def resolve_mentions(tenant, question, ps):
    """Find known devices/entities named in the question. Returns (sanitised question, collector ids, entity ids)."""
    q = question
    cands = [(c["name"], "collector", cid) for cid, c in ps.coll.items() if c["name"]]
    cands += [((e.get("label") or eid), "entity", eid) for eid, e in ps.ents.items()]
    cands += [(eid.split(":", 1)[-1], "entity", eid) for eid in ps.ents]      # ids like host:app-node
    cands += [(eid, "entity", eid) for eid in ps.ents]                            # the full id as typed
    cands += [(cid, "collector", cid) for cid in ps.coll]                         # raw collector ids
    cands.sort(key=lambda x: -len(x[0]))                                          # longest first
    colls, ents = [], []
    for nm, typ, key in cands:
        if len(nm) < 3:
            continue
        pat = re.compile(r"(?<![\w-])" + re.escape(nm) + r"(?![\w-])", re.I)
        if pat.search(q):
            p = ps.collector(key) if typ == "collector" else ps.entity(key)
            q = pat.sub(p, q)
            (colls if typ == "collector" else ents).append(key)
    # partial names ("demo" for My-Laptop) when unambiguous
    owners = {}
    for cid, c in ps.coll.items():
        for t in _tokens(c["name"]):
            owners.setdefault(t, set()).add(("collector", cid))
    for eid, e in ps.ents.items():
        for t in _tokens(e.get("label") or eid):
            owners.setdefault(t, set()).add(("entity", eid))
    for t, own in owners.items():
        if len(own) == 1 and re.search(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", q, re.I):
            typ, key = next(iter(own))
            p = ps.collector(key) if typ == "collector" else ps.entity(key)
            q = re.sub(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", p, q, flags=re.I)
            (colls if typ == "collector" else ents).append(key)
    return q, list(dict.fromkeys(colls)), list(dict.fromkeys(ents))


# ------------------------------------------------------------------------------------------------ lookups -> facts
def _age(ms, now):
    return int(max(0, now - ms) / 1000) if ms else None


def _fleet(tenant, ps, colls, now):
    rows = [c for cid, c in ps.coll.items() if not colls or cid in colls]
    out = []
    for c in sorted(rows, key=lambda c: c["name"] or "")[:12]:
        lat = db.all("SELECT source_id, metric, value, event_ms FROM latest WHERE tenant_id=? AND collector_id=?", (tenant, c["id"]))
        mets = {r["metric"]: round(r["value"], 1) for r in lat if r["metric"] in FACT_METRICS and r["value"] is not None}
        host = next((r["source_id"] for r in lat if r["source_id"].startswith("host:")), None)
        st = db.one("SELECT state FROM health_state WHERE tenant_id=? AND entity_id=?", (tenant, host))["state"] if host and \
            db.one("SELECT 1 FROM health_state WHERE tenant_id=? AND entity_id=?", (tenant, host)) else None
        p = ps.collector(c["id"])
        out.append({"id": p, "text": json.dumps({"device": p, "platform": c.get("platform") or "unknown", "status": c["status"],
                                                 "health": st, "seconds_since_last_seen": _age(c["last_seen_ms"], now), "latest": mets})})
    return out


METRIC_WORDS = (("battery", "battery_percent"), ("cpu", "cpu_percent"), ("memory", "memory_percent"), ("ram", "memory_percent"),
                ("disk", "disk_percent"), ("storage", "disk_percent"), ("latency", "latency_ms"), ("loss", "packet_loss_pct"))


def _extremes(tenant, ps, question_l, colls, now):
    """Comparisons are computed here, not by the model (a 1.5B model gets 'lowest/highest' wrong)."""
    out = []
    for word, metric in METRIC_WORDS:
        if word not in question_l or any(f["metric"] == metric for f in out):
            continue
        vals = []
        for r in db.all("SELECT collector_id, value FROM latest WHERE tenant_id=? AND metric=? AND value IS NOT NULL", (tenant, metric)):
            if r["collector_id"] in ps.coll and (not colls or r["collector_id"] in colls):
                vals.append((r["value"], r["collector_id"]))
        if vals:
            lo, hi = min(vals), max(vals)
            out.append({"metric": metric, "lowest": {"device": ps.collector(lo[1]), "value": round(lo[0], 1)},
                        "highest": {"device": ps.collector(hi[1]), "value": round(hi[0], 1)}, "devices_with_data": len(vals)})
    return [{"id": f"extremes {f['metric']}", "text": json.dumps(f)} for f in out]


def _intel(tenant, ps):
    """Global-intelligence facts: Python-computed correlations for THIS tenant's devices. Third-party titles are bounded plain text and flagged untrusted."""
    from .intel import ai as intel_ai, correlate
    rows = db.all("SELECT * FROM intel_correlations WHERE tenant_id=? ORDER BY (status='confirmed') DESC, score DESC LIMIT 8", (tenant,))
    facts = []
    by = {f"{r['kind']}/{r['status']}": r["n"] for r in db.all("SELECT kind, status, COUNT(*) n FROM intel_correlations WHERE tenant_id=? GROUP BY kind, status", (tenant,))}
    facts.append({"id": "global intelligence summary", "text": json.dumps({"correlations_by_kind_status": by,
                                                                        "note": "these are evidence-based matches, not statements of cause"})})
    for r in rows:
        o = correlate.out_row(r)
        g = o["global_event"] or {}
        facts.append({"id": f"correlation {r['id']}", "text": json.dumps({
            "correlation": r["id"], "kind": o["kind"], "status": o["status"], "score": o["score"], "device": ps.collector(r["collector_id"]),
            "source": g.get("source"), "severity": g.get("severity"), "external_text_untrusted": intel_ai.sanitise_external(g.get("title"), 140),
            "supporting_factors": [f["factor"] for f in o["factors"] if f["matched"]][:4]})})
    return facts


def _incident_line(tenant, ps, inc, now):
    an = jl(inc["analysis"], {})
    tri = (an.get("triage") or {}).get("priority") or {}
    root = an.get("root") or {}
    devs = [ps.collector(d["id"]) for d in tri.get("devices", [])]
    return {"id": f"incident {inc['id']}", "text": json.dumps({
        "incident": inc["id"], "status": inc["status"], "priority": inc.get("priority_level"), "score": inc.get("priority"),
        "category": inc.get("category"), "root_entity": ps.entity(root["entity"]) if root.get("entity") else None,
        "root_metric": root.get("metric"), "alerts": inc["alert_count"], "devices": devs,
        "seconds_since_opened": _age(inc["opened_ms"], now)})}


def _incidents(tenant, ps, level=None, category=None, colls=(), ents=(), limit=8, now=0):
    from .triage import rank_key
    rows = db.all("SELECT * FROM incidents WHERE tenant_id=? AND status='open'", (tenant,))
    if level:
        rows = [r for r in rows if r["priority_level"] == level]
    if category:
        rows = [r for r in rows if r["category"] == category]
    if colls or ents:
        keep = []
        for r in rows:
            an = jl(r["analysis"], {})
            devs = {d["id"] for d in ((an.get("triage") or {}).get("priority") or {}).get("devices", [])}
            if devs & set(colls) or (set(jl(r["entities"], [])) & set(ents)) or (r["root_entity"] in ents):
                keep.append(r)
        rows = keep
    rows.sort(key=lambda r: rank_key(r["priority_level"], r["priority"]))
    return [_incident_line(tenant, ps, r, now) for r in rows[:limit]], len(rows)


def _incident_detail(tenant, ps, iid, now):
    inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (iid, tenant))
    if not inc:
        return []
    an = jl(inc["analysis"], {})
    facts = [_incident_line(tenant, ps, inc, now)]
    tri = (an.get("triage") or {}).get("priority") or {}
    facts.append({"id": f"incident {iid} priority factors", "text": json.dumps(
        {"incident": iid, "factors": [{"factor": r["factor"], "points": r["points"]} for r in tri.get("reasons", [])]})})
    for i, s in enumerate(an.get("signals", [])[:8], 1):
        facts.append({"id": f"incident {iid} signal {i}", "text": json.dumps({
            "incident": iid, "signal": i, "entity": ps.entity(s["entity"]), "metric": ai._name(s["metric"]), "severity": s["severity"],
            "value": ai._num(s.get("value")), "baseline": ai._num(s.get("baseline")), "z_score": ai._num(s.get("z_score")),
            "seconds_after_first": ai._num(s.get("t_offset_s"), 0), "cleared": bool(s.get("cleared"))})})
    facts.append({"id": f"incident {iid} impact", "text": json.dumps({
        "incident": iid, "root_cause_engine_confidence": ai._num((an.get("root") or {}).get("confidence"), 2),
        "affected": [ps.entity(e) for e in an.get("affected", [])][:8], "at_risk_downstream": [ps.entity(e) for e in an.get("blast_radius", [])][:8]})})
    return facts


def _alerts(tenant, ps, colls, now):
    rows = db.all("SELECT * FROM alerts WHERE tenant_id=? AND cleared_ms IS NULL AND severity!='info' ORDER BY event_ms DESC LIMIT 60", (tenant,))
    if colls:
        rows = [r for r in rows if r["collector_id"] in colls]
    sev = {}
    for r in rows:
        sev[r["severity"]] = sev.get(r["severity"], 0) + 1
    facts = [{"id": "alerts summary", "text": json.dumps({"active_alerts_by_severity": sev, "total": len(rows)})}]
    for r in rows[:6]:
        facts.append({"id": f"alert {r['id']}", "text": json.dumps({
            "alert": r["id"], "entity": ps.entity(r["source_id"]), "metric": ai._name(r["metric"]), "severity": r["severity"],
            "category": r["category"], "incident": r["incident_id"], "seconds_since_start": _age(r["event_ms"], now)})})
    return facts


def gather(tenant, question, ps, colls, ents):
    """Deterministic router. Returns (facts, topics)."""
    ql, now, facts, topics = question.lower(), now_ms(), [], []
    m = INC_RE.search(question)
    if m:
        f = _incident_detail(tenant, ps, int(m.group(1)), now)
        if f:
            facts += f
            topics.append(f"incident {m.group(1)} detail")
    lvl = LEVEL_RE.search(question)
    wants_inc = bool(lvl) or any(w in ql for w in ("incident", "priority", "urgent", "critical", "important", "worst", "attention", "problem", "issue", "wrong", "happen"))
    cat = next((c for w, c in (("security", "Security"), ("login", "Security"), ("brute", "Security"), ("credential", "Security"),
                               ("network", "Network"), ("latency", "Network"), ("packet", "Network"),
                               ("collector health", "Collector Health"), ("offline", "Collector Health")) if w in ql), None)
    if wants_inc or colls or ents or (cat and not m):   # naming a device/entity also pulls in its open incidents
        f, total = _incidents(tenant, ps, f"P{lvl.group(1)}" if lvl else None, cat, colls, ents, now=now)
        facts.append({"id": "incident list", "text": json.dumps({"open_incidents_matching": total, "shown": len(f),
                                                                "filter": {"priority": f"P{lvl.group(1)}" if lvl else None, "category": cat}})})
        facts += f
        topics.append("open incidents" + (f" P{lvl.group(1)}" if lvl else "") + (f" · {cat}" if cat else ""))
    if colls or any(w in ql for w in ("device", "laptop", "phone", "android", "collector", "fleet", "online", "offline", "battery", "cpu", "memory",
                                      "ram", "disk", "storage", "latency", "bandwidth", "status", "how is", "how are")):
        facts += _extremes(tenant, ps, ql, colls, now) + _fleet(tenant, ps, colls, now)
        topics.append("devices" + (" (named)" if colls else ""))
    if "alert" in ql:
        facts += _alerts(tenant, ps, colls, now)
        topics.append("active alerts")
    if any(w in ql for w in ("outage", "vulnerab", "cve", "aws", "azure", "cloudflare", "github", "google cloud", "gcp", "bgp", "routing", "global", "external",
                             "intelligence", "exposed", "exposure", "patch", "worldwide", "internet")):
        facts += _intel(tenant, ps)
        topics.append("global intelligence")
    if not facts:      # nothing specific asked: give the overall picture
        f, total = _incidents(tenant, ps, now=now, limit=5)
        facts.append({"id": "incident list", "text": json.dumps({"open_incidents": total, "shown": len(f)})})
        facts += f + _fleet(tenant, ps, colls, now)[:6]
        topics.append("overview")
    return facts, topics


# ------------------------------------------------------------------------------------------------ model
def _ask_model(question, facts, lang=None):
    body = "QUESTION: " + question + "\nFACTS:\n" + "\n".join(f"[{f['id']}] {f['text']}" for f in facts)
    if scan(body, include_pii=True) or scan(SYSTEM, include_pii=True):
        raise ai.AIError("blocked", "privacy filter: the question or data matched a secret/PII pattern; nothing was sent to the model")
    try:
        with ai._client(min(config.OLLAMA_TIMEOUT_S, 120)) as c:
            r = c.post("/api/chat", json={"model": config.OLLAMA_MODEL, "stream": False, "format": SCHEMA,
                                          "options": {"temperature": 0.1, "num_ctx": 4096},
                                          "messages": [{"role": "system", "content": SYSTEM + ai.sys_for(lang)[len(ai.SYSTEM):]}, {"role": "user", "content": body + ai.lang_tail(lang)}]})
    except ai.AIError:
        raise
    except httpx.TimeoutException:
        raise ai.AIError("error", "the local model did not answer in time")
    except httpx.HTTPError:
        raise ai.AIError("unavailable", "Ollama is not reachable on the local machine")
    if r.status_code != 200:
        raise ai.AIError("error", f"Ollama returned HTTP {r.status_code}")
    try:
        return r.json()["message"]["content"], body
    except (ValueError, KeyError, TypeError):
        raise ai.AIError("malformed", "unexpected Ollama response shape")


def validate(raw, valid_ids):
    try:
        d = json.loads(raw)
    except (TypeError, ValueError):
        raise ai.AIError("malformed", "model did not return valid JSON")
    if not isinstance(d, dict) or not isinstance(d.get("answer"), str) or not d["answer"].strip():
        raise ai.AIError("malformed", "model JSON is missing an answer")
    srcs = [s for s in (d.get("sources") or []) if isinstance(s, str) and s in valid_ids][:8]
    enough = d.get("enough_data") is True
    return {"answer": ai._clean(d["answer"], 1200), "enough_data": enough, "sources": list(dict.fromkeys(srcs))}


def _rate_ok(user):
    t = time.time()
    q = [x for x in _recent.get(user, []) if t - x < 60]
    if len(q) >= 10:
        _recent[user] = q
        return False
    _recent[user] = q + [t]
    return True


def ask(tenant, user, question, lang=None):
    question = (question or "").strip()
    if not question:
        raise ai.AIError("badrequest", "question is empty")
    if len(question) > MAX_Q:
        raise ai.AIError("badrequest", f"question is too long (max {MAX_Q} characters)")
    if not _rate_ok(user):
        raise ai.AIError("busy", "too many questions; wait a moment")
    t0 = now_ms()
    ps = Pseudo(tenant)
    safe_q, colls, ents = resolve_mentions(tenant, question, ps)
    facts, topics = gather(tenant, question, ps, colls, ents)   # the router reads the real text server-side only
    res = {"topics": topics, "facts": [{"id": f["id"], "text": ps.restore(f["text"])} for f in facts],
           "status": "ready", "error": None, "answer": None, "model": config.OLLAMA_MODEL, "sources": [], "enough_data": None,
           "question_sent": None}
    sent_q, _ = redact(safe_q)
    outcome = "facts_only"
    try:
        if not facts or all(f["id"] in ("incident list", "alerts summary") for f in facts):
            res["status"], res["error"] = "nodata", "No matching data was found for that question."
            outcome = "nodata"
        else:
            av = ai.availability(force=True)
            if not av["available"]:
                raise ai.AIError("unavailable", av["reason"])
            if not ai._gate.acquire(blocking=False):
                raise ai.AIError("busy", "the local model is busy with another request; try again shortly")
            try:
                raw, sent = _ask_model(sent_q, facts, lang)
            finally:
                ai._gate.release()
            out = validate(raw, {f["id"] for f in facts})
            res.update(answer=ps.restore(out["answer"]), enough_data=out["enough_data"],
                       sources=[ps.restore(s) for s in out["sources"]], question_sent=sent_q)
            outcome = "ready"
    except ai.AIError as e:
        res["status"], res["error"] = e.status, e.msg
        outcome = e.status
    except Exception as e:      # an AI problem must never break the dashboard
        res["status"], res["error"] = "error", f"unexpected error: {type(e).__name__}"
        outcome = "error"
    res["duration_ms"] = round(now_ms() - t0)
    audit(tenant, user, "ai.ask", {"chars": len(question), "topics": topics, "outcome": outcome})   # never the question text
    return res
