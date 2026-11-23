"""Optional local AI analysis of incidents through Ollama (qwen2.5:1.5b by default).

Rules enforced here:
* The model only ever sees an allow-listed, pseudonymised, numbers-and-enums context (no names, logs, messages, evidence).
  The pseudonym map stays server-side. The final prompt is scanned for secrets/PII and the call is aborted on any hit.
* Runs on the backend, on demand (admin), one request at a time, off the ingestion/monitoring/correlation paths.
* Output is untrusted: strictly validated, secret-redacted, never executed, never written to incident category/priority.
* Results carry a context hash; if the incident's analysis/triage changes the stored result is reported as stale."""
import hashlib
import json
import math
import re
import threading
from urllib.parse import urlparse

import httpx

from common.secrets import redact, scan
from . import config
from .core import audit, entity_info, now_ms
from .correlation import CAUSE
from .db import db, jd, jl

_gate = threading.Semaphore(1)          # at most one Ollama request at a time
_avail = {"t": 0.0, "v": None}
SEV = {"info", "warning", "critical"}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
SIG_RE = re.compile(r"\bS\d{1,3}\b")
TYPE_PREFIX = {"host": "host", "service": "service", "network": "link", "collector": "collector"}

SCHEMA = {"type": "object", "properties": {
    "summary": {"type": "string"},
    "hypotheses": {"type": "array", "items": {"type": "object", "properties": {
        "statement": {"type": "string"}, "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "evidence_refs": {"type": "array", "items": {"type": "string"}}}, "required": ["statement", "confidence", "evidence_refs"]}},
    "investigation_steps": {"type": "array", "items": {"type": "string"}},
    "recommendations": {"type": "array", "items": {"type": "object", "properties": {
        "title": {"type": "string"}, "rationale": {"type": "string"}}, "required": ["title", "rationale"]}}},
    "required": ["summary", "hypotheses", "investigation_steps", "recommendations"]}

SYSTEM = ("You are an SRE assistant inside an observability product. You are given structured facts about ONE incident as JSON. "
          "Use ONLY those facts. Never invent metrics, devices, numbers or causes. Refer to entities only by the given ids "
          "(e.g. host-1) and cite the supporting signal ids (S1, S2...) in evidence_refs. If the evidence is insufficient to "
          "name a cause, say so and keep confidence low. Hypotheses are guesses for a human to verify, not conclusions. "
          "Investigation steps and recommendations are suggestions for a human operator; do not write shell commands. "
          "The priority and category were computed by deterministic rules; do not change or dispute them. Be concise and specific.")


class AIError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status, self.msg = status, msg


# ------------------------------------------------------------------------------------------- context (privacy boundary)
def _num(v, nd=1):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return round(f, nd) if math.isfinite(f) else None


def _name(v):
    return v if isinstance(v, str) and NAME_RE.match(v) else "unknown"


def build_context(tenant, incident):
    """-> (context dict sent to the model, pseudonym map {pseudonym: original entity id}). Reads only structured fields."""
    an = jl(incident["analysis"], {}) if not isinstance(incident["analysis"], dict) else incident["analysis"]
    tri = an.get("triage") or {}
    pr = tri.get("priority") or {}
    info = entity_info(tenant)
    ents = sorted({s["entity"] for s in an.get("signals", [])} | set(an.get("affected", [])) | set(an.get("blast_radius", []))
                  | ({an["root"]["entity"]} if an.get("root") else set()))
    counts, ps, pmap = {}, {}, {}

    def etype(e):
        return "collector" if e.startswith("collector:") else (info.get(e) or {}).get("type", "service")
    for e in ents:
        pre = TYPE_PREFIX.get(etype(e), "service")
        counts[pre] = counts.get(pre, 0) + 1
        ps[e] = f"{pre}-{counts[pre]}"
        pmap[ps[e]] = e
    root = an.get("root") or {}
    rtype = etype(root.get("entity", ""))
    cause = CAUSE.get((rtype, root.get("metric")), "Anomaly on {label}").format(label=ps.get(root.get("entity"), "unknown"))
    sigs = []
    for i, s in enumerate(an.get("signals", []), 1):
        sigs.append({"id": f"S{i}", "entity": ps.get(s["entity"], "unknown"), "metric": _name(s["metric"]),
                     "severity": s["severity"] if s["severity"] in SEV else "unknown", "value": _num(s.get("value")),
                     "baseline": _num(s.get("baseline")), "z_score": _num(s.get("z_score")),
                     "seconds_after_first": _num(s.get("t_offset_s"), 0), "cleared": bool(s.get("cleared")),
                     "detectors": len(s.get("detected_by") or [])})
    ctx = {"incident": {"category": tri.get("category") if tri.get("category") in
                        ("Infrastructure", "Network", "Security", "Collector Health") else "unknown",
                        "secondary_categories": [c for c in tri.get("secondary_categories", []) if isinstance(c, str) and len(c) < 20],
                        "status": incident.get("status") if incident.get("status") in ("open", "resolved") else "unknown",
                        "priority": pr.get("level") if pr.get("level") in ("P1", "P2", "P3", "P4") else "unknown",
                        "priority_score": _num(pr.get("score"), 0), "devices_reporting": len(pr.get("devices", [])),
                        "priority_factors": [{"factor": _name(r.get("factor")), "points": _num(r.get("points"), 0)}
                                             for r in pr.get("reasons", [])]},
           "deterministic_root_cause": {"entity": ps.get(root.get("entity"), "unknown"), "metric": _name(root.get("metric")),
                                        "label": cause, "engine_confidence": _num(root.get("confidence"), 2)},
           "signals": sigs, "affected_entities": [ps[e] for e in an.get("affected", []) if e in ps],
           "at_risk_downstream": [ps[e] for e in an.get("blast_radius", []) if e in ps],
           "entities": {ps[e]: TYPE_PREFIX.get(etype(e), "service") for e in ents}}
    return ctx, pmap


def context_hash(ctx):
    # durations are excluded on purpose (they grow every second); factor points capture duration buckets
    return hashlib.sha256(json.dumps(ctx, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def build_prompt(ctx):
    user = "Incident facts (JSON):\n" + json.dumps(ctx, separators=(",", ":"))
    hits = scan(user, include_pii=True) + scan(SYSTEM, include_pii=True)
    if hits:
        raise AIError("blocked", "privacy filter: the prompt matched a secret/PII pattern; nothing was sent to the model")
    return user


# ------------------------------------------------------------------------------------------- output validation (untrusted)
def _clean(text, limit):
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(text)).strip()[:limit]
    t, _ = redact(t)
    return t


def validate(raw, valid_ids):
    try:
        d = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        raise AIError("malformed", "model did not return valid JSON")
    if not isinstance(d, dict) or not isinstance(d.get("summary"), str) or not isinstance(d.get("hypotheses"), list):
        raise AIError("malformed", "model JSON is missing required fields")
    hyps = []
    for h in d["hypotheses"][:6]:
        if not isinstance(h, dict) or not isinstance(h.get("statement"), str) or not isinstance(h.get("evidence_refs"), list):
            continue
        refs = sorted({m for r in h["evidence_refs"] for m in SIG_RE.findall(str(r)) if m in valid_ids}, key=lambda x: int(x[1:]))
        if not refs:     # a hypothesis that cites no real signal is not allowed through
            continue
        conf = h.get("confidence") if h.get("confidence") in ("low", "medium", "high") else "low"
        conf = "medium" if conf == "high" else conf    # a 1.5B model's self-rated certainty is never shown as "high"
        hyps.append({"statement": _clean(h["statement"], 400), "model_confidence": conf, "evidence_refs": refs})
    if not hyps:
        raise AIError("malformed", "model produced no hypothesis grounded in the supplied signals")
    steps = [_clean(x, 300) for x in (d.get("investigation_steps") or []) if isinstance(x, str) and x.strip()][:6]
    recs = [{"title": _clean(r["title"], 150), "rationale": _clean(r.get("rationale", ""), 300)}
            for r in (d.get("recommendations") or []) if isinstance(r, dict) and isinstance(r.get("title"), str) and r["title"].strip()][:5]
    return {"summary": _clean(d["summary"], 800), "hypotheses": hyps[:4], "investigation_steps": steps, "recommendations": recs}


# ------------------------------------------------------------------------------------------- Ollama client
def _loopback(url):
    return (urlparse(url).hostname or "") in ("127.0.0.1", "localhost", "::1")


def _client(timeout):
    if not _loopback(config.OLLAMA_URL):
        raise AIError("unavailable", "SENTINEL_OLLAMA_URL must be a loopback address; refusing to contact it")
    return httpx.Client(base_url=config.OLLAMA_URL, timeout=timeout, trust_env=False)   # no env proxies: never leaves the box


def availability(force=False):
    """Cheap, cached probe: is Ollama up and is the configured model installed?"""
    if not force and now_ms() - _avail["t"] < 10_000 and _avail["v"] is not None:
        return _avail["v"]
    try:
        with _client(2.5) as c:
            names = {m.get("name") for m in c.get("/api/tags").json().get("models", [])}
        ok = config.OLLAMA_MODEL in names
        v = {"available": ok, "model": config.OLLAMA_MODEL,
             "reason": None if ok else f"model '{config.OLLAMA_MODEL}' is not installed in Ollama (run: ollama pull {config.OLLAMA_MODEL})"}
    except AIError as e:
        v = {"available": False, "model": config.OLLAMA_MODEL, "reason": e.msg}
    except Exception:
        v = {"available": False, "model": config.OLLAMA_MODEL, "reason": "Ollama is not reachable on the local machine"}
    _avail.update(t=now_ms(), v=v)
    return v


LANGS = {"hi": "Hindi (Devanagari script)", "kn": "Kannada (Kannada script)"}


def sys_for(lang):
    """System prompt + a language instruction. English (default/fallback) adds nothing. Identifiers stay untouched."""
    if lang not in LANGS:
        return SYSTEM
    return SYSTEM + (f" Write every free-text field of your answer in {LANGS[lang]}. Do NOT translate or alter: incident IDs, evidence/signal IDs and JSON keys, "
                     "device names such as Device-27, metric names and numeric values, timestamps, severity codes (P1-P4, critical/warning/info), or technical terms; keep them exactly as given.")


_EXAMPLE = {"hi": "उदाहरण (Example): \"Device-9000 और Device-12 ऑफ़लाइन हैं।\"",
            "kn": "ಉದಾಹರಣೆ (Example): \"Device-9000 ಮತ್ತು Device-12 ಆಫ್‌ಲೈನ್ ಆಗಿವೆ.\""}


def lang_tail(lang):
    """Repeated at the END of the user message (small models follow the last instruction best)."""
    if lang not in LANGS:
        return ""
    return (f"\n\nIMPORTANT: write the answer text in {LANGS[lang]}, not in English. Keep device names (e.g. Device-27), incident/signal IDs, numbers, "
            "timestamps and codes exactly as given. " + _EXAMPLE[lang])


def call_model(prompt, lang=None):
    try:
        with _client(config.OLLAMA_TIMEOUT_S) as c:
            r = c.post("/api/chat", json={"model": config.OLLAMA_MODEL, "stream": False, "format": SCHEMA,
                                          "options": {"temperature": 0.1, "num_ctx": 4096},
                                          "messages": [{"role": "system", "content": sys_for(lang)}, {"role": "user", "content": prompt + lang_tail(lang)}]})
    except AIError:
        raise
    except httpx.TimeoutException:
        raise AIError("error", f"the local model did not answer within {int(config.OLLAMA_TIMEOUT_S)} s")
    except httpx.HTTPError:
        raise AIError("unavailable", "Ollama is not reachable on the local machine")
    if r.status_code != 200:
        raise AIError("error", f"Ollama returned HTTP {r.status_code}")
    try:
        return r.json()["message"]["content"]
    except (ValueError, KeyError, TypeError):
        raise AIError("malformed", "unexpected Ollama response shape")


# ------------------------------------------------------------------------------------------- orchestration
def _incident(tenant, iid):
    return db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (iid, tenant))


def _run(tenant, iid, user, ctx, pmap, h, t0, lang=None):
    status, result, err = "ready", None, None
    try:
        prompt = build_prompt(ctx)
        av = availability(force=True)
        if not av["available"]:
            raise AIError("unavailable", av["reason"])
        result = validate(call_model(prompt, lang), {s["id"] for s in ctx["signals"]})
    except AIError as e:
        status, err = e.status, e.msg
    except Exception as e:      # never let an AI problem escape the worker
        status, err = "error", f"unexpected error: {type(e).__name__}"
    finally:
        _gate.release()
    ms = now_ms()
    db.exec("UPDATE incident_ai SET status=?, finished_ms=?, duration_ms=?, result=?, error=? WHERE tenant_id=? AND incident_id=?",
            (status, ms, ms - t0, jd(result) if result else None, err, tenant, iid))
    audit(tenant, user, "ai.analysis", {"incident": iid, "model": config.OLLAMA_MODEL, "context_hash": h, "outcome": status})


def start(tenant, iid, user, lang=None):
    """Queue one analysis. Raises AIError('busy'|'notfound'). Returns immediately; the work runs in a daemon thread."""
    inc = _incident(tenant, iid)
    if not inc:
        raise AIError("notfound", "incident not found")
    ctx, pmap = build_context(tenant, inc)
    if not ctx["signals"]:
        raise AIError("nodata", "this incident has no analysed signals yet")
    if not _gate.acquire(blocking=False):
        raise AIError("busy", "another AI analysis is already running (one at a time); try again shortly")
    h, t0 = context_hash(ctx), now_ms()
    try:
        db.exec("INSERT OR REPLACE INTO incident_ai(tenant_id,incident_id,status,model,ctx_hash,requested_by,requested_ms,context,pmap)"
                " VALUES(?,?,?,?,?,?,?,?,?)", (tenant, iid, "running", config.OLLAMA_MODEL, h, user, t0, jd(ctx), jd(pmap)))
        threading.Thread(target=_run, args=(tenant, iid, user, ctx, pmap, h, t0, lang), daemon=True, name="ai").start()
    except Exception:
        _gate.release()
        raise
    return {"status": "running"}


def _restore_names(text, pmap, info):
    def sub(m):
        e = pmap.get(m.group(0).lower())
        return (info.get(e) or {}).get("label") or e if e else m.group(0)
    return re.sub(r"\b(?:host|service|link|collector)-\d{1,3}\b", sub, text, flags=re.I)


def get(tenant, iid):
    inc = _incident(tenant, iid)
    if not inc:
        raise AIError("notfound", "incident not found")
    av = availability()
    row = db.one("SELECT * FROM incident_ai WHERE tenant_id=? AND incident_id=?", (tenant, iid))
    out = {"ollama": av, "analysis": None}
    if not row:
        return out
    if row["status"] == "running" and now_ms() - row["requested_ms"] > (config.OLLAMA_TIMEOUT_S + 30) * 1000:
        db.exec("UPDATE incident_ai SET status='error', error='analysis was interrupted' WHERE tenant_id=? AND incident_id=?", (tenant, iid))
        row["status"], row["error"] = "error", "analysis was interrupted"
    ctx, _ = build_context(tenant, inc)
    pmap, info = jl(row["pmap"], {}), entity_info(tenant)
    res = jl(row["result"], None)
    if res:   # pseudonyms are mapped back to real names only here, at display time, never in the prompt
        res = {
            "summary": _restore_names(res["summary"], pmap, info),
            "hypotheses": [{**h, "statement": _restore_names(h["statement"], pmap, info)} for h in res["hypotheses"]],
            "investigation_steps": [_restore_names(s, pmap, info) for s in res["investigation_steps"]],
            "recommendations": [{"title": _restore_names(r["title"], pmap, info), "rationale": _restore_names(r["rationale"], pmap, info)}
                                for r in res["recommendations"]]}
    out["analysis"] = {"status": row["status"], "model": row["model"], "error": row["error"], "requested_by": row["requested_by"],
                       "requested_ms": row["requested_ms"], "finished_ms": row["finished_ms"], "duration_ms": row["duration_ms"],
                       "context_hash": row["ctx_hash"], "stale": context_hash(ctx) != row["ctx_hash"], "result": res,
                       "context_sent": jl(row["context"], {}),
                       "signal_map": {f"S{i}": {"entity": (info.get(s["entity"]) or {}).get("label") or s["entity"], "metric": s["metric"]}
                                      for i, s in enumerate(jl(inc["analysis"], {}).get("signals", []), 1)}}
    return out
