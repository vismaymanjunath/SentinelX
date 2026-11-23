"""Metadata allow-list (the data contract across the trust boundary) + event filter.

Used by the collector privacy firewall (lenient: drop/redact) and by the SaaS ingest guard
(strict: reject anything that deviates).
"""
import math
import re
from datetime import datetime, timezone

from .secrets import redact, scan

SCHEMA_VERSION = "1.0"
TYPES = {"metric", "alert", "security_summary", "privacy_summary", "log_summary", "sim_marker"}
SEVERITIES = {"info", "warning", "critical"}
CATEGORIES = {"infrastructure", "network", "service", "security", "privacy", "collector", "system"}
UNITS = {"percent", "ms", "mbps", "count", "bool", "ratio", "bytes", "none", "seconds"}

RX_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")
RX_SRC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.\-]{0,63}$")
RX_METRIC = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
RX_TZ = re.compile(r"^[A-Za-z][A-Za-z0-9_/+\-]{0,39}$")
MAX_STR = 140

TOP_FIELDS = {"event_id", "type", "source_id", "category", "severity", "metric", "value", "unit",
              "event_time", "source_tz", "context"}
REQUIRED = {"event_id", "type", "source_id", "category", "severity", "event_time", "source_tz"}

# context allow-list per event type: key -> kind
CONTEXT_ALLOW = {
    "metric": {"origin": "str"},
    "alert": {"kind": "str", "message": "str", "z_score": "num", "baseline_mean": "num", "baseline_std": "num",
              "rate_of_change": "num", "direction": "str", "threshold": "num", "window_s": "num",
              "detected_by": "str"},
    "security_summary": {"failed_attempts": "num", "unique_sources": "num", "window_s": "num", "risk": "str",
                         "top_sources": "strlist", "service": "str"},
    "privacy_summary": {"lines_scanned": "num", "secrets_redacted": "num", "pii_redacted": "num",
                        "secret_types": "strlist"},
    "log_summary": {"lines": "num", "errors": "num", "warnings": "num", "window_s": "num"},
    "sim_marker": {"scenario": "str", "injected_at": "isoz", "duration_s": "num"},
}

HEARTBEAT_FIELDS = {"collector_id": "id", "version": "str", "config_version": "num", "source_tz": "str",
                    "host_id": "str", "proc_cpu_percent": "num", "proc_mem_mb": "num", "buffer_depth": "num",
                    "oldest_pending_s": "num", "link_state": "str", "sent_at": "isoz", "topology": "topology",
                    "retention_s": "num", "last_seq": "num",
                    # optional device descriptors (additive; older collectors simply omit them)
                    "platform": "str", "os_version": "str", "device_model": "str", "interval_s": "num",
                    # local-anonymisation declaration + counters (numbers only, no identifiers)
                    "anon": "anon",
                    # privacy/security telemetry for the central Privacy & Security view: counters, enum labels and hashes ONLY
                    "privacy": "privacy",
                    # coarse environment facts for correlation with global intelligence (public identifiers only)
                    "environment": "environment",
                    # which predefined remediation actions this collector build can execute (closed vocabulary)
                    "actions": "actions"}


def utc_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(s: str) -> float:
    if not isinstance(s, str) or not s.endswith("Z"):
        raise ValueError("timestamp must be UTC (Z suffix)")
    return datetime.strptime(s[:-1], "%Y-%m-%dT%H:%M:%S.%f" if "." in s else "%Y-%m-%dT%H:%M:%S") \
        .replace(tzinfo=timezone.utc).timestamp()


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _clean_str(path, v, redactions):
    """Truncate + redact secrets/PII from an allowed string. Returns (value, still_unsafe)."""
    v = v[:MAX_STR]
    out, findings = redact(v)
    for f in findings:
        redactions.append({"field": path, "label": f["label"]})
    return out, bool(scan(out))


def _check_ctx_value(path, kind, v, redactions):
    """Return (ok, value, unsafe)."""
    if kind == "num":
        return (_is_num(v), v, False)
    if kind == "str":
        if not isinstance(v, str):
            return False, None, False
        out, unsafe = _clean_str(path, v, redactions)
        return True, out, unsafe
    if kind == "isoz":
        try:
            parse_iso(v)
            return True, v, False
        except Exception:
            return False, None, False
    if kind == "strlist":
        if not isinstance(v, list) or len(v) > 10:
            return False, None, False
        res = []
        for i, item in enumerate(v):
            if not isinstance(item, str):
                return False, None, False
            o, unsafe = _clean_str(f"{path}[{i}]", item, redactions)
            if unsafe:
                return True, None, True
            res.append(o)
        return True, res, False
    return False, None, False


def filter_event(ev: dict) -> dict:
    """Apply the allow-list. Returns {clean, blocked_fields, redactions, violations, blocked, reason}."""
    blocked_fields, redactions, violations = [], [], []
    clean = {}
    unsafe = False
    if not isinstance(ev, dict):
        return {"clean": None, "blocked_fields": [], "redactions": [], "violations": ["not an object"],
                "blocked": True, "reason": "event is not an object"}
    for k, v in ev.items():
        if k not in TOP_FIELDS:
            blocked_fields.append(k)
            continue
        if k == "context":
            continue
        ok = True
        if k == "event_id":
            ok = isinstance(v, str) and RX_ID.match(v)
        elif k == "type":
            ok = v in TYPES
        elif k == "source_id":
            ok = isinstance(v, str) and RX_SRC.match(v)
        elif k == "category":
            ok = v in CATEGORIES
        elif k == "severity":
            ok = v in SEVERITIES
        elif k == "metric":
            ok = isinstance(v, str) and RX_METRIC.match(v)
        elif k == "unit":
            ok = v in UNITS
        elif k == "value":
            ok = _is_num(v)
        elif k == "event_time":
            try:
                parse_iso(v)
            except Exception:
                ok = False
        elif k == "source_tz":
            ok = isinstance(v, str) and RX_TZ.match(v)
        if not ok:
            violations.append(f"invalid value for {k}")
            continue
        clean[k] = v
    missing = REQUIRED - set(clean)
    if missing:
        violations.append("missing required: " + ",".join(sorted(missing)))
    etype = clean.get("type")
    if etype in ("metric",) and not {"metric", "value", "unit"} <= set(clean):
        violations.append("metric event needs metric,value,unit")
    ctx = ev.get("context")
    if ctx is not None and etype in CONTEXT_ALLOW:
        if not isinstance(ctx, dict):
            violations.append("context must be an object")
        else:
            allow = CONTEXT_ALLOW[etype]
            cc = {}
            for ck, cv in ctx.items():
                if ck not in allow:
                    blocked_fields.append(f"context.{ck}")
                    continue
                ok, val, uns = _check_ctx_value(f"context.{ck}", allow[ck], cv, redactions)
                if uns:
                    unsafe = True
                if not ok:
                    violations.append(f"invalid context.{ck}")
                    continue
                cc[ck] = val
            clean["context"] = cc
    elif ctx is not None:
        blocked_fields.append("context")
    blocked = bool(missing) or unsafe or any(v.startswith("metric event") for v in violations)
    reason = None
    if unsafe:
        reason = "unredactable sensitive content in allowed field"
    elif blocked:
        reason = "; ".join(violations)
    return {"clean": None if blocked else clean, "blocked_fields": blocked_fields, "redactions": redactions,
            "violations": violations, "blocked": blocked, "reason": reason}


def payload_text_findings(text: str):
    """Last-line guard: scan serialized payload bytes for anything secret-shaped."""
    return scan(text, include_pii=True)


PRIVACY_BREAKDOWN = {"identifying_field", "username", "ip", "mac", "user_path", "device_id"}
PRIVACY_FIREWALL = {"blocked_events", "blocked_fields", "redactions", "policy_blocked"}
PRIVACY_TLS_ERR = {"expired", "hostname", "untrusted", "self_signed", "other"}
RX_LABEL = re.compile(r"^[a-z][a-z0-9_]{1,23}$")
RX_SHA = re.compile(r"^[0-9a-f]{64}$")


def valid_privacy(v) -> bool:
    """Closed-world check: only known keys, numbers, enum values, label-shaped keys, an id and a sha256. Nothing free-form,
    so this block cannot carry a name, address or mapping even by accident."""
    if not isinstance(v, dict) or set(v) - {"breakdown", "firewall", "egress", "tls"}:
        return False
    b = v.get("breakdown", {})
    if not isinstance(b, dict) or set(b) - PRIVACY_BREAKDOWN or not all(_is_num(x) for x in b.values()):
        return False
    f = v.get("firewall", {})
    if not isinstance(f, dict) or set(f) - (PRIVACY_FIREWALL | {"redaction_labels"}):
        return False
    if not all(_is_num(x) for k, x in f.items() if k != "redaction_labels"):
        return False
    rl = f.get("redaction_labels", {})
    if not isinstance(rl, dict) or len(rl) > 16 or not all(isinstance(k, str) and RX_LABEL.match(k) and _is_num(x) for k, x in rl.items()):
        return False
    e = v.get("egress", {})
    if not isinstance(e, dict) or set(e) - {"payload_id", "sha256", "payloads_sent", "events_sent"}:
        return False
    if "payload_id" in e and not (isinstance(e["payload_id"], str) and RX_ID.match(e["payload_id"])):
        return False
    if "sha256" in e and not (isinstance(e["sha256"], str) and RX_SHA.match(e["sha256"])):
        return False
    if not all(_is_num(e[k]) for k in ("payloads_sent", "events_sent") if k in e):
        return False
    t = v.get("tls", {})
    if not isinstance(t, dict) or set(t) - {"verified", "trust", "min_tls", "error"}:
        return False
    if "verified" in t and not isinstance(t["verified"], bool):
        return False
    if t.get("trust") not in (None, "pinned_ca", "system_store") or t.get("min_tls") not in (None, "1.2", "1.3"):
        return False
    return t.get("error") in (None, *PRIVACY_TLS_ERR)


RX_SW = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,39}$")
RX_SWVER = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+\-]{0,39}$")


def valid_environment(v) -> bool:
    if not isinstance(v, dict) or set(v) - {"network", "software"}:
        return False
    n = v.get("network")
    if n is not None:
        if not isinstance(n, dict) or set(n) - {"asn", "country"}:
            return False
        if "asn" in n and not (isinstance(n["asn"], int) and not isinstance(n["asn"], bool) and 1 <= n["asn"] <= 4294967295):
            return False
        if "country" in n and not (isinstance(n["country"], str) and re.fullmatch(r"[A-Z]{2}", n["country"])):
            return False
    sw = v.get("software", [])
    if not isinstance(sw, list) or len(sw) > 40:
        return False
    for e in sw:
        if not (isinstance(e, dict) and set(e) == {"eco", "vendor", "product", "version"} and e["eco"] in ("os", "runtime", "pypi", "app")
                and all(isinstance(e[k], str) for k in e) and RX_SW.match(e["vendor"]) and RX_SW.match(e["product"]) and RX_SWVER.match(e["version"])):
            return False
    return True


def validate_heartbeat(hb: dict):
    """Strict heartbeat validation. Returns list of problems."""
    probs = []
    for k, v in hb.items():
        kind = HEARTBEAT_FIELDS.get(k)
        if kind is None:
            probs.append(f"field not allowed: {k}")
            continue
        if kind == "num" and not _is_num(v):
            probs.append(f"bad {k}")
        elif kind == "str" and (not isinstance(v, str) or len(v) > 64 or scan(v)):
            probs.append(f"bad {k}")
        elif kind == "id" and not (isinstance(v, str) and RX_ID.match(v)):
            probs.append(f"bad {k}")
        elif kind == "isoz":
            try:
                parse_iso(v)
            except Exception:
                probs.append(f"bad {k}")
        elif kind == "anon":
            if not (isinstance(v, dict) and set(v) <= {"enabled", "policy", "records", "removed", "pseudonymised"}
                    and isinstance(v.get("enabled"), bool) and all(_is_num(v[k]) for k in ("records", "removed", "pseudonymised") if k in v)
                    and (v.get("policy") is None or (isinstance(v["policy"], str) and len(v["policy"]) <= 8))):
                probs.append("bad anon")
        elif kind == "actions":
            if not (isinstance(v, list) and len(v) <= 20 and all(isinstance(a, str) and re.fullmatch(r"[a-z_]{3,40}", a) for a in v)):
                probs.append("bad actions")
        elif kind == "environment":
            if not valid_environment(v):
                probs.append("bad environment")
        elif kind == "privacy":
            if not valid_privacy(v):
                probs.append("bad privacy")
        elif kind == "topology":
            if not isinstance(v, dict) or set(v) - {"nodes", "edges"}:
                probs.append("bad topology")
                continue
            for n in v.get("nodes", []):
                if not (isinstance(n, dict) and set(n) <= {"id", "type", "label"} and RX_SRC.match(str(n.get("id", "")))
                        and n.get("type") in {"host", "network", "service"} and len(str(n.get("label", ""))) <= 48):
                    probs.append("bad topology node")
                    break
            for e in v.get("edges", []):
                if not (isinstance(e, list) and len(e) == 2 and all(RX_SRC.match(str(x)) for x in e)):
                    probs.append("bad topology edge")
                    break
    return probs
