"""PRIVACY FIREWALL: the only door out of the customer environment.

Stage 1 allow-list (drop every field not in the contract)  ->  Stage 2 secret/PII redaction of allowed strings
Stage 3 per-event + whole-payload last-line guard (pattern scan + canary check of raw secrets seen locally).
Anything that cannot be made safe is BLOCKED and never queued for transmission."""
import json

from common.schema import filter_event, payload_text_findings
from .logs import CANARIES


def _canary_hit(text: str):
    return [c for c in CANARIES if c in text]


def process(candidates: list):
    clean, blocked_events, blocked_fields, redactions = [], [], [], []
    for i, c in enumerate(candidates):
        r = filter_event(c)
        if r["blocked_fields"]:
            blocked_fields.append({"event_index": i, "type": c.get("type"), "source_id": c.get("source_id"), "fields": r["blocked_fields"]})
        for x in r["redactions"]:
            redactions.append({"event_index": i, **x})
        if r["blocked"]:
            blocked_events.append({"event_index": i, "type": c.get("type"), "reason": r["reason"]})
            continue
        ev = r["clean"]
        txt = json.dumps({"c": ev.get("context", {}), "s": ev["source_id"]}, sort_keys=True)
        hit = _canary_hit(json.dumps(ev, sort_keys=True))
        guard = payload_text_findings(txt)
        if hit or guard:
            blocked_events.append({"event_index": i, "type": c.get("type"),
                                   "reason": "last-line guard: " + ("raw secret (canary) found in payload" if hit else
                                                                    "sensitive pattern " + guard[0]["label"])})
            continue
        clean.append(ev)
    return {"clean": clean, "blocked_events": blocked_events, "blocked_fields": blocked_fields, "redactions": redactions}


def final_payload_check(body: str):
    """Run on the exact bytes about to be stored for transmission."""
    hit = _canary_hit(body)
    return hit
