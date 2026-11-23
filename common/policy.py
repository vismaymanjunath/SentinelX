"""Outgoing-data policy: what telemetry may contain when it leaves a laptop. Used by the collector as a last-line check and
by the central host to reject/flag violations. Findings carry only a CODE and a FIELD NAME, never the matched value, so
violation records, logs and error messages cannot leak the identifier they are about."""
import re

from .anon import RX_IPV4, RX_IPV6, RX_MAC, RX_USER_KV, RX_USER_PATH, IDENTIFYING_FIELDS

PSEUDO_ENTITY = re.compile(r"^(?:host|net):device-\d{3,4}(?:-link)?$")
PSEUDO_LABEL = re.compile(r"^Device-\d{3,4}(?: link)?$")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PLACEHOLDER = re.compile(r"\[(?:REMOVED|REDACTED):[a-z0-9_]+\]")

# severity: 'reject' = never acceptable on the wire; 'flag' = accepted but recorded (legacy / policy drift)
TEXT_RULES = (("ip_address", RX_IPV4, "reject"), ("ipv6_address", RX_IPV6, "reject"), ("mac_address", RX_MAC, "reject"),
              ("email", EMAIL, "reject"))


def _text_findings(field, s):
    if not isinstance(s, str):
        return []
    # username=VALUE is judged on the original text: a placeholder value ("[REMOVED:username]") is exactly what we want to see
    users = [m for m in RX_USER_KV.finditer(s) if not m.group("v").startswith("[")]
    paths = [m for m in RX_USER_PATH.finditer(s) if not m.group("v").startswith("[")]
    s = PLACEHOLDER.sub("", s)                  # already-removed placeholders are fine
    out = [{"code": c, "field": field, "level": lvl} for c, rx, lvl in TEXT_RULES if rx.search(s)]
    if users:
        out.append({"code": "username_value", "field": field, "level": "reject"})
    if paths:
        out.append({"code": "user_path", "field": field, "level": "reject"})
    return out


def check_event(ev):
    out = []
    for k, v in ev.items():
        if k in IDENTIFYING_FIELDS:
            out.append({"code": "identifying_field", "field": k, "level": "reject"})
        elif k == "context" and isinstance(v, dict):
            for ck, cv in v.items():
                if ck in IDENTIFYING_FIELDS:
                    out.append({"code": "identifying_field", "field": f"context.{ck}", "level": "reject"})
                for i, item in enumerate(cv if isinstance(cv, list) else [cv]):
                    out += _text_findings(f"context.{ck}", item)
        elif k == "source_id":
            out += _text_findings("source_id", v)
        elif isinstance(v, str):
            out += _text_findings(k, v)
    return out


def check_heartbeat(hb):
    out = []
    for k, v in hb.items():
        if k == "topology" and isinstance(v, dict):
            for n in v.get("nodes", []):
                out += _text_findings("topology.label", n.get("label"))
        elif k != "topology":
            out += _text_findings(k, v if isinstance(v, str) else None)
    return out


def device_identity_findings(source_ids=(), labels=()):
    """Remote devices that declare anonymisation must use pseudonymous device ids/labels (flag, don't reject)."""
    out = []
    for sid in source_ids:
        if (sid.startswith("host:") or sid.startswith("net:")) and not PSEUDO_ENTITY.match(sid):
            out.append({"code": "non_pseudonymous_device_id", "field": "source_id", "level": "flag"})
            break
    for lab in labels:
        if lab and not PSEUDO_LABEL.match(lab):
            out.append({"code": "non_pseudonymous_device_label", "field": "topology.label", "level": "flag"})
            break
    return out
