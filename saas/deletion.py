"""Data-deletion requests (tenant-scoped): any user may request; only an admin may approve (typed confirmation) or reject.
Approval really deletes the device's stored telemetry from THIS host and records an audit entry; nothing outside this tenant is ever touched.
What is deleted: events, payload records (incl. stored bodies), latest values, alerts raised by that device, its rejected-payload log and incident-AI context
for incidents that device raised. What is kept (and said so in the result): incidents and the audit log (audit is append-only evidence),
the collector registration, and anything on the collector device itself (the host cannot delete data on the device)."""
from .core import audit, now_ms
from .db import db, jd, jl

SCOPES = {"telemetry": "All stored telemetry received from this device"}


def create(tenant, user, collector_id, reason, scope="telemetry"):
    if scope not in SCOPES:
        raise ValueError("unknown scope")
    if not db.one("SELECT 1 FROM collectors WHERE id=? AND tenant_id=?", (collector_id, tenant)):
        raise LookupError("device not found")
    reason = str(reason or "").strip()[:200]
    if len(reason) < 5:
        raise ValueError("please give a short reason (at least 5 characters)")
    if db.one("SELECT 1 FROM deletion_requests WHERE tenant_id=? AND collector_id=? AND status='pending'", (tenant, collector_id)):
        raise ValueError("a request for this device is already pending")
    cur = db.exec("INSERT INTO deletion_requests(tenant_id,collector_id,scope,reason,status,requested_by,requested_ms) VALUES(?,?,?,?,?,?,?)",
                  (tenant, collector_id, scope, reason, "pending", user, now_ms()))
    audit(tenant, user, "privacy.deletion.requested", f"request#{cur.lastrowid} device={collector_id} scope={scope}")
    return get(tenant, cur.lastrowid)


def get(tenant, rid):
    r = db.one("SELECT * FROM deletion_requests WHERE id=? AND tenant_id=?", (rid, tenant))
    if r:
        r["result"] = jl(r["result"], None)
    return r


def listing(tenant):
    return [get(tenant, r["id"]) for r in db.all("SELECT id FROM deletion_requests WHERE tenant_id=? ORDER BY id DESC LIMIT 50", (tenant,))]


def reject(tenant, user, role, rid, note=""):
    if role != "admin":
        raise PermissionError("admin role required")
    r = get(tenant, rid)
    if not r:
        raise LookupError("request not found")
    if r["status"] != "pending":
        raise ValueError(f"request is {r['status']}")
    db.exec("UPDATE deletion_requests SET status='rejected', decided_by=?, decided_ms=?, decision_note=? WHERE id=?", (user, now_ms(), str(note)[:200], rid))
    audit(tenant, user, "privacy.deletion.rejected", f"request#{rid} nothing was deleted")
    return get(tenant, rid)


def approve(tenant, user, role, rid, confirm_text=None, note=""):
    if role != "admin":
        raise PermissionError("admin role required")
    r = get(tenant, rid)
    if not r:
        raise LookupError("request not found")
    if r["status"] != "pending":
        raise ValueError(f"request is {r['status']}")
    if (confirm_text or "").strip() != "DELETE":
        raise ValueError("deleting data cannot be undone: type DELETE to confirm")
    cid = r["collector_id"]
    counts = {}
    with db.lock:
        for label, sql in (("events", "DELETE FROM events WHERE tenant_id=? AND collector_id=?"),
                           ("payloads", "DELETE FROM payloads WHERE tenant_id=? AND collector_id=?"),
                           ("latest_values", "DELETE FROM latest WHERE tenant_id=? AND collector_id=?"),
                           ("alerts", "DELETE FROM alerts WHERE tenant_id=? AND collector_id=?"),
                           ("rejected_payload_log", "DELETE FROM rejected WHERE tenant_id=? AND collector_id=?")):
            counts[label] = db.exec(sql, (tenant, cid)).rowcount
    res = {"deleted": counts, "kept": ["incidents (their alert links may now be empty)", "audit log (append-only evidence)", "the device registration",
                                      "data on the device itself: the host cannot delete it"]}
    db.exec("UPDATE deletion_requests SET status='completed', decided_by=?, decided_ms=?, decision_note=?, result=? WHERE id=?", (user, now_ms(), str(note)[:200], jd(res), rid))
    audit(tenant, user, "privacy.deletion.completed", f"request#{rid} device={cid} " + " ".join(f"{k}={v}" for k, v in counts.items()))
    return get(tenant, rid)
