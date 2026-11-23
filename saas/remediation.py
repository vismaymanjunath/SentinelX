"""Controlled remediation: propose -> policy check -> human approval -> sandbox execution on the collector ->
audit + rollback. Nothing executes without an approval record (enforced here, server-side)."""
import uuid

from .core import audit, dependents, entity_info, now_ms
from .db import db, jd, jl

ACTIONS = {
    "scale_up_host": {"title": "Scale out / shed load", "target_types": ["host"],
                      "rollback": "Restore previous sandbox capacity (scale back in)"},
    "recycle_process": {"title": "Recycle leaking process", "target_types": ["host"],
                        "rollback": "Restore previous process state (sandbox snapshot)"},
    "failover_wan_link": {"title": "Fail over WAN link to secondary", "target_types": ["network"],
                          "rollback": "Fail back to the primary link"},
    "block_login_sources": {"title": "Temporarily block offending login sources", "target_types": ["service"],
                            "rollback": "Remove the temporary block list"},
    "restart_service": {"title": "Restart service", "target_types": ["service"],
                        "rollback": "Restore previous service state (sandbox snapshot)"},
}
COOLDOWN_S = 30


def _owner_collector(tenant, target):
    r = db.one("SELECT collector_id FROM latest WHERE tenant_id=? AND source_id=? ORDER BY event_ms DESC LIMIT 1", (tenant, target))
    if r:
        return r["collector_id"]
    c = db.one("SELECT id FROM collectors WHERE tenant_id=? LIMIT 1", (tenant,))
    return c["id"] if c else None


def policy_checks(tenant, incident, action, target, collector_id):
    info = entity_info(tenant)
    checks = []
    spec = ACTIONS.get(action)
    checks.append({"rule": "action is on the allow-listed safe action catalogue", "passed": bool(spec),
                   "detail": action})
    ttype = (info.get(target) or {}).get("type")
    checks.append({"rule": "target type is valid for this action", "passed": bool(spec) and ttype in spec["target_types"],
                   "detail": f"{target} is a {ttype}"})
    scope = set(jl(incident["entities"], [])) | dependents(tenant, incident["root_entity"] or "")
    checks.append({"rule": "target is within the incident's scope (affected set or root cause)", "passed": target in scope,
                   "detail": f"scope: {sorted(scope)[:8]}"})
    checks.append({"rule": "execution environment is sandbox / test (no production actions)", "passed": True,
                   "detail": "executes against the collector's simulated test environment"})
    checks.append({"rule": "action is reversible and a rollback plan exists", "passed": bool(spec),
                   "detail": (spec or {}).get("rollback", "-")})
    recent = db.one("SELECT id FROM remediation WHERE tenant_id=? AND target=? AND action=? AND status IN "
                    "('approved','executing','executed') AND COALESCE(executed_ms, approved_ms) > ?",
                    (tenant, target, action, now_ms() - COOLDOWN_S * 1000))
    checks.append({"rule": f"no identical action on this target in the last {COOLDOWN_S}s (cooldown)", "passed": not recent, "detail": ""})
    col = db.one("SELECT last_seen_ms FROM collectors WHERE id=?", (collector_id,)) if collector_id else None
    online = bool(col and col["last_seen_ms"] and now_ms() - col["last_seen_ms"] < 30000)
    checks.append({"rule": "owning collector is online to execute and acknowledge", "passed": online, "detail": collector_id or "none"})
    checks.append({"rule": "human approval by an admin is required before execution", "passed": True,
                   "detail": "enforced: execution command is only created by the approval endpoint"})
    return checks


def propose(tenant, user, incident_id, action, target):
    inc = db.one("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (incident_id, tenant))
    if not inc:
        raise LookupError("incident not found")
    spec = ACTIONS.get(action)
    cid = _owner_collector(tenant, target)
    checks = policy_checks(tenant, inc, action, target, cid)
    ok = all(c["passed"] for c in checks)
    rec = next((r for r in (jl(inc["analysis"], {}).get("recommendations") or []) if r.get("action") == action and r.get("target") == target), None)
    ms = now_ms()
    cur = db.exec(
        "INSERT INTO remediation(tenant_id,incident_id,collector_id,action,target,title,rationale,status,policy,risk,"
        "proposed_by,proposed_ms,rollback_plan) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (tenant, incident_id, cid, action, target, (spec or {}).get("title", action) + f" → {target}",
         (rec or {}).get("rationale", "operator-initiated"), "proposed" if ok else "blocked_by_policy", jd(checks), "low",
         user, ms, (spec or {}).get("rollback")))
    rid = cur.lastrowid
    audit(tenant, user, "remediation.proposed", f"#{rid} {action}→{target} policy={'pass' if ok else 'FAIL'}")
    return get(tenant, rid)


def get(tenant, rid):
    r = db.one("SELECT * FROM remediation WHERE id=? AND tenant_id=?", (rid, tenant))
    if not r:
        return None
    r["policy"] = jl(r["policy"], [])
    r["before_state"] = jl(r["before_state"], None)
    r["result"] = jl(r["result"], None)
    return r


def approve(tenant, user, role, rid, note=""):
    if role != "admin":
        raise PermissionError("approval requires the admin role")
    r = get(tenant, rid)
    if not r:
        raise LookupError("not found")
    if r["status"] != "proposed":
        raise ValueError(f"cannot approve in status {r['status']}")
    # re-run policy at approval time (state may have changed)
    inc = db.one("SELECT * FROM incidents WHERE id=?", (r["incident_id"],))
    checks = policy_checks(tenant, inc, r["action"], r["target"], r["collector_id"])
    if not all(c["passed"] for c in checks):
        db.exec("UPDATE remediation SET status='blocked_by_policy', policy=? WHERE id=?", (jd(checks), rid))
        audit(tenant, user, "remediation.blocked", f"#{rid} policy re-check failed at approval")
        raise ValueError("policy re-check failed at approval time")
    cmd = str(uuid.uuid4())
    ms = now_ms()
    db.exec("UPDATE remediation SET status='approved', approved_by=?, approved_ms=?, command_id=? WHERE id=?", (user, ms, cmd, rid))
    db.exec("INSERT INTO commands(id,tenant_id,collector_id,remediation_id,kind,action,target,status,created_ms) VALUES(?,?,?,?,?,?,?,?,?)",
            (cmd, tenant, r["collector_id"], rid, "execute", r["action"], r["target"], "queued", ms))
    audit(tenant, user, "remediation.approved", f"#{rid} {r['action']}→{r['target']} note={note[:80]}")
    return get(tenant, rid)


def reject(tenant, user, role, rid, note=""):
    if role != "admin":
        raise PermissionError("rejection requires the admin role")
    r = get(tenant, rid)
    if not r or r["status"] != "proposed":
        raise ValueError("not in proposed state")
    db.exec("UPDATE remediation SET status='rejected', approved_by=?, approved_ms=? WHERE id=?", (user, now_ms(), rid))
    audit(tenant, user, "remediation.rejected", f"#{rid} {note[:80]}")
    return get(tenant, rid)


def request_rollback(tenant, user, role, rid):
    if role != "admin":
        raise PermissionError("rollback requires the admin role")
    r = get(tenant, rid)
    if not r or r["status"] != "executed":
        raise ValueError("only executed actions can be rolled back")
    cmd = str(uuid.uuid4())
    ms = now_ms()
    db.exec("UPDATE remediation SET status='rollback_pending' WHERE id=?", (rid,))
    db.exec("INSERT INTO commands(id,tenant_id,collector_id,remediation_id,kind,action,target,status,created_ms) VALUES(?,?,?,?,?,?,?,?,?)",
            (cmd, tenant, r["collector_id"], rid, "rollback", r["action"], r["target"], "queued", ms))
    audit(tenant, user, "remediation.rollback_requested", f"#{rid} {r['action']}→{r['target']}")
    return get(tenant, rid)


def pending_commands(tenant, collector_id):
    ms = now_ms()
    rows = db.all("SELECT * FROM commands WHERE tenant_id=? AND collector_id=? AND (status='queued' OR "
                  "(status='delivered' AND delivered_ms < ?))", (tenant, collector_id, ms - 15000))
    out = []
    for c in rows:
        db.exec("UPDATE commands SET status='delivered', delivered_ms=? WHERE id=?", (ms, c["id"]))
        if c.get("plan_step_id"):                      # a step of an AI-assisted plan: params + (for rollback) the recorded before-state
            st = db.one("SELECT before_state FROM rem_steps WHERE id=?", (c["plan_step_id"],))
            out.append({"command_id": c["id"], "kind": c["kind"], "action": c["action"], "target": c["target"], "params": jl(c.get("params"), {}),
                        "before_state": jl(st["before_state"], None) if st else None})
            continue
        rem = db.one("SELECT before_state FROM remediation WHERE id=?", (c["remediation_id"],))
        out.append({"command_id": c["id"], "kind": c["kind"], "action": c["action"], "target": c["target"],
                    "before_state": jl(rem["before_state"], None) if rem else None})
    return out


def command_result(tenant, collector_id, command_id, ok, detail, before_state, after_state):
    c = db.one("SELECT * FROM commands WHERE id=? AND tenant_id=? AND collector_id=?", (command_id, tenant, collector_id))
    if not c or c["status"] == "done":
        return False
    ms = now_ms()
    db.exec("UPDATE commands SET status='done', done_ms=?, result=? WHERE id=?", (ms, jd({"ok": ok, "detail": detail}), command_id))
    if c.get("plan_step_id"):
        from . import rem_engine
        rem_engine.step_result(tenant, collector_id, c, ok, detail, before_state, after_state)
        return True
    rid = c["remediation_id"]
    if c["kind"] == "execute":
        db.exec("UPDATE remediation SET status=?, executed_ms=?, result=?, before_state=? WHERE id=?",
                ("executed" if ok else "failed", ms, jd({"ok": ok, "detail": detail, "after": after_state}),
                 jd(before_state), rid))
        audit(tenant, "collector:" + collector_id, "remediation.executed" if ok else "remediation.failed", f"#{rid} {detail}")
    else:
        db.exec("UPDATE remediation SET status=?, rolled_back_ms=?, result=? WHERE id=?",
                ("rolled_back" if ok else "executed", ms, jd({"ok": ok, "detail": detail, "after": after_state}), rid))
        audit(tenant, "collector:" + collector_id, "remediation.rolled_back" if ok else "remediation.rollback_failed", f"#{rid} {detail}")
    return True


def evaluate_outcomes(tenant):
    """Did the executed action clear the incident's alerts? (closes the loop with evidence)"""
    ms = now_ms()
    for r in db.all("SELECT id, incident_id, executed_ms FROM remediation WHERE tenant_id=? AND status='executed' AND outcome IS NULL", (tenant,)):
        if ms - r["executed_ms"] < 10000:
            continue
        open_alerts = db.one("SELECT COUNT(*) n FROM alerts WHERE incident_id=? AND cleared_ms IS NULL", (r["incident_id"],))["n"]
        if open_alerts == 0:
            db.exec("UPDATE remediation SET outcome='effective: all incident alerts cleared after action' WHERE id=?", (r["id"],))
            audit(tenant, "system", "remediation.outcome", f"#{r['id']} effective")
        elif ms - r["executed_ms"] > 90000:
            db.exec("UPDATE remediation SET outcome=? WHERE id=?", (f"not effective: {open_alerts} alert(s) still active after 90s", r["id"]))
            audit(tenant, "system", "remediation.outcome", f"#{r['id']} not effective")
