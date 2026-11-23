"""Collector runtime: collect -> process logs -> local detect -> privacy firewall -> durable outbox -> retrying sender."""
import hashlib
import json
import random
import threading
import time
import uuid
from collections import deque

import httpx
import psutil

from common import policy
from common.schema import SCHEMA_VERSION, utc_iso
from . import actions as local_actions, config, detector, envinfo, firewall, logs, sources, tlsutil
from .anonymise import anonymiser
from .db import db
from .simstate import sim

def _platform_info():
    import platform
    s = platform.system()
    if s == "Windows":
        return "windows", f"Windows {platform.release()}"[:60]
    if s == "Darwin":
        return "macos", f"macOS {platform.mac_ver()[0] or platform.release()}"[:60]
    return ("linux" if s == "Linux" else "other"), f"{s} {platform.release()}"[:60]


PLATFORM, OS_VERSION = _platform_info()
ACTIONS = {"scale_up_host", "recycle_process", "failover_wan_link", "block_login_sources", "restart_service"}


class Engine:
    def __init__(self):
        self.det = detector.LocalDetector()
        self.logproc = logs.LogProcessor()
        self.stop = threading.Event()
        self.wake = threading.Event()   # set when a payload is queued so the sender ships it immediately
        # TLS verification is always ON: a pinned private CA if configured (local demo), else the system trust store.
        # (certificate + host-name verification, TLS >= 1.2, https-only URL enforced in config; trust_env off: no proxy surprises)
        self.client = tlsutil.build_client(config.CA_CERT, timeout=5.0 if config.REMOTE else 3.0,
                                           headers={"Authorization": f"Bearer {config.API_KEY}", "ngrok-skip-browser-warning": "1"})
        self.tick_s = config.TICK_S                    # runtime-adjustable (remediation: lower_collector_footprint)
        self.reconnect = threading.Event()             # set when the host answers a heartbeat after a network failure: retry NOW, don't wait out the backoff
        self.retry_after_s = 0.0
        self.link = {"state": "connected", "last_error": None, "last_ack_ms": db.kv_get("last_sync_ms"), "fail_streak": 0, "tls_error": False,
                     "err_kind": None, "queue_full": False}
        anonymiser.stats.update({k: v for k, v in (db.kv_get("anon_stats", {}) or {}).items() if k in anonymiser.stats})
        self.stats = {"payloads_built": 0, "payloads_sent": 0, "events_sent": 0, "blocked_events": 0, "blocked_fields": 0,
                      "redactions": 0, "retries": 0, "duplicates_acked": 0, "ticks": 0, "last_tick_ms": None,
                      "queue_full_payloads": (db.kv_get("queue_full_payloads", 0) or 0), "queue_full_events": (db.kv_get("queue_full_events", 0) or 0)}
        ps = db.kv_get("privacy_stats", {}) or {}
        anonymiser.by.update({k: v for k, v in (ps.get("by") or {}).items() if isinstance(v, (int, float))})
        for k in ("blocked_events", "blocked_fields", "redactions", "payloads_sent", "events_sent"):
            self.stats[k] = max(self.stats.get(k, 0), ps.get(k, 0) or 0)
        self.policy_blocked = ps.get("policy_blocked", 0) or 0
        self.red_labels = dict(ps.get("red_labels") or {})
        self.last_tls_kind = ps.get("last_tls_kind")
        self.recent = {}
        self.local_alerts = deque(maxlen=60)
        self.batch = []
        self.reorder_wait = None
        self.pending_results = []
        self.cfg = {**config.DEFAULTS, **(db.kv_get("config", {}) or {})}
        self.cfg_version = db.kv_get("config_version", 1)
        self._last_purge = 0.0
        db.audit("collector.start", f"{config.COLLECTOR_ID} v{config.VERSION} tz={config.SOURCE_TZ} host_mode={config.HOST_MODE}")

    # ------------------------------------------------------------------ collection pipeline
    def tick(self):
        now = time.time()
        if sim.collector_down():
            return
        cands = sources.collect(now)
        cands += self.logproc.process(logs.generate(now), now, config.SOURCE_TZ)
        cands += envinfo.probe_events(now, sources.anon.PUBLIC_SLUG, config.SOURCE_TZ)      # real cloud-reachability handshakes (about 1/min)
        for ev in [c for c in cands if c["type"] == "metric"]:
            k = (ev["source_id"], ev["metric"])
            self.recent.setdefault(k, deque(maxlen=90)).append((ev["event_time"], ev["value"]))
            a = self.det.update(ev, now)
            if a:
                cands.append(a)
                self.local_alerts.appendleft({"time": a["event_time"], "source": a["source_id"], "metric": a["metric"],
                                              "severity": a["severity"], **a["context"]})
                db.audit("local.alert", f"{a['source_id']} {a['metric']} {a['context']['message']}")
        for m in sim.drain_markers():
            cands.append({"event_id": str(uuid.uuid4()), "type": "sim_marker", "source_id": "collector:" + config.COLLECTOR_ID,
                          "category": "system", "severity": "info", "event_time": utc_iso(m["injected_at"]),
                          "source_tz": config.SOURCE_TZ,
                          "context": {"scenario": m["scenario"], "injected_at": utc_iso(m["injected_at"]), "duration_s": m["duration_s"]}})
            db.audit("scenario.injected", m["scenario"])
        self.emit(cands, now)
        self.stats["ticks"] += 1
        self.stats["last_tick_ms"] = now * 1000
        if now - self._last_purge > 30:
            self._last_purge = now
            self.purge()
        db.kv_set("anon_stats", {k: anonymiser.stats[k] for k in ("records", "removed", "pseudonymised")})   # counters survive restarts
        db.kv_set("privacy_stats", {"by": anonymiser.breakdown(), "policy_blocked": self.policy_blocked, "red_labels": self.red_labels,
                                    "last_tls_kind": self.last_tls_kind,
                                    **{k: self.stats[k] for k in ("blocked_events", "blocked_fields", "redactions", "payloads_sent", "events_sent")}})

    def emit(self, cands, now):
        # 1) local anonymisation FIRST: nothing identifying can reach the firewall output, the outbox or the network.
        #    `cands` (raw) stays local only, for the Egress Proof Panel's BEFORE view.
        anon_cands = [anonymiser.event(c)[0] for c in cands]
        res = firewall.process(anon_cands)
        # 2) last-line outgoing-data policy (same rules the host enforces): block anything that still looks identifying
        ok = []
        for ev in res["clean"]:
            bad = sorted({f["code"] for f in policy.check_event(ev) if f["level"] == "reject"})
            if bad:
                self.policy_blocked += 1
                res["blocked_events"].append({"event_index": -1, "type": ev.get("type"), "reason": "outgoing-data policy: " + ",".join(bad)})
            else:
                ok.append(ev)
        res["clean"] = ok
        clean = res["clean"]
        self.stats["blocked_events"] += len(res["blocked_events"])
        self.stats["blocked_fields"] += sum(len(b["fields"]) for b in res["blocked_fields"])
        self.stats["redactions"] += len(res["redactions"])
        for x in res["redactions"]:
            lab = str(x.get("label", ""))
            if lab:
                self.red_labels[lab] = self.red_labels.get(lab, 0) + 1
        pid = str(uuid.uuid4())
        blocked = {"events": res["blocked_events"], "fields": res["blocked_fields"]}
        if not clean:
            if res["blocked_events"]:
                self._egress_row(pid, 0, "blocked", cands, [], None, blocked, res["redactions"], None, 0)
            return
        seq = db.next_seq()
        payload = {"payload_id": pid, "collector_id": config.COLLECTOR_ID, "seq": seq, "sent_at": utc_iso(),
                   "schema_version": SCHEMA_VERSION, "events": clean}
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        hits = firewall.final_payload_check(body)
        if hits:
            db.audit("egress.blocked", f"payload {pid} blocked by canary check")
            self._egress_row(pid, seq, "blocked", cands, clean, None, {**blocked, "payload": "canary secret in body"}, res["redactions"], None, 0)
            return
        sha = hashlib.sha256(body.encode()).hexdigest()
        first_ms = now * 1000
        q = db.one("SELECT COUNT(*) n, COALESCE(SUM(LENGTH(body)),0) b FROM outbox WHERE status='pending'")
        if q["n"] >= config.OUTBOX_MAX_PENDING or q["b"] >= config.OUTBOX_MAX_MB * 1e6:
            # Queue full: keep the OLDEST data (chronological continuity), do not enqueue this payload, and make the loss VISIBLE:
            # its sequence number is consumed (the host's gap detection shows it), it is counted, audited and shown in the status.
            self.link["queue_full"] = True
            self.stats["queue_full_payloads"] += 1
            self.stats["queue_full_events"] += len(clean)
            db.kv_set("queue_full_payloads", self.stats["queue_full_payloads"])
            db.kv_set("queue_full_events", self.stats["queue_full_events"])
            if time.time() - getattr(self, "_qf_audit", 0) > 60:
                self._qf_audit = time.time()
                db.audit("outbox.full", f"queue full ({q['n']} payloads, {q['b'] // 1024} KiB): payload seq {seq} NOT queued; "
                                        f"{self.stats['queue_full_payloads']} payload(s) not recorded so far")
            self._egress_row(pid, seq, "not_queued_queue_full", cands, clean, None, blocked, res["redactions"], sha, len(clean))
            return
        self.link["queue_full"] = False
        db.exec("INSERT INTO outbox(seq,payload_id,body,sha256,status,created_ms,event_count,first_event_ms) VALUES(?,?,?,?,?,?,?,?)",
                (seq, pid, body, sha, "pending", now * 1000, len(clean), first_ms))
        held = self.link["state"] == "buffering" or sim.saas_blocked()
        self._egress_row(pid, seq, "buffered" if held else "queued", cands, clean, payload, blocked, res["redactions"], sha, len(clean))
        self.stats["payloads_built"] += 1
        self.wake.set()

    def _egress_row(self, pid, seq, status, original, redacted, final, blocked, redactions, sha, n):
        db.exec("INSERT OR REPLACE INTO egress(payload_id,seq,created_ms,status,original,redacted,final,blocked,redactions,attempts,"
                "sha256,event_count,blocked_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, seq, time.time() * 1000, status, json.dumps(original, default=str), json.dumps(redacted),
                 json.dumps(final) if final else None, json.dumps(blocked), json.dumps(redactions), "[]", sha, n,
                 len(blocked["events"]) + sum(len(b["fields"]) for b in blocked["fields"])))

    def selftest(self):
        """Pen-test the firewall: unsafe fields + secrets in allowed fields + raw secret smuggled in a context string."""
        now = time.time()
        secret = "AKIAIOSFODNN7EXAMPLE"
        logs.CANARIES.add("Sup3rS3cretToken99")
        bad = [
            {"event_id": str(uuid.uuid4()), "type": "alert", "source_id": "api-gateway", "category": "service", "severity": "warning",
             "metric": "response_ms", "value": 123.0, "unit": "ms", "event_time": utc_iso(now), "source_tz": config.SOURCE_TZ,
             "context": {"kind": "selftest", "message": f"debug: key {secret} password=hunter2 user bob@corp.com ip 203.0.113.9",
                         "raw_log": "Authorization: Bearer abcdefghijklmnop12345", "z_score": 9.9},
             "username": "bob", "raw_payload": "card=4111 1111 1111 1111", "api_token": "Sup3rS3cretToken99"},
            {"event_id": str(uuid.uuid4()), "type": "alert", "source_id": "auth-service", "category": "security", "severity": "warning",
             "metric": "failed_logins", "value": 9.0, "unit": "count", "event_time": utc_iso(now), "source_tz": config.SOURCE_TZ,
             "context": {"kind": "selftest", "message": "token Sup3rS3cretToken99 leaked"}},
        ]
        db.audit("firewall.selftest", "unsafe candidate events submitted to firewall")
        self.emit(bad, now)

    # ------------------------------------------------------------------ transmission
    def _next_row(self):
        if self.batch:
            return self.batch.pop(0)
        if sim.resend_n > 0:
            sim.resend_n = 0
            self.resend_old()
        if sim.reorder_next > 0:
            pend = db.all("SELECT * FROM outbox WHERE status='pending' ORDER BY seq LIMIT 3")
            if len(pend) >= 3 or (self.reorder_wait and time.time() - self.reorder_wait > 8 and pend):
                sim.reorder_next = 0
                self.reorder_wait = None
                self.batch = list(reversed(pend))
                db.audit("scenario.reorder", "delivering " + ",".join(str(p["seq"]) for p in self.batch))
                return self.batch.pop(0)
            if not self.reorder_wait:
                self.reorder_wait = time.time()
            return None
        return db.one("SELECT * FROM outbox WHERE status='pending' ORDER BY seq LIMIT 1")

    def resend_old(self):
        rows = db.all("SELECT * FROM outbox WHERE status='sent' ORDER BY seq DESC LIMIT 3")
        for r in rows:
            self._post(r, replay=True)
        # also an immediate double-send of the newest pending payload
        p = db.one("SELECT * FROM outbox WHERE status='pending' ORDER BY seq LIMIT 1")
        if p:
            self._post(p, replay=True)
        db.audit("scenario.duplicates", f"re-sent {len(rows)} acked payload(s) verbatim")

    def _log_attempt(self, pid, entry):
        e = db.one("SELECT attempts FROM egress WHERE payload_id=?", (pid,))
        if not e:
            return
        a = json.loads(e["attempts"] or "[]")
        a.append(entry)
        db.exec("UPDATE egress SET attempts=? WHERE payload_id=?", (json.dumps(a[-12:]), pid))

    def _post(self, row, replay=False):
        """One transmission attempt. Returns 'ok' | 'dup' | 'rejected' | 'retry'."""
        att = (row["attempts"] or 0) + 1
        tx = f"TX-{row['seq']:06d}-{'R' if replay else ''}{att}"
        t0 = time.perf_counter()
        try:
            if sim.saas_blocked():
                raise httpx.ConnectError("simulated network partition to SaaS")
            r = self.client.post(f"{config.SAAS_URL}/api/ingest/v1/payload", content=row["body"],
                                 headers={"Content-Type": "application/json", "X-Attempt": str(att), "X-Tx-Id": tx})
        except Exception as e:
            self._log_attempt(row["payload_id"], {"tx_id": tx, "ts": utc_iso(), "outcome": "network_error",
                                                   "detail": tlsutil.explain_tls_error(e) if tlsutil.is_tls_error(e) else str(e)[:100], "replay": replay})
            if not replay:
                db.exec("UPDATE outbox SET attempts=?, last_attempt_ms=? WHERE seq=?", (att, time.time() * 1000, row["seq"]))
                db.exec("UPDATE egress SET status='buffered' WHERE status='queued' AND payload_id IN "
                        "(SELECT payload_id FROM outbox WHERE status='pending')")
            why = tlsutil.explain_tls_error(e) if not isinstance(e, httpx.ConnectError) or tlsutil.is_tls_error(e) else str(e)[:100]
            safe = why if tlsutil.is_tls_error(e) else "network unreachable or the host is not responding"
            self.link.update(state="buffering", last_error=safe, fail_streak=self.link["fail_streak"] + 1, tls_error=tlsutil.is_tls_error(e), err_kind="network")
            if tlsutil.is_tls_error(e):
                self.last_tls_kind = tlsutil.tls_error_kind(e)
            return "retry"
        ms = round((time.perf_counter() - t0) * 1000, 1)
        out = {"tx_id": tx, "ts": utc_iso(), "http_status": r.status_code, "ms": ms, "replay": replay}
        if r.status_code == 200:
            j = r.json()
            dup = j.get("status") == "duplicate"
            out["outcome"] = "duplicate_acked" if dup else "accepted"
            match = j.get("sha256") == row["sha256"]
            out["sha256_match"] = match
            self._log_attempt(row["payload_id"], out)
            self.link.update(state="connected", last_error=None, fail_streak=0, last_ack_ms=time.time() * 1000, tls_error=False, err_kind=None)
            db.kv_set("last_sync_ms", self.link["last_ack_ms"])
            if replay:
                self.stats["duplicates_acked"] += 1 if dup else 0
                return "dup"
            db.exec("UPDATE outbox SET status='sent', attempts=?, sent_ms=?, ack=? WHERE seq=?",
                    (att, time.time() * 1000, json.dumps(j), row["seq"]))
            db.exec("UPDATE egress SET status=?, http_status=200, saas_sha256=? WHERE payload_id=?",
                    ("delivered" if not dup else "delivered (SaaS: already had it)", j.get("sha256"), row["payload_id"]))
            self.stats["payloads_sent"] += 1
            self.stats["events_sent"] += row["event_count"] or 0
            if dup:
                self.stats["duplicates_acked"] += 1
            return "ok"
        if r.status_code in (400, 413, 422):          # permanent: this exact payload will never be accepted. Quarantined (kept, audited), NOT retried.
            out["outcome"] = "rejected"
            out["detail"] = r.text[:200]
            self._log_attempt(row["payload_id"], out)
            if not replay:
                db.audit("outbox.rejected", f"payload seq {row['seq']} rejected by the host with HTTP {r.status_code}; quarantined, not retried")
                self.link.update(last_error=f"HTTP {r.status_code}: a payload was rejected by the host and quarantined (not retried)")
                db.exec("UPDATE outbox SET status='rejected', attempts=? WHERE seq=?", (att, row["seq"]))
                db.exec("UPDATE egress SET status='rejected_by_saas', http_status=? WHERE payload_id=?", (r.status_code, row["payload_id"]))
            return "rejected"
        out["outcome"] = "http_error"
        self._log_attempt(row["payload_id"], out)
        kind = "auth" if r.status_code in (401, 403, 426) else "http"       # auth/TLS-policy problems may be fixed by an operator: keep retrying, flag clearly
        note = {"auth": "credentials/TLS policy refused by the host", "http": "temporary server error"}[kind]
        try:
            self.retry_after_s = min(max(float(r.headers.get("retry-after", 0)), 0.0), 300.0)
        except (TypeError, ValueError):
            self.retry_after_s = 0.0
        self.link.update(state="buffering", last_error=f"HTTP {r.status_code}: {note}; will retry", fail_streak=self.link["fail_streak"] + 1, err_kind=kind)
        if not replay:
            db.exec("UPDATE outbox SET attempts=?, last_attempt_ms=? WHERE seq=?", (att, time.time() * 1000, row["seq"]))
            db.exec("UPDATE egress SET status='buffered' WHERE payload_id=? AND status='queued'", (row["payload_id"],))
        return "retry"

    def sender_loop(self):
        while not self.stop.is_set():
            if sim.collector_down():
                self.stop.wait(0.5)
                continue
            row = self._next_row()
            if not row:
                self.wake.wait(0.25)
                self.wake.clear()
                continue
            res = self._post(row)
            if res == "retry":
                self.stats["retries"] += 1
                delay = min(config.BACKOFF_BASE_S * (2 ** min(self.link["fail_streak"] - 1, 10)), config.BACKOFF_MAX_S)
                delay = max(delay * (0.5 + random.random() * 0.5), self.retry_after_s)          # exponential, jittered, honours Retry-After
                self.retry_after_s = 0.0
                self.reconnect.wait(delay)
                self.reconnect.clear()

    # ------------------------------------------------------------------ heartbeat + remediation commands
    def heartbeat_loop(self):
        proc = psutil.Process()
        proc.cpu_percent(None)
        while not self.stop.is_set():
            if not sim.collector_down():
                try:
                    pend = db.one("SELECT COUNT(*) n, MIN(created_ms) m FROM outbox WHERE status='pending'")
                    hb = {"collector_id": config.COLLECTOR_ID, "version": config.VERSION, "config_version": self.cfg_version,
                          "source_tz": config.SOURCE_TZ, "host_id": sources.host_pseudonym(),
                          "proc_cpu_percent": proc.cpu_percent(None), "proc_mem_mb": round(proc.memory_info().rss / 1e6, 1),
                          "buffer_depth": pend["n"], "oldest_pending_s": round((time.time() * 1000 - pend["m"]) / 1000, 1) if pend["m"] else 0,
                          "link_state": "partitioned" if sim.saas_blocked() else self.link["state"], "sent_at": utc_iso(),
                          "topology": sources.TOPOLOGY, "retention_s": self.cfg["retention_s"], "last_seq": db.kv_get("seq", 0),
                          "platform": PLATFORM, "os_version": OS_VERSION, "interval_s": self.tick_s, "actions": local_actions.CAPABILITIES}
                    hb = anonymiser.heartbeat(hb)
                    snap = anonymiser.snapshot()
                    hb["anon"] = {"enabled": snap["enabled"], "policy": snap["policy"], "records": snap["records"],
                                  "removed": snap["removed"], "pseudonymised": snap["pseudonymised"]}
                    hb["privacy"] = self.privacy_report()
                    env = envinfo.environment()
                    if env:
                        hb["environment"] = env
                    bad = sorted({f["code"] for f in policy.check_heartbeat(hb) if f["level"] == "reject"})
                    if bad:
                        db.audit("heartbeat.withheld", "outgoing-data policy: " + ",".join(bad))
                        raise ValueError("heartbeat withheld by outgoing-data policy")
                    if sim.saas_blocked():
                        raise httpx.ConnectError("simulated network partition to SaaS")
                    r = self.client.post(f"{config.SAAS_URL}/api/ingest/v1/heartbeat", json=hb)
                    if r.status_code == 200 and self.link.get("err_kind") == "network":
                        self.link.update(fail_streak=0)      # the host is reachable again: drain the queue now instead of waiting out the backoff
                        self.reconnect.set()
                        self.wake.set()
                    if r.status_code == 200:
                        for cmd in r.json().get("commands", []):
                            self.run_command(cmd)
                    self._flush_results()
                except Exception as e:
                    self.link.update(last_error=tlsutil.explain_tls_error(e) if tlsutil.is_tls_error(e) else "network unreachable or the host is not responding",
                                     tls_error=tlsutil.is_tls_error(e))
                    if tlsutil.is_tls_error(e):
                        self.last_tls_kind = tlsutil.tls_error_kind(e)
            self.stop.wait(config.HB_S)

    def privacy_report(self):
        """Counters, enum labels and a hash only - the same closed set the host validates. No names, addresses or mapping."""
        last = db.one("SELECT payload_id, sha256 FROM outbox WHERE status='sent' ORDER BY seq DESC LIMIT 1")
        egress = {"payloads_sent": self.stats["payloads_sent"], "events_sent": self.stats["events_sent"]}
        if last and last["sha256"]:
            egress.update(payload_id=last["payload_id"], sha256=last["sha256"])
        return {"breakdown": anonymiser.breakdown(),
                "firewall": {"blocked_events": self.stats["blocked_events"], "blocked_fields": self.stats["blocked_fields"],
                             "redactions": self.stats["redactions"], "policy_blocked": self.policy_blocked,
                             "redaction_labels": dict(sorted(self.red_labels.items(), key=lambda kv: -kv[1])[:12])},
                "egress": egress,
                "tls": {"verified": True, "trust": "pinned_ca" if config.CA_CERT else "system_store", "min_tls": "1.2",
                        "error": self.last_tls_kind}}

    def run_command(self, cmd):
        cid = cmd["command_id"]
        done = db.kv_get("cmd:" + cid)
        if done is None:
            try:
                ok, detail, before, after = self.execute(cmd)
            except Exception as e:
                ok, detail, before, after = False, f"error: {e}", None, None
            done = {"command_id": cid, "ok": ok, "detail": detail, "before_state": before, "after_state": after}
            db.kv_set("cmd:" + cid, done)
            db.audit("remediation." + cmd["kind"], f"{cmd['action']}→{cmd['target']} ok={ok} {detail}")
        self.pending_results.append(done)

    def _flush_results(self):
        keep = []
        for res in self.pending_results:
            try:
                r = self.client.post(f"{config.SAAS_URL}/api/ingest/v1/command-result", json=res)
                if r.status_code != 200:
                    keep.append(res)
            except Exception:
                keep.append(res)
        self.pending_results = keep

    def execute(self, cmd):
        """Sandbox execution against the simulated test environment. Returns (ok, detail, before, after)."""
        action, target, kind = cmd["action"], cmd["target"], cmd["kind"]
        if action in local_actions.CAPABILITIES:        # REAL, bounded actions: measured before/after, reversible where stated
            try:
                return local_actions.run(self, action, cmd.get("params") or {}, rollback=(kind == "rollback"), before_state=cmd.get("before_state"))
            except ValueError as e:
                return False, f"rejected by the collector: {e}", None, None
        if action not in ACTIONS:
            return False, "action not in local allow-list", None, None
        before = sim.snapshot()
        if kind == "rollback":
            snap = cmd.get("before_state")
            if not snap:
                return False, "no rollback snapshot", before, None
            sim.restore(snap)
            return True, f"rolled back {action} on {target}: sandbox state restored", before, sim.snapshot()
        if action == "scale_up_host":
            sim.mit["scaled_up"] = True
        elif action == "recycle_process":
            sim.mit["recycled"] = True
        elif action == "failover_wan_link":
            sim.mit["wan_failover"] = True
        elif action == "block_login_sources":
            sim.mit["login_blocked"] = True
        elif action == "restart_service":
            sim.mit["restarted"][target] = time.time()
            sources.reset_service(target)
        return True, f"[SANDBOX] executed {action} on {target}", before, sim.snapshot()

    # ------------------------------------------------------------------ housekeeping
    def purge(self):
        now = time.time()
        db.exec("DELETE FROM raw_logs WHERE ts<?", (now - self.cfg["retention_s"],))
        db.exec("DELETE FROM egress WHERE created_ms<?", ((now - self.cfg["egress_retention_s"]) * 1000,))
        db.exec("DELETE FROM outbox WHERE status IN ('sent','rejected') AND created_ms<?", ((now - self.cfg["retention_s"]) * 1000,))

    def set_config(self, new):
        for k in ("retention_s", "egress_retention_s"):
            if k in new:
                self.cfg[k] = max(30, int(new[k]))
        self.cfg_version += 1
        db.kv_set("config", self.cfg)
        db.kv_set("config_version", self.cfg_version)
        db.audit("config.changed", json.dumps(new))

    def run(self):
        envinfo.start(self.stop)
        threading.Thread(target=self.sender_loop, daemon=True, name="sender").start()
        threading.Thread(target=self.heartbeat_loop, daemon=True, name="heartbeat").start()
        nxt = time.time()
        while not self.stop.is_set():
            try:
                self.tick()
            except Exception as e:
                db.audit("tick.error", repr(e))
                print("tick error", repr(e))
            nxt += self.tick_s
            self.stop.wait(max(0.0, nxt - time.time()))


engine = Engine()
