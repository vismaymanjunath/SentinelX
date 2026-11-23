"""Focused offline-reliability tests: real SaaS + real collector processes on private ports/temp dirs (the live system is never touched)."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

import httpx

from tests.conftest import BASE, wait_until

HTTP, HTTPS, CPORT = 18090, 18453, 19051


class Rig:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sx-offline-"))
        self.env = {**os.environ, "SENTINEL_DATA_DIR": str(self.tmp), "SAAS_HTTP_PORT": str(HTTP), "SAAS_HTTPS_PORT": str(HTTPS),
                    "SENTINEL_INTEL": "0", "COLLECTOR_HOST_MODE": "simulated", "COLLECTOR_TICK_S": "1", "COLLECTOR_HB_S": "2",
                    "COLLECTOR_BACKOFF_BASE_S": "1", "COLLECTOR_BACKOFF_MAX_S": "4"}
        subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, env=self.env, check=True, capture_output=True)
        self.saas = self.col = None
        self.c = httpx.Client(base_url=f"http://127.0.0.1:{CPORT}", timeout=10)

    def start_saas(self):
        self.saas = subprocess.Popen([sys.executable, "-m", "saas.main"], cwd=BASE, env=self.env,
                                     stdout=open(self.tmp / "saas.log", "a"), stderr=subprocess.STDOUT)

    def start_col(self, extra=None):
        self.col = subprocess.Popen([sys.executable, "-m", "collector.main"], cwd=BASE,
                                    env={**self.env, "COLLECTOR_CONFIG": str(self.tmp / "collector-acme.json"), "COLLECTOR_PORT": str(CPORT), **(extra or {})},
                                    stdout=open(self.tmp / "col.log", "a"), stderr=subprocess.STDOUT)

    def stop(self, p):
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()

    def status(self):
        return self.c.get("/api/status").json()

    def close(self):
        self.stop(self.col)
        self.stop(self.saas)


def test_offline_queue_restart_recovery_no_duplicates_no_privacy_regression():
    r = Rig()
    try:
        r.start_saas()
        wait_until(lambda: httpx.get(f"http://127.0.0.1:{HTTP}/api/whoami").status_code == 200, 30, msg="saas")
        r.start_col()
        wait_until(lambda: r.status()["outbox"]["sent"] >= 3, 60, msg="initial delivery")
        assert r.status()["sync"]["state"] == "ONLINE"

        # --- SaaS becomes unreachable: collector keeps monitoring and queues
        r.stop(r.saas)
        t0 = r.status()["stats"]["ticks"]
        wait_until(lambda: r.status()["sync"]["state"] == "OFFLINE", 30, msg="offline detected")
        wait_until(lambda: r.status()["sync"]["pending"] >= 4, 40, msg="queue grows while offline")
        s = r.status()
        assert s["stats"]["ticks"] > t0, "collector stopped monitoring while offline"
        assert s["sync"]["last_sync_error"] and s["sync"]["last_successful_sync"]
        assert "127.0.0.1" not in json.dumps(s["sync"]) and "localhost" not in json.dumps(s["sync"])
        pending_before = s["sync"]["pending"]
        seqs_before = s["outbox"]["pending_seq_range"]

        # --- collector restart: the queue is durable
        r.stop(r.col)
        r.start_col()
        wait_until(lambda: r.c.get("/api/status").status_code == 200, 30, msg="collector back")
        after = r.status()
        assert after["sync"]["pending"] >= pending_before, "queued payloads were lost across a collector restart"
        assert after["outbox"]["pending_seq_range"][0] == seqs_before[0]

        # --- privacy: everything in the queue passes the outgoing-data policy (no identifiers / raw logs)
        from common import policy
        con = sqlite3.connect(str(r.tmp / "collector-acme" / "collector.db"))
        bodies = [json.loads(b) for (b,) in con.execute("SELECT body FROM outbox WHERE status='pending'")]
        con.close()
        assert bodies
        for b in bodies:
            for ev in b["events"]:
                assert not [f for f in policy.check_event(ev) if f["level"] == "reject"]

        # --- connectivity returns: automatic delivery, then verify no loss / no duplicates on the host
        r.start_saas()
        wait_until(lambda: r.status()["sync"]["pending"] == 0 and r.status()["sync"]["state"] == "ONLINE", 90, msg="auto-drain")
        time.sleep(3)
        con = sqlite3.connect(str(r.tmp / "collector-acme" / "collector.db"))
        sent_ids = {p for (p,) in con.execute("SELECT payload_id FROM outbox WHERE status='sent'")}
        sent_events = sum(n for (n,) in con.execute("SELECT event_count FROM outbox WHERE status='sent'"))
        con.close()
        h = sqlite3.connect(f"file:{r.tmp / 'saas.db'}?mode=ro", uri=True)
        host_ids = [p for (p,) in h.execute("SELECT payload_id FROM payloads")]
        n_events, n_distinct, host_sum = h.execute("SELECT COUNT(*), COUNT(DISTINCT event_id), 0 FROM events").fetchone()
        h.close()
        assert sent_ids <= set(host_ids), "payloads acknowledged by the collector are missing on the host"
        assert len(host_ids) == len(set(host_ids)), "duplicate payloads on the host"
        assert n_events == n_distinct, "duplicate events on the host"
        assert n_events == sent_events, f"event count mismatch host={n_events} collector_sent={sent_events}"
    finally:
        r.close()


def test_queue_limit_never_silent_and_status_codes():
    r = Rig()
    try:
        # SaaS never started: unreachable from the beginning; tiny queue limit
        r.start_col({"COLLECTOR_OUTBOX_MAX_PENDING": "3"})
        wait_until(lambda: r.c.get("/api/status").status_code == 200, 30, msg="collector up")
        wait_until(lambda: r.status()["sync"]["queue_full"], 40, msg="queue full flagged")
        wait_until(lambda: r.status()["sync"]["state"] == "OFFLINE", 30, msg="offline detected")
        s = r.status()
        assert s["sync"]["pending"] == 3 and s["sync"]["not_queued_payloads"] >= 1 and s["sync"]["state"] == "OFFLINE"
        con = sqlite3.connect(str(r.tmp / "collector-acme" / "collector.db"))
        assert con.execute("SELECT COUNT(*) FROM audit WHERE kind='outbox.full'").fetchone()[0] >= 1, "overflow was not audited"
        assert con.execute("SELECT COUNT(*) FROM egress WHERE status='not_queued_queue_full'").fetchone()[0] >= 1
        con.close()
    finally:
        r.close()

    # HTTP status handling, in-process with a stub client (no network)
    cfgdir = Path(tempfile.mkdtemp(prefix="sx-status-"))
    cfg = json.loads((r.tmp / "collector-acme.json").read_text())
    cfg["data_dir"] = str(cfgdir / "d")
    (cfgdir / "c.json").write_text(json.dumps(cfg))
    code = textwrap.dedent("""
        import json, os, time
        from collector import config
        from collector.db import db
        from collector.engine import Engine
        e = Engine()
        class R:
            def __init__(s, code, headers=None): s.status_code = code; s.headers = headers or {}; s.text = "x"
            def json(s): return {"status": "ok", "sha256": row["sha256"]}
        row_body = json.dumps({"payload_id": "p-1", "events": []})
        def mk(seq):
            db.exec("INSERT INTO outbox(seq,payload_id,body,sha256,status,created_ms,event_count) VALUES(?,?,?,?,?,?,?)", (seq, "p-%d" % seq, row_body, "h", "pending", 1, 0))
            return db.one("SELECT * FROM outbox WHERE seq=?", (seq,))
        out = {}
        for i, (code, hdr) in enumerate([(422, None), (413, None), (503, {"retry-after": "7"}), (401, None), (429, None), (200, None)], start=1):
            row = mk(i)
            e.client = type("C", (), {"post": lambda self, *a, **k: R(code, hdr)})()
            res = e._post(row)
            out[code] = [res, db.one("SELECT status FROM outbox WHERE seq=?", (i,))["status"], e.retry_after_s, e.link.get("last_error")]
        print("RESULT" + json.dumps(out))
    """)
    p = subprocess.run([sys.executable, "-c", code], cwd=BASE, capture_output=True, text=True, timeout=60,
                       env={**os.environ, "COLLECTOR_CONFIG": str(cfgdir / "c.json"), "COLLECTOR_HOST_MODE": "simulated"})
    line = [x for x in p.stdout.splitlines() if x.startswith("RESULT")]
    assert line, p.stdout + p.stderr
    out = json.loads(line[0][6:])
    assert out["422"][:2] == ["rejected", "rejected"] and out["413"][:2] == ["rejected", "rejected"]          # permanent: quarantined, not retried
    assert out["503"][:2] == ["retry", "pending"] and out["503"][2] == 7.0                                         # transient: retried, Retry-After honoured
    assert out["401"][:2] == ["retry", "pending"] and "credentials" in out["401"][3]                              # auth: retried slowly, clearly flagged
    assert out["429"][:2] == ["retry", "pending"]
    assert out["200"][:2] == ["ok", "sent"]
