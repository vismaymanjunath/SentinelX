"""Focused Live Judge Mode / Global Reliability tests on a private SaaS + SIMULATED collector (never touches live devices)."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from tests.conftest import BASE, wait_until

HTTP, HTTPS, CPORT = 18190, 18553, 19151


def test_judge_scenarios_measured_from_real_pipeline_and_reliability_view():
    tmp = Path(tempfile.mkdtemp(prefix="sx-judge-"))
    env = {**os.environ, "SENTINEL_DATA_DIR": str(tmp), "SAAS_HTTP_PORT": str(HTTP), "SAAS_HTTPS_PORT": str(HTTPS), "SENTINEL_INTEL": "0",
           "COLLECTOR_HOST_MODE": "simulated"}
    subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, env=env, check=True, capture_output=True)
    procs = [subprocess.Popen([sys.executable, "-m", "saas.main"], cwd=BASE, env=env, stdout=open(tmp / "s.log", "w"), stderr=subprocess.STDOUT)]
    try:
        saas = httpx.Client(base_url=f"http://127.0.0.1:{HTTP}", timeout=15)
        wait_until(lambda: saas.get("/api/whoami").status_code == 200, 30, msg="saas")
        procs.append(subprocess.Popen([sys.executable, "-m", "collector.main"], cwd=BASE, stdout=open(tmp / "c.log", "w"), stderr=subprocess.STDOUT,
                                      env={**env, "COLLECTOR_CONFIG": str(tmp / "collector-acme.json"), "COLLECTOR_PORT": str(CPORT)}))
        col = httpx.Client(base_url=f"http://127.0.0.1:{CPORT}", timeout=15)
        wait_until(lambda: col.get("/api/whoami").status_code == 200, 30, msg="collector")
        who = col.get("/api/whoami").json()
        assert who["host_mode"] == "simulated" and not who["remote"]
        tok = saas.post("/api/login", json={"username": "acme-admin", "password": "Acme#Admin2026"}).json()["token"]
        H = {"Authorization": "Bearer " + tok}
        time.sleep(40)                                     # let baselines form from the live simulated stream

        # unauthenticated access is refused
        assert saas.get("/api/judge/result?scenario=cpu_spike&since_ms=0").status_code == 401
        assert saas.get("/api/reliability").status_code == 401

        # --- CPU spike: detect, alert, correlate, measured latencies, privacy
        since = time.time() * 1000 - 3000
        assert col.post("/api/sim/cpu_spike", json={}).status_code == 200
        res = wait_until(lambda: (lambda r: r if r.get("found") and r["alerts"] and r["incident"] else None)(
            saas.get(f"/api/judge/result?scenario=cpu_spike&since_ms={since}", headers=H).json()), 60, msg="alert+incident")
        m = res["metrics"]
        assert m["breach_to_alert_ms"] is not None and 0 <= m["breach_to_alert_ms"] <= 15_000, m          # measured, and within the target
        assert res["verdicts"]["breach_to_alert"] is True
        assert res["verdicts"]["offline_detect"] is None                                                  # not measured => not claimed
        assert res["simulated"] is True and res["policy_findings"] == [] and res["payload"]
        assert any(a["severity"] != "info" for a in res["alerts"])
        # the verdict is computed from the numbers (no hardcoded success): re-derive it
        assert res["verdicts"]["breach_to_alert"] == (m["breach_to_alert_ms"] <= res["targets"]["breach_to_alert_ms"])

        # --- duplicate delivery: duplicates are ignored, none stored
        since = time.time() * 1000 - 3000
        assert col.post("/api/sim/duplicate_ooo", json={}).status_code == 200
        res = wait_until(lambda: (lambda r: r if r.get("found") and r["delivery"]["duplicates_ignored"] > 0 else None)(
            saas.get(f"/api/judge/result?scenario=duplicate_ooo&since_ms={since}", headers=H).json()), 60, msg="duplicates ignored")
        rel = saas.get("/api/reliability", headers=H).json()
        assert rel["idempotency"]["duplicate_payloads_stored"] == 0 and rel["idempotency"]["duplicate_events_stored"] == 0
        assert rel["idempotency"]["duplicates_ignored"] >= 1
        assert rel["regional"]["regional_ingest_endpoints"].startswith("Not configured")            # unsupported => honestly labelled
        assert rel["regional"]["regional_storage"].startswith("Not configured")
        assert rel["recent"] and all(e["event_time_utc"].endswith("Z") for e in rel["recent"]) and all(e["source_tz"] for e in rel["recent"])
        assert rel["ordering"]["arrival_order_inversions"] >= 0

        # --- collector offline: measured detection time against the 60 s target
        col.post("/api/sim/clear", json={})
        time.sleep(3)
        since = time.time() * 1000 - 3000
        assert col.post("/api/sim/collector_disconnect", json={"duration_s": 40}).status_code == 200
        res = wait_until(lambda: (lambda r: r if r.get("found") and r["outage"] else None)(
            saas.get(f"/api/judge/result?scenario=collector_disconnect&since_ms={since}", headers=H).json()), 90, interval=2, msg="offline detected")
        assert res["metrics"]["offline_detect_ms"] is not None
        assert res["verdicts"]["offline_detect"] == (res["metrics"]["offline_detect_ms"] <= 60_000)
        assert res["metrics"]["offline_detect_ms"] <= 60_000, res["metrics"]
    finally:
        for p in procs:
            p.terminate()
