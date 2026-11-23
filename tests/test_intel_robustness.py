"""Regression tests for the Global Intelligence 'stuck on loading' investigation."""
import json
import os
import subprocess
import sys
import tempfile

from .conftest import BASE


def test_perf_render_no_longer_collides_with_a_long_running_ingestion_transaction():
    """The 500s came from perf_render writing on the shared SQLite connection WITHOUT the db lock while an ingestion thread was mid-transaction."""
    code = '''
import os, time, threading, json
os.environ["SENTINEL_INTEL"] = "0"
from saas.db import db
import saas.main as m
from common.schema import utc_iso
started = threading.Event()
def long_tx():
    with db.tx() as c:
        c.execute("INSERT INTO intel_cache(key,value,fetched_ms) VALUES('t','x',1)")
        started.set(); time.sleep(1.5)
t = threading.Thread(target=long_tx); t.start(); started.wait(5)
body = {"samples": [{"event_id": "e1", "event_time": utc_iso(), "rendered_ms": time.time() * 1000}]}
errs = []
for i in range(5):
    try: m.perf_render(body, {"tenant_id": "acme"})
    except Exception as e: errs.append(type(e).__name__ + ": " + str(e)[:80])
t.join()
print("@@" + json.dumps({"errors": errs, "stored": db.one("SELECT COUNT(*) n FROM perf_render")["n"]}))
'''
    r = subprocess.run([sys.executable, "-c", code], cwd=BASE, env={**os.environ, "SENTINEL_DATA_DIR": tempfile.mkdtemp(), "SENTINEL_INTEL": "0"}, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-1500:]
    out = json.loads(r.stdout.split("@@")[-1])
    assert out["errors"] == [] and out["stored"] == 5


def test_global_intelligence_shows_an_error_instead_of_loading_forever():
    js = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in (BASE / "web" / "dist" / "assets").glob("*.js"))
    assert "Could not load this data from the SENTINEL X backend" in js and "restart it (python run_host.py)" in js


def test_no_code_path_bypasses_the_database_lock():
    import re
    for f in (BASE / "saas").rglob("*.py"):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bdb\.conn\.", line) and "with db.lock" not in line and "db.py" != f.name:
                prev = f.read_text(encoding="utf-8").splitlines()[i - 2]
                assert "with db.lock" in prev, f"{f.name}:{i} uses db.conn outside the lock: {line.strip()}"
