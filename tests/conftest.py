import os as _os_intel
_os_intel.environ.setdefault("SENTINEL_INTEL", "0")   # intel tests fetch explicitly; other tests must not hit external feeds
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

BASE = Path(__file__).resolve().parent.parent
HTTP, HTTPS, CA_PORT, CB_PORT = 18080, 18443, 19001, 19002


def wait_until(fn, timeout=30, interval=0.5, msg="condition"):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa
            last = e
        time.sleep(interval)
    raise AssertionError(f"timeout waiting for {msg} (last={last!r})")


class Stack:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.env = {**os.environ, "SENTINEL_DATA_DIR": str(self.tmp), "SAAS_HTTP_PORT": str(HTTP), "SAAS_HTTPS_PORT": str(HTTPS),
                    "COLLECTOR_HOST_MODE": "simulated"}
        self.procs = []
        subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, env=self.env, check=True, capture_output=True)
        self.spawn("saas", ["-m", "saas.main"])
        time.sleep(3)
        for t, port in (("acme", CA_PORT), ("globex", CB_PORT)):
            self.spawn(f"col-{t}", ["-m", "collector.main"], {"COLLECTOR_CONFIG": str(self.tmp / f"collector-{t}.json"),
                                                               "COLLECTOR_PORT": str(port)})
        self.saas = httpx.Client(base_url=f"http://127.0.0.1:{HTTP}", timeout=10)
        self.ca = httpx.Client(base_url=f"http://127.0.0.1:{CA_PORT}", timeout=10)
        self.cb = httpx.Client(base_url=f"http://127.0.0.1:{CB_PORT}", timeout=10)
        self.cfg = {t: json.loads((self.tmp / f"collector-{t}.json").read_text()) for t in ("acme", "globex")}

    def spawn(self, name, args, extra=None):
        f = open(self.tmp / f"{name}.log", "w")
        self.procs.append(subprocess.Popen([sys.executable] + args, cwd=BASE, stdout=f, stderr=subprocess.STDOUT,
                                           env={**self.env, **(extra or {})}))

    def login(self, user, pw):
        r = self.saas.post("/api/login", json={"username": user, "password": pw})
        assert r.status_code == 200, r.text
        return {"Authorization": "Bearer " + r.json()["token"]}

    def close(self):
        for p in self.procs:
            p.terminate()


@pytest.fixture(scope="session")
def stack():
    tmp = tempfile.mkdtemp(prefix="sentinelx-test-")
    s = Stack(tmp)
    wait_until(lambda: s.saas.get("/api/whoami").status_code == 200, 30, msg="saas up")
    wait_until(lambda: s.ca.get("/api/whoami").status_code == 200, 30, msg="collector up")
    yield s
    s.close()


@pytest.fixture(scope="session")
def admin(stack):
    return stack.login("acme-admin", "Acme#Admin2026")


@pytest.fixture(scope="session")
def viewer(stack):
    return stack.login("acme-viewer", "Acme#View2026")


@pytest.fixture(scope="session")
def gadmin(stack):
    return stack.login("globex-admin", "Globex#Admin2026")
