"""Helpers for the real-world intelligence tests: run code against a throw-away DB and the REAL internet."""
import json
import os
import subprocess
import sys
import tempfile

import httpx
import pytest

from .conftest import BASE


def internet_ok():
    try:
        return httpx.get("https://www.cisa.gov/", timeout=10, follow_redirects=True).status_code < 500
    except Exception:
        return False


needs_internet = pytest.mark.skipif(not internet_ok(), reason="no internet access: real-world intelligence tests cannot run")

PRE = '''
import json, os, time
from saas.intel import core, registry
from saas.db import db
def out(o): print("@@" + json.dumps(o, default=str))
'''


def run_intel(body, tmp=None, timeout=300, extra_env=None):
    tmp = tmp or tempfile.mkdtemp(prefix="sx-intel-")
    env = {**os.environ, "SENTINEL_DATA_DIR": str(tmp), "SENTINEL_INTEL": "0", **(extra_env or {})}
    r = subprocess.run([sys.executable, "-c", PRE + body], cwd=BASE, env=env, capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, r.stdout[-1500:] + r.stderr[-2500:]
    return json.loads(r.stdout.split("@@")[-1])
