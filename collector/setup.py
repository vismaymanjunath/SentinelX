"""One-screen connect page for a remote laptop:  python -m collector.setup   ->  http://127.0.0.1:9100

Enter the host's HTTPS (ngrok) URL, the join code and a device name, then click Connect:
  1. register over HTTPS - the server certificate is verified against the normal trusted certificate store
     (ngrok presents a public certificate); verification is never disabled
  2. the server returns this device's own API key; it is stored in the local config (never the join code)
  3. start the normal collector (real CPU/RAM/disk/network) and redirect to its console.
Deliberately imports nothing from collector.config (which needs a config file at import time).
SENTINEL_TLS_CA (optional) pins a private CA instead of the system store - for local rehearsals only."""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from collector import tlsutil
from common import anon as anonlib

BASE = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get("SENTINEL_REMOTE_DIR", BASE / "data" / "remote-collector"))
CFG = HOME / "collector.json"
CONSOLE_PORT = int(os.environ.get("COLLECTOR_PORT", 9001))
SETUP_PORT = int(os.environ.get("SETUP_PORT", 9100))
TLS_CA = os.environ.get("SENTINEL_TLS_CA") or None
app = FastAPI()
state = {"proc": None}

PAGE = """<!doctype html><meta charset=utf-8><title>SENTINEL X – connect</title>
<style>body{background:#0b1220;color:#e6ecf8;font:15px system-ui;display:flex;justify-content:center;padding-top:8vh}
.c{background:#111a2e;border:1px solid #24324f;border-radius:10px;padding:26px;width:440px}h2{margin:0 0 4px}
input{width:100%;box-sizing:border-box;margin:6px 0 14px;padding:10px;border-radius:6px;border:1px solid #24324f;background:#0b1426;color:#e6ecf8;font:inherit}
button{width:100%;padding:11px;border:0;border-radius:6px;background:#4f8cff;color:#fff;font:inherit;font-weight:700;cursor:pointer}
#m{margin-top:14px;white-space:pre-wrap}.ok{color:#2ecc71}.er{color:#ff8a8a}small{color:#8da0c4}</style>
<div class=c><h2>SENTINEL X <small>collector</small></h2><small>Connect this laptop to the monitoring server.</small><br><br>
<label>Server URL (https://….ngrok-free.app)</label><input id=url placeholder="https://abcd-1234.ngrok-free.app" value="__URL__">
<label>Join code</label><input id=code type=password autocomplete=off placeholder="from the host">
<label>Device name (stays on this laptop)</label><input id=nm placeholder="My-Laptop" value="__NAME__">
<label style="display:flex;gap:8px;align-items:center;margin:4px 0 10px"><input id=an type=checkbox checked style="width:auto;margin:0"> Anonymise this device (recommended): the host only ever sees a pseudonym like Device-27</label>
<details style="margin-bottom:12px"><summary><small>Advanced: private host CA certificate (only if the host does not use ngrok / a public certificate)</small></summary>
<label>Host CA certificate (PEM)</label><textarea id=ca rows=3 style="width:100%;box-sizing:border-box;background:#0b1426;color:#e6ecf8;border:1px solid #24324f;border-radius:6px"></textarea>
<label>CA fingerprint (SHA-256, from the host)</label><input id=fp placeholder="AB:CD:..."></details>
<button onclick=go()>Connect</button><div id=m></div></div>
<script>async function go(){const m=document.getElementById('m');m.className='';m.textContent='Connecting…';
try{const r=await fetch('/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({server_url:url.value.trim(),join_code:code.value,device_name:nm.value.trim(),anonymise:an.checked,ca_pem:ca.value.trim()||null,ca_fingerprint:fp.value.trim()||null})});
const j=await r.json();if(!r.ok)throw new Error(j.detail);m.className='ok';m.textContent='Connected as '+j.collector_id+'\\nOpening your collector console…';
setTimeout(()=>location.href=j.console_url,4000)}catch(e){m.className='er';m.textContent=String(e.message||e)}}</script>"""


@app.get("/", response_class=HTMLResponse)
def index():
    url = name = ""
    if CFG.exists():
        c = json.loads(CFG.read_text())
        url, name = c.get("saas_url", ""), c.get("device_name", "")
    return PAGE.replace("__URL__", url).replace("__NAME__", name)


def _tz_label():
    off = datetime.now().astimezone().utcoffset()
    mins = int(off.total_seconds() // 60) if off else 0
    sign = "+" if mins >= 0 else "-"
    return f"UTC{sign}{abs(mins) // 60:02d}{abs(mins) % 60:02d}"


def _stop_previous_collector():
    """Stop a still-running collector console from a previous Connect (found by its listening port + command line)."""
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            if c.status == "LISTEN" and c.laddr.port == CONSOLE_PORT and c.pid:
                p = psutil.Process(c.pid)
                if "collector.main" in " ".join(p.cmdline()):
                    p.terminate()
                    p.wait(5)
    except Exception:
        pass


def normalize_url(raw: str) -> str:
    """https://host[:port] only - no path/query, no plain http."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    u = urlparse(raw)
    if u.scheme != "https":
        raise HTTPException(400, "The server URL must start with https:// (use the ngrok https URL)")
    if not u.hostname or not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", u.hostname) or u.path not in ("", "/") or u.query or u.username:
        raise HTTPException(400, "Enter just the server address, e.g. https://abcd-1234.ngrok-free.app")
    return f"https://{u.hostname}" + (f":{u.port}" if u.port and u.port != 443 else "")


@app.post("/connect")
def connect(body: dict):
    url = normalize_url(str(body.get("server_url", "")))
    code = str(body.get("join_code", ""))
    name = str(body.get("device_name", "")).strip()
    if not code or len(code) > 128:
        raise HTTPException(400, "Enter the join code the host gave you")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.\-]{0,31}", name):
        raise HTTPException(400, "Device name: 1-32 letters/digits/space/._-")
    HOME.mkdir(parents=True, exist_ok=True)
    # --- trust anchor: a private host CA is accepted ONLY if it matches the fingerprint the host gave you out-of-band
    ca_path = TLS_CA
    if body.get("ca_pem"):
        try:
            tlsutil.check_ca(str(body["ca_pem"]), str(body.get("ca_fingerprint") or ""))
        except tlsutil.TLSProblem as e:
            raise HTTPException(400, str(e))
        (HOME / "host-ca.pem").write_text(str(body["ca_pem"]).strip() + "\n")
        ca_path = str(HOME / "host-ca.pem")
    anonymise = body.get("anonymise", True) is not False
    store = anonlib.Store(HOME / "anon-map.json")
    reg_name = store.device_alias(seed=name) if anonymise else name     # the host only ever sees the pseudonym
    reg_body = lambda n: {"device_name": n, "join_code": code, **({"install_id": store.install_id()} if anonymise else {})}
    r = None
    for _attempt in range(6):
        try:
            with tlsutil.build_client(ca_path, timeout=15, headers={"ngrok-skip-browser-warning": "1"}) as c:   # TLS verification ON
                r = c.post(f"{url}/api/ingest/v1/register", json=reg_body(reg_name))
        except Exception as e:
            if tlsutil.is_tls_error(e):
                raise HTTPException(495, tlsutil.explain_tls_error(e))
            raise HTTPException(502, f"Cannot connect to {url}: {tlsutil.explain_tls_error(e)}")
        if r.status_code == 409 and anonymise:      # pseudonym already used by a different installation: pick another
            reg_name = store.next_alias(seed=name)
            continue
        break
    if r.status_code == 404 and "ngrok" in r.text.lower():
        raise HTTPException(502, "ngrok says this tunnel is offline or the URL is wrong. Ask the host for the current URL.")
    if r.status_code == 403:
        raise HTTPException(403, "The server rejected the join code (or enrollment is disabled).")
    if r.status_code == 429:
        raise HTTPException(429, "Too many attempts - wait a minute and retry.")
    if r.status_code != 200:
        raise HTTPException(r.status_code if r.status_code < 600 else 502, "Server refused enrollment: " + r.text[:160])
    reg = r.json()
    cfg = {"collector_id": reg["collector_id"], "tenant": "remote", "api_key": reg["api_key"], "region": reg["region"],
           "source_tz": _tz_label(), "saas_url": url, "ca_cert": ca_path, "ui_port": CONSOLE_PORT,
           "data_dir": str(HOME / "data"), "remote": True, "device_name": name, "slug": reg["slug"],
           "anonymise": anonymise, "anon_map": str(HOME / "anon-map.json"), "laptop_id": str(body.get("laptop_id") or "")[:48]}
    CFG.write_text(json.dumps(cfg, indent=2))   # contains this device's API key (not the join code)
    if state["proc"] and state["proc"].poll() is None:
        state["proc"].terminate()
    _stop_previous_collector()   # a collector from an earlier run would hold the port with a now-rotated key
    state["proc"] = subprocess.Popen([sys.executable, "-m", "collector.main"], cwd=BASE,
                                     env={**os.environ, "COLLECTOR_CONFIG": str(CFG), "COLLECTOR_PORT": str(CONSOLE_PORT)})
    return {"collector_id": reg["collector_id"], "console_url": f"http://127.0.0.1:{CONSOLE_PORT}"}


if __name__ == "__main__":
    print(f"Open http://127.0.0.1:{SETUP_PORT} and click Connect.", flush=True)
    try:
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{SETUP_PORT}")
    except Exception:
        pass
    uvicorn.run(app, host="127.0.0.1", port=SETUP_PORT, log_level="warning")
