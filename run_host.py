"""Host launcher for remote collectors via ngrok.   python run_host.py

Starts the SaaS with remote enrollment enabled (needs SENTINEL_JOIN_CODE; one is generated if unset):
  - dashboard           : http://127.0.0.1:8080   (loopback only - NEVER tunnel this)
  - local TLS ingest    : https://127.0.0.1:8443  (for the local collectors)
  - ngrok ingest-only   : http://127.0.0.1:8090   <- the ONLY port you give to ngrok (ngrok http http://127.0.0.1:8090)
Use start_host_ngrok.ps1 to start this and the tunnel together."""
import os
import secrets
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main():
    code = os.environ.get("SENTINEL_JOIN_CODE", "").strip()
    generated = not code
    if generated:
        code = secrets.token_urlsafe(6)
    env = {**os.environ, "SENTINEL_JOIN_CODE": code}
    env.setdefault("SAAS_PUBLIC_PORT", "8090")
    subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, env=env, check=True)
    print("\n=== Host ready ===")
    print("Dashboard (local only): http://127.0.0.1:8080   login acme-admin / Acme#Admin2026")
    print(f"Ingest-only listener  : http://127.0.0.1:{env['SAAS_PUBLIC_PORT']}  -> tunnel ONLY this with ngrok")
    print(f"Join code for friends : {code}" + ("   (generated; set SENTINEL_JOIN_CODE to choose your own)" if generated else ""))
    print("Stop with Ctrl+C when the demo is over.\n")
    try:
        subprocess.run([sys.executable, "-m", "saas.main"], cwd=BASE, env=env)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
