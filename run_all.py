"""Start the whole demo: SaaS (HTTP 8080 + TLS 8443), collector for tenant acme (9001) and globex (9002)."""
import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOGS = BASE / "data" / "logs"
LOGS.mkdir(parents=True, exist_ok=True)


def main():
    subprocess.run([sys.executable, "-m", "saas.seed"], cwd=BASE, check=True)
    procs = []

    def spawn(name, args, env=None):
        f = open(LOGS / f"{name}.log", "w")
        procs.append(subprocess.Popen([sys.executable] + args, cwd=BASE, stdout=f, stderr=subprocess.STDOUT,
                                      env={**os.environ, **(env or {})}))
        print("started", name)

    spawn("saas", ["-m", "saas.main"])
    time.sleep(2.5)
    for t in ("acme", "globex"):
        spawn(f"collector-{t}", ["-m", "collector.main"], {"COLLECTOR_CONFIG": str(BASE / "data" / f"collector-{t}.json")})
    print("\nSaaS dashboard : http://127.0.0.1:8080")
    print("Collector acme : http://127.0.0.1:9001   (customer-side console: egress proof, simulator)")
    print("Collector globex: http://127.0.0.1:9002")
    print("Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
