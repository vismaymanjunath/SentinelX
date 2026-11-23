"""Build sentinelx-collector.zip: only what a friend's laptop needs (collector + shared schema + prebuilt UI)."""
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "sentinelx-collector.zip"
REQ = "fastapi\nuvicorn\nhttpx\npsutil\n"
START = "@echo off\r\ncd /d %~dp0\r\npython -m pip install -q -r requirements-collector.txt\r\npython -m collector.setup\r\n"

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for folder in ("collector", "common"):
        for p in (BASE / folder).rglob("*.py"):
            z.write(p, p.relative_to(BASE))
    for p in (BASE / "web" / "dist").rglob("*"):
        if p.is_file():
            z.write(p, p.relative_to(BASE))
    z.writestr("requirements-collector.txt", REQ)
    z.writestr("start_collector.bat", START)
    z.writestr("README.txt", "SENTINEL X collector\r\n1. Install Python 3.10+\r\n2. Double-click start_collector.bat\r\n"
                             "3. In the page that opens, enter the Server URL (https://....ngrok-free.app), the Join code and a Device name; click Connect.\r\n"
                             "Your CPU/RAM/disk/network metrics are then sent to the host. TLS is verified with the normal trusted certificate store.\r\n")
print("wrote", OUT, f"({OUT.stat().st_size // 1024} KB)")
