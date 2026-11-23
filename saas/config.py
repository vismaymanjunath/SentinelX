import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("SENTINEL_DATA_DIR", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)
HTTPS_PORT = int(os.environ.get("SAAS_HTTPS_PORT", 8443))
HTTP_PORT = int(os.environ.get("SAAS_HTTP_PORT", 8080))
HOST = os.environ.get("SAAS_HOST", "127.0.0.1")          # dashboard/UI listener (keep loopback)
INGEST_HOST = os.environ.get("SAAS_INGEST_HOST", "127.0.0.1")  # local TLS collector ingest (own CA; local collectors)
TLS_NAMES = [x.strip() for x in os.environ.get("SAAS_TLS_NAMES", "").split(",") if x.strip()]  # extra SANs for the LOCAL cert
# Remote collectors (ngrok): self-registration is enabled ONLY when a join code is set.
JOIN_CODE = os.environ.get("SENTINEL_JOIN_CODE", "").strip()
ENROLL_TENANT = os.environ.get("SENTINEL_ENROLL_TENANT", "acme")
# Ingest-only listener (loopback). This is the ONLY port ever handed to ngrok; the dashboard (HTTP_PORT) never is.
PUBLIC_PORT = int(os.environ.get("SAAS_PUBLIC_PORT", 8090))
# Outgoing-data policy. Violations that put identifiers on the wire are ALWAYS rejected; REQUIRE_ANON=1 additionally rejects
# collectors that do not declare local anonymisation (default: they are accepted but flagged on the Cloud page).
REQUIRE_ANON = os.environ.get("SENTINEL_REQUIRE_ANON", "0").strip().lower() in ("1", "true", "yes", "on")
# Global intelligence ingestion (public feeds). Runs in its own threads, separate from the collector ingest listener.
INTEL_ENABLED = os.environ.get("SENTINEL_INTEL", "1").strip().lower() not in ("0", "false", "no", "off")
INTEL_UA = os.environ.get("SENTINEL_INTEL_UA", "SentinelX/1.0 (local AIOps instance; public-feed reader)")
# Local AI (Ollama). Must be a loopback address; the model is only ever called by this backend.
OLLAMA_URL = os.environ.get("SENTINEL_OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("SENTINEL_OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA_TIMEOUT_S = float(os.environ.get("SENTINEL_OLLAMA_TIMEOUT", 240))
# Public deployment (e.g. Render): ONE public HTTPS port (TLS ends at the platform's edge proxy). Dashboard APIs still require a login token;
# collectors use the same HTTPS port. Local-only listeners (loopback dashboard, private-CA TLS port, ngrok front) are not started.
PUBLIC_MODE = os.environ.get("SENTINEL_PUBLIC_MODE", "0").strip().lower() in ("1", "true", "yes", "on")
if PUBLIC_MODE:
    HOST = "0.0.0.0"
    HTTP_PORT = int(os.environ.get("PORT", 10000))
DB_PATH = DATA / "saas.db"
CERT_DIR = DATA / "tls"
WEB_DIST = BASE / "web" / "dist"

# defaults, overridable per tenant in the UI (settings table)
DEFAULT_SETTINGS = {
    "stale_after_s": 15,        # telemetry older than this => state downgraded to Fair
    "offline_after_s": 30,      # no heartbeat/payload for this long => collector offline => Poor
    "correlation_window_s": 120,
    "graph_hops": 2,
    "retention_hours": 24,
}

DEFAULT_THRESHOLDS = {
    # metric: (good_max, warn, crit)
    "cpu_percent": (60, 80, 92),
    "memory_percent": (78, 90, 96),
    "disk_percent": (85, 93, 98),
    "latency_ms": (80, 150, 300),
    "packet_loss_pct": (0.5, 2, 5),
    "response_ms": (250, 500, 1000),
    "error_rate_pct": (1, 5, 15),
    "failed_logins": (3, 6, 15),
    # LOWER is worse (mobile battery): Good below good_max, Fair at/below warn, Poor at/below crit. Ignored while charging.
    "battery_percent": (40, 20, 10),
}

LOWER_IS_WORSE = {"battery_percent"}
# signals that are state, not load: never baseline-anomaly-detected (battery uses threshold-only)
NO_BASELINE = {"battery_percent", "battery_charging"}

METRIC_META = {
    # floor: minimum sigma; min_delta: minimum absolute move to count as anomaly; up_only: only upward is bad
    "cpu_percent": dict(floor=3, min_delta=15, up_only=True, category="infrastructure", unit="%"),
    "memory_percent": dict(floor=1.5, min_delta=8, up_only=True, category="infrastructure", unit="%"),
    "disk_percent": dict(floor=1, min_delta=5, up_only=True, category="infrastructure", unit="%"),
    "latency_ms": dict(floor=4, min_delta=40, up_only=True, category="network", unit="ms"),
    "packet_loss_pct": dict(floor=0.15, min_delta=1.5, up_only=True, category="network", unit="%"),
    "bandwidth_mbps": dict(floor=3, min_delta=20, up_only=False, category="network", unit="Mbps"),
    "response_ms": dict(floor=4, min_delta=20, up_only=True, category="service", unit="ms"),
    "error_rate_pct": dict(floor=0.3, min_delta=2, up_only=True, category="service", unit="%"),
    "availability": dict(floor=0.1, min_delta=0.5, up_only=False, category="service", unit=""),
    "failed_logins": dict(floor=1, min_delta=3, up_only=True, category="security", unit=""),
    "battery_percent": dict(floor=2, min_delta=10, up_only=False, category="infrastructure", unit="%"),
    "battery_charging": dict(floor=0.1, min_delta=0.5, up_only=False, category="infrastructure", unit=""),
}
