import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
_cfg_path = os.environ.get("COLLECTOR_CONFIG", str(BASE / "data" / "collector-acme.json"))
CFG = json.loads(Path(_cfg_path).read_text())

COLLECTOR_ID = CFG["collector_id"]
TENANT_LABEL = CFG["tenant"]          # known locally only; the SaaS derives tenant from the credential
API_KEY = CFG["api_key"]
from . import tlsutil   # noqa: E402  (no config import inside: avoids a cycle)
try:
    SAAS_URL = tlsutil.require_https(CFG["saas_url"])   # unencrypted collector connections are refused at startup
except tlsutil.TLSProblem as _e:
    raise SystemExit(f"collector refused to start: {_e}")
CA_CERT = CFG.get("ca_cert") or None   # None -> normal trusted certificate store (ngrok / any public CA)
SOURCE_TZ = CFG["source_tz"]
REGION = CFG["region"]
UI_PORT = int(os.environ.get("COLLECTOR_PORT", CFG.get("ui_port", 9001)))
DATA_DIR = Path(os.environ.get("COLLECTOR_DATA_DIR", CFG["data_dir"]))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "collector.db"
VERSION = "1.0.0"
TICK_S = float(os.environ.get("COLLECTOR_TICK_S", 2.0))
HB_S = float(os.environ.get("COLLECTOR_HB_S", 5.0))
HOST_MODE = os.environ.get("COLLECTOR_HOST_MODE", "real")   # real | simulated
SIM_SEED = int(os.environ.get("COLLECTOR_SEED", 42))
PSEUDONYM_SALT = CFG.get("salt", COLLECTOR_ID)   # legacy; pseudonyms now use the local secret in the anonymisation store
# Local anonymisation (on by default). COLLECTOR_ANONYMISE=0 or "anonymise": false in the config turns it off (the host flags it).
ANONYMISE = str(os.environ.get("COLLECTOR_ANONYMISE", CFG.get("anonymise", True))).strip().lower() not in ("0", "false", "no", "off")
LAPTOP_ID = str(CFG.get("laptop_id", "") or "")
EXTRA_IDENTIFIERS = [str(x) for x in CFG.get("extra_identifiers", [])]
ANON_MAP_PATH = Path(CFG.get("anon_map") or (DATA_DIR / "anon-map.json"))   # LOCAL ONLY: original -> pseudonym mapping
REMOTE = bool(CFG.get("remote", False))   # remote laptop: real host + real link metrics only, unique per-device entity IDs
DEVICE_NAME = CFG.get("device_name", COLLECTOR_ID)
SLUG = CFG.get("slug", "device")

# Offline reliability: retry backoff (exponential with jitter) and the durable-queue limits (never silently discarded: see engine.emit)
BACKOFF_BASE_S = float(os.environ.get("COLLECTOR_BACKOFF_BASE_S", CFG.get("backoff_base_s", 1.0)))
BACKOFF_MAX_S = float(os.environ.get("COLLECTOR_BACKOFF_MAX_S", CFG.get("backoff_max_s", 30.0)))
OUTBOX_MAX_PENDING = int(os.environ.get("COLLECTOR_OUTBOX_MAX_PENDING", CFG.get("outbox_max_pending", 5000)))
OUTBOX_MAX_MB = float(os.environ.get("COLLECTOR_OUTBOX_MAX_MB", CFG.get("outbox_max_mb", 100)))

DEFAULTS = {"retention_s": 3600, "egress_retention_s": 21600, "min_alert_severity": "warning"}
