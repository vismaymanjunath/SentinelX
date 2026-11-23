"""Raw log generation + LOCAL processing: scan, redact, store (raw stays here), summarise into metadata only."""
import random
import re
import time
import uuid
from collections import deque

from common.schema import utc_iso
from common.secrets import redact
from . import config
from .db import db
from .simstate import sim
from .sources import AUTH_SRC, pseudonym

CANARIES: set = set()       # raw secret values seen locally: used by the firewall as a last-line egress check
_rng = random.Random(config.SIM_SEED + 1)
RX_FAILED = re.compile(r"login failed\b.*?\buser=(?P<user>\S+).*?\bip=(?P<ip>[\d.]+)", re.I)
RX_LEVEL = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\b")
RX_SVC = re.compile(r"\b(web-frontend|api-gateway|auth-service|payment-service|cache|db-primary|config-loader|deploy-agent)\b")
USERS = ["alice@corp.com", "bob@corp.com", "carol@corp.com", "dave@corp.com", "svc-batch"]
ATTACKERS = ["203.0.113.9", "198.51.100.23", "192.0.2.77"]
GUESSES = ["Winter2026!", "Passw0rd", "letmein", "Summer#99"]


def _ts():
    return utc_iso()


def generate(now):
    lines = []
    for _ in range(_rng.randint(2, 5)):
        k = _rng.random()
        if k < 0.5:
            lines.append(f"{_ts()} INFO api-gateway GET /api/orders/{_rng.randint(1000,9999)} 200 {_rng.randint(8,60)}ms client={_rng.choice(['10.0.1.23','10.0.1.57','10.0.2.9'])}")
        elif k < 0.75:
            lines.append(f"{_ts()} INFO auth-service login success user={_rng.choice(USERS)} ip=10.0.1.{_rng.randint(2,200)}")
        elif k < 0.9:
            lines.append(f"{_ts()} INFO payment-service charge ok order={_rng.randint(10000,99999)} amount={_rng.randint(5,900)}.00")
        else:
            lines.append(f"{_ts()} WARN cache slow key lookup {_rng.randint(20,80)}ms")
    if _rng.random() < 0.03:  # baseline noise: the odd single failed login
        lines.append(f"{_ts()} WARN auth-service login failed user={_rng.choice(USERS)} ip=10.0.1.{_rng.randint(2,200)} reason=bad_password")
    rate = sim.failed_login_rate()
    for _ in range(rate):
        ip = _rng.choice(ATTACKERS)
        g = f" attempted password={_rng.choice(GUESSES)}" if _rng.random() < 0.3 else ""
        lines.append(f"{_ts()} WARN auth-service login failed user={_rng.choice(USERS)} ip={ip} reason=bad_password{g}")
    lines += [f"{_ts()} {l}" for l in sim.drain_logs()]
    return lines


class LogProcessor:
    def __init__(self):
        self.failed = deque()      # (ts, src_pseudonym)
        self.last_summary = 0.0
        self.stats = {"lines": 0, "secrets": 0, "pii": 0}

    def process(self, lines, now, source_tz):
        """Returns candidate events (metadata only) + side-effects: raw logs persisted locally."""
        n_secret = n_pii = errors = warns = 0
        types = {}
        raw_samples = []
        for raw in lines:
            red, findings = redact(raw)
            secrets = [f for f in findings if f["kind"] == "secret"]
            pii = [f for f in findings if f["kind"] == "pii"]
            for f in secrets:
                v = raw[f["start"]:f["end"]]
                if len(v) >= 6:
                    CANARIES.add(v)
                types[f["label"]] = types.get(f["label"], 0) + 1
            n_secret += len(secrets)
            n_pii += len(pii)
            lm, sm = RX_LEVEL.search(raw), RX_SVC.search(raw)
            lvl = lm.group(1) if lm else "INFO"
            svc = sm.group(1) if sm else "unknown"
            errors += lvl in ("ERROR", "CRITICAL")
            warns += lvl in ("WARN", "WARNING")
            db.exec("INSERT INTO raw_logs(ts,raw,redacted,secrets,pii,level,service) VALUES(?,?,?,?,?,?,?)",
                    (now, raw, red, ",".join(sorted({f['label'] for f in secrets})), len(pii), lvl, svc))
            m = RX_FAILED.search(raw)
            if m:
                self.failed.append((now, pseudonym(m.group("ip")), m.group("ip"), m.group("user"), raw))
            if secrets:
                raw_samples.append(raw)
        while self.failed and now - self.failed[0][0] > 60:
            self.failed.popleft()
        if len(CANARIES) > 500:
            for _ in range(100):
                CANARIES.pop()
        self.stats["lines"] += len(lines)
        self.stats["secrets"] += n_secret
        self.stats["pii"] += n_pii
        tz = source_tz
        base = {"source_tz": tz, "event_time": utc_iso(now)}
        out = []
        out.append({**base, "event_id": str(uuid.uuid4()), "type": "log_summary", "source_id": "collector:" + config.COLLECTOR_ID,
                    "category": "system", "severity": "info",
                    "context": {"lines": len(lines), "errors": errors, "warnings": warns, "window_s": config.TICK_S},
                    "raw_sample": lines[0] if lines else ""})
        if n_secret:
            out.append({**base, "event_id": str(uuid.uuid4()), "type": "privacy_summary", "source_id": "collector:" + config.COLLECTOR_ID,
                        "category": "privacy", "severity": "info",
                        "context": {"lines_scanned": len(lines), "secrets_redacted": n_secret, "pii_redacted": n_pii,
                                    "secret_types": sorted(types)},
                        "raw_sample": raw_samples[0], "raw_secret_lines": raw_samples[:5]})
        cnt = len(self.failed)
        out.append({**base, "event_id": str(uuid.uuid4()), "type": "metric", "source_id": AUTH_SRC, "category": "security",
                    "severity": "info", "metric": "failed_logins", "value": float(cnt), "unit": "count",
                    "context": {"origin": "log-derived"}})
        if cnt >= 5 and now - self.last_summary >= 6:
            self.last_summary = now
            srcs = sorted({f[1] for f in self.failed})
            out.append({**base, "event_id": str(uuid.uuid4()), "type": "security_summary", "source_id": AUTH_SRC,
                        "category": "security", "severity": "critical" if cnt >= 15 else "warning",
                        "context": {"failed_attempts": cnt, "unique_sources": len(srcs), "window_s": 60,
                                    "risk": "high" if cnt >= 15 else "elevated", "top_sources": srcs[:5], "service": "auth-service"},
                        "raw_ips": sorted({f[2] for f in self.failed}), "usernames": sorted({f[3] for f in self.failed}),
                        "raw_sample": self.failed[-1][4]})
        return out
