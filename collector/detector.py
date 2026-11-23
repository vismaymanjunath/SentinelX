"""Local (edge) anomaly detection: EWMA baseline + z-score + rate-of-change, frozen while an anomaly is active."""
import math
import uuid

from common.schema import utc_iso
from . import config

META = {  # floor sigma, min absolute delta
    "cpu_percent": (3, 15), "memory_percent": (1.5, 8), "disk_percent": (1, 5), "latency_ms": (4, 40),
    "packet_loss_pct": (0.15, 1.5), "bandwidth_mbps": (3, 20), "response_ms": (4, 20), "error_rate_pct": (0.3, 2),
    "failed_logins": (1, 3),
}


class LocalDetector:
    def __init__(self):
        self.s = {}

    def update(self, ev, now):
        if ev["type"] != "metric":
            return None
        key = (ev["source_id"], ev["metric"])
        v = ev["value"]
        m = ev["metric"]
        st = self.s.setdefault(key, {"n": 0, "mean": v, "var": 0.0, "prev": v, "step": 0.0, "streak": 0, "active": False,
                                     "normal": 0, "sev": None})
        if m == "availability":
            if v < 0.5 and not st["active"]:
                st["active"] = True
                return self._alert(ev, "availability", "critical", 0, st["mean"], 0, 0, f"{ev['source_id']} reported unavailable")
            if v >= 0.5:
                st["active"] = False
            return None
        floor, min_delta = META.get(m, (1, 1))
        std = max(math.sqrt(st["var"]), floor, 0.03 * abs(st["mean"]))
        z = (v - st["mean"]) / std
        step = abs(v - st["prev"])
        roc = (v - st["prev"]) / max(st["step"], floor)
        alert = None
        deviates = st["n"] >= 20 and z >= 4 and (v - st["mean"]) >= min_delta
        if deviates:
            st["streak"] += 1
        else:
            st["streak"] = 0
        sev = "critical" if z >= 12 else "warning"
        if st["n"] >= 20 and not st["active"] and (st["streak"] >= 2 or (z >= 8 and (v - st["mean"]) >= min_delta)):
            st["active"], st["normal"], st["sev"] = True, 0, sev
            kind = "rate_of_change" if roc >= 8 else "baseline_deviation"
            alert = self._alert(ev, kind, sev, z, st["mean"], std, roc,
                                f"{m} {v:.1f} vs local baseline {st['mean']:.1f} (z={z:.1f})")
        elif st["active"]:
            if sev == "critical" and st["sev"] != "critical":
                st["sev"] = "critical"
                alert = self._alert(ev, "baseline_deviation", "critical", z, st["mean"], std, roc,
                                    f"{m} escalated to {v:.1f} vs baseline {st['mean']:.1f} (z={z:.1f})")
            if z < 2.5:
                st["normal"] += 1
                if st["normal"] >= 4:
                    st["active"], st["streak"] = False, 0
            else:
                st["normal"] = 0
        if not st["active"]:  # freeze baseline during anomalies
            a = 0.08
            d = v - st["mean"]
            st["mean"] += a * d
            st["var"] = (1 - a) * (st["var"] + a * d * d)
            st["step"] = 0.9 * st["step"] + 0.1 * step if st["n"] else step
        st["prev"] = v
        st["n"] += 1
        return alert

    def _alert(self, ev, kind, sev, z, mean, std, roc, msg):
        return {"event_id": str(uuid.uuid4()), "type": "alert", "source_id": ev["source_id"], "category": ev["category"],
                "severity": sev, "metric": ev["metric"], "value": ev["value"], "unit": ev["unit"],
                "event_time": ev["event_time"], "source_tz": ev["source_tz"],
                "context": {"kind": kind, "message": msg, "z_score": round(z, 2), "baseline_mean": round(mean, 2),
                            "baseline_std": round(std, 2), "rate_of_change": round(roc, 2), "direction": "up",
                            "detected_by": "collector-local"},
                "hostname": ev.get("hostname", "local"), "local_note": "triggered by local EWMA detector"}
