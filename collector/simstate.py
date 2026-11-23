"""Live scenario simulator state. Scenarios do not write to the SaaS: they perturb the *sources* (metrics, logs,
link) and everything then travels through the normal collect -> redact -> detect -> firewall -> buffer -> send path."""
import threading
import time

SCENARIOS = {
    "cpu_spike": {"label": "CPU spike", "duration": 60, "desc": "+60 pts CPU on the application host"},
    "memory_anomaly": {"label": "Memory anomaly (leak)", "duration": 70, "desc": "Memory ramps up ~35 pts"},
    "latency_increase": {"label": "Network latency increase", "duration": 60, "desc": "+250 ms on the WAN link"},
    "packet_loss": {"label": "Packet loss", "duration": 60, "desc": "~8% packet loss on the WAN link"},
    "failed_logins": {"label": "Repeated failed logins", "duration": 40, "desc": "Credential-stuffing burst against auth-service"},
    "secret_logs": {"label": "Raw logs containing credentials", "duration": 0, "desc": "Injects log lines with passwords, keys, JWT, card, private key"},
    "saas_disconnect": {"label": "SaaS disconnection", "duration": 40, "desc": "Network partition between collector and SaaS"},
    "collector_disconnect": {"label": "Collector disconnection", "duration": 45, "desc": "Collector process stops (no collection, no heartbeat)"},
    "correlated": {"label": "Multiple correlated anomalies", "duration": 70, "desc": "Host CPU + memory pressure cascading to dependent services"},
    "duplicate_ooo": {"label": "Duplicate + out-of-order delivery", "duration": 0, "desc": "Re-sends acked payloads and delivers the next batch in reverse order"},
    "service_outage": {"label": "Service outage (payment-service)", "duration": 50, "desc": "payment-service stops responding"},
}


class Sim:
    def __init__(self):
        self.lock = threading.RLock()
        self.active = {}            # name -> {start, end, params}
        self.markers = []           # pending sim_marker events
        self.log_queue = []         # custom / scenario raw log lines
        self.reorder_next = 0
        self.resend_n = 0
        self.mit = {"scaled_up": False, "wan_failover": False, "recycled": False, "login_blocked": False, "restarted": {}}

    # ---- scenario lifecycle
    def inject(self, name, duration=None, params=None):
        meta = SCENARIOS[name]
        now = time.time()
        dur = meta["duration"] if duration is None else duration
        with self.lock:
            if name == "secret_logs":
                self.log_queue += SECRET_LINES
            elif name == "duplicate_ooo":
                self.resend_n = 3
                self.reorder_next = 3
            else:
                self.active[name] = {"start": now, "end": now + dur, "params": params or {}}
            self.markers.append({"scenario": name, "injected_at": now, "duration_s": dur})
        return self.status()

    def clear(self, name=None):
        with self.lock:
            if name:
                self.active.pop(name, None)
            else:
                self.active.clear()
                self.log_queue.clear()
                self.reorder_next = 0
                self.resend_n = 0

    def _alive(self, name, now=None):
        now = now or time.time()
        a = self.active.get(name)
        if not a:
            return None
        if now > a["end"]:
            self.active.pop(name, None)
            return None
        return a

    def on(self, name):
        with self.lock:
            return self._alive(name) is not None

    def elapsed(self, name):
        with self.lock:
            a = self._alive(name)
            return (time.time() - a["start"]) if a else 0.0

    def status(self):
        now = time.time()
        with self.lock:
            act = [{"name": n, "label": SCENARIOS[n]["label"], "remaining_s": round(max(0, a["end"] - now), 1)}
                   for n, a in list(self.active.items()) if a["end"] > now]
            return {"active": act, "mitigations": dict(self.mit, restarted=dict(self.mit["restarted"]))}

    def drain_markers(self):
        with self.lock:
            m, self.markers = self.markers, []
            return m

    def drain_logs(self):
        with self.lock:
            q, self.log_queue = self.log_queue, []
            return q

    # ---- effects (scaled by mitigations applied through approved remediation)
    def inj(self, name, full):
        """Current injected magnitude for a scenario after remediation effects."""
        with self.lock:
            a = self._alive(name)
            if not a:
                return 0.0
            f = 1.0
            if name in ("cpu_spike", "correlated") and self.mit["scaled_up"]:
                f = 0.12
            if name in ("latency_increase", "packet_loss") and self.mit["wan_failover"]:
                f = 0.1
            if name in ("memory_anomaly",) and self.mit["recycled"]:
                f = 0.1
            return full * f

    def cpu_extra(self):
        return self.inj("cpu_spike", 60.0) + self.inj("correlated", 52.0)

    def mem_extra(self):
        ramp = lambda n, full, secs: full * min(1.0, self.elapsed(n) / secs)
        with self.lock:
            f_mem = 0.1 if self.mit["recycled"] else 1.0
            f_cor = 0.12 if self.mit["scaled_up"] else 1.0
        return (ramp("memory_anomaly", 35.0, 20.0) * f_mem if self.on("memory_anomaly") else 0.0) + \
               (ramp("correlated", 22.0, 15.0) * f_cor if self.on("correlated") else 0.0)

    def latency_extra(self):
        return self.inj("latency_increase", 250.0)

    def loss_extra(self):
        return self.inj("packet_loss", 8.0)

    def failed_login_rate(self):
        with self.lock:
            if self.mit["login_blocked"]:
                return 0
        return 7 if self.on("failed_logins") else 0

    def service_down(self, svc):
        with self.lock:
            if svc in self.mit["restarted"] and time.time() - self.mit["restarted"][svc] < 600:
                return False
        return svc == "payment-service" and self.on("service_outage")

    def saas_blocked(self):
        return self.on("saas_disconnect")

    def collector_down(self):
        return self.on("collector_disconnect")

    # ---- remediation hooks (sandbox actions)
    def snapshot(self):
        with self.lock:
            return {**{k: v for k, v in self.mit.items() if k != "restarted"}, "restarted": dict(self.mit["restarted"])}

    def restore(self, snap):
        with self.lock:
            for k in ("scaled_up", "wan_failover", "recycled", "login_blocked"):
                self.mit[k] = bool(snap.get(k, False))
            self.mit["restarted"] = dict(snap.get("restarted", {}))


SECRET_LINES = [
    "DEBUG config-loader db_url=postgres://admin:S3cr3tP@ss@10.0.0.5:5432/prod connected",
    "INFO deploy-agent AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "DEBUG api-gateway Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "WARN payment-service charge failed card=4111 1111 1111 1111 holder=jane.doe@corp.com cvv=123",
    "ERROR auth-service login debug user=admin password=Hunter2!Prod api_key=sk_live_51HxExampleKey99",
    "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun -----END RSA PRIVATE KEY-----",
]

sim = Sim()
