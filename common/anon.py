"""Local anonymisation (pseudonymisation) of outgoing telemetry. Runs ON THE COLLECTOR, before the outbox/firewall queue.

What it does
  * removes identifying fields (usernames, laptop/asset IDs, IP and MAC addresses, raw log samples) from events/heartbeats
  * replaces this device's names and identifiers (hostname, device name, laptop ID, slug, MACs) with ONE stable pseudonym
    ("Device-27"); the same device always gets the same pseudonym, across events and restarts
  * scrubs free text (error descriptions, log-derived messages): usernames, IPs, MACs and user home paths are removed
  * keeps everything operational: metric names/values/units, timestamps, severities, error descriptions
The original -> pseudonym mapping lives only in a local JSON file (Store). It is never part of any payload.
This is PSEUDONYMISATION, not irreversible anonymisation: the pseudonym is stable, so the host can still correlate one
device over time, and anyone holding the local mapping can reverse it. Network-level metadata (the source IP of the TLS
connection) is outside what the application payload can hide.
Pure module: no collector config/db imports, so the host can run it for previews and tests can run it in isolation."""
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import uuid
from pathlib import Path

POLICY_VERSION = "1"
ALIAS_PREFIX = "Device-"

# keys that identify a person/device and must never be in an outgoing record
IDENTIFYING_FIELDS = {"hostname", "host_name", "fqdn", "username", "usernames", "user", "users", "raw_ips", "ip", "ips",
                      "ip_address", "laptop_id", "asset_tag", "serial", "serial_number", "mac", "macs", "mac_address",
                      "email", "emails", "domain", "raw_sample", "raw_secret_lines"}
BREAKDOWN_KEYS = {"identifying_field", "username", "ip", "mac", "user_path", "device_id"}
TEXT_LIMIT = 140
STOP_USERNAMES = {"user", "users", "system", "default", "guest", "test", "public", "local"}

RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_H = r"[0-9a-fA-F]{1,4}"
# full form (8 groups) or compressed form containing '::' - never plain clock times such as 10:00:00
RX_IPV6 = re.compile(r"(?<![\w:])(?:(?:" + _H + r":){7}" + _H + r"|(?:" + _H + r":){1,6}:(?:" + _H + r"(?::" + _H + r"){0,5})?"
                     r"|::" + _H + r"(?::" + _H + r"){0,6})(?![\w:])")
RX_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
RX_USER_KV = re.compile(r"(?i)\b(?P<k>user(?:name)?|login|account|owner|logged[_ -]?in[_ -]?as)\s*[=:]\s*(?P<v>[^\s,;&\"']+)")
RX_USER_PATH = re.compile(r"(?i)(?P<p>(?:[A-Z]:)?[\\/]+(?:Users|home)[\\/]+)(?P<v>[^\\/\s\"']+)")


def _hm(salt, text):
    return hmac.new(salt.encode(), text.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------------------------------------ local mapping
class Store:
    """Local-only mapping file. {'salt', 'device': {'alias', 'attempt', 'identifiers': {...}}}. path=None -> in memory."""

    def __init__(self, path=None, salt=None):
        self.path = Path(path) if path else None
        self.lock = threading.RLock()
        self.data = {"salt": salt or secrets.token_hex(16), "device": {"alias": None, "attempt": 0, "identifiers": {}}}
        if self.path and self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass           # unreadable mapping: start fresh rather than crash (a new alias will be generated)
        self.data.setdefault("device", {"alias": None, "attempt": 0, "identifiers": {}})
        self._save()

    def _save(self):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @property
    def salt(self):
        return self.data["salt"]

    def device_alias(self, seed=None):
        """Stable pseudonym for this device; created once from the local secret salt (never derivable by the host)."""
        with self.lock:
            d = self.data["device"]
            if not d.get("alias"):
                d["alias"] = self._pick(seed or "device", d.get("attempt", 0))
                self._save()
            return d["alias"]

    def set_device_alias(self, alias):
        with self.lock:
            self.data["device"]["alias"] = alias
            self._save()

    def next_alias(self, seed=None):
        """Used when the host reports the alias is already taken by a different installation (rare collision)."""
        with self.lock:
            d = self.data["device"]
            d["attempt"] = d.get("attempt", 0) + 1
            d["alias"] = self._pick(seed or "device", d["attempt"])
            self._save()
            return d["alias"]

    def _pick(self, seed, attempt):
        n = int(_hm(self.salt, f"{seed}|{attempt}")[:8], 16) % 9000 + 100       # Device-100 .. Device-9099
        return f"{ALIAS_PREFIX}{n}"

    def install_id(self):
        """Random per-installation id sent at enrollment so a different laptop can never take over this device's entry."""
        with self.lock:
            if not self.data.get("install_id"):
                self.data["install_id"] = str(uuid.uuid4())
                self._save()
            return self.data["install_id"]

    def remember(self, kind, real, alias=None):
        """Record original -> pseudonym for the LOCAL console. Raw values are stored only here."""
        if not real:
            return
        with self.lock:
            ids = self.data["device"]["identifiers"]
            if ids.get(real) != kind:
                ids[real] = kind
                self._save()

    def mapping(self):
        d = self.data["device"]
        return {"alias": d.get("alias"), "identifiers": dict(d.get("identifiers", {}))}


def slug_of(alias):
    return alias.lower()


# ------------------------------------------------------------------------------------------------ identity detection
def detect_identity(device_name="", slug="", laptop_id="", extra=()):
    """Identifiers of THIS machine/user that must never be sent. Best effort; all lookups are local."""
    import getpass
    import socket
    ids = {}

    def add(kind, v):
        v = (v or "").strip()
        if len(v) >= 3 and v.lower() not in STOP_USERNAMES:
            ids.setdefault(v, kind)

    add("device_name", device_name)
    add("slug", slug)
    add("laptop_id", laptop_id)
    for x in extra:
        add("device_id", x)
    try:
        h = socket.gethostname()
        add("hostname", h)
        add("hostname", h.split(".")[0])
        add("hostname", socket.getfqdn())
    except OSError:
        pass
    users = set()
    for src in (lambda: getpass.getuser(), lambda: os.environ.get("USERNAME"), lambda: os.environ.get("USER"),
                lambda: os.environ.get("LOGNAME"), lambda: Path.home().name):
        try:
            v = src()
            if v:
                users.add(v)
        except Exception:
            pass
    try:
        import psutil
        users |= {u.name for u in psutil.users()}
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.address and (RX_MAC.fullmatch(a.address) or RX_IPV4.fullmatch(a.address)):
                    add("mac" if RX_MAC.fullmatch(a.address) else "ip", a.address)
    except Exception:
        pass
    for u in users:
        add("username", u)
    return ids


# ------------------------------------------------------------------------------------------------ the anonymiser
class Anonymiser:
    def __init__(self, store, identifiers, enabled=True):
        self.store, self.enabled = store, enabled
        self.ids = dict(identifiers)                      # real value -> kind
        self.stats = {"records": 0, "removed": 0, "pseudonymised": 0}
        self.by = {}                       # removal/replacement counts per TYPE (closed label set); numbers only, safe to report
        self.lock = threading.Lock()
        for real, kind in self.ids.items():
            if real.lower() == store.device_alias().lower():
                continue                       # the pseudonym is not an original identifier
            if kind in ("device_name", "hostname", "laptop_id", "slug", "device_id", "mac"):
                store.remember("device", real)
            elif kind in ("username", "ip"):
                store.remember(kind, real)
        al = store.device_alias().lower()
        # the pseudonym itself (or its slug) is not an identifier: never count "replacing" it with itself
        dev = [r for r, k in self.ids.items() if k in ("device_name", "hostname", "laptop_id", "slug", "device_id", "mac")
               and r.lower() not in (al, al.replace("device-", "device-"))]
        usr = [r for r, k in self.ids.items() if k == "username"]
        ips = [r for r, k in self.ids.items() if k == "ip"]
        self._rx_dev = self._rx(dev)
        self._rx_usr = self._rx(usr)
        self._rx_ip = self._rx(ips)

    @staticmethod
    def _rx(vals):
        vals = sorted({v for v in vals if v}, key=len, reverse=True)
        if not vals:
            return None
        return re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(v) for v in vals) + r")(?![A-Za-z0-9])", re.I)

    @property
    def alias(self):
        return self.store.device_alias()

    @property
    def slug(self):
        return slug_of(self.alias)

    @staticmethod
    def _sub(rx, repl, s):
        """Substitute and count only matches that actually CHANGE the text."""
        n = [0]

        def f(m):
            if m.group(0) != repl:
                n[0] += 1
            return repl
        return rx.sub(f, s), n[0]

    # ---- text -------------------------------------------------------------------------------------------
    def scrub_text(self, s):
        """-> (clean text, removed_count, pseudonymised_count). Order: device ids -> pseudonym, then removals."""
        if not isinstance(s, str) or not s:
            return s, 0, 0
        rem = pse = 0
        acc = {}

        def bump(label, n):
            if n:
                acc[label] = acc.get(label, 0) + n
        if self._rx_dev:
            s, n = self._sub(self._rx_dev, self.alias, s)
            pse += n
            bump("device_id", n)
        for rx, label in ((self._rx_usr, "username"), (self._rx_ip, "ip")):
            if rx:
                s, n = rx.subn(f"[REMOVED:{label}]", s)
                rem += n
                bump(label, n)
        s, n = RX_USER_KV.subn(lambda m: f"{m.group('k')}=[REMOVED:username]", s)
        rem += n
        bump("username", n)
        s, n = RX_USER_PATH.subn(lambda m: m.group("p") + "[REMOVED:username]", s)
        rem += n
        bump("user_path", n)
        for rx, label in ((RX_MAC, "mac"), (RX_IPV6, "ip"), (RX_IPV4, "ip")):
            s, n = rx.subn(f"[REMOVED:{label}]", s)
            rem += n
            bump(label, n)
        if acc:
            with self.lock:
                for k, v in acc.items():
                    self.by[k] = self.by.get(k, 0) + v
        return s, rem, pse

    def scrub_id(self, s):
        """Identifier-shaped strings (source_id 'host:demo-laptop', topology ids): device identifiers -> alias slug."""
        if not isinstance(s, str) or not self._rx_dev:
            return s, 0
        return self._sub(self._rx_dev, self.slug, s)

    # ---- records ----------------------------------------------------------------------------------------
    def event(self, ev):
        """Returns (anonymised copy, removed, pseudonymised). The input is never modified."""
        if not self.enabled:
            return ev, 0, 0
        out, rem, pse = {}, 0, 0
        for k, v in ev.items():
            if k in IDENTIFYING_FIELDS:
                if v not in (None, "", [], {}):
                    rem += 1
                    self._bump_by("identifying_field", 1)
                continue
            if k == "source_id":
                v, n = self.scrub_id(v)
                pse += n
            elif k == "context" and isinstance(v, dict):
                ctx = {}
                for ck, cv in v.items():
                    if ck in IDENTIFYING_FIELDS:
                        rem += 1
                        self._bump_by("identifying_field", 1)
                        continue
                    if isinstance(cv, str):
                        cv, r, p = self.scrub_text(cv)
                        rem, pse = rem + r, pse + p
                    elif isinstance(cv, list):
                        nl = []
                        for it in cv:
                            if isinstance(it, str):
                                it, r, p = self.scrub_text(it)
                                rem, pse = rem + r, pse + p
                            nl.append(it)
                        cv = nl
                    ctx[ck] = cv
                v = ctx
            elif isinstance(v, str) and k in ("metric", "unit", "category", "severity", "type", "source_tz", "event_time", "event_id"):
                pass
            out[k] = v
        with self.lock:
            self.stats["records"] += 1
            self.stats["removed"] += rem
            self.stats["pseudonymised"] += pse
        return out, rem, pse

    def heartbeat(self, hb):
        if not self.enabled:
            return hb
        out, rem, pse = copy.deepcopy(hb), 0, 0
        topo = out.get("topology")
        if isinstance(topo, dict):
            for n in topo.get("nodes", []):
                n["id"], a = self.scrub_id(n.get("id"))
                lab, r, p = self.scrub_text(n.get("label", ""))
                n["label"], rem, pse = lab, rem + r, pse + p + a
            topo["edges"] = [[self.scrub_id(x)[0] for x in e] for e in topo.get("edges", [])]
        with self.lock:
            self.stats["records"] += 1
            self.stats["removed"] += rem
            self.stats["pseudonymised"] += pse
        return out

    def _bump_by(self, label, n):
        with self.lock:
            self.by[label] = self.by.get(label, 0) + n

    def breakdown(self):
        with self.lock:
            return {k: v for k, v in self.by.items() if k in BREAKDOWN_KEYS}

    def snapshot(self):
        with self.lock:
            return {"enabled": self.enabled, "policy": POLICY_VERSION, **self.stats}


# ------------------------------------------------------------------------------------------------ host-side sample preview
SAMPLE = {"username": "Rahul", "laptop_id": "LAP-104", "ip": "192.168.1.15", "cpu": 95.0, "error": "Server timeout",
          "device_name": "Rahul-Laptop"}


def preview(sample=None, alias="Device-27"):
    """BEFORE/AFTER for sample data using the REAL anonymiser (the same code the collector runs). Touches no real data."""
    s = {**SAMPLE, **{k: v for k, v in (sample or {}).items() if isinstance(v, (str, int, float)) and k in SAMPLE}}
    s = {k: (str(v)[:48] if isinstance(v, str) else v) for k, v in s.items()}
    store = Store(None, salt="preview-salt")
    store.set_device_alias(alias)
    ids = {}
    for kind, key in (("device_name", "device_name"), ("laptop_id", "laptop_id"), ("username", "username"), ("ip", "ip")):
        if s.get(key):
            ids[str(s[key])] = kind
    slug = re.sub(r"[^a-z0-9]+", "-", str(s["device_name"]).lower()).strip("-")
    ids2 = {**ids, slug: "slug"} if slug else ids
    an = Anonymiser(store, ids2)
    before = {"event_id": "11111111-2222-3333-4444-555555555555", "type": "alert", "source_id": f"host:{slug}", "category": "infrastructure",
              "severity": "warning", "metric": "cpu_percent", "value": float(s["cpu"]), "unit": "percent",
              "event_time": "2026-01-01T10:00:00.000Z", "source_tz": "UTC+0530",
              "context": {"kind": "threshold", "message": f"{s['error']} on {s['device_name']} ({s['laptop_id']}) at {s['ip']} user={s['username']}"},
              "hostname": s["device_name"], "username": s["username"], "laptop_id": s["laptop_id"], "ip_address": s["ip"]}
    after, rem, pse = an.event(before)
    return {"sample": s, "alias": alias, "before": before, "after": after, "removed": rem, "pseudonymised": pse,
            "payload": {"payload_id": "sample-payload-0001", "collector_id": f"col-r-{slug_of(alias)}", "seq": 1,
                        "sent_at": "2026-01-01T10:00:01.000Z", "schema_version": "1.0", "events": [after]}}
