"""Secret / PII scanner shared by the collector firewall and the SaaS defence-in-depth guard."""
import re

_NR = r"(?!\[REDACTED)"  # never re-flag already-redacted placeholders

# (label, kind, compiled regex). If the regex has a named group "v", only that span is redacted.
PATTERNS = [
    ("private_key", "secret", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----)?", re.S)),
    ("aws_access_key", "secret", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", "secret", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*(?P<v>" + _NR + r"\S+)")),
    ("jwt", "secret", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b")),
    ("bearer_token", "secret", re.compile(r"(?i)\bbearer\s+(?P<v>" + _NR + r"[A-Za-z0-9._~+/=-]{12,})")),
    ("url_credentials", "secret", re.compile(r"\b[a-z][a-z0-9+.-]*://(?P<v>" + _NR + r"[^\s:/@]+:\S+)@(?=[^\s@]+(?:[/\s]|$))")),
    ("api_key", "secret", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b")),
    ("github_token", "secret", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", "secret", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("password", "secret", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|client_secret|token|api[_-]?key|apikey|access_key)\s*[=:]\s*(?P<v>" + _NR + r"[^\s,;&]+)")),
    ("credit_card", "secret", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("email", "pii", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", "pii", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]


def _luhn(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        t += x
    return t % 10 == 0


def scan(text: str, include_pii: bool = True):
    """Return merged, non-overlapping findings [{label, kind, start, end}]."""
    raw = []
    for label, kind, rx in PATTERNS:
        if kind == "pii" and not include_pii:
            continue
        for m in rx.finditer(text):
            if label == "credit_card" and not _luhn(m.group(0)):
                continue
            span = m.span("v") if "v" in rx.groupindex else m.span()
            if span[1] > span[0]:
                raw.append({"label": label, "kind": kind, "start": span[0], "end": span[1]})
    raw.sort(key=lambda f: (f["start"], -(f["end"] - f["start"])))
    merged = []
    for f in raw:
        if merged and f["start"] < merged[-1]["end"]:
            if f["end"] > merged[-1]["end"]:
                merged[-1]["end"] = f["end"]
            continue
        merged.append(dict(f))
    return merged


def redact(text: str, include_pii: bool = True):
    """Return (redacted_text, findings)."""
    findings = scan(text, include_pii)
    if not findings:
        return text, []
    out, pos = [], 0
    for f in findings:
        out.append(text[pos:f["start"]])
        out.append(f"[REDACTED:{f['label']}]")
        pos = f["end"]
    out.append(text[pos:])
    return "".join(out), findings
