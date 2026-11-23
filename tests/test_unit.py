import copy

from common.schema import CONTEXT_ALLOW, filter_event, validate_heartbeat, parse_iso, utc_iso
from common.secrets import redact, scan

BASE = {"event_id": "11111111-2222-3333-4444-555555555555", "type": "alert", "source_id": "api-gateway", "category": "service",
        "severity": "warning", "metric": "response_ms", "value": 120.0, "unit": "ms", "event_time": "2026-01-01T00:00:00.000Z",
        "source_tz": "Europe/London", "context": {"kind": "baseline_deviation", "message": "ok", "z_score": 5.0}}


def ev(**kw):
    e = copy.deepcopy(BASE)
    for k, v in kw.items():
        if k.startswith("ctx_"):
            e["context"][k[4:]] = v
        else:
            e[k] = v
    return e


def test_scanner_detects_and_redacts_each_secret_class():
    cases = {
        "postgres://admin:S3cr3tP@ss@10.0.0.5:5432/prod": ("S3cr3tP@ss", "url_credentials"),
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": ("wJalrXUtnFEMI", "aws_secret"),
        "key AKIAIOSFODNN7EXAMPLE": ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        "Authorization: Bearer abcdefghijklmnopqrstuv": ("abcdefghijklmnopqrstuv", "bearer_token"),
        "password=hunter2": ("hunter2", "password"),
        "card 4111 1111 1111 1111": ("4111 1111 1111 1111", "credit_card"),
        "sk_live_51HxExampleKey99": ("sk_live_51HxExampleKey99", "api_key"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----": ("MIIabc", "private_key"),
    }
    for text, (secret, label) in cases.items():
        out, f = redact(text)
        assert secret not in out, text
        assert label in [x["label"] for x in f], (text, f)
        assert not scan(out, include_pii=False), "redaction must be stable (no re-flagging placeholders)"


def test_scanner_has_no_false_positives_on_normal_ops_text():
    for t in ["GET /api/orders/1454 200 43ms", "version 1.4.0 started", "reason=bad_password", "auth-service login failed",
              "order=12345 amount=99.00", "card number 1234 5678 9012 3456"]:  # last one fails Luhn
        assert not scan(t, include_pii=False), t


def test_pii_is_pseudonymised_out():
    out, f = redact("login success user=alice@corp.com ip=10.0.1.23")
    assert "alice@corp.com" not in out and "10.0.1.23" not in out


def test_allowlist_drops_unknown_fields_and_validates_values():
    r = filter_event(ev(hostname="LAPTOP-1", raw_log="password=x"))
    assert not r["blocked"] and set(r["blocked_fields"]) == {"hostname", "raw_log"}
    assert "hostname" not in r["clean"]
    r = filter_event(ev(ctx_raw="boom"))
    assert "context.raw" in r["blocked_fields"] and "raw" not in r["clean"]["context"]
    assert filter_event(ev(severity="catastrophic"))["blocked"], "invalid enum on a required field blocks the event"
    assert filter_event(ev(event_time="yesterday"))["blocked"]
    r = filter_event(ev(value=float("nan")))
    assert "value" not in (r["clean"] or {}), "non-finite numbers never pass"


def test_secrets_in_allowed_fields_are_redacted_or_event_blocked():
    r = filter_event(ev(ctx_message="debug password=hunter2 AKIAIOSFODNN7EXAMPLE bob@corp.com"))
    assert not r["blocked"]
    assert "hunter2" not in r["clean"]["context"]["message"] and "[REDACTED:" in r["clean"]["context"]["message"]
    assert {x["label"] for x in r["redactions"]} >= {"password", "aws_access_key", "email"}


def test_every_context_key_kind_is_known():
    for t, keys in CONTEXT_ALLOW.items():
        assert set(keys.values()) <= {"num", "str", "strlist", "isoz"}


def test_utc_roundtrip_and_source_tz_required():
    t = 1_800_000_000.123
    assert abs(parse_iso(utc_iso(t)) - t) < 0.002 and utc_iso(t).endswith("Z")
    e = ev()
    e.pop("source_tz")
    assert filter_event(e)["blocked"]


def test_heartbeat_rejects_unknown_fields():
    ok = {"collector_id": "col-acme-01-aaaa", "version": "1.0.0", "config_version": 1, "source_tz": "UTC"}
    assert validate_heartbeat(ok) == []
    assert validate_heartbeat({**ok, "hostname": "x"})
    assert validate_heartbeat({**ok, "version": "password=abc"})
