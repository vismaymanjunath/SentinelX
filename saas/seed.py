"""Create tenants, users, collector credentials and TLS material. Idempotent: python -m saas.seed"""
import json

from . import config, security
from .core import set_setting
from .db import db

TENANTS = [
    {"id": "acme", "name": "Acme Manufacturing", "region": "eu-west", "tz": "Europe/London", "port": 9001,
     "users": [("acme-admin", "Acme#Admin2026", "admin"), ("acme-viewer", "Acme#View2026", "viewer")]},
    {"id": "globex", "name": "Globex Logistics", "region": "ap-south", "tz": "Asia/Kolkata", "port": 9002,
     "users": [("globex-admin", "Globex#Admin2026", "admin")]},
]


def seed():
    ca, crt, key = security.ensure_tls()
    out = {}
    for t in TENANTS:
        db.exec("INSERT OR IGNORE INTO tenants VALUES(?,?,?)", (t["id"], t["name"], t["region"]))
        for u, pw, role in t["users"]:
            if not db.one("SELECT 1 FROM users WHERE username=?", (u,)):
                db.exec("INSERT INTO users(tenant_id,username,pw_hash,role) VALUES(?,?,?,?)", (t["id"], u, security.hash_pw(pw), role))
        cid = f"col-{t['id']}-01"
        cfg_file = config.DATA / f"collector-{t['id']}.json"
        if not db.one("SELECT 1 FROM collectors WHERE id=?", (cid,)) or not cfg_file.exists():
            api_key = security.new_key()
            db.exec("DELETE FROM collectors WHERE id=?", (cid,))
            db.exec("INSERT INTO collectors(id,tenant_id,name,key_hash,region,registered_ms) VALUES(?,?,?,?,?,strftime('%s','now')*1000)",
                    (cid, t["id"], f"{t['name'].split()[0]} Site-01", security.hash_key(api_key), t["region"]))
            cfg_file.write_text(json.dumps({
                "collector_id": cid, "tenant": t["id"], "api_key": api_key, "region": t["region"], "source_tz": t["tz"],
                "saas_url": f"https://localhost:{config.HTTPS_PORT}", "ca_cert": str(ca), "ui_port": t["port"],
                "data_dir": str(config.DATA / f"collector-{t['id']}")}, indent=2))
        out[t["id"]] = cid
    return out


def seed_public():
    """Public deployment: tenants + users only, passwords ONLY from the environment (the well-known demo passwords are never used or kept).
    Existing data (e.g. a migrated database) is untouched except that demo-account passwords are replaced."""
    import os
    import secrets
    admin_pw = os.environ.get("SENTINEL_ADMIN_PASSWORD", "")
    if len(admin_pw) < 12:
        raise SystemExit("SENTINEL_PUBLIC_MODE requires SENTINEL_ADMIN_PASSWORD (at least 12 characters) set in the environment.")
    viewer_pw = os.environ.get("SENTINEL_VIEWER_PASSWORD", "") or secrets.token_urlsafe(24)    # unusable unless you set one
    wanted = {"acme-admin": admin_pw, "acme-viewer": viewer_pw, "globex-admin": secrets.token_urlsafe(24)}
    for t in TENANTS:
        db.exec("INSERT OR IGNORE INTO tenants VALUES(?,?,?)", (t["id"], t["name"], t["region"]))
        for u, _pw, role in t["users"]:
            h = security.hash_pw(wanted[u])
            if db.one("SELECT 1 FROM users WHERE username=?", (u,)):
                db.exec("UPDATE users SET pw_hash=? WHERE username=?", (h, u))
            else:
                db.exec("INSERT INTO users(tenant_id,username,pw_hash,role) VALUES(?,?,?,?)", (t["id"], u, h, role))
    security.ensure_tls()          # keeps the (informational) certificate pages working; it is not served publicly


if __name__ == "__main__":
    print("seeded:", seed())
    print("\nDemo logins (UI http://127.0.0.1:8080):")
    for t in TENANTS:
        for u, pw, role in t["users"]:
            print(f"  {t['id']:7s} {u:14s} {pw:18s} ({role})")
